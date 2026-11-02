
from __future__ import annotations

import asyncio
from datetime import datetime
import hashlib
import errno
import json
import socket
import logging
import os
from pathlib import Path
import re
import time

from dotenv import load_dotenv
from aiogram import Bot, Dispatcher, F, Router
from aiogram.enums import ChatType
from aiogram.exceptions import TelegramAPIError, TelegramBadRequest, TelegramForbiddenError
from aiogram.filters import Command, CommandObject
from aiogram.fsm.context import FSMContext
from aiogram.types import (
    BufferedInputFile, CallbackQuery, InlineKeyboardButton,
    InlineKeyboardMarkup, Message,
)

TelegramEvent = Message | CallbackQuery

from detector import FrameDetector, Inspection
from obs_client import OBSClient

ROOT = Path(__file__).resolve().parent
DATA_ROOT = Path(
    os.environ.get("BOT_DATA_DIR", ROOT / "data")
).resolve()

DATA_ROOT.mkdir(parents=True, exist_ok=True)

ALERT_TTL_SECONDS = 60
ALERT_COOLDOWN_SECONDS = 5 * 60
NOTIFICATION_CLEANUP_INTERVAL_SECONDS = 5
NOTIFICATION_HISTORY_LIMIT = 200

NOTIFICATION_DEFAULTS = {
    'ttl_seconds': ALERT_TTL_SECONDS,
    'cooldown_seconds': ALERT_COOLDOWN_SECONDS,
    'cleanup_interval_seconds': NOTIFICATION_CLEANUP_INTERVAL_SECONDS,
}
NOTIFICATION_LIMITS = {
    'ttl_seconds': (10, 3600),
    'cooldown_seconds': (30, 86400),
    'cleanup_interval_seconds': (1, 60),
}
NOTIFICATION_PRESETS = {
    'ttl_seconds': (30, 60, 120, 300, 600),
    'cooldown_seconds': (60, 300, 600, 900, 1800),
    'cleanup_interval_seconds': (1, 5, 10, 15, 30),
}
NOTIFICATION_LABELS = {
    'ttl_seconds': 'Удаление push-уведомлений',
    'cooldown_seconds': 'Антиспам новых push',
    'cleanup_interval_seconds': 'Интервал фоновой очистки',
}
LOG = logging.getLogger('obs_guard')


OBS_OFFLINE_RETRY_SECONDS = 30


def is_obs_connection_failure(exc: BaseException) -> bool:

    if isinstance(exc, (ConnectionError, TimeoutError, socket.gaierror)):
        return True
    if isinstance(exc, OSError):
        return (getattr(exc, 'winerror', None) in {10051, 10053, 10054, 10057, 10060, 10061, 10065}
                or exc.errno in {errno.ECONNREFUSED, errno.ECONNRESET, errno.ECONNABORTED,
                                 errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ETIMEDOUT,
                                 errno.ENOTCONN, errno.EPIPE})
    return type(exc).__name__ in {
        'WebSocketTimeoutException', 'WebSocketConnectionClosedException',
        'OBSSDKTimeoutError',
    }


def user_facing_error(exc: BaseException) -> str:

    if is_obs_connection_failure(exc):
        return 'OBS недоступен'
    return f'Ошибка: {str(exc)[:500]}'


class IgnoreExpectedOBSDisconnect(logging.Filter):


    def filter(self, record: logging.LogRecord) -> bool:
        return not (record.exc_info and is_obs_connection_failure(record.exc_info[1]))


def configure_obs_logging() -> None:


    logging.getLogger('obsws_python').setLevel(logging.WARNING)
    logger = logging.getLogger('obsws_python.baseclient.ObsClient')
    if not any(isinstance(f, IgnoreExpectedOBSDisconnect) for f in logger.filters):
        logger.addFilter(IgnoreExpectedOBSDisconnect())

ROLES = {'viewer': 1, 'operator': 2, 'admin': 3}
ACCESS_REQUEST_COOLDOWN_SECONDS = 10 * 60
ACCESS_MAX_PENDING = 100
ACCESS_PAGE_SIZE = 8
SOURCE_RELOAD_PAGE_SIZE = 8
ACCESS_ROLE_LABELS = {'viewer': '👁 Наблюдатель', 'operator': '🎛 Оператор', 'admin': '👑 Администратор'}


def valid_user_id(value: str) -> str:
    if not isinstance(value, str) or len(value) > 19 or not value.isascii() or not value.isdecimal():
        raise ValueError('Введите числовой Telegram ID, например 123456789')
    number = int(value)
    if not 1 <= number <= 2**63 - 1:
        raise ValueError('Некорректный Telegram ID')
    return str(number)


def access_display(uid: str, meta: dict | None) -> str:
    info = meta if isinstance(meta, dict) else {}
    username = str(info.get('username') or '')[:32].strip()
    name = str(info.get('name') or '')[:60].strip()
    return ('@' + username if username else name) or uid

ASSIGNMENTS = {'source': 'source_name', 'normal': 'normal_scene', 'fallback': 'fallback_scene'}
RULE_LIMITS = {
    'audio_threshold_db': (-80, -10, float),
    'audio_hold_seconds': (1, 30, float),
    'interval_seconds': (1, 60, float), 'bad_checks': (1, 100, int),
    'good_checks': (1, 100, int), 'black_pixel_threshold': (0, 100, int),
    'black_fraction': (0.5, 1.0, float), 'uniform_stddev': (0.0, 50.0, float),
    'freeze_seconds': (3, 600, float), 'frame_diff_threshold': (0, 30, float),
}

RULE_PRESETS = {
    'audio_threshold_db': (-65, -60, -55, -50, -45, -40, -35, -30),
    'audio_hold_seconds': (3, 5, 8, 10, 15, 20),
    'interval_seconds': (1, 2, 3, 5, 10, 15, 30, 60),
    'freeze_seconds': (3, 5, 10, 15, 30, 60, 120, 300, 600),
    'bad_checks': (1, 2, 3, 4, 5, 10, 15, 20),
    'good_checks': (1, 2, 3, 4, 5, 10, 15, 20),
}
RULE_LABELS = {
    'audio_threshold_db': '🔉 Минимальный уровень звука',
    'audio_hold_seconds': '🎵 Удержание звукового сигнала',
    'interval_seconds': '⏱ Интервал проверки кадра',
    'freeze_seconds': '🧊 Время определения зависания',
    'bad_checks': '🔴 Плохих проверок до паузы',
    'good_checks': '🟢 Хороших проверок до возврата',
}
RULE_UNITS = {
    'audio_threshold_db': 'дБ',
    'audio_hold_seconds': 'сек',
    'interval_seconds': 'сек',
    'freeze_seconds': 'сек',
    'bad_checks': 'проверок',
    'good_checks': 'проверок',
}


def name_id(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8')).hexdigest()[:16]


def keyboard(items: list[tuple[str, str]], cols: int = 2) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=label[:60], callback_data=code)
         for label, code in items[i:i + cols]]
        for i in range(0, len(items), cols)
    ])


def save_json(path: Path, data: dict) -> None:

    tmp = path.with_suffix(path.suffix + '.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        if os.name != 'nt':
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def connection_value(field: str, value: str):

    if field == 'host':
        host = value.strip()
        if not 1 <= len(host) <= 253 or not re.fullmatch(r'[A-Za-z0-9_.:\-]+', host):
            raise ValueError('Адрес: hostname или IP без http://, пробелов и пути')
        return host
    if field == 'port':
        if not value.isdecimal() or not 1 <= int(value) <= 65535:
            raise ValueError('Порт должен быть целым числом от 1 до 65535')
        return int(value)
    if field == 'password':
        if len(value) > 1024:
            raise ValueError('Пароль слишком длинный')
        return value
    raise ValueError('Неизвестное поле подключения')


def binding_issue(monitor: dict, collection: str, scenes: list[str], browsers: list[str]) -> str | None:

    if not all(monitor.get(k) for k in ('collection_name', *ASSIGNMENTS.values())):
        return 'Не выбраны все назначения: источник, основная сцена, сцена паузы'
    if monitor['collection_name'] != collection:
        return f'Активна другая коллекция сцен: {collection}'
    if monitor['normal_scene'] == monitor['fallback_scene']:
        return 'Основная сцена и пауза не должны совпадать'
    if monitor['normal_scene'] not in scenes:
        return f'Основная сцена удалена или переименована: {monitor["normal_scene"]}'
    if monitor['fallback_scene'] not in scenes:
        return f'Сцена паузы удалена или переименована: {monitor["fallback_scene"]}'
    if monitor['source_name'] not in browsers:
        return f'Browser Source удалён, переименован или сменил тип: {monitor["source_name"]}'
    return None


def format_rules(r: dict) -> str:
    return (
        'Правила обнаружения:\n'
        f"• Чёрный кадр: {'ВКЛ' if r['black'] else 'ВЫКЛ'} "
        f"(порог {r['black_pixel_threshold']}; доля {r['black_fraction']})\n"
        f"• Однотонный кадр: {'ВКЛ' if r['uniform'] else 'ВЫКЛ'} "
        f"(σ ≤ {r['uniform_stddev']})\n"
        f"• Зависание: {'ВКЛ' if r['freeze'] else 'ВЫКЛ'} "
        f"({r['freeze_seconds']} сек; разница ≤ {r['frame_diff_threshold']})\n"
        f"• Разрешать плохую картинку при наличии звука: "
        f"{'ВКЛ' if r.get('audio_override', False) else 'ВЫКЛ'} "
        f"(порог {r.get('audio_threshold_db', -45)} дБ; "
        f"удержание {r.get('audio_hold_seconds', 8)} сек)\n"
        f"• Интервал: {r['interval_seconds']} сек\n"
        f"• До паузы при чёрном/однотонном кадре: {r['bad_checks']} плохих проверок\n"
        f"• До восстановления: {r['good_checks']} хороших проверок\n\n"
        'Интервал — время между проверками, а «до паузы» / «до восстановления» —\n'
        'число последовательных проверок. При зависании сцена переключается\n'
        'сразу после достижения порога времени, без ожидания плохих проверок.\n\n'
        'Выберите значения кнопками ниже или задайте точное через /setrule bad_checks 5\n'
        'Ключи: interval_seconds, bad_checks, good_checks, black_pixel_threshold, '
        'black_fraction, uniform_stddev, freeze_seconds, frame_diff_threshold, '
        'audio_threshold_db, audio_hold_seconds.'
    )


def parse_rule_value(key: str, text: str) -> float | int:

    if key not in RULE_LIMITS:
        raise ValueError('Неизвестный параметр проверки камеры')
    lower, upper, value_type = RULE_LIMITS[key]
    text = text.strip()
    if value_type is int and ('.' in text or 'e' in text.lower()):
        raise ValueError('Ожидается целое число')
    try:
        value = value_type(text)
    except (ValueError, OverflowError) as exc:
        raise ValueError('Введите корректное число') from exc
    if not lower <= value <= upper:
        raise ValueError(f'Для {key} допустимы значения от {lower} до {upper}')
    return value


def rule_value_label(key: str, value: float | int) -> str:
    return f'{value:g} {RULE_UNITS[key]}'


def rule_buttons(rules: dict) -> list[tuple[str, str]]:
    return [(f'{RULE_LABELS[key]}: {rule_value_label(key, rules[key])}',
             f'checkrule:pick:{key}') for key in RULE_PRESETS]


def rule_picker_description(key: str) -> str:
    if key == 'interval_seconds':
        return ('Как часто делать скриншот Browser Source. Чем меньше интервал, '
                'тем выше нагрузка на OBS. Смена значения не выключает автоматику.')
    if key == 'freeze_seconds':
        return ('Сколько времени изображение должно оставаться практически неизменным, '
                'чтобы переключиться на паузу без дополнительных плохих проверок. '
                'Работает при включённом детекторе зависания, проверка звука имеет приоритет.')
    if key == 'audio_threshold_db':
        return 'Громкость реального сигнала, при которой чёрный, однотонный или зависший кадр не вызывает переключения. Чем ближе к нулю, тем громче нужен звук.'
    if key == 'audio_hold_seconds':
        return 'На сколько секунд запоминать последний всплеск звука выше порога. Измеритель при этом обязан продолжать присылать свежие показания OBS.'
    if key == 'bad_checks':
        return ('Сколько плохих проверок подряд требуется для чёрного или однотонного кадра. '
                'Зависание переключает сцену по своему времени без этого ожидания.')
    return 'Сколько хороших проверок подряд требуется для возврата на основную сцену.'


def notification_interval(key: str, text: str) -> int:

    if key not in NOTIFICATION_LIMITS:
        raise ValueError('Неизвестный параметр уведомлений')
    if not text.isdecimal():
        raise ValueError('Укажите целое число секунд')
    value = int(text)
    low, high = NOTIFICATION_LIMITS[key]
    if not low <= value <= high:
        raise ValueError(f'Для {key} допустимы значения от {low} до {high} секунд')
    return value


def format_notifications(cfg: dict, rules: dict) -> str:
    return (
        '🔔 Настройки уведомлений\n\n'
        f"• Удалять push через: {cfg['ttl_seconds']} сек\n"
        f"• Пауза между push: {cfg['cooldown_seconds']} сек\n"
        f"• Проверять очередь удаления: раз в {cfg['cleanup_interval_seconds']} сек\n\n"
        'Мониторинг OBS не зависит от этих настроек:\n'
        f"• Проверять кадр: раз в {rules['interval_seconds']} сек\n"
        f"• Для паузы при чёрном/однотонном кадре: {rules['bad_checks']} плохих подряд\n"
        f"• При зависании: {rules['freeze_seconds']:g} сек без дополнительных проверок\n"
        f"• Для восстановления: {rules['good_checks']} хороших подряд\n\n"
        'Push отправляется при переключении на паузу или ошибке, а не после каждой проверки. '
        'При восстановлении обновляется только статус.\n\n'
        'Выберите настройку кнопкой или введите, например:\n'
        '/setnotify ttl_seconds 90\n'
        '/setnotify cooldown_seconds 600\n'
        '/setnotify cleanup_interval_seconds 10\n\n'
        'Изменения сохраняются в settings.json. Новое время удаления относится к новым уведомлениям.'
    )


def load_settings(admin_id: str | None) -> tuple[dict, str]:

    settings_file = DATA_ROOT / 'settings.json'
    legacy_file = DATA_ROOT / 'config.json'
    default_file = ROOT / 'config.example.json'
    if settings_file.exists():
        cfg = json.loads(settings_file.read_text(encoding='utf-8'))
    elif legacy_file.exists():
        cfg = json.loads(legacy_file.read_text(encoding='utf-8'))
        legacy_password = os.getenv('OBS_WEBSOCKET_PASSWORD', '')
        if legacy_password and 'replace_this' not in legacy_password:
            cfg.setdefault('obs', {})['password'] = legacy_password
        cfg['monitor'].setdefault('collection_name', '')
    else:
        cfg = json.loads(default_file.read_text(encoding='utf-8'))
    cfg.setdefault('obs', {}).setdefault('password', '')
    cfg['monitor']['rules'].setdefault('audio_override', False)
    cfg['monitor']['rules'].setdefault('audio_threshold_db', -45.0)
    cfg['monitor']['rules'].setdefault('audio_hold_seconds', 8.0)
    cfg['monitor'].setdefault('audio_source_name', '')
    notifications = cfg.setdefault('notifications', {})
    for key, default in NOTIFICATION_DEFAULTS.items():
        notifications.setdefault(key, default)


    cfg.setdefault('stream', {}).setdefault('selected_profile', '')
    telegram_cfg = cfg.setdefault('telegram', {})
    users = telegram_cfg.setdefault('users', {})

    telegram_cfg.setdefault('access_requests', {})
    telegram_cfg.setdefault('access_request_last_at', {})
    telegram_cfg.setdefault('user_info', {})
    if not admin_id:
        admins = [uid for uid, role in users.items() if role == 'admin']
        if not admins:
            raise SystemExit('Укажите ADMIN_TELEGRAM_ID в .env (или admin в старом config.json)')
        admin_id = admins[0]
    if not admin_id.isdecimal() or int(admin_id) < 1:
        raise SystemExit('ADMIN_TELEGRAM_ID должен быть положительным числом')
    users[admin_id] = 'admin'
    cfg['monitor'].setdefault('collection_name', '')
    validate_config(cfg)
    save_json(settings_file, cfg)
    return cfg, admin_id


def validate_config(cfg: dict) -> None:
    m = cfg['monitor']
    if not 8 <= int(m['screenshot_width']) <= 4096 or not 8 <= int(m['screenshot_height']) <= 4096:
        raise ValueError('Неверный размер скриншота')
    l, t, r, b = m['crop']
    if not (0 <= l < r <= 1 and 0 <= t < b <= 1):
        raise ValueError('Неверная область crop')
    for key, (lo, hi, typ) in RULE_LIMITS.items():
        val = m['rules'][key]
        if not ((type(val) is int if typ is int else type(val) in (int, float)) and lo <= val <= hi):
            raise ValueError(f'Неверный параметр: {key}')
    if any(type(m['rules'][k]) is not bool for k in ('black', 'uniform', 'freeze', 'audio_override')):
        raise ValueError('Неверные логические параметры детектора')
    if not all(k.isdecimal() and v in ROLES for k, v in cfg['telegram']['users'].items()):
        raise ValueError('Неверные Telegram ID/роли')
    for field in ('access_requests', 'access_request_last_at', 'user_info'):
        if not isinstance(cfg['telegram'].get(field), dict):
            raise ValueError(f'Некорректные данные доступа: {field}')
    stream = cfg.get('stream')
    if not isinstance(stream, dict) or not isinstance(stream.get('selected_profile'), str):
        raise ValueError('Неверная настройка профиля трансляции')
    notification_cfg = cfg.get('notifications', NOTIFICATION_DEFAULTS)
    if not isinstance(notification_cfg, dict):
        raise ValueError('Некорректные настройки уведомлений')
    for key, (low, high) in NOTIFICATION_LIMITS.items():
        value = notification_cfg.get(key)
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f'Некорректный параметр уведомлений: {key}')


class StatusNotifier:


    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = asyncio.Lock()
        self.last_render_date = datetime.now().astimezone().date().isoformat()
        self.data = {
            'status_message_ids': {},
            'last_push_at': {},
            'pending_deletions': [],
            'last_event': 'Событий пока нет',
            'last_event_at': None,
            'failure_date': '',
            'failure_count': 0,
            'recent_events': [],
        }
        if path.exists():
            saved = json.loads(path.read_text(encoding='utf-8'))
            if isinstance(saved, dict):
                for key in self.data:
                    if key in saved and type(saved[key]) is type(self.data[key]):
                        self.data[key] = saved[key]

    def save(self) -> None:
        save_json(self.path, self.data)

    @staticmethod
    def admins(ctrl: Controller) -> list[str]:
        return [uid for uid, role in ctrl.config['telegram']['users'].items()
                if role == 'admin']

    def board_text(self, ctrl: Controller) -> str:
        if ctrl.last_validation_error:
            label = '⚠️ Некорректные назначения OBS'
        elif ctrl.last_error:
            label = '⚠️ Ошибка мониторинга OBS'
        elif not ctrl.state['enabled']:
            label = '⏹ Автоматика выключена'
        elif ctrl.state['owned_fallback']:
            label = '🔴 Нет сигнала — включена пауза'
        else:
            label = '🟢 Мониторинг работает'

        scene = ctrl.last_known_scene or 'не определена (см. /status)'
        date = datetime.now().astimezone().date().isoformat()
        failures = self.data['failure_count'] if self.data['failure_date'] == date else 0
        when = self.data['last_event_at']
        timestamp = (datetime.fromtimestamp(when).astimezone().strftime('%d.%m %H:%M:%S %Z')
                     if when is not None else '—')
        if ctrl.last_stream_active is None:
            stream_label = 'не проверена'
        elif ctrl.last_stream_reconnecting:
            stream_label = 'переподключение'
        else:
            stream_label = 'В ЭФИРЕ' if ctrl.last_stream_active else 'выключена'
        stream_profile = ctrl.last_stream_profile or 'неизвестен'
        return (
            '📌 OBS Control — состояние\n\n'
            f'{label}\n'
            f'🎬 Последняя известная сцена: {scene}\n'
            f'📡 Трансляция (последняя проверка): {stream_label}\n'
            f'👤 Профиль OBS: {stream_profile}\n'
            f"🤖 Автоматика: {'ВКЛ' if ctrl.state['enabled'] else 'ВЫКЛ'}\n"
            f'🔴 Переключений на паузу сегодня: {failures}\n\n'
            f'🕒 Последнее событие: {timestamp}\n'
            f"{str(self.data['last_event'])[:600]}\n\n"
            'Подробности: /status'
        )[:4096]

    async def _update_one(self, bot: Bot, uid: str, text: str) -> None:
        ids = self.data['status_message_ids']
        message_id = ids.get(uid)
        if isinstance(message_id, int) and message_id > 0:
            try:
                await bot.edit_message_text(chat_id=int(uid), message_id=message_id, text=text)
                return
            except TelegramBadRequest as exc:
                reason = str(exc).lower()
                if 'message is not modified' in reason:
                    return

                if not any(pattern in reason for pattern in (
                    'message to edit not found', "message can't be edited",
                    'message_id_invalid', 'message not found',
                )):
                    LOG.warning('Status edit failed for %s: %s', uid, type(exc).__name__)
                    return
            except TelegramAPIError as exc:
                LOG.warning('Status edit failed for %s: %s', uid, type(exc).__name__)
                return
        try:
            sent = await bot.send_message(chat_id=int(uid), text=text,
                                          disable_notification=True)
            ids[uid] = sent.message_id
            self.save()
            try:
                await bot.pin_chat_message(chat_id=int(uid), message_id=sent.message_id,
                                           disable_notification=True)
            except TelegramAPIError as exc:

                LOG.warning('Could not pin status for %s: %s', uid, type(exc).__name__)
        except TelegramAPIError as exc:
            LOG.warning('Status delivery failed for %s: %s', uid, type(exc).__name__)

    async def _update_all_locked(self, ctrl: Controller, bot: Bot) -> None:
        text = self.board_text(ctrl)
        for uid in self.admins(ctrl):
            await self._update_one(bot, uid, text)

    async def update_all(self, ctrl: Controller, bot: Bot) -> None:

        async with self.lock:
            await self._update_all_locked(ctrl, bot)
            self.last_render_date = datetime.now().astimezone().date().isoformat()

    async def remove_admin(self, bot: Bot, uid: str) -> None:

        async with self.lock:
            message_id = self.data['status_message_ids'].pop(uid, None)
            self.data['last_push_at'].pop(uid, None)
            self.save()
            if not isinstance(message_id, int):
                return
            try:
                await bot.unpin_chat_message(chat_id=int(uid), message_id=message_id)
            except TelegramAPIError:
                pass

            try:
                await bot.delete_message(chat_id=int(uid), message_id=message_id)
            except TelegramAPIError:
                pass

    async def event(self, ctrl: Controller, bot: Bot, message: str,
                    *, kind: str = 'warning') -> None:


        async with self.lock:
            now = time.time()
            self.data['last_event'] = message[:600]
            self.data['last_event_at'] = now
            history = self.data['recent_events']
            history.append({'at': now, 'kind': kind, 'text': message[:600]})
            del history[:-NOTIFICATION_HISTORY_LIMIT]
            if kind == 'fallback':
                today = datetime.now().astimezone().date().isoformat()
                if self.data['failure_date'] != today:
                    self.data['failure_date'] = today
                    self.data['failure_count'] = 0
                self.data['failure_count'] += 1
            self.save()
            await self._update_all_locked(ctrl, bot)
            self.last_render_date = datetime.now().astimezone().date().isoformat()


            if kind in ('recovered', 'stream'):
                return
            for uid in self.admins(ctrl):
                last = float(self.data['last_push_at'].get(uid, 0))
                if now - last < ctrl.notification_settings['cooldown_seconds']:
                    continue
                try:
                    sent = await bot.send_message(chat_id=int(uid), text=message,
                                                  disable_notification=False)
                except TelegramAPIError as exc:
                    LOG.warning('Alert delivery failed for %s: %s', uid, type(exc).__name__)
                    continue
                self.data['last_push_at'][uid] = time.time()
                self.data['pending_deletions'].append({
                    'chat_id': int(uid), 'message_id': sent.message_id,
                    'delete_at': time.time() + ctrl.notification_settings['ttl_seconds'],
                })

                self.save()

    async def delete_due(self, bot: Bot) -> None:
        async with self.lock:
            now = time.time()
            remaining = []
            for item in self.data['pending_deletions']:
                if float(item['delete_at']) > now:
                    remaining.append(item)
                    continue
                try:
                    await bot.delete_message(chat_id=int(item['chat_id']),
                                             message_id=int(item['message_id']))
                except TelegramForbiddenError:

                    pass
                except TelegramBadRequest as exc:
                    reason = str(exc).lower()
                    if not any(part in reason for part in (
                        'message to delete not found', "message can't be deleted",
                        'message not found',
                    )):
                        remaining.append(item)
                except TelegramAPIError:

                    remaining.append(item)
            if len(remaining) != len(self.data['pending_deletions']):
                self.data['pending_deletions'] = remaining
                self.save()

    async def cleanup_loop(self, ctrl: Controller, bot: Bot) -> None:
        while True:
            try:
                await self.delete_due(bot)
                current_day = datetime.now().astimezone().date().isoformat()
                if current_day != self.last_render_date:
                    await self.update_all(ctrl, bot)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                LOG.warning('Alert cleanup failed: %s', type(exc).__name__)
            await asyncio.sleep(ctrl.notification_settings['cleanup_interval_seconds'])


class Controller:
    def __init__(self, cfg: dict, bootstrap_admin: str) -> None:
        self.config = cfg
        self.bootstrap_admin = bootstrap_admin
        telegram_cfg = cfg.setdefault('telegram', {})
        telegram_cfg.setdefault('access_requests', {})
        telegram_cfg.setdefault('access_request_last_at', {})
        telegram_cfg.setdefault('user_info', {})
        self.monitor = cfg['monitor']
        self.monitor.setdefault('audio_source_name', '')
        self.stream_settings = cfg.setdefault('stream', {'selected_profile': ''})
        self.last_stream_active: bool | None = None
        self.last_stream_reconnecting: bool = False
        self.last_stream_profile: str | None = None
        self.notification_settings = cfg.setdefault('notifications', {})
        for key, default in NOTIFICATION_DEFAULTS.items():
            self.notification_settings.setdefault(key, default)
        self.obs = OBSClient(cfg['obs'])
        self.detector = FrameDetector()
        self.action_lock = asyncio.Lock()
        self.access_lock = asyncio.Lock()

        self.monitor_wakeup = asyncio.Event()
        self.notifications = StatusNotifier(DATA_ROOT / 'notifications.json')
        self.last_known_scene: str | None = None
        self.notification_cleanup_task: asyncio.Task | None = None
        initial = {
            'enabled': bool(self.monitor.get('auto_enabled_on_first_run', False)),
            'owned_fallback': False,
            'rules': self.monitor['rules'].copy(),
        }
        self.state_file = DATA_ROOT / 'state.json'
        if self.state_file.exists():
            saved = json.loads(self.state_file.read_text(encoding='utf-8'))
            initial['enabled'] = bool(saved.get('enabled', initial['enabled']))
            initial['owned_fallback'] = bool(saved.get('owned_fallback', False))
            initial['rules'].update(saved.get('rules', {}))
        initial['rules'].setdefault('audio_override', False)
        initial['rules'].setdefault('audio_threshold_db', -45.0)
        initial['rules'].setdefault('audio_hold_seconds', 8.0)
        self.state = initial
        self.last_inspection: Inspection | None = None
        self.last_error: str | None = None
        self.obs_offline = False
        self.bad_count = 0
        self.good_count = 0
        self.last_error_notice_at = 0.0
        self.last_error_signature: str | None = None
        self.last_validation_error: str | None = None
        self.seen_valid_binding = False
        self.monitor_task: asyncio.Task | None = None

    def save(self) -> None:
        save_json(self.state_file, self.state)

    def save_settings(self) -> None:
        save_json(DATA_ROOT / 'settings.json', self.config)

    def set_notification_interval(self, key: str, value: str) -> int:

        parsed = notification_interval(key, value)
        previous = self.notification_settings[key]
        self.notification_settings[key] = parsed
        try:
            self.save_settings()
        except Exception:
            self.notification_settings[key] = previous
            raise
        return parsed

    async def set_rule_value(self, key: str, text: str) -> float | int:

        parsed = parse_rule_value(key, text)
        async with self.action_lock:
            old_value = self.state['rules'][key]
            self.state['rules'][key] = parsed
            try:
                self.save()
            except Exception:
                self.state['rules'][key] = old_value
                raise
            self.reset_counters()
            if key == 'interval_seconds':
                self.monitor_wakeup.set()
        return parsed

    async def assign_audio_source(self, name: str) -> None:
        async with self.action_lock:
            names = await asyncio.to_thread(self.obs.all_input_names)
            if name and name not in names:
                raise ValueError('Источник звука больше не существует. Обновите список.')
            old_name = self.monitor.get('audio_source_name', '')
            self.monitor['audio_source_name'] = name
            try:
                self.save_settings()
            except Exception:
                self.monitor['audio_source_name'] = old_name
                raise
            await asyncio.to_thread(self.obs.stop_audio_meter)
            self.reset_counters()

    def audio_allowed(self) -> bool:
        rules = self.state['rules']
        source = self.monitor.get('audio_source_name', '')
        return (bool(rules.get('audio_override')) and bool(source)
                and self.obs.audio_is_present(source, float(rules['audio_threshold_db']),
                                              float(rules.get('audio_hold_seconds', 8))))

    async def audio_override_active(self) -> bool:
        if not self.audio_allowed():
            return False
        try:
            reply = await asyncio.to_thread(self.obs.request, 'get_input_mute',
                                            self.monitor['audio_source_name'])
            return not bool(reply.input_muted)
        except Exception:
            return False

    async def diagnose_audio(self) -> str:
        async with self.action_lock:
            source = self.monitor.get('audio_source_name', '')
            if not source:
                return '🎤 Источник звука не выбран. Откройте «⚙️ Правила» и выберите его.'
            rules = self.state['rules']
            threshold = float(rules.get('audio_threshold_db', -45))
            hold = float(rules.get('audio_hold_seconds', 8))
            try:
                await asyncio.to_thread(self.obs.ensure_audio_meter, source)
                await asyncio.sleep(1.5)
                status = self.obs.audio_status(source, threshold, hold)
                mute_error = False
                try:
                    muted = await asyncio.to_thread(self.obs.request, 'get_input_mute', source)
                    is_muted = bool(muted.input_muted)
                except Exception as exc:
                    if is_obs_connection_failure(exc):
                        raise
                    mute_error = True
                    is_muted = False
                peak = status['peak_db']
                peak_text = f'{peak:.1f} дБ' if peak is not None else 'нет показаний'
                if mute_error:
                    verdict = '⚠️ Не удаётся проверить mute выбранного источника. Аудиоисключение не сработает.'
                elif is_muted:
                    verdict = '⛔ Источник заглушён в OBS.'
                elif not status['events_recent']:
                    verdict = '⚠️ Бот не получает события измерителя OBS. Проверьте WebSocket.'
                elif not status['source_recent']:
                    verdict = '⚠️ События приходят, но выбранный источник не присутствует в измерителе.'
                elif peak is None:
                    verdict = '⚠️ Источник есть в событиях, но нет корректных показаний уровня.'
                elif peak < threshold:
                    verdict = '🔇 Сигнал ниже установленного порога.'
                else:
                    verdict = '✅ Звук обнаружен выше порога.'
                if not rules.get('audio_override', False):
                    verdict += '\nПравило сейчас выключено.'
                return (f'🔊 Проверка звука OBS\n\nИсточник: {source}\n'
                        f'Пик за последние {hold:g} сек: {peak_text}\n'
                        f'Порог: {threshold:g} дБ\n'
                        f'События OBS: {"есть" if status["events_recent"] else "нет"}\n'
                        f'Показания источника: {"есть" if status["source_recent"] else "нет"}\n\n'
                        f'{verdict}\n\nДля проверки говорите или стучите в микрофон, пока идёт измерение.')
            finally:
                if not self.state['enabled']:
                    await asyncio.to_thread(self.obs.stop_audio_meter)

    def reset_counters(self) -> None:
        self.bad_count = 0
        self.good_count = 0
        self.detector.reset()

    def set_auto(self, enabled: bool) -> None:
        self.state['enabled'] = enabled

        self.state['owned_fallback'] = False
        self.reset_counters()
        self.save()

    def role(self, event: TelegramEvent) -> str | None:
        if isinstance(event, CallbackQuery):
            user = event.from_user
            chat = event.message.chat if event.message is not None else None
        else:
            user = event.from_user
            chat = event.chat
        if user is None or chat is None or chat.type != ChatType.PRIVATE:
            return None
        return self.config['telegram']['users'].get(str(user.id))

    @property
    def access_requests(self) -> dict:
        return self.config['telegram']['access_requests']

    def get_user_info(self, uid: str) -> dict:
        return self.config['telegram']['user_info'].get(uid, {})

    async def update_known_user(self, user) -> None:

        uid = str(user.id)
        if uid not in self.config['telegram']['users']:
            return
        info = {'name': str(getattr(user, 'full_name', '') or '')[:60],
                'username': str(getattr(user, 'username', '') or '')[:32]}
        if self.config['telegram']['user_info'].get(uid) != info:
            self.config['telegram']['user_info'][uid] = info
            try:
                self.save_settings()
            except OSError:
                LOG.warning('Could not save user display name')

    async def request_access(self, bot: Bot, user) -> str:
        uid = valid_user_id(str(user.id))
        now = time.time()
        async with self.access_lock:
            if uid in self.config['telegram']['users']:
                return 'У вас уже есть доступ. Откройте /menu.'
            if uid in self.access_requests:
                return '⏳ Заявка уже отправлена и ожидает решения администратора.'
            last_at = self.config['telegram']['access_request_last_at']

            for old_uid, stamp in list(last_at.items()):
                if not isinstance(stamp, (int, float)) or now - stamp > 86400:
                    last_at.pop(old_uid, None)
            last = float(last_at.get(uid, 0))
            if now - last < ACCESS_REQUEST_COOLDOWN_SECONDS:
                remaining = max(1, int((ACCESS_REQUEST_COOLDOWN_SECONDS - (now - last) + 59) // 60))
                return f'Повторная заявка будет доступна через {remaining} мин.'
            if len(self.access_requests) >= ACCESS_MAX_PENDING:
                return 'Слишком много необработанных заявок. Обратитесь к администратору.'
            request = {
                'name': str(getattr(user, 'full_name', '') or '')[:60],
                'username': str(getattr(user, 'username', '') or '')[:32],
                'created_at': now, 'notices': {},
            }
            self.access_requests[uid] = request
            last_at[uid] = now
            try:
                self.save_settings()
            except Exception:
                self.access_requests.pop(uid, None)
                last_at.pop(uid, None)
                raise
            admins = [admin for admin, role in self.config['telegram']['users'].items()
                      if role == 'admin']
        label = access_display(uid, request)
        text = (f'👤 Заявка на доступ к OBS Control\n'
                f'Пользователь: {label}\nTelegram ID: {uid}\n\n'
                'Выберите роль или отклоните заявку:')
        buttons = access_request_buttons(uid)

        for admin_uid in admins:
            try:
                sent = await bot.send_message(int(admin_uid), text, reply_markup=buttons)
            except TelegramAPIError as exc:
                LOG.warning('Access request delivery failed for %s: %s', admin_uid, type(exc).__name__)
                continue
            async with self.access_lock:
                current = self.access_requests.get(uid)
                if current is not None:
                    current['notices'][admin_uid] = sent.message_id
                    self.save_settings()
                else:
                    try:
                        await bot.delete_message(chat_id=int(admin_uid), message_id=sent.message_id)
                    except TelegramAPIError:
                        pass
        return '✅ Заявка отправлена. Администратор выберет роль или отклонит запрос.'

    async def _clear_access_notices(self, bot: Bot, notices: dict) -> None:
        for admin_uid, message_id in notices.items():
            try:
                await bot.delete_message(chat_id=int(admin_uid), message_id=int(message_id))
            except TelegramAPIError:
                pass

    async def grant_access(self, bot: Bot, uid: str, new_role: str,
                           *, actor_uid: str | None = None,
                           require_request: bool = False) -> tuple[str | None, dict]:
        uid = valid_user_id(uid)
        if new_role not in ROLES:
            raise ValueError('Неизвестная роль')
        if uid == self.bootstrap_admin and new_role != 'admin':
            raise PermissionError('Первого администратора нельзя понизить')
        if uid == actor_uid and new_role != 'admin':
            raise PermissionError('Нельзя понизить собственную роль')
        async with self.access_lock:
            if require_request and uid not in self.access_requests:
                raise ValueError('Заявка уже обработана или отозвана')
            users = self.config['telegram']['users']
            previous = users.get(uid)
            request = self.access_requests.get(uid)
            old_info = self.config['telegram']['user_info'].get(uid)
            users[uid] = new_role
            if request is not None:
                self.config['telegram']['user_info'][uid] = {
                    'name': request['name'], 'username': request['username']}
                del self.access_requests[uid]
            try:
                self.save_settings()
            except Exception:
                if previous is None:
                    users.pop(uid, None)
                else:
                    users[uid] = previous
                if request is not None:
                    self.access_requests[uid] = request
                    if old_info is None:
                        self.config['telegram']['user_info'].pop(uid, None)
                    else:
                        self.config['telegram']['user_info'][uid] = old_info
                raise
            notices = dict(request.get('notices', {})) if request else {}
        await self._clear_access_notices(bot, notices)
        if previous == 'admin' and new_role != 'admin':
            await self.notifications.remove_admin(bot, uid)
        elif new_role == 'admin' and previous != 'admin':
            await self.refresh_status(bot)
        try:
            await bot.send_message(chat_id=int(uid),
                                   text=f'✅ Доступ к OBS Control: {ACCESS_ROLE_LABELS[new_role]}. Откройте /menu.')
        except TelegramAPIError:

            pass
        return previous, notices

    async def reject_access(self, bot: Bot, uid: str) -> dict:
        uid = valid_user_id(uid)
        async with self.access_lock:
            request = self.access_requests.pop(uid, None)
            if request is None:
                raise ValueError('Заявка уже обработана или отозвана')
            try:
                self.save_settings()
            except Exception:
                self.access_requests[uid] = request
                raise
            notices = dict(request.get('notices', {}))
        await self._clear_access_notices(bot, notices)
        try:
            await bot.send_message(chat_id=int(uid),
                                   text='❌ Заявка на доступ отклонена. Повторить запрос можно позже.')
        except TelegramAPIError:
            pass
        return notices

    async def revoke_access(self, bot: Bot, uid: str, *, actor_uid: str | None = None) -> str:
        uid = valid_user_id(uid)
        if uid == self.bootstrap_admin:
            raise PermissionError('Первого администратора нельзя удалить')
        if uid == actor_uid:
            raise PermissionError('Нельзя удалить собственный доступ')
        async with self.access_lock:
            users = self.config['telegram']['users']
            previous = users.pop(uid, None)
            if previous is None:
                raise ValueError('Пользователь уже удалён')
            previous_info = self.config['telegram']['user_info'].pop(uid, None)
            try:
                self.save_settings()
            except Exception:
                users[uid] = previous
                if previous_info is not None:
                    self.config['telegram']['user_info'][uid] = previous_info
                raise
        if previous == 'admin':
            await self.notifications.remove_admin(bot, uid)
        try:
            await bot.send_message(chat_id=int(uid), text='⛔ Ваш доступ к OBS Control отозван.')
        except TelegramAPIError:
            pass
        return previous

    async def notify_admins(self, bot: Bot, message: str, *, kind: str = 'warning') -> None:
        await self.notifications.event(self, bot, message, kind=kind)

    async def refresh_status(self, bot: Bot) -> None:
        await self.notifications.update_all(self, bot)

    async def set_connection(self, field: str, value: str) -> None:
        parsed = connection_value(field, value)
        async with self.action_lock:
            self.set_auto(False)
            changed = self.config['obs'].get(field) != parsed
            self.config['obs'][field] = parsed
            if changed and field in ('host', 'port'):

                self.monitor['collection_name'] = ''
                for key in ASSIGNMENTS.values():
                    self.monitor[key] = ''
            await asyncio.to_thread(self.obs.configure, self.config['obs'])
            self.save_settings()
            self.last_error = None
            self.last_validation_error = None
            self.seen_valid_binding = False
            self.obs_offline = False
            self.monitor_wakeup.set()

    async def validate_bindings(self) -> str | None:

        _, collection = await asyncio.to_thread(self.obs.collections)
        scenes = await asyncio.to_thread(self.obs.scenes)
        browsers = await asyncio.to_thread(self.obs.browser_sources)
        return binding_issue(self.monitor, collection, scenes, browsers)

    async def assign(self, field: str, value: str, expected_collection_hash: str) -> None:
        async with self.action_lock:
            _, collection = await asyncio.to_thread(self.obs.collections)
            if name_id(collection) != expected_collection_hash:
                raise ValueError('Коллекция сцен изменилась. Откройте выбор заново.')
            if field == 'source':
                options = await asyncio.to_thread(self.obs.browser_sources)
            else:
                options = await asyncio.to_thread(self.obs.scenes)
            if value not in options:
                raise ValueError('Источник или сцена больше не существует. Обновите список.')

            if self.monitor.get('collection_name') != collection:
                for key in ASSIGNMENTS.values():
                    self.monitor[key] = ''
                self.monitor['collection_name'] = collection
            key = ASSIGNMENTS[field]
            other = 'fallback_scene' if key == 'normal_scene' else 'normal_scene'
            if field != 'source' and value == self.monitor.get(other):
                raise ValueError('Основная сцена и пауза должны отличаться')
            self.monitor[key] = value
            self.set_auto(False)
            self.save_settings()
            self.last_validation_error = None
            self.seen_valid_binding = False

    async def enable_auto(self) -> None:
        async with self.action_lock:
            issue = await self.validate_bindings()
            if issue:
                raise ValueError('Нельзя включить автоматику: ' + issue)
            current = await asyncio.to_thread(self.obs.current_scene)
            if current != self.monitor['normal_scene']:
                raise ValueError('Для включения автоматики сначала выберите основную сцену OBS')
            self.set_auto(True)
            self.seen_valid_binding = True
            self.last_validation_error = None

    async def status(self) -> str:
        obs_status = 'не проверено'
        try:
            scene = await asyncio.to_thread(self.obs.current_scene)
            _, profile = await asyncio.to_thread(self.obs.profiles)
            _, collection = await asyncio.to_thread(self.obs.collections)
            stream = await asyncio.to_thread(self.obs.stream_status)
            self._remember_stream(profile, stream)
            stream_state = ('переподключение' if stream['reconnecting'] else
                            'В ЭФИРЕ' if stream['active'] else 'остановлена')
            obs_status = (f'подключено\nСцена: {scene}\nПрофиль: {profile}'
                          f'\nКоллекция: {collection}\nТрансляция: {stream_state}')
        except Exception as e:
            obs_status = ('OBS недоступен' if is_obs_connection_failure(e) else
                          f'нет связи ({type(e).__name__}: {str(e)[:120]})')
        i = self.last_inspection
        frame = ('Нет успешной проверки' if i is None else
                 f"{'ПРОБЛЕМА: ' + i.reason if i.is_bad else 'изображение нормальное'}; "
                 f'чёрных {i.black_fraction:.1%}; σ={i.stddev:.1f}; '
                 f'неподвижность {i.frozen_for:.1f} сек')
        m = self.monitor
        return (
            f'OBS: {obs_status}\nАвтоматика: {"ВКЛ" if self.state["enabled"] else "ВЫКЛ"}\n'
            f'Сохранённая коллекция: {m.get("collection_name") or "не назначена"}\n'
            f'Источник: {m.get("source_name") or "не назначен"}\n'
            f'Основная сцена: {m.get("normal_scene") or "не назначена"}\n'
            f'Пауза: {m.get("fallback_scene") or "не назначена"}\n'
            f'Кадр: {frame}\n'
            f'Аудиоисключение: {"ВКЛ" if self.state["rules"].get("audio_override") else "ВЫКЛ"}; '
            f'источник: {m.get("audio_source_name") or "не выбран"}; '
            f'измеренный звук: {"есть" if self.audio_allowed() else "нет"}\n'
            f'Плохих/хороших подряд: {self.bad_count}/{self.good_count}\n'
            f'Проверка назначений: {self.last_validation_error or "нет обнаруженных ошибок"}\n'
            f'Ошибка мониторинга: {self.last_error or "нет"}'
        )

    async def manual_scene(self, name: str) -> None:
        async with self.action_lock:
            names = await asyncio.to_thread(self.obs.scenes)
            if name not in names:
                raise ValueError('Сцена больше не существует')
            self.set_auto(False)
            await asyncio.to_thread(self.obs.request, 'set_current_program_scene', name)
            self.last_known_scene = name

    async def manual_profile_or_collection(self, kind: str, name: str) -> None:
        async with self.action_lock:
            if kind == 'profile':
                names, current = await asyncio.to_thread(self.obs.profiles)
                if name != current:
                    stream_status = await asyncio.to_thread(self.obs.stream_status)
                    if stream_status['active'] or stream_status['reconnecting']:
                        raise ValueError('Нельзя переключить профиль во время трансляции.')
                    if await asyncio.to_thread(self.obs.record_status):
                        raise ValueError('Нельзя переключить профиль во время записи.')
                method = 'set_current_profile'
            else:
                names, _ = await asyncio.to_thread(self.obs.collections)
                method = 'set_current_scene_collection'
            if name not in names:
                raise ValueError('Объект больше не существует')
            self.set_auto(False)
            await asyncio.to_thread(self.obs.request, method, name)
            self.last_known_scene = None
            self.last_validation_error = None
            self.seen_valid_binding = False

    def _remember_stream(self, profile: str, status: dict) -> None:
        self.last_stream_profile = profile
        self.last_stream_active = bool(status['active'])
        self.last_stream_reconnecting = bool(status['reconnecting'])

    async def stream_overview(self) -> tuple[list[str], str, dict]:

        async with self.action_lock:
            names, current = await asyncio.to_thread(self.obs.profiles)
            status = await asyncio.to_thread(self.obs.stream_status)
            self._remember_stream(current, status)
            return names, current, status

    async def select_stream_profile(self, profile_hash: str) -> str:

        async with self.action_lock:
            names, current = await asyncio.to_thread(self.obs.profiles)
            status = await asyncio.to_thread(self.obs.stream_status)
            self._remember_stream(current, status)
            if status['active'] or status['reconnecting']:
                raise ValueError('Пока идёт трансляция, профиль менять нельзя. Остановите эфир.')
            chosen = next((name for name in names if name_id(name) == profile_hash), None)
            if chosen is None:
                raise ValueError('Профиль изменился или удалён. Обновите список.')
            previous = self.stream_settings['selected_profile']
            self.stream_settings['selected_profile'] = chosen
            try:
                self.save_settings()
            except Exception:
                self.stream_settings['selected_profile'] = previous
                raise
            return chosen

    async def start_stream(self, expected_profile_hash: str) -> tuple[str, bool]:


        async with self.action_lock:
            target = self.stream_settings.get('selected_profile', '')
            if not target or name_id(target) != expected_profile_hash:
                raise ValueError('Выбранный профиль изменился. Начните запуск заново.')
            names, current = await asyncio.to_thread(self.obs.profiles)
            if target not in names:
                raise ValueError('Профиль удалён из OBS. Выберите другой.')
            status = await asyncio.to_thread(self.obs.stream_status)
            self._remember_stream(current, status)
            if status['active'] or status['reconnecting']:
                raise ValueError(f'Трансляция уже запущена (профиль «{current}»).')
            if current != target:
                recording = await asyncio.to_thread(self.obs.record_status)
                if recording:
                    raise ValueError('OBS ведёт запись. Остановите запись перед сменой профиля.')

                self.set_auto(False)
                await asyncio.to_thread(self.obs.request, 'set_current_profile', target)
                _, switched = await asyncio.to_thread(self.obs.profiles)
                if switched != target:
                    raise ValueError('OBS не подтвердил смену профиля. Запуск отменён.')
                self.last_known_scene = None
                self.last_validation_error = None
                self.seen_valid_binding = False


            _, current_now = await asyncio.to_thread(self.obs.profiles)
            if current_now != target:
                raise ValueError('Профиль OBS сменился перед запуском. Запуск отменён.')
            status_now = await asyncio.to_thread(self.obs.stream_status)
            if status_now['active'] or status_now['reconnecting']:
                raise ValueError('OBS уже начал трансляцию. Повторный запуск отменён.')
            await asyncio.to_thread(self.obs.request, 'start_stream')


            for attempt in range(4):
                status = await asyncio.to_thread(self.obs.stream_status)
                if status['active'] or status['reconnecting']:
                    break
                if attempt < 3:
                    await asyncio.sleep(0.5)
            self._remember_stream(target, status)
            return target, bool(status['active'] or status['reconnecting'])

    async def stop_stream(self, expected_profile_hash: str) -> tuple[str, bool]:

        async with self.action_lock:
            _, current = await asyncio.to_thread(self.obs.profiles)
            if name_id(current) != expected_profile_hash:
                raise ValueError('Профиль OBS сменился. Подтвердите остановку заново.')
            status = await asyncio.to_thread(self.obs.stream_status)
            self._remember_stream(current, status)
            if not (status['active'] or status['reconnecting']):
                raise ValueError('Трансляция уже остановлена.')
            await asyncio.to_thread(self.obs.request, 'stop_stream')
            for attempt in range(4):
                status = await asyncio.to_thread(self.obs.stream_status)
                if not (status['active'] or status['reconnecting']):
                    break
                if attempt < 3:
                    await asyncio.sleep(0.5)
            self._remember_stream(current, status)
            return current, not (status['active'] or status['reconnecting'])

    async def toggle_source(self, scene: str, item_id: int) -> tuple[str, bool]:
        async with self.action_lock:
            if await asyncio.to_thread(self.obs.current_scene) != scene:
                raise ValueError('Сцена изменилась: откройте /sources заново')
            items = await asyncio.to_thread(self.obs.scene_items, scene)
            item = next((i for i in items if i['sceneItemId'] == item_id), None)
            if item is None:
                raise ValueError('Элемент сцены больше не существует')
            new_state = not bool(item['sceneItemEnabled'])
            await asyncio.to_thread(self.obs.set_item_visible, scene, item_id, new_state)
            return item['sourceName'], new_state

    async def reload_browser_source(self, source: str, collection_hash: str) -> None:

        async with self.action_lock:
            _, collection = await asyncio.to_thread(self.obs.collections)
            if name_id(collection) != collection_hash:
                raise ValueError('Коллекция OBS изменилась. Откройте список источников заново.')
            sources = await asyncio.to_thread(self.obs.browser_sources)
            if source not in sources:
                raise ValueError('Browser Source больше не существует. Обновите список.')

            await asyncio.to_thread(self.obs.request, 'press_input_properties_button',
                                    source, 'refreshnocache')
            if (self.monitor.get('collection_name') == collection
                    and self.monitor.get('source_name') == source):

                self.reset_counters()

    async def reload_all_browser_sources(self, collection_hash: str) -> int:

        async with self.action_lock:
            _, collection = await asyncio.to_thread(self.obs.collections)
            if name_id(collection) != collection_hash:
                raise ValueError('Коллекция OBS изменилась. Откройте список источников заново.')
            sources = await asyncio.to_thread(self.obs.browser_sources)
            if not sources:
                raise ValueError('В текущей коллекции OBS нет Browser Source.')
            refreshed_monitored = False
            try:
                for source in sources:
                    await asyncio.to_thread(self.obs.request, 'press_input_properties_button',
                                            source, 'refreshnocache')
                    refreshed_monitored |= (self.monitor.get('collection_name') == collection
                                            and self.monitor.get('source_name') == source)
            finally:

                if refreshed_monitored:
                    self.reset_counters()
            return len(sources)

    async def tick(self, bot: Bot) -> None:


        async with self.action_lock:
            await self._tick_locked(bot)

    async def _tick_locked(self, bot: Bot) -> None:
        try:


            has_binding = any(self.monitor.get(k) for k in ASSIGNMENTS.values())
            if not self.state['enabled'] and self.obs.audio_events is not None:
                await asyncio.to_thread(self.obs.stop_audio_meter)
            if not has_binding and not self.state['enabled']:
                return
            issue = await self.validate_bindings()
            if self.obs_offline:


                self.obs_offline = False
                self.last_error = None
                self.last_error_signature = None
                LOG.info('Соединение с OBS восстановлено')
                await self.notify_admins(bot, '🟢 Соединение с OBS восстановлено.',
                                         kind='recovered')
            if issue:
                was_enabled = self.state['enabled']
                if was_enabled:
                    self.set_auto(False)
                should_notify = was_enabled or (self.seen_valid_binding and issue != self.last_validation_error)
                self.last_validation_error = issue
                if should_notify:
                    await self.notify_admins(bot, '⚠️ Назначения OBS недействительны: ' + issue +
                                             '\nАвтоматика отключена. Откройте /setup.')
                self.reset_counters()
                return
            self.seen_valid_binding = True
            had_invalid_bindings = self.last_validation_error is not None
            self.last_validation_error = None
            if had_invalid_bindings:
                await self.refresh_status(bot)
            if not self.state['enabled']:
                return
            scene = await asyncio.to_thread(self.obs.current_scene)
            changed_scene = self.last_known_scene != scene
            self.last_known_scene = scene
            if changed_scene:
                await self.refresh_status(bot)
            normal, pause = self.monitor['normal_scene'], self.monitor['fallback_scene']
            if self.state['owned_fallback']:
                if scene != pause:
                    self.set_auto(False)
                    await self.notify_admins(bot, '⚠️ Сцена изменена извне; автоматика отключена.')
                    return
            elif scene != normal:

                self.reset_counters()
                return
            rules = self.state['rules']
            if rules.get('audio_override') and self.monitor.get('audio_source_name'):
                try:
                    await asyncio.to_thread(self.obs.ensure_audio_meter,
                                            self.monitor['audio_source_name'])
                except Exception as audio_error:
                    LOG.debug('Audio meter unavailable: %s', type(audio_error).__name__)
            elif self.obs.audio_events is not None:
                await asyncio.to_thread(self.obs.stop_audio_meter)
            png = await asyncio.to_thread(self.obs.screenshot, self.monitor['source_name'],
                                          self.monitor['screenshot_width'],
                                          self.monitor['screenshot_height'])
            result = self.detector.inspect(png, rules, self.monitor['crop'])
            self.last_inspection = result
            had_monitor_error = self.last_error is not None
            self.last_error = None
            if had_monitor_error:
                await self.refresh_status(bot)
            sound_allows = result.is_bad and await self.audio_override_active()
            effective_bad = result.is_bad and not sound_allows
            self.bad_count = self.bad_count + 1 if effective_bad else 0
            self.good_count = self.good_count + 1 if not effective_bad else 0
            frozen = (effective_bad and bool(rules['freeze'])
                      and result.frozen_for >= float(rules['freeze_seconds']))
            need_fallback = frozen or (effective_bad and self.bad_count >= rules['bad_checks'])
            if need_fallback and not self.state['owned_fallback']:
                if not self.state['enabled'] or self.state['owned_fallback']:
                    return
                if await self.validate_bindings() or await asyncio.to_thread(self.obs.current_scene) != normal:
                    return
                await asyncio.to_thread(self.obs.request, 'set_current_program_scene', pause)
                self.state['owned_fallback'] = True
                self.last_known_scene = pause
                self.save()
                self.bad_count = 0
                reason = ('видео не меняется (возможное зависание)' if frozen else result.reason)
                await self.notify_admins(bot, f'🔴 {reason}. Переключено на «{pause}».', kind='fallback')
            elif not effective_bad and self.state['owned_fallback'] and self.good_count >= rules['good_checks']:
                if not self.state['enabled'] or not self.state['owned_fallback']:
                    return
                if await self.validate_bindings() or await asyncio.to_thread(self.obs.current_scene) != pause:
                    return
                await asyncio.to_thread(self.obs.request, 'set_current_program_scene', normal)
                self.state['owned_fallback'] = False
                self.last_known_scene = normal
                self.save()
                self.good_count = 0
                await self.notify_admins(bot, f'🟢 Изображение восстановилось: «{normal}».', kind='recovered')
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.obs_offline = is_obs_connection_failure(e)
            self.last_error = ('OBS недоступен' if self.obs_offline else
                               f'{type(e).__name__}: {str(e)[:200]}')
            self.reset_counters()
            try:
                await asyncio.to_thread(self.obs.stop_audio_meter)
            except Exception:
                pass
            now = time.monotonic()
            if self.last_error != self.last_error_signature or now - self.last_error_notice_at > 300:
                self.last_error_signature = self.last_error
                self.last_error_notice_at = now
                LOG.warning('OBS monitor: %s', type(e).__name__)
                if self.state['enabled']:
                    await self.notify_admins(bot, '⚠️ Ошибка мониторинга OBS: ' + self.last_error)

    async def monitor_loop(self, bot: Bot) -> None:
        while True:
            started_at = time.monotonic()
            await self.tick(bot)
            interval = (max(OBS_OFFLINE_RETRY_SECONDS,
                            float(self.state['rules']['interval_seconds']))
                        if self.obs_offline else
                        max(1, float(self.state['rules']['interval_seconds'])))
            delay = max(0.05, started_at + interval - time.monotonic())
            try:
                await asyncio.wait_for(self.monitor_wakeup.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass
            finally:
                self.monitor_wakeup.clear()

async def reply(event: TelegramEvent, text: str, markup: InlineKeyboardMarkup | None = None) -> None:
    if isinstance(event, CallbackQuery):

        if isinstance(event.message, Message):
            try:
                await event.message.edit_text(text, reply_markup=markup)
            except TelegramBadRequest as exc:
                if 'message is not modified' not in str(exc).lower():
                    raise
        else:
            await event.bot.send_message(event.from_user.id, text, reply_markup=markup)
    else:
        await event.answer(text, reply_markup=markup)


async def delete_input_message(message: Message) -> None:

    try:
        await message.delete()
    except TelegramAPIError:

        pass


async def edit_input_prompt(message: Message, state: FSMContext, text: str,
                            markup: InlineKeyboardMarkup | None = None) -> None:


    message_id = (await state.get_data()).get('wizard_message_id')
    if type(message_id) is int and message_id > 0:
        try:
            await message.bot.edit_message_text(text=text, chat_id=message.chat.id,
                                                message_id=message_id, reply_markup=markup)
            return
        except TelegramBadRequest as exc:
            if 'message is not modified' in str(exc).lower():
                return

            if not any(reason in str(exc).lower() for reason in
                       ('message to edit not found', "message can't be edited",
                        'message identifier is not specified')):
                raise
    sent = await message.answer(text, reply_markup=markup)
    await state.update_data(wizard_message_id=sent.message_id)


async def delete_input_prompt(bot: Bot, chat_id: int, message_id: int | None) -> None:
    if type(message_id) is not int or message_id <= 0:
        return
    try:
        await bot.delete_message(chat_id=chat_id, message_id=message_id)
    except TelegramAPIError:

        pass


def menu(role: str) -> InlineKeyboardMarkup:
    buttons = [('📊 Статус', 'go:status')]
    if ROLES[role] >= 2:
        buttons.extend([('🎬 Сцены', 'go:scenes'), ('🧩 Источники', 'go:sources'),
                        ('🤖 Автоматика', 'go:auto'), ('📷 Проверить кадр', 'go:check')])
    if role == 'admin':
        buttons.extend([('🔌 Подключение OBS', 'go:obs'), ('🎯 Назначения', 'go:setup'),
                        ('⚙️ Правила', 'go:rules'), ('👤 Профили', 'go:profiles'),
                        ('📁 Коллекции', 'go:collections'), ('👥 Доступ', 'go:users'),
                        ('🔔 Уведомления', 'go:notifications'),
                        ('📡 Трансляция', 'go:stream')])
    return keyboard(buttons)


async def show_page(ctrl: Controller, event: TelegramEvent, role: str, page: str) -> None:
    rules = ctrl.state['rules']
    if page == 'main':
        await reply(event, f'OBS Control. Ваша роль: {role}', menu(role))
    elif page == 'status':
        await reply(event, await ctrl.status(), keyboard([('◀️ Меню', 'go:main')]))
    elif page == 'obs':
        if role != 'admin':
            raise PermissionError('Только администратор')
        obs_cfg = ctrl.config['obs']
        await reply(event,
                    f"Подключение OBS\nАдрес: {obs_cfg['host']}\nПорт: {obs_cfg['port']}\n"
                    f"Пароль: {'задан' if obs_cfg.get('password') else 'пустой'}\n\n"
                    'Выберите поле для ввода. Пароль ни разу не отображается в ответах. '
                    'Изменение любого поля отключает автоматику.',
                    keyboard([('🌐 Изменить адрес', 'edit:host'),
                              ('🔢 Изменить порт', 'edit:port'),
                              ('🔑 Изменить пароль', 'edit:password'),
                              ('🔍 Проверить связь', 'test:obs'),
                              ('◀️ Меню', 'go:main')]))
    elif page == 'setup':
        if role != 'admin':
            raise PermissionError('Только администратор')
        m = ctrl.monitor
        await reply(event,
                    f"Назначения мониторинга\nКоллекция: {m.get('collection_name') or 'не выбрана'}\n"
                    f"Browser Source: {m.get('source_name') or 'не выбран'}\n"
                    f"Основная сцена: {m.get('normal_scene') or 'не выбрана'}\n"
                    f"Сцена паузы: {m.get('fallback_scene') or 'не выбрана'}\n\n"
                    'Списки запрашиваются непосредственно у OBS. '
                    'При выборе первого элемента из другой коллекции старые назначения сбрасываются. '
                    'Любое переназначение отключает автоматику.',
                    keyboard([('📹 Выбрать Browser Source', 'pick:source'),
                              ('🟢 Выбрать основную сцену', 'pick:normal'),
                              ('⏸ Выбрать сцену паузы', 'pick:fallback'),
                              ('🔎 Проверить назначения', 'test:bindings'),
                              ('◀️ Меню', 'go:main')], cols=1))
    elif page == 'auto':
        if ROLES[role] < 2:
            raise PermissionError('Недостаточно прав')
        await reply(event,
                    f"Автоматика: {'ВКЛ' if ctrl.state['enabled'] else 'ВЫКЛ'}\n"
                    'Перед включением проверяются актуальные сцены и Browser Source. '
                    'Ручное переключение сцены выключает автоматику.',
                    keyboard([('✅ Включить', 'auto:1'), ('⛔ Выключить', 'auto:0'),
                              ('◀️ Меню', 'go:main')]))
    elif page == 'scenes':
        if ROLES[role] < 2:
            raise PermissionError('Недостаточно прав')
        scene = await asyncio.to_thread(ctrl.obs.current_scene)
        names = await asyncio.to_thread(ctrl.obs.scenes)
        buttons = [(('✅ ' if s == scene else '') + s, 'scene:' + name_id(s)) for s in names]
        await reply(event, 'Выберите текущую сцену (ручной выбор отключает автоматику):',
                    keyboard(buttons + [('🔄 Обновить', 'go:scenes'), ('◀️ Меню', 'go:main')]))
    elif page == 'sources':
        if ROLES[role] < 2:
            raise PermissionError('Недостаточно прав')
        scene = await asyncio.to_thread(ctrl.obs.current_scene)
        items = await asyncio.to_thread(ctrl.obs.scene_items, scene)
        buttons = [(('🟢 ' if i['sceneItemEnabled'] else '⚫ ') + i['sourceName'],
                    f"item:{name_id(scene)}:{i['sceneItemId']}") for i in items]
        await reply(event, f'Элементы сцены «{scene}» (переключить видимость):',
                    keyboard(buttons + [('♻️ Перезагрузить Browser Source', 'go:source_refresh'),
                                        ('🔄 Обновить', 'go:sources'), ('◀️ Меню', 'go:main')]))
    elif page == 'source_refresh':
        await show_source_refresh_picker(ctrl, event, role)
    elif page in ('profiles', 'collections'):
        if role != 'admin':
            raise PermissionError('Только администратор')
        names, current = await asyncio.to_thread(
            ctrl.obs.profiles if page == 'profiles' else ctrl.obs.collections)
        key = 'profile:' if page == 'profiles' else 'collection:'
        buttons = [(('✅ ' if s == current else '') + s, key + name_id(s)) for s in names]
        await reply(event, 'Выбор отключит автоматику:',
                    keyboard(buttons + [('🔄 Обновить', 'go:' + page), ('◀️ Меню', 'go:main')]))
    elif page == 'stream':
        if role != 'admin':
            raise PermissionError('Только администратор')
        profiles, current, info = await ctrl.stream_overview()
        await ctrl.refresh_status(event.bot)
        selected = ctrl.stream_settings.get('selected_profile') or 'не выбран'
        if info['reconnecting']:
            state_label = '🟡 Переподключение к платформе'
        elif info['active']:
            state_label = '🔴 ИДЁТ ТРАНСЛЯЦИЯ'
        else:
            state_label = '⚫ Трансляция остановлена'
        text = (f'📡 Управление трансляцией OBS\n\n'
                f'{state_label}\n'
                f'Текущий профиль OBS: {current}\n'
                f'Профиль для следующего запуска: {selected}\n'
                'Выбранный профиль задаёт настройки вещания OBS (платформу, '
                'сервер, ключ потока). Их нужно заранее настроить в OBS.\n\n'
                'При запуске OBS переключится на выбранный профиль, только '
                'если сейчас нет эфира и записи. При смене профиля автоматика '
                'камеры отключается.\n'
                'Проверяйте статус эфира кнопкой «Обновить».')
        active = info['active'] or info['reconnecting']
        if active:
            buttons = [('⏹ Остановить трансляцию', 'stream:confirm_stop')]
        else:
            buttons = [('🎯 Выбрать профиль', 'stream:pick')]
            if selected in profiles:
                buttons.append(('▶️ Запустить трансляцию', 'stream:confirm_start'))
        buttons.extend([('🔄 Обновить', 'go:stream'), ('◀️ Меню', 'go:main')])
        await reply(event, text, keyboard(buttons, cols=1))
    elif page == 'rules':
        if role != 'admin':
            raise PermissionError('Только администратор')
        buttons = [(('✅ ' if rules[key] else '⬜ ') + name, 'rule:' + key)
                   for key, name in [('black', 'Чёрный кадр'),
                                     ('uniform', 'Однотонный кадр'),
                                     ('freeze', 'Зависание'),
                                     ('audio_override', 'Разрешить проблемную картинку при звуке')]]
        buttons.append((f"🎤 Источник звука: {ctrl.monitor.get('audio_source_name') or 'не выбран'}", 'audio:pick'))
        buttons.append(('🔊 Проверить звук', 'audio:test'))
        buttons.extend(rule_buttons(rules))
        await reply(event, format_rules(rules),
                    keyboard(buttons + [('◀️ Меню', 'go:main')], cols=1))
    elif page == 'notifications':
        if role != 'admin':
            raise PermissionError('Только администратор')
        await reply(event, format_notifications(ctrl.notification_settings, rules),
                    keyboard([('⏳ Время удаления', 'notify:pick:ttl_seconds'),
                              ('🔕 Антиспам', 'notify:pick:cooldown_seconds'),
                              ('🧹 Частота очистки', 'notify:pick:cleanup_interval_seconds'),
                              ('⚙️ Проверки камеры', 'go:rules'),
                              ('◀️ Меню', 'go:main')], cols=1))
    elif page == 'users':
        if role != 'admin':
            raise PermissionError('Только администратор')
        user_count = len(ctrl.config['telegram']['users'])
        requests_count = len(ctrl.access_requests)
        await reply(event,
                    f'👥 Управление доступом\nПользователей: {user_count}\n'
                    f'Ожидают решения: {requests_count}\n\n'
                    'Новые пользователи могут самостоятельно отправлять заявки через /start. '
                    'Также можно добавить человека по Telegram ID.\n\n'
                    'Первого администратора из .env удалить или понизить нельзя.',
                    keyboard([('➕ Добавить по Telegram ID', 'access:add'),
                              (f'📥 Заявки ({requests_count})', 'access:requests:0'),
                              ('👤 Пользователи и роли', 'access:list:0'),
                              ('◀️ Меню', 'go:main')], cols=1))
    elif page == 'check':
        if ROLES[role] < 2:
            raise PermissionError('Недостаточно прав')
        issue = await ctrl.validate_bindings()
        if issue:
            raise ValueError(issue)
        png = await asyncio.to_thread(ctrl.obs.screenshot, ctrl.monitor['source_name'],
                                      ctrl.monitor['screenshot_width'], ctrl.monitor['screenshot_height'])
        res = FrameDetector().inspect(png, rules, ctrl.monitor['crop'])
        await reply(event, f"Источник: {ctrl.monitor['source_name']}\n"
                    f"Результат: {res.reason or 'кадр выглядит нормально'}\n"
                    f'Чёрных пикселей: {res.black_fraction:.1%}; σ={res.stddev:.2f}\n'
                    f'Разрешение по звуку: {"да" if await ctrl.audio_override_active() else "нет"}\n'
                    'Для поиска зависания нужны несколько последовательных кадров.',
                    keyboard([('◀️ Меню', 'go:main')]))
    else:
        raise ValueError('Неизвестная команда меню')


def access_request_buttons(uid: str) -> InlineKeyboardMarkup:
    return keyboard([('👁 Viewer', f'access:approve:{uid}:viewer'),
                     ('🎛 Operator', f'access:approve:{uid}:operator'),
                     ('👑 Admin', f'access:approve:{uid}:admin'),
                     ('❌ Отклонить', f'access:reject:{uid}')], cols=2)


async def show_access_welcome(event: TelegramEvent) -> None:
    await reply(event, '👋 OBS Control\n\nУ вас пока нет доступа к управлению OBS. '
                'Вы можете отправить заявку администратору.\n\n'
                'Ваш Telegram ID: ' + str(event.from_user.id),
                keyboard([('📨 Запросить доступ', 'access:request')], cols=1))


async def show_access_users(ctrl: Controller, event: TelegramEvent, page: int = 0) -> None:
    users = sorted(ctrl.config['telegram']['users'].items(), key=lambda item: (ROLES[item[1]] * -1, int(item[0])))
    count = len(users)
    pages = max(1, (count + ACCESS_PAGE_SIZE - 1) // ACCESS_PAGE_SIZE)
    page = min(max(0, page), pages - 1)
    buttons = []
    for uid, role in users[page * ACCESS_PAGE_SIZE:(page + 1) * ACCESS_PAGE_SIZE]:
        display = access_display(uid, ctrl.get_user_info(uid))
        buttons.append((f'{ACCESS_ROLE_LABELS[role]} · {display[:22]}', f'access:view:{uid}'))
    if page > 0:
        buttons.append(('◀️ Ранее', f'access:list:{page - 1}'))
    if page + 1 < pages:
        buttons.append(('Далее ▶️', f'access:list:{page + 1}'))
    buttons.append(('👥 Управление доступом', 'go:users'))
    await reply(event, f'👤 Пользователи ({count}) · страница {page + 1}/{pages}', keyboard(buttons, cols=1))


async def show_access_requests(ctrl: Controller, event: TelegramEvent, page: int = 0) -> None:
    requests = sorted(ctrl.access_requests.items(), key=lambda item: item[1].get('created_at', 0))
    count = len(requests)
    pages = max(1, (count + ACCESS_PAGE_SIZE - 1) // ACCESS_PAGE_SIZE)
    page = min(max(0, page), pages - 1)
    buttons = [(f'📨 {access_display(uid, info)[:30]} · {uid}', f'access:req:{uid}')
               for uid, info in requests[page * ACCESS_PAGE_SIZE:(page + 1) * ACCESS_PAGE_SIZE]]
    if page > 0:
        buttons.append(('◀️ Ранее', f'access:requests:{page - 1}'))
    if page + 1 < pages:
        buttons.append(('Далее ▶️', f'access:requests:{page + 1}'))
    buttons.append(('👥 Управление доступом', 'go:users'))
    await reply(event, f'📥 Заявки на доступ ({count}) · страница {page + 1}/{pages}\n'
                + ('Выберите заявку:' if count else 'Новых заявок нет.'), keyboard(buttons, cols=1))


async def show_access_request(ctrl: Controller, event: TelegramEvent, uid: str) -> None:
    request = ctrl.access_requests.get(uid)
    if request is None:
        raise ValueError('Заявка уже обработана или отозвана')
    created = datetime.fromtimestamp(float(request.get('created_at', 0))).astimezone().strftime('%d.%m.%Y %H:%M')
    await reply(event,
                f'📨 Заявка на доступ\nПользователь: {access_display(uid, request)}\n'
                f'ID: {uid}\nОтправлена: {created}\n\nВыберите роль:',
                keyboard([('👁 Viewer', f'access:approve:{uid}:viewer'),
                          ('🎛 Operator', f'access:approve:{uid}:operator'),
                          ('👑 Admin', f'access:approve:{uid}:admin'),
                          ('❌ Отклонить', f'access:reject:{uid}'),
                          ('◀️ Заявки', 'access:requests:0')], cols=1))


async def show_access_user(ctrl: Controller, event: TelegramEvent, uid: str) -> None:
    role = ctrl.config['telegram']['users'].get(uid)
    if role is None:
        raise ValueError('Пользователь уже удалён')
    display = access_display(uid, ctrl.get_user_info(uid))
    buttons = [('🔁 Изменить роль', f'access:edit:{uid}')]
    if uid != ctrl.bootstrap_admin:
        buttons.append(('⛔ Отозвать доступ', f'access:revoke:{uid}'))
    buttons.append(('◀️ К списку', 'access:list:0'))
    await reply(event,
                f'👤 Пользователь: {display}\nTelegram ID: {uid}\n'
                f'Роль: {ACCESS_ROLE_LABELS[role]}'
                + ('\n🔒 Первоначальный администратор' if uid == ctrl.bootstrap_admin else ''),
                keyboard(buttons, cols=1))


def access_role_picker_content(ctrl: Controller, uid: str, *, manual_add: bool = False
                               ) -> tuple[str, InlineKeyboardMarkup]:
    old_role = ctrl.config['telegram']['users'].get(uid)
    buttons = [(('✅ ' if old_role == role else '') + label, f'access:role:{uid}:{role}')
               for role, label in ACCESS_ROLE_LABELS.items()
               if uid != ctrl.bootstrap_admin or role == 'admin']
    buttons.append(('❌ Отмена', 'access:cancel_add' if manual_add else f'access:view:{uid}'))
    text = (f'👤 Telegram ID: {uid}\n'
            + (f'Текущая роль: {ACCESS_ROLE_LABELS[old_role]}\n'
               if old_role else 'Новый пользователь\n')
            + 'Выберите роль:')
    return text, keyboard(buttons, cols=1)


async def show_access_role_picker(ctrl: Controller, event: TelegramEvent, uid: str,
                                  *, manual_add: bool = False) -> None:
    text, markup = access_role_picker_content(ctrl, uid, manual_add=manual_add)
    await reply(event, text, markup)


async def show_stream_picker(ctrl: Controller, event: TelegramEvent, role: str) -> None:
    if role != 'admin':
        raise PermissionError('Только администратор')
    names, current, info = await ctrl.stream_overview()
    if info['active'] or info['reconnecting']:
        raise ValueError('Остановите трансляцию перед выбором профиля.')
    selected = ctrl.stream_settings.get('selected_profile', '')
    buttons = [(('✅ ' if name == selected else '') + name,
                'stream:select:' + name_id(name)) for name in names]
    buttons += [('🔄 Обновить', 'stream:pick'), ('◀️ Трансляция', 'go:stream')]
    await reply(event, f'Профиль OBS сейчас: {current}\n'
                'Выберите профиль, с которым начинать следующий эфир. '
                'Сам выбор не запускает эфир и не переключает профиль OBS.',
                keyboard(buttons, cols=1))


async def show_stream_confirmation(ctrl: Controller, event: TelegramEvent,
                                   role: str, action: str) -> None:
    if role != 'admin':
        raise PermissionError('Только администратор')
    profiles, current, status = await ctrl.stream_overview()
    active = status['active'] or status['reconnecting']
    if action == 'start':
        target = ctrl.stream_settings.get('selected_profile', '')
        if not target or target not in profiles:
            raise ValueError('Сначала выберите существующий профиль в разделе «Трансляция».')
        if active:
            raise ValueError('OBS уже ведёт трансляцию. Запуск отменён.')
        text = (f'⚠️ Подтвердите НАЧАЛО трансляции\n\n'
                f'Выбранный профиль: {target}\nТекущий профиль OBS: {current}\n\n'
                'OBS может переключиться на выбранный профиль и начнёт '
                'трансляцию с его настройками вещания. Продолжить?')
        action_id = 'stream:do_start:' + name_id(target)
        label = '▶️ Да, начать эфир'
    elif action == 'stop':
        if not active:
            raise ValueError('Трансляция уже остановлена.')
        text = (f'⚠️ Подтвердите ОСТАНОВКУ эфира\n\n'
                f'Текущий профиль OBS: {current}\n\n'
                'Остановка прекратит текущую трансляцию OBS. Продолжить?')
        action_id = 'stream:do_stop:' + name_id(current)
        label = '⏹ Да, остановить эфир'
    else:
        raise ValueError('Неизвестное действие')
    await reply(event, text, keyboard([(label, action_id),
                                       ('❌ Отмена', 'go:stream')], cols=1))


async def show_source_refresh_picker(ctrl: Controller, event: TelegramEvent,
                                     role: str, page: int = 0) -> None:

    if ROLES[role] < 2:
        raise PermissionError('Недостаточно прав')
    _, collection = await asyncio.to_thread(ctrl.obs.collections)
    sources = await asyncio.to_thread(ctrl.obs.browser_sources)
    count = len(sources)
    pages = max(1, (count + SOURCE_RELOAD_PAGE_SIZE - 1) // SOURCE_RELOAD_PAGE_SIZE)
    page = min(max(0, page), pages - 1)
    collection_hash = name_id(collection)
    buttons = [(f'♻️ {source}', f'reload:one:{collection_hash}:{name_id(source)}')
               for source in sources[page * SOURCE_RELOAD_PAGE_SIZE:(page + 1) * SOURCE_RELOAD_PAGE_SIZE]]
    if page > 0:
        buttons.append(('◀️ Предыдущая страница', f'reload:page:{page - 1}'))
    if page + 1 < pages:
        buttons.append(('Следующая страница ▶️', f'reload:page:{page + 1}'))
    if count > 1:
        buttons.append((f'♻️ Перезагрузить все ({count})', f'reload:confirm_all:{collection_hash}'))
    buttons.extend([('🔄 Обновить список', 'go:source_refresh'),
                    ('🧩 Источники сцены', 'go:sources'),
                    ('◀️ Меню', 'go:main')])
    await reply(event,
                f'♻️ Перезагрузка Browser Source\n'
                f'Коллекция OBS: «{collection}»\n'
                f'Источников: {count} · страница {page + 1}/{pages}\n\n'
                'Выберите источник для принудительного обновления веб-страницы.\n'
                'Видимость источника, сцена и автоматика не изменяются. '
                'Во время перезагрузки изображение может ненадолго пропасть.'
                if count else f'В коллекции «{collection}» нет Browser Source.',
                keyboard(buttons, cols=1))


async def show_audio_picker(ctrl: Controller, event: TelegramEvent, role: str) -> None:
    if role != 'admin':
        raise PermissionError('Только администратор')
    names = await asyncio.to_thread(ctrl.obs.all_input_names)
    selected = ctrl.monitor.get('audio_source_name', '')
    buttons = [(('✅ ' if name == selected else '') + name,
                'audio:choose:' + name_id(name)) for name in names]
    buttons.extend([('❌ Не использовать звук', 'audio:clear'),
                    ('🔄 Обновить список', 'audio:pick'),
                    ('◀️ Правила', 'go:rules')])
    await reply(event, '🎤 Выберите OBS-источник, в котором действительно есть звук.\n'
                'Учитывается измеренный уровень звукового сигнала, а не громкость ползунка.\n'
                'Выбирайте аудио именно проблемного видеопотока.\n\n'
                f'Сейчас: {selected or "не выбран"}', keyboard(buttons, cols=1))


async def show_rule_picker(ctrl: Controller, event: TelegramEvent, role: str, key: str) -> None:
    if role != 'admin' or key not in RULE_PRESETS:
        raise PermissionError('Только администратор')
    current = ctrl.state['rules'][key]
    options = [(('✅ ' if value == current else '') + rule_value_label(key, value),
                f'checkrule:set:{key}:{value}') for value in RULE_PRESETS[key]]
    await reply(event,
                f'{RULE_LABELS[key]}\n\n'
                f'Текущее значение: {rule_value_label(key, current)}\n\n'
                f'{rule_picker_description(key)}\n\n'
                f'Точное значение: /setrule {key} <число>',
                keyboard(options + [('◀️ Правила', 'go:rules')], cols=2))


async def show_notification_picker(ctrl: Controller, event: TelegramEvent, role: str, key: str) -> None:
    if role != 'admin' or key not in NOTIFICATION_LIMITS:
        raise PermissionError('Только администратор')
    current = ctrl.notification_settings[key]
    options = [(('✅ ' if v == current else '') + f'{v} сек', f'notify:set:{key}:{v}')
               for v in NOTIFICATION_PRESETS[key]]
    await reply(event,
                f'{NOTIFICATION_LABELS[key]}\nСейчас: {current} сек\n'
                f'Другие значения: /setnotify {key} <секунды>',
                keyboard(options + [('◀️ Уведомления', 'go:notifications')], cols=2))


async def show_picker(ctrl: Controller, event: TelegramEvent, role: str, field: str) -> None:
    if role != 'admin' or field not in ASSIGNMENTS:
        raise PermissionError('Только администратор')
    _, collection = await asyncio.to_thread(ctrl.obs.collections)
    options = await asyncio.to_thread(ctrl.obs.browser_sources if field == 'source' else ctrl.obs.scenes)
    selected = ctrl.monitor[ASSIGNMENTS[field]] if ctrl.monitor.get('collection_name') == collection else ''
    items = [(('✅ ' if name == selected else '') + name,
              f'choose:{field}:{name_id(collection)}:{name_id(name)}') for name in options]
    if not items:
        await reply(event, 'В OBS нет подходящих объектов в текущей коллекции «' + collection + '».',
                    keyboard([('🔄 Обновить', 'pick:' + field), ('◀️ Назад', 'go:setup')]))
        return
    label = {'source': 'Browser Source', 'normal': 'основную сцену', 'fallback': 'сцену паузы'}[field]
    await reply(event, f'Коллекция OBS: «{collection}»\nВыберите {label}:',
                keyboard(items + [('🔄 Обновить', 'pick:' + field),
                                  ('◀️ Назад', 'go:setup')], cols=1))


async def commands(message: Message, command: CommandObject,
                   controller: Controller, state: FSMContext) -> None:
    ctrl = controller
    cmd = command.command.lower()
    args = command.args.split() if command.args else []
    if cmd == 'id' and message.chat.type == ChatType.PRIVATE:
        await reply(message, f'Ваш Telegram ID: {message.from_user.id}')
        return
    role = ctrl.role(message)
    if role is None:
        if message.chat.type == ChatType.PRIVATE and cmd in ('start', 'help', 'menu', 'request_access'):
            if cmd == 'request_access':
                try:
                    result = await ctrl.request_access(message.bot, message.from_user)
                    await reply(message, result, keyboard([('◀️ Начало', 'access:welcome')]))
                except Exception as exc:
                    LOG.warning('Request access failed: %s', type(exc).__name__)
                    await reply(message, 'Не удалось отправить заявку. Повторите позже.')
            else:
                await show_access_welcome(message)
        else:
            await reply(message, 'Нет доступа. Откройте бота в личном чате и отправьте /start.')
        return
    await ctrl.update_known_user(message.from_user)
    if cmd != 'cancel':


        existing = await state.get_data()
        if (existing.get('pending_access_user') or existing.get('access_add_uid')
                or existing.get('pending_obs_field')):
            await delete_input_prompt(message.bot, message.chat.id, existing.get('wizard_message_id'))
            await state.clear()
    if cmd in ('start', 'help', 'menu'):
        await state.clear()
        await show_page(ctrl, message, role, 'main')
        if role == 'admin':
            await ctrl.refresh_status(message.bot)
        return
    if cmd == 'cancel':
        current = await state.get_data()
        await state.clear()
        if current.get('pending_access_user') or current.get('access_add_uid') or current.get('pending_obs_field'):
            await delete_input_prompt(message.bot, message.chat.id, current.get('wizard_message_id'))
            await delete_input_message(message)
        else:
            await reply(message, 'Нет активного ввода. Откройте /menu.')
        return
    try:
        if cmd in ('status', 'scenes', 'sources', 'refreshsources', 'profiles', 'collections', 'rules',
                   'setup', 'obs', 'users', 'notifications', 'stream'):
            await show_page(ctrl, message, role, 'source_refresh' if cmd == 'refreshsources' else cmd)
        elif cmd in ('check', 'snapshot'):
            if ROLES[role] < 2:
                raise PermissionError('Недостаточно прав')
            if cmd == 'check':
                await show_page(ctrl, message, role, 'check')
            else:
                issue = await ctrl.validate_bindings()
                if issue:
                    raise ValueError(issue)
                png = await asyncio.to_thread(ctrl.obs.screenshot, ctrl.monitor['source_name'],
                                              ctrl.monitor['screenshot_width'], ctrl.monitor['screenshot_height'])
                await message.answer_photo(BufferedInputFile(png, filename='obs_source.png'),
                                           caption='Снимок Browser Source')
        elif cmd == 'auto':
            if ROLES[role] < 2:
                raise PermissionError('Недостаточно прав')
            if not args:
                await show_page(ctrl, message, role, 'auto')
            elif args == ['on']:
                await ctrl.enable_auto()
                await ctrl.refresh_status(message.bot)
                await reply(message, 'Автоматика включена.')
            elif args == ['off']:
                async with ctrl.action_lock:
                    ctrl.set_auto(False)
                await ctrl.refresh_status(message.bot)
                await reply(message, 'Автоматика выключена.')
            else:
                await reply(message, 'Формат: /auto on или /auto off')
        elif cmd == 'setnotify':
            if role != 'admin':
                raise PermissionError('Только администратор')
            if len(args) != 2 or args[0] not in NOTIFICATION_LIMITS:
                await reply(message, 'Формат: /setnotify ttl_seconds 90\n'
                            + format_notifications(ctrl.notification_settings, ctrl.state['rules']),
                            keyboard([('🔔 Настройки', 'go:notifications')]))
                return
            parsed = ctrl.set_notification_interval(args[0], args[1])
            await reply(message, f'✅ {NOTIFICATION_LABELS[args[0]]}: {parsed} сек. Сохранено.',
                        keyboard([('🔔 Уведомления', 'go:notifications')]))
        elif cmd == 'setrule':
            if role != 'admin':
                raise PermissionError('Только администратор')
            if len(args) != 2 or args[0] not in RULE_LIMITS:
                await reply(message, 'Формат: /setrule bad_checks 5\n' + format_rules(ctrl.state['rules']))
                return
            key, value = args
            parsed = await ctrl.set_rule_value(key, value)
            await reply(message, f'Настройка сохранена: {key} = {parsed}',
                        keyboard([('⚙️ Правила', 'go:rules')]))
        elif cmd == 'refresh':
            if ROLES[role] < 2:
                raise PermissionError('Недостаточно прав')
            issue = await ctrl.validate_bindings()
            if issue:
                raise ValueError(issue)
            await ctrl.reload_browser_source(ctrl.monitor['source_name'],
                                             name_id(ctrl.monitor['collection_name']))
            await reply(message, 'Запрошено обновление Browser Source.')
        elif cmd == 'grant':
            if role != 'admin':
                raise PermissionError('Только администратор')
            if len(args) != 2 or args[1] not in ROLES:
                raise ValueError('Формат: /grant 123456789 operator (viewer / operator / admin)')
            uid = valid_user_id(args[0])
            await ctrl.grant_access(message.bot, uid, args[1], actor_uid=str(message.from_user.id))
            await reply(message, f'✅ Права для {uid}: {args[1]}',
                        keyboard([('👥 Доступ', 'go:users')]))
        elif cmd == 'revoke':
            if role != 'admin':
                raise PermissionError('Только администратор')
            if len(args) != 1:
                raise ValueError('Формат: /revoke 123456789')
            uid = valid_user_id(args[0])
            await ctrl.revoke_access(message.bot, uid, actor_uid=str(message.from_user.id))
            await reply(message, f'⛔ Доступ отозван для {uid}',
                        keyboard([('👥 Доступ', 'go:users')]))
        else:
            await show_page(ctrl, message, role, 'main')
    except Exception as e:
        LOG.warning('Command %s failed: %s', cmd, type(e).__name__)
        await reply(message, user_facing_error(e))


async def input_text(message: Message, controller: Controller, state: FSMContext) -> None:
    ctrl = controller
    role = ctrl.role(message)
    data = await state.get_data()
    if role == 'admin' and data.get('pending_access_user'):

        await delete_input_message(message)
        try:
            uid = valid_user_id((message.text or '').strip())
        except ValueError as exc:
            await edit_input_prompt(message, state,
                                    f'⚠️ {exc}\nПовторите ввод или нажмите «Отмена».',
                                    keyboard([('❌ Отмена', 'access:cancel_add')]))
            return
        await state.update_data(pending_access_user=False, access_add_uid=uid)
        text, markup = access_role_picker_content(ctrl, uid, manual_add=True)
        await edit_input_prompt(message, state, text, markup)
        return
    if role == 'admin' and data.get('access_add_uid'):

        await delete_input_message(message)
        uid = data['access_add_uid']
        text, markup = access_role_picker_content(ctrl, uid, manual_add=True)
        await edit_input_prompt(message, state, text, markup)
        return
    field = data.get('pending_obs_field')
    if role != 'admin' or field not in ('host', 'port', 'password'):
        if role:
            await reply(message, 'Используйте /menu для управления OBS.')
        return


    await delete_input_message(message)
    try:
        await ctrl.set_connection(field, message.text or '')
        await ctrl.refresh_status(message.bot)
        await edit_input_prompt(message, state,
                                '✅ Параметр сохранён. Автоматика отключена. Проверьте подключение в /obs.',
                                keyboard([('🔌 Подключение OBS', 'go:obs')]))
        await state.clear()
    except ValueError as e:
        await edit_input_prompt(message, state,
                                '⚠️ Ошибка ввода: ' + str(e) + '\nПовторите ввод или /cancel.',
                                keyboard([('❌ Отмена', 'go:obs')]))
    except Exception as e:
        LOG.warning('OBS setup failed: %s', type(e).__name__)
        await edit_input_prompt(message, state,
                                'Ошибка сохранения: ' + type(e).__name__ + '\nПовторите ввод или /cancel.',
                                keyboard([('❌ Отмена', 'go:obs')]))


async def callback(query: CallbackQuery, controller: Controller, state: FSMContext) -> None:
    ctrl = controller
    role = ctrl.role(query)
    if role is None:

        if (query.data in ('access:request', 'access:welcome')
                and query.message is not None and query.message.chat.type == ChatType.PRIVATE):
            await query.answer()
            if query.data == 'access:welcome':
                await show_access_welcome(query)
            else:
                try:
                    result = await ctrl.request_access(query.bot, query.from_user)
                except Exception as exc:
                    LOG.warning('Access request failed: %s', type(exc).__name__)
                    result = 'Не удалось отправить заявку. Повторите позже.'
                await reply(query, result,
                            keyboard([('◀️ Начало', 'access:welcome')]))
        else:
            await query.answer('Нет доступа', show_alert=True)
        return
    await query.answer()
    try:
        value = query.data
        if not isinstance(value, str) or ':' not in value:
            raise ValueError('Некорректная кнопка')
        kind, arg = value.split(':', 1)
        previous_state = await state.get_data()
        access_parts = arg.split(':') if kind == 'access' else []
        manual_access_step = (
            kind == 'access' and len(access_parts) >= 2
            and access_parts[0] in ('role', 'do_role', 'picknew')
            and previous_state.get('access_add_uid') == access_parts[1]
        )
        if not manual_access_step:
            await state.clear()
        if kind == 'go':
            await show_page(ctrl, query, role, arg)
        elif kind == 'access':
            if arg in ('request', 'welcome'):

                await show_page(ctrl, query, role, 'main')
                return
            if role != 'admin':
                raise PermissionError('Только администратор')
            parts = arg.split(':')
            action = parts[0]
            if action == 'add' and len(parts) == 1:
                await state.update_data(
                    pending_access_user=True,
                    wizard_message_id=query.message.message_id if query.message is not None else None,
                )
                await reply(query, '➕ Введите Telegram ID пользователя числом, например 123456789.\n'
                            'После этого выберите роль кнопкой.\nОтмена: /cancel',
                            keyboard([('❌ Отмена', 'access:cancel_add')]))
            elif action == 'cancel_add' and len(parts) == 1:
                if isinstance(query.message, Message):
                    try:
                        await query.message.delete()
                    except TelegramAPIError:
                        await reply(query, 'Добавление отменено.',
                                    keyboard([('👥 Доступ', 'go:users')]))
            elif action == 'picknew' and len(parts) == 2:
                uid = valid_user_id(parts[1])
                await show_access_role_picker(ctrl, query, uid, manual_add=manual_access_step)
            elif action in ('list', 'requests') and len(parts) == 2 and parts[1].isascii() and parts[1].isdecimal():
                page = min(int(parts[1]), 100000)
                if action == 'list':
                    await show_access_users(ctrl, query, page)
                else:
                    await show_access_requests(ctrl, query, page)
            elif action in ('view', 'req', 'edit', 'revoke', 'delete', 'reject') and len(parts) == 2:
                uid = valid_user_id(parts[1])
                if action == 'view':
                    await show_access_user(ctrl, query, uid)
                elif action == 'req':
                    await show_access_request(ctrl, query, uid)
                elif action == 'edit':
                    await show_access_role_picker(ctrl, query, uid)
                elif action == 'revoke':
                    if uid == ctrl.bootstrap_admin or uid == str(query.from_user.id):
                        raise PermissionError('Этот доступ нельзя удалить')
                    await reply(query, f'⚠️ Отозвать доступ у {uid}?',
                                keyboard([('⛔ Да, удалить', f'access:delete:{uid}'),
                                          ('❌ Отмена', f'access:view:{uid}')], cols=1))
                elif action == 'delete':
                    await ctrl.revoke_access(query.bot, uid, actor_uid=str(query.from_user.id))
                    await show_access_users(ctrl, query)
                else:
                    notices = await ctrl.reject_access(query.bot, uid)
                    if not (str(query.from_user.id) in notices
                            and query.message is not None
                            and notices[str(query.from_user.id)] == query.message.message_id):
                        await show_access_requests(ctrl, query)
            elif action in ('role', 'approve', 'do_role', 'do_approve') and len(parts) == 3:
                uid = valid_user_id(parts[1])
                selected_role = parts[2]
                if selected_role not in ROLES:
                    raise ValueError('Неизвестная роль')
                is_request = action in ('approve', 'do_approve')
                if is_request and uid not in ctrl.access_requests:
                    raise ValueError('Заявка уже обработана или отозвана')
                if selected_role == 'admin' and action in ('role', 'approve'):
                    cancel = (f'access:req:{uid}' if is_request else
                              f'access:picknew:{uid}' if manual_access_step else f'access:edit:{uid}')
                    confirm = f'access:do_approve:{uid}:admin' if is_request else f'access:do_role:{uid}:admin'
                    await reply(query, f'⚠️ Вы уверены, что хотите выдать права администратора пользователю {uid}?\n'
                                'Администратор получит полный доступ к настройкам OBS и пользователям.',
                                keyboard([('✅ Да, выдать Admin', confirm),
                                          ('❌ Отмена', cancel)], cols=1))
                else:
                    previous_role, notices = await ctrl.grant_access(query.bot, uid, selected_role,
                                                                      actor_uid=str(query.from_user.id),
                                                                      require_request=is_request)
                    if is_request:

                        if not (str(query.from_user.id) in notices
                                and query.message is not None
                                and notices[str(query.from_user.id)] == query.message.message_id):
                            await show_access_requests(ctrl, query)
                    elif manual_access_step:
                        result_text = (f'✅ Пользователь {uid} добавлен.' if previous_role is None else
                                       f'✅ Права пользователя {uid} обновлены.')
                        await reply(query, result_text + f'\nРоль: {ACCESS_ROLE_LABELS[selected_role]}',
                                    keyboard([('👤 Подробнее', f'access:view:{uid}'),
                                              ('👥 Доступ', 'go:users')], cols=1))
                        await state.clear()
                    else:
                        await show_access_user(ctrl, query, uid)
            else:
                raise ValueError('Неизвестная кнопка управления доступом')
        elif kind == 'reload':
            if ROLES[role] < 2:
                raise PermissionError('Недостаточно прав')
            parts = arg.split(':')
            action = parts[0]
            if action == 'page' and len(parts) == 2 and parts[1].isascii() and parts[1].isdecimal():
                await show_source_refresh_picker(ctrl, query, role, min(int(parts[1]), 100000))
            elif action == 'one' and len(parts) == 3:
                collection_hash, source_hash = parts[1], parts[2]
                _, collection = await asyncio.to_thread(ctrl.obs.collections)
                if name_id(collection) != collection_hash:
                    raise ValueError('Коллекция OBS изменилась. Откройте список источников заново.')
                sources = await asyncio.to_thread(ctrl.obs.browser_sources)
                source = next((s for s in sources if name_id(s) == source_hash), None)
                if source is None:
                    raise ValueError('Источник удалён или переименован. Обновите список.')
                await ctrl.reload_browser_source(source, collection_hash)
                await reply(query, f'✅ Browser Source «{source}» перезагружен.',
                            keyboard([('♻️ Перезагрузить другой', 'go:source_refresh'),
                                      ('🧩 Источники', 'go:sources'),
                                      ('◀️ Меню', 'go:main')], cols=1))
            elif action == 'confirm_all' and len(parts) == 2:
                collection_hash = parts[1]
                _, collection = await asyncio.to_thread(ctrl.obs.collections)
                if name_id(collection) != collection_hash:
                    raise ValueError('Коллекция OBS изменилась. Откройте список источников заново.')
                sources = await asyncio.to_thread(ctrl.obs.browser_sources)
                if not sources:
                    raise ValueError('В этой коллекции нет Browser Source.')
                await reply(query, f'⚠️ Перезагрузить все Browser Source ({len(sources)}) '
                            f'в коллекции «{collection}»?\n'
                            'Во время обновления изображение может ненадолго пропасть.',
                            keyboard([('✅ Да, перезагрузить все', f'reload:all:{collection_hash}'),
                                      ('❌ Отмена', 'go:source_refresh')], cols=1))
            elif action == 'all' and len(parts) == 2:
                count = await ctrl.reload_all_browser_sources(parts[1])
                await reply(query, f'✅ Перезагружено Browser Source: {count}.',
                            keyboard([('♻️ К списку источников', 'go:source_refresh'),
                                      ('🧩 Источники', 'go:sources'),
                                      ('◀️ Меню', 'go:main')], cols=1))
            else:
                raise ValueError('Неизвестная кнопка перезагрузки источника')
        elif kind == 'stream':
            if role != 'admin':
                raise PermissionError('Только администратор')
            if arg == 'pick':
                await show_stream_picker(ctrl, query, role)
            elif arg.startswith('select:'):
                selected = await ctrl.select_stream_profile(arg.split(':', 1)[1])
                await ctrl.refresh_status(query.bot)
                await show_page(ctrl, query, role, 'stream')
            elif arg == 'confirm_start':
                await show_stream_confirmation(ctrl, query, role, 'start')
            elif arg == 'confirm_stop':
                await show_stream_confirmation(ctrl, query, role, 'stop')
            elif arg.startswith('do_start:'):
                target, live = await ctrl.start_stream(arg.split(':', 1)[1])
                message = (f'📡 Запуск эфира на профиле «{target}» '
                           + ('подтверждён OBS.' if live else
                              'запрошен, но OBS пока не подтвердил активность.'))
                await ctrl.notifications.event(ctrl, query.bot, message, kind='stream')
                await reply(query, message, keyboard([('📡 Трансляция', 'go:stream'),
                                                     ('◀️ Меню', 'go:main')]))
            elif arg.startswith('do_stop:'):
                profile, stopped = await ctrl.stop_stream(arg.split(':', 1)[1])
                message = (f'⏹ Остановка эфира на профиле «{profile}» '
                           + ('подтверждена OBS.' if stopped else
                              'запрошена, но OBS пока не подтвердил завершение.'))
                await ctrl.notifications.event(ctrl, query.bot, message, kind='stream')
                await reply(query, message, keyboard([('📡 Трансляция', 'go:stream'),
                                                     ('◀️ Меню', 'go:main')]))
            else:
                raise ValueError('Неизвестное действие с трансляцией')
        elif kind == 'audio':
            if role != 'admin':
                raise PermissionError('Только администратор')
            if arg == 'pick':
                await show_audio_picker(ctrl, query, role)
            elif arg == 'test':
                result = await ctrl.diagnose_audio()
                await reply(query, result, keyboard([('🔄 Проверить повторно', 'audio:test'),
                                                     ('◀️ Правила', 'go:rules')], cols=1))
            elif arg == 'clear':
                await ctrl.assign_audio_source('')
                await show_page(ctrl, query, role, 'rules')
            elif arg.startswith('choose:'):
                expected = arg.split(':', 1)[1]
                names = await asyncio.to_thread(ctrl.obs.all_input_names)
                chosen = next((s for s in names if name_id(s) == expected), None)
                if chosen is None:
                    raise ValueError('Источник изменился. Обновите список.')
                await ctrl.assign_audio_source(chosen)
                await show_page(ctrl, query, role, 'rules')
            else:
                raise ValueError('Неизвестная кнопка аудио')
        elif kind == 'checkrule':
            if role != 'admin':
                raise PermissionError('Только администратор')
            parts = arg.split(':')
            if len(parts) == 2 and parts[0] == 'pick' and parts[1] in RULE_PRESETS:
                await show_rule_picker(ctrl, query, role, parts[1])
            elif len(parts) == 3 and parts[0] == 'set' and parts[1] in RULE_PRESETS:
                key, value = parts[1], parts[2]
                if value not in tuple(str(preset) for preset in RULE_PRESETS[key]):
                    raise ValueError('Это устаревшая кнопка. Откройте выбор заново.')
                await ctrl.set_rule_value(key, value)
                await show_page(ctrl, query, role, 'rules')
            else:
                raise ValueError('Неизвестная настройка проверки камеры')
        elif kind == 'notify':
            if role != 'admin':
                raise PermissionError('Только администратор')
            parts = arg.split(':')
            if len(parts) == 2 and parts[0] == 'pick' and parts[1] in NOTIFICATION_LIMITS:
                await show_notification_picker(ctrl, query, role, parts[1])
            elif len(parts) == 3 and parts[0] == 'set' and parts[1] in NOTIFICATION_LIMITS:
                ctrl.set_notification_interval(parts[1], parts[2])
                await show_page(ctrl, query, role, 'notifications')
            else:
                raise ValueError('Неизвестная настройка уведомлений')
        elif kind == 'edit':
            if role != 'admin' or arg not in ('host', 'port', 'password'):
                raise PermissionError('Только администратор')
            await state.update_data(
                pending_obs_field=arg,
                wizard_message_id=query.message.message_id if query.message is not None else None,
            )
            hint = {'host': 'Введите IP или hostname OBS (без http://)',
                    'port': 'Введите порт OBS WebSocket (обычно 4455)',
                    'password': 'Отправьте пароль OBS WebSocket отдельным сообщением. '
                                'Бот попытается сразу удалить его из чата. '
                                'Пароль хранится локально в settings.json.\n'
                                'Для пустого пароля отправьте /empty_password.'}[arg]
            await reply(query, hint + '\nОтмена: /cancel',
                        keyboard([('❌ Отмена', 'go:obs')]))
        elif kind == 'test':
            if role != 'admin':
                raise PermissionError('Только администратор')
            if arg == 'obs':
                version = await asyncio.to_thread(ctrl.obs.test_connection)
                await reply(query, f'✅ OBS подключен. Версия: {version}',
                            keyboard([('🎯 Назначения', 'go:setup'), ('◀️ Назад', 'go:obs')]))
            elif arg == 'bindings':
                issue = await ctrl.validate_bindings()
                await reply(query, ('⚠️ ' + issue) if issue else '✅ Назначения корректны.',
                            keyboard([('◀️ Назначения', 'go:setup')]))
            else:
                raise ValueError('Неизвестная проверка')
        elif kind == 'pick':
            await show_picker(ctrl, query, role, arg)
        elif kind == 'choose':
            if role != 'admin':
                raise PermissionError('Только администратор')
            field, collection_hash, choice_hash = arg.split(':', 2)
            if field not in ASSIGNMENTS:
                raise ValueError('Неизвестное назначение')
            _, collection = await asyncio.to_thread(ctrl.obs.collections)
            if name_id(collection) != collection_hash:
                raise ValueError('Коллекция изменилась. Откройте /setup снова.')
            names = await asyncio.to_thread(ctrl.obs.browser_sources if field == 'source' else ctrl.obs.scenes)
            selection = next((s for s in names if name_id(s) == choice_hash), None)
            if selection is None:
                raise ValueError('Список изменился. Обновите меню.')
            await ctrl.assign(field, selection, collection_hash)
            await ctrl.refresh_status(query.bot)
            await show_page(ctrl, query, role, 'setup')
        elif kind == 'auto':
            if ROLES[role] < 2 or arg not in ('1', '0'):
                raise PermissionError('Недостаточно прав')
            if arg == '1':
                await ctrl.enable_auto()
            else:
                async with ctrl.action_lock:
                    ctrl.set_auto(False)
            await ctrl.refresh_status(query.bot)
            await show_page(ctrl, query, role, 'auto')
        elif kind == 'rule':
            if role != 'admin' or arg not in ('black', 'uniform', 'freeze', 'audio_override'):
                raise PermissionError('Недостаточно прав')
            if arg == 'audio_override' and not ctrl.monitor.get('audio_source_name'):
                raise ValueError('Сначала выберите источник звука в разделе правил.')
            ctrl.state['rules'][arg] = not ctrl.state['rules'][arg]
            ctrl.reset_counters()
            ctrl.save()
            await show_page(ctrl, query, role, 'rules')
        elif kind in ('scene', 'profile', 'collection'):
            if ROLES[role] < (3 if kind != 'scene' else 2):
                raise PermissionError('Недостаточно прав')
            if kind == 'scene':
                options = await asyncio.to_thread(ctrl.obs.scenes)
            elif kind == 'profile':
                options, _ = await asyncio.to_thread(ctrl.obs.profiles)
            else:
                options, _ = await asyncio.to_thread(ctrl.obs.collections)
            chosen = next((name for name in options if name_id(name) == arg), None)
            if chosen is None:
                raise ValueError('Список изменился. Обновите меню.')
            if kind == 'scene':
                await ctrl.manual_scene(chosen)
            else:
                await ctrl.manual_profile_or_collection(kind, chosen)
            await ctrl.refresh_status(query.bot)
            await reply(query, f'Выбрано: {chosen}\nАвтоматика отключена.',
                        keyboard([('◀️ Меню', 'go:main')]))
        elif kind == 'item':
            if ROLES[role] < 2:
                raise PermissionError('Недостаточно прав')
            scene_hash, item_str = arg.split(':', 1)
            scene = await asyncio.to_thread(ctrl.obs.current_scene)
            if name_id(scene) != scene_hash:
                raise ValueError('Сцена изменилась. Откройте /sources снова.')
            name, visible = await ctrl.toggle_source(scene, int(item_str))
            await reply(query, f'{name}: {"видимый" if visible else "скрытый"}',
                        keyboard([('🧩 Источники', 'go:sources'), ('◀️ Меню', 'go:main')]))
        else:
            raise ValueError('Неизвестная кнопка')
    except Exception as e:
        LOG.warning('Callback %s failed: %s', (query.data or '').split(':', 1)[0], type(e).__name__)
        await reply(query, user_facing_error(e),
                    keyboard([('◀️ Меню', 'go:main')]))


async def empty_password(message: Message, controller: Controller, state: FSMContext) -> None:
    ctrl = controller
    if ctrl.role(message) != 'admin' or (await state.get_data()).get('pending_obs_field') != 'password':
        await reply(message, 'Откройте /obs и выберите изменение пароля (только администратор).')
        return
    await ctrl.set_connection('password', '')
    await ctrl.refresh_status(message.bot)
    await edit_input_prompt(message, state,
                            '✅ Пароль OBS очищен. Настоятельно рекомендуется включить аутентификацию OBS.',
                            keyboard([('🔌 Подключение OBS', 'go:obs')]))
    await state.clear()
    await delete_input_message(message)


async def on_startup(bot: Bot, controller: Controller) -> None:

    try:
        await controller.stream_overview()
    except Exception as exc:
        LOG.info('OBS streaming status unavailable at startup: %s', type(exc).__name__)

    await controller.refresh_status(bot)
    controller.notification_cleanup_task = asyncio.create_task(
        controller.notifications.cleanup_loop(controller, bot), name='notification-cleanup')
    controller.monitor_task = asyncio.create_task(controller.monitor_loop(bot), name='monitor')
    LOG.info('OBS Control started')


async def on_shutdown(controller: Controller) -> None:
    tasks = [task for task in (controller.monitor_task, controller.notification_cleanup_task)
             if task is not None]
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    await asyncio.to_thread(controller.obs.close)


async def run() -> None:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    configure_obs_logging()
    load_dotenv(DATA_ROOT / '.env')
    token = os.getenv('TELEGRAM_BOT_TOKEN', '')
    if not token or 'replace_this' in token:
        raise SystemExit('Укажите TELEGRAM_BOT_TOKEN в .env')

    cfg, admin = load_settings(os.getenv('ADMIN_TELEGRAM_ID'))
    ctrl = Controller(cfg, admin)
    router = Router()
    bot_commands = (
        'start', 'help', 'menu', 'id', 'status', 'scenes', 'sources', 'profiles',
        'collections', 'rules', 'setrule', 'notifications', 'setnotify', 'stream',
        'auto', 'check', 'snapshot', 'refresh', 'refreshsources',
        'setup', 'obs', 'users', 'grant', 'revoke', 'cancel', 'request_access',
    )
    router.message.register(commands, Command(*bot_commands))
    router.message.register(empty_password, Command('empty_password'))
    router.callback_query.register(callback)
    router.message.register(input_text, F.chat.type == ChatType.PRIVATE,
                            F.text, ~F.text.startswith('/'))

    dp = Dispatcher(controller=ctrl)
    dp.include_router(router)
    dp.startup.register(on_startup)
    dp.shutdown.register(on_shutdown)

    async with Bot(token=token) as bot:
        await bot.delete_webhook(drop_pending_updates=True)
        await dp.start_polling(bot, allowed_updates=['message', 'callback_query'],
                               close_bot_session=False)


def main() -> None:
    asyncio.run(run())


if __name__ == '__main__':
    main()
