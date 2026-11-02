
from __future__ import annotations

import base64
from collections import deque
import math
import threading
import time

import obsws_python as obs
from obsws_python.error import OBSSDKRequestError


class OBSClient:
    def __init__(self, config: dict) -> None:
        self.config = dict(config)
        self.client = None
        self.lock = threading.RLock()
        self.audio_lock = threading.Lock()
        self.audio_events = None
        self.audio_source = ''
        self.audio_samples = deque(maxlen=1000)
        self.audio_packet_at = 0.0
        self.audio_any_packet_at = 0.0
        self.audio_try_at = 0.0

    def configure(self, config: dict) -> None:
        with self.lock:
            try:
                self.close()
            except Exception:

                self.client = None
            self.config = dict(config)

    def request(self, method: str, *args):
        with self.lock:
            try:
                if self.client is None:
                    self.client = obs.ReqClient(
                        host=self.config['host'],
                        port=int(self.config['port']),
                        password=self.config.get('password', ''),
                        timeout=5,
                    )
                return getattr(self.client, method)(*args)
            except OBSSDKRequestError:

                raise
            except Exception:

                try:
                    self.close()
                except Exception:
                    self.client = None
                raise

    @staticmethod
    def _audio_peak_db(item: dict) -> float | None:
        linear = item.get('inputLevelsMul', item.get('input_levels_mul'))
        if isinstance(linear, (list, tuple)):
            values = []
            for channel in linear:
                if isinstance(channel, (list, tuple)):
                    if len(channel) >= 2:
                        values.append(channel[1])
                    elif len(channel) == 1:
                        values.append(channel[0])
                elif isinstance(channel, (int, float)):
                    values.append(channel)
            clean = [float(v) for v in values if type(v) in (int, float) and math.isfinite(v) and v >= 0]
            if clean:
                peak = max(clean)
                return 20.0 * math.log10(peak) if peak > 0 else -200.0
        decibels = item.get('inputLevelsDb', item.get('input_levels_db'))
        if isinstance(decibels, (list, tuple)):
            values = []
            for channel in decibels:
                if isinstance(channel, (list, tuple)):
                    if len(channel) >= 2:
                        values.append(channel[1])
                    elif len(channel) == 1:
                        values.append(channel[0])
                elif isinstance(channel, (int, float)):
                    values.append(channel)
            clean = [float(v) for v in values if type(v) in (int, float) and math.isfinite(v)]
            if clean:
                return max(clean)
        return None

    def on_input_volume_meters(self, data) -> None:
        inputs = getattr(data, 'inputs', [])
        if isinstance(inputs, dict):
            inputs = [dict(inputName=name, inputLevelsMul=levels)
                      for name, levels in inputs.items()]
        if not isinstance(inputs, (list, tuple)):
            return
        now = time.monotonic()
        with self.audio_lock:
            self.audio_any_packet_at = now
            for item in inputs:
                if not isinstance(item, dict):
                    continue
                name = item.get('inputName', item.get('input_name'))
                if name != self.audio_source:
                    continue
                self.audio_packet_at = now
                peak = self._audio_peak_db(item)
                if peak is not None:
                    self.audio_samples.append((now, peak))

    def ensure_audio_meter(self, source: str) -> None:
        with self.lock:
            with self.audio_lock:
                if self.audio_source != source:
                    self.audio_source = source
                    self.audio_samples.clear()
                    self.audio_packet_at = 0.0
                    self.audio_any_packet_at = 0.0
                last_packet = self.audio_any_packet_at
            now = time.monotonic()
            if self.audio_events is not None and now - last_packet <= 15:
                return
            if now - self.audio_try_at < 20:
                return
            self.audio_try_at = now
            self._stop_audio_meter_locked()
            with self.audio_lock:
                self.audio_source = source
            client = obs.EventClient(
                host=self.config['host'],
                port=int(self.config['port']),
                password=self.config.get('password', ''),
                timeout=5,
                subs=obs.Subs.INPUTVOLUMEMETERS,
            )
            client.callback.register(self.on_input_volume_meters)
            self.audio_events = client

    def audio_status(self, source: str, threshold_db: float, recent_seconds: float = 8.0) -> dict:
        now = time.monotonic()
        with self.audio_lock:
            matched = self.audio_source == source
            source_recent = matched and self.audio_packet_at > 0 and now - self.audio_packet_at <= 3.0
            events_recent = matched and self.audio_any_packet_at > 0 and now - self.audio_any_packet_at <= 3.0
            values = [level for at, level in self.audio_samples if now - at <= recent_seconds] if matched else []
            peak = max(values) if values else None
            age = now - self.audio_packet_at if matched and self.audio_packet_at > 0 else None
            return {
                'connected': self.audio_events is not None,
                'events_recent': bool(events_recent),
                'source_recent': bool(source_recent),
                'peak_db': peak,
                'age_seconds': age,
                'allowed': bool(source_recent and peak is not None and peak >= threshold_db),
            }

    def audio_is_present(self, source: str, threshold_db: float, recent_seconds: float = 8.0) -> bool:
        return self.audio_status(source, threshold_db, recent_seconds)['allowed']

    def _stop_audio_meter_locked(self) -> None:
        client, self.audio_events = self.audio_events, None
        with self.audio_lock:
            self.audio_samples.clear()
            self.audio_packet_at = 0.0
            self.audio_any_packet_at = 0.0
        if client is not None:
            try:
                client.disconnect()
            except Exception:
                pass

    def stop_audio_meter(self) -> None:
        with self.lock:
            self._stop_audio_meter_locked()
            self.audio_try_at = 0.0

    def all_input_names(self) -> list[str]:
        return sorted({item['inputName'] for item in self.request('get_input_list').inputs})

    def raw(self, request_type: str, payload: dict):
        return self.request('send', request_type, payload)

    def test_connection(self) -> str:
        try:
            response = self.request('get_version')
        except (OSError, TimeoutError, ConnectionError) as exc:
            raise ConnectionError(
                'OBS недоступен. Проверьте, что OBS запущен, '
                'WebSocket включён и правильно указаны адрес и порт.'
            ) from exc
        return response.obs_version

    def screenshot(self, name: str, width: int, height: int) -> bytes:
        result = self.request('get_source_screenshot', name, 'png', width, height, -1)
        data = result.image_data
        if ',' in data:
            data = data.split(',', 1)[1]
        return base64.b64decode(data, validate=True)

    def scenes(self) -> list[str]:
        return [s['sceneName'] for s in self.request('get_scene_list').scenes]

    def browser_sources(self) -> list[str]:
        inputs = self.request('get_input_list').inputs
        return sorted({s['inputName'] for s in inputs
                       if s.get('inputKind') == 'browser_source'
                       or s.get('unversionedInputKind') == 'browser_source'})

    def current_scene(self) -> str:
        return self.request('get_current_program_scene').current_program_scene_name

    def profiles(self) -> tuple[list[str], str]:
        r = self.request('get_profile_list')
        return r.profiles, r.current_profile_name

    def collections(self) -> tuple[list[str], str]:
        r = self.request('get_scene_collection_list')
        return r.scene_collections, r.current_scene_collection_name

    def stream_status(self) -> dict:

        reply = self.request('get_stream_status')
        return {
            'active': bool(reply.output_active),
            'reconnecting': bool(reply.output_reconnecting),
        }

    def record_status(self) -> bool:

        return bool(self.request('get_record_status').output_active)

    def scene_items(self, scene: str) -> list[dict]:
        return self.raw('GetSceneItemList', {'sceneName': scene}).scene_items

    def set_item_visible(self, scene: str, item_id: int, visible: bool) -> None:
        self.raw('SetSceneItemEnabled', {
            'sceneName': scene, 'sceneItemId': item_id, 'sceneItemEnabled': visible,
        })

    def close(self) -> None:
        with self.lock:
            self._stop_audio_meter_locked()
            if self.client is not None:
                try:
                    self.client.disconnect()
                finally:
                    self.client = None
