from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
import time

from PIL import Image, ImageChops, ImageOps, ImageStat


@dataclass(frozen=True)
class Inspection:
    reason: str | None
    black_fraction: float
    stddev: float
    frame_difference: float | None
    frozen_for: float

    @property
    def is_bad(self) -> bool:
        return self.reason is not None


class FrameDetector:
    def __init__(self) -> None:
        self.previous: Image.Image | None = None
        self.freeze_started: float | None = None

    def reset(self) -> None:
        self.previous = None
        self.freeze_started = None

    def inspect(self, png: bytes, rules: dict, crop: list[float], now: float | None = None) -> Inspection:
        now = time.monotonic() if now is None else now
        with Image.open(BytesIO(png)) as raw:
            rgba = raw.convert('RGBA')
            base = Image.new('RGBA', rgba.size, (0, 0, 0, 255))
            base.alpha_composite(rgba)
            gray = ImageOps.grayscale(base.convert('RGB'))
        w, h = gray.size
        left, top, right, bottom = crop
        rect = (int(left * w), int(top * h), max(int(right * w), int(left * w) + 1),
                max(int(bottom * h), int(top * h) + 1))
        gray = gray.crop(rect).resize((160, 90), Image.Resampling.BILINEAR)
        hist = gray.histogram()
        threshold = int(rules['black_pixel_threshold'])
        black_fraction = sum(hist[:threshold + 1]) / (gray.width * gray.height)
        stddev = ImageStat.Stat(gray).stddev[0]

        difference = None
        if self.previous is not None:
            difference = ImageStat.Stat(ImageChops.difference(gray, self.previous)).mean[0]
        if difference is None or difference > float(rules['frame_diff_threshold']) or self.freeze_started is None:
            self.freeze_started = now
        frozen_for = 0.0 if self.freeze_started is None else now - self.freeze_started
        self.previous = gray

        reason = None
        if rules['black'] and black_fraction >= float(rules['black_fraction']):
            reason = 'почти полностью чёрный кадр'
        elif rules['uniform'] and stddev <= float(rules['uniform_stddev']):
            reason = 'однотонный / пустой кадр'
        elif (rules['freeze'] and self.freeze_started is not None
              and frozen_for >= float(rules['freeze_seconds'])):
            reason = 'видео не меняется (возможное зависание)'
        return Inspection(reason, black_fraction, stddev, difference, frozen_for)
