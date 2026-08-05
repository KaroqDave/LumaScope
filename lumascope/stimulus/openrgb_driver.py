"""OpenRGB stimulus driver (deterministic ground truth).

When the target device is OpenRGB-supported this is the best driver: the commanded color
*is* the known label, applied in sub-millisecond, with no GUI in the loop. It also enables
the end-to-end ground-truth loop — drive a known-protocol device and confirm the decoder
recovers its real protocol.

``openrgb-python`` is an optional dependency, imported lazily so the rest of LumaScope (and
the manual driver) work without it. Requires the OpenRGB SDK server running (default
127.0.0.1:6742). Not exercised in CI on a machine without OpenRGB.
"""

from __future__ import annotations

from typing import Optional

from ..model import SweepStep
from .base import StimulusDriver


class OpenRGBDriver(StimulusDriver):
    name = "openrgb"

    def __init__(self, host: str = "127.0.0.1", port: int = 6742, device_index: int = 0) -> None:
        self.host = host
        self.port = port
        self.device_index = device_index
        self._client = None
        self._device = None

    def setup(self, led_count: int, total_steps: int = 0) -> None:
        from openrgb import OpenRGBClient  # lazy optional dependency

        self._client = OpenRGBClient(self.host, self.port, name="LumaScope")
        self._device = self._client.devices[self.device_index]
        # A static, per-LED-addressable mode is required for direct color writes.
        for mode in ("Direct", "Static"):
            try:
                self._device.set_mode(mode)
                break
            except Exception:
                continue

    def set_state(self, step: SweepStep) -> bool:
        from openrgb.utils import RGBColor

        colors = [RGBColor(r, g, b) for (r, g, b) in step.colors]
        self._device.set_colors(colors)
        return True

    def teardown(self) -> None:
        if self._client is not None:
            try:
                self._client.disconnect()
            except Exception:
                pass
