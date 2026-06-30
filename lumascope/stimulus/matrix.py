"""Sweep-matrix generator — the controlled-stimulus contract the decoder relies on.

The decode engine can only localize a field if exactly one thing varies at a time.
This module produces that disciplined set of :class:`SweepStep` s:

* **per-channel** sweeps on LED 0 (full 0..255) — locate LED-0 R/G/B offsets + scaling.
* **per-channel** single points (value 255) on LEDs 1..n-1 — reveal stride + channel order.
* **LED walk** — one LED lit white at a time — cross-checks stride / per-LED mapping.
* **uniform** sweeps — every LED the same — give whole-frame variety so the checksum
  search sees the field change as a function of the *whole* packet (breaks the
  degenerate "only one byte ever changes" symmetry between a channel byte and a checksum).
* **brightness** sweep (optional) — color held white, brightness swept — isolates a
  global brightness byte.

Keep `value` lists short: the matrix is run against real hardware one step at a time
with settle delays, so steps cost wall-clock seconds each.
"""

from __future__ import annotations

from ..model import (
    KIND_BRIGHTNESS,
    KIND_LED_WALK,
    KIND_PER_CHANNEL,
    KIND_UNIFORM,
    Color,
    SweepStep,
)

# Default sweep value lists. Coarse but enough to fit identity/linear/gamma and to
# expose a checksum's whole-frame dependence.
DEFAULT_CHANNEL_VALUES = (0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255)
DEFAULT_UNIFORM_VALUES = (0, 64, 128, 192, 255)
DEFAULT_BRIGHTNESS_VALUES = (0, 64, 128, 192, 255)


def _blank(count: int) -> list[Color]:
    return [(0, 0, 0) for _ in range(count)]


def generate(
    led_count: int,
    *,
    channel_values: tuple[int, ...] = DEFAULT_CHANNEL_VALUES,
    uniform_values: tuple[int, ...] = DEFAULT_UNIFORM_VALUES,
    brightness_values: tuple[int, ...] | None = DEFAULT_BRIGHTNESS_VALUES,
    include_walk: bool = True,
) -> list[SweepStep]:
    """Build the full sweep matrix for a device with ``led_count`` LEDs."""
    steps: list[SweepStep] = []
    sid = 0

    def add(step_kwargs: dict) -> None:
        nonlocal sid
        steps.append(SweepStep(step_id=sid, **step_kwargs))
        sid += 1

    # 1) LED 0: full per-channel sweeps (locate offsets + recover scaling).
    for ch_idx, ch in enumerate(("R", "G", "B")):
        for v in channel_values:
            colors = _blank(led_count)
            rgb = [0, 0, 0]
            rgb[ch_idx] = v
            colors[0] = (rgb[0], rgb[1], rgb[2])
            add(dict(kind=KIND_PER_CHANNEL, colors=colors, led=0, channel=ch, value=v))

    # 2) LEDs 1..n-1: a single bright point per channel (locate per-LED offsets => stride).
    for led in range(1, led_count):
        for ch_idx, ch in enumerate(("R", "G", "B")):
            colors = _blank(led_count)
            rgb = [0, 0, 0]
            rgb[ch_idx] = 255
            colors[led] = (rgb[0], rgb[1], rgb[2])
            add(dict(kind=KIND_PER_CHANNEL, colors=colors, led=led, channel=ch, value=255))

    # 3) LED walk: one LED white at a time.
    if include_walk:
        for led in range(led_count):
            colors = _blank(led_count)
            colors[led] = (255, 255, 255)
            add(dict(kind=KIND_LED_WALK, colors=colors, led=led))

    # 4) Uniform sweeps: whole-frame variety for checksum discovery.
    for v in uniform_values:
        colors = [(v, v, v) for _ in range(led_count)]
        add(dict(kind=KIND_UNIFORM, colors=colors, value=v))

    # 5) Brightness sweep: color fixed white, brightness swept.
    if brightness_values:
        for b in brightness_values:
            colors = [(255, 255, 255) for _ in range(led_count)]
            add(dict(kind=KIND_BRIGHTNESS, colors=colors, brightness=b))

    return steps
