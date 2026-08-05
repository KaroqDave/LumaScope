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

Two profiles, because the cost of a step depends entirely on who applies it:

* ``full`` probes **every** LED. Right for an API driver (OpenRGB), where a step costs
  milliseconds. On a 120-LED board it is 535 steps.
* ``quick`` probes a *contiguous* run of the first few LEDs and samples the rest of the
  matrix coarsely: ~46 steps whatever the LED count. Right for the manual driver, where
  every step is a human operating a GUI and ``full`` would mean over an hour of clicking.

``quick`` samples a contiguous prefix rather than spreading probes across the strip, and
that detail is load-bearing: the layout pass distinguishes planar from interleaved by
comparing neighbouring LEDs' offsets, and a gap in the probed LEDs makes a planar device
decode as interleaved. ``tests/test_matrix_profiles.py`` pins this — both layouts, at
realistic LED counts.
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

# Quick profile: six points still fit a gamma curve, and five contiguous LEDs are twice
# the minimum needed to separate planar from interleaved.
QUICK_CHANNEL_VALUES = (0, 51, 102, 153, 204, 255)
QUICK_LED_SAMPLES = 5

FULL, QUICK = "full", "quick"
PROFILES = (FULL, QUICK)


def _blank(count: int) -> list[Color]:
    return [(0, 0, 0) for _ in range(count)]


def probed_leds(led_count: int, profile: str) -> list[int]:
    """Which LEDs beyond LED 0 get a per-channel probe. Contiguous by necessity."""
    if profile == QUICK:
        return list(range(1, min(QUICK_LED_SAMPLES, led_count - 1) + 1))
    return list(range(1, led_count))


def generate(
    led_count: int,
    *,
    profile: str = FULL,
    channel_values: tuple[int, ...] | None = None,
    uniform_values: tuple[int, ...] = DEFAULT_UNIFORM_VALUES,
    brightness_values: tuple[int, ...] | None = DEFAULT_BRIGHTNESS_VALUES,
    include_walk: bool = True,
) -> list[SweepStep]:
    """Build the sweep matrix for a device with ``led_count`` LEDs."""
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r}; choose from {PROFILES}")
    if channel_values is None:
        channel_values = QUICK_CHANNEL_VALUES if profile == QUICK else DEFAULT_CHANNEL_VALUES

    steps: list[SweepStep] = []
    sid = 0

    def add(step_kwargs: dict) -> None:
        nonlocal sid
        steps.append(SweepStep(step_id=sid, **step_kwargs))
        sid += 1

    # 1) LED 0: per-channel sweeps (locate offsets + recover scaling).
    for ch_idx, ch in enumerate(("R", "G", "B")):
        for v in channel_values:
            colors = _blank(led_count)
            rgb = [0, 0, 0]
            rgb[ch_idx] = v
            colors[0] = (rgb[0], rgb[1], rgb[2])
            add(dict(kind=KIND_PER_CHANNEL, colors=colors, led=0, channel=ch, value=v))

    # 2) Further LEDs: a single bright point per channel (per-LED offsets => stride/layout).
    for led in probed_leds(led_count, profile):
        for ch_idx, ch in enumerate(("R", "G", "B")):
            colors = _blank(led_count)
            rgb = [0, 0, 0]
            rgb[ch_idx] = 255
            colors[led] = (rgb[0], rgb[1], rgb[2])
            add(dict(kind=KIND_PER_CHANNEL, colors=colors, led=led, channel=ch, value=255))

    # 3) LED walk: one LED white at a time. Quick walks only the ends -- this is a
    #    cross-check on the mapping, not the source of it.
    if include_walk:
        walk = (sorted({0, 1, led_count - 1} & set(range(led_count)))
                if profile == QUICK else list(range(led_count)))
        for led in walk:
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


def describe(led_count: int, profile: str, *, seconds_per_step: float) -> str:
    """A one-line cost estimate, so nobody starts an hour of clicking unknowingly."""
    n = len(generate(led_count, profile=profile))
    total = n * seconds_per_step
    if total < 90:
        eta = f"~{round(total)}s"
    elif total < 3600:
        eta = f"~{round(total / 60)} min"
    else:
        eta = f"~{total / 3600:.1f} hours"
    return f"{n} steps, {eta}"
