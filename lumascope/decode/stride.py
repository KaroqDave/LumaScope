"""Per-LED layout recovery: base offset, stride, channel order, interleaved vs planar.

Given the per-(led, channel) offset map from :mod:`.diff`, fit how the bytes are laid
out across the strip. Two common shapes:

* **interleaved** — ``RGBRGB...``: ``offset(led, pos) = base + led*stride + pos``
  (stride may exceed 3 if there is per-LED padding).
* **planar** — ``RR..GG..BB..``: ``offset(led, pos) = base + pos*count + led``.

Channel order (e.g. ``GRB``) is read off LED 0 by sorting the three channels by offset.
"""

from __future__ import annotations

from ..model import LedLayout, Scaling

CHANNELS = ("R", "G", "B")


def _along_led_stride(field_map: dict[tuple[int, str], int], ch: str, count: int) -> int | None:
    """Constant offset delta between consecutive LEDs for one channel, or None."""
    offs = [field_map[(led, ch)] for led in range(count) if (led, ch) in field_map]
    if len(offs) < 2:
        return None
    diffs = [b - a for a, b in zip(offs, offs[1:])]
    return diffs[0] if all(d == diffs[0] for d in diffs) else None


def solve_layout(
    field_map: dict[tuple[int, str], int],
    led_count: int,
    scaling: Scaling,
) -> LedLayout:
    """Fit a :class:`LedLayout` from the recovered per-(led, channel) offsets."""
    if not all((0, ch) in field_map for ch in CHANNELS):
        # Could not localize LED 0 fully — emit a best-effort default.
        base = min(field_map.values()) if field_map else 0
        return LedLayout(count=led_count, layout="interleaved", base_offset=base,
                         stride=3, channel_order="RGB", scaling=scaling)

    led0 = {ch: field_map[(0, ch)] for ch in CHANNELS}
    base_offset = min(led0.values())
    channel_order = "".join(sorted(CHANNELS, key=lambda c: led0[c]))
    led0_sorted = sorted(led0.values())
    contiguous = (led0_sorted[-1] - led0_sorted[0]) == 2

    along = {ch: _along_led_stride(field_map, ch, led_count) for ch in CHANNELS}
    along_vals = {v for v in along.values() if v is not None}

    # Interleaved: channels of LED 0 are adjacent; consecutive LEDs differ by a constant stride.
    if contiguous and len(along_vals) == 1:
        stride = next(iter(along_vals))
        if stride is not None and stride >= 3:
            return LedLayout(count=led_count, layout="interleaved", base_offset=base_offset,
                             stride=stride, channel_order=channel_order, scaling=scaling)

    # Planar: along-LED stride is 1 for every channel, and channels are `count` apart.
    if along_vals == {1} and (led0_sorted[1] - led0_sorted[0]) == led_count:
        return LedLayout(count=led_count, layout="planar", base_offset=base_offset,
                         stride=1, channel_order=channel_order, scaling=scaling)

    # Fallback: interleaved with the best stride estimate we have.
    stride = next(iter(along_vals), 3) or 3
    return LedLayout(count=led_count, layout="interleaved", base_offset=base_offset,
                     stride=stride, channel_order=channel_order, scaling=scaling)
