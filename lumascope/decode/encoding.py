"""Global brightness-byte detection.

The brightness sweep holds color constant (white) and varies a global brightness. After
the checksum and per-LED color bytes are accounted for, the single remaining varying
column in that group is the brightness byte; its observed range gives [min, max].
"""

from __future__ import annotations

from ..model import KIND_BRIGHTNESS, BrightnessField, Corpus
from .diff import of_length, varying_offsets


def detect_brightness(
    corpus: Corpus,
    length: int,
    exclude_offsets: set[int],
) -> BrightnessField:
    """Locate a global brightness byte from the brightness sweep, if one exists."""
    group = of_length(corpus.by_kind(KIND_BRIGHTNESS), length)
    if len(group) < 2:
        return BrightnessField(present=False)

    candidates = sorted(varying_offsets(group, length) - exclude_offsets)
    if not candidates:
        return BrightnessField(present=False)

    # Prefer a column whose value moves monotonically with the swept brightness.
    pairs_by_offset = {
        o: sorted(((lf.step.brightness, lf.data[o]) for lf in group), key=lambda p: p[0])
        for o in candidates
    }
    offset = _best_monotonic(pairs_by_offset)
    if offset is None:
        return BrightnessField(present=False)

    pairs = pairs_by_offset[offset]
    return BrightnessField(
        present=True,
        offset=offset,
        min=min(b for _, b in pairs),
        max=max(b for _, b in pairs),
    )


def _best_monotonic(pairs_by_offset: dict[int, list[tuple[int, int]]]) -> int | None:
    best: int | None = None
    best_span = -1
    for offset, pairs in pairs_by_offset.items():
        ys = [b for _, b in pairs]
        non_decreasing = all(b >= a for a, b in zip(ys, ys[1:]))
        non_increasing = all(b <= a for a, b in zip(ys, ys[1:]))
        if non_decreasing or non_increasing:
            span = max(ys) - min(ys)
            if span > best_span:
                best, best_span = offset, span
    return best
