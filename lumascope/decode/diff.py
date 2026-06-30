"""Byte-column analysis + field localization.

The core primitive is "what does byte column *o* do across this set of frames":
constant columns are header/padding, columns that track a swept parameter are that
parameter's field, and the leftover varying column (handled in :mod:`.checksum`) is
the checksum.
"""

from __future__ import annotations

from collections import Counter, defaultdict

from ..model import KIND_PER_CHANNEL, LabeledFrame, Scaling

# --------------------------------------------------------------------------- #
# Column primitives
# --------------------------------------------------------------------------- #
def modal_length(frames: list[LabeledFrame]) -> int:
    """Most common frame length — the device's nominal packet size."""
    counts = Counter(len(lf.data) for lf in frames)
    return counts.most_common(1)[0][0]


def of_length(frames: list[LabeledFrame], length: int) -> list[LabeledFrame]:
    return [lf for lf in frames if len(lf.data) == length]


def column(frames: list[LabeledFrame], offset: int) -> list[int]:
    return [lf.data[offset] for lf in frames]


def varying_offsets(frames: list[LabeledFrame], length: int) -> set[int]:
    """Offsets whose byte value is not identical across every frame."""
    out: set[int] = set()
    for o in range(length):
        first = frames[0].data[o]
        if any(lf.data[o] != first for lf in frames):
            out.add(o)
    return out


def constant_offsets(frames: list[LabeledFrame], length: int) -> dict[int, int]:
    """Offsets that hold the same value across every frame -> that value."""
    out: dict[int, int] = {}
    for o in range(length):
        first = frames[0].data[o]
        if all(lf.data[o] == first for lf in frames):
            out[o] = first
    return out


def group_per_channel(frames: list[LabeledFrame]) -> dict[tuple[int, str], list[LabeledFrame]]:
    """Group per-channel sweep steps by (led, channel)."""
    groups: dict[tuple[int, str], list[LabeledFrame]] = defaultdict(list)
    for lf in frames:
        if lf.step.kind == KIND_PER_CHANNEL:
            groups[(lf.step.led, lf.step.channel)].append(lf)
    return groups


def modal_baseline(frames: list[LabeledFrame], length: int) -> bytes:
    """Per-offset most-common byte across all frames — the device's "resting" frame.

    Data bytes are 0 in most frames, header bytes hold their constant, so this
    approximates an all-off frame and gives every sweep (even single-point ones) a
    reference to diff against.
    """
    base = bytearray(length)
    for o in range(length):
        base[o] = Counter(lf.data[o] for lf in frames).most_common(1)[0][0]
    return bytes(base)


# --------------------------------------------------------------------------- #
# Scaling inference (value -> wire byte)
# --------------------------------------------------------------------------- #
def _median(xs: list[float]) -> float:
    s = sorted(xs)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2.0


def derive_scaling(values: list[int], bytes_seq: list[int]) -> Scaling | None:
    """Find the scaling that maps every ``values[i]`` to ``bytes_seq[i]``, or None.

    Tries identity, then linear (byte = round(value*k)), then gamma
    (byte = round(255*(value/255)**g)) via a fine grid search. Needs the wrong column
    to *fail* so localization picks the right one, hence the all-or-nothing match.
    """
    pairs = list(zip(values, bytes_seq))

    # identity
    if all(b == max(0, min(255, v)) for v, b in pairs):
        return Scaling(type="identity")

    nonzero = [(v, b) for v, b in pairs if v > 0]

    # linear: byte = round(value * k)
    if nonzero:
        k = _median([b / v for v, b in nonzero])
        if k > 0 and all(b == max(0, min(255, round(v * k))) for v, b in pairs):
            if abs(k - 1.0) < 1e-9:
                return Scaling(type="identity")
            return Scaling(type="linear", k=round(k, 6))

    # gamma: byte = round(255*(value/255)**g). Iterate exact integer hundredths so a
    # recovered gamma equals a literal like 2.2 bit-for-bit (clean round-trip).
    for gi in range(50, 401):
        g = gi / 100.0
        if all(b == max(0, min(255, round(255.0 * (v / 255.0) ** g))) for v, b in pairs):
            return Scaling(type="gamma", gamma=round(g, 4))
    return None


# --------------------------------------------------------------------------- #
# Field localization
# --------------------------------------------------------------------------- #
def localize_fields(
    groups: dict[tuple[int, str], list[LabeledFrame]],
    color_frames: list[LabeledFrame],
    checksum_offsets: set[int],
    length: int,
) -> tuple[dict[tuple[int, str], int], Scaling]:
    """Locate each (led, channel) wire offset and the global channel scaling.

    Each per-channel sweep sets exactly one channel of one LED (all else off), so the
    byte that differs from the :func:`modal_baseline` (other than the checksum) is that
    channel's wire offset. Works for full sweeps *and* single-point (value-255) sweeps.
    Scaling is voted only from rich (>=3 distinct value) sweeps — single points can't
    tell identity from gamma.
    """
    baseline = modal_baseline(color_frames, length)
    field_map: dict[tuple[int, str], int] = {}
    scaling_votes: list[Scaling] = []

    for (led, ch), group in groups.items():
        pairs = sorted(((lf.step.value, lf.data) for lf in group), key=lambda p: p[0])
        values = [v for v, _ in pairs]
        distinct_values = len(set(values))

        diff_offsets: set[int] = set()
        for _, d in pairs:
            diff_offsets.update(o for o in range(length) if d[o] != baseline[o])
        candidates = sorted(diff_offsets - checksum_offsets)
        if not candidates:
            continue

        chosen_offset: int | None = None
        chosen_scaling: Scaling | None = None
        for o in candidates:
            sc = derive_scaling(values, [d[o] for _, d in pairs])
            if sc is not None:
                chosen_offset, chosen_scaling = o, sc
                break

        if chosen_offset is None:
            # Odd firmware curve we can't fit: take the column that deviates most.
            chosen_offset = max(
                candidates, key=lambda o: max(abs(d[o] - baseline[o]) for _, d in pairs)
            )
            chosen_scaling = Scaling(type="identity")

        field_map[(led, ch)] = chosen_offset
        if distinct_values >= 3:
            scaling_votes.append(chosen_scaling)

    return field_map, _consensus_scaling(scaling_votes)


def _consensus_scaling(votes: list[Scaling]) -> Scaling:
    if not votes:
        return Scaling(type="identity")
    keyed = Counter((v.type, v.k, v.gamma) for v in votes)
    (vtype, k, gamma), _ = keyed.most_common(1)[0]
    return Scaling(type=vtype, k=k, gamma=gamma)
