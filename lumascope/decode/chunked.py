"""Chunked / streamed protocol reassembly.

Some devices (e.g. ASUS Aura USB, ``EC 40 <channel> <offset> <count> <data>``) don't send one
packet per LED state — they stream a logical state across many small packets, each writing a
``count``-byte slice at ``offset`` into a per-``channel`` buffer. The single-packet decode
engine can't see the structure until those chunks are reassembled.

This pass does that: it infers the chunk framing from a raw capture, then concatenates the
chunks into dense per-channel buffers (last write wins, so a re-streamed static state collapses
to its final value). The assembled buffers can then be fed to the normal field/stride/encoding
analysis.

Assumes the frames passed in are a single command class (filter by report id / command first)
whose header is ``[constant prefix][channel][offset][count][payload…]`` — the common shape.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from math import gcd
from typing import Optional

from ..model import CaptureFrame


@dataclass
class ChunkFraming:
    """Where the chunk header fields live within each packet.

    ``unit`` is the bytes-per-element of the offset/count fields: 1 when they count payload
    bytes, 3 when they count RGB LEDs (ASUS Aura: ``count``=20 means 20 LEDs = 60 payload bytes).
    """

    prefix: bytes        # constant leading bytes (e.g. report id + command)
    channel_pos: int
    channel_mask: int    # AND-mask to strip a last-chunk/flag bit (0x7f) -> logical channel
    offset_pos: int
    count_pos: int
    payload_start: int
    unit: int = 1

    def matches(self, data: bytes) -> bool:
        return len(data) >= self.payload_start and data[: len(self.prefix)] == self.prefix


def _common_prefix_len(datas: list[bytes]) -> int:
    """Number of leading byte columns that are constant across all packets."""
    n = min(len(d) for d in datas)
    out = 0
    for i in range(n):
        if len({d[i] for d in datas}) == 1:
            out += 1
        else:
            break
    return out


def _common_stride(values: list[int]) -> int:
    """GCD of distinct values (>0); a regular offset column divides by its chunk stride."""
    vals = sorted(set(values))
    g = 0
    for v in vals:
        g = gcd(g, v)
    return g


def infer_framing(frames: list[CaptureFrame]) -> Optional[ChunkFraming]:
    """Propose a :class:`ChunkFraming` from a raw chunk capture.

    Heuristic: the constant lead bytes are the prefix; the three header columns right after it
    are channel/offset/count, told apart by behaviour — ``count`` is the most constant column,
    ``offset`` is the column whose distinct values share a common stride (0,20,40,…), and the
    remaining one is ``channel`` (flag bit 0x80 stripped if present).
    """
    datas = [f.data for f in frames if f.data]
    if len(datas) < 2:
        return None
    prefix_len = _common_prefix_len(datas)
    if prefix_len == 0:
        return None  # no stable command prefix -> not a single command class
    n = min(len(d) for d in datas)
    if prefix_len + 3 > n:
        return None
    header = list(range(prefix_len, prefix_len + 3))  # channel / offset / count, some order
    cols = {i: [d[i] for d in datas] for i in header}
    card = {i: len(set(v)) for i, v in cols.items()}

    # The defining signal of a chunked stream: the offset column advances by exactly the chunk
    # size, so its stride equals the count column's value. Try every (count, offset) assignment
    # and accept the one that satisfies it (this is robust to a last-chunk flag bit in the
    # channel column, which would otherwise masquerade as a strided offset).
    for count_pos in header:
        count_mode = Counter(cols[count_pos]).most_common(1)[0][0]
        if count_mode <= 1:
            continue
        for offset_pos in header:
            if offset_pos == count_pos or card[offset_pos] < 2:
                continue
            if _common_stride(cols[offset_pos]) != count_mode:
                continue
            channel_pos = next(i for i in header if i not in (count_pos, offset_pos))
            channel_mask = 0x7F if any(v & 0x80 for v in cols[channel_pos]) else 0xFF
            payload_start = prefix_len + 3
            return ChunkFraming(
                prefix=bytes(datas[0][:prefix_len]),
                channel_pos=channel_pos,
                channel_mask=channel_mask,
                offset_pos=offset_pos,
                count_pos=count_pos,
                payload_start=payload_start,
                unit=_infer_unit(datas, payload_start, count_pos, count_mode),
            )
    return None


def _infer_unit(datas: list[bytes], payload_start: int, count_pos: int, count_mode: int) -> int:
    """Bytes per element of the count/offset fields: 1 if ``count`` counts payload bytes, 3 if
    it counts RGB LEDs (Aura). Decided by a padding test — if a full-``count`` packet carries
    real data *beyond* its first ``count`` payload bytes, those fields are in larger units.
    (Robust to colours whose trailing channels are zero, e.g. red = ``ff 00 00``.)
    """
    full = [d for d in datas if count_mode and d[count_pos] == count_mode]
    if not full:
        return 1
    capacity = max(len(d) for d in full) - payload_start
    if capacity <= count_mode or capacity % count_mode != 0:
        return 1
    beyond_has_data = any(
        any(d[payload_start + count_mode: payload_start + capacity]) for d in full
    )
    return capacity // count_mode if beyond_has_data else 1


def reassemble(frames: list[CaptureFrame], framing: ChunkFraming) -> dict[int, bytes]:
    """Concatenate chunks into dense per-channel buffers (last write wins)."""
    buffers: dict[int, bytearray] = {}
    for f in frames:
        d = f.data
        if not framing.matches(d):
            continue
        channel = d[framing.channel_pos] & framing.channel_mask
        offset = d[framing.offset_pos] * framing.unit
        count = d[framing.count_pos] * framing.unit
        payload = d[framing.payload_start: framing.payload_start + count]
        if not payload:
            continue
        buf = buffers.setdefault(channel, bytearray())
        end = offset + len(payload)
        if len(buf) < end:
            buf.extend(b"\x00" * (end - len(buf)))
        buf[offset:end] = payload
    return {ch: bytes(b) for ch, b in buffers.items()}


def reassemble_auto(frames: list[CaptureFrame]) -> tuple[Optional[ChunkFraming], dict[int, bytes]]:
    """Infer the framing and reassemble in one call. Returns ``(framing, channel_buffers)``."""
    framing = infer_framing(frames)
    if framing is None:
        return None, {}
    return framing, reassemble(frames, framing)


def dominant_command_class(frames: list[CaptureFrame]) -> list[CaptureFrame]:
    """Pick the largest group of outbound frames sharing (length, report id, command).

    A raw bus/hook capture is full of unrelated traffic (other devices, polls); the chunked
    color writes are the dominant outbound command class.
    """
    from collections import Counter

    out = [f for f in frames if f.direction == "out" and len(f.data) >= 5]
    if not out:
        return []
    key = Counter((len(f.data), f.data[0], f.data[1]) for f in out).most_common(1)[0][0]
    return [f for f in out if (len(f.data), f.data[0], f.data[1]) == key]


def reassemble_capture(
    frames: list[CaptureFrame],
) -> tuple[Optional[ChunkFraming], dict[int, bytes]]:
    """End-to-end on a noisy capture: isolate the dominant command class, infer, reassemble."""
    return reassemble_auto(dominant_command_class(frames))
