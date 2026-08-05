"""Turn what the decoder inferred into a byte-by-byte field map.

:mod:`lumascope.view` knows how to *draw* an annotated packet; this module decides
*what the annotations are*. Both of LumaScope's structural findings can label bytes:

* a :class:`~lumascope.decode.chunked.ChunkFraming` (recovered from a raw capture)
  names the streaming header -- report id, command, channel, offset, count, payload;
* a :class:`~lumascope.model.ProtocolSpec` (the decoder's final output) names the
  whole packet -- constants, LED bytes in wire-channel order, brightness, checksum.

The point is that a dump can explain itself. Nobody should need a second tool -- or a
language model -- to work out which byte is the LED count.
"""

from __future__ import annotations

from typing import Optional

from .decode.chunked import ChunkFraming
from .model import ProtocolSpec
from .view import (
    KIND_BRIGHTNESS,
    KIND_CHECKSUM,
    KIND_HEADER,
    KIND_PAD,
    KIND_PAYLOAD,
    Field,
    FieldMap,
)

RGB_TAGS = ("R", "G", "B")


def _prefix_fields(prefix_len: int, data: bytes) -> list[Field]:
    """Name the constant lead bytes. Two or more reads as report id + command, which is
    the near-universal HID shape; a single byte is just the report id."""
    if prefix_len <= 0:
        return []
    if prefix_len == 1:
        return [Field(0, 1, "report id", "id", _hexval(data, 0), KIND_HEADER)]
    out = [
        Field(0, 1, "report id", "id", _hexval(data, 0), KIND_HEADER),
        Field(1, 2, "command", "cm", _hexval(data, 1), KIND_HEADER),
    ]
    if prefix_len > 2:
        out.append(Field(2, prefix_len, "constant", "==",
                         data[2:prefix_len].hex(" "), KIND_HEADER))
    return out


def _hexval(data: bytes, i: int) -> str:
    return f"0x{data[i]:02x} ({data[i]})" if i < len(data) else ""


def fields_from_framing(framing: ChunkFraming, data: bytes) -> FieldMap:
    """Field map for one chunk of a streamed protocol."""
    fields = _prefix_fields(len(framing.prefix), data)

    if framing.channel_pos < len(data):
        raw = data[framing.channel_pos]
        logical = raw & framing.channel_mask
        detail = f"channel {logical}"
        if framing.final_flag and (raw & ~framing.channel_mask):
            detail += f"  + final-chunk flag {framing.final_flag:#04x}"
        fields.append(Field(framing.channel_pos, framing.channel_pos + 1,
                            "channel", "ch", detail, KIND_HEADER))

    unit_name = "LED" if framing.unit == 3 else "byte"
    if framing.offset_pos < len(data):
        raw = data[framing.offset_pos]
        detail = f"starts at {unit_name} {raw}"
        if framing.unit != 1:
            detail += f" (byte {raw * framing.unit} of the buffer)"
        fields.append(Field(framing.offset_pos, framing.offset_pos + 1, "offset", "of",
                            detail, KIND_HEADER))

    count = 0
    if framing.count_pos < len(data):
        count = data[framing.count_pos]
        fields.append(Field(framing.count_pos, framing.count_pos + 1, "count", "ct",
                            f"{count} {unit_name}(s) in this chunk", KIND_HEADER))

    start = framing.payload_start
    payload_len = count * framing.unit
    end = min(len(data), start + payload_len) if payload_len else len(data)
    if end > start:
        if framing.unit == 3:
            fields.append(Field(start, end, "LED colour data", "",
                                f"{(end - start) // 3} LED(s)", KIND_PAYLOAD, RGB_TAGS))
        else:
            fields.append(Field(start, end, "payload", "..",
                                f"{end - start} byte(s)", KIND_PAYLOAD))
    if end < len(data):
        fields.append(Field(end, len(data), "unused / padding", "--",
                            f"{len(data) - end} byte(s)", KIND_PAD))
    return FieldMap(fields)


def fields_from_spec(spec: ProtocolSpec, data: Optional[bytes] = None) -> FieldMap:
    """Field map for a packet described by a decoded :class:`ProtocolSpec`."""
    data = data if data is not None else b"\x00" * spec.packet_len
    n = len(data)
    fields: list[Field] = []
    claimed: set[int] = set()

    def claim(f: Field) -> None:
        if f.start >= n:
            return
        f.end = min(f.end, n)
        if f.end <= f.start:
            return
        fields.append(f)
        claimed.update(range(f.start, f.end))

    if spec.report_id is not None:
        claim(Field(0, 1, "report id", "id", _hexval(data, 0), KIND_HEADER))
    for offset, value in spec.header.constant_bytes:
        if offset in claimed:
            continue
        claim(Field(offset, offset + 1, "constant", "==", f"0x{value:02x}", KIND_HEADER))
    if spec.header.command_offset is not None and spec.header.command_offset not in claimed:
        claim(Field(spec.header.command_offset, spec.header.command_offset + 1,
                    "command", "cm", _hexval(data, spec.header.command_offset), KIND_HEADER))
    if spec.header.mode_offset is not None and spec.header.mode_offset not in claimed:
        claim(Field(spec.header.mode_offset, spec.header.mode_offset + 1,
                    "mode", "md", _hexval(data, spec.header.mode_offset), KIND_HEADER))

    leds = spec.leds
    order = tuple(leds.channel_order.upper()) or RGB_TAGS
    if leds.count:
        if leds.layout == "planar":
            plane = leds.count
            for k, ch in enumerate(order):
                start = leds.base_offset + k * plane
                claim(Field(start, start + plane, f"LED {ch} plane", ch,
                            f"{plane} byte(s)", KIND_PAYLOAD, (ch,)))
        elif leds.stride == 3:
            start = leds.base_offset
            claim(Field(start, start + leds.count * 3, "LED colour data", "",
                        f"{leds.count} LED(s), wire order {leds.channel_order}",
                        KIND_PAYLOAD, order))
        else:
            for led in range(leds.count):
                start = leds.base_offset + led * leds.stride
                claim(Field(start, start + 3, f"LED {led}", "",
                            f"wire order {leds.channel_order}", KIND_PAYLOAD, order))

    if spec.brightness.present and spec.brightness.offset is not None:
        claim(Field(spec.brightness.offset, spec.brightness.offset + 1, "brightness", "br",
                    _hexval(data, spec.brightness.offset), KIND_BRIGHTNESS))

    if spec.checksum.present and spec.checksum.offset is not None:
        rng = spec.checksum.range
        detail = spec.checksum.kind
        if rng:
            detail += f" over bytes {rng[0]}..{rng[1] - 1}"
        claim(Field(spec.checksum.offset, spec.checksum.offset + spec.checksum.width,
                    "checksum", "ck", detail, KIND_CHECKSUM))

    # Everything left over is honestly labelled as unaccounted for, in contiguous runs.
    run_start: Optional[int] = None
    for i in range(n + 1):
        unclaimed = i < n and i not in claimed
        if unclaimed and run_start is None:
            run_start = i
        elif not unclaimed and run_start is not None:
            fields.append(Field(run_start, i, "unused / padding", "--",
                                f"{i - run_start} byte(s)", KIND_PAD))
            run_start = None

    fields.sort(key=lambda f: f.start)
    return FieldMap(fields)


def describe_framing(framing: ChunkFraming) -> str:
    """A plain-English sentence for an inferred chunk framing."""
    unit = "LEDs" if framing.unit == 3 else "bytes"
    prefix = framing.prefix.hex(" ") or "(none)"
    parts = [
        f"Each packet starts with {prefix}, then:",
        f"  byte {framing.channel_pos} = which channel/header this writes to"
        + (f" (top bit {framing.final_flag:#04x} marks the last chunk)" if framing.final_flag else ""),
        f"  byte {framing.offset_pos} = how far into that channel's buffer this chunk starts, in {unit}",
        f"  byte {framing.count_pos} = how many {unit} this chunk carries"
        + (f" (usually {framing.chunk_count})" if framing.chunk_count else ""),
        f"  byte {framing.payload_start} onward = the colour data itself",
    ]
    return "\n".join(parts)
