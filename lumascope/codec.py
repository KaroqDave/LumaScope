"""Reference codec: turn a :class:`ProtocolSpec` + per-LED colors into wire bytes.

This is the single source of truth for how a spec maps to bytes. It is used by:

* :mod:`lumascope.synthetic` — to fabricate labeled captures from a known spec
  (so the decode engine can be tested with no hardware), and
* :mod:`lumascope.decode.spec` — the validation loop re-encodes held-out frames and
  asserts byte-for-byte equality against what was captured.

The C++ emitter (:mod:`lumascope.emit.openrgb_cpp`) reproduces this same logic in C++,
so a spec that round-trips here is one that will round-trip in LumaCore.
"""

from __future__ import annotations

from .model import (
    BrightnessField,
    ChecksumModel,
    Color,
    LedLayout,
    ProtocolSpec,
    Scaling,
    logical_index,
)


def clamp8(v: int) -> int:
    return 0 if v < 0 else 255 if v > 255 else int(v)


# --------------------------------------------------------------------------- #
# Channel scaling
# --------------------------------------------------------------------------- #
def apply_scaling(value: int, scaling: Scaling) -> int:
    """Map a logical channel value (0..255) to its wire byte."""
    if scaling.type == "linear":
        return clamp8(round(value * scaling.k))
    if scaling.type == "gamma":
        return clamp8(round(255.0 * (value / 255.0) ** scaling.gamma))
    return clamp8(value)  # identity


def apply_brightness(value: int, field: BrightnessField) -> int:
    """Map a logical brightness (0..255) into the device's [min, max] range."""
    span = field.max - field.min
    return clamp8(field.min + round(value * span / 255.0))


# --------------------------------------------------------------------------- #
# LED offset mapping
# --------------------------------------------------------------------------- #
def led_channel_offset(layout: LedLayout, led: int, wire_pos: int) -> int:
    """Byte offset of the ``wire_pos``-th channel of ``led``.

    ``wire_pos`` indexes into ``layout.channel_order`` (0 = first wire channel).
    """
    if layout.explicit_offsets is not None:
        return layout.explicit_offsets[led][wire_pos]
    if layout.layout == "planar":
        return layout.base_offset + wire_pos * layout.count + led
    return layout.base_offset + led * layout.stride + wire_pos  # interleaved


# --------------------------------------------------------------------------- #
# Checksums
# --------------------------------------------------------------------------- #
def _reflect(value: int, width: int) -> int:
    out = 0
    for i in range(width):
        if value & (1 << i):
            out |= 1 << (width - 1 - i)
    return out


def crc_compute(
    data: bytes,
    width: int,
    poly: int,
    init: int,
    refin: bool,
    refout: bool,
    xorout: int,
) -> int:
    """Generic Williams-model CRC (width >= 8). Matches the reveng/catalog conventions."""
    mask = (1 << width) - 1
    topbit = 1 << (width - 1)
    crc = init & mask
    for byte in data:
        if refin:
            byte = _reflect(byte, 8)
        crc ^= (byte << (width - 8)) & mask
        for _ in range(8):
            if crc & topbit:
                crc = ((crc << 1) ^ poly) & mask
            else:
                crc = (crc << 1) & mask
    if refout:
        crc = _reflect(crc, width)
    return (crc ^ xorout) & mask


def compute_checksum_value(model: ChecksumModel, data: bytes) -> int:
    """Compute the integer checksum of ``data`` under ``model`` (excludes the field itself)."""
    s = sum(data)
    if model.kind == "sum8":
        return s & 0xFF
    if model.kind == "sum16":
        return s & 0xFFFF
    if model.kind == "twos8":
        return (-s) & 0xFF
    if model.kind == "onescomp8":
        return (~s) & 0xFF
    if model.kind == "xor8":
        x = 0
        for b in data:
            x ^= b
        return x & 0xFF
    if model.kind == "crc":
        p = model.params
        return crc_compute(
            data,
            width=p["width"],
            poly=p["poly"],
            init=p["init"],
            refin=p["refin"],
            refout=p["refout"],
            xorout=p["xorout"],
        )
    raise ValueError(f"unknown checksum kind: {model.kind}")


def checksum_bytes(model: ChecksumModel, value: int) -> bytes:
    return value.to_bytes(model.width, model.endian)


# --------------------------------------------------------------------------- #
# Frame encoding
# --------------------------------------------------------------------------- #
def encode_frame(
    spec: ProtocolSpec,
    colors: list[Color],
    brightness: int = 255,
    command: int | None = None,
    mode_value: int | None = None,
) -> bytes:
    """Build one wire frame for ``colors`` (per-LED logical RGB) under ``spec``."""
    buf = bytearray(spec.packet_len)

    # Report ID (byte 0 for feature/output reports), if the transport carries it.
    if spec.report_id is not None and spec.packet_len > 0:
        buf[0] = spec.report_id & 0xFF

    # Fixed header bytes.
    for offset, value in spec.header.constant_bytes:
        buf[offset] = value & 0xFF
    if command is not None and spec.header.command_offset is not None:
        buf[spec.header.command_offset] = command & 0xFF
    if mode_value is not None and spec.header.mode_offset is not None:
        buf[spec.header.mode_offset] = mode_value & 0xFF

    # Per-LED colors.
    layout = spec.leds
    for led in range(min(layout.count, len(colors))):
        rgb = colors[led]
        for wire_pos, ch in enumerate(layout.channel_order):
            val = rgb[logical_index(ch)]
            buf[led_channel_offset(layout, led, wire_pos)] = apply_scaling(val, layout.scaling)

    # Global brightness byte.
    if spec.brightness.present and spec.brightness.offset is not None:
        buf[spec.brightness.offset] = apply_brightness(brightness, spec.brightness)

    # Checksum (computed last, over its declared range, excluding its own bytes).
    cs = spec.checksum
    if cs.present and cs.offset is not None and cs.range is not None:
        start, end = cs.range
        covered = bytes(buf[start:end])
        value = compute_checksum_value(cs, covered)
        buf[cs.offset : cs.offset + cs.width] = checksum_bytes(cs, value)

    return bytes(buf)
