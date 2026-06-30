"""Ground-truth example protocol specs.

These exercise the decode engine across the dimensions real RGB devices vary in:
interleaved vs planar layout, channel order, identity vs gamma scaling, presence of a
global brightness byte, and sum/xor/CRC checksums. The synthetic generator turns each
into a labeled corpus; a correct decoder recovers the same spec (verified in tests and
by ``lumascope selftest``).
"""

from __future__ import annotations

from .model import (
    BrightnessField,
    ChecksumModel,
    HeaderField,
    LedLayout,
    ProtocolSpec,
    Scaling,
)


def interleaved_grb_sum8() -> ProtocolSpec:
    """HID feature, report id 0xCC, 10 LEDs interleaved GRB, global brightness, sum8."""
    return ProtocolSpec(
        name="demo-interleaved-grb-sum8",
        transport="hid_feature",
        report_id=0xCC,
        packet_len=64,
        header=HeaderField(constant_bytes=[(1, 0x24)]),
        leds=LedLayout(
            count=10, layout="interleaved", base_offset=2, stride=3,
            channel_order="GRB", scaling=Scaling(type="identity"),
        ),
        brightness=BrightnessField(present=True, offset=32, min=0, max=255),
        checksum=ChecksumModel(present=True, kind="sum8", offset=33, width=1, range=(1, 33)),
        vid=0x1234, pid=0x5678,
    )


def interleaved_gamma_crc16() -> ProtocolSpec:
    """HID output, no report id, 8 LEDs interleaved RGB, gamma 2.2, CRC-16/MODBUS."""
    return ProtocolSpec(
        name="demo-interleaved-gamma-crc16",
        transport="hid_output",
        report_id=None,
        packet_len=40,
        header=HeaderField(constant_bytes=[(0, 0xAA), (1, 0x55)]),
        leds=LedLayout(
            count=8, layout="interleaved", base_offset=2, stride=3,
            channel_order="RGB", scaling=Scaling(type="gamma", gamma=2.2),
        ),
        brightness=BrightnessField(present=False),
        checksum=ChecksumModel(
            present=True, kind="crc", offset=26, width=2, endian="little", range=(0, 26),
            params={
                "name": "CRC-16/MODBUS", "width": 16, "poly": 0x8005,
                "init": 0xFFFF, "refin": True, "refout": True, "xorout": 0x0000,
            },
        ),
        vid=0x1532, pid=0x0111,
    )


def planar_rgb_xor8() -> ProtocolSpec:
    """HID feature, report id 0x01, 16 LEDs planar RGB, no brightness, xor8."""
    return ProtocolSpec(
        name="demo-planar-rgb-xor8",
        transport="hid_feature",
        report_id=0x01,
        packet_len=80,
        header=HeaderField(constant_bytes=[(1, 0x3B)]),
        leds=LedLayout(
            count=16, layout="planar", base_offset=4, stride=1,
            channel_order="RGB", scaling=Scaling(type="identity"),
        ),
        brightness=BrightnessField(present=False),
        checksum=ChecksumModel(present=True, kind="xor8", offset=52, width=1, range=(1, 52)),
        vid=0x0B05, pid=0x1939,
    )


def no_checksum_identity() -> ProtocolSpec:
    """HID interrupt, no report id, 6 LEDs interleaved RGB, no checksum at all.

    Mirrors devices (e.g. the ITE8910) that rely on the HID layer for integrity.
    """
    return ProtocolSpec(
        name="demo-no-checksum",
        transport="hid_interrupt",
        report_id=None,
        packet_len=24,
        header=HeaderField(constant_bytes=[(0, 0xE0)]),
        leds=LedLayout(
            count=6, layout="interleaved", base_offset=2, stride=3,
            channel_order="RGB", scaling=Scaling(type="identity"),
        ),
        brightness=BrightnessField(present=False),
        checksum=ChecksumModel(present=False, kind="none"),
        vid=0x048D, pid=0x8910,
    )


ALL = [
    interleaved_grb_sum8,
    interleaved_gamma_crc16,
    planar_rgb_xor8,
    no_checksum_identity,
]

# Short CLI handles for `lumascope demo|emit --example <name>`.
BY_NAME = {
    "interleaved": interleaved_grb_sum8,
    "gamma": interleaved_gamma_crc16,
    "planar": planar_rgb_xor8,
    "nochecksum": no_checksum_identity,
}
