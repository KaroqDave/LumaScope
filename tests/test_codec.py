"""Focused regression tests for reference codec buffer sizing."""

from __future__ import annotations

import pytest

from lumascope import codec
from lumascope.model import (
    BrightnessField,
    ChecksumModel,
    ChunkingModel,
    ChunkTarget,
    LedLayout,
    ProtocolSpec,
)


def _target_spec(*, payload_len: int | None = None) -> tuple[ProtocolSpec, ChunkTarget]:
    target = ChunkTarget(channel=4, led_count=1, payload_len=payload_len)
    spec = ProtocolSpec(
        packet_len=0,
        leds=LedLayout(count=6, base_offset=0, stride=3, channel_order="RGB"),
        chunking=ChunkingModel(
            present=True,
            packet_len=8,
            prefix=b"\xEC\x40",
            channel_pos=2,
            offset_pos=3,
            count_pos=4,
            payload_start=5,
            unit=1,
            chunk_count=3,
            final_flag=0x80,
            targets=[target],
        ),
    )
    return spec, target


def test_multi_target_encoding_does_not_build_unused_full_frame():
    spec, _target = _target_spec(payload_len=3)

    packets = codec.encode_packets(spec, [(1, 2, 3)] * spec.leds.count)

    assert len(packets) == 1
    assert packets[0][2] == 0x84
    assert packets[0][5:8] == bytes([1, 2, 3])


def test_empty_explicit_offsets_use_regular_layout():
    layout = LedLayout(
        count=2,
        base_offset=1,
        stride=3,
        channel_order="RGB",
        explicit_offsets=[],
    )
    spec = ProtocolSpec(packet_len=7, leds=layout)

    assert codec.logical_payload_len(layout) == 7
    assert codec.encode_frame(spec, [(1, 2, 3), (4, 5, 6)]) == bytes(
        [0, 1, 2, 3, 4, 5, 6]
    )


@pytest.mark.parametrize(
    ("field", "expected_len"),
    [
        ("constant_header", 6),
        ("command", 6),
        ("mode", 6),
        ("brightness", 6),
        ("checksum_field", 7),
        ("checksum_range", 8),
    ],
)
def test_inferred_target_length_covers_inherited_fields(field: str, expected_len: int):
    spec, target = _target_spec()
    encode_kwargs: dict[str, int] = {}
    if field == "constant_header":
        spec.header.constant_bytes = [(5, 0xA5)]
    elif field == "command":
        spec.header.command_offset = 5
        encode_kwargs["command"] = 0x42
    elif field == "mode":
        spec.header.mode_offset = 5
        encode_kwargs["mode_value"] = 0x24
    elif field == "brightness":
        spec.brightness = BrightnessField(present=True, offset=5)
    elif field == "checksum_field":
        spec.checksum = ChecksumModel(
            present=True,
            kind="sum16",
            offset=5,
            width=2,
            range=(0, 5),
        )
    else:
        spec.checksum = ChecksumModel(
            present=True,
            kind="sum8",
            offset=3,
            width=1,
            range=(0, 8),
        )

    assert codec.chunk_target_payload_len(spec, target) == expected_len
    payload = codec.encode_chunk_target_payload(spec, target, [(1, 2, 3)], **encode_kwargs)
    assert len(payload) == expected_len


@pytest.mark.parametrize(
    "field",
    ["constant_header", "command", "mode", "brightness", "checksum"],
)
def test_explicit_undersized_target_rejects_inherited_field(field: str):
    spec, target = _target_spec(payload_len=3)
    if field == "constant_header":
        spec.header.constant_bytes = [(5, 0xA5)]
    elif field == "command":
        spec.header.command_offset = 5
    elif field == "mode":
        spec.header.mode_offset = 5
    elif field == "brightness":
        spec.brightness = BrightnessField(present=True, offset=5)
    else:
        spec.checksum = ChecksumModel(
            present=True,
            kind="sum8",
            offset=5,
            width=1,
            range=(0, 5),
        )

    with pytest.raises(ValueError, match=r"payload_len 3 .* required minimum 6"):
        codec.chunk_target_payload_len(spec, target)


def test_explicit_zero_target_length_is_not_treated_as_omitted():
    spec, target = _target_spec(payload_len=0)

    with pytest.raises(ValueError, match=r"payload_len 0 .* required minimum 3"):
        codec.encode_chunk_target_payload(spec, target, [(1, 2, 3)])


def test_target_payload_length_is_aligned_to_chunk_unit():
    spec, target = _target_spec()
    spec.chunking.unit = 3
    spec.chunking.chunk_count = 1
    spec.checksum = ChecksumModel(
        present=True,
        kind="sum8",
        offset=33,
        width=1,
        range=(0, 33),
    )

    assert codec.chunk_target_payload_len(spec, target) == 36
    payload = codec.encode_chunk_target_payload(spec, target, [(1, 2, 3)])
    packets = codec.chunk_payload(spec, payload, channel=target.channel)
    assert len(payload) == 36
    assert packets[-1][spec.chunking.count_pos] == 1


def test_explicit_target_and_direct_payload_must_align_to_chunk_unit():
    spec, target = _target_spec(payload_len=4)
    spec.chunking.unit = 3

    with pytest.raises(ValueError, match=r"payload_len 4 .* chunking unit 3"):
        codec.chunk_target_payload_len(spec, target)
    with pytest.raises(ValueError, match=r"payload length 4 .* chunking unit 3"):
        codec.chunk_payload(spec, b"\x00" * 4, channel=target.channel)
