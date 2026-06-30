"""Synthetic round-trip: a correct decoder must recover the spec that generated the bytes.

For each ground-truth spec we fabricate a labeled corpus with the reference codec, decode
it, and assert (a) every frame round-trips and (b) the recovered structure matches.
"""

from __future__ import annotations

import pytest

from lumascope import codec, examples, synthetic
from lumascope.decode import decode
from lumascope.model import ChecksumModel


@pytest.mark.parametrize("factory", examples.ALL, ids=[f.__name__ for f in examples.ALL])
def test_spec_round_trips(factory):
    truth = factory()
    corpus = synthetic.generate_corpus(truth)
    result = decode(corpus, name=truth.name)

    assert result.validation.ok, (
        f"{truth.name}: {result.validation.summary()}; "
        f"first failures: {result.validation.failures[:2]}"
    )


@pytest.mark.parametrize("factory", examples.ALL, ids=[f.__name__ for f in examples.ALL])
def test_structure_recovered(factory):
    truth = factory()
    got = decode(synthetic.generate_corpus(truth), name=truth.name).spec

    assert got.packet_len == truth.packet_len
    assert got.report_id == truth.report_id
    assert got.transport == truth.transport
    assert got.leds.count == truth.leds.count
    assert got.leds.layout == truth.leds.layout
    assert got.leds.base_offset == truth.leds.base_offset
    assert got.leds.channel_order == truth.leds.channel_order
    assert got.leds.scaling.type == truth.leds.scaling.type
    if truth.leds.layout == "interleaved":
        assert got.leds.stride == truth.leds.stride
    assert got.brightness.present == truth.brightness.present
    if truth.brightness.present:
        assert got.brightness.offset == truth.brightness.offset
    assert got.checksum.kind == truth.checksum.kind
    assert got.checksum.offset == truth.checksum.offset
    assert got.checksum.range == truth.checksum.range


def test_gamma_scaling_value_recovered():
    truth = examples.interleaved_gamma_crc16()
    got = decode(synthetic.generate_corpus(truth)).spec
    assert got.leds.scaling.type == "gamma"
    assert got.leds.scaling.gamma == pytest.approx(truth.leds.scaling.gamma, abs=0.001)


def test_no_checksum_reported_as_absent():
    truth = examples.no_checksum_identity()
    got = decode(synthetic.generate_corpus(truth)).spec
    assert got.checksum.present is False
    assert got.checksum.kind == "none"


def test_brightness_range_recovered():
    truth = examples.interleaved_grb_sum8()
    got = decode(synthetic.generate_corpus(truth)).spec
    assert got.brightness.present
    assert got.brightness.min == 0
    assert got.brightness.max == 255


# --- codec / checksum unit sanity ---------------------------------------------------- #
def test_crc16_modbus_check_value():
    # Canonical CRC-16/MODBUS check value of "123456789" is 0x4B37.
    val = codec.crc_compute(b"123456789", 16, 0x8005, 0xFFFF, True, True, 0x0000)
    assert val == 0x4B37


def test_sum8_and_xor8():
    data = bytes([0x10, 0x20, 0x30])
    assert codec.compute_checksum_value(ChecksumModel(kind="sum8"), data) == 0x60
    assert codec.compute_checksum_value(ChecksumModel(kind="xor8"), data) == (0x10 ^ 0x20 ^ 0x30)


def test_planar_offsets_are_distinct_and_in_bounds():
    spec = examples.planar_rgb_xor8()
    frame = codec.encode_frame(spec, [(255, 0, 0)] * spec.leds.count)
    # LED 0 red occupies base_offset in planar RGB; LED 1 red is the next byte.
    assert frame[spec.leds.base_offset] == 255
    assert frame[spec.leds.base_offset + 1] == 255
    assert len(frame) == spec.packet_len
