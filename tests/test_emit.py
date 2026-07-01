"""Emit: spec JSON round-trips, corpus JSON round-trips, and C++ reflects the spec."""

from __future__ import annotations

import pytest

from lumascope import examples, synthetic
from lumascope.capture.serialize import corpus_from_dict, corpus_to_dict
from lumascope.emit import render_cpp, spec_from_dict, spec_to_dict
from lumascope.emit.openrgb_cpp import _class_name
from lumascope.model import ChunkingModel, LedLayout, ProtocolSpec, Scaling


@pytest.mark.parametrize("factory", examples.ALL, ids=[f.__name__ for f in examples.ALL])
def test_spec_json_round_trips(factory):
    spec = factory()
    again = spec_from_dict(spec_to_dict(spec))
    assert spec_to_dict(again) == spec_to_dict(spec)


@pytest.mark.parametrize("factory", examples.ALL, ids=[f.__name__ for f in examples.ALL])
def test_corpus_json_round_trips(factory):
    corpus = synthetic.generate_corpus(factory())
    again = corpus_from_dict(corpus_to_dict(corpus))
    assert len(again) == len(corpus)
    assert again.led_count == corpus.led_count
    assert again.frames[0].data == corpus.frames[0].data
    assert again.frames[5].step.colors == corpus.frames[5].step.colors


def test_chunking_json_round_trips():
    spec = examples.no_checksum_identity()
    spec.chunking = ChunkingModel(
        present=True,
        packet_len=8,
        prefix=b"\xEC\x40",
        channel=2,
        channel_pos=2,
        channel_mask=0x7F,
        final_flag=0x80,
        offset_pos=3,
        count_pos=4,
        payload_start=5,
        unit=3,
        chunk_count=1,
    )
    again = spec_from_dict(spec_to_dict(spec))
    assert again.chunking.present
    assert again.chunking.prefix == b"\xEC\x40"
    assert again.chunking.channel == 2
    assert again.chunking.unit == 3
    assert again.chunking.chunk_count == 1


def test_cpp_contains_recovered_constants():
    spec = examples.interleaved_grb_sum8()
    cpp = render_cpp(spec)
    assert _class_name(spec.name) in cpp
    assert "LED_COUNT  = 10" in cpp
    assert "PACKET_LEN = 64" in cpp
    assert "REPORT_ID  = 0xCC" in cpp
    # GRB order: first wire byte is the green channel.
    assert "RGBGetGValue(colors[i])" in cpp
    assert "Checksum(buf)" in cpp                 # sum8 applied
    assert "hid_send_feature_report" in cpp       # feature transport


def test_cpp_crc_section_has_polynomial():
    cpp = render_cpp(examples.interleaved_gamma_crc16())
    assert "0x8005" in cpp           # CRC-16/MODBUS poly
    assert "std::pow" in cpp         # gamma scaling
    assert "reflect8" in cpp         # refin


def test_cpp_planar_offset_expression():
    cpp = render_cpp(examples.planar_rgb_xor8())
    assert "*LED_COUNT + i" in cpp   # planar packing
    assert "sum ^= buf[i]" in cpp    # xor8


def test_cpp_no_checksum_is_noted():
    cpp = render_cpp(examples.no_checksum_identity())
    assert "no checksum" in cpp.lower()
    assert "hid_write" in cpp        # interrupt transport


def test_cpp_clamps_scaled_values():
    spec = examples.no_checksum_identity()
    spec.leds.scaling = Scaling(type="linear", k=2.0)
    cpp = render_cpp(spec)
    assert "clamp8((int)std::lround(v * 2.0))" in cpp


def test_cpp_uses_explicit_offsets_table():
    spec = ProtocolSpec(
        name="explicit",
        packet_len=16,
        leds=LedLayout(
            count=2,
            channel_order="RGB",
            explicit_offsets=[(5, 2, 9), (6, 3, 10)],
        ),
    )
    cpp = render_cpp(spec)
    assert "LED_OFFSETS[LED_COUNT][3]" in cpp
    assert "buf[LED_OFFSETS[i][0]]" in cpp


def test_cpp_emits_chunked_send_loop():
    spec = examples.no_checksum_identity()
    spec.chunking = ChunkingModel(
        present=True,
        packet_len=8,
        prefix=b"\xEC\x40",
        channel=0,
        channel_pos=2,
        offset_pos=3,
        count_pos=4,
        payload_start=5,
        unit=1,
        chunk_count=3,
        final_flag=0x80,
    )
    cpp = render_cpp(spec)
    assert "CHUNK_PACKET_LEN" in cpp
    assert "pkt[0] = 0xEC;" in cpp
    assert "CHUNK_FINAL_FLAG" in cpp
    assert "for (size_t offset = 0; offset < buf.size(); offset += max_payload)" in cpp


def test_cpp_unsupported_transport_throws_instead_of_hid_fallback():
    spec = examples.no_checksum_identity()
    spec.transport = "usb_control"
    cpp = render_cpp(spec)
    assert "throw std::runtime_error(\"usb_control replay is not implemented\")" in cpp
    assert "libusb_control_transfer" not in cpp
