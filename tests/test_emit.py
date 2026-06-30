"""Emit: spec JSON round-trips, corpus JSON round-trips, and C++ reflects the spec."""

from __future__ import annotations

import pytest

from lumascope import examples, synthetic
from lumascope.capture.serialize import corpus_from_dict, corpus_to_dict
from lumascope.emit import render_cpp, spec_from_dict, spec_to_dict
from lumascope.emit.openrgb_cpp import _class_name


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
