"""Replay tests — verify packet generation and the safety gates, no hardware.

The headline check closes the RE loop offline: a spec *decoded from captures* must replay
byte-identically to the ground-truth spec — i.e. the recovered spec drives the device with
exactly the packets the real device expects.
"""
import pytest

from lumascope import examples, replay, synthetic
from lumascope.decode import decode
from lumascope.model import ChunkingModel


def test_decoded_spec_replays_identically_to_ground_truth():
    for factory in examples.ALL:
        truth = factory()
        recovered = decode(synthetic.generate_corpus(truth)).spec
        truth_seq = replay.build_replay_sequence(truth)
        recovered_seq = replay.build_replay_sequence(recovered)
        assert len(truth_seq) == len(recovered_seq)
        for a, b in zip(truth_seq, recovered_seq):
            assert a.label == b.label
            assert a.data == b.data, (truth.name, a.label)  # loop closes: identical wire bytes


def test_sequence_structure():
    spec = examples.interleaved_grb_sum8()
    steps = replay.build_replay_sequence(spec)
    # 5 solid frames (R/G/B/white/off) + one walk frame per LED.
    assert len(steps) == 5 + spec.leds.count
    assert steps[0].label == "all red"
    assert all(len(s.data) == spec.packet_len for s in steps)


def test_dry_run_writes_nothing():
    spec = examples.interleaved_grb_sum8()
    steps = replay.build_replay_sequence(spec)
    out = []
    wrote = replay.write_sequence(spec, steps, dry_run=True, out=out.append)
    assert wrote is False
    assert any("dry-run" in line for line in out)


def test_write_refused_without_confirm():
    spec = examples.interleaved_grb_sum8()
    steps = replay.build_replay_sequence(spec)
    out = []
    # Even with dry_run=False, confirm=False must not write (and must not need a device).
    wrote = replay.write_sequence(spec, steps, device_path=None, confirm=False, dry_run=False, out=out.append)
    assert wrote is False


def test_confirmed_write_requires_device_path():
    spec = examples.interleaved_grb_sum8()
    steps = replay.build_replay_sequence(spec)
    with pytest.raises(RuntimeError):
        replay.write_sequence(spec, steps, device_path=None, confirm=True, dry_run=False, out=lambda m: None)


def test_chunked_replay_steps_expose_individual_packets():
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
    steps = replay.build_replay_sequence(spec, walk=False)
    assert len(steps[0].packets) > 1
    assert all(len(packet) == spec.chunking.packet_len for packet in steps[0].packets)
    assert steps[0].packets[-1][spec.chunking.channel_pos] == 0x80


def test_replay_writer_rejects_unsupported_transport_before_writing():
    spec = examples.no_checksum_identity()
    spec.transport = "usb_control"
    writer = replay.HidReplayWriter(spec, "unused")
    with pytest.raises(RuntimeError, match="usb_control"):
        writer.write(b"\x00")
