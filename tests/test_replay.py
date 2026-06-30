"""Replay tests — verify packet generation and the safety gates, no hardware.

The headline check closes the RE loop offline: a spec *decoded from captures* must replay
byte-identically to the ground-truth spec — i.e. the recovered spec drives the device with
exactly the packets the real device expects.
"""
import pytest

from lumascope import examples, replay, synthetic
from lumascope.decode import decode


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
