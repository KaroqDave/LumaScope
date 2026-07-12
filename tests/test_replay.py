"""Replay tests — verify packet generation and the safety gates, no hardware.

The headline check closes the RE loop offline: a spec *decoded from captures* must replay
byte-identically to the ground-truth spec — i.e. the recovered spec drives the device with
exactly the packets the real device expects.
"""
import pytest

from lumascope import codec, examples, replay, synthetic
from lumascope.decode import decode
from lumascope.model import ChunkingModel, ChunkTarget


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
    spec.header.constant_bytes = []
    spec.leds.base_offset = 0
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


def test_multi_target_chunked_replay_writes_each_channel():
    spec = examples.no_checksum_identity()
    spec.header.constant_bytes = []
    spec.leds.base_offset = 0
    spec.chunking = ChunkingModel(
        present=True,
        packet_len=14,
        prefix=b"\xEC\x40",
        channel_pos=2,
        offset_pos=3,
        count_pos=4,
        payload_start=5,
        unit=3,
        chunk_count=1,
        final_flag=0x80,
        targets=[
            ChunkTarget(channel=0, led_count=2, payload_len=6),
            ChunkTarget(channel=4, led_count=1, payload_len=3),
        ],
    )

    step = replay.build_replay_sequence(spec, walk=False)[0]

    assert [p[2] for p in step.packets] == [0x00, 0x80, 0x84]
    assert [p[3:5] for p in step.packets] == [bytes([0, 1]), bytes([1, 1]), bytes([0, 1])]
    assert step.packets[0][5:8] == bytes.fromhex("ff0000")
    assert step.packets[1][5:8] == bytes.fromhex("ff0000")
    assert step.packets[2][5:8] == bytes.fromhex("ff0000")


def test_replay_writer_rejects_unsupported_transport_before_writing():
    spec = examples.no_checksum_identity()
    spec.transport = "smbus"
    writer = replay.HidReplayWriter(spec, "unused")
    with pytest.raises(RuntimeError, match="smbus"):
        writer.write(b"\x00")


def test_usb_control_writer_uses_pyusb_control_transfer():
    class FakeDevice:
        def __init__(self):
            self.calls = []

        def ctrl_transfer(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            return len(args[4])

    class FakeCore:
        def __init__(self, dev):
            self.dev = dev

        def find(self, **kwargs):
            assert kwargs == {"idVendor": 0x0B05, "idProduct": 0x19AF}
            return self.dev

    dev = FakeDevice()
    spec = examples.no_checksum_identity()
    spec.transport = "usb_control"
    spec.vid = 0x0B05
    spec.pid = 0x19AF
    writer = replay.UsbControlReplayWriter(spec, usb_core=FakeCore(dev))

    writer.open()
    writer.write(bytes.fromhex("ec400000"))

    args, kwargs = dev.calls[0]
    assert args[:4] == (0x21, 0x09, 0x03EC, 0)
    assert args[4] == bytes.fromhex("ec400000")
    assert kwargs == {"timeout": 1000}


def test_usb_control_w_value_precedence_and_empty_packet_fallback():
    spec = examples.no_checksum_identity()
    data = bytes.fromhex("ec400000")

    assert codec.usb_control_w_value(spec, data) == 0x03EC
    assert codec.usb_control_w_value(spec, b"") == 0x0300

    spec.report_id = 0x55
    assert codec.usb_control_w_value(spec, data) == 0x0355

    spec.control.w_value = 0x1234
    assert codec.usb_control_w_value(spec, data) == 0x1234
