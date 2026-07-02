"""Regression tests pinned to distilled real ASUS Aura capture fixtures."""

from pathlib import Path

from lumascope.capture.serialize import load_frames
from lumascope.decode.cadence import analyze_cadence
from lumascope.decode.chunked import infer_framing, reassemble

FIXTURES = Path(__file__).parent / "fixtures"


def test_real_aura_ec40_fixture_reassembles_channels():
    frames = load_frames(str(FIXTURES / "aura_ec40_first_update.jsonl"))
    framing = infer_framing(frames)

    assert framing is not None
    assert framing.prefix == b"\xEC\x40"
    assert framing.channel_pos == 2
    assert framing.channel_mask == 0x7F
    assert framing.final_flag == 0x80
    assert framing.offset_pos == 3
    assert framing.count_pos == 4
    assert framing.payload_start == 5
    assert framing.unit == 3
    assert framing.chunk_count == 20

    channels = reassemble(frames, framing)
    assert {ch: len(buf) for ch, buf in channels.items()} == {0: 360, 1: 360, 2: 360, 4: 6}
    assert channels[0][:12] == bytes.fromhex("ff0000ff0000ff0000ff0000")
    assert channels[4] == bytes.fromhex("ff0000ff0000")


def test_real_rainbow_cadence_fixtures_preserve_speed_ordering():
    slow = analyze_cadence(load_frames(str(FIXTURES / "rainbow_slow_first_chunks.jsonl")))
    med = analyze_cadence(load_frames(str(FIXTURES / "rainbow_med_first_chunks.jsonl")))
    fast = analyze_cadence(load_frames(str(FIXTURES / "rainbow_fast_first_chunks.jsonl")))

    assert slow is not None and med is not None and fast is not None
    assert slow.has_timing and med.has_timing and fast.has_timing
    assert slow.command == med.command == fast.command == (0xEC, 0x40)
    assert fast.cycle_period_s < med.cycle_period_s < slow.cycle_period_s
    assert slow.hue_deg_per_update < med.hue_deg_per_update < fast.hue_deg_per_update
