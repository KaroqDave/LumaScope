"""One-shot analysis report tests."""

from pathlib import Path

from lumascope.analyze import analyze_frames, format_analysis
from lumascope.capture.serialize import load_frames
from lumascope.model import CaptureFrame

FIXTURES = Path(__file__).parent / "fixtures"


def test_analyze_reports_chunking_and_channels():
    frames = load_frames(str(FIXTURES / "aura_ec40_first_update.jsonl"))
    report = analyze_frames(frames)
    text = format_analysis(report, name="aura")

    assert report.framing is not None
    assert report.channels[0][:3] == bytes.fromhex("ff0000")
    assert "# LumaScope analysis: aura" in text
    assert "prefix=ec40" in text
    assert "channel 4: 6 bytes" in text


def test_analyze_reports_cadence_when_timestamps_exist():
    frames = load_frames(str(FIXTURES / "rainbow_fast_first_chunks.jsonl"))
    report = analyze_frames(frames)
    text = format_analysis(report, name="rainbow_fast")

    assert report.cadence is not None
    assert report.cadence.has_timing
    assert "cycle period" in text


def _non_aura_chunks(*, direction="out"):
    """Chunk framing is prefix, channel, offset, count, unlike Aura's two-byte prefix."""
    frames = []
    samples = [
        (0, bytes.fromhex("ff0000")),
        (2, bytes.fromhex("010203")),
        (0, bytes.fromhex("00ff00")),
        (2, bytes.fromhex("040506")),
    ]
    for index, (offset, rgb) in enumerate(samples, start=1):
        data = bytes([0xAB, 7, offset, 2]) + rgb + b"\x01\x01\x01"
        frames.append(CaptureFrame(
            data=data,
            direction=direction,
            timestamp_ns=index * 1_000_000_000,
        ))
    return frames


def test_analyze_threads_inferred_framing_into_cadence():
    report = analyze_frames(_non_aura_chunks())

    assert report.framing is not None
    assert (
        report.framing.channel_pos,
        report.framing.offset_pos,
        report.framing.payload_start,
    ) == (1, 2, 4)
    assert report.cadence is not None
    assert report.cadence.channel == 7
    assert report.cadence.samples == 2
    assert report.cadence.hue_deg_per_s > 0


def test_analyze_direction_filters_every_report_section():
    inbound = _non_aura_chunks(direction="in")

    report = analyze_frames(inbound, direction="in")
    assert report.groups
    assert report.framing is not None
    assert report.channels
    assert report.cadence is not None and report.cadence.samples == 2

    outbound = analyze_frames(inbound, direction="out")
    assert not outbound.groups
    assert outbound.framing is None
    assert not outbound.channels
    assert outbound.cadence is None
