"""One-shot analysis report tests."""

from pathlib import Path

from lumascope.analyze import analyze_frames, format_analysis
from lumascope.capture.serialize import load_frames

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
