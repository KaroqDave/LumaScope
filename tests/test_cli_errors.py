"""Mistakes a user will actually make must produce guidance, not a traceback.

Every case here is one someone hits in the first ten minutes: a path that does not exist,
the two capture formats mixed up, a mistyped command. The contract is the same each time
-- exit non-zero, explain, and name the command that works.
"""

import json
from pathlib import Path

import pytest

from lumascope import cli
from lumascope.capture.serialize import CORPUS, FRAMES, PCAP, SPEC, load_corpus, load_frames, sniff
from lumascope.errors import LumaScopeError

SAMPLE = Path(__file__).parent.parent / "samples" / "aura-red.frames.jsonl"


# --------------------------------------------------------------------------- #
# Format identification
# --------------------------------------------------------------------------- #
def test_sniff_identifies_a_frame_capture():
    assert sniff(str(SAMPLE)) == FRAMES


def test_sniff_identifies_a_corpus(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"device_name": "x", "led_count": 8, "frames": []}), encoding="utf-8")
    assert sniff(str(p)) == CORPUS


def test_sniff_identifies_a_spec(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"name": "x", "packet_len": 40, "leds": {}}), encoding="utf-8")
    assert sniff(str(p)) == SPEC


def test_sniff_identifies_a_pcap(tmp_path):
    p = tmp_path / "c.pcap"
    p.write_bytes(bytes.fromhex("d4c3b2a1") + b"\x00" * 32)
    assert sniff(str(p)) == PCAP


def test_sniff_reports_a_missing_file_usefully(tmp_path):
    with pytest.raises(LumaScopeError) as exc:
        sniff(str(tmp_path / "nope.jsonl"))
    assert "no such file" in exc.value.message


# --------------------------------------------------------------------------- #
# Loaders refuse the wrong format with a pointer to the right command
# --------------------------------------------------------------------------- #
def test_frames_file_passed_as_corpus_names_the_right_command():
    with pytest.raises(LumaScopeError) as exc:
        load_corpus(str(SAMPLE))
    rendered = exc.value.render()
    assert "raw frame capture" in rendered
    assert "lumascope analyze --frames" in rendered


def test_corpus_file_passed_as_frames_names_the_right_command(tmp_path):
    p = tmp_path / "c.corpus.json"
    p.write_text(json.dumps({"device_name": "x", "led_count": 8, "frames": []}), encoding="utf-8")
    with pytest.raises(LumaScopeError) as exc:
        load_frames(str(p))
    assert "lumascope decode --corpus" in exc.value.render()


def test_empty_capture_explains_rather_than_returning_nothing(tmp_path):
    p = tmp_path / "empty.frames.jsonl"
    p.write_text("", encoding="utf-8")
    with pytest.raises(LumaScopeError) as exc:
        load_frames(str(p))
    assert "empty" in exc.value.message


def test_pcap_passed_to_a_loader_suggests_converting_it(tmp_path):
    p = tmp_path / "bus.pcap"
    p.write_bytes(bytes.fromhex("d4c3b2a1") + b"\x00" * 32)
    with pytest.raises(LumaScopeError) as exc:
        load_frames(str(p))
    assert "--backend usbpcap --pcap" in exc.value.render()


def test_corrupt_frame_line_reports_the_line_number(tmp_path):
    p = tmp_path / "bad.frames.jsonl"
    p.write_text('{"hex": "ec40"}\nnot json at all\n', encoding="utf-8")
    with pytest.raises(LumaScopeError) as exc:
        load_frames(str(p))
    assert "line 2" in exc.value.message


# --------------------------------------------------------------------------- #
# CLI surface
# --------------------------------------------------------------------------- #
def test_errors_exit_nonzero_without_a_traceback(capsys):
    assert cli.main(["show", "--frames", "does-not-exist.jsonl"]) == 2
    err = capsys.readouterr().err
    assert "Traceback" not in err
    assert "no such file" in err


def test_unknown_command_suggests_the_closest_match(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["anaylze"])
    assert exc.value.code == 2
    assert "lumascope analyze" in capsys.readouterr().err


def test_bare_invocation_prints_a_starting_point(capsys):
    assert cli.main([]) == 0
    out = capsys.readouterr().out
    assert "lumascope doctor" in out
    assert "samples/" in out


def test_help_lists_every_command_in_a_group():
    text = cli.help_text()
    for name in cli.ALL_COMMANDS:
        assert f"  {name}" in text


def test_unknown_example_lists_the_real_ones(capsys):
    assert cli.main(["demo", "not-an-example"]) == 2
    err = capsys.readouterr().err
    assert "lumascope demo gamma" in err


def test_show_without_a_target_points_at_the_samples(capsys):
    assert cli.main(["show"]) == 2
    assert "samples/aura-red.frames.jsonl" in capsys.readouterr().err


def test_hints_can_be_silenced(capsys, monkeypatch):
    monkeypatch.setenv("LUMASCOPE_NO_HINTS", "1")
    cli.main(["show", "--frames", str(SAMPLE), "--limit", "1", "--color", "never"])
    assert "Next:" not in capsys.readouterr().err
