"""On-disk formats for captures.

* **frame JSONL** — what a live capture backend streams: one :class:`CaptureFrame` per
  line (``hex`` + metadata). Backend-agnostic; the orchestrator labels frames afterward.
* **corpus JSON** — a labeled :class:`Corpus` (stimulus step + frame pairs) the decode
  engine consumes. This is the unit ``lumascope decode`` reads.
"""

from __future__ import annotations

import json
from typing import Any

from ..model import CaptureFrame, Corpus, LabeledFrame, SweepStep


# --------------------------------------------------------------------------- #
# CaptureFrame
# --------------------------------------------------------------------------- #
def frame_to_dict(f: CaptureFrame) -> dict[str, Any]:
    return {
        "hex": f.data.hex(),
        "timestamp_ns": f.timestamp_ns,
        "source": f.source,
        "api": f.api,
        "direction": f.direction,
        "transfer": f.transfer,
        "vid": f.vid,
        "pid": f.pid,
        "path": f.path,
        "report_id": f.report_id,
        "endpoint": f.endpoint,
        "meta": f.meta,
    }


def frame_from_dict(d: dict[str, Any]) -> CaptureFrame:
    return CaptureFrame(
        data=bytes.fromhex(d["hex"]),
        timestamp_ns=d.get("timestamp_ns", 0),
        source=d.get("source", ""),
        api=d.get("api", ""),
        direction=d.get("direction", "out"),
        transfer=d.get("transfer", ""),
        vid=d.get("vid"),
        pid=d.get("pid"),
        path=d.get("path"),
        report_id=d.get("report_id"),
        endpoint=d.get("endpoint"),
        meta=d.get("meta", {}),
    )


def frames_to_jsonl(frames: list[CaptureFrame], path: str) -> None:
    """Stream raw (unlabeled) frames, one JSON object per line — what a backend records."""
    with open(path, "w", encoding="utf-8") as fh:
        for f in frames:
            fh.write(json.dumps(frame_to_dict(f)) + "\n")


def load_frames(path: str) -> list[CaptureFrame]:
    out: list[CaptureFrame] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(frame_from_dict(json.loads(line)))
    return out


# --------------------------------------------------------------------------- #
# SweepStep
# --------------------------------------------------------------------------- #
def step_to_dict(s: SweepStep) -> dict[str, Any]:
    return {
        "step_id": s.step_id,
        "kind": s.kind,
        "colors": [list(c) for c in s.colors],
        "led": s.led,
        "channel": s.channel,
        "value": s.value,
        "brightness": s.brightness,
        "mode": s.mode,
        "params": s.params,
    }


def step_from_dict(d: dict[str, Any]) -> SweepStep:
    return SweepStep(
        step_id=d["step_id"],
        kind=d["kind"],
        colors=[tuple(c) for c in d.get("colors", [])],
        led=d.get("led"),
        channel=d.get("channel"),
        value=d.get("value"),
        brightness=d.get("brightness"),
        mode=d.get("mode"),
        params=d.get("params", {}),
    )


# --------------------------------------------------------------------------- #
# Corpus
# --------------------------------------------------------------------------- #
def corpus_to_dict(c: Corpus) -> dict[str, Any]:
    return {
        "device_name": c.device_name,
        "led_count": c.led_count,
        "vid": c.vid,
        "pid": c.pid,
        "frames": [
            {"step": step_to_dict(lf.step), "frame": frame_to_dict(lf.frame)} for lf in c.frames
        ],
    }


def corpus_from_dict(d: dict[str, Any]) -> Corpus:
    return Corpus(
        frames=[
            LabeledFrame(step=step_from_dict(e["step"]), frame=frame_from_dict(e["frame"]))
            for e in d.get("frames", [])
        ],
        led_count=d.get("led_count", 0),
        device_name=d.get("device_name", "unknown"),
        vid=d.get("vid"),
        pid=d.get("pid"),
    )


def save_corpus(c: Corpus, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(corpus_to_dict(c), fh, indent=2)


def load_corpus(path: str) -> Corpus:
    with open(path, encoding="utf-8") as fh:
        return corpus_from_dict(json.load(fh))
