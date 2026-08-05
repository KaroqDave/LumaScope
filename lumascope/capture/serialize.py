"""On-disk formats for captures.

* **frame JSONL** (``.frames.jsonl``) — what a live capture backend streams: one
  :class:`CaptureFrame` per line (``hex`` + metadata). Backend-agnostic; the orchestrator
  labels frames afterward.
* **corpus JSON** (``.corpus.json``) — a labeled :class:`Corpus` (stimulus step + frame
  pairs) the decode engine consumes. This is the unit ``lumascope decode`` reads.

The two are easy to mix up, so :func:`sniff` identifies a file by content and the loaders
refuse the wrong one with a message naming the command that *does* take it.
"""

from __future__ import annotations

import json
import os
from typing import Any

from ..errors import LumaScopeError
from ..model import CaptureFrame, Corpus, LabeledFrame, SweepStep


# --------------------------------------------------------------------------- #
# Format identification
# --------------------------------------------------------------------------- #
FRAMES, CORPUS, SPEC, PCAP, EMPTY, UNKNOWN = "frames", "corpus", "spec", "pcap", "empty", "unknown"

_KIND_HELP = {
    FRAMES: ("a raw frame capture (one JSON object per line)", "--frames"),
    CORPUS: ("a labeled capture corpus (stimulus steps paired with frames)", "--corpus"),
    SPEC: ("a decoded protocol spec", "--spec"),
    PCAP: ("a raw pcap/pcapng file", "capture --backend usbpcap --pcap"),
}


def sniff(path: str) -> str:
    """Identify a LumaScope file by its content, not its extension."""
    if not os.path.exists(path):
        raise LumaScopeError(
            f"no such file: {path}",
            detail="Check the path, or run the command that produces it first.",
        )
    if os.path.isdir(path):
        raise LumaScopeError(f"{path} is a directory, not a file")
    with open(path, "rb") as fh:
        head = fh.read(4)
    if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"):
        return PCAP
    with open(path, encoding="utf-8", errors="replace") as fh:
        first = ""
        for line in fh:
            if line.strip():
                first = line.strip()
                break
    if not first:
        return EMPTY
    try:
        obj = json.loads(first)
    except json.JSONDecodeError:
        # A pretty-printed JSON document does not parse line by line; read it whole.
        try:
            with open(path, encoding="utf-8") as fh:
                obj = json.load(fh)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return UNKNOWN
    if not isinstance(obj, dict):
        return UNKNOWN
    if "hex" in obj:
        return FRAMES
    if "frames" in obj and "led_count" in obj:
        return CORPUS
    if "leds" in obj or "packet_len" in obj:
        return SPEC
    return UNKNOWN


def _wrong_kind(path: str, actual: str, wanted: str, commands: list[str]) -> LumaScopeError:
    actual_desc = _KIND_HELP.get(actual, ("an unrecognized file", ""))[0]
    wanted_desc, wanted_flag = _KIND_HELP[wanted]
    if actual == EMPTY:
        return LumaScopeError(
            f"{path} is empty",
            detail="The capture recorded nothing. If the vendor app was idle, change a colour\n"
                   "while the capture window is open, or try the other capture backend.",
        )
    if actual == PCAP:
        return LumaScopeError(
            f"{path} is a raw pcap file, not {wanted_desc}",
            detail="Convert it to LumaScope frames first.",
            commands=[f"lumascope capture --backend usbpcap --pcap {path} --out capture.frames.jsonl"],
        )
    return LumaScopeError(
        f"{path} is {actual_desc}, but {wanted_flag} expects {wanted_desc}",
        detail=_MIXUP_HELP,
        commands=commands,
    )


_MIXUP_HELP = (
    "LumaScope has two capture files:\n"
    "  .frames.jsonl  raw packets straight off the device      <- `capture` writes this\n"
    "  .corpus.json   packets paired with the state that caused them  <- `sweep` writes this\n"
    "Only a corpus can be decoded, because decoding needs to know what each packet meant."
)


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
    """Load a raw frame capture, rejecting the other formats with a usable message."""
    kind = sniff(path)
    if kind == CORPUS:
        raise _wrong_kind(path, kind, FRAMES, [
            f"lumascope decode --corpus {path}",
            f"lumascope show --corpus {path}",
        ])
    if kind != FRAMES:
        raise _wrong_kind(path, kind, FRAMES, [f"lumascope show --frames {path}"])
    out: list[CaptureFrame] = []
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(frame_from_dict(json.loads(line)))
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                raise LumaScopeError(
                    f"{path} line {lineno} is not a valid capture frame ({exc})",
                    detail="Frame files are written by `lumascope capture`; if you edited this\n"
                           "one by hand, each line must be a complete JSON object with a `hex` key.",
                ) from exc
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
    """Load a labeled corpus, rejecting the other formats with a usable message."""
    kind = sniff(path)
    if kind == FRAMES:
        raise _wrong_kind(path, kind, CORPUS, [
            f"lumascope analyze --frames {path}",
            f"lumascope show --frames {path}",
        ])
    if kind != CORPUS:
        raise _wrong_kind(path, kind, CORPUS, [])
    with open(path, encoding="utf-8") as fh:
        return corpus_from_dict(json.load(fh))
