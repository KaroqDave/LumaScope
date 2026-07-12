"""One-shot capture analysis report."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .decode import inspect as ins
from .decode.cadence import Cadence, analyze_cadence, format_cadence
from .decode.chunked import ChunkFraming, reassemble_capture
from .model import CaptureFrame


@dataclass
class Analysis:
    groups: list[ins.CommandGroup]
    framing: Optional[ChunkFraming]
    channels: dict[int, bytes]
    cadence: Optional[Cadence]


def analyze_frames(
    frames: list[CaptureFrame],
    *,
    sig_len: int = 2,
    direction: Optional[str] = "out",
    vid: Optional[int] = None,
    pid: Optional[int] = None,
    channel: Optional[int] = None,
) -> Analysis:
    """Run the standard first-pass analyses over a raw capture."""
    groups = ins.group_frames(frames, sig_len=sig_len, direction=direction, vid=vid, pid=pid)
    filtered = [
        f for f in frames
        if (vid is None or f.vid is None or f.vid == vid)
        and (pid is None or f.pid is None or f.pid == pid)
    ]
    framing, channels = reassemble_capture(filtered, direction=direction)
    cadence_kwargs = {
        "channel": channel,
        "vid": vid,
        "pid": pid,
        "direction": direction,
    }
    if framing is not None:
        cadence_kwargs.update({
            "channel_pos": framing.channel_pos,
            "offset_pos": framing.offset_pos,
            "payload_offset": framing.payload_start,
            "channel_mask": framing.channel_mask,
        })
    cadence = analyze_cadence(frames, **cadence_kwargs)
    return Analysis(groups=groups, framing=framing, channels=channels, cadence=cadence)


def format_analysis(report: Analysis, *, name: str = "capture") -> str:
    """Render an analysis report suitable for stdout or a Markdown file."""
    lines = [f"# LumaScope analysis: {name}", ""]
    lines.append("## Command classes")
    lines.append(ins.format_groups(report.groups) if report.groups else "No matching command classes.")
    lines.append("")

    lines.append("## Chunking")
    if report.framing is None:
        lines.append("No chunked command class detected.")
    else:
        fr = report.framing
        lines.append(
            f"prefix={fr.prefix.hex()} channel@{fr.channel_pos}(mask {fr.channel_mask:#x}) "
            f"offset@{fr.offset_pos} count@{fr.count_pos} payload@{fr.payload_start} "
            f"unit={fr.unit} chunk_count={fr.chunk_count} final_flag={fr.final_flag:#x}"
        )
        for ch in sorted(report.channels):
            buf = report.channels[ch]
            preview = " ".join(buf[i:i + 3].hex() for i in range(0, min(len(buf), 12), 3))
            lines.append(f"- channel {ch}: {len(buf)} bytes (~{len(buf)//3} LEDs) [{preview}]")
    lines.append("")

    lines.append("## Cadence")
    lines.append(format_cadence(report.cadence, name=name) if report.cadence else "No cadence signal detected.")
    return "\n".join(lines)
