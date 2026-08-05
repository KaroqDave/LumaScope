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


def format_analysis(report: Analysis, *, name: str = "capture", color: bool = False,
                    width: int = 16) -> str:
    """Render an analysis report suitable for stdout or a Markdown file.

    Each section leads with plain English and follows with the exact numbers, so the
    report is readable by someone meeting the protocol for the first time and still
    precise enough to implement from.
    """
    from .annotate import describe_framing
    from . import view

    lines = [f"# LumaScope analysis: {name}", ""]
    lines.append("## Command classes")
    lines.append("")
    if report.groups:
        lines.append("Packets grouped by their leading command bytes. `^^` marks the byte")
        lines.append("columns that change between packets of the same class.")
        lines.append("")
        lines.append(ins.format_groups(report.groups, color=color, width=width))
    else:
        lines.append("No matching command classes.")
    lines.append("")

    lines.append("## Chunking")
    lines.append("")
    if report.framing is None:
        lines.append("No chunked command class detected -- this device does not appear to")
        lines.append("stream one lighting state across multiple packets.")
    else:
        fr = report.framing
        lines.append("This device streams one lighting state across many packets.")
        lines.append("")
        lines.append(describe_framing(fr))
        lines.append("")
        lines.append(
            f"prefix={fr.prefix.hex()} channel@{fr.channel_pos}(mask {fr.channel_mask:#x}) "
            f"offset@{fr.offset_pos} count@{fr.count_pos} payload@{fr.payload_start} "
            f"unit={fr.unit} chunk_count={fr.chunk_count} final_flag={fr.final_flag:#x}"
        )
        lines.append("")
        lines.append("Reassembled buffers:")
        for ch in sorted(report.channels):
            buf = report.channels[ch]
            lines.append(f"- channel {ch}: {len(buf)} bytes (~{len(buf)//3} LEDs)")
            bar = view.color_bar(buf, color=color, cells=48)
            if bar:
                lines.append(f"    {bar}")
            lines.append(view.led_table(buf, color=color, indent="    ", max_runs=6))
    lines.append("")

    lines.append("## Cadence")
    lines.append("")
    lines.append(format_cadence(report.cadence, name=name) if report.cadence
                 else "No cadence signal detected (needs timestamps and a changing buffer).")
    return "\n".join(lines)
