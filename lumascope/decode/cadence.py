"""Temporal (cadence) analysis of a streamed effect.

Some effects have no command encoding at all — the vendor app renders them in software and
streams direct-colour frames (see the ASUS Aura write-up: breathing, colour-cycle and rainbow
are all `EC40` streams). For those, *speed* is not a byte you can diff — it lives in the timing:
how fast the streamed colour advances. This pass measures that.

It needs per-frame timestamps (``CaptureFrame.timestamp_ns``; the USBPcap backend fills them
from tshark's ``frame.time_relative``). It reports the stream frame rate, and — by tracking one
reference LED's hue over time — the colour-cycle period and hue rate, which *is* the effect's
speed. Comparing two captures that differ only by a speed slider then reveals the mechanism
(phase-step-per-frame vs. frame-rate) and the slider→period mapping.
"""

from __future__ import annotations

import colorsys
from collections import Counter
from dataclasses import dataclass
from typing import Optional

from ..model import CaptureFrame


@dataclass
class Cadence:
    command: tuple[int, int]      # the streamed command class (report id, command)
    frames: int                   # frames of that class
    has_timing: bool              # were usable timestamps present?
    span_s: float                 # capture duration over that class
    frame_rate: float             # frames / s (the stream refresh rate)
    channel: int                  # which reference channel was tracked
    samples: int                  # first-chunk samples for that channel (one per update)
    update_rate: float            # full-buffer updates / s
    hue_deg_per_s: float          # rate the reference LED's hue advances  ← perceived speed
    cycle_period_s: float         # seconds per full 360° hue revolution
    hue_deg_per_update: float     # hue advance per streamed update
    monotonic: float              # 0..1: net directional travel / total travel (1 = clean cycle)


def _hue(rgb: bytes) -> float:
    r, g, b = rgb[0] / 255, rgb[1] / 255, rgb[2] / 255
    return colorsys.rgb_to_hsv(r, g, b)[0]  # 0..1


def _signed_step(a: float, b: float) -> float:
    """Shortest signed hue step from a to b, in turns (-0.5..0.5)."""
    return (b - a + 0.5) % 1.0 - 0.5


def analyze_cadence(
    frames: list[CaptureFrame],
    *,
    channel: Optional[int] = None,
    channel_pos: int = 2,
    offset_pos: int = 3,
    payload_offset: int = 5,
    channel_mask: int = 0x7F,
    vid: Optional[int] = None,
    pid: Optional[int] = None,
) -> Optional[Cadence]:
    """Measure the cadence of the dominant streamed command class.

    Defaults match the ASUS Aura ``EC40`` header (channel @2, offset @3, RGB payload @5). The
    reference sample per update is a *first chunk* (``offset`` field == 0) of one channel; its
    RGB triplet is tracked through time to recover the hue rate. ``channel=None`` auto-picks the
    channel with the most first-chunk samples.
    """
    out = [
        f for f in frames
        if f.direction == "out" and len(f.data) >= payload_offset + 3
        and (vid is None or f.vid is None or f.vid == vid)
        and (pid is None or f.pid is None or f.pid == pid)
    ]
    if not out:
        return None

    cmd = Counter((f.data[0], f.data[1]) for f in out).most_common(1)[0][0]
    cls = [f for f in out if (f.data[0], f.data[1]) == cmd]

    ts = [f.timestamp_ns for f in cls]
    has_timing = any(ts) and max(ts) != min(ts)
    span = (max(ts) - min(ts)) / 1e9 if has_timing else 0.0
    frame_rate = len(cls) / span if span else 0.0

    firsts = [f for f in cls if f.data[offset_pos] == 0]
    by_ch: dict[int, list[CaptureFrame]] = {}
    for f in firsts:
        by_ch.setdefault(f.data[channel_pos] & channel_mask, []).append(f)
    if channel is None:
        channel = max(by_ch, key=lambda c: len(by_ch[c])) if by_ch else 0
    samp = by_ch.get(channel, [])

    update_rate = hue_dps = period = hue_per_update = mono = 0.0
    if has_timing and len(samp) > 1:
        tspan = (samp[-1].timestamp_ns - samp[0].timestamp_ns) / 1e9
        hues = [_hue(f.data[payload_offset:payload_offset + 3]) for f in samp]
        steps = [_signed_step(a, b) for a, b in zip(hues, hues[1:])]
        total = sum(abs(s) for s in steps)          # turns travelled
        net = abs(sum(steps))
        if tspan > 0:
            update_rate = len(samp) / tspan
            hue_dps = total / tspan * 360
            period = tspan / total if total else 0.0
            hue_per_update = total / len(steps) * 360 if steps else 0.0
            mono = net / total if total else 0.0

    return Cadence(
        command=cmd, frames=len(cls), has_timing=has_timing, span_s=span,
        frame_rate=frame_rate, channel=channel, samples=len(samp),
        update_rate=update_rate, hue_deg_per_s=hue_dps, cycle_period_s=period,
        hue_deg_per_update=hue_per_update, monotonic=mono,
    )


def format_cadence(c: Cadence, name: str = "") -> str:
    tag = f"{c.command[0]:02x} {c.command[1]:02x}"
    head = f"# cadence {name}".rstrip()
    if not c.has_timing:
        return (f"{head}\n  command {tag}: {c.frames} frames, but NO timestamps "
                f"(re-convert the pcap with the current parser to get timing)")
    return (
        f"{head}\n"
        f"  command {tag}: {c.frames} frames over {c.span_s:.1f}s  "
        f"= {c.frame_rate:.0f} frames/s ({c.update_rate:.1f} updates/s on ch{c.channel})\n"
        f"  cycle period {c.cycle_period_s:.1f}s  |  {c.hue_deg_per_s:.0f} deg/s  |  "
        f"{c.hue_deg_per_update:.1f} deg/update  |  monotonic {c.monotonic*100:.0f}%"
    )
