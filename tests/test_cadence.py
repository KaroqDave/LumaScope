"""Cadence (temporal) analysis of a streamed effect — no hardware.

Builds a synthetic EC40-style colour-cycle stream with KNOWN timing and a KNOWN hue rate, then
checks the analyzer recovers the frame rate, the cycle period, and the hue rate — the same
measurement that reads a rainbow effect's speed off a real capture.
"""
import colorsys

from lumascope.decode.cadence import analyze_cadence
from lumascope.model import CaptureFrame


def _rgb(h):
    r, g, b = colorsys.hsv_to_rgb(h % 1.0, 1.0, 1.0)
    return bytes([round(r * 255), round(g * 255), round(b * 255)])


def build_cycle(*, revolutions=1.0, steps=100, span_s=2.0, dt_ns=None, channel=0):
    """EC40 first-chunk frames whose LED0 hue advances `revolutions` turns over `span_s`."""
    frames = []
    n = steps + 1
    for i in range(n):
        h = revolutions * i / steps
        ts = int(i * (span_s / steps) * 1e9) if dt_ns is None else i * dt_ns
        d = bytes([0xEC, 0x40, channel, 0x00, 0x01]) + _rgb(h) + b"\x00" * 57
        frames.append(CaptureFrame(data=d[:65], direction="out", timestamp_ns=ts,
                                   vid=0x0B05, pid=0x19AF))
    return frames


def test_recovers_frame_rate_and_cycle_period():
    # 101 frames over exactly 2.0 s, hue does one full revolution in that time.
    c = analyze_cadence(build_cycle(revolutions=1.0, steps=100, span_s=2.0))
    assert c is not None and c.has_timing
    assert c.command == (0xEC, 0x40)
    assert c.frames == 101
    assert abs(c.frame_rate - 50.0) < 1.0            # 100 intervals / 2.0 s
    assert abs(c.cycle_period_s - 2.0) < 0.1         # one revolution in 2.0 s
    assert abs(c.hue_deg_per_s - 180.0) < 5.0        # 360° / 2.0 s
    assert c.monotonic > 0.95                        # clean one-directional cycle


def test_faster_effect_has_shorter_period_same_frame_rate():
    # Same 50 fps stream; the "fast" one advances hue 4x further per frame.
    slow = analyze_cadence(build_cycle(revolutions=1.0, steps=100, span_s=2.0))
    fast = analyze_cadence(build_cycle(revolutions=4.0, steps=100, span_s=2.0))
    assert abs(slow.frame_rate - fast.frame_rate) < 1.0          # frame rate unchanged
    assert abs(fast.hue_deg_per_update / slow.hue_deg_per_update - 4.0) < 0.2  # 4x phase step
    assert fast.cycle_period_s < slow.cycle_period_s / 3         # ~4x shorter period


def test_auto_picks_channel_with_most_samples():
    frames = build_cycle(channel=2) + build_cycle(channel=2) + build_cycle(channel=5)
    c = analyze_cadence(frames)
    assert c.channel == 2


def test_no_timestamps_flagged_not_crashed():
    frames = build_cycle(dt_ns=0)   # all timestamps 0
    c = analyze_cadence(frames)
    assert c is not None
    assert c.has_timing is False
    assert c.frame_rate == 0.0 and c.cycle_period_s == 0.0


def test_returns_none_without_outbound_frames():
    assert analyze_cadence([]) is None
    inbound = [CaptureFrame(data=bytes([0xEC, 0x40, 0, 0, 1, 9, 9, 9]) + b"\x00" * 57,
                            direction="in", timestamp_ns=1)]
    assert analyze_cadence(inbound) is None
    assert analyze_cadence(inbound, direction="in") is not None


def test_dominant_command_class_includes_packet_length():
    streamed = build_cycle(steps=10)
    decoys = [
        CaptureFrame(
            data=bytes([0xEC, 0x40, 0, 0, 1, 9, 9, 9]),
            direction="out",
            timestamp_ns=index + 1,
        )
        for index in range(5)
    ]

    cadence = analyze_cadence(streamed + decoys)

    assert cadence is not None
    assert cadence.frames == len(streamed)
