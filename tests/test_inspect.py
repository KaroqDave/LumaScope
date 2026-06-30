"""Command-packet inspection + single-variable diff (no hardware).

Builds synthetic ASUS-Aura-shaped captures (EC40 chunked colour, EC35 mode, EC36 colour-data)
and checks that grouping buckets them by command class and that diffing two captures which
differ by exactly one variable localises the single changed byte column.
"""
from lumascope.decode.inspect import (
    command_signature,
    compress_columns,
    diff_captures,
    group_frames,
)
from lumascope.model import CaptureFrame


def _f(data, **kw):
    kw.setdefault("direction", "out")
    kw.setdefault("vid", 0x0B05)
    kw.setdefault("pid", 0x19AF)
    return CaptureFrame(data=bytes(data), **kw)


def ec40_chunks(color, leds=40, chunk=20, packet_len=65):
    """EC40 direct-colour chunks for one channel — offsets vary across the stream."""
    full = bytes(color) * leds
    frames = []
    for off in range(0, leds, chunk):
        n = min(chunk, leds - off)
        payload = full[off * 3:(off + n) * 3]
        head = bytes([0xEC, 0x40, 0x80 if off + n >= leds else 0, off, n])
        data = head + payload
        data += b"\x00" * (packet_len - len(data))
        frames.append(_f(data[:packet_len]))
    return frames


def ec35_mode(mode, packet_len=65):
    return [_f((bytes([0xEC, 0x35, 0x00, 0x00, mode]) + b"\x00" * packet_len)[:packet_len])]


def ec36_color(color, packet_len=65):
    # EC36 <ch> <offset> <count>  R G B  ...
    return [_f((bytes([0xEC, 0x36, 0x00, 0x00, 0x01]) + bytes(color) + b"\x00" * packet_len)[:packet_len])]


def capture(color, mode):
    return ec40_chunks(color) + ec35_mode(mode) + ec36_color(color)


def test_signature_is_report_plus_command():
    assert command_signature(bytes([0xEC, 0x40, 0x84]), 2) == (0xEC, 0x40)


def test_grouping_buckets_by_command_class():
    frames = capture((0xFF, 0x00, 0x00), mode=0x03)
    groups = {g.signature: g for g in group_frames(frames)}
    assert set(groups) == {(0xEC, 0x40), (0xEC, 0x35), (0xEC, 0x36)}
    assert groups[(0xEC, 0x40)].count == 2          # two chunks
    assert groups[(0xEC, 0x35)].count == 1
    # EC40 flag-bit and offset columns vary across the stream; the prefix does not.
    varying = groups[(0xEC, 0x40)].varying_columns()
    assert 0 not in varying and 1 not in varying      # ec 40 constant
    assert 2 in varying and 3 in varying              # last-chunk flag + offset advance
    assert 4 not in varying                           # count constant (both chunks = 20 LEDs)


def test_filters_drop_inbound_and_foreign_devices():
    frames = ec36_color((1, 2, 3))
    frames.append(_f(bytes([0xEC, 0x36, 0, 0, 1, 9, 9, 9]) + b"\x00" * 57, direction="in"))
    frames.append(_f(bytes([0xAB, 0xCD, 0, 0, 1, 9, 9, 9]) + b"\x00" * 57, vid=0x1234, pid=0x5678))
    groups = group_frames(frames, vid=0x0B05, pid=0x19AF, direction="out")
    assert [g.signature for g in groups] == [(0xEC, 0x36)]
    assert groups[0].count == 1


def test_diff_localises_the_single_changed_colour_byte():
    # Same effect (mode 0x03), only the colour differs: red -> green. The EC36 colour byte
    # (and EC40 payload) must light up; the unchanged mode command and the chunk offsets cancel.
    red = capture((0xFF, 0x00, 0x00), mode=0x03)
    green = capture((0x00, 0xFF, 0x00), mode=0x03)
    diffs = {d.signature: d for d in diff_captures(red, green)}

    ec35 = diffs[(0xEC, 0x35)]
    assert ec35.shared and not ec35.changed           # effect unchanged -> no columns flagged

    ec36 = diffs[(0xEC, 0x36)]
    changed = {c.index: (c.a_values, c.b_values) for c in ec36.changed}
    assert set(changed) == {5, 6}                      # R col and G col moved, B (col 7) didn't
    assert changed[5] == ([0xFF], [0x00])              # red byte: ff -> 00
    assert changed[6] == ([0x00], [0xFF])              # green byte: 00 -> ff


def test_diff_flags_changed_effect_mode_byte():
    # Hold colour, change only the effect mode in EC35 -> only the mode column should differ.
    a = capture((0x10, 0x20, 0x30), mode=0x03)
    b = capture((0x10, 0x20, 0x30), mode=0x04)
    diffs = {d.signature: d for d in diff_captures(a, b)}
    ec35 = diffs[(0xEC, 0x35)]
    assert [c.index for c in ec35.changed] == [4]
    assert ec35.changed[0].a_values == [0x03] and ec35.changed[0].b_values == [0x04]
    assert not diffs[(0xEC, 0x36)].changed             # colour identical


def test_diff_reports_command_classes_present_in_only_one_capture():
    a = ec35_mode(0x03) + ec36_color((1, 2, 3))
    b = ec35_mode(0x03)
    diffs = {d.signature: d for d in diff_captures(a, b)}
    assert diffs[(0xEC, 0x36)].in_a and not diffs[(0xEC, 0x36)].in_b


def test_compress_columns_renders_runs():
    assert compress_columns([2, 3, 4, 7, 9, 10]) == "2..4,7,9..10"
    assert compress_columns([]) == "-"
    assert compress_columns([5]) == "5"
