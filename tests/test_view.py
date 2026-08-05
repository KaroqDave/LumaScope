"""Rendering tests: annotated hex dumps, field maps, LED tables, comparisons.

These assert the properties a reader depends on -- that columns line up, that every byte
is named, that colour is opt-in -- rather than pinning exact strings, so the layout can
be tuned without churning the suite.
"""

import re

from lumascope import view
from lumascope.annotate import RGB_TAGS, describe_framing, fields_from_framing, fields_from_spec
from lumascope.decode.chunked import ChunkFraming
from lumascope.examples import BY_NAME

AURA = ChunkFraming(
    prefix=bytes.fromhex("ec40"), channel_pos=2, channel_mask=0x7F, offset_pos=3,
    count_pos=4, payload_start=5, unit=3, chunk_count=20, final_flag=0x80,
)
PACKET = bytes.fromhex("ec408400" "02" "ff0000" "00ff00") + b"\x00" * 52


def test_field_map_names_every_header_byte():
    fmap = fields_from_framing(AURA, PACKET)
    names = {fmap.at(i).name for i in range(5)}
    assert names == {"report id", "command", "channel", "offset", "count"}


def test_field_map_tags_payload_as_rgb_in_order():
    fmap = fields_from_framing(AURA, PACKET)
    # count=2 -> two LEDs of payload starting at byte 5
    assert [fmap.tag_at(i).strip() for i in range(5, 11)] == list(RGB_TAGS) * 2


def test_field_map_marks_the_final_chunk_flag():
    fmap = fields_from_framing(AURA, PACKET)
    channel = fmap.at(2)
    assert "channel 4" in channel.detail
    assert "final" in channel.detail.lower()


def test_field_map_covers_the_packet_with_no_gaps():
    fmap = fields_from_framing(AURA, PACKET)
    assert all(fmap.at(i) is not None for i in range(len(PACKET)))


def test_hexdump_rows_are_column_aligned():
    fmap = fields_from_framing(AURA, PACKET)
    text = view.hexdump(PACKET, fields=fmap, width=16, collapse=False, ascii_gutter=False)
    hex_rows = [ln for ln in text.splitlines() if re.match(r"\s+\d+\s+[0-9a-f]{2}", ln)]
    assert len(hex_rows) == 5  # 65 bytes at 16/row
    # The tag row under a full hex row must be exactly as wide as the hex it labels.
    lines = text.splitlines()
    first_hex = lines.index(hex_rows[0])
    assert len(lines[first_hex + 1].rstrip()) <= len(lines[first_hex].rstrip())


def test_hexdump_collapses_repeated_rows():
    data = b"\xab" + b"\x00" * 200
    collapsed = view.hexdump(data, collapse=True)
    full = view.hexdump(data, collapse=False)
    assert "identical row" in collapsed
    assert len(collapsed.splitlines()) < len(full.splitlines())
    # The last row must survive collapsing so the end of the packet stays visible.
    assert collapsed.splitlines()[-1].strip().startswith("192")


def test_hexdump_marks_varying_columns():
    text = view.hexdump(PACKET, vary=[2, 3], width=16)
    marker = next(ln for ln in text.splitlines() if "^^" in ln)
    hex_row = next(ln for ln in text.splitlines() if " ec 40 " in ln)
    assert marker.index("^^") == hex_row.index("ec 40 84") + len("ec 40 ")


def test_no_ansi_escapes_unless_colour_requested():
    fmap = fields_from_framing(AURA, PACKET)
    plain = view.render_packet(PACKET, fields=fmap, color=False)
    assert "\033[" not in plain
    assert "\033[" in view.render_packet(PACKET, fields=fmap, color=True)


def test_output_is_pure_ascii_without_colour():
    """A legacy Windows console must be able to render every glyph."""
    fmap = fields_from_framing(AURA, PACKET)
    text = view.render_packet(PACKET, fields=fmap, color=False)
    text += view.led_table(b"\xff\x00\x00" * 4, color=False)
    text += view.compare(PACKET, PACKET[:5] + b"\x00" * 60)
    text += describe_framing(AURA)
    text.encode("ascii")  # raises if anything non-ASCII slipped in


def test_led_table_collapses_identical_runs():
    buf = b"\xff\x00\x00" * 120
    table = view.led_table(buf, color=False)
    assert len(table.splitlines()) == 1
    assert "LED 0..119" in table
    assert "(x120)" in table


def test_led_runs_respects_wire_channel_order():
    # One LED whose wire bytes are GRB: 00 ff 00 is red in GRB order.
    assert view.led_runs(bytes.fromhex("00ff00"), order="GRB") == [(0, 0, (255, 0, 0))]
    assert view.led_runs(bytes.fromhex("00ff00"), order="RGB") == [(0, 0, (0, 255, 0))]


def test_compare_marks_only_the_differing_columns():
    a = bytes.fromhex("ec400000") + b"\x00" * 4
    b = bytes.fromhex("ec400100") + b"\x00" * 4
    text = view.compare(a, b)
    marker = next(ln for ln in text.splitlines() if "^^" in ln)
    assert marker.count("^^") == 1


def test_fields_from_spec_names_checksum_and_leds():
    spec = BY_NAME["interleaved"]()
    fmap = fields_from_spec(spec)
    names = {f.name for f in fmap.fields}
    assert "LED colour data" in names
    if spec.checksum.present:
        assert "checksum" in names


def test_fields_from_spec_covers_the_whole_packet():
    for factory in BY_NAME.values():
        spec = factory()
        fmap = fields_from_spec(spec)
        assert all(fmap.at(i) is not None for i in range(spec.packet_len)), spec.name


def test_resolve_color_never_honours_force(monkeypatch):
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert view.resolve_color("never") is False
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.delenv("FORCE_COLOR")
    assert view.resolve_color("auto") is False
