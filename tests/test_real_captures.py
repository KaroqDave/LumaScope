"""Regression tests pinned to distilled real ASUS Aura capture fixtures."""

from pathlib import Path

from lumascope.capture.serialize import load_frames
from lumascope.decode.cadence import analyze_cadence
from lumascope.decode.chunked import infer_framing, reassemble

FIXTURES = Path(__file__).parent / "fixtures"


def test_real_aura_ec40_fixture_reassembles_channels():
    frames = load_frames(str(FIXTURES / "aura_ec40_first_update.jsonl"))
    framing = infer_framing(frames)

    assert framing is not None
    assert framing.prefix == b"\xEC\x40"
    assert framing.channel_pos == 2
    assert framing.channel_mask == 0x7F
    assert framing.final_flag == 0x80
    assert framing.offset_pos == 3
    assert framing.count_pos == 4
    assert framing.payload_start == 5
    assert framing.unit == 3
    assert framing.chunk_count == 20

    channels = reassemble(frames, framing)
    assert {ch: len(buf) for ch, buf in channels.items()} == {0: 360, 1: 360, 2: 360, 4: 6}
    assert channels[0][:12] == bytes.fromhex("ff0000ff0000ff0000ff0000")
    assert channels[4] == bytes.fromhex("ff0000ff0000")


def test_real_rainbow_cadence_fixtures_preserve_speed_ordering():
    slow = analyze_cadence(load_frames(str(FIXTURES / "rainbow_slow_first_chunks.jsonl")))
    med = analyze_cadence(load_frames(str(FIXTURES / "rainbow_med_first_chunks.jsonl")))
    fast = analyze_cadence(load_frames(str(FIXTURES / "rainbow_fast_first_chunks.jsonl")))

    assert slow is not None and med is not None and fast is not None
    assert slow.has_timing and med.has_timing and fast.has_timing
    assert slow.command == med.command == fast.command == (0xEC, 0x40)
    assert fast.cycle_period_s < med.cycle_period_s < slow.cycle_period_s
    assert slow.hue_deg_per_update < med.hue_deg_per_update < fast.hue_deg_per_update


# --------------------------------------------------------------------------- #
# Mixed chunk sizes (found on live hardware)
# --------------------------------------------------------------------------- #
MIXED = FIXTURES / "aura_ec40_mixed_chunk_sizes.jsonl"


def test_framing_infers_when_channels_use_different_chunk_sizes():
    """Captured live: SignalRGB driving an ASUS Aura controller.

    Its channels have different LED counts, so each ends in a short final chunk and the
    count column holds 20/8/4. The modal count is then 8 -- a *partial* chunk -- which no
    offset stride can match, and framing inference returned None on a device that plainly
    is chunked. The full chunk size is the maximum, not the mode.

    The bundled Armoury Crate samples never showed this: their counts are near-uniform.
    """
    from lumascope.decode.chunked import dominant_command_class, infer_framing

    frames = load_frames(str(MIXED))
    counts = {f.data[4] for f in frames}
    assert len(counts) > 1, "fixture must keep the mixed-size property"

    framing = infer_framing(dominant_command_class(frames))
    assert framing is not None
    assert framing.chunk_count == max(counts)
    assert (framing.channel_pos, framing.offset_pos, framing.count_pos) == (2, 3, 4)
    assert framing.unit == 3
    assert framing.final_flag == 0x80


def test_mixed_chunk_capture_reassembles_every_channel():
    from lumascope.decode.chunked import reassemble_capture

    framing, channels = reassemble_capture(load_frames(str(MIXED)))
    assert framing is not None
    # Three zones of different lengths -- the shape that broke inference.
    assert {ch: len(buf) // 3 for ch, buf in channels.items()} == {0: 48, 1: 8, 4: 4}
    assert len({len(buf) for buf in channels.values()}) > 1


def test_partial_final_chunks_do_not_become_the_inferred_chunk_size():
    """Guards the specific regression: picking the mode here yields 8, and 8 is a
    partial chunk. If this starts failing, inference has gone back to trusting the mode."""
    from collections import Counter

    from lumascope.decode.chunked import dominant_command_class, infer_framing

    frames = load_frames(str(MIXED))
    modal_count = Counter(f.data[4] for f in frames).most_common(1)[0][0]
    framing = infer_framing(dominant_command_class(frames))
    assert modal_count != framing.chunk_count


# --------------------------------------------------------------------------- #
# End-to-end on hardware-derived data
# --------------------------------------------------------------------------- #
LIVE_CORPUS = FIXTURES / "aura_openrgb_live.corpus.json"


def test_decodes_a_corpus_captured_from_real_hardware():
    """The only decode test whose input came off a physical device.

    Captured by `lumascope sweep --driver openrgb` against an ASUS Aura USB mainboard
    controller (0B05:19AF), Frida hooking OpenRGB as it applied each state. Every field
    below independently reproduces docs/asus-aura-pid19af-protocol.md, which was derived
    from Armoury Crate -- a different host entirely.
    """
    from lumascope.capture.serialize import load_corpus
    from lumascope.decode import decode

    corpus = load_corpus(str(LIVE_CORPUS))
    assert len(corpus.frames) == 63

    result = decode(corpus, name="aura-live")
    assert result.validation.ok, result.validation.summary()

    spec = result.spec
    assert spec.packet_len == 65
    assert spec.report_id == 0xEC
    assert spec.leds.count == 2
    assert spec.leds.layout == "interleaved"
    assert spec.leds.stride == 3
    assert spec.leds.channel_order == "RGB"      # the doc's controlled-capture finding
    assert spec.leds.base_offset == 5            # payload begins after the 5-byte header
    assert spec.checksum.kind == "none"          # "no checksum observed"
    assert spec.leds.scaling.type == "identity"


def test_live_corpus_reencodes_byte_for_byte():
    """The strongest statement available: the recovered spec regenerates every packet
    the hardware actually sent."""
    from lumascope import codec
    from lumascope.capture.serialize import load_corpus
    from lumascope.decode import decode

    corpus = load_corpus(str(LIVE_CORPUS))
    spec = decode(corpus, name="aura-live").spec
    for lf in corpus.frames:
        brightness = lf.step.brightness if lf.step.brightness is not None else 255
        assert codec.encode_frame(spec, lf.step.colors, brightness=brightness) == lf.frame.data


CHUNKED_CORPUS = FIXTURES / "aura_chunked_48led.corpus.json"


def test_decodes_a_chunked_48led_corpus_from_real_hardware():
    """The strongest hardware case: a 48-LED addressable header, streamed in chunks.

    Captured by `lumascope sweep --driver openrgb` against an ASUS Aura USB controller
    with a real strip attached. Unlike the 2-LED mainboard zone, this gives the layout
    and stride passes 48 LEDs of evidence, and exercises chunk reassembly end to end.
    """
    from lumascope.capture.serialize import load_corpus
    from lumascope.decode import decode

    result = decode(load_corpus(str(CHUNKED_CORPUS)), name="aura-48")
    assert result.validation.ok, result.validation.summary()

    spec = result.spec
    assert spec.leds.count == 48
    assert spec.leds.layout == "interleaved"
    assert spec.leds.stride == 3
    assert spec.leds.channel_order == "RGB"
    assert spec.leds.scaling.type == "identity"
    assert spec.checksum.kind == "none"

    # The chunking model, recovered rather than assumed: EC 40, 20 LEDs per chunk.
    assert spec.chunking.present
    assert spec.chunking.prefix == b"\xEC\x40"
    assert spec.chunking.chunk_count == 20
    assert spec.chunking.unit == 3
    assert spec.chunking.payload_start == 5


def test_chunked_corpus_reencodes_byte_for_byte():
    from lumascope import codec
    from lumascope.capture.serialize import load_corpus
    from lumascope.decode import decode

    corpus = load_corpus(str(CHUNKED_CORPUS))
    spec = decode(corpus, name="aura-48").spec
    for lf in corpus.frames:
        brightness = lf.step.brightness if lf.step.brightness is not None else 255
        assert codec.encode_frame(spec, lf.step.colors, brightness=brightness) == lf.frame.data
