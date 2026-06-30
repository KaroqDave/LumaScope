"""Chunked-protocol reassembly tests (Aura-style EC40 framing), no hardware.

Builds a synthetic chunked capture from known per-channel buffers, then checks that the
reassembly recovers them and that framing inference finds the header layout — the same shape
the pass recovered from a real ASUS Aura USB capture.
"""
from lumascope.decode.chunked import ChunkFraming, infer_framing, reassemble, reassemble_auto
from lumascope.model import CaptureFrame

FRAMING = ChunkFraming(prefix=b"\xec\x40", channel_pos=2, channel_mask=0x7F,
                       offset_pos=3, count_pos=4, payload_start=5)


def build_chunks(channel_buffers, *, prefix=b"\xec\x40", chunk=20, packet_len=65, flag=0x80):
    """Emit EC40-style chunk packets for each channel buffer (flag bit set on the last chunk)."""
    frames = []
    for ch, buf in channel_buffers.items():
        offsets = list(range(0, len(buf), chunk)) or [0]
        for i, off in enumerate(offsets):
            piece = buf[off:off + chunk]
            last = i == len(offsets) - 1
            head = bytes([ch | (flag if last else 0), off, len(piece)])
            data = bytearray(prefix) + head + piece
            data += b"\x00" * (packet_len - len(data))
            frames.append(CaptureFrame(data=bytes(data[:packet_len]), direction="out"))
    return frames


def test_reassemble_recovers_buffers():
    bufs = {0: bytes(range(30)), 1: bytes((i * 5) & 0xFF for i in range(60))}
    out = reassemble(build_chunks(bufs), FRAMING)
    assert out[0] == bufs[0]
    assert out[1] == bufs[1]


def test_infer_framing_recovers_layout():
    # 3 channels of 40 GRB LEDs (red in GRB = 00 ff 00), exact multiples of the chunk size.
    bufs = {0: bytes([0, 255, 0] * 40), 1: bytes([255, 0, 0] * 40), 2: bytes([0, 0, 255] * 40)}
    fr = infer_framing(build_chunks(bufs))
    assert fr is not None
    assert fr.prefix == b"\xec\x40"
    assert fr.channel_pos == 2 and fr.channel_mask == 0x7F   # flag bit detected + stripped
    assert fr.offset_pos == 3 and fr.count_pos == 4
    assert fr.payload_start == 5


def test_reassemble_auto_end_to_end():
    bufs = {0: bytes([0, 255, 0] * 40), 1: bytes([255, 0, 0] * 40)}
    fr, chans = reassemble_auto(build_chunks(bufs))
    assert fr is not None
    assert chans[0] == bufs[0] and chans[1] == bufs[1]
    # the flag-bit channels (0x80|ch) collapse onto the same logical channel
    assert set(chans) == {0, 1}


def test_last_write_wins_for_restreamed_state():
    frames = build_chunks({0: bytes([1, 2, 3] * 4)}) + build_chunks({0: bytes([9, 9, 9] * 4)})
    assert reassemble(frames, FRAMING)[0] == bytes([9, 9, 9] * 4)


def test_infers_led_units_payload_times_three():
    # ASUS Aura shape: offset/count are in LEDs, payload = count*3 bytes (RGB). The unit must
    # be inferred as 3 even for red (ff0000), whose per-LED trailing bytes are zero.
    leds, chunk = 30, 20
    full = b"\xff\x00\x00" * leds  # 90 bytes, all red
    frames = []
    for off in range(0, leds, chunk):
        n = min(chunk, leds - off)
        payload = full[off * 3:(off + n) * 3]
        head = bytes([0xEC, 0x40, (0x80 if off + n >= leds else 0), off, n])
        data = head + payload + b"\x00" * (65 - 5 - len(payload))
        frames.append(CaptureFrame(data=bytes(data[:65]), direction="out"))

    fr = infer_framing(frames)
    assert fr is not None
    assert fr.unit == 3                       # count is in LEDs, not bytes
    assert reassemble(frames, fr)[0] == full  # 90 bytes recovered, not 30


def test_non_chunked_capture_returns_none():
    # Frames with no stride-like offset column shouldn't be mistaken for chunked.
    frames = [CaptureFrame(data=bytes([0xEC, 0x40, i, 0xAA, 0xBB]) + b"\x00" * 60, direction="out")
              for i in range(4)]
    assert infer_framing(frames) is None
