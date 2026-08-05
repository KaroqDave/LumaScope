"""Orchestrator tests — no hardware.

A mock backend + a mock driver simulate a real capture: per sweep step the driver pushes the
codec-encoded packet for that step (plus an occasional differently-sized "handshake" decoy)
into the backend, exactly as a live capture would surface them. The orchestrator pairs them
into a Corpus and the real decode engine must recover the known ground-truth spec — proving
the drive->capture->pair->decode wiring end to end.
"""
from lumascope import codec, examples, orchestrate
from lumascope.capture.base import CaptureBackend
from lumascope.decode import decode
from lumascope.model import KIND_UNIFORM, CaptureFrame, SweepStep
from lumascope.stimulus.base import StimulusDriver
from lumascope.synthetic import frame_for_step

FAST = dict(settle=0, quiet=0, poll=0, max_wait=0.5)


class MockBackend(CaptureBackend):
    name = "mock"

    def open(self) -> None:
        pass

    def close(self) -> None:
        pass


class EncodingDriver(StimulusDriver):
    """'Applies' a step by pushing its codec-encoded frame (and a periodic decoy) into the
    shared backend, simulating the capture a real device would produce for that state."""

    name = "mock-encode"

    def __init__(self, spec, backend: MockBackend) -> None:
        self.spec = spec
        self.backend = backend

    def set_state(self, step: SweepStep) -> bool:
        # An occasional handshake/keepalive of a different length the pairing must ignore.
        if step.step_id % 3 == 0:
            self.backend._push(CaptureFrame(data=b"\xAA\xBB", direction="out", transfer="interrupt"))
        self.backend._push(frame_for_step(self.spec, step))
        return True


def test_orchestrate_end_to_end_recovers_every_example():
    for factory in examples.ALL:
        spec = factory()
        backend = MockBackend()
        driver = EncodingDriver(spec, backend)
        corpus, raw = orchestrate.run_sweep(
            backend, driver, spec.leds.count,
            device_name=spec.name, vid=spec.vid, pid=spec.pid, **FAST,
        )
        # Every step contributed exactly one representative frame (decoys filtered out).
        assert len(corpus.frames) == len(raw)
        result = decode(corpus, name=spec.name)
        assert result.validation.ok, (spec.name, result.validation.summary())
        assert result.spec.leds.channel_order == spec.leds.channel_order
        assert result.spec.checksum.kind == spec.checksum.kind


def test_pair_selects_modal_length_representative():
    s0 = SweepStep(step_id=0, kind=KIND_UNIFORM, colors=[(0, 0, 0)])
    s1 = SweepStep(step_id=1, kind=KIND_UNIFORM, colors=[(0, 0, 0)])
    real0 = CaptureFrame(data=bytes(64), direction="out")
    decoy = CaptureFrame(data=b"\x01\x02", direction="out")        # wrong length
    inbound = CaptureFrame(data=bytes(64), direction="in")          # wrong direction
    raw = [
        (s0, [decoy, real0, inbound]),
        (s1, [CaptureFrame(data=bytes(64), direction="out")]),
    ]
    corpus = orchestrate.pair(raw, led_count=1)
    assert len(corpus.frames) == 2
    assert len(corpus.frames[0].frame.data) == 64   # modal length, not the 2-byte decoy
    assert corpus.frames[0].frame.direction == "out"


class ChunkedDriver(StimulusDriver):
    """'Applies' a step by encoding its colors into EC40-style chunk packets (like ASUS Aura):
    a flat wire buffer in the given channel order, streamed in `chunk`-byte pieces."""

    name = "chunked-mock"
    _IDX = {"R": 0, "G": 1, "B": 2}

    def __init__(self, backend, *, order="GRB", chunk=6, channel=0, transfer="", report_id=None):
        self.backend = backend
        self.order = order
        self.chunk = chunk
        self.channel = channel
        self.transfer = transfer
        self.report_id = report_id

    def set_state(self, step):
        buf = bytearray()
        for color in step.colors:
            for ch in self.order:
                buf.append(color[self._IDX[ch]])
        offsets = list(range(0, len(buf), self.chunk)) or [0]
        for i, off in enumerate(offsets):
            piece = buf[off:off + self.chunk]
            last = i == len(offsets) - 1
            head = bytes([0xEC, 0x40, self.channel | (0x80 if last else 0), off, len(piece)])
            data = head + bytes(piece)
            data += b"\x00" * (65 - len(data))
            self.backend._push(CaptureFrame(
                data=bytes(data[:65]),
                direction="out",
                transfer=self.transfer,
                report_id=self.report_id,
            ))
        return True


def test_chunked_sweep_reassembles_and_decodes():
    # A chunked (Aura-like) device: the orchestrator must reassemble each step's chunks into the
    # full buffer before decoding. led_count kept small so byte offsets stay < 256.
    backend = MockBackend()
    driver = ChunkedDriver(backend, order="GRB", chunk=6, channel=0)
    corpus, raw = orchestrate.run_sweep(backend, driver, led_count=8, **FAST)

    assert len(corpus.frames) == len(raw)
    # Each paired frame is the reassembled buffer (8 LEDs x 3 = 24 bytes), not a 65-byte chunk.
    assert all(len(lf.frame.data) == 24 for lf in corpus.frames)
    result = decode(corpus, name="chunked")
    assert result.validation.ok, result.validation.summary()
    assert result.spec.leds.channel_order == "GRB"      # recovered the wire order
    assert result.spec.leds.count == 8
    assert result.spec.chunking.present
    assert result.spec.chunking.packet_len == 65
    assert result.spec.chunking.chunk_count == 6
    assert codec.encode_packets(result.spec, raw[0][0].colors) == [f.data for f in raw[0][1]]


def test_chunked_reassembly_keeps_report_id_in_prefix_only():
    backend = MockBackend()
    driver = ChunkedDriver(backend, transfer="feature", report_id=0xEC)
    corpus, _raw = orchestrate.run_sweep(backend, driver, led_count=4, **FAST)
    result = decode(corpus, name="chunked-feature")
    assert result.validation.ok, result.validation.summary()
    assert result.spec.transport == "hid_feature"
    assert result.spec.report_id is None
    assert result.spec.chunking.prefix == b"\xEC\x40"


def test_chunked_disabled_falls_back_to_single_packet():
    backend = MockBackend()
    driver = ChunkedDriver(backend, chunk=6, channel=0)
    corpus, _raw = orchestrate.run_sweep(backend, driver, led_count=8, chunked=False, **FAST)
    # With reassembly off, each step pairs a single 65-byte chunk instead of the 24-byte buffer.
    assert all(len(lf.frame.data) == 65 for lf in corpus.frames)


def test_skipped_step_contributes_no_frame():
    class SkipDriver(StimulusDriver):
        name = "skip"

        def set_state(self, step):
            return False  # operator skipped; nothing applied, nothing captured

    backend = MockBackend()
    corpus, raw = orchestrate.run_sweep(backend, SkipDriver(), led_count=2, **FAST)
    assert raw == []
    assert corpus.frames == []


class TrackingDriver(StimulusDriver):
    """Records the lifecycle calls it receives. Uses the pre-``total_steps`` signature on
    purpose, to prove drivers written against the older contract still run."""

    name = "tracking"

    def __init__(self, fail_on_step=False):
        self.setup_called = False
        self.teardown_called = False
        self.fail_on_step = fail_on_step

    def setup(self, led_count: int) -> None:
        self.setup_called = True

    def set_state(self, step):
        if self.fail_on_step:
            raise RuntimeError("boom")
        return True

    def teardown(self) -> None:
        self.teardown_called = True


def test_backend_opens_before_the_driver_is_engaged():
    """A failure to start capturing must not first walk an operator into a manual session."""

    class FailingBackend(MockBackend):
        def open(self) -> None:
            raise RuntimeError("boom")

    driver = TrackingDriver()
    try:
        orchestrate.run_sweep(FailingBackend(), driver, led_count=2, **FAST)
    except RuntimeError as exc:
        assert str(exc) == "boom"
    else:
        raise AssertionError("backend open failure should propagate")
    assert not driver.setup_called
    assert not driver.teardown_called


def test_driver_teardown_runs_when_a_step_fails():
    driver = TrackingDriver(fail_on_step=True)
    try:
        orchestrate.run_sweep(MockBackend(), driver, led_count=2, **FAST)
    except RuntimeError as exc:
        assert str(exc) == "boom"
    else:
        raise AssertionError("step failure should propagate")
    assert driver.setup_called
    assert driver.teardown_called


# --------------------------------------------------------------------------- #
# Boilerplate packets (found on live hardware)
# --------------------------------------------------------------------------- #
def _zone_writing_host(step_colors):
    """A host that writes each zone separately and finishes with empty applies.

    OpenRGB driving an ASUS Aura controller does exactly this: the colour goes out
    first, then one zero-length apply per addressable zone that has no LEDs in it. Those
    applies are the *last* writes of the modal length, so "take the last one" pairs every
    step with an all-zero payload.
    """
    frames = []
    r, g, b = step_colors
    frames.append(CaptureFrame(data=bytes([0xEC, 0x40, 0x84, 0x00, 0x02, r, g, b] + [0] * 57),
                               direction="out"))
    for zone in (0x80, 0x81, 0x82):
        frames.append(CaptureFrame(data=bytes([0xEC, 0x40, zone, 0x00, 0x00] + [0] * 60),
                                   direction="out"))
    return frames


def test_pairing_skips_packets_repeated_identically_in_every_step():
    colors = [(255, 0, 0), (0, 255, 0), (0, 0, 255), (255, 255, 0), (0, 128, 255)]
    raw = [
        (SweepStep(step_id=i, kind=KIND_UNIFORM, colors=[c], value=c[0]), _zone_writing_host(c))
        for i, c in enumerate(colors)
    ]
    corpus = orchestrate.pair(raw, led_count=1, chunked=False)

    assert len(corpus.frames) == len(colors)
    for lf, c in zip(corpus.frames, colors):
        # The colour packet, not one of the empty applies.
        assert lf.frame.data[4] == 0x02, lf.frame.data[:6].hex(" ")
        assert tuple(lf.frame.data[5:8]) == c


def test_boilerplate_detection_needs_enough_steps_to_be_meaningful():
    """With two steps everything looks constant; refuse to guess."""
    raw = [
        (SweepStep(step_id=i, kind=KIND_UNIFORM, colors=[c], value=c[0]), _zone_writing_host(c))
        for i, c in enumerate([(255, 0, 0), (0, 255, 0)])
    ]
    assert orchestrate._boilerplate(raw, modal_len=65) == frozenset()


def test_pairing_falls_back_when_every_packet_is_boilerplate():
    """A device whose writes never vary must still yield a frame per step, not nothing."""
    same = (7, 7, 7)
    raw = [
        (SweepStep(step_id=i, kind=KIND_UNIFORM, colors=[same], value=7), _zone_writing_host(same))
        for i in range(4)
    ]
    corpus = orchestrate.pair(raw, led_count=1, chunked=False)
    assert len(corpus.frames) == 4
