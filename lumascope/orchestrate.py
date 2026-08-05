"""Drive -> capture -> pair: turn live stimulus + capture into a labeled :class:`Corpus`.

The orchestrator is the seam between the hardware-facing half (a stimulus driver + a capture
backend) and the proven software half (decode -> emit). Per sweep step it:

    backend.drain()                       # discard anything buffered before this step
    driver.set_state(step)                # apply the known state (API or operator)
    frames = collect_until_quiet(backend) # capture this step's writes

Then :func:`pair` selects one representative packet per step (the last write of the modal
output-packet length — vendor apps interleave handshakes/keepalives of other lengths) and
assembles a :class:`Corpus` that ``lumascope decode`` consumes unchanged.
"""

from __future__ import annotations

import inspect
from collections import Counter
from dataclasses import replace
from typing import Callable, Optional

from .decode.chunked import ChunkFraming, dominant_command_class, infer_framing, reassemble
from .model import CaptureFrame, Corpus, LabeledFrame, SweepStep
from .stimulus import matrix
from .stimulus.base import StimulusDriver
from .stimulus.manual import SweepAborted
from .stimulus.sync import collect_until_quiet


def _representative(
    frames: list[CaptureFrame],
    modal_len: Optional[int],
    boilerplate: frozenset[bytes] = frozenset(),
) -> Optional[CaptureFrame]:
    """Pick the one frame that best represents a step.

    The last outbound write of the modal packet length, skipping any packet in
    ``boilerplate`` -- byte patterns a host repeats identically in every step.

    Skipping those matters: a host that writes each zone separately finishes an update
    with empty applies for the zones it has no LEDs in. Those are the *last* writes of
    the modal length, so a naive "take the last one" rule labels every step with an
    all-zero payload and the whole corpus decodes to nothing.
    """
    out = [f for f in frames if f.direction == "out" and len(f.data) > 0]
    if not out:
        return None
    if modal_len is not None:
        same = [f for f in out if len(f.data) == modal_len]
        informative = [f for f in same if bytes(f.data) not in boilerplate]
        if informative:
            return informative[-1]
        if same:
            return same[-1]
    return out[-1]


def pair(
    raw: list[tuple[SweepStep, list[CaptureFrame]]],
    led_count: int,
    *,
    device_name: str = "unknown",
    vid: Optional[int] = None,
    pid: Optional[int] = None,
    chunked: object = "auto",
    channel: Optional[int] = None,
) -> Corpus:
    """Build a labeled Corpus from per-step captured frames.

    With ``chunked`` truthy ("auto" by default), detect a chunked/streamed protocol across the
    capture and, if found, reassemble each step's chunks into a full per-channel buffer before
    pairing (so a device like ASUS Aura, whose one state spans many packets, decodes correctly).
    Otherwise fall back to single-packet pairing.
    """
    if chunked:
        framing = _detect_framing(raw)
        if framing is not None:
            return _pair_chunked(raw, framing, led_count,
                                 device_name=device_name, vid=vid, pid=pid, channel=channel)
    return _pair_single(raw, led_count, device_name=device_name, vid=vid, pid=pid)


def _pair_single(
    raw: list[tuple[SweepStep, list[CaptureFrame]]],
    led_count: int,
    *,
    device_name: str,
    vid: Optional[int],
    pid: Optional[int],
) -> Corpus:
    lengths: Counter[int] = Counter()
    for _step, frames in raw:
        for f in frames:
            if f.direction == "out" and len(f.data) > 0:
                lengths[len(f.data)] += 1
    modal_len = lengths.most_common(1)[0][0] if lengths else None
    boilerplate = _boilerplate(raw, modal_len)

    labeled: list[LabeledFrame] = []
    for step, frames in raw:
        rep = _representative(frames, modal_len, boilerplate)
        if rep is not None:
            labeled.append(LabeledFrame(step=step, frame=rep))
    return Corpus(frames=labeled, led_count=led_count, device_name=device_name, vid=vid, pid=pid)


def _boilerplate(
    raw: list[tuple[SweepStep, list[CaptureFrame]]],
    modal_len: Optional[int],
    threshold: float = 0.9,
) -> frozenset[bytes]:
    """Byte patterns a host emits identically in nearly every step.

    Pairing exists to correlate captured bytes with the state that produced them, so a
    packet that is byte-identical across the whole sweep cannot be the one carrying the
    state -- it is an apply, a keepalive, or a write to a zone with nothing in it.
    Identifying them lets :func:`_representative` skip past to the packet that varies.

    Needs at least three steps to tell "constant" from "we only have two samples".
    """
    if len(raw) < 3:
        return frozenset()
    seen: Counter[bytes] = Counter()
    for _step, frames in raw:
        unique = {bytes(f.data) for f in frames
                  if f.direction == "out" and (modal_len is None or len(f.data) == modal_len)}
        seen.update(unique)
    cutoff = len(raw) * threshold
    return frozenset(data for data, n in seen.items() if n >= cutoff)


def _detect_framing(raw: list[tuple[SweepStep, list[CaptureFrame]]]) -> Optional[ChunkFraming]:
    all_frames = [f for _step, frames in raw for f in frames]
    return infer_framing(dominant_command_class(all_frames))


def _pick_channel(per_step: list[tuple[SweepStep, dict[int, bytes]]]) -> Optional[int]:
    """Choose the channel carrying LED data: the one that varies most across steps (responds to
    the stimulus), tie-broken by buffer size; tiny control/commit channels are excluded."""
    bufs: dict[int, list[bytes]] = {}
    for _step, chans in per_step:
        for ch, buf in chans.items():
            bufs.setdefault(ch, []).append(buf)
    cands = {ch: v for ch, v in bufs.items() if max(len(b) for b in v) >= 6}
    if not cands:
        return None
    return max(cands, key=lambda ch: (len({b.hex() for b in cands[ch]}),
                                      max(len(b) for b in cands[ch]), -ch))


def _pair_chunked(
    raw: list[tuple[SweepStep, list[CaptureFrame]]],
    framing: ChunkFraming,
    led_count: int,
    *,
    device_name: str,
    vid: Optional[int],
    pid: Optional[int],
    channel: Optional[int],
) -> Corpus:
    per_step = [(step, reassemble(frames, framing)) for step, frames in raw]
    target = channel if channel is not None else _pick_channel(per_step)
    labeled: list[LabeledFrame] = []
    if target is not None:
        for step, chans in per_step:
            buf = chans.get(target)
            if buf:
                meta = {"chunking": _chunking_meta(framing, raw, target)}
                transfer = _chunk_transport(raw)
                frame = CaptureFrame(
                    data=buf,
                    source="reassembled",
                    transfer=transfer,
                    direction="out",
                    meta=meta,
                )
                labeled.append(LabeledFrame(step=step, frame=frame))

    # ``led_count`` is what the operator says the *device* has, but a chunked capture is
    # paired down to a single wire channel, which may carry only some of them: an Aura
    # board splits 58 LEDs across channels of 48, 8 and 2. Keeping the device-wide count
    # here describes a buffer far larger than the one paired, and the decoder then builds
    # a spec that writes past the end of its own packet.
    channel_leds = max((len(lf.frame.data) for lf in labeled), default=0) // 3
    if channel_leds:
        led_count = min(led_count, channel_leds)
        labeled = _align_colors(labeled, channel_leds)
    return Corpus(frames=labeled, led_count=led_count, device_name=device_name, vid=vid, pid=pid)


def _align_colors(labeled: list[LabeledFrame], channel_leds: int) -> list[LabeledFrame]:
    """Relabel each step with the slice of the colour vector this channel actually drives.

    A host addresses one logical strip, but the device splits it across wire channels, and
    a channel need not start at logical LED 0 -- OpenRGB lists an Aura board's 2 mainboard
    LEDs before its 48-LED header, so that header carries colours [2:50]. Labelling it with
    [0:48] misaligns every per-LED step, and the decode fails in a way that reads like a
    protocol mismatch rather than an indexing one.

    The offset is found by which LEDs are *lit*: that signal survives whatever channel order
    and scaling the wire uses, so it can be resolved before any of those are known.
    """
    widest = max((len(lf.step.colors) for lf in labeled), default=0)
    if widest <= channel_leds:
        return labeled

    def lit_in_buffer(buf: bytes) -> set[int]:
        return {i for i in range(channel_leds) if any(buf[i * 3:i * 3 + 3])}

    best_offset, best_score = 0, -1
    for offset in range(widest - channel_leds + 1):
        score = 0
        for lf in labeled:
            window = lf.step.colors[offset:offset + channel_leds]
            lit_colors = {i for i, c in enumerate(window) if any(c)}
            if lit_colors == lit_in_buffer(lf.frame.data):
                score += 1
        if score > best_score:
            best_offset, best_score = offset, score

    if best_offset == 0:
        return labeled
    return [
        LabeledFrame(
            step=replace(lf.step, colors=lf.step.colors[best_offset:best_offset + channel_leds]),
            frame=lf.frame,
        )
        for lf in labeled
    ]


def _chunking_meta(
    framing: ChunkFraming,
    raw: list[tuple[SweepStep, list[CaptureFrame]]],
    channel: int,
) -> dict:
    packet_len = 0
    for _step, frames in raw:
        for f in frames:
            if framing.matches(f.data):
                packet_len = len(f.data)
                break
        if packet_len:
            break
    return {
        "packet_len": packet_len,
        "prefix": list(framing.prefix),
        "channel": channel,
        "channel_pos": framing.channel_pos,
        "channel_mask": framing.channel_mask,
        "final_flag": framing.final_flag,
        "offset_pos": framing.offset_pos,
        "count_pos": framing.count_pos,
        "payload_start": framing.payload_start,
        "unit": framing.unit,
        "chunk_count": framing.chunk_count,
    }


def _chunk_transport(raw: list[tuple[SweepStep, list[CaptureFrame]]]) -> str:
    transfers: Counter[str] = Counter()
    for _step, frames in raw:
        for f in frames:
            if f.direction != "out" or not f.data:
                continue
            if f.transfer:
                transfers[f.transfer] += 1
    return transfers.most_common(1)[0][0] if transfers else "output"


def _setup_driver(driver: StimulusDriver, led_count: int, total_steps: int) -> None:
    """Call ``driver.setup``, passing the step total only if the driver accepts it.

    ``total_steps`` was added so operator-facing drivers can show progress. Probing the
    signature keeps drivers written against the older one working, rather than failing
    with a confusing TypeError raised from inside the orchestrator.
    """
    try:
        accepts = "total_steps" in inspect.signature(driver.setup).parameters
    except (TypeError, ValueError):  # C-implemented or otherwise un-introspectable
        accepts = False
    if accepts:
        driver.setup(led_count, total_steps=total_steps)
    else:
        driver.setup(led_count)


def run_sweep(
    backend,
    driver: StimulusDriver,
    led_count: int,
    *,
    steps: Optional[list[SweepStep]] = None,
    settle: float = 0.2,
    quiet: float = 0.3,
    poll: float = 0.02,
    max_wait: float = 3.0,
    device_name: str = "unknown",
    vid: Optional[int] = None,
    pid: Optional[int] = None,
    chunked: object = "auto",
    channel: Optional[int] = None,
    log: Optional[Callable[[str], None]] = None,
    profile: str = matrix.FULL,
    checkpoint: Optional[Callable[[Corpus], None]] = None,
) -> tuple[Corpus, list[tuple[SweepStep, list[CaptureFrame]]]]:
    """Run the sweep and return ``(corpus, raw_per_step_frames)``.

    ``raw`` is kept so a caller can inspect/persist everything captured, not just the one
    representative frame per step that ends up in the corpus. ``chunked``/``channel`` control
    chunked-protocol reassembly (see :func:`pair`).

    A manual sweep is a long, uninterruptible-feeling session, so partial work is never
    thrown away: ``checkpoint`` is called with the corpus-so-far after every step, and
    stopping early -- Ctrl-C, or ``q`` at the prompt -- still returns everything captured
    up to that point rather than raising past the caller's save.
    """
    steps = steps if steps is not None else matrix.generate(led_count, profile=profile)
    raw: list[tuple[SweepStep, list[CaptureFrame]]] = []

    def build() -> Corpus:
        return pair(raw, led_count, device_name=device_name, vid=vid, pid=pid,
                    chunked=chunked, channel=channel)

    driver_started = False
    backend_started = False
    try:
        # Open the capture backend *before* engaging the driver. Under the manual driver
        # setup prints "start setting states" to a human, and it is worth failing loudly
        # first rather than walking someone into a session that cannot record anything.
        backend.open()
        backend_started = True
        _setup_driver(driver, led_count, len(steps))
        driver_started = True
        for step in steps:
            backend.drain()  # drop frames buffered before this step's state was applied
            applied = driver.set_state(step)
            if not applied:
                continue
            frames = collect_until_quiet(
                backend, settle=settle, quiet=quiet, poll=poll, max_wait=max_wait
            )
            raw.append((step, frames))
            if log:
                log(f"step {step.step_id} ({step.describe()}): {len(frames)} frame(s)")
            if checkpoint is not None:
                checkpoint(build())
    except (KeyboardInterrupt, SweepAborted):
        if log:
            log(f"stopped early -- keeping the {len(raw)} step(s) already captured")
    finally:
        if backend_started:
            backend.close()
        if driver_started:
            driver.teardown()

    return build(), raw
