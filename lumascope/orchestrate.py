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
from typing import Callable, Optional

from .decode.chunked import ChunkFraming, dominant_command_class, infer_framing, reassemble
from .model import CaptureFrame, Corpus, LabeledFrame, SweepStep
from .stimulus import matrix
from .stimulus.base import StimulusDriver
from .stimulus.manual import SweepAborted
from .stimulus.sync import collect_until_quiet


def _representative(frames: list[CaptureFrame], modal_len: Optional[int]) -> Optional[CaptureFrame]:
    """Pick the one frame that best represents a step: the last outbound write of the modal
    packet length (falls back to the last outbound write of any length)."""
    out = [f for f in frames if f.direction == "out" and len(f.data) > 0]
    if not out:
        return None
    if modal_len is not None:
        same = [f for f in out if len(f.data) == modal_len]
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

    labeled: list[LabeledFrame] = []
    for step, frames in raw:
        rep = _representative(frames, modal_len)
        if rep is not None:
            labeled.append(LabeledFrame(step=step, frame=rep))
    return Corpus(frames=labeled, led_count=led_count, device_name=device_name, vid=vid, pid=pid)


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
    return Corpus(frames=labeled, led_count=led_count, device_name=device_name, vid=vid, pid=pid)


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
