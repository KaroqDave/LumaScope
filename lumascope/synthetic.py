"""Fabricate labeled captures from a known :class:`ProtocolSpec` — no hardware needed.

This is what makes the decode engine testable: pick a ground-truth spec, run the sweep
matrix through the reference codec, and you get a :class:`Corpus` identical in shape to
what a real capture backend would emit. Feed it to :func:`lumascope.decode.spec.decode`
and assert the recovered spec matches the ground truth.

It also doubles as a noise model: pass ``decoy_frames`` to interleave unrelated traffic
(other USB devices, keep-alives) that the decoder must ignore — though for the core
round-trip tests we keep it clean.
"""

from __future__ import annotations

from . import codec
from .model import (
    KIND_BRIGHTNESS,
    CaptureFrame,
    Corpus,
    LabeledFrame,
    ProtocolSpec,
    SweepStep,
)
from .stimulus import matrix


def _transfer_for(spec: ProtocolSpec) -> str:
    return {
        "hid_feature": "feature",
        "hid_output": "output",
        "hid_interrupt": "interrupt",
        "usb_control": "control",
        "smbus": "smbus",
    }.get(spec.transport, "feature")


def frame_for_step(spec: ProtocolSpec, step: SweepStep, *, ts: int = 0) -> CaptureFrame:
    """Encode a single labeled step into a CaptureFrame using the reference codec."""
    brightness = step.brightness if step.kind == KIND_BRIGHTNESS else 255
    data = codec.encode_frame(spec, step.colors, brightness=brightness)
    return CaptureFrame(
        data=data,
        timestamp_ns=ts,
        source="synthetic",
        api="HidD_SetFeature",
        direction="out",
        transfer=_transfer_for(spec),
        vid=spec.vid,
        pid=spec.pid,
        report_id=spec.report_id,
    )


def generate_corpus(
    spec: ProtocolSpec,
    *,
    steps: list[SweepStep] | None = None,
    name: str | None = None,
) -> Corpus:
    """Generate a full labeled corpus for ``spec`` by running the sweep matrix."""
    if steps is None:
        steps = matrix.generate(spec.leds.count)
    labeled = [
        LabeledFrame(step=s, frame=frame_for_step(spec, s, ts=i * 10_000_000))
        for i, s in enumerate(steps)
    ]
    return Corpus(
        frames=labeled,
        led_count=spec.leds.count,
        device_name=name or spec.name,
        vid=spec.vid,
        pid=spec.pid,
    )
