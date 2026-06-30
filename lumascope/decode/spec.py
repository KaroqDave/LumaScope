"""Top-level decode: labeled corpus -> :class:`ProtocolSpec` (+ validation report)."""

from __future__ import annotations

from dataclasses import dataclass, field

from .. import codec
from ..model import (
    KIND_BRIGHTNESS,
    CaptureFrame,
    Corpus,
    HeaderField,
    ProtocolSpec,
)
from . import checksum as checksum_mod
from . import diff, encoding, stride

# Capture transfer kind -> spec transport string.
_TRANSPORT = {
    "feature": "hid_feature",
    "output": "hid_output",
    "interrupt": "hid_interrupt",
    "control": "usb_control",
    "smbus": "smbus",
}


@dataclass
class Validation:
    total: int = 0
    matched: int = 0
    failures: list[tuple[str, str, str]] = field(default_factory=list)  # (label, got, expected)

    @property
    def ok(self) -> bool:
        return self.total > 0 and self.matched == self.total

    def summary(self) -> str:
        status = "OK" if self.ok else "MISMATCH"
        return f"{status}: {self.matched}/{self.total} frames round-trip"


@dataclass
class DecodeResult:
    spec: ProtocolSpec
    validation: Validation


def _transport_from_frame(frame: CaptureFrame) -> str:
    return _TRANSPORT.get(frame.transfer, "hid_feature")


def decode(
    corpus: Corpus,
    *,
    name: str | None = None,
    vid: int | None = None,
    pid: int | None = None,
    validate: bool = True,
) -> DecodeResult:
    """Decode a labeled capture corpus into a protocol spec."""
    if not corpus.frames:
        raise ValueError("empty corpus")

    length = diff.modal_length(corpus.frames)
    frames = diff.of_length(corpus.frames, length)
    color_frames = [lf for lf in frames if lf.step.kind != KIND_BRIGHTNESS]

    f0 = color_frames[0].frame
    report_id = f0.report_id
    transport = _transport_from_frame(f0)

    # 1) Checksum — discover the column reproducible from the rest of the packet.
    cs = checksum_mod.detect(color_frames, length, has_report_id=report_id is not None)
    checksum_offsets = (
        set(range(cs.offset, cs.offset + cs.width)) if cs.present and cs.offset is not None else set()
    )

    # 2) Field localization — per-channel sweeps pin each (led, channel) offset + scaling.
    groups = diff.group_per_channel(color_frames)
    field_map, scaling = diff.localize_fields(groups, color_frames, checksum_offsets, length)

    # 3) Layout — base/stride/channel-order/interleaved-vs-planar.
    layout = stride.solve_layout(field_map, corpus.led_count, scaling)

    # 4) Brightness — a global brightness byte, if present.
    led_offsets = set(field_map.values())
    brightness = encoding.detect_brightness(corpus, length, led_offsets | checksum_offsets)

    # 5) Header constants — fixed nonzero bytes that aren't the report id or a data field.
    assigned = set(led_offsets) | checksum_offsets
    if brightness.present and brightness.offset is not None:
        assigned.add(brightness.offset)
    skip = {0} if report_id is not None else set()
    consts = diff.constant_offsets(color_frames, length)
    header_consts = sorted(
        (o, v) for o, v in consts.items() if o not in assigned and o not in skip and v != 0
    )
    header = HeaderField(constant_bytes=header_consts)

    spec = ProtocolSpec(
        name=name or corpus.device_name,
        transport=transport,
        report_id=report_id,
        packet_len=length,
        header=header,
        leds=layout,
        brightness=brightness,
        checksum=cs,
        vid=vid if vid is not None else corpus.vid,
        pid=pid if pid is not None else corpus.pid,
    )

    validation = _validate(spec, corpus) if validate else Validation()
    return DecodeResult(spec=spec, validation=validation)


def _validate(spec: ProtocolSpec, corpus: Corpus) -> Validation:
    """Re-encode every captured frame from the recovered spec and compare byte-for-byte."""
    v = Validation()
    for lf in corpus.frames:
        if len(lf.data) != spec.packet_len:
            continue
        v.total += 1
        brightness = lf.step.brightness if lf.step.kind == KIND_BRIGHTNESS else 255
        regenerated = codec.encode_frame(spec, lf.step.colors, brightness=brightness)
        if regenerated == lf.data:
            v.matched += 1
        elif len(v.failures) < 12:
            v.failures.append((lf.step.describe(), lf.data.hex(), regenerated.hex()))
    return v
