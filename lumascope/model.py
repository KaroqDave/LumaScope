"""Core data model shared across capture, stimulus, decode, and emit.

Three families of types:

* **Capture** — what a backend records: :class:`CaptureFrame`.
* **Stimulus** — what we told the device to do: :class:`SweepStep`, and the pairing
  :class:`LabeledFrame` / :class:`Corpus` that the decode engine consumes.
* **Protocol spec** — what the decoder produces and the emitter consumes:
  :class:`ProtocolSpec` and its parts.

Everything is plain ``dataclasses`` so it round-trips cleanly to/from JSON
(:mod:`lumascope.emit.spec_json`) and is trivial to construct in tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

Color = tuple[int, int, int]  # logical (R, G, B), each 0..255

# Logical channel order. Stimulus always speaks logical RGB; the *wire* order
# (which the decoder recovers) may be GRB, BRG, etc.
LOGICAL_CHANNELS = ("R", "G", "B")


def logical_index(channel: str) -> int:
    """Index of a logical channel letter in an (R, G, B) tuple."""
    return LOGICAL_CHANNELS.index(channel.upper())


# --------------------------------------------------------------------------- #
# Capture
# --------------------------------------------------------------------------- #
@dataclass
class CaptureFrame:
    """One captured packet/transaction, normalized across all capture backends."""

    data: bytes
    timestamp_ns: int = 0
    source: str = ""          # "frida" | "usbpcap" | "smbus" | "synthetic"
    api: str = ""             # "HidD_SetFeature" | "WriteFile" | "WinUsb_WritePipe" | ...
    direction: str = "out"    # "out" (host->device) | "in"
    transfer: str = ""        # "feature" | "output" | "interrupt" | "control" | "smbus"
    vid: Optional[int] = None
    pid: Optional[int] = None
    path: Optional[str] = None         # device path, e.g. \\?\HID#VID_1532&PID_...
    report_id: Optional[int] = None    # HID report id (byte 0 for feature/output), if known
    endpoint: Optional[int] = None
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def hex(self) -> str:
        return self.data.hex()

    def __len__(self) -> int:
        return len(self.data)


# --------------------------------------------------------------------------- #
# Stimulus
# --------------------------------------------------------------------------- #
# Sweep step kinds. The decode engine keys its passes off these.
KIND_PER_CHANNEL = "per_channel"   # one LED, one channel, swept 0..255
KIND_LED_WALK = "led_walk"         # exactly one LED lit (marker), walked across the strip
KIND_UNIFORM = "uniform"           # every LED set to the same color (whole-frame variety)
KIND_BRIGHTNESS = "brightness"     # color held constant, global brightness swept
KIND_MODE = "mode"                 # a named effect/mode selected
KIND_INIT = "init"                 # captured at startup / mode-enter (handshake packets)


@dataclass
class SweepStep:
    """The known target state for one stimulus step — the *label* for its capture.

    ``colors`` is the full per-LED logical-RGB target and is the ground truth the
    decoder correlates bytes against. The scalar fields (``led``/``channel``/``value``/
    ``brightness``) describe *what* is being swept so passes can group steps.
    """

    step_id: int
    kind: str
    colors: list[Color] = field(default_factory=list)
    led: Optional[int] = None
    channel: Optional[str] = None      # "R" | "G" | "B"
    value: Optional[int] = None        # the swept scalar, 0..255
    brightness: Optional[int] = None   # 0..255 logical
    mode: Optional[str] = None
    params: dict[str, Any] = field(default_factory=dict)

    def describe(self) -> str:
        if self.kind == KIND_PER_CHANNEL:
            return f"led{self.led}.{self.channel}={self.value}"
        if self.kind == KIND_LED_WALK:
            return f"walk led{self.led}"
        if self.kind == KIND_UNIFORM:
            return f"uniform={self.value}"
        if self.kind == KIND_BRIGHTNESS:
            return f"brightness={self.brightness}"
        if self.kind == KIND_MODE:
            return f"mode={self.mode}"
        return self.kind


@dataclass
class LabeledFrame:
    """A captured frame paired with the stimulus step that produced it."""

    step: SweepStep
    frame: CaptureFrame

    @property
    def data(self) -> bytes:
        return self.frame.data


@dataclass
class Corpus:
    """A labeled capture set the decode engine operates on.

    ``led_count`` is operator-known context (how many LEDs the device exposes) — for a
    real capture you configure it; the synthetic generator sets it from the spec.
    """

    frames: list[LabeledFrame] = field(default_factory=list)
    led_count: int = 0
    device_name: str = "unknown"
    vid: Optional[int] = None
    pid: Optional[int] = None

    def by_kind(self, kind: str) -> list[LabeledFrame]:
        return [lf for lf in self.frames if lf.step.kind == kind]

    def __len__(self) -> int:
        return len(self.frames)


# --------------------------------------------------------------------------- #
# Protocol spec (decoder output / emitter input)
# --------------------------------------------------------------------------- #
@dataclass
class Scaling:
    """How a logical 0..255 channel value maps to a wire byte."""

    type: str = "identity"     # "identity" | "linear" | "gamma"
    k: float = 1.0             # for linear:  byte = round(value * k)
    gamma: float = 1.0         # for gamma:   byte = round(255 * (value/255) ** gamma)


@dataclass
class LedLayout:
    count: int = 0
    layout: str = "interleaved"   # "interleaved" (RGBRGB..) | "planar" (RR..GG..BB..)
    base_offset: int = 0
    stride: int = 3
    channel_order: str = "RGB"    # wire order, e.g. "GRB"
    scaling: Scaling = field(default_factory=Scaling)
    # For non-uniform layouts (matrix keyboards), an explicit per-LED (r,g,b) offset
    # table overrides base/stride. None means "use base_offset + led*stride".
    explicit_offsets: Optional[list[tuple[int, int, int]]] = None


@dataclass
class HeaderField:
    constant_bytes: list[tuple[int, int]] = field(default_factory=list)  # (offset, value)
    command_offset: Optional[int] = None
    mode_offset: Optional[int] = None


@dataclass
class BrightnessField:
    present: bool = False
    offset: Optional[int] = None
    min: int = 0
    max: int = 255


@dataclass
class ChecksumModel:
    present: bool = False
    kind: str = "none"             # "none"|"sum8"|"xor8"|"twos8"|"onescomp8"|"sum16"|"crc"
    offset: Optional[int] = None   # where the checksum byte(s) live
    width: int = 1                 # bytes
    endian: str = "little"         # for width > 1
    range: Optional[tuple[int, int]] = None   # [start, end) of bytes covered
    params: dict[str, Any] = field(default_factory=dict)  # crc: poly/init/refin/refout/xorout


@dataclass
class ProtocolSpec:
    name: str = "unknown"
    transport: str = "hid_feature"   # hid_feature|hid_output|hid_interrupt|usb_control|smbus
    report_id: Optional[int] = None
    packet_len: int = 0
    header: HeaderField = field(default_factory=HeaderField)
    leds: LedLayout = field(default_factory=LedLayout)
    brightness: BrightnessField = field(default_factory=BrightnessField)
    checksum: ChecksumModel = field(default_factory=ChecksumModel)
    vid: Optional[int] = None
    pid: Optional[int] = None
    notes: list[str] = field(default_factory=list)
