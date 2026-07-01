"""Replay a decoded :class:`ProtocolSpec` to verify it on the real device.

This closes the RE loop: capture -> decode -> emit gives you a spec; replay *proves* it by
driving the device with packets the spec generates (via the reference :mod:`~lumascope.codec`)
and letting you see whether the LEDs show the expected colors.

SAFETY (non-negotiable): replay performs device **writes**, so it is opt-in and dry-run by
default. A real write requires explicit confirmation, and the vendor app/service MUST be
closed first — it holds an exclusive device handle, and concurrent access is exactly the
condition that has bricked boards. We only ever replay packets the spec itself produces;
we never probe addresses or guess.

The packet *generation* is fully verifiable offline (a spec decoded from captures replays
byte-identically to its ground truth); the device write needs your hardware.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import codec
from .model import Color, ProtocolSpec


@dataclass
class ReplayStep:
    label: str
    colors: list[Color]
    data: bytes
    packets: list[bytes] = field(default_factory=list)


def build_replay_sequence(spec: ProtocolSpec, *, brightness: int = 255, walk: bool = True) -> list[ReplayStep]:
    """A visual verification pattern: solid R/G/B/white, then one-LED-at-a-time white walk.

    All values are 0 or 255, so the pattern is unambiguous to the eye and independent of the
    recovered scaling curve.
    """
    n = max(spec.leds.count, 1)
    patterns: list[tuple[str, list[Color]]] = [
        ("all red", [(255, 0, 0)] * n),
        ("all green", [(0, 255, 0)] * n),
        ("all blue", [(0, 0, 255)] * n),
        ("all white", [(255, 255, 255)] * n),
        ("all off", [(0, 0, 0)] * n),
    ]
    if walk:
        for i in range(n):
            colors = [(0, 0, 0)] * n
            colors[i] = (255, 255, 255)
            patterns.append((f"walk LED {i}", colors))

    return [
        _replay_step(spec, label, colors, brightness=brightness)
        for label, colors in patterns
    ]


def _replay_step(spec: ProtocolSpec, label: str, colors: list[Color], *, brightness: int) -> ReplayStep:
    packets = codec.encode_packets(spec, colors, brightness=brightness)
    data = packets[0] if len(packets) == 1 else b"".join(packets)
    return ReplayStep(label=label, colors=colors, data=data, packets=packets)


class HidReplayWriter:
    """Write replay packets to an HID device via its captured device path (ctypes; Windows).

    The path comes from the capture corpus (``CaptureFrame.path``) or ``--device-path``. Opens
    only on an explicit, confirmed write — never during dry-run.
    """

    def __init__(self, spec: ProtocolSpec, device_path: str) -> None:
        self.spec = spec
        self.device_path = device_path
        self._h = None
        self._k = None

    def open(self) -> None:
        import ctypes
        import ctypes.wintypes as w

        self._k = ctypes.windll.kernel32
        GENERIC_WRITE, GENERIC_READ = 0x40000000, 0x80000000
        FILE_SHARE_RW, OPEN_EXISTING = 0x3, 3
        self._k.CreateFileW.restype = w.HANDLE
        self._k.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.c_void_p,
                                        w.DWORD, w.DWORD, w.HANDLE]
        h = self._k.CreateFileW(self.device_path, GENERIC_WRITE | GENERIC_READ,
                                FILE_SHARE_RW, None, OPEN_EXISTING, 0, None)
        if not h or h == ctypes.c_void_p(-1).value:
            raise OSError(f"could not open {self.device_path} - is the vendor app/service closed?")
        self._h = h

    def write(self, data: bytes) -> None:
        import ctypes
        import ctypes.wintypes as w

        if self.spec.transport == "hid_feature":
            ok = ctypes.windll.hid.HidD_SetFeature(self._h, data, len(data))
        elif self.spec.transport in ("hid_output", "hid_interrupt"):
            written = w.DWORD(0)
            ok = self._k.WriteFile(self._h, data, len(data), ctypes.byref(written), None)
            if ok and written.value != len(data):
                raise OSError(f"short device write ({written.value}/{len(data)} bytes)")
        else:
            raise RuntimeError(f"replay does not support transport {self.spec.transport!r}")
        if not ok:
            raise OSError(f"device write failed (GetLastError={ctypes.get_last_error()})")

    def close(self) -> None:
        if self._h and self._k:
            try:
                self._k.CloseHandle(self._h)
            except Exception:
                pass
            self._h = None


def write_sequence(
    spec: ProtocolSpec,
    steps: list[ReplayStep],
    *,
    device_path: Optional[str] = None,
    confirm: bool = False,
    dry_run: bool = True,
    settle: float = 0.6,
    out: Callable[[str], None] = print,
) -> bool:
    """Replay ``steps``. Dry-run (default) only prints the packets; a real write requires
    ``dry_run=False`` AND ``confirm=True`` AND a device path. Returns True if writes happened.
    """
    if dry_run or not confirm:
        out("[dry-run] no device writes. Packets that WOULD be sent:")
        for s in steps:
            packets = s.packets or [s.data]
            suffix = f" ({len(packets)} chunks)" if len(packets) > 1 else ""
            out(f"  {s.label:14} {sum(len(p) for p in packets):3}B{suffix}")
            for packet in packets:
                out(f"      {len(packet):3}B  {packet.hex()}")
        out("Re-run with --write --yes (vendor app CLOSED) to send these to the device.")
        return False

    if not device_path:
        raise RuntimeError("replay needs a device path (from the capture corpus or --device-path)")

    writer = HidReplayWriter(spec, device_path)
    writer.open()
    out(f"writing {len(steps)} replay packet(s) to {device_path}")
    try:
        for s in steps:
            for packet in (s.packets or [s.data]):
                writer.write(packet)
            out(f"  sent {s.label}")
            time.sleep(settle)
    finally:
        writer.close()
    return True
