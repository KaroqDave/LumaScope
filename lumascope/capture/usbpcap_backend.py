"""USBPcap + tshark capture backend (Phase 3 fallback).

Used when Frida can't be injected (anti-tamper/packed vendor apps) or when ground-truth
*wire* bytes are wanted rather than the host-side buffer. USBPcap sniffs the USB bus from a
kernel filter driver (needs admin + a one-time install/reboot), tshark converts the pcap to
JSON, and :func:`parse_tshark_packets` turns that into :class:`CaptureFrame` s.

The parser is the verifiable core (tested against a saved fixture); the live-capture
orchestration needs USBPcap installed and is exercised on your machine, not in CI. Field
placement in tshark JSON varies by version, so extraction is deliberately field-tolerant:
the payload may surface as ``usbhid.data``, ``usb.capdata`` or ``usb.data_fragment``, nested
under a layer object or flat at the layers level.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from ..model import CaptureFrame
from .base import CaptureBackend

# Payload field names, in priority order (HID-decoded first, then raw capture data).
PAYLOAD_FIELDS = ("usbhid.data", "usb.capdata", "usb.data_fragment")

# Wireshark usb.transfer_type values.
_TRANSFER = {
    "0x00": "isochronous", "0": "isochronous",
    "0x01": "interrupt", "1": "interrupt",
    "0x02": "control", "2": "control",
    "0x03": "bulk", "3": "bulk",
}


def _flatten(obj, out: dict) -> None:
    """Collect every leaf ``field -> value`` in a nested tshark layers dict (first wins)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                _flatten(v, out)
            elif k not in out:
                out[k] = v
    elif isinstance(obj, list):
        for item in obj:
            _flatten(item, out)


def _hex_to_bytes(s: str) -> bytes:
    cleaned = str(s).replace(":", "").replace(" ", "").replace("\n", "")
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return b""


def _maybe_int(v) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(str(v), 0)
    except ValueError:
        return None


def parse_tshark_packets(data) -> list[CaptureFrame]:
    """Parse ``tshark -T json -x`` output (str/bytes or already-decoded list) into frames.

    Packets carrying no USB payload (descriptors, status, other devices) are skipped.
    """
    if isinstance(data, (str, bytes, bytearray)):
        packets = json.loads(data)
    else:
        packets = data

    frames: list[CaptureFrame] = []
    for pkt in packets:
        layers = (pkt.get("_source") or {}).get("layers") or {}
        flat: dict = {}
        _flatten(layers, flat)

        payload = next((flat[f] for f in PAYLOAD_FIELDS if flat.get(f)), None)
        if not payload:
            continue
        raw = _hex_to_bytes(payload)
        if not raw:
            continue

        direction = "out"
        d = flat.get("usb.endpoint_address.direction")
        if d is not None:
            direction = "in" if str(d) in ("1", "0x1") else "out"
        elif flat.get("usb.src") and str(flat.get("usb.src")).lower() != "host":
            direction = "in"

        endpoint = None
        ep = flat.get("usb.endpoint_address.number")
        if ep is None:
            ep = flat.get("usb.endpoint_address")
        ep_int = _maybe_int(ep)
        if ep_int is not None:
            endpoint = ep_int & 0x7F

        transfer = _TRANSFER.get(str(flat.get("usb.transfer_type", "")).lower(), "")

        frames.append(CaptureFrame(
            data=raw,
            timestamp_ns=_frame_time_ns(flat),
            source="usbpcap",
            api="usbpcap",
            direction=direction,
            transfer=transfer,
            endpoint=endpoint,
            vid=_maybe_int(flat.get("usb.idVendor")),
            pid=_maybe_int(flat.get("usb.idProduct")),
            meta={"transfer_type": flat.get("usb.transfer_type")},
        ))
    return frames


def _seconds_to_ns(v) -> Optional[int]:
    """Float seconds -> integer ns. Returns None for missing/non-float values (e.g. some tshark
    builds render ``frame.time_epoch`` as an ISO-8601 string rather than epoch seconds)."""
    if v is None:
        return None
    try:
        return int(round(float(v) * 1_000_000_000))
    except (ValueError, TypeError):
        return None


def _frame_time_ns(flat: dict) -> int:
    """Capture timestamp in nanoseconds.

    Timing is the only signal for streamed-effect *rate* (a software-rendered animation carries
    no speed byte — speed shows up as how fast frames advance), so preserve it. Prefers
    ``frame.time_relative`` (float seconds since capture start — robust across tshark versions and
    all that rate analysis needs); falls back to an absolute ``frame.time_epoch`` when that build
    emits it as float epoch seconds. 0 when neither is usable.
    """
    ns = _seconds_to_ns(flat.get("frame.time_relative"))
    if ns is not None:
        return ns
    ns = _seconds_to_ns(flat.get("frame.time_epoch"))
    return ns if ns is not None else 0


def find_usbpcapcmd() -> Optional[str]:
    found = shutil.which("USBPcapCMD")
    if found:
        return found
    candidate = Path(r"C:\Program Files\USBPcap\USBPcapCMD.exe")
    return str(candidate) if candidate.exists() else None


def find_tshark() -> Optional[str]:
    found = shutil.which("tshark")
    if found:
        return found
    for c in (r"C:\Program Files\Wireshark\tshark.exe", r"C:\Program Files (x86)\Wireshark\tshark.exe"):
        if os.path.exists(c):
            return c
    return None


def run_tshark(pcap_path: str, tshark: Optional[str] = None) -> list[CaptureFrame]:
    """Convert a saved pcap to frames via ``tshark -r <pcap> -T json -x``."""
    exe = tshark or find_tshark()
    if not exe:
        raise RuntimeError("tshark not found (install Wireshark, or add it to PATH)")
    out = subprocess.run(
        [exe, "-r", pcap_path, "-T", "json", "-x"],
        capture_output=True, text=True, check=True,
    )
    return parse_tshark_packets(out.stdout or "[]")


class UsbpcapBackend(CaptureBackend):
    """Capture USB traffic via USBPcap, or parse an existing pcap offline.

    Live mode (``pcap=None``): spawn ``USBPcapCMD -d <interface> -o <tmp.pcap>`` for the
    capture window, then convert with tshark on close. Offline mode (``pcap=<path>``):
    open/close do nothing live; close parses the given pcap. Live mode needs admin and a
    USBPcap install; the orchestrator's per-step ``drain`` is not supported (USBPcap yields
    frames only after the window closes) — use Frida for sweeps, USBPcap for one-shot capture.
    """

    name = "usbpcap"

    def __init__(
        self,
        *,
        interface: str = r"\\.\USBPcap1",
        address: Optional[int] = None,
        pcap: Optional[str] = None,
        usbpcapcmd: Optional[str] = None,
        tshark: Optional[str] = None,
        keep_pcap: bool = False,
    ) -> None:
        super().__init__()
        self.interface = interface
        self.address = address
        self.pcap = pcap
        self.usbpcapcmd = usbpcapcmd
        self.tshark = tshark
        self.keep_pcap = keep_pcap
        self.logs: list[tuple[str, object]] = []
        self._proc = None
        self._tmp_pcap: Optional[str] = None

    def open(self) -> None:
        if self.pcap is not None:
            return  # offline: nothing to start
        exe = self.usbpcapcmd or find_usbpcapcmd()
        if not exe:
            raise RuntimeError("USBPcapCMD not found (install from https://desowin.org/usbpcap/)")
        self._tmp_pcap = tempfile.mktemp(suffix=".pcap")
        cmd = [exe, "-d", self.interface, "-o", self._tmp_pcap]
        if self.address is not None:
            cmd += ["--devices", str(self.address)]
        else:
            # Without a device selection USBPcap monitors no devices and yields an empty
            # capture; -A captures from all devices on the filter (we narrow later in analysis).
            cmd += ["-A"]
        self._proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def close(self) -> None:
        pcap_path = self.pcap
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None
            pcap_path = self._tmp_pcap

        if pcap_path and os.path.exists(pcap_path):
            try:
                for frame in run_tshark(pcap_path, tshark=self.tshark):
                    self._push(frame)
            except Exception as exc:
                self.logs.append(("error", str(exc)))
            finally:
                if self._tmp_pcap and not self.keep_pcap and os.path.exists(self._tmp_pcap):
                    try:
                        os.remove(self._tmp_pcap)
                    except OSError:
                        pass
