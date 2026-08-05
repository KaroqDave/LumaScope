"""Find the RGB device and the process that drives it.

The hardest step in reversing a device is the first one: *which* USB device is the
lighting controller, what is its VID:PID, and which process writes to it? Answering that
by hand means Device Manager, a registry spelunk, and Task Manager. This module answers
it in one command.

Enumeration is pure ``ctypes`` over the Windows HID stack (no dependencies): SetupAPI
lists the HID interfaces, and each device path already encodes VID/PID, so identification
works even while the vendor app holds the device open. Product strings are read too when
the handle can be opened non-exclusively.

Nothing here writes to a device or opens one for I/O -- it is strictly a read-only survey.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Optional

# USB vendor ids seen on RGB controllers. A hint for ranking candidates, not an authority.
VENDORS = {
    0x0B05: "ASUS",
    0x1532: "Razer",
    0x1B1C: "Corsair",
    0x046D: "Logitech",
    0x1462: "MSI",
    0x1E71: "NZXT",
    0x1038: "SteelSeries",
    0x2516: "Cooler Master",
    0x1E7D: "ROCCAT",
    0x3842: "EVGA",
    0x0951: "Kingston / HyperX",
    0x1044: "Gigabyte / Aorus",
    0x264A: "Thermaltake",
    0x0C45: "Sonix (OEM keyboards)",
}

# Processes known to drive vendor lighting. Matching one tells you what to attach to.
VENDOR_PROCESSES = {
    "armourycrate.service.exe": "ASUS Armoury Crate service",
    "armourycrate.usersessionhelper.exe": "ASUS Armoury Crate helper",
    "lightingservice.exe": "ASUS Aura lighting service",
    "asusservice.exe": "ASUS service",
    "razer synapse service.exe": "Razer Synapse service",
    "rzsdkservice.exe": "Razer SDK service",
    "icue.exe": "Corsair iCUE",
    "corsair.service.exe": "Corsair service",
    "msi center.exe": "MSI Center",
    "lightkeeperservice.exe": "MSI Mystic Light service",
    "nzxt cam.exe": "NZXT CAM",
    "lghub_agent.exe": "Logitech G HUB agent",
    "signalrgb.exe": "SignalRGB",
    # Closing the SignalRGB window leaves this service running, and it keeps the device.
    # Matching only the GUI let `replay --write` proceed while lighting was still driven.
    "signalrgbservice.exe": "SignalRGB background service",
    "openrgb.exe": "OpenRGB",
    "steelseriesengine.exe": "SteelSeries Engine",
}

_PATH_IDS = re.compile(r"vid_([0-9a-f]{4})&pid_([0-9a-f]{4})", re.IGNORECASE)

# Word boundaries matter: "led" must not match "Bundled".
_LIGHT_WORDS = re.compile(r"\b(rgb|aura|led|chroma|lighting|mystic|glow|illumination)\b", re.I)


@dataclass
class DeviceInfo:
    """One HID interface present on the machine."""

    path: str
    vid: Optional[int] = None
    pid: Optional[int] = None
    product: str = ""
    manufacturer: str = ""

    @property
    def vendor_name(self) -> str:
        return VENDORS.get(self.vid or -1, "")

    @property
    def label(self) -> str:
        name = self.product or self.manufacturer or ""
        if not name:
            name = self.vendor_name or "unknown device"
        return name

    @property
    def ids(self) -> str:
        if self.vid is None or self.pid is None:
            return "????:????"
        return f"{self.vid:04x}:{self.pid:04x}"

    @property
    def score(self) -> int:
        """How likely this is to be the lighting controller.

        A name that says "AURA LED Controller" is far stronger evidence than merely
        sharing a vendor id with a mouse, so naming outweighs the VID hint.
        """
        s = 0
        if _LIGHT_WORDS.search(f"{self.product} {self.manufacturer}"):
            s += 4
        if self.vid in VENDORS:
            s += 2
        if self.product:
            s += 1
        return s

    def interesting(self) -> bool:
        """Whether this looks like a lighting controller worth trying first."""
        return self.score >= 2


# --------------------------------------------------------------------------- #
# Windows HID enumeration
# --------------------------------------------------------------------------- #
def _enumerate_windows() -> list[DeviceInfo]:
    import ctypes
    from ctypes import wintypes

    setupapi = ctypes.windll.setupapi
    hid = ctypes.windll.hid
    kernel32 = ctypes.windll.kernel32

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                    ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]

    class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("InterfaceClassGuid", GUID),
                    ("Flags", wintypes.DWORD), ("Reserved", ctypes.POINTER(ctypes.c_ulong))]

    class HIDD_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Size", ctypes.c_ulong), ("VendorID", ctypes.c_ushort),
                    ("ProductID", ctypes.c_ushort), ("VersionNumber", ctypes.c_ushort)]

    DIGCF_PRESENT, DIGCF_DEVICEINTERFACE = 0x02, 0x10
    INVALID_HANDLE = ctypes.c_void_p(-1).value
    FILE_SHARE_RW, OPEN_EXISTING = 0x3, 3

    guid = GUID()
    hid.HidD_GetHidGuid(ctypes.byref(guid))

    # Every handle must be declared c_void_p. Without argtypes ctypes assumes a 32-bit
    # int and silently truncates 64-bit handles, which fails as "int too long to convert".
    setupapi.SetupDiGetClassDevsW.restype = ctypes.c_void_p
    setupapi.SetupDiGetClassDevsW.argtypes = [ctypes.POINTER(GUID), wintypes.LPCWSTR,
                                              wintypes.HWND, wintypes.DWORD]
    setupapi.SetupDiEnumDeviceInterfaces.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(GUID), wintypes.DWORD,
        ctypes.POINTER(SP_DEVICE_INTERFACE_DATA)]
    setupapi.SetupDiEnumDeviceInterfaces.restype = wintypes.BOOL
    setupapi.SetupDiGetDeviceInterfaceDetailW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(SP_DEVICE_INTERFACE_DATA), ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    setupapi.SetupDiGetDeviceInterfaceDetailW.restype = wintypes.BOOL
    setupapi.SetupDiDestroyDeviceInfoList.argtypes = [ctypes.c_void_p]
    hid.HidD_GetAttributes.argtypes = [ctypes.c_void_p, ctypes.POINTER(HIDD_ATTRIBUTES)]
    hid.HidD_GetProductString.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
    hid.HidD_GetManufacturerString.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                     ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                     wintypes.HANDLE]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]

    dev_info = setupapi.SetupDiGetClassDevsW(
        ctypes.byref(guid), None, None, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE)
    if not dev_info or dev_info == INVALID_HANDLE:
        return []

    # The detail struct's declared size is 6 on 32-bit and 8 on 64-bit; the path always
    # begins at byte 4 of the returned buffer.
    detail_size = 6 if ctypes.sizeof(ctypes.c_void_p) == 4 else 8

    out: list[DeviceInfo] = []
    try:
        index = 0
        while True:
            iface = SP_DEVICE_INTERFACE_DATA()
            iface.cbSize = ctypes.sizeof(SP_DEVICE_INTERFACE_DATA)
            if not setupapi.SetupDiEnumDeviceInterfaces(
                    dev_info, None, ctypes.byref(guid), index, ctypes.byref(iface)):
                break
            index += 1

            needed = wintypes.DWORD(0)
            setupapi.SetupDiGetDeviceInterfaceDetailW(
                dev_info, ctypes.byref(iface), None, 0, ctypes.byref(needed), None)
            if not needed.value:
                continue
            buf = ctypes.create_string_buffer(needed.value)
            ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD))[0] = detail_size
            if not setupapi.SetupDiGetDeviceInterfaceDetailW(
                    dev_info, ctypes.byref(iface), buf, needed.value, None, None):
                continue
            path = ctypes.wstring_at(ctypes.addressof(buf) + 4)

            info = DeviceInfo(path=path)
            m = _PATH_IDS.search(path)
            if m:
                info.vid, info.pid = int(m.group(1), 16), int(m.group(2), 16)

            # Access mode 0 asks for metadata only, so this succeeds even when the
            # vendor service holds the device open for I/O.
            handle = kernel32.CreateFileW(path, 0, FILE_SHARE_RW, None, OPEN_EXISTING, 0, None)
            if handle and handle != INVALID_HANDLE:
                try:
                    attrs = HIDD_ATTRIBUTES()
                    attrs.Size = ctypes.sizeof(HIDD_ATTRIBUTES)
                    if hid.HidD_GetAttributes(handle, ctypes.byref(attrs)):
                        info.vid = info.vid if info.vid is not None else attrs.VendorID
                        info.pid = info.pid if info.pid is not None else attrs.ProductID
                    sbuf = ctypes.create_unicode_buffer(256)
                    if hid.HidD_GetProductString(handle, sbuf, ctypes.sizeof(sbuf)):
                        info.product = sbuf.value.strip()
                    if hid.HidD_GetManufacturerString(handle, sbuf, ctypes.sizeof(sbuf)):
                        info.manufacturer = sbuf.value.strip()
                finally:
                    kernel32.CloseHandle(handle)
            out.append(info)
    finally:
        setupapi.SetupDiDestroyDeviceInfoList(dev_info)
    return out


def list_devices() -> list[DeviceInfo]:
    """Every HID interface present, most interesting first. Empty off Windows."""
    if sys.platform != "win32":
        return []
    try:
        devices = _enumerate_windows()
    except Exception:
        return []
    devices.sort(key=lambda d: (-d.score, d.ids, d.path))
    return devices


def dedupe(devices: list[DeviceInfo]) -> list[DeviceInfo]:
    """Collapse the several HID interfaces a single physical device exposes,
    keeping the most descriptive one."""
    seen: dict[tuple[Optional[int], Optional[int]], DeviceInfo] = {}
    for d in devices:
        key = (d.vid, d.pid)
        best = seen.get(key)
        if best is None or (d.score, len(d.product)) > (best.score, len(best.product)):
            seen[key] = d
    return sorted(seen.values(), key=lambda d: (-d.score, d.ids))


# --------------------------------------------------------------------------- #
# Processes
# --------------------------------------------------------------------------- #
def running_processes() -> list[str]:
    """Names of running processes (lowercase). Empty if they cannot be listed."""
    try:
        if sys.platform == "win32":
            raw = subprocess.run(["tasklist", "/fo", "csv", "/nh"],
                                 capture_output=True, text=True, timeout=15).stdout
            return [line.split('","')[0].lstrip('"').lower()
                    for line in raw.splitlines() if line.strip()]
        raw = subprocess.run(["ps", "-eo", "comm"],
                             capture_output=True, text=True, timeout=15).stdout
        return [line.strip().lower() for line in raw.splitlines()[1:] if line.strip()]
    except Exception:
        return []


def vendor_processes() -> list[tuple[str, str]]:
    """Running processes known to drive vendor lighting, as ``(process, description)``."""
    running = set(running_processes())
    return [(name, desc) for name, desc in VENDOR_PROCESSES.items() if name in running]


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
def report(*, all_devices: bool = False) -> str:
    """The human-facing ``lumascope devices`` output."""
    lines = ["LumaScope devices", "=" * 17, ""]

    if sys.platform != "win32":
        lines += [
            "  Live device enumeration is Windows-only (it reads the Windows HID stack).",
            "",
            "  On Linux/macOS, list USB devices with `lsusb` (Linux) or",
            "  `system_profiler SPUSBDataType` (macOS) and note the VID:PID you care about.",
            "  The decode half of LumaScope runs fine here on captures taken elsewhere.",
        ]
        return "\n".join(lines)

    devices = list_devices()
    if not devices:
        lines += ["  No HID devices found (or enumeration failed).", ""]
    else:
        shown = devices if all_devices else dedupe([d for d in devices if d.interesting()])
        if not shown:
            shown = dedupe(devices)[:10]
            lines.append("  No obvious RGB controller. Showing what is present:")
            lines.append("")
        else:
            lines.append("  Likely lighting controllers (--all shows every HID device):")
            lines.append("")
        width = max((len(d.label) for d in shown), default=10)
        for i, d in enumerate(shown, 1):
            vendor = f"  [{d.vendor_name}]" if d.vendor_name else ""
            lines.append(f"  {i:>2}. {d.ids}  {d.label.ljust(width)}{vendor}")
        lines.append("")
        top = shown[0]
        if top.vid is not None and top.pid is not None:
            lines += [
                "  To capture from the first device, run the vendor app, then:",
                f"    lumascope capture --backend usbpcap --vid 0x{top.vid:04x} "
                f"--pid 0x{top.pid:04x} \\",
                "        --duration 20 --out capture.frames.jsonl",
                "",
                "  Device path for `replay --device-path` (quote it):",
                f"    {top.path}",
                "",
            ]

    procs = vendor_processes()
    lines.append("  Vendor lighting processes running now:")
    if procs:
        for name, desc in procs:
            lines.append(f"    [+] {name.ljust(36)} {desc}")
        lines += [
            "",
            f"    Frida can hook it directly:  lumascope capture --attach {procs[0][0]} \\",
            "        --duration 20 --out capture.frames.jsonl",
        ]
    else:
        lines += [
            "    none detected -- start the vendor app (Armoury Crate, iCUE, Synapse, ...)",
            "    before capturing, or use the USBPcap backend to sniff the bus instead.",
        ]
    return "\n".join(lines)
