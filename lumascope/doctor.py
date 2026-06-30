"""Environment doctor: report what LumaScope can do on this machine right now.

Pure stdlib and side-effect-free — it only *reads* the environment. Each check is
classified ok / warn / missing so you can see at a glance which phases are runnable
(decode engine needs nothing; capture needs frida or USBPcap; etc.).
"""

from __future__ import annotations

import importlib.util
import shutil
import socket
import sys
from dataclasses import dataclass
from pathlib import Path

OK, WARN, MISSING = "ok", "warn", "missing"
_GLYPH = {OK: "[+]", WARN: "[~]", MISSING: "[-]"}


@dataclass
class Check:
    name: str
    status: str
    detail: str


def _module_version(mod: str) -> str | None:
    if importlib.util.find_spec(mod) is None:
        return None
    try:
        m = __import__(mod)
        return getattr(m, "__version__", "installed")
    except Exception as exc:  # importing a native ext can fail on a too-new Python
        return f"present but failed to import: {exc}"


def _is_admin() -> bool:
    if sys.platform != "win32":
        try:
            import os
            return os.geteuid() == 0  # type: ignore[attr-defined]
        except Exception:
            return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def _port_open(host: str, port: int, timeout: float = 0.3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _find_openrgb() -> str | None:
    found = shutil.which("OpenRGB") or shutil.which("openrgb")
    if found:
        return found
    candidates = [
        Path(r"C:\Program Files\OpenRGB\OpenRGB.exe"),
        Path(r"C:\Program Files (x86)\OpenRGB\OpenRGB.exe"),
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return None


def _usbpcap() -> str | None:
    found = shutil.which("USBPcapCMD")
    if found:
        return found
    c = Path(r"C:\Program Files\USBPcap\USBPcapCMD.exe")
    return str(c) if c.exists() else None


def _tshark() -> str | None:
    found = shutil.which("tshark")
    if found:
        return found
    for c in (Path(r"C:\Program Files\Wireshark\tshark.exe"),
              Path(r"C:\Program Files (x86)\Wireshark\tshark.exe")):
        if c.exists():
            return str(c)
    return None


def run_checks() -> list[Check]:
    checks: list[Check] = []

    # --- core (decode engine needs only this) ---
    py_ok = sys.version_info[:2] >= (3, 10)
    checks.append(Check(
        "Python", OK if py_ok else WARN,
        f"{sys.version.split()[0]} ({sys.executable})"
        + ("" if py_ok else "  -- 3.10+ recommended"),
    ))

    # --- capture: Frida (Phase 2) ---
    frida_v = _module_version("frida")
    checks.append(Check(
        "frida (USB/HID hook capture)",
        OK if frida_v and "failed" not in frida_v else MISSING,
        frida_v or "not installed  ->  pip install -e .[frida]  (native wheel; may lag newest Python)",
    ))

    # --- capture: USBPcap + tshark (Phase 3) ---
    tshark = _tshark()
    checks.append(Check(
        "tshark (Wireshark CLI)", OK if tshark else MISSING,
        tshark or "not found  ->  install Wireshark (or add it to PATH)",
    ))
    usbpcap = _usbpcap()
    checks.append(Check(
        "USBPcap", OK if usbpcap else MISSING,
        usbpcap or "not installed  ->  https://desowin.org/usbpcap/ (admin + reboot)",
    ))

    # --- stimulus (Phase 4) ---
    for mod, label in [
        ("openrgb", "openrgb-python (ground-truth driver)"),
        ("pywinauto", "pywinauto (GUI automation)"),
        ("requests", "requests (REST drivers)"),
        ("pyautogui", "pyautogui (image-match clicks)"),
        ("cv2", "opencv-python (template match)"),
    ]:
        v = _module_version(mod)
        checks.append(Check(label, OK if v and "failed" not in v else MISSING,
                            v or f"not installed  ->  pip install -e .[stimulus|image]"))

    openrgb_exe = _find_openrgb()
    server = _port_open("127.0.0.1", 6742)
    if openrgb_exe or server:
        detail = openrgb_exe or "found"
        detail += "  (SDK server UP on :6742)" if server else "  (SDK server not running)"
        checks.append(Check("OpenRGB app", OK if server else WARN, detail))
    else:
        checks.append(Check("OpenRGB app", MISSING,
                            "not found  ->  enables the end-to-end ground-truth loop"))

    # --- checksum escalation (optional) ---
    reveng = shutil.which("reveng")
    checks.append(Check("reveng (exotic CRC search)", OK if reveng else WARN,
                        reveng or "optional  ->  catalog covers common CRCs without it"))

    # --- privilege (needed for USBPcap / SMBus) ---
    admin = _is_admin()
    checks.append(Check("Admin / elevation", OK if admin else WARN,
                        "elevated" if admin else "not elevated  -- needed for USBPcap capture & SMBus"))

    return checks


def report(checks: list[Check] | None = None) -> str:
    checks = checks if checks is not None else run_checks()
    width = max(len(c.name) for c in checks)
    lines = ["LumaScope environment", "=" * 21, ""]
    for c in checks:
        lines.append(f"  {_GLYPH[c.status]} {c.name.ljust(width)}  {c.detail}")
    runnable = [
        "decode engine + selftest (no deps)",
        "Frida capture" if any(c.name.startswith("frida") and c.status == OK for c in checks) else None,
        "USBPcap capture" if all(
            any(c.name.startswith(n) and c.status == OK for c in checks) for n in ("tshark", "USBPcap")
        ) else None,
    ]
    lines += ["", "Runnable now: " + ", ".join(r for r in runnable if r)]
    return "\n".join(lines)
