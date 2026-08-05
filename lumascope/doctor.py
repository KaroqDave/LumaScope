"""Environment doctor: report what LumaScope can do on this machine right now.

Pure stdlib and side-effect-free — it only *reads* the environment. The report is
organised around capabilities rather than packages: it leads with what you can already
do, then lists only what is actually blocking the rest, each with the exact command that
fixes it. A newcomer should be able to act on this without knowing which Python package
underpins which feature.
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
    fix: str = ""       # a command the user can literally run
    needed_for: str = ""  # the capability this unlocks


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

    # --- capture: in-process hook ---
    frida_v = _module_version("frida")
    frida_broken = bool(frida_v) and "failed" in frida_v
    checks.append(Check(
        "frida", OK if frida_v and not frida_broken else MISSING,
        frida_v or "not installed (native wheel; may lag the newest Python release)",
        # An unimportable frida needs a *different* fix from a missing one, and
        # reinstalling the same extra would just put the same broken wheel back.
        fix=('pip install "frida<17"   (frida 17 requires Python 3.11+)'
             if frida_broken else 'pip install -e ".[frida]"'),
        needed_for="capture --backend frida (hook the vendor app from inside)",
    ))

    # --- capture: USB bus sniff ---
    tshark = _tshark()
    checks.append(Check(
        "tshark (Wireshark)", OK if tshark else MISSING,
        tshark or "not found on PATH",
        fix="install Wireshark from https://www.wireshark.org/ (tick the tshark component)",
        needed_for="capture --backend usbpcap (sniff the USB bus)",
    ))
    usbpcap = _usbpcap()
    checks.append(Check(
        "USBPcap", OK if usbpcap else MISSING,
        usbpcap or "not installed",
        fix="install from https://desowin.org/usbpcap/ (needs admin + a reboot)",
        needed_for="capture --backend usbpcap (sniff the USB bus)",
    ))

    # --- stimulus ---
    for mod, label, extra in [
        ("openrgb", "openrgb-python", "stimulus"),
        ("pywinauto", "pywinauto", "stimulus"),
        ("requests", "requests", "stimulus"),
        ("pyautogui", "pyautogui", "image"),
        ("cv2", "opencv-python", "image"),
    ]:
        v = _module_version(mod)
        checks.append(Check(
            label, OK if v and "failed" not in v else MISSING,
            v or "not installed",
            fix=f'pip install -e ".[{extra}]"',
            needed_for="sweep --driver openrgb (drive device state automatically)",
        ))

    openrgb_exe = _find_openrgb()
    server = _port_open("127.0.0.1", 6742)
    if openrgb_exe or server:
        detail = openrgb_exe or "found"
        detail += "  (SDK server UP on :6742)" if server else "  (SDK server not running)"
        checks.append(Check("OpenRGB app", OK if server else WARN, detail,
                            fix="" if server else "start OpenRGB and enable its SDK server",
                            needed_for="sweep --driver openrgb"))
    else:
        checks.append(Check("OpenRGB app", MISSING, "not found",
                            fix="install from https://openrgb.org/",
                            needed_for="sweep --driver openrgb (a known-good reference device)"))

    # --- checksum escalation (optional) ---
    reveng = shutil.which("reveng")
    checks.append(Check("reveng (exotic CRC search)", OK if reveng else WARN,
                        reveng or "not installed (the built-in catalog covers common CRCs)",
                        fix="", needed_for="decoding unusual CRC variants"))

    # --- privilege (needed for USBPcap / SMBus) ---
    admin = _is_admin()
    checks.append(Check("Admin / elevation", OK if admin else WARN,
                        "elevated" if admin else "not elevated",
                        fix="" if admin else "re-run this terminal as Administrator",
                        needed_for="capture --backend usbpcap, and seeing SYSTEM services"))

    return checks


def _ok(checks: list[Check], name: str) -> bool:
    return any(c.name.startswith(name) and c.status == OK for c in checks)


def capabilities(checks: list[Check]) -> tuple[list[str], list[tuple[str, str]]]:
    """Split what this machine can do from what is blocked, with the fix for each.

    Returns ``(can_do, blocked)`` where each blocked entry is ``(capability, fix)``.
    """
    can: list[str] = [
        "Read and analyse existing captures  (show, analyze, inspect, cadence)",
        "Decode a corpus into a protocol spec, and emit JSON / C++  (decode, emit)",
        "Run the built-in examples  (demo, selftest)",
    ]
    blocked: list[tuple[str, str]] = []

    frida = _ok(checks, "frida")
    sniff = _ok(checks, "tshark") and _ok(checks, "USBPcap")
    admin = _ok(checks, "Admin")

    if frida:
        can.append("Record from a vendor app by hooking it  (capture --backend frida, sweep)")
    else:
        blocked.append(("Record by hooking the vendor app", 'pip install -e ".[frida]"'))

    if sniff and admin:
        can.append("Record by sniffing the USB bus  (capture --backend usbpcap)")
    elif sniff:
        blocked.append(("Record by sniffing the USB bus",
                        "re-run this terminal as Administrator (USBPcap and Wireshark are installed)"))
    else:
        missing = [n for n in ("tshark", "USBPcap") if not _ok(checks, n)]
        blocked.append((f"Record by sniffing the USB bus (missing {', '.join(missing)})",
                        "install Wireshark and USBPcap, then re-run as Administrator"))

    if _ok(checks, "openrgb-python") and _ok(checks, "OpenRGB app"):
        can.append("Drive a reference device automatically  (sweep --driver openrgb)")
    else:
        blocked.append(("Drive a reference device automatically",
                        'pip install -e ".[stimulus]" and run OpenRGB with its SDK server on'))

    if sys.platform != "win32":
        blocked.append(("Live capture and replay (this is a Windows-only path)",
                        "the decode/emit half works fine here on captures taken elsewhere"))
    return can, blocked


def report(checks: list[Check] | None = None, *, verbose: bool = False) -> str:
    checks = checks if checks is not None else run_checks()
    can, blocked = capabilities(checks)

    lines = ["LumaScope environment", "=" * 21, "", "You can do this now:"]
    lines += [f"  [+] {c}" for c in can]

    if blocked:
        lines += ["", "Not yet available:"]
        for capability, fix in blocked:
            lines.append(f"  [-] {capability}")
            if fix:
                lines.append(f"      -> {fix}")

    shown = checks if verbose else [c for c in checks if c.status != OK]
    if shown:
        heading = "All checks:" if verbose else "Details (missing / warnings only -- --verbose for all):"
        lines += ["", heading]
        width = max(len(c.name) for c in shown)
        for c in shown:
            lines.append(f"  {_GLYPH[c.status]} {c.name.ljust(width)}  {c.detail}")
            if c.status != OK and c.needed_for:
                lines.append(f"      needed for: {c.needed_for}")

    lines += ["", "Next:  lumascope devices     (find the device to reverse)",
              "       lumascope guide       (the full workflow)"]
    return "\n".join(lines)
