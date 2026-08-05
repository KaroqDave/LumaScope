"""End-to-end Frida capture test — no hardware required.

Spawns ``_capture_harness.py`` under the real :class:`FridaBackend`, agent and all, and
asserts the captured frames match the buffers the harness emitted. Verifies: hook firing,
binary buffer transport, CreateFile->VID:PID correlation, the VID:PID filter, CloseHandle
handle-reuse eviction, over-length truncation, and WinUsb_ControlTransfer by-value setup
parsing. Skipped off-Windows or when frida is not installed.
"""
import importlib.util
import os
import sys

import pytest

def _frida_usable() -> bool:
    """Whether frida can actually be imported, not merely whether it is present.

    An incompatible wheel installs fine and raises on import (frida 17 needs Python
    3.11), so a `find_spec` guard lets these tests hard-fail instead of skipping.
    """
    if importlib.util.find_spec("frida") is None:
        return False
    try:
        import frida  # noqa: F401
    except Exception:
        return False
    return True


pytestmark = [
    pytest.mark.skipif(sys.platform != "win32", reason="Frida HID/WinUSB capture is Windows-only"),
    pytest.mark.skipif(not _frida_usable(), reason="frida not installed or not importable"),
]

HERE = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(HERE, "_capture_harness.py")

WF_BUF = b"LUMASCOPE-WRITEFILE-AABBCCDD"
HID_BUF = b"\x00LUMASCOPE-HIDFEATURE"
OUT_BUF = b"\x01LUMASCOPE-HIDOUTPUT"
WU_BUF = b"LUMASCOPE-WINUSB-WRITEPIPE"
CT_BUF = b"LUMASCOPE-CTRL"
REUSE_BUF = b"LUMASCOPE-REUSED-NONDEVICE"
# setup = RequestType 0x40, Request 0x01, Value 0x1234, Index 0x5678, Length 0x000e (=len CT_BUF)
EXPECTED_SETUP = "4001341278560e00"


def _paths(tmp_path):
    # The device filename embeds a device-like token so the agent maps the handle to VID:PID.
    dev = str(tmp_path / "hid#vid_1234&pid_5678#cap.bin")
    reuse = str(tmp_path / "plain_reuse.bin")
    return dev, reuse


def _capture(tmp_path, **kwargs):
    from lumascope.capture.frida_backend import FridaBackend

    dev, reuse = _paths(tmp_path)
    backend = FridaBackend(spawn=[sys.executable, HARNESS, dev, reuse], **kwargs)
    frames = backend.capture(duration=4.0)
    return frames, backend


def test_captures_all_hook_families(tmp_path):
    frames, backend = _capture(tmp_path)
    logs = list(backend.logs)

    # WriteFile on the device-like handle: correlated to VID:PID (written exactly once).
    wf = [f for f in frames if f.data == WF_BUF]
    assert len(wf) == 1, logs
    assert wf[0].api == "WriteFile"
    assert wf[0].vid == 0x1234
    assert wf[0].pid == 0x5678

    # Over-length write: truncated to 64K, real length preserved in meta.
    big = [f for f in frames if f.meta.get("truncated")]
    assert big, logs
    assert big[0].meta["full_len"] == 70000
    assert len(big[0].data) == 65536

    # HID feature + output reports (bogus handle; onEnter still captures the buffer).
    assert any(f.data == HID_BUF and f.transfer == "feature" for f in frames)
    assert any(f.data == OUT_BUF and f.transfer == "output" for f in frames)

    # WinUSB write pipe, captured via the lazily-loaded winusb.dll, pipe id preserved.
    wu = [f for f in frames if f.data == WU_BUF]
    assert wu, logs
    assert wu[0].api == "WinUsb_WritePipe"
    assert wu[0].endpoint == 2

    # WinUSB control transfer: SETUP packet read as an 8-byte by-value struct, direction OUT.
    ct = [f for f in frames if f.data == CT_BUF]
    assert ct, logs
    assert ct[0].api == "WinUsb_ControlTransfer"
    assert ct[0].direction == "out"
    assert ct[0].meta.get("setup") == EXPECTED_SETUP


def test_vidpid_filter_drops_unmapped(tmp_path):
    # With a filter and keep_unmapped=False, only the correlated WriteFile survives; the
    # bogus-handle HID/WinUSB frames are unmapped and dropped.
    frames, backend = _capture(tmp_path, vid=0x1234, pid=0x5678, keep_unmapped=False)

    assert any(f.data == WF_BUF and f.vid == 0x1234 for f in frames), list(backend.logs)
    assert all(f.data != HID_BUF for f in frames)
    assert all(f.data != WU_BUF for f in frames)


def test_closehandle_eviction_prevents_stale_tagging(tmp_path):
    # After the device handle closes, the harness reopens a NON-device file that often reuses
    # the same numeric HANDLE. With CloseHandle eviction the stale device mapping is gone, so
    # the reused handle's write must never be tagged with the device VID:PID (and is therefore
    # dropped under a vid/pid filter). Without eviction it would leak through mislabeled.
    frames, backend = _capture(tmp_path, vid=0x1234, pid=0x5678, keep_unmapped=False)
    assert all(f.data != REUSE_BUF for f in frames), list(backend.logs)
