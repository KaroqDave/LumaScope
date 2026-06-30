"""Capture harness for test_frida_capture (NOT a pytest module).

Emits one of each hookable Win32 call with a distinctive, known buffer, then exits.
``argv[1]`` is a device-like file path whose *name* embeds ``hid#vid_1234&pid_5678`` —
opening + writing it lets the agent exercise the CreateFile->VID:PID correlation with a
real, succeeding handle. The HID/WinUSB calls use bogus/NULL handles: the call fails but
the agent's onEnter hook still captures the buffer (no real device needed).

``argv[2]`` is a plain (non-device) file path used for the handle-reuse test: after the
device handle is closed, reopening here frequently recycles the same numeric HANDLE, which
must NOT be mislabeled with the device's VID:PID once CloseHandle eviction is in place.
"""
import ctypes
import ctypes.wintypes as w
import sys
import time

WF_BUF = b"LUMASCOPE-WRITEFILE-AABBCCDD"
HID_BUF = b"\x00LUMASCOPE-HIDFEATURE"
OUT_BUF = b"\x01LUMASCOPE-HIDOUTPUT"
WU_BUF = b"LUMASCOPE-WINUSB-WRITEPIPE"
CT_BUF = b"LUMASCOPE-CTRL"            # 14 bytes -> setup wLength = 0x000e
BIG_BUF = b"Z" * 70000               # > MAX_LEN (64K): exercises truncation
REUSE_BUF = b"LUMASCOPE-REUSED-NONDEVICE"


class WINUSB_SETUP_PACKET(ctypes.Structure):
    _fields_ = [
        ("RequestType", ctypes.c_ubyte),
        ("Request", ctypes.c_ubyte),
        ("Value", ctypes.c_ushort),
        ("Index", ctypes.c_ushort),
        ("Length", ctypes.c_ushort),
    ]


def main() -> None:
    dev_path = sys.argv[1]
    reuse_path = sys.argv[2]
    k = ctypes.windll.kernel32
    GENERIC_WRITE = 0x40000000
    CREATE_ALWAYS = 2
    FILE_ATTRIBUTE_NORMAL = 0x80
    k.CreateFileW.restype = w.HANDLE
    k.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.c_void_p,
                              w.DWORD, w.DWORD, w.HANDLE]

    h = k.CreateFileW(dev_path, GENERIC_WRITE, 0, None, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, None)
    written = w.DWORD(0)
    k.WriteFile(h, WF_BUF, len(WF_BUF), ctypes.byref(written), None)
    k.WriteFile(h, BIG_BUF, len(BIG_BUF), ctypes.byref(written), None)  # truncation path
    k.CloseHandle(h)

    # Handle reuse: reopen a NON-device file; Windows commonly hands back the same HANDLE.
    h2 = k.CreateFileW(reuse_path, GENERIC_WRITE, 0, None, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, None)
    print("device handle:", hex(h or 0), "reuse handle:", hex(h2 or 0), "reused:", h == h2)
    k.WriteFile(h2, REUSE_BUF, len(REUSE_BUF), ctypes.byref(written), None)
    k.CloseHandle(h2)

    try:
        hid = ctypes.windll.hid
        b1 = ctypes.create_string_buffer(HID_BUF, len(HID_BUF))
        hid.HidD_SetFeature(ctypes.c_void_p(0x999001), b1, len(HID_BUF))
        b2 = ctypes.create_string_buffer(OUT_BUF, len(OUT_BUF))
        hid.HidD_SetOutputReport(ctypes.c_void_p(0x999001), b2, len(OUT_BUF))
    except Exception as e:  # pragma: no cover - diagnostic only
        print("hid err", e)

    try:
        wu = ctypes.windll.winusb
        # WinUsb_WritePipe with a NULL interface handle: rejected cleanly (no AV), onEnter
        # still captures the buffer.
        b3 = ctypes.create_string_buffer(WU_BUF, len(WU_BUF))
        transferred = w.DWORD(0)
        wu.WinUsb_WritePipe(ctypes.c_void_p(0), 0x02, b3, len(WU_BUF),
                            ctypes.byref(transferred), None)
        # WinUsb_ControlTransfer: SETUP packet passed BY VALUE (8 bytes in RDX on x64).
        setup = WINUSB_SETUP_PACKET(0x40, 0x01, 0x1234, 0x5678, len(CT_BUF))  # 0x40 = host->device
        b4 = ctypes.create_string_buffer(CT_BUF, len(CT_BUF))
        wu.WinUsb_ControlTransfer(ctypes.c_void_p(0), setup, b4, len(CT_BUF),
                                  ctypes.byref(transferred), None)
    except Exception as e:  # pragma: no cover - diagnostic only
        print("winusb err", e)

    time.sleep(0.3)  # let the agent flush before we exit


if __name__ == "__main__":
    main()
