"""Frida capture backend.

Spawns the target *suspended* (so the CreateFile handle map is built from the very first
device open) or attaches to a running process, injects :mod:`agent.js`, and turns each
``send(meta, bytes)`` from the agent into a :class:`CaptureFrame`.

``frida`` is an optional dependency (native wheel). It is imported lazily inside
:meth:`open` so the rest of LumaScope works without it installed.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from typing import Optional, Union

from ..model import CaptureFrame
from .base import CaptureBackend

_AGENT_PATH = os.path.join(os.path.dirname(__file__), "agent.js")


def _load_agent_source() -> str:
    with open(_AGENT_PATH, encoding="utf-8") as fh:
        return fh.read()


class FridaBackend(CaptureBackend):
    """Capture device writes by hooking the target process with Frida.

    Provide exactly one of ``spawn`` (a ``[program, *args]`` list to launch under capture)
    or ``attach`` (a running pid or process name). ``vid``/``pid`` filter to one USB device;
    omit both to capture every device-handle write the agent sees.
    """

    name = "frida"

    def __init__(
        self,
        *,
        spawn: Optional[list[str]] = None,
        attach: Optional[Union[int, str]] = None,
        vid: Optional[int] = None,
        pid: Optional[int] = None,
        keep_unmapped: Optional[bool] = None,
        max_len: int = 65536,
        kill_on_close: Optional[bool] = None,
    ) -> None:
        super().__init__()
        if (spawn is None) == (attach is None):
            raise ValueError("FridaBackend needs exactly one of spawn=[...] or attach=pid|name")
        self.spawn = spawn
        self.attach = attach
        self.vid = vid
        self.pid = pid
        # In spawn mode we see every CreateFile from the start, so the handle map is
        # complete and any unmapped frame is non-device noise -> drop it. In attach mode the
        # device handle may predate injection, so keep unmapped frames by default.
        self.keep_unmapped = (attach is not None) if keep_unmapped is None else keep_unmapped
        self.max_len = max_len
        # By default we kill what we spawned, but leave attached processes alone.
        self.kill_on_close = (spawn is not None) if kill_on_close is None else kill_on_close

        self.logs: list[tuple[str, object]] = []
        self.ready = False
        self._device = None
        self._session = None
        self._script = None
        self._pid: Optional[int] = None
        self._spawned = False

    # --- lifecycle --- #
    def open(self) -> None:
        import frida  # lazy: optional native dependency

        self._device = frida.get_local_device()
        if self.spawn is not None:
            # frida.spawn needs a resolvable executable path; unlike subprocess it does
            # not search PATH, so resolve a bare program name (e.g. "python", "OpenRGB").
            prog = self.spawn[0]
            if not os.path.isfile(prog):
                prog = shutil.which(prog) or prog
            self._pid = self._device.spawn([prog, *self.spawn[1:]])
            self._spawned = True
        else:
            self._pid = self._resolve_attach_target(frida)

        self._session = self._device.attach(self._pid)
        self._session.on("detached", self._on_detached)
        config = {
            "vid": self.vid,
            "pid": self.pid,
            "keepUnmapped": self.keep_unmapped,
            "maxLen": self.max_len,
        }
        source = "globalThis.LUMASCOPE_CONFIG = %s;\n%s" % (json.dumps(config), _load_agent_source())
        self._script = self._session.create_script(source)
        self._script.on("message", self._on_message)
        self._script.on("destroyed", self._on_destroyed)
        self._script.load()
        if self._spawned:
            self._device.resume(self._pid)

    def capture(self, duration: float):
        frames = super().capture(duration)
        # A loaded agent that saw nothing usually means the device-writing code lives in a
        # different process (e.g. a vendor background service) than the one we hooked.
        if self.ready and not frames:
            self.logs.append((
                "warn",
                "agent loaded but captured 0 frames - the device-writing process may be a "
                "separate service; try --attach <service-name-or-pid>",
            ))
        return frames

    def _on_detached(self, reason, *args) -> None:
        self.logs.append(("detached", reason))

    def _on_destroyed(self, *args) -> None:
        self.logs.append(("destroyed", None))

    def _resolve_attach_target(self, frida_mod):
        target = self.attach
        if isinstance(target, int):
            return target
        if isinstance(target, str) and target.isdigit():
            return int(target)

        want = str(target).lower()
        want_base = want[:-4] if want.endswith(".exe") else want
        procs = list(self._device.enumerate_processes())

        # Exact match, ignoring case and a trailing ".exe" on either side (Windows process
        # names come back as "LightingService.exe").
        for proc in procs:
            name = proc.name.lower()
            base = name[:-4] if name.endswith(".exe") else name
            if base == want_base:
                return proc.pid

        # Unambiguous substring fallback.
        matches = [p for p in procs if want_base in p.name.lower()]
        if len(matches) == 1:
            return matches[0].pid
        if len(matches) > 1:
            listed = ", ".join(f"{p.name}({p.pid})" for p in matches[:8])
            raise frida_mod.ProcessNotFoundError(f"{target!r} is ambiguous: {listed}. Use --attach <pid>.")
        raise frida_mod.ProcessNotFoundError(f"no running process named {target!r}")

    def _on_message(self, message, data) -> None:
        if message.get("type") == "error":
            self.logs.append(("error", message.get("description") or message.get("stack")))
            return
        payload = message.get("payload") or {}
        kind = payload.get("type")
        if kind == "frame":
            if data is None:  # a frame message must carry its buffer; drop malformed ones
                self.logs.append(("dropped", payload.get("api")))
                return
            self._push(self._frame_from_payload(payload, data))
        elif kind == "ready":
            self.ready = True
            self.logs.append(("ready", payload))
        elif kind == "log":
            self.logs.append(("log", payload.get("msg")))

    @staticmethod
    def _frame_from_payload(payload: dict, data) -> CaptureFrame:
        raw = bytes(data) if data is not None else b""
        meta = {k: payload[k] for k in ("ioctl", "setup", "handle", "truncated", "full_len") if k in payload}
        # HID feature/output reports carry the report id in byte 0.
        report_id = None
        if payload.get("transfer") in ("feature", "output") and raw:
            report_id = raw[0]
        return CaptureFrame(
            data=raw,
            timestamp_ns=time.time_ns(),
            source="frida",
            api=payload.get("api", ""),
            direction=payload.get("direction", "out"),
            transfer=payload.get("transfer", ""),
            vid=payload.get("vid"),
            pid=payload.get("pid"),
            path=payload.get("path"),
            report_id=report_id,
            endpoint=payload.get("endpoint"),
            meta=meta,
        )

    def close(self) -> None:
        try:
            if self._script is not None:
                self._script.unload()
        except Exception:
            pass
        self._script = None
        try:
            if self._spawned and self.kill_on_close and self._device is not None:
                try:
                    self._device.kill(self._pid)
                except Exception:
                    pass
            if self._session is not None:
                self._session.detach()
        except Exception:
            pass
        self._session = None
