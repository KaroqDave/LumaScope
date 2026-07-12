"""Frida capture backend.

Spawns the target *suspended* and follows its gated descendants (so the CreateFile handle map
is built from the very first device open), or attaches to a running process. It injects
:mod:`agent.js` and turns each ``send(meta, bytes)`` into a :class:`CaptureFrame`.

``frida`` is an optional dependency (native wheel). It is imported lazily inside
:meth:`open` so the rest of LumaScope works without it installed.
"""

from __future__ import annotations

import json
import os
import shutil
import threading
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

    Provide exactly one of ``spawn`` (a ``[program, *args]`` list whose process tree is
    launched under capture) or ``attach`` (a running pid or process name). ``vid``/``pid``
    filter to one USB device; omit both to capture every device-handle write the agent sees.
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
        self._sessions: dict[int, object] = {}
        self._scripts: dict[int, object] = {}
        self._state_lock = threading.RLock()
        self._agent_source: Optional[str] = None
        self._pid: Optional[int] = None
        self._spawned = False
        self._spawned_pids: set[int] = set()
        self._gated_pids: set[int] = set()
        self._watching_children = False
        self._closing = False

    # --- lifecycle --- #
    def open(self) -> None:
        import frida  # lazy: optional native dependency

        with self._state_lock:
            self._closing = False
        self._device = frida.get_local_device()
        config = {
            "vid": self.vid,
            "pid": self.pid,
            "keepUnmapped": self.keep_unmapped,
            "maxLen": self.max_len,
        }
        # Read and format the agent before creating a suspended process. A local source error
        # then cannot strand a process that has not yet entered the cleanup-protected section.
        agent_source = "globalThis.LUMASCOPE_CONFIG = %s;\n%s" % (
            json.dumps(config),
            _load_agent_source(),
        )

        try:
            if self.spawn is not None:
                # frida.spawn needs a resolvable executable path; unlike subprocess it does
                # not search PATH, so resolve a bare program name (e.g. "python", "OpenRGB").
                prog = self.spawn[0]
                if not os.path.isfile(prog):
                    prog = shutil.which(prog) or prog
                self._pid = self._device.spawn([prog, *self.spawn[1:]])
                self._spawned = True
                with self._state_lock:
                    self._spawned_pids.add(self._pid)
                    self._gated_pids.add(self._pid)
            else:
                self._pid = self._resolve_attach_target(frida)

            with self._state_lock:
                self._agent_source = agent_source

            if self._spawned:
                # Windows virtualenv launchers and some vendor frontends create the real target
                # as a child. Gate descendants so every process is instrumented before it runs.
                self._device.on("child-added", self._on_child_added)
                with self._state_lock:
                    remove_observer = self._closing
                    self._watching_children = not remove_observer
                if remove_observer:
                    try:
                        self._device.off("child-added", self._on_child_added)
                    except Exception:
                        pass

            instrumented = self._instrument_process(self._pid)
            if self._spawned:
                with self._state_lock:
                    closing = self._closing
                if instrumented and not closing:
                    self._resume_gated_process(self._pid)
                elif not self.kill_on_close:
                    self._resume_gated_process(
                        self._pid,
                        warning="backend closed while the spawned process was being instrumented",
                    )
                elif closing:
                    self._kill_spawned_process(self._pid)
        except BaseException:
            self.close()
            raise

    def _instrument_process(self, pid: int) -> bool:
        """Load the agent and publish its resources unless shutdown won the race."""
        with self._state_lock:
            if self._closing:
                return False
            device = self._device
            agent_source = self._agent_source

        if device is None:
            raise RuntimeError("Frida device is not initialized")
        if agent_source is None:
            raise RuntimeError("Frida agent source is not initialized")

        session = None
        script = None
        try:
            session = device.attach(pid)
            with self._state_lock:
                if self._closing:
                    publish = False
                else:
                    publish = None
            if publish is False:
                self._dispose_instrumentation(session=session, script=None)
                return False

            session.on("detached", lambda reason, *args: self._on_detached(pid, reason, *args))
            if self._spawned:
                session.enable_child_gating()

            script = session.create_script(agent_source)
            script.on("message", self._on_message)
            script.on("destroyed", lambda *args: self._on_destroyed(pid, *args))
            script.load()

            with self._state_lock:
                if self._closing:
                    publish = False
                else:
                    self._sessions[pid] = session
                    self._scripts[pid] = script
                    publish = True

            if not publish:
                self._dispose_instrumentation(session=session, script=script)
            return publish
        except Exception:
            with self._state_lock:
                self._scripts.pop(pid, None)
                self._sessions.pop(pid, None)
            self._dispose_instrumentation(session=session, script=script)
            raise

    @staticmethod
    def _dispose_instrumentation(*, session, script) -> None:
        if script is not None:
            try:
                script.unload()
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass

    def _resume_gated_process(self, pid: int, *, warning: Optional[str] = None) -> None:
        with self._state_lock:
            if pid not in self._gated_pids:
                return
            device = self._device
        if warning is not None:
            self.logs.append(("warn", f"{warning}; resuming process {pid} uninstrumented"))
        if device is None:
            return
        try:
            device.resume(pid)
        except Exception as exc:
            self.logs.append(("error", f"could not resume process {pid}: {exc}"))
            return
        with self._state_lock:
            self._gated_pids.discard(pid)
            if self._closing and not self.kill_on_close:
                self._spawned_pids.discard(pid)

    def _kill_spawned_process(self, pid: int) -> None:
        with self._state_lock:
            if pid not in self._spawned_pids:
                return
            device = self._device
        if device is None:
            return
        try:
            device.kill(pid)
        except Exception as exc:
            self.logs.append(("error", f"could not kill process {pid}: {exc}"))
            return
        with self._state_lock:
            self._gated_pids.discard(pid)
            self._spawned_pids.discard(pid)

    def _on_child_added(self, child) -> None:
        pid = child.pid
        with self._state_lock:
            self._spawned_pids.add(pid)
            self._gated_pids.add(pid)
            closing = self._closing
        self.logs.append(("child", {"pid": pid, "parent_pid": child.parent_pid, "path": child.path}))

        if closing:
            if self.kill_on_close:
                self._kill_spawned_process(pid)
            else:
                self._resume_gated_process(pid, warning="backend is closing")
            return

        try:
            instrumented = self._instrument_process(pid)
        except Exception as exc:
            instrumented = False
            self.logs.append(("error", f"could not instrument child {pid}: {exc}"))

        with self._state_lock:
            closing = self._closing

        if instrumented and not closing:
            self._resume_gated_process(pid)
        elif closing and self.kill_on_close:
            # This callback may have been dispatched before child observation was disabled but
            # reached us after close() took its PID snapshot. Kill it here so it cannot orphan.
            self._kill_spawned_process(pid)
        elif not self.kill_on_close:
            reason = "backend closed during child instrumentation" if closing else "child instrumentation failed"
            self._resume_gated_process(pid, warning=reason)
        # With kill_on_close enabled, a failed child intentionally remains gated. close() will
        # terminate it, rather than releasing an uninstrumented process that can lose traffic.

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

    def _on_detached(self, pid, reason, *args) -> None:
        with self._state_lock:
            self._scripts.pop(pid, None)
            self._sessions.pop(pid, None)
        self.logs.append(("detached", {"pid": pid, "reason": reason}))

    def _on_destroyed(self, pid, *args) -> None:
        self.logs.append(("destroyed", pid))

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
        # Mark shutdown first. A child callback already queued by Frida will then dispose of its
        # own PID instead of instrumenting/resuming it after our snapshots were taken.
        with self._state_lock:
            self._closing = True
            watching_children = self._watching_children
            self._watching_children = False
            device = self._device

        if watching_children and device is not None:
            try:
                device.off("child-added", self._on_child_added)
            except Exception:
                pass

        with self._state_lock:
            scripts = list(self._scripts.values())
            sessions = list(self._sessions.values())
            pids = list(self._spawned_pids)
            gated_pids = list(self._gated_pids)
            self._scripts.clear()
            self._sessions.clear()
            self._agent_source = None

        for script in scripts:
            try:
                script.unload()
            except Exception:
                pass

        if self._spawned and self.kill_on_close and device is not None:
            for pid in reversed(pids):
                self._kill_spawned_process(pid)
        elif self._spawned and device is not None:
            for pid in reversed(gated_pids):
                self._resume_gated_process(pid, warning="backend closed while process was gated")
            with self._state_lock:
                self._spawned_pids.difference_update(pids)

        for session in sessions:
            try:
                session.detach()
            except Exception:
                pass
