"""Capture backend interface.

All backends (Frida, USBPcap, SMBus) present the same streaming shape so the orchestrator
(Phase 4) can treat them interchangeably:

    backend.open()                 # start capturing into an internal buffer
    ... drive a stimulus step ...
    frames = backend.drain()       # take everything captured since the last drain
    backend.close()

``capture(duration)`` is a convenience for the one-shot ``lumascope capture`` command:
open, wait, close, return all frames. Backends are also context managers.

Frames are pushed from a backend-internal thread (Frida's message callback, a tshark reader
thread, ...), so ``_push`` / ``drain`` are mutex-guarded.
"""

from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from collections import deque

from ..model import CaptureFrame


class CaptureBackend(ABC):
    name = "base"

    def __init__(self) -> None:
        self._frames: deque[CaptureFrame] = deque()
        self._lock = threading.Lock()

    # --- backend-internal: called from the capture thread --- #
    def _push(self, frame: CaptureFrame) -> None:
        with self._lock:
            self._frames.append(frame)

    # --- lifecycle (implemented per backend) --- #
    @abstractmethod
    def open(self) -> None:
        """Begin capturing. Returns once frames will start flowing into the buffer."""

    @abstractmethod
    def close(self) -> None:
        """Stop capturing and release the device/process. Idempotent."""

    # --- shared --- #
    def drain(self) -> list[CaptureFrame]:
        """Return and clear all frames captured since the last drain."""
        with self._lock:
            out = list(self._frames)
            self._frames.clear()
        return out

    def capture(self, duration: float) -> list[CaptureFrame]:
        """One-shot: capture for ``duration`` seconds, then return every frame."""
        self.open()
        try:
            time.sleep(duration)
        finally:
            self.close()
        return self.drain()

    def __enter__(self) -> "CaptureBackend":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()
