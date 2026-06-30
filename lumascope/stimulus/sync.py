"""Capture-window synchronization.

After a stimulus step is applied, the device may emit its packet(s) after a variable delay
(GUI repaint, service round-trip). ``collect_until_quiet`` drains the backend until the
device has been silent for ``quiet`` seconds (or ``max_wait`` elapses), so a step's window
adapts to real latency instead of guessing a fixed sleep.

Timing is fully parameterized so the orchestrator test can run it with zero delays.
"""

from __future__ import annotations

import time

from ..model import CaptureFrame


def collect_until_quiet(
    backend,
    *,
    settle: float = 0.2,
    quiet: float = 0.3,
    poll: float = 0.02,
    max_wait: float = 3.0,
) -> list[CaptureFrame]:
    """Drain ``backend`` until it goes quiet for ``quiet`` seconds; return all frames seen."""
    if settle:
        time.sleep(settle)
    collected: list[CaptureFrame] = []
    start = time.monotonic()
    last_activity = start
    while True:
        batch = backend.drain()
        now = time.monotonic()
        if batch:
            collected.extend(batch)
            last_activity = now
        elif now - last_activity >= quiet:
            break
        if now - start >= max_wait:
            break
        if poll:
            time.sleep(poll)
    return collected
