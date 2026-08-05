"""Manual / operator-guided stimulus driver.

The realistic path when the device has no programmable API (e.g. a motherboard whose only
control surface is the vendor app): LumaScope prints the exact target state for each sweep
step, you reproduce it in the vendor GUI, and confirm — the capture taken during that window
is then labeled with that known state.

Every step here costs a human twenty seconds of clicking, so the prompt earns its space:
it shows position, percentage, and a running estimate of the time left, and it describes
the target in the words a vendor GUI uses ("LED 3 only, full green") rather than as a
vector of tuples. `s` skips a step you cannot reproduce; `q` stops the sweep and keeps
everything captured so far.

Both the prompt and output are injectable so the orchestrator test can drive it without a
real console.
"""

from __future__ import annotations

import time
from typing import Callable

from ..model import (
    KIND_BRIGHTNESS,
    KIND_LED_WALK,
    KIND_PER_CHANNEL,
    KIND_UNIFORM,
    SweepStep,
)
from .base import StimulusDriver

_CHANNEL_WORDS = {"R": "red", "G": "green", "B": "blue"}


class SweepAborted(Exception):
    """The operator asked to stop the sweep. Everything captured so far is kept."""


def _describe_target(step: SweepStep) -> str:
    """The target state in the terms a vendor GUI actually offers."""
    if step.kind == KIND_PER_CHANNEL:
        word = _CHANNEL_WORDS.get((step.channel or "").upper(), step.channel or "?")
        level = "off" if step.value == 0 else f"{round((step.value or 0) / 255 * 100)}% {word}"
        return f"LED {step.led} only, {level}  (every other LED off)"
    if step.kind == KIND_LED_WALK:
        return f"LED {step.led} only, full white  (every other LED off)"
    if step.kind == KIND_UNIFORM:
        v = step.value or 0
        if v == 0:
            return "every LED off"
        return f"every LED the same grey, {round(v / 255 * 100)}% brightness"
    if step.kind == KIND_BRIGHTNESS:
        b = step.brightness or 0
        return f"every LED white, master brightness {round(b / 255 * 100)}%"
    return step.describe()


def _short_colors(colors, limit: int = 6) -> str:
    shown = ", ".join(f"({r},{g},{b})" for r, g, b in colors[:limit])
    return shown + (" ..." if len(colors) > limit else "")


def _eta(elapsed: float, done: int, total: int) -> str:
    if done < 2 or not total or done >= total:
        return ""
    remaining = (elapsed / done) * (total - done)
    if remaining < 90:
        return f"~{round(remaining)}s left"
    return f"~{round(remaining / 60)} min left"


class ManualDriver(StimulusDriver):
    name = "manual"

    def __init__(self, prompt: Callable[[str], str] = input, out: Callable[[str], None] = print) -> None:
        self._prompt = prompt
        self._out = out
        self._total = 0
        self._done = 0
        self._started = 0.0

    def setup(self, led_count: int, total_steps: int = 0) -> None:
        self._total = total_steps
        self._done = 0
        self._started = time.monotonic()
        count = f"{total_steps} steps" if total_steps else "a sweep"
        self._out(
            f"\nManual sweep over {led_count} LED(s), {count}.\n"
            f"For each step: set the described state in the vendor app, then press Enter.\n"
            f"  Enter = captured    s = skip this step    q = stop and keep what we have\n"
        )

    def set_state(self, step: SweepStep) -> bool:
        self._done += 1
        position = f"{self._done}/{self._total}" if self._total else str(self._done)
        pct = f"  {round(self._done / self._total * 100):>3}%" if self._total else ""
        eta = _eta(time.monotonic() - self._started, self._done - 1, self._total)

        self._out(f"\n[{position}{pct}]  {_describe_target(step)}")
        self._out(f"           colors: {_short_colors(step.colors)}"
                  + (f"   ({eta})" if eta else ""))
        answer = str(self._prompt("           Enter when set / s / q > ")).strip().lower()
        if answer == "q":
            raise SweepAborted()
        return answer != "s"
