"""Manual / operator-guided stimulus driver.

The realistic path when the device has no programmable API (e.g. a motherboard whose only
control surface is the vendor app): LumaScope prints the exact target state for each sweep
step, you reproduce it in the vendor GUI, and confirm — the capture taken during that window
is then labeled with that known state.

Both the prompt and output are injectable so the orchestrator test can drive it without a
real console.
"""

from __future__ import annotations

from typing import Callable

from ..model import SweepStep
from .base import StimulusDriver


def _short_colors(colors, limit: int = 6) -> str:
    shown = ", ".join(f"({r},{g},{b})" for r, g, b in colors[:limit])
    return shown + (" ..." if len(colors) > limit else "")


class ManualDriver(StimulusDriver):
    name = "manual"

    def __init__(self, prompt: Callable[[str], str] = input, out: Callable[[str], None] = print) -> None:
        self._prompt = prompt
        self._out = out

    def setup(self, led_count: int) -> None:
        self._out(
            f"Manual sweep over {led_count} LED(s). For each step, set the shown state in the "
            f"vendor app, then press Enter to capture (or type 's' to skip a step)."
        )

    def set_state(self, step: SweepStep) -> bool:
        self._out(f"\n[step {step.step_id}] target: {step.describe()}")
        self._out(f"           colors: {_short_colors(step.colors)}")
        answer = self._prompt("           press Enter when set (or 's' to skip) > ")
        return str(answer).strip().lower() != "s"
