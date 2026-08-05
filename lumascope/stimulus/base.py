"""Stimulus driver interface.

A driver puts the device into a known state (the ``SweepStep``'s per-LED colors) so the
capture that follows is *labeled*. The orchestrator calls, per step:

    driver.setup(led_count)        # once, before the sweep
    driver.set_state(step)         # drive the device / wait for the operator to
    driver.teardown()              # once, after

Preference order (API/CLI > config > GUI): an API driver like OpenRGB makes the commanded
color *the* ground-truth label deterministically; the manual driver is the realistic
fallback for a device with no programmable interface (you change the colour in the vendor
app and confirm). ``set_state`` returns True once the target state is believed applied.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..model import SweepStep


class StimulusDriver(ABC):
    name = "base"

    def setup(self, led_count: int, total_steps: int = 0) -> None:
        """Optional one-time preparation (connect, select device, enter a static mode).

        ``total_steps`` lets an operator-facing driver show progress; drivers that do not
        need it ignore it.
        """

    @abstractmethod
    def set_state(self, step: SweepStep) -> bool:
        """Drive the device to ``step.colors``. Return True if the state was applied."""

    def teardown(self) -> None:
        """Optional cleanup (disconnect, restore)."""
