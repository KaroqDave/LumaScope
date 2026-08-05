"""Sweep-profile tests.

The `quick` profile exists because a `full` sweep of a 120-LED board is 535 steps, and
under the manual driver every step is a human in a vendor GUI -- roughly three hours of
clicking. Cutting the matrix is only acceptable if the decoder still recovers the same
spec, so that is what these tests assert, per example protocol and at realistic LED counts.
"""

import pytest

from lumascope import examples, orchestrate, synthetic
from lumascope.capture.base import CaptureBackend
from lumascope.cli import _spec_mismatches
from lumascope.decode import decode
from lumascope.model import (
    BrightnessField,
    CaptureFrame,
    ChecksumModel,
    HeaderField,
    LedLayout,
    ProtocolSpec,
    Scaling,
    SweepStep,
)
from lumascope.stimulus import matrix
from lumascope.stimulus.base import StimulusDriver
from lumascope.stimulus.manual import ManualDriver, SweepAborted
from lumascope.synthetic import frame_for_step

FAST = dict(settle=0, quiet=0, poll=0, max_wait=0.5)


def _recovers(spec, steps) -> tuple[bool, list[str]]:
    result = decode(synthetic.generate_corpus(spec, steps=steps), name=spec.name)
    mismatches = _spec_mismatches(spec, result.spec)
    return result.validation.ok and not mismatches, mismatches


# --------------------------------------------------------------------------- #
# The quick profile must not cost accuracy
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("factory", examples.ALL, ids=lambda f: f().name)
def test_quick_profile_recovers_every_example(factory):
    spec = factory()
    steps = matrix.generate(spec.leds.count, profile=matrix.QUICK)
    ok, mismatches = _recovers(spec, steps)
    assert ok, f"{spec.name}: {mismatches}"


def _big(layout: str, n: int, order: str = "RGB") -> ProtocolSpec:
    """A device with a realistic LED count, where `full` becomes impractical."""
    body = 4 + n * 3
    return ProtocolSpec(
        name=f"big-{layout}-{n}", transport="hid_output", report_id=None,
        packet_len=body + 2, header=HeaderField(constant_bytes=[(0, 0xAA)]),
        leds=LedLayout(count=n, layout=layout, base_offset=4,
                       stride=3 if layout == "interleaved" else 1,
                       channel_order=order, scaling=Scaling(type="identity")),
        brightness=BrightnessField(present=False),
        checksum=ChecksumModel(present=True, kind="sum8", offset=body, width=1, range=(0, body)),
    )


@pytest.mark.parametrize("layout", ["interleaved", "planar"])
@pytest.mark.parametrize("n", [30, 120])
def test_quick_profile_recovers_large_devices(layout, n):
    spec = _big(layout, n)
    ok, mismatches = _recovers(spec, matrix.generate(n, profile=matrix.QUICK))
    assert ok, f"{layout} n={n}: {mismatches}"


def test_quick_profile_cost_does_not_grow_with_led_count():
    """The whole point: a 120-LED board costs the operator no more than an 8-LED one."""
    counts = {n: len(matrix.generate(n, profile=matrix.QUICK)) for n in (8, 30, 120, 500)}
    assert len(set(counts.values())) == 1, counts
    assert counts[120] < len(matrix.generate(120, profile=matrix.FULL)) / 10


# --------------------------------------------------------------------------- #
# Why the probed LEDs are contiguous
# --------------------------------------------------------------------------- #
def test_quick_profile_probes_a_contiguous_run_of_leds():
    probed = matrix.probed_leds(120, matrix.QUICK)
    assert probed == list(range(1, len(probed) + 1))


def test_spreading_the_probes_across_the_strip_breaks_planar_detection():
    """Documents the constraint the contiguous prefix exists to satisfy.

    Layout inference compares neighbouring LEDs' offsets. Probing 1, 2, 8, 15 instead of
    1..5 makes a planar device decode as interleaved -- silently, and with a spec that
    looks plausible. If this ever starts passing, the contiguity requirement has been
    relaxed and `probed_leds` can be simplified.
    """
    spec = examples.planar_rgb_xor8()
    gapped = [s for s in matrix.generate(spec.leds.count, profile=matrix.FULL)
              if s.led is None or s.led in (0, 1, 2, 8, 15)]
    ok, mismatches = _recovers(spec, gapped)
    assert not ok
    assert any("layout" in m for m in mismatches), mismatches


def test_full_profile_still_probes_every_led():
    assert matrix.probed_leds(30, matrix.FULL) == list(range(1, 30))


def test_unknown_profile_is_rejected():
    with pytest.raises(ValueError, match="unknown profile"):
        matrix.generate(8, profile="turbo")


def test_describe_reports_steps_and_a_time_estimate():
    assert "46 steps" in matrix.describe(120, matrix.QUICK, seconds_per_step=20)
    assert "hours" in matrix.describe(120, matrix.FULL, seconds_per_step=20)


# --------------------------------------------------------------------------- #
# A long sweep must never lose captured work
# --------------------------------------------------------------------------- #
class _Backend(CaptureBackend):
    name = "mock"

    def open(self) -> None:
        pass

    def close(self) -> None:
        pass


class _Driver(StimulusDriver):
    """Encodes each step, and optionally gives up part-way through."""

    name = "mock"

    def __init__(self, spec, backend, stop_after=None, exc=SweepAborted):
        self.spec, self.backend = spec, backend
        self.stop_after, self.exc = stop_after, exc
        self.applied = 0
        self.total_steps = None

    def setup(self, led_count: int, total_steps: int = 0) -> None:
        self.total_steps = total_steps

    def set_state(self, step: SweepStep) -> bool:
        if self.stop_after is not None and self.applied >= self.stop_after:
            raise self.exc()
        self.applied += 1
        self.backend._push(frame_for_step(self.spec, step))
        return True


def test_driver_is_told_the_step_total_for_progress():
    spec = examples.no_checksum_identity()
    backend = _Backend()
    driver = _Driver(spec, backend)
    steps = matrix.generate(spec.leds.count, profile=matrix.QUICK)
    orchestrate.run_sweep(backend, driver, spec.leds.count, steps=steps, **FAST)
    assert driver.total_steps == len(steps)


@pytest.mark.parametrize("exc", [SweepAborted, KeyboardInterrupt])
def test_stopping_early_keeps_everything_captured_so_far(exc):
    spec = examples.no_checksum_identity()
    backend = _Backend()
    driver = _Driver(spec, backend, stop_after=7, exc=exc)
    corpus, raw = orchestrate.run_sweep(
        backend, driver, spec.leds.count,
        steps=matrix.generate(spec.leds.count, profile=matrix.QUICK), **FAST,
    )
    assert len(raw) == 7
    assert len(corpus.frames) == 7


def test_checkpoint_runs_after_every_step():
    spec = examples.no_checksum_identity()
    backend = _Backend()
    driver = _Driver(spec, backend)
    seen = []
    steps = matrix.generate(spec.leds.count, profile=matrix.QUICK)
    orchestrate.run_sweep(backend, driver, spec.leds.count, steps=steps,
                          checkpoint=lambda c: seen.append(len(c.frames)), **FAST)
    assert seen == list(range(1, len(steps) + 1))


def test_checkpoint_survives_an_abort():
    """The saved file must still hold the work when the operator quits mid-sweep."""
    spec = examples.no_checksum_identity()
    backend = _Backend()
    driver = _Driver(spec, backend, stop_after=4)
    seen = []
    orchestrate.run_sweep(
        backend, driver, spec.leds.count,
        steps=matrix.generate(spec.leds.count, profile=matrix.QUICK),
        checkpoint=lambda c: seen.append(len(c.frames)), **FAST,
    )
    assert seen == [1, 2, 3, 4]


# --------------------------------------------------------------------------- #
# Operator-facing prompt
# --------------------------------------------------------------------------- #
def _manual(answers):
    lines = []
    it = iter(answers)
    return ManualDriver(prompt=lambda _p: next(it), out=lines.append), lines


def test_manual_prompt_shows_position_and_percentage():
    driver, lines = _manual([""] * 3)
    driver.setup(8, total_steps=40)
    driver.set_state(SweepStep(step_id=0, kind="uniform", colors=[(0, 0, 0)] * 8, value=0))
    assert any("[1/40" in ln for ln in lines)
    assert any("%" in ln for ln in lines)


def test_manual_prompt_describes_the_target_in_gui_terms():
    driver, lines = _manual([""])
    driver.setup(8, total_steps=1)
    driver.set_state(SweepStep(step_id=0, kind="per_channel", colors=[(0, 0, 0)] * 8,
                               led=3, channel="G", value=255))
    text = "\n".join(lines)
    assert "LED 3 only" in text and "green" in text


def test_manual_skip_and_quit():
    driver, _ = _manual(["s", "q"])
    driver.setup(4, total_steps=2)
    step = SweepStep(step_id=0, kind="uniform", colors=[(0, 0, 0)] * 4, value=0)
    assert driver.set_state(step) is False
    with pytest.raises(SweepAborted):
        driver.set_state(step)
