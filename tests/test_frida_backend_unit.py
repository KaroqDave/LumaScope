"""Deterministic unit tests for Frida child-gating lifecycle races."""

from __future__ import annotations

import sys
import threading
from types import SimpleNamespace

import pytest

from lumascope.capture.frida_backend import FridaBackend


class FakeScript:
    def __init__(self, backend: FridaBackend, *, load_error=None, load_started=None, load_release=None):
        self.backend = backend
        self.load_error = load_error
        self.load_started = load_started
        self.load_release = load_release
        self.events = {}
        self.loaded = False
        self.unload_count = 0

    def _assert_unlocked(self):
        acquired = self.backend._state_lock.acquire(blocking=False)
        assert acquired, "Frida IPC called while _state_lock was held"
        self.backend._state_lock.release()

    def on(self, event, callback):
        self._assert_unlocked()
        self.events[event] = callback

    def load(self):
        self._assert_unlocked()
        if self.load_started is not None:
            self.load_started.set()
        if self.load_release is not None:
            assert self.load_release.wait(timeout=2), "test did not release script.load()"
        if self.load_error is not None:
            raise self.load_error
        self.loaded = True

    def unload(self):
        self._assert_unlocked()
        self.unload_count += 1


class FakeSession:
    def __init__(self, backend: FridaBackend, script: FakeScript):
        self.backend = backend
        self.script = script
        self.events = {}
        self.child_gating_count = 0
        self.detach_count = 0

    def _assert_unlocked(self):
        acquired = self.backend._state_lock.acquire(blocking=False)
        assert acquired, "Frida IPC called while _state_lock was held"
        self.backend._state_lock.release()

    def on(self, event, callback):
        self._assert_unlocked()
        self.events[event] = callback

    def enable_child_gating(self):
        self._assert_unlocked()
        self.child_gating_count += 1

    def create_script(self, source):
        self._assert_unlocked()
        assert source == "agent source"
        return self.script

    def detach(self):
        self._assert_unlocked()
        self.detach_count += 1


class FakeDevice:
    def __init__(self, backend: FridaBackend, session: FakeSession):
        self.backend = backend
        self.session = session
        self.resumed = []
        self.killed = []
        self.off_callback = None
        self.on_error = None

    def _assert_unlocked(self):
        acquired = self.backend._state_lock.acquire(blocking=False)
        assert acquired, "Frida IPC called while _state_lock was held"
        self.backend._state_lock.release()

    def attach(self, pid):
        self._assert_unlocked()
        return self.session

    def spawn(self, argv):
        self._assert_unlocked()
        return 123

    def on(self, event, callback):
        self._assert_unlocked()
        assert event == "child-added"
        if self.on_error is not None:
            raise self.on_error

    def resume(self, pid):
        self._assert_unlocked()
        self.resumed.append(pid)

    def kill(self, pid):
        self._assert_unlocked()
        self.killed.append(pid)

    def off(self, event, callback):
        self._assert_unlocked()
        assert event == "child-added"
        if self.off_callback is not None:
            self.off_callback()


def make_backend(*, kill_on_close=True, load_error=None, load_started=None, load_release=None):
    backend = FridaBackend(spawn=["fake.exe"], kill_on_close=kill_on_close)
    # A plain Lock makes the fakes' non-blocking acquisition detect accidental lock ownership;
    # unlike RLock, it cannot be reacquired by the same callback thread.
    backend._state_lock = threading.Lock()
    backend._spawned = True
    backend._agent_source = "agent source"
    script = FakeScript(
        backend,
        load_error=load_error,
        load_started=load_started,
        load_release=load_release,
    )
    session = FakeSession(backend, script)
    device = FakeDevice(backend, session)
    backend._device = device
    return backend, device, session, script


def child(pid=222):
    return SimpleNamespace(pid=pid, parent_pid=111, path="child.exe")


@pytest.mark.parametrize("kill_on_close", [True, False])
def test_failed_child_instrumentation_obeys_gated_process_policy(kill_on_close):
    backend, device, session, script = make_backend(
        kill_on_close=kill_on_close,
        load_error=RuntimeError("load failed"),
    )

    backend._on_child_added(child())

    assert backend._sessions == {}
    assert backend._scripts == {}
    assert session.detach_count == 1
    assert script.unload_count == 1
    if kill_on_close:
        assert device.resumed == []
        assert 222 in backend._gated_pids
        backend.close()
        assert device.killed == [222]
    else:
        assert device.resumed == [222]
        assert 222 not in backend._gated_pids
        assert any(level == "warn" and "uninstrumented" in str(message) for level, message in backend.logs)


def test_successful_child_and_close_never_hold_state_lock_during_ipc():
    backend, device, session, script = make_backend()

    backend._on_child_added(child())

    assert device.resumed == [222]
    assert backend._sessions == {222: session}
    assert backend._scripts == {222: script}
    assert not hasattr(backend, "_session")
    assert not hasattr(backend, "_script")

    backend.close()

    assert device.killed == [222]
    assert script.unload_count == 1
    assert session.detach_count == 1
    assert backend._sessions == {}
    assert backend._scripts == {}


@pytest.mark.parametrize("kill_on_close", [True, False])
def test_close_racing_script_load_disposes_unpublished_resources(kill_on_close):
    load_started = threading.Event()
    load_release = threading.Event()
    backend, device, session, script = make_backend(
        kill_on_close=kill_on_close,
        load_started=load_started,
        load_release=load_release,
    )
    callback = threading.Thread(target=backend._on_child_added, args=(child(),))
    callback.start()
    assert load_started.wait(timeout=2)

    backend.close()
    load_release.set()
    callback.join(timeout=2)

    assert not callback.is_alive()
    assert backend._sessions == {}
    assert backend._scripts == {}
    assert script.unload_count == 1
    assert session.detach_count == 1
    if kill_on_close:
        assert device.killed == [222]
        assert device.resumed == []
    else:
        assert device.resumed == [222]
        assert device.killed == []


def test_child_dispatched_during_observer_removal_kills_itself():
    backend, device, _, _ = make_backend()
    backend._watching_children = True
    device.off_callback = lambda: backend._on_child_added(child(333))

    backend.close()

    assert device.killed == [333]
    assert device.resumed == []
    assert backend._closing is True


def test_late_child_is_resumed_when_close_will_not_kill_spawned_processes():
    backend, device, _, _ = make_backend(kill_on_close=False)
    backend.close()

    backend._on_child_added(child(444))

    assert device.resumed == [444]
    assert device.killed == []
    assert 444 not in backend._gated_pids


@pytest.mark.parametrize(
    "failure",
    [RuntimeError("observer registration failed"), KeyboardInterrupt()],
)
def test_open_failure_after_spawn_cleans_up_suspended_process(monkeypatch, failure):
    backend, device, _, _ = make_backend()
    backend._spawned = False
    device.on_error = failure
    fake_frida = SimpleNamespace(get_local_device=lambda: device)
    monkeypatch.setitem(sys.modules, "frida", fake_frida)

    with pytest.raises(type(failure)):
        backend.open()

    assert device.killed == [123]
    assert backend._spawned_pids == set()
    assert backend._gated_pids == set()
    assert backend._closing is True
