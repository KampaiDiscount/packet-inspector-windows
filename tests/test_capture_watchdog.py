"""Nonblocking idle capture and externally supervised progress regression gates."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sys
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from packet_audit.capture import CaptureError, CaptureStats, PcapyLiveSource
from packet_audit.config import AuditConfig
from packet_audit.service_watchdog import ServiceWatchdog, ServiceWatchdogError
from packet_audit.supervisor import AuditSupervisor


class _IdleHandle:
    def __init__(self):
        self.nonblock = 0
        self.closed = False
        self.calls = 0

    def setfilter(self, _value): pass
    def datalink(self): return 1
    def setnonblock(self, value): self.nonblock = value
    def getnonblock(self): return self.nonblock
    def close(self): self.closed = True

    def dispatch(self, _limit, _callback):
        self.calls += 1
        return 0


def _live_source(handle, read_timeout_ms=100):
    module = SimpleNamespace(open_live=lambda *_args: handle)
    return PcapyLiveSource("synthetic0", read_timeout_ms=read_timeout_ms, pcapy_module=module)


@pytest.mark.parametrize("timeout_ms,expected_wait", [(1, 0.001), (25, 0.025), (5000, 0.1)])
def test_idle_live_capture_is_nonblocking_and_wait_is_bounded(timeout_ms, expected_wait):
    handle = _IdleHandle()
    source = _live_source(handle, timeout_ms)
    waits = []
    source._idle_stop = SimpleNamespace(wait=waits.append, set=lambda: None)
    assert source.read_batch() == []
    assert source.read_batch() == []
    assert handle.nonblock == 1
    assert handle.calls == 2
    assert waits == [expected_wait, expected_wait]
    assert not source.eof  # Idle traffic is not EOF or a failure.
    source.close()
    assert source.read_batch() == []
    assert len(waits) == 2


def test_live_capture_with_available_packets_does_not_idle_wait():
    handle = _IdleHandle()
    header = SimpleNamespace(getts=lambda: (1, 0), getcaplen=lambda: 1, getlen=lambda: 1)
    handle.dispatch = lambda _limit, callback: (callback(header, b"x"), 1)[1]
    source = _live_source(handle)
    source._idle_stop = SimpleNamespace(wait=lambda _timeout: pytest.fail("unexpected idle wait"))
    assert len(source.read_batch()) == 1


@pytest.mark.parametrize("mode", ["missing", "negative_result", "still_blocking", "raises"])
def test_nonblocking_setup_failure_is_fatal_and_closes_handle(mode):
    handle = _IdleHandle()
    if mode == "missing":
        handle.setnonblock = None
    elif mode == "negative_result":
        handle.setnonblock = lambda _value: -1
    elif mode == "still_blocking":
        handle.setnonblock = lambda _value: None
    else:
        def fail(_value):
            raise OSError("synthetic unsupported nonblocking mode")
        handle.setnonblock = fail
    with pytest.raises(CaptureError, match="non-blocking|blocking|setnonblock"):
        _live_source(handle)
    assert handle.closed


def test_live_next_fallback_remains_nonblocking_and_idle_bounded():
    handle = _IdleHandle()
    handle.dispatch = None
    handle.next = lambda: (None, None)
    source = _live_source(handle)
    waits = []
    source._idle_stop = SimpleNamespace(wait=waits.append)
    assert source.read_batch() == []
    assert handle.nonblock == 1
    assert waits == [0.1]


def test_watchdog_is_inert_without_service_environment():
    watchdog = ServiceWatchdog.from_environment({})
    watchdog.ready()
    watchdog.progress()
    watchdog.stopping()
    assert not watchdog.ready_sent


def test_watchdog_ignores_environment_for_another_main_pid():
    watchdog = ServiceWatchdog.from_environment({
        "NOTIFY_SOCKET": "/run/synthetic", "WATCHDOG_USEC": "90000000",
        "WATCHDOG_PID": str(os.getpid() + 1),
    })
    assert watchdog.address is None


@pytest.mark.parametrize("environment", [
    {"NOTIFY_SOCKET": "relative-socket"},
    {"NOTIFY_SOCKET": "/run/notify", "WATCHDOG_USEC": "0"},
    {"NOTIFY_SOCKET": "/run/notify", "WATCHDOG_USEC": "invalid"},
    {"WATCHDOG_USEC": "90000000"},
    {"WATCHDOG_PID": "invalid"},
])
def test_invalid_service_configuration_is_visible(environment):
    with pytest.raises(ServiceWatchdogError):
        ServiceWatchdog.from_environment(environment)


def test_watchdog_ready_progress_throttle_and_stopping_are_explicit(monkeypatch):
    now = [10.0]
    monkeypatch.setattr("packet_audit.service_watchdog.time.monotonic", lambda: now[0])
    watchdog = ServiceWatchdog.from_environment({
        "NOTIFY_SOCKET": "/run/synthetic", "WATCHDOG_USEC": "90000000",
        "WATCHDOG_PID": str(os.getpid()),
    })
    sent = []
    monkeypatch.setattr(watchdog, "_send", sent.append)
    with pytest.raises(ServiceWatchdogError, match="before capture startup"):
        watchdog.progress()
    watchdog.ready()
    watchdog.ready()
    watchdog.progress()
    assert len(sent) == 1 and sent[0].startswith("READY=1\n")
    now[0] = 39.9
    watchdog.progress()
    assert len(sent) == 1
    now[0] = 40.0
    watchdog.progress()
    assert sent[-1] == "WATCHDOG=1"
    watchdog.stopping()
    now[0] = 100.0
    watchdog.progress()
    assert len(sent) == 3 and sent[-1].startswith("STOPPING=1\n")


@pytest.mark.parametrize("address,expected", [("/run/notify", "/run/notify"), ("@notify", "\0notify")])
def test_notify_datagram_supports_paths_and_abstract_sockets_with_timeout(monkeypatch, address, expected):
    calls = []
    class FakeSocket:
        def __enter__(self): return self
        def __exit__(self, *_args): pass
        def settimeout(self, seconds): calls.append(("timeout", seconds))
        def sendto(self, payload, destination):
            calls.append((payload, destination))
            return len(payload)
    monkeypatch.setattr("packet_audit.service_watchdog.socket.socket", lambda *_args: FakeSocket())
    monkeypatch.setattr("packet_audit.service_watchdog.socket.AF_UNIX", 1, raising=False)
    ServiceWatchdog(address)._send("WATCHDOG=1")
    assert calls == [("timeout", 0.25), (b"WATCHDOG=1", expected)]


def test_socket_failure_is_not_silently_ignored(monkeypatch):
    def fail(*_args):
        raise OSError("synthetic notification failure")
    monkeypatch.setattr("packet_audit.service_watchdog.socket.socket", fail)
    with pytest.raises(ServiceWatchdogError, match="notification failed"):
        ServiceWatchdog("/run/synthetic").ready()


def test_inherited_watchdog_object_cannot_notify_as_main_process(monkeypatch):
    watchdog = ServiceWatchdog("/run/synthetic")
    watchdog.owner_pid = os.getpid() + 1
    monkeypatch.setattr("packet_audit.service_watchdog.socket.socket",
                        lambda *_args: pytest.fail("non-owner must not open notify socket"))
    watchdog._send("WATCHDOG=1")


@pytest.mark.skipif(sys.platform != "linux", reason="Linux Unix datagram integration")
@pytest.mark.parametrize("abstract", [False, True])
def test_actual_unix_datagram_delivery(tmp_path, abstract):
    address = "@packet-audit-test-" + uuid4().hex if abstract else str(tmp_path / "notify.sock")
    bind_address = "\0" + address[1:] if abstract else address
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as receiver:
        receiver.bind(bind_address)
        receiver.settimeout(1.0)
        watchdog = ServiceWatchdog.from_environment({
            "NOTIFY_SOCKET": address, "WATCHDOG_USEC": "90000000",
            "WATCHDOG_PID": str(os.getpid()),
        })
        watchdog.ready()
        assert receiver.recv(1024).startswith(b"READY=1\n")
        watchdog.last_notification = 0.0
        watchdog.progress()
        assert receiver.recv(1024) == b"WATCHDOG=1"
        watchdog.stopping()
        assert receiver.recv(1024).startswith(b"STOPPING=1\n")


class _RecordingWatchdog(ServiceWatchdog):
    def __init__(self, fail_prefix=None):
        super().__init__("/run/synthetic-only", interval_seconds=0.001)
        self.messages = []
        self.fail_prefix = fail_prefix

    def _send(self, message):
        if self.fail_prefix and message.startswith(self.fail_prefix):
            raise ServiceWatchdogError("synthetic notification failure")
        self.messages.append(message)


class _ControlledSource:
    def __init__(self, blocked=False):
        self.eof = False
        self.closed = False
        self.entered = threading.Event()
        self.release = threading.Event()
        if not blocked:
            self.release.set()

    def read_batch(self):
        self.entered.set()
        if not self.release.wait(5):
            raise RuntimeError("test source was not released")
        self.eof = True
        return []

    def stats(self): return CaptureStats(0, 0, None, 0)
    def close(self): self.closed = True


def _test_supervisor(tmp_path, monkeypatch, watchdog, source):
    config = AuditConfig(
        workers=1, heartbeat_seconds=1, raw_capture_enabled=False,
        output_jsonl=tmp_path / "findings.jsonl", operational_jsonl=tmp_path / "operations.jsonl",
    )
    supervisor = AuditSupervisor(config)
    monkeypatch.setattr(supervisor, "_source", lambda: source)
    monkeypatch.setattr(ServiceWatchdog, "from_environment", lambda: watchdog)
    return supervisor


def test_blocked_capture_sends_no_watchdog_ping_until_loop_completes(tmp_path, monkeypatch):
    watchdog = _RecordingWatchdog()
    source = _ControlledSource(blocked=True)
    supervisor = _test_supervisor(tmp_path, monkeypatch, watchdog, source)
    result, errors = [], []
    def run():
        try:
            result.append(supervisor.run())
        except BaseException as exc:
            errors.append(exc)
    thread = threading.Thread(target=run)
    thread.start()
    try:
        assert source.entered.wait(5)
        before = list(watchdog.messages)
        assert len(before) == 1 and before[0].startswith("READY=1\n")
        time.sleep(0.03)  # Thirty notification intervals without completed capture.
        assert watchdog.messages == before
    finally:
        source.release.set()
        thread.join(10)
    assert not thread.is_alive()
    assert not errors
    assert result[0]["verdict"] == "complete"
    assert watchdog.messages[1] == "WATCHDOG=1"
    assert watchdog.messages[-1].startswith("STOPPING=1\n")


@pytest.mark.parametrize("failure_point", ["WATCHDOG=1", "STOPPING=1"])
def test_notification_failure_cannot_return_complete_verdict(tmp_path, monkeypatch, failure_point):
    watchdog = _RecordingWatchdog(fail_prefix=failure_point)
    watchdog.interval_seconds = 1e-12
    # Some Windows monotonic clocks have coarse granularity for an empty replay.
    original_ready = watchdog.ready
    def ready():
        original_ready()
        watchdog.last_notification = 0.0
    monkeypatch.setattr(watchdog, "ready", ready)
    supervisor = _test_supervisor(tmp_path, monkeypatch, watchdog, _ControlledSource())
    if failure_point == "WATCHDOG=1":
        with pytest.raises(ServiceWatchdogError, match="synthetic notification failure"):
            supervisor.run()
        operations = [json.loads(line) for line in supervisor.config.operational_jsonl.read_text().splitlines()]
        assert any(record["event"] == "session_error" for record in operations)
    else:
        result = supervisor.run()
        assert result["verdict"] == "incomplete"
        assert any("watchdog shutdown notification failed" in reason for reason in result["incomplete_reasons"])


def test_ready_notification_failure_closes_initialized_source(tmp_path, monkeypatch):
    source = _ControlledSource()
    supervisor = _test_supervisor(tmp_path, monkeypatch, _RecordingWatchdog("READY=1"), source)
    with pytest.raises(ServiceWatchdogError, match="synthetic notification failure"):
        supervisor.run()
    assert source.closed
    assert not supervisor.writer.is_alive()
    assert all(not worker.is_alive() for worker in supervisor.workers)


def test_systemd_watchdog_tracks_main_process_and_has_flush_grace():
    root = Path(__file__).resolve().parents[1]
    unit = (root / "systemd/packet-audit@.service").read_text()
    for required in ("Type=notify", "NotifyAccess=main", "WatchdogSec=90s",
                     "TimeoutStartSec=90s", "TimeoutStopSec=75s", "LimitCORE=0"):
        assert required in unit
