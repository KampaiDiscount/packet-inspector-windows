"""Synthetic process/file tests only: never start dumpcap or signal a console."""
import io
import json
import os
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from packet_audit.capture import CaptureStats
from packet_audit.config import AuditConfig
from packet_audit.raw_capture import DumpcapRing, build_dumpcap_command
from packet_audit.supervisor import AuditSupervisor


def _config(tmp_path, **options):
    return AuditConfig(workers=1, raw_capture_dir=tmp_path / 'ring',
                       output_jsonl=tmp_path / 'findings.jsonl',
                       operational_jsonl=tmp_path / 'operations.jsonl', **options)


def test_optional_basename_preserves_builder_compatibility(tmp_path):
    config = _config(tmp_path)
    original = build_dumpcap_command(config)
    assert Path(original[original.index('-w') + 1]).name == 'packet-audit.pcapng'
    custom = build_dumpcap_command(config, basename='unique.pcapng')
    assert Path(custom[custom.index('-w') + 1]).name == 'unique.pcapng'


@pytest.mark.parametrize('basename', ['', '.', '..', '../escape', r'folder\escape', 'file:stream', 'x\x00y'])
def test_raw_basename_cannot_escape_private_directory(tmp_path, basename):
    with pytest.raises(ValueError):
        build_dumpcap_command(_config(tmp_path), basename=basename)


def test_each_raw_start_uses_fresh_uuid_prefix_and_closes_old_stderr(tmp_path, monkeypatch):
    process = Mock(pid=123)
    process.poll.return_value = None
    launched = []
    def popen(command, **_kwargs):
        launched.append(list(command))
        process.poll.return_value = None
        return process
    monkeypatch.setattr('packet_audit.raw_capture.find_dumpcap', lambda _name: 'synthetic-dumpcap')
    monkeypatch.setattr('packet_audit.raw_capture.subprocess.Popen', popen)
    monkeypatch.setattr('packet_audit.raw_capture.time.sleep', lambda _seconds: None)
    ring = DumpcapRing(_config(tmp_path))
    try:
        ring.start()
        first_stderr = ring.stderr_handle
        process.poll.return_value = 0
        ring.start()
        assert first_stderr.closed
        names = [Path(command[command.index('-w') + 1]).name for command in launched]
        assert len(names) == 2 and names[0] != names[1]
        assert all(re.fullmatch(r'packet-audit-[0-9a-f]{32}\.pcapng', name) for name in names)
    finally:
        ring._close_stderr()


def test_stop_without_child_still_closes_stderr(tmp_path):
    ring = DumpcapRing(_config(tmp_path))
    stream = ring.stderr_handle = io.BytesIO()
    ring.stop()
    assert stream.closed and ring.stderr_handle is None


@pytest.mark.skipif(os.name != 'nt', reason='Mocked Windows shutdown branch')
@pytest.mark.parametrize('failure', ['terminate', 'final_wait'])
def test_shutdown_failure_always_closes_stderr(tmp_path, monkeypatch, failure):
    ring = DumpcapRing(_config(tmp_path))
    ring.process = Mock(pid=123)
    ring.process.poll.return_value = None
    stream = ring.stderr_handle = io.BytesIO()
    if failure == 'terminate':
        monkeypatch.setattr('packet_audit.raw_capture.subprocess.run', Mock(side_effect=OSError('helper unavailable')))
        ring.process.terminate.side_effect = PermissionError('synthetic termination refusal')
        expected = PermissionError
    else:
        monkeypatch.setattr('packet_audit.raw_capture.subprocess.run', Mock(return_value=None))
        ring.process.wait.side_effect = subprocess.TimeoutExpired('synthetic process', 1)
        expected = subprocess.TimeoutExpired
    with pytest.raises(expected):
        ring.stop(timeout=1)
    assert stream.closed and ring.stderr_handle is None
    assert ring.forced_termination
    if failure == 'final_wait':
        ring.process.kill.assert_called_once()


@pytest.mark.skipif(os.name != 'nt', reason='Mocked Windows shutdown branch')
@pytest.mark.parametrize('isolated', [0, 1])
def test_successful_windows_console_request_does_not_force_termination(tmp_path, monkeypatch, isolated):
    from packet_audit import raw_capture
    ring = DumpcapRing(_config(tmp_path))
    process = ring.process = Mock(pid=123)
    process.poll.return_value = None
    process.wait.side_effect = lambda **_kwargs: setattr(process.poll, 'return_value', 0)
    helper = Mock(return_value=None)
    monkeypatch.setattr('packet_audit.raw_capture.subprocess.run', helper)
    monkeypatch.setattr(raw_capture, 'sys', SimpleNamespace(executable=raw_capture.sys.executable,
                                                          flags=SimpleNamespace(isolated=isolated)))
    status = ring.stop()
    assert not status.running and not status.forced_termination
    process.terminate.assert_not_called()
    assert helper.call_args.kwargs['creationflags'] == subprocess.CREATE_NO_WINDOW
    assert ('-I' in helper.call_args.args[0]) is bool(isolated)


class _EmptySource:
    eof = False
    def read_batch(self):
        self.eof = True
        return []
    def stats(self): return CaptureStats(0, 0, 0)
    def close(self): pass


def test_raw_shutdown_failure_does_not_skip_worker_and_writer_finalization(tmp_path, monkeypatch):
    # Normal synthetic multiprocessing/export path, with no native capture or
    # dumpcap process. Only the raw-ring stop call is fault-injected.
    config = _config(tmp_path, raw_capture_enabled=False)
    supervisor = AuditSupervisor(config)
    monkeypatch.setattr(supervisor, '_source', _EmptySource)
    monkeypatch.setattr(supervisor.raw_ring, 'stop', Mock(side_effect=PermissionError('synthetic shutdown refusal')))
    result = supervisor.run()
    assert result['verdict'] == 'incomplete'
    assert any('raw capture shutdown failed' in reason for reason in result['incomplete_reasons'])
    assert not supervisor.writer.is_alive()
    assert all(not worker.is_alive() for worker in supervisor.workers)
    records = [json.loads(line) for line in config.operational_jsonl.read_text().splitlines()]
    assert any(record['event'] == 'raw_capture_shutdown_error' for record in records)
    assert any(record['event'] == 'session_stopped' for record in records)


@pytest.mark.parametrize('platform,parent,expected', [('nt', object(), 2), ('nt', None, 0), ('posix', object(), 0)])
def test_child_interrupt_policy_changes_only_windows_multiprocessing_children(monkeypatch, platform, parent, expected):
    from packet_audit import process_signals
    registration = Mock()
    monkeypatch.setattr(process_signals, 'os', SimpleNamespace(name=platform))
    monkeypatch.setattr(process_signals, 'mp', SimpleNamespace(parent_process=lambda: parent))
    monkeypatch.setattr(process_signals, 'signal', SimpleNamespace(
        signal=registration, SIGINT=2, SIGBREAK=21, SIG_IGN=1))
    process_signals.ignore_windows_child_interrupts()
    assert registration.call_count == expected
    if expected:
        assert registration.call_args_list[0].args == (2, 1)
        assert registration.call_args_list[1].args == (21, 1)


def test_child_signal_registration_failure_is_not_silently_ignored(monkeypatch):
    from packet_audit import process_signals
    monkeypatch.setattr(process_signals, 'os', SimpleNamespace(name='nt'))
    monkeypatch.setattr(process_signals, 'mp', SimpleNamespace(parent_process=lambda: object()))
    monkeypatch.setattr(process_signals, 'signal', SimpleNamespace(
        signal=Mock(side_effect=OSError('synthetic registration failure')), SIGINT=2, SIGBREAK=21, SIG_IGN=1))
    with pytest.raises(OSError, match='registration failure'):
        process_signals.ignore_windows_child_interrupts()


@pytest.mark.parametrize('role', ['worker', 'writer'])
def test_child_entrypoint_installs_signal_policy_before_any_processing(monkeypatch, role):
    from packet_audit import worker, writer
    module = worker if role == 'worker' else writer
    sentinel = RuntimeError('signal policy reached before processing')
    guard = Mock(side_effect=sentinel)
    monkeypatch.setattr(module, 'ignore_windows_child_interrupts', guard)
    with pytest.raises(RuntimeError, match='signal policy reached'):
        if role == 'worker':
            worker.worker_process(0, None, None, None, None, 'synthetic')
        else:
            writer.writer_process(None, None, None, None, False)
    guard.assert_called_once()


@pytest.mark.skipif(os.name != 'nt', reason='Windows SIGBREAK registration')
def test_supervisor_registers_and_restores_ctrl_break_stop_handler(tmp_path, monkeypatch):
    import signal
    from packet_audit import supervisor as supervisor_module
    previous = object()
    register = Mock(return_value=previous)
    monkeypatch.setattr(supervisor_module.signal, 'signal', register)
    supervisor = AuditSupervisor(_config(tmp_path, raw_capture_enabled=False))
    monkeypatch.setattr(supervisor, '_source', _EmptySource)
    result = supervisor.run()
    assert result['verdict'] == 'complete'
    break_calls = [call.args for call in register.call_args_list if call.args[0] == signal.SIGBREAK]
    assert break_calls == [(signal.SIGBREAK, supervisor.request_stop), (signal.SIGBREAK, previous)]
