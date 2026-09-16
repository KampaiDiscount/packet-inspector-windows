"""Synthetic app/launcher tests; never run setup, capture, or native discovery."""
from dataclasses import asdict
from datetime import datetime, timezone
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from packet_audit import windows_app as app
from packet_audit.config import AuditConfig


DEVICES = [r'\Device\NPF_{11111111-1111-1111-1111-111111111111}',
           r'\Device\NPF_Loopback']


@pytest.fixture
def interfaces(monkeypatch):
    backend = SimpleNamespace(findalldevs=Mock(return_value=list(DEVICES)))
    monkeypatch.setattr(app, '_load_pcapy', lambda: backend)
    monkeypatch.setattr(app, 'find_dumpcap', lambda: None)
    monkeypatch.setattr(app.subprocess, 'run', Mock(side_effect=AssertionError('Unexpected subprocess')))
    monkeypatch.setattr('builtins.input', Mock(side_effect=AssertionError('Unexpected prompt')))
    return backend


@pytest.mark.parametrize('requested', DEVICES)
def test_exact_interface_selection_never_prompts_or_probes_dumpcap(interfaces, requested):
    assert app.select_interface(requested) == requested
    app.subprocess.run.assert_not_called()


@pytest.mark.parametrize('number,index', [('1', 0), ('2', 1)])
def test_number_selection_uses_the_displayed_npcap_order(interfaces, number, index):
    assert app.select_interface(number) == DEVICES[index]


@pytest.mark.parametrize('requested', ['', '0', '3', '-1', '1abc', 'Ethernet', r'\Device\NPF_{missing}'])
def test_invalid_explicit_selection_has_no_default_or_reprompt(interfaces, requested):
    with pytest.raises(ValueError, match='Interface was not found'):
        app.select_interface(requested)


def test_no_interfaces_does_not_prompt_or_fall_back(interfaces):
    interfaces.findalldevs.return_value = []
    with pytest.raises(RuntimeError, match='did not enumerate'):
        app.select_interface(None)


def test_prompt_number_selection_is_explicit(interfaces, monkeypatch, capsys):
    prompt = Mock(return_value=' 2 ')
    monkeypatch.setattr('builtins.input', prompt)
    assert app.select_interface(None) == DEVICES[1]
    prompt.assert_called_once()
    output = capsys.readouterr().out
    assert all(name in output for name in DEVICES)


def test_prompt_accepts_an_exact_enumerated_device_name(interfaces, monkeypatch):
    monkeypatch.setattr('builtins.input', lambda _prompt: DEVICES[1])
    assert app.select_interface(None) == DEVICES[1]


def test_empty_prompt_is_not_an_implicit_first_interface(interfaces, monkeypatch):
    monkeypatch.setattr('builtins.input', lambda _prompt: '')
    with pytest.raises(ValueError):
        app.select_interface(None)


def test_dumpcap_label_order_cannot_remap_numeric_selection(interfaces, monkeypatch):
    monkeypatch.setattr(app, 'find_dumpcap', lambda: 'synthetic-dumpcap')
    run = Mock(return_value=SimpleNamespace(returncode=0,
        stdout=f'1. {DEVICES[1]} (Loopback label)\n2. {DEVICES[0]} (Ethernet label)\n'))
    monkeypatch.setattr(app.subprocess, 'run', run)
    assert app.select_interface('1') == DEVICES[0]
    assert run.call_args.args[0] == ['synthetic-dumpcap', '-D']


@pytest.mark.parametrize('offline', [False, True])
def test_generated_toml_roundtrips_every_config_field(tmp_path, offline):
    config, path = app.new_run_config(tmp_path / 'synthetic évidence',
        interface=DEVICES[0], bpf='tcp and (port 12345 or port 12346)', offline=offline)
    assert asdict(AuditConfig.from_toml(path)) == asdict(config)
    assert config.raw_capture_enabled is not offline
    assert not config.console_unredacted and not config.console_findings
    assert config.output_jsonl.parent == path.parent
    assert config.operational_jsonl.parent == path.parent
    assert config.raw_capture_dir == path.parent / 'pcap-ring'
    assert config.raw_capture_dir.is_dir()
    assert b'\r\n' not in path.read_bytes()
    assert not config.output_jsonl.exists()  # Configuration creation is not capture.


def test_multiple_runs_in_one_second_never_share_evidence(tmp_path, monkeypatch):
    instant = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(app, 'datetime', SimpleNamespace(now=lambda _zone: instant))
    paths = [app.new_run_config(tmp_path / 'runs', interface=DEVICES[0])[1] for _ in range(8)]
    assert len(set(paths)) == 8
    assert all(path.parent.name.startswith('20260916T120000Z-') for path in paths)


def test_forced_session_collision_fails_without_overwriting_config(tmp_path, monkeypatch):
    instant = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(app, 'datetime', SimpleNamespace(now=lambda _zone: instant))
    monkeypatch.setattr(app, 'uuid4', lambda: SimpleNamespace(hex='a' * 32))
    _, path = app.new_run_config(tmp_path / 'runs', interface=DEVICES[0])
    before = path.read_bytes()
    with pytest.raises(FileExistsError):
        app.new_run_config(tmp_path / 'runs', interface=DEVICES[1])
    assert path.read_bytes() == before


@pytest.fixture
def safe_app(monkeypatch):
    # Runtime, native interfaces, child processes and browser are all forbidden
    # unless a test explicitly supplies a harmless stand-in.
    for name in ('_run_runtime', 'doctor', 'select_interface', 'list_interfaces'):
        monkeypatch.setattr(app, name, Mock(side_effect=AssertionError('Unmocked app operation: ' + name)))
    monkeypatch.setattr(app.subprocess, 'Popen', Mock(side_effect=AssertionError('Unexpected child process')))
    monkeypatch.setattr(app.webbrowser, 'open', Mock(side_effect=AssertionError('Unexpected browser')))
    monkeypatch.setattr(app.time, 'sleep', lambda _seconds: None)


@pytest.mark.skipif(os.name != 'nt', reason='Windows app guard')
def test_app_interfaces_only_lists_without_capture_or_setup(safe_app, monkeypatch):
    listing = Mock(return_value=0)
    monkeypatch.setattr(app, 'list_interfaces', listing)
    assert app.main(['interfaces']) == 0
    listing.assert_called_once()
    app._run_runtime.assert_not_called()


@pytest.mark.skipif(os.name != 'nt', reason='Windows app guard')
def test_failed_doctor_prevents_runtime_and_dashboard(tmp_path, safe_app, monkeypatch):
    monkeypatch.setattr(app, 'select_interface', lambda _requested: DEVICES[0])
    monkeypatch.setattr(app, 'doctor', Mock(return_value=1))
    assert app.main(['start', '--output-root', str(tmp_path / 'runs')]) == 1
    app._run_runtime.assert_not_called()
    app.subprocess.Popen.assert_not_called()


@pytest.mark.skipif(os.name != 'nt', reason='Windows app guard')
def test_missing_replay_file_is_rejected_before_session_creation(tmp_path, safe_app):
    output = tmp_path / 'not-created'
    assert app.main(['replay', str(tmp_path / 'absent.pcap'), '--output-root', str(output)]) == 1
    assert not output.exists()
    app._run_runtime.assert_not_called()


@pytest.mark.skipif(os.name != 'nt', reason='Windows app guard')
def test_replay_passes_only_explicit_file_to_mock_runtime(tmp_path, safe_app, monkeypatch):
    capture = tmp_path / 'synthetic.pcap'
    capture.write_bytes(b'not read: runtime is mocked')
    runtime = Mock(return_value=2)
    monkeypatch.setattr(app, '_run_runtime', runtime)
    assert app.main(['replay', str(capture), '--output-root', str(tmp_path / 'runs'), '--no-dashboard']) == 2
    config, passed_capture = runtime.call_args.args
    assert passed_capture == capture and not config.raw_capture_enabled
    assert config.interface == 'offline'
    app.select_interface.assert_not_called()
    app.doctor.assert_not_called()


@pytest.mark.skipif(os.name != 'nt', reason='Windows app guard')
@pytest.mark.parametrize('isolated', [0, 1])
def test_dashboard_child_is_loopback_hidden_and_closed_after_runtime(tmp_path, safe_app, monkeypatch, isolated):
    capture = tmp_path / 'synthetic.pcap'
    capture.write_bytes(b'not read: runtime is mocked')
    process = Mock()
    process.poll.return_value = None
    popen = Mock(return_value=process)
    monkeypatch.setattr(app.subprocess, 'Popen', popen)
    monkeypatch.setattr(app, '_run_runtime', Mock(return_value=0))
    monkeypatch.setattr(app, 'sys', SimpleNamespace(executable=app.sys.executable,
        flags=SimpleNamespace(isolated=isolated), stdin=SimpleNamespace(isatty=lambda: False), stderr=app.sys.stderr))
    assert app.main(['replay', str(capture), '--output-root', str(tmp_path / 'runs'), '--no-browser']) == 0
    command = popen.call_args.args[0]
    assert command[command.index('--host') + 1] == '127.0.0.1'
    assert '--no-auth' in command
    assert ('-I' in command) is bool(isolated)
    assert popen.call_args.kwargs['creationflags'] == app.subprocess.CREATE_NO_WINDOW
    process.terminate.assert_called_once()
    assert popen.call_args.kwargs['stderr'].closed


@pytest.mark.skipif(os.name != 'nt', reason='Windows app guard')
@pytest.mark.parametrize('failure', ['terminate', 'kill', 'final_wait'])
def test_dashboard_cleanup_errors_close_log_and_preserve_capture_result(tmp_path, safe_app, monkeypatch, capsys, failure):
    capture = tmp_path / 'synthetic.pcap'
    capture.write_bytes(b'not read: runtime is mocked')
    process = Mock(pid=987)
    process.poll.return_value = None
    popen = Mock(return_value=process)
    if failure == 'terminate':
        process.terminate.side_effect = PermissionError('synthetic viewer termination failure')
    else:
        process.wait.side_effect = app.subprocess.TimeoutExpired('synthetic viewer', 5)
        if failure == 'kill':
            process.kill.side_effect = PermissionError('synthetic viewer kill failure')
    monkeypatch.setattr(app.subprocess, 'Popen', popen)
    monkeypatch.setattr(app, '_run_runtime', Mock(return_value=2))
    monkeypatch.setattr(app, 'sys', SimpleNamespace(executable=app.sys.executable,
        flags=SimpleNamespace(isolated=1), stdin=SimpleNamespace(isatty=lambda: False), stderr=app.sys.stderr))
    assert app.main(['replay', str(capture), '--output-root', str(tmp_path / 'runs'), '--no-browser']) == 2
    assert popen.call_args.kwargs['stderr'].closed
    assert 'Viewer cleanup failed for owned PID 987' in capsys.readouterr().err


def test_cmd_launchers_preserve_exit_code_and_use_quoted_local_script():
    root = Path(app.__file__).resolve().parents[1]
    for name, mode in [('SETUP.cmd', 'Setup'), ('START-PACKET-INSPECTOR.cmd', 'Start'),
                       ('LIST-INTERFACES.cmd', 'Interfaces'), ('REPLAY-PCAP.cmd', 'Replay')]:
        source = (root / name).read_text()
        assert '"%~dp0windows\\Packet-Inspector.ps1"' in source
        assert f'-Mode {mode}' in source
        assert 'set "RC=%ERRORLEVEL%"' in source
        assert 'exit /b %RC%' in source


def test_setup_uses_only_bundled_wheel_without_dependency_download():
    source = (Path(app.__file__).resolve().parents[1] / 'windows' / 'Packet-Inspector.ps1').read_text()
    assert '-m pip install --no-index --no-deps --force-reinstall' in source
    assert "'packet_inspector_windows-*.whl'" in source
    assert 'Invoke-Expression' not in source
    assert '-m venv' in source


def test_setup_validates_reused_environment_before_install_and_checks_installed_cli():
    source = (Path(app.__file__).resolve().parents[1] / 'windows' / 'Packet-Inspector.ps1').read_text()
    validation = source.index('& $environmentPython -I -c')
    install = source.index('& $environmentPython -m pip install')
    assert validation < install
    assert 'sys.version_info >= (3,11)' in source[validation:install]
    assert 'sys.maxsize > 2**32' in source[validation:install]
    assert '$LASTEXITCODE -ne 0' in source[validation:install]
    check = source.index('& $environmentPython -I -m packet_audit --version')
    success = source.index("Write-Host 'Setup complete.")
    assert check < success
    assert '$LASTEXITCODE -ne 0' in source[check:success]
    assert "$runtimeArguments=@('-I','-m','packet_audit.windows_app'" in source
