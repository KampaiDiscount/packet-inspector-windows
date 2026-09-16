"""Windows interactive launcher; explicit adapter choice and unique private runs."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from uuid import uuid4
import webbrowser

from .capture import _load_pcapy
from .cli import _run_runtime, doctor, list_interfaces
from .config import AuditConfig, _CONFIG_SECTION_KEYS
from .platform_tools import find_dumpcap
from .writer import prepare_private_directory


def select_interface(requested: str | None) -> str:
    interfaces = _load_pcapy().findalldevs()
    if not interfaces:
        raise RuntimeError('Npcap did not enumerate any interfaces; check driver installation and capture permissions')
    if requested and requested in interfaces:
        return requested
    labels = {}
    dumpcap = find_dumpcap()
    if dumpcap:
        result = subprocess.run([dumpcap, '-D'], capture_output=True, text=True, timeout=15, check=False)
        for line in result.stdout.splitlines():
            match = re.match(r'^\d+\.\s+(\S+)\s+(.*)$', line)
            if match:
                labels[match.group(1)] = match.group(2)
    if requested is None:
        for index, name in enumerate(interfaces, 1):
            print(f'{index:2}. {labels.get(name, "")}  {name}')
        requested = input('Select the authorized capture interface number (no automatic default): ').strip()
    if requested in interfaces:
        return requested
    if requested.isdecimal() and 1 <= int(requested) <= len(interfaces):
        return interfaces[int(requested) - 1]
    raise ValueError('Interface was not found; use a displayed number or exact Npcap device name')


def new_run_config(root: Path, *, interface: str, bpf: str = 'ip or ip6', offline: bool = False) -> tuple[AuditConfig, Path]:
    root = prepare_private_directory(root)
    directory = root / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + uuid4().hex[:12])
    prepare_private_directory(directory)
    ring = prepare_private_directory(directory / 'pcap-ring')
    config = AuditConfig(interface=interface, bpf=bpf, raw_capture_enabled=not offline,
        output_jsonl=directory / 'findings-unredacted.jsonl', operational_jsonl=directory / 'operations.jsonl',
        raw_capture_dir=ring)
    config.validate()
    lines = []
    for section, names in _CONFIG_SECTION_KEYS.items():
        lines.append(f'[{section}]')
        for name in sorted(names):
            value = getattr(config, name)
            if isinstance(value, Path):
                value = str(value)
            lines.append(f'{name} = {json.dumps(value, ensure_ascii=False)}')
        lines.append('')
    config_path = directory / 'session.toml'
    with config_path.open('x', encoding='utf-8', newline='\n') as output:
        output.write('\n'.join(lines))
    return config, config_path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['start', 'interfaces', 'replay'])
    parser.add_argument('capture', nargs='?', type=Path)
    parser.add_argument('--interface')
    parser.add_argument('--filter', default='ip or ip6')
    parser.add_argument('--output-root', type=Path, default=Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'PacketInspector-Windows' / 'evidence')
    parser.add_argument('--port', type=int, default=8766)
    parser.add_argument('--no-dashboard', action='store_true')
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args(argv)
    dashboard = None
    log_handle = None
    try:
        if os.name != 'nt':
            raise ValueError('This convenience launcher is for Windows; use packet-audit on other systems')
        if args.mode == 'interfaces':
            return list_interfaces()
        if not 1 <= args.port <= 65535:
            raise ValueError('Dashboard port must be 1..65535')
        offline = args.mode == 'replay'
        if offline and (not args.capture or not args.capture.is_file()):
            raise ValueError('Replay needs an existing PCAP/PCAPNG file')
        interface = 'offline' if offline else select_interface(args.interface)
        config, config_path = new_run_config(args.output_root, interface=interface, bpf=args.filter, offline=offline)
        evidence = config.output_jsonl.parent
        print(f'Private evidence: {evidence}\nSaved configuration: {config_path}')
        if not offline and doctor(config):
            raise RuntimeError('Preflight failed; no capture was started')
        if not args.no_dashboard:
            log_handle = (evidence / 'dashboard.stderr.log').open('xb', buffering=0)
            dashboard = subprocess.Popen([sys.executable, *(['-I'] if sys.flags.isolated else []), '-m', 'packet_audit', 'serve',
                '--evidence-dir', str(evidence), '--host', '127.0.0.1', '--port', str(args.port), '--no-auth'],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log_handle,
                creationflags=subprocess.CREATE_NO_WINDOW)
            time.sleep(0.5)
            if dashboard.poll() is not None:
                raise RuntimeError(f'Dashboard could not start; check {evidence / "dashboard.stderr.log"} or choose another --port')
            print(f'Live dashboard: http://127.0.0.1:{args.port}/ (local clients only, no token)')
            if not args.no_browser:
                webbrowser.open(f'http://127.0.0.1:{args.port}/')
        print('Ctrl+C stops capture and drains pending analysis. Wait for the final verdict.')
        result = _run_runtime(config, args.capture if offline else None)
        if offline and dashboard is not None and sys.stdin.isatty():
            input('Replay finished; press Enter to close its dashboard. ')
        return result
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, RuntimeError) as exc:
        print(f'Packet Inspector: {exc}', file=sys.stderr)
        return 1
    finally:
        try:
            if dashboard is not None and dashboard.poll() is None:
                dashboard.terminate()  # Read-only viewer; no capture/evidence writer is killed.
                try:
                    dashboard.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    dashboard.kill()
                    dashboard.wait(timeout=5)
        except (OSError, subprocess.SubprocessError) as exc:
            print(f'Viewer cleanup failed for owned PID {dashboard.pid}: {exc}; check that local viewer manually.', file=sys.stderr)
        finally:
            if log_handle is not None:
                log_handle.close()


if __name__ == '__main__':
    raise SystemExit(main())
