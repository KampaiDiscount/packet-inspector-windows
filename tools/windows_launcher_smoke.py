"""Opt-in installed launcher/HTTP viewer/Ctrl+C test on synthetic loopback only."""
from __future__ import annotations
import argparse
import base64
import json
from pathlib import Path
import re
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

if not sys.flags.isolated:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from packet_audit.writer import prepare_private_directory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('Use a new synthetic output directory')
    output = prepare_private_directory(args.output)
    python = args.package / '.venv' / 'Scripts' / 'python.exe'
    if not python.is_file():
        raise ValueError('Run package setup first')

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            data = b''
            while b'\r\n\r\n' not in data and len(data) < 8192:
                chunk = self.request.recv(8192)
                if not chunk:
                    return
                data += chunk
            self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK')

    server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        viewer_port = probe.getsockname()[1]
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0
    command = ['powershell.exe', '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', str(args.package / 'windows' / 'Packet-Inspector.ps1'), '-Mode', 'Start',
        '-Interface', r'\Device\NPF_Loopback', '-Bpf', f'host 127.0.0.1 and tcp port {server.server_address[1]}',
        '-OutputRoot', str(output / 'runs'), '-Port', str(viewer_port), '-NoBrowser']
    process = None
    session = None

    def records(path):
        if not path.is_file():
            return []
        return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.endswith('}')]

    with (output / 'launcher-output.log').open('xb', buffering=0) as log:
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                cwd=str(output), creationflags=subprocess.CREATE_NEW_CONSOLE, startupinfo=startup)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                candidates = list((output / 'runs').glob('*/operations.jsonl'))
                if candidates and any(item.get('event') == 'session_started' for item in records(candidates[0])):
                    session = candidates[0].parent
                    break
                if process.poll() is not None:
                    raise RuntimeError('Launcher exited before capture startup; see private launcher log')
                time.sleep(0.1)
            if session is None:
                raise TimeoutError('Launcher capture startup timed out')
            token = base64.b64encode(b'launcher-smoke-user:Synthetic-Only-Password!')
            for index in range(12):
                with socket.create_connection(server.server_address, timeout=3) as connection:
                    connection.sendall(b'GET /launcher/' + str(index).encode() + b' HTTP/1.1\r\nHost: loopback.test\r\nAuthorization: Basic ' + token + b'\r\nConnection: close\r\n\r\n')
                    while connection.recv(8192):
                        pass
            deadline = time.monotonic() + 10
            page = {}
            while time.monotonic() < deadline:
                try:
                    with urllib.request.urlopen(f'http://127.0.0.1:{viewer_port}/api/findings?limit=500', timeout=2) as response:
                        page = json.load(response)
                    if len(page.get('records', [])) == 12:
                        break
                except urllib.error.URLError:
                    pass
                time.sleep(0.1)
            visible = page.get('records', [])
            assert len(visible) == 12, 'Dashboard must show all twelve synthetic findings'
            assert all(item.get('source_endpoint', '').startswith('127.0.0.1:') and
                       item.get('destination_endpoint', '').startswith('127.0.0.1:') for item in visible)
            # Signal only this newly-created owned hidden console, exactly as
            # pressing Ctrl+C in its foreground launcher window would do.
            subprocess.run([str(python), '-I', '-m', 'packet_audit.windows_control', str(process.pid), '0'],
                check=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
            process.wait(timeout=35)
            operations = records(session / 'operations.jsonl')
            stopped = [item for item in operations if item.get('event') == 'session_stopped']
            assert stopped, 'Console stop must persist a final session verdict'
            # The engine prints its post-writer verdict after the durable
            # session_stopped/writer_stopped records; do not confuse the two.
            transcript = (output / 'launcher-output.log').read_text(encoding='utf-8')
            summaries = []
            for match in re.finditer(r'^\{', transcript, re.MULTILINE):
                item, _end = json.JSONDecoder().raw_decode(transcript[match.start():])
                if 'verdict' in item:
                    summaries.append(item)
            assert summaries, 'Final post-writer verdict must be printed'
            final = summaries[-1]
            assert final.get('verdict') == 'complete', f'Unexpected verdict: {final.get("verdict")}'
            assert any(item.get('event') == 'writer_stopped' and item.get('findings_written') == 12 for item in operations)
            findings = records(session / 'findings-unredacted.jsonl')
            assert len(findings) == 12
            with socket.socket() as check:
                check.settimeout(1)
                viewer_closed = check.connect_ex(('127.0.0.1', viewer_port)) != 0
            assert viewer_closed, 'Owned dashboard was not closed'
            summary = {'launcher': 'Windows PowerShell 5.1', 'isolated_installed_package': True,
                'synthetic_attempts': 12, 'dashboard_findings': len(visible), 'jsonl_findings': len(findings),
                'endpoints_displayed': True, 'real_console_ctrl_c': True,
                'verdict': final.get('verdict'), 'viewer_closed': viewer_closed,
                'launcher_exitcode': process.returncode}
            (output / 'launcher-summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
            print(json.dumps(summary, indent=2))
        finally:
            server.shutdown()
            server.server_close()
            if process is not None and process.poll() is None:
                # Best effort graceful stop of ONLY the owned test console.
                subprocess.run([str(python), '-I', '-m', 'packet_audit.windows_control', str(process.pid), '0'],
                    timeout=5, check=False, creationflags=subprocess.CREATE_NO_WINDOW)
                process.wait(timeout=35)


if __name__ == '__main__':
    main()
