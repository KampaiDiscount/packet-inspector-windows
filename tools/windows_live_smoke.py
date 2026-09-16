"""Opt-in native loopback smoke: capture only a new synthetic local HTTP port."""
from __future__ import annotations
import argparse
import base64
import json
import os
from pathlib import Path
import socket
import socketserver
import sys
import threading
import time

if not sys.flags.isolated:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from packet_audit.config import AuditConfig
from packet_audit.supervisor import AuditSupervisor
from packet_audit.capture import OfflineCaptureSource
from packet_audit.writer import prepare_private_directory, verify_export_permissions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--attempts', type=int, default=12)
    args = parser.parse_args()
    if os.name != 'nt' or not 1 <= args.attempts <= 1000:
        raise ValueError('Windows only; use 1..1000 synthetic attempts')
    if args.output.exists():
        raise ValueError('Use a new output directory so no existing evidence is reused')
    output = prepare_private_directory(args.output)

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
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = AuditConfig(interface=r'\Device\NPF_Loopback',
        bpf=f'host 127.0.0.1 and tcp port {server.server_address[1]}',
        workers=2, output_jsonl=output / 'findings-unredacted.jsonl',
        operational_jsonl=output / 'operations.jsonl', raw_capture_dir=output / 'pcap-ring',
        heartbeat_seconds=1, capture_buffer_mb=16, raw_capture_duration_seconds=2)
    supervisor = AuditSupervisor(config)
    errors = []

    def records(path):
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.endswith('}')]

    def client():
        try:
            deadline = time.monotonic() + 25
            while not any(item.get('event') == 'session_started' for item in records(config.operational_jsonl)):
                if time.monotonic() > deadline:
                    raise TimeoutError('Live capture did not acknowledge startup')
                time.sleep(0.05)
            # Keep an idle interval across a ring rotation before traffic arrives.
            time.sleep(2.3)
            basic = base64.b64encode(b'windows-smoke-user:Synthetic-Only-Password!')
            for index in range(args.attempts):
                with socket.create_connection(server.server_address, timeout=3) as connection:
                    connection.sendall(b'GET /synthetic/' + str(index).encode() + b' HTTP/1.1\r\nHost: loopback.test\r\nAuthorization: Basic ' + basic + b'\r\nConnection: close\r\n\r\n')
                    while connection.recv(8192):
                        pass
                time.sleep(0.015)
            deadline = time.monotonic() + 10
            while sum(item.get('detector') == 'http_basic' for item in records(config.output_jsonl)) < args.attempts:
                if time.monotonic() > deadline:
                    raise TimeoutError('Synthetic findings did not reach the export')
                time.sleep(0.05)
            time.sleep(0.3)
        except BaseException as exc:
            errors.append(f'{type(exc).__name__}: {exc}')
        finally:
            supervisor.request_stop()

    sender = threading.Thread(target=client, daemon=True)
    sender.start()
    try:
        result = supervisor.run()
    finally:
        supervisor.request_stop()
        server.shutdown()
        server.server_close()
        sender.join(5)
        thread.join(5)
    findings = records(config.output_jsonl)
    basic_count = sum(item.get('detector') == 'http_basic' for item in findings)
    raw_count = 0
    for capture in config.raw_capture_dir.glob('*.pcapng'):
        with OfflineCaptureSource(capture) as source:
            raw_count += sum(1 for _ in source)
    checks = {'verdict': result['verdict'], 'incomplete_reasons': result['incomplete_reasons'],
        'attempts_sent': args.attempts, 'basic_findings': basic_count,
        'captured_packets': result['captured_packets'], 'raw_ring_packets': raw_count,
        'capture_acl_private': verify_export_permissions(config.output_jsonl)[0],
        'forced_raw_termination': supervisor.raw_ring.forced_termination, 'errors': errors}
    (output / 'smoke-summary.json').write_text(json.dumps(checks, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(checks, indent=2))
    return 0 if not errors and basic_count == args.attempts and result['verdict'] == 'complete' and raw_count else 1


if __name__ == '__main__':
    raise SystemExit(main())
