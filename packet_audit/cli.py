"""Command-line interface for live capture, replay, and preflight diagnostics."""

from __future__ import annotations

import argparse
from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Sequence

from . import __version__
from .config import AuditConfig
from .raw_capture import DumpcapRing
from .supervisor import AuditSupervisor
from .writer import validate_evidence_paths, verify_export_permissions
from .platform_tools import find_dumpcap


def _common_runtime_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", type=Path, help="TOML configuration file")
    parser.add_argument("--interface", help="capture interface override")
    parser.add_argument("--output", type=Path, help="unredacted findings JSONL override")
    parser.add_argument("--workers", type=int, help="analysis worker count override")
    parser.add_argument(
        "--console-findings",
        action="store_true",
        help="print finding notices to the terminal with sensitive material redacted",
    )
    parser.add_argument(
        "--console-unredacted",
        action="store_true",
        help="also print unredacted material to the terminal (export is always unredacted)",
    )
    parser.add_argument(
        "--no-raw-ring",
        action="store_true",
        help="disable the independent dumpcap packet ring",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="packet-audit",
        description="Flow-aware sensitive-information traffic auditor",
    )
    parser.add_argument("--version", action="version", version=f"packet-audit {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    live = subparsers.add_parser("live", help="inspect a live interface")
    _common_runtime_options(live)

    replay = subparsers.add_parser("replay", help="inspect a PCAP or PCAPNG file")
    replay.add_argument("capture", type=Path)
    _common_runtime_options(replay)

    doctor = subparsers.add_parser("doctor", help="validate dependencies, interface, and paths")
    doctor.add_argument("--config", type=Path, help="TOML configuration file")
    doctor.add_argument("--interface", help="capture interface override")

    subparsers.add_parser("list-interfaces", help="list interfaces reported by capture engines")

    validate = subparsers.add_parser(
        "validate-export", help="check an unredacted export's restrictive permissions"
    )
    validate.add_argument("path", type=Path)

    serve = subparsers.add_parser("serve", help="serve a restricted loopback live-results dashboard")
    serve.add_argument("--evidence-dir", type=Path, required=True)
    serve.add_argument("--host", choices=("127.0.0.1",), default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    access = serve.add_mutually_exclusive_group()
    access.add_argument("--token-file", type=Path)
    access.add_argument("--no-auth", action="store_true",
                        help="allow all local clients without a token; loopback-only")
    return parser


def _load_config(args: argparse.Namespace) -> AuditConfig:
    config = AuditConfig.from_toml(args.config) if getattr(args, "config", None) else AuditConfig()
    updates = {}
    if getattr(args, "interface", None):
        updates["interface"] = args.interface
    if getattr(args, "output", None):
        updates["output_jsonl"] = args.output
    if getattr(args, "workers", None) is not None:
        updates["workers"] = args.workers
    if getattr(args, "console_unredacted", False):
        updates["console_unredacted"] = True
        updates["console_findings"] = True
    elif getattr(args, "console_findings", False):
        updates["console_findings"] = True
    if getattr(args, "no_raw_ring", False):
        updates["raw_capture_enabled"] = False
    if updates:
        config = replace(config, **updates)
    config.validate()
    return config


def _list_pcapy_interfaces() -> tuple[list[str], str | None]:
    try:
        from .capture import _load_pcapy
        pcapy = _load_pcapy()
    except (ImportError, RuntimeError, OSError) as exc:
        return [], f"capture backend unavailable: {exc}"
    try:
        return list(pcapy.findalldevs()), None
    except Exception as exc:
        return [], f"pcapy interface enumeration failed: {type(exc).__name__}: {exc}"


def list_interfaces() -> int:
    interfaces, error = _list_pcapy_interfaces()
    result: dict[str, object] = {"interfaces": interfaces, "pcapy": interfaces,
                                "engine": "Npcap" if os.name == "nt" else "pcapy-ng"}
    if error:
        result["pcapy_error"] = error
    dumpcap = find_dumpcap()
    if dumpcap:
        probe = subprocess.run(
            [dumpcap, "-D"], capture_output=True, text=True, timeout=15, check=False
        )
        result["dumpcap_returncode"] = probe.returncode
        result["dumpcap"] = (probe.stdout or "") + (probe.stderr or "")
    else:
        result["dumpcap_error"] = "dumpcap not found"
    print(json.dumps(result, indent=2))
    return 0 if interfaces else 1


def doctor(config: AuditConfig) -> int:
    checks: list[dict[str, object]] = []
    interfaces, pcapy_error = _list_pcapy_interfaces()
    checks.append(
        {
            "check": "Npcap" if os.name == "nt" else "pcapy-ng",
            "ok": pcapy_error is None,
            "detail": pcapy_error or f"{len(interfaces)} interfaces listed",
        }
    )
    checks.append(
        {
            "check": "interface",
            "ok": config.interface in interfaces,
            "detail": f"selected={config.interface}; available={interfaces}",
        }
    )
    raw_ok, raw_detail = DumpcapRing(config).preflight()
    checks.append({"check": "dumpcap_ring", "ok": raw_ok, "detail": raw_detail})
    evidence_ok, evidence_detail = validate_evidence_paths(
        config.output_jsonl,
        config.operational_jsonl,
        raw_capture_enabled=config.raw_capture_enabled,
        raw_capture_dir=config.raw_capture_dir,
    )
    checks.append(
        {
            "check": "evidence_paths",
            "ok": evidence_ok,
            "detail": evidence_detail,
        }
    )
    if hasattr(os, "geteuid"):
        checks.append(
            {
                "check": "privilege_context",
                "ok": True,
                "detail": f"euid={os.geteuid()} (dumpcap capabilities/group access are preferred)",
            }
        )
    print(json.dumps({"config": str(config), "checks": checks}, indent=2, default=str))
    return 0 if all(bool(check["ok"]) for check in checks) else 1


def _run_runtime(config: AuditConfig, capture: Path | None) -> int:
    if capture is not None:
        if not capture.is_file():
            print(f"capture does not exist: {capture}", file=sys.stderr)
            return 2
        config = replace(config, raw_capture_enabled=False)
    supervisor = AuditSupervisor(config, offline_path=capture)
    try:
        result = supervisor.run()
    except KeyboardInterrupt:
        supervisor.request_stop()
        return 130
    except Exception as exc:
        print(f"packet-audit failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0 if result["verdict"] == "complete" else 3


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "serve":
        from .dashboard import serve_dashboard

        try:
            serve_dashboard(
                args.evidence_dir, host=args.host, port=args.port,
                token_file=args.token_file, require_token=not args.no_auth,
            )
        except KeyboardInterrupt:
            return 0
        except (OSError, ValueError) as exc:
            print(f"dashboard failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        return 0
    if args.command == "list-interfaces":
        return list_interfaces()
    if args.command == "validate-export":
        ok, detail = verify_export_permissions(args.path)
        print(json.dumps({"path": str(args.path), "ok": ok, "detail": detail}))
        return 0 if ok else 1
    try:
        config = _load_config(args)
    except (OSError, ValueError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    if args.command == "doctor":
        return doctor(config)
    if args.command == "live":
        return _run_runtime(config, None)
    if args.command == "replay":
        return _run_runtime(config, args.capture)
    parser.error(f"unsupported command: {args.command}")
    return 2
