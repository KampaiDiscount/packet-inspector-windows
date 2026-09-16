from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_engine_reference_documents_safety_and_operational_contract() -> None:
    readme = read("ENGINE.md")
    required = (
        "explicit authorization",
        "Ettercap",
        "ARP MITM",
        "mode `0600`",
        "mode `0700`",
        "no credential-level suppression",
        "TLS",
        "QUIC/HTTP/3",
        "dumpcap",
        "packet-audit live",
        "packet-audit replay",
        "packet-audit doctor",
        "packet-audit list-interfaces",
        "packet-audit validate-export",
        "systemctl start packet-audit@eth0.service",
        "systemctl stop packet-audit@eth0.service",
        "userspace_queue_drops",
        "libpcap_dropped",
        "interface_dropped",
        "active_flows",
        "reassembly_bytes",
        "parser_errors",
    )
    for phrase in required:
        assert phrase in readme, f"Engine reference is missing {phrase!r}"


def test_notice_covers_evidence_and_third_party_boundaries() -> None:
    notice = read("NOTICE.md")
    for phrase in (
        "written scope",
        "Unredacted JSONL",
        "raw PCAP/PCAPNG",
        "does not configure Ettercap",
        "PCredz by Laurent Gaffie",
        "pcapy-ng",
        "libpcap",
        "Wireshark",
    ):
        assert phrase in notice


def test_license_is_complete_gpl_v3() -> None:
    license_text = read("LICENSE")
    assert "GNU GENERAL PUBLIC LICENSE" in license_text
    assert "Version 3, 29 June 2007" in license_text
    assert "END OF TERMS AND CONDITIONS" in license_text
    assert len(license_text) > 30_000


def test_installer_is_idempotent_scoped_and_does_not_start_capture() -> None:
    installer = read("scripts/install-kali.sh")
    for token in (
        "set -Eeuo pipefail",
        "apt-get install",
        "python3-venv",
        "tshark",
        "libpcap-dev",
        "getent group",
        "useradd",
        "setcap 'cap_net_raw,cap_net_admin=eip'",
        "systemctl daemon-reload",
        "preserving existing",
    ):
        assert token in installer

    # Help text may show a start command, but the installer itself must not run
    # enable/start or configure an interception mechanism.
    assert not re.search(r"(?m)^\s*systemctl\s+(?:enable|start)\b", installer)
    for forbidden in (
        "ettercap ",
        "arpspoof ",
        "/proc/sys/net/ipv4/ip_forward",
        "iptables ",
        "nft add",
    ):
        assert forbidden not in installer.lower()


def test_systemd_unit_matches_cli_and_restricts_evidence() -> None:
    unit = read("systemd/packet-audit@.service")
    assert (
        "ExecStart=/opt/packet-audit/venv/bin/packet-audit live "
        "--config /etc/packet-audit/packet-audit.toml --interface %I"
    ) in unit
    for directive in (
        "User=packet-audit",
        "SupplementaryGroups=wireshark",
        "StateDirectory=packet-audit/%i",
        "StateDirectoryMode=0700",
        "RuntimeDirectoryMode=0700",
        "UMask=0077",
        "KillSignal=SIGINT",
        "KillMode=mixed",
        "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN",
        "AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "Restart=on-failure",
    ):
        assert directive in unit


def test_doctor_is_read_only_and_checks_capture_boundary() -> None:
    doctor = read("scripts/packet-audit-doctor.sh")
    for token in (
        "--interface",
        "/sys/class/net/",
        "dumpcap -D",
        "getcap",
        "cap_net_raw",
        "cap_net_admin",
        "mode 0600",
        "mode 0700",
        "console_unredacted=true",
        "packet-audit/venv/bin/packet-audit",
        "doctor --config",
        "list-interfaces",
        "check_private_directory_path",
        "same pathname",
        "same file/inode",
        "non-newline partial JSONL tail",
        "stat -Lc '%d:%i'",
        "tail od",
    ):
        assert token in doctor

    assert '[[ -L "${path}" ]]' in doctor
    assert '[[ -L "${resolved}" ]]' in doctor

    for mutating_command in (
        "ip link set",
        "setcap ",
        "systemctl start",
        "systemctl enable",
        "ettercap ",
        "arpspoof ",
        "iptables ",
        "nft add",
    ):
        assert mutating_command not in doctor.lower()


def test_shell_scripts_parse_with_bash_when_available() -> None:
    bash = shutil.which("bash")
    if bash is None:
        return
    scripts = [
        ROOT / "scripts" / "install-kali.sh",
        ROOT / "scripts" / "packet-audit-doctor.sh",
    ]
    completed = subprocess.run(
        [bash, "-n", *(str(path) for path in scripts)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
