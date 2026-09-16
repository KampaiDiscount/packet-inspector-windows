# Packet Inspector for Windows

Native Windows packet inspection for authorized network assessments, with
Npcap capture, TCP stream reconstruction, sensitive-field detection, structured
evidence exports, and a local dashboard.

**Current release: [0.1.4+win.1 — Windows test prerelease](https://github.com/KampaiDiscount/packet-inspector-windows/releases/tag/v0.1.4-win.1).**
Based on the [Packet Inspector Linux 0.1.4 engine](https://github.com/KampaiDiscount/packet-inspector).
The Windows package is named `packet-inspector-windows`; both `packet-inspector`
and `packet-audit` remain available as command-line entry points.

## Download and start

Download the **[deployment ZIP](https://github.com/KampaiDiscount/packet-inspector-windows/releases/download/v0.1.4-win.1/Packet-Inspector-Windows-0.1.4-win1.zip)**
and its **[SHA-256 checksum](https://github.com/KampaiDiscount/packet-inspector-windows/releases/download/v0.1.4-win.1/Packet-Inspector-Windows-0.1.4-win1.zip.sha256)**.
The deployment ZIP contains the Windows launchers, an offline-install Python
wheel, source, documentation, and an internal checksum manifest. GitHub's
automatic **Source code** archives and a Git clone do not contain that wheel.

1. Install **64-bit Python 3.11+**, **Wireshark with dumpcap**, and **Npcap**
   separately. Their binaries are not bundled.
2. Verify the ZIP checksum and extract the complete archive into a local folder
   controlled by your Windows account.
3. Run `SETUP.cmd` to create a package-local `.venv` and install the bundled
   wheel without downloading Python packages.
4. Run `LIST-INTERFACES.cmd`, then `START-PACKET-INSPECTOR.cmd` and select the
   authorized adapter. There is no automatic adapter choice.
5. Open the dashboard at **http://127.0.0.1:8766/**. Press **Ctrl+C once** in the
   capture window and wait for the final verdict and evidence drain to stop.

Follow **[WINDOWS.md](WINDOWS.md)** for checksum verification, prerequisites,
capture filters, alternate ports, replay, permissions, and troubleshooting.
Linux Bash/systemd instructions belong to the upstream Linux project.

## What it does

- Captures IPv4/IPv6 traffic through native Npcap and reconstructs bounded TCP
  streams for the shared protocol-aware detection engine.
- Detects supported cleartext authentication, correlated NTLM challenge-response
  material, HTTP login fields, and secret candidates. See
  [COVERAGE.md](COVERAGE.md) and [LOGIN_FIELDS.md](LOGIN_FIELDS.md) for exact formats
  and limits.
- Writes JSONL findings with endpoints, timestamps, stream context, and packet
  provenance; later authentication attempts remain separate observations.
- Records capture loss, queue pressure, parser limitations, and shutdown state,
  with an explicit final completeness verdict.
- Maintains an independent rotating `dumpcap` PCAPNG ring for later verification.
- Provides a read-only loopback dashboard and offline PCAP/PCAPNG replay through
  `REPLAY-PCAP.cmd`.

## Evidence and local access

Each launcher run writes to a fresh session directory beneath
`%LOCALAPPDATA%\PacketInspector-Windows\evidence\`, with restricted Windows ACLs.
Findings and raw traffic may contain credentials, tokens, and personal data;
keep unredacted evidence in an approved private destination.

The default dashboard binds to IPv4 loopback without a token. Other local
accounts or processes able to reach the listener may read its findings; CLI
token authentication is also available. Read the [access and evidence
guidance](WINDOWS.md#evidence-and-privacy) before use on a shared workstation.

## Validation and limits

This is a **test prerelease**. The published validation records native Windows
loopback capture, repeated synthetic logins, installed launchers, offline
replay, restricted exports, and clean Ctrl+C shutdown. Physical Ethernet/Wi-Fi,
live Windows SMB/LDAP, sustained load, and long-duration capture still require
deployment-specific acceptance checks.

Encrypted TLS/HTTPS, SSH, and other protected payloads are not decrypted.
Packet loss, unsupported wire formats, and bounded resources can leave evidence
incomplete. A healthy process or `complete` verdict does not establish universal
detection or zero loss, and a finding does not prove credential validity or
account compromise.

See [WINDOWS-VALIDATION.md](WINDOWS-VALIDATION.md) for acceptance checks,
[VALIDATION-REPORT.md](VALIDATION-REPORT.md) for recorded test results, and
[RELIABILITY.md](RELIABILITY.md) for shared-engine regression coverage.

## Project links

- [Windows setup and usage](WINDOWS.md)
- [Shared engine and Linux reference](ENGINE.md)
- [Release notes](RELEASE.md) and [downloads](https://github.com/KampaiDiscount/packet-inspector-windows/releases)
- [Windows CI](https://github.com/KampaiDiscount/packet-inspector-windows/actions/workflows/tests.yml)
- [Report an issue](https://github.com/KampaiDiscount/packet-inspector-windows/issues)
- [Contributing and development](CONTRIBUTING.md)
- [Report a security vulnerability privately](SECURITY.md)
- [Linux/Kali upstream](https://github.com/KampaiDiscount/packet-inspector)

Licensed under **GPL-3.0-or-later**. See [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md).
Use only within the interfaces, systems, and time windows covered by your
assessment authorization.
