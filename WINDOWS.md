# Packet Inspector for Windows

Version **0.1.4+win.1**, a Windows test release based on upstream Linux 0.1.4
(`575dc2364d20bb7e7e36d96edeaef207c61ff41f`). This is a separate fork; it does
not replace or remotely modify a Kali installation.

## First run

1. Extract the complete ZIP into a local, user-controlled Scripts folder. Do not
   run the launchers from inside the ZIP or a network share.
2. Install **64-bit Python 3.11 or newer**, **Wireshark with its dumpcap capture
   tool**, and **Npcap**. They are not bundled or silently installed. Review the
   [Npcap installation and licensing information](https://npcap.com/guide/npcap-users-guide.html).
3. Run `SETUP.cmd`. It creates a package-local `.venv` and installs the included
   wheel offline, without downloading Python packages.
4. Run `LIST-INTERFACES.cmd` to check capture availability.
5. Run `START-PACKET-INSPECTOR.cmd` and explicitly select the authorized adapter.
   The live dashboard opens at **http://127.0.0.1:8766/**.
6. Press **Ctrl+C once** in the capture window to stop. Wait for the final
   verdict and worker/export drain; closing the window or killing Python is
   not a verified clean stop.

If Npcap was installed with administrator-only capture, run the launcher from
an elevated terminal. The package does not auto-elevate or weaken driver
permissions. Both the Python environment and the Scripts folder must be
controlled by the user who launches them, especially when elevated.

If setup cannot find Python, supply its full path:

```powershell
.\SETUP.cmd -PythonExe 'C:\Path\To\Python\python.exe'
```

The convenience launchers are unsigned. Their PowerShell invocation uses a
process-local execution-policy override; it does not modify the saved system
policy. Managed application-control policies may still prohibit execution.

## Useful commands

Select an exact Npcap interface, or use the interactive menu:

```powershell
.\START-PACKET-INSPECTOR.cmd -Interface '\Device\NPF_{ADAPTER-GUID}'
.\START-PACKET-INSPECTOR.cmd -Port 8767 -NoBrowser
.\START-PACKET-INSPECTOR.cmd -Bpf 'host 192.0.2.10 and tcp' -NoDashboard
.\REPLAY-PCAP.cmd -CapturePath 'C:\Captures\authorized-test.pcapng'
```

Use an actual device name reported on your host, not the placeholder GUID or
example address above. There is **no default adapter selection**. Wi-Fi
promiscuous capture does not magically expose other clients' traffic; the
selected adapter must actually receive both directions of the test flow.
Monitor-mode 802.11/radiotap capture is not qualified by this port.

If a dashboard port is occupied, choose another port; the launcher will not
reuse another session's viewer or automatically expose it to the network.
The launcher closes its viewer when capture exits; cleanup failure produces a
warning identifying its owned PID. Reopen a saved run with:

```powershell
.\.venv\Scripts\python.exe -m packet_audit serve --evidence-dir 'C:\Path\To\Session' --host 127.0.0.1 --port 8766 --no-auth
```

The original command-line interface remains available under both
`packet-audit` and `packet-inspector` inside `.venv\Scripts`. Every new launcher
run saves a complete `session.toml`; inspect it for the actual limits. For
custom limits, stop first, edit a copy of that configuration, then use the
engine's `live --config` or `replay --config` command (see `--help`).

## Evidence and privacy

Each run gets a fresh UTC/UUID directory under:

```text
%LOCALAPPDATA%\PacketInspector-Windows\evidence\
```

Use `-OutputRoot 'C:\Private\PacketInspectorEvidence'` to choose a different
local destination. Do not place live unredacted evidence in a shared or
cloud-synced Scripts directory. The launcher never edits an existing broad ACL
to make it private: it refuses the destination and explains the problem.

- `findings-unredacted.jsonl`: unredacted sensitive findings, endpoints and
  provenance. Treat this and raw captures as assessment-sensitive evidence.
- `operations.jsonl`: health, loss, coverage and session/writer-stop records.
  The final post-writer verdict is printed in the capture console.
- `pcap-ring\`: bounded rotating raw PCAPNG files, plus dumpcap diagnostics.
- `session.toml`: the exact configuration, including filter and limits.
- `dashboard.stderr.log`: local viewer startup errors, if the viewer is used.

New evidence directories use protected Windows ACLs for the current account,
SYSTEM and Administrators. Existing destinations are checked using Windows
security APIs, not Unix mode bits. UNC/device paths, alternate data streams,
reparse/junction paths and hard-linked evidence files are refused. This is not
protection against processes running as the same user or as an administrator.
The disk/volume must support those Windows ACL checks.

The dashboard binds only to IPv4 loopback, **without a token**, as requested.
Host/Origin checks remain in place. Any local account/process able to connect
to that port can potentially read the findings: do not use token-free mode on
a shared/untrusted workstation. `serve` without `--no-auth` offers token mode.

Default raw retention is 24 files, rotating at 256 MB or 300 seconds per file;
it is a bounded ring, not a permanent packet archive. Preserve required raw
evidence before it rotates out. Observed disk/capture loss or forced raw-child
shutdown makes a run incomplete. Killing the entire parent process may prevent
any final verdict from being written; an absent final verdict is unverified.

## What changed for Windows

- A bounded ctypes Npcap adapter with nonblocking reads, correct Windows
  native layouts, explicit EOF/errors, and trusted DLL loading.
- Independent dumpcap ring capture and the same flow-affine worker processes,
  stream reassembly, detectors and durable JSONL writer as Linux 0.1.4.
- Windows loopback link-layer decoding, including IPv4/IPv6 header families.
- Graceful shutdown of the owned raw-capture process in its own hidden console;
  forced termination is recorded as incomplete. No unrelated console is signaled.
- Restricted Windows export ACLs, unique run/ring filenames, offline setup,
  adapter selection, and a local read-only live viewer.

No ARP poisoning or persistent forwarding, routing, firewall, adapter,
startup-service or driver configuration is changed. Capture requests temporary
promiscuous mode on the selected adapter. If using a separately authorized interception
setup, keep its forwarding and cleanup lifecycle separate from this sensor.

## Coverage and reliability boundaries

See [COVERAGE.md](COVERAGE.md) for precise inherited protocol support, including
NetNTLMv1/v2, SMB2 session-scoped NTLM, LDAP simple binds and the supported
cleartext authentication formats. No protocol detectors were removed for the
Windows port. Distinct repeated authentication exchanges are retained; TCP
retransmission of the same bytes is not a new authentication attempt.

This tool does not decrypt HTTPS/TLS, SSH, encrypted SMB or other protected
payloads, nor convert Kerberos authentication into NTLM. It cannot recover
traffic the adapter never received. Bounded resource limits are intentional;
coverage counters and incomplete verdicts must be reviewed alongside findings.
Neither a `complete` verdict nor a healthy process proves universal detection
or losslessness. The verdict means no configured runtime fault was observed.

This release has native Windows loopback evidence, not a Windows Ethernet/Wi-Fi
assessment qualification. Follow [WINDOWS-VALIDATION.md](WINDOWS-VALIDATION.md)
on the actual adapter, host and anticipated traffic load before relying on it.

## Upstream and dependencies

Upstream: [KampaiDiscount/packet-inspector](https://github.com/KampaiDiscount/packet-inspector).
The package is GPL-3.0-or-later; see LICENSE and NOTICE.md. Npcap, Wireshark and
Python are separate dependencies governed by their respective licenses; their
binaries are not redistributed in this ZIP. Default dumpcap discovery uses the
Wireshark registry/install directories, not the current directory or PATH.
For a nonstandard installation, set an absolute `dumpcap_path` in a custom
configuration and use the engine CLI.
