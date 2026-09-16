# Windows candidate validation report

Build: `0.1.4+win.1`, 2026-09-16. Baseline: upstream
`575dc2364d20bb7e7e36d96edeaef207c61ff41f` (Linux 0.1.4).

Host: Windows 11 build 26200, x64 Python 3.12.14, Npcap 1.88 / libpcap 1.10.6,
Wireshark dumpcap 4.6.8. The proposed minimum is x64 Python 3.11; this run did
not separately qualify every supported Python or Windows version.

| Check | Result |
| --- | --- |
| Full unit/integration/regression suite | 649 passed, 10 skipped, no failures |
| Python byte compilation / PowerShell parser / Git whitespace checks | Passed |
| Native loopback repeat/idle/ring test | 200 attempts, 200 findings; 2,200 analyzer packets and 2,200 raw-ring replay packets |
| Capture verdict / private export ACL | Complete; ACL passed; no forced raw termination |
| Clean offline wheel installation, directory containing spaces | Passed with Windows PowerShell 5.1; module loaded from venv site-packages in isolated mode |
| Installed launcher + read-only HTTP viewer | 12/12 synthetic findings; both IP:port endpoints present |
| Actual Ctrl+C delivered to owned hidden test console | Complete; all worker/export drain acknowledged; viewer closed; launcher exit 0 |
| Installed replay launcher | 132 packets, 12 findings, complete, exit 0 |

The ten skips comprise two Linux Unix-datagram watchdog tests, seven POSIX
mode-bit tests, and one legacy pcapy-native test. Native Windows Npcap, ACL,
console-control and loopback tests run separately rather than being treated
as covered by those skipped POSIX tests.

The native capture test used `\Device\NPF_Loopback` and a BPF filter restricted
to a newly allocated synthetic local HTTP port. No physical network adapter,
ARP/routing change, real third-party login, or Kali listener was involved.
Live synthetic evidence is excluded from the distributed archive.

Reproduction helpers are included:

- `tools/windows_live_smoke.py`: explicit-output, bounded synthetic loopback
  repeat/idle/ring checks (defaults to 12 attempts; tested with 200).
- `tools/windows_launcher_smoke.py`: explicit installed-package/output paths,
  loopback viewer and Ctrl+C checks against its own newly created console.
- `tools/build_windows_release.py`: clean allowlisted source staging, wheel and
  source build, source-inclusive ZIP and SHA-256 manifests. Requires the
  development build package; ordinary deployment uses the bundled wheel.

These helpers are opt-in tests, not startup hooks. They must not be pointed at
existing evidence destinations. The package includes no driver binaries,
private captures, credentials, host-specific config, or prebuilt Python venv.

This is a test-ready Windows fork, **not a zero-loss certification**. Live
Windows SMB/LDAP, physical Ethernet/Wi-Fi, disconnect recovery, sustained load,
long soak, and all target Windows/security-software combinations remain
deployment acceptance gates. Use WINDOWS-VALIDATION.md before an assessment.
