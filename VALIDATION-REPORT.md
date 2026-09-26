# Windows 0.1.6+win.3 candidate validation report

Checked 2026-09-26 on Windows 11 with 64-bit Python 3.12.14 and Npcap 1.88.

| Check | Result |
| --- | --- |
| Full native suite | 700 passed, 9 expected platform skips, 28 subtests passed |
| HTTP byte-range regression | Five focused tests passed: numeric `Range`/`Content-Range` offsets no longer become card candidates; card-shaped values elsewhere and split TCP input remain covered |
| Candidate ZIP and offline setup | External SHA-256 and all 91 internal entries verified; one 0.1.6+win.3 wheel and source archive passed package checks; extracted offline setup loaded the bundled wheel |
| Installed Windows replay | Separate 42-frame Win11-to-Linode PNG HTTP capture processed 42/42 frames, produced the expected two cookie and one PNG-signature findings, and ended complete with zero reported drops or parser errors |

The historical Kali first-window replay on the Windows fork was interrupted
before a valid final verdict, so it is not a Windows-package acceptance test.
The 42-frame capture tests clear HTTP/1 file and cookie classification, not
live Windows capture or native Win11 HTTP/LDAP/SMB authentication; that latter
matrix was observed by the Linux sensor. No universal or sustained zero-loss
claim follows from these bounded tests.

---

# Historical Windows 0.1.6+win.2 candidate validation report

Checked 2026-09-26 on Windows 11 with 64-bit Python 3.12.14 and Npcap 1.88.
The candidate includes the Linux 0.1.6 token-quality and HTTP file-signature
changes in a separate Windows checkout. This validation used synthetic token
values, an authorized Kali-to-Linode PNG HTTP capture replayed on Windows, and
a distinct live Win11-to-Linode PNG exchange captured by Kali and replayed on
Windows. The separate real Win11 HTTP authentication matrix is not either PNG
capture.

| Check | Result |
| --- | --- |
| Full native suite | 695 passed, 9 skipped, 28 subtests passed |
| Token classification | Short Bearer, preference/session-cookie distinction, signed/unsigned/malformed JWT and four-packet 5.3 KiB JWT regressions passed |
| File-signature matrix | PNG, JPEG, GIF, WebP, PDF and ZIP request/response findings, split boundaries, partial/multipart limits and binary-body isolation passed |
| Kali-to-Linode PNG PCAPNG replayed on Windows | 12 packets processed, one high-confidence PNG finding with complete packet provenance, zero reported drops/gaps, complete verdict |
| Live Win11-to-Linode PNG PCAPNG replayed on Windows | 42/42 packets processed, one high-confidence server-to-Win11 PNG finding with complete packet provenance at packet 19; two medium-confidence cookie candidates; zero reported drops, complete verdict |
| Synthetic PNG upload/download replay | 46 packets, two PNG findings with complete provenance, no credential finding from image text; incomplete verdict from one existing unsupported HTTP body content-type counter |
| Candidate ZIP and offline setup | External SHA-256 and 91 internal entries verified; one 0.1.6+win.2 wheel and one source archive; extracted setup installed wheel offline and CLI reported 0.1.6+win.2 |

The earlier 0.1.6+win.1 notes incorrectly called the 12-packet PNG source Win11;
packet addresses identify Kali 192.168.1.10 and Linode. This attribution
correction does not change its replayed Windows detector result. The separate
42-frame capture genuinely originated from the Win11 VM, and the live Kali
capture session counted 4,910 captured and dispatched packets without queue
drops. Its two cookie candidates were not validated as usable sessions.

This confirms detection and classification for the tested clear HTTP/1 shapes,
not arbitrary files, encrypted sessions, successful authentication or zero
loss under live load. Installed live-capture launchers were not repeated for
this candidate; physical adapter and sustained-load qualification remain
deployment-specific.

---

# Historical Windows 0.1.5+win.1 candidate validation report

Checked 2026-09-26 on Windows with 64-bit Python 3.12.14, Npcap 1.88 and
the native Windows PowerShell 5.1 launcher. Validation used synthetic
loopback authentication and offline Ethernet VLAN frames. It did not use
physical-adapter interception or real client credentials.

| Check | Result |
| --- | --- |
| Full unit/integration/regression suite | 670 passed, 9 skipped, 28 subtests passed |
| Native Npcap default BPF | Untagged IPv4/IPv6, single/double VLAN-tagged Ethernet IP and Windows loopback IPv4/IPv6 retained |
| Direct native loopback capture | 12/12 synthetic logins; 132 analyzer packets and 132 raw-ring packets; complete verdict and private evidence ACL |
| Deployment ZIP integrity and setup | External SHA-256 plus all 89 internal entries verified; one wheel and source archive; fresh offline wheel install loaded 0.1.5+win.1 from its package-local environment |
| Installed launcher and viewer | 12/12 synthetic findings with endpoints; owned Ctrl+C drained cleanly, viewer closed, exit 0, complete verdict |
| Installed offline replay | 132 packets, 12 findings, zero queue drops, complete verdict |

The SMB zero-SessionId, deferred reassembly and replay-backpressure regressions
are synthetic. Live Windows SMB/LDAP, physical Ethernet/Wi-Fi VLAN delivery,
sustained line-rate traffic and long soaks remain deployment acceptance gates.
The prior 0.1.4+win.1 evidence below is historical and is not a substitute for
these 0.1.5-specific checks.

---

# Historical Windows 0.1.4+win.1 candidate validation report

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
