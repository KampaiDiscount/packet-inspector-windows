# Packet Inspector for Windows 0.1.4+win.1

Release date: 2026-09-16. Git tag: `v0.1.4-win.1`. **Test prerelease.**

The Windows package is a separate fork of the Linux 0.1.4 engine, based on
upstream commit `575dc2364d20bb7e7e36d96edeaef207c61ff41f`.

- Native Npcap capture and Windows loopback link-layer decoding.
- Independent Wireshark `dumpcap` ring and the shared stream-aware detection
  engine, with restricted Windows evidence ACLs.
- Offline wheel setup, explicit adapter selection, live capture and replay
  launchers, and a read-only loopback dashboard on port 8766.
- Clean Ctrl+C shutdown drains workers and exports; forced raw-capture
  termination is recorded as incomplete.
- Both `packet-inspector` and `packet-audit` CLI names are available.

Use the attached **[Packet-Inspector-Windows-0.1.4-win1.zip](https://github.com/KampaiDiscount/packet-inspector-windows/releases/download/v0.1.4-win.1/Packet-Inspector-Windows-0.1.4-win1.zip)**
and [checksum](https://github.com/KampaiDiscount/packet-inspector-windows/releases/download/v0.1.4-win.1/Packet-Inspector-Windows-0.1.4-win1.zip.sha256).
The deployment ZIP includes the offline wheel, launchers, source, documentation,
and internal manifest. Automatic GitHub source archives do not include the wheel.
Python 3.11+ x64, Wireshark/dumpcap, and Npcap must be installed separately.

Recorded validation: 649 tests passed with 10 documented platform/backend skips;
200 separate synthetic loopback logins produced 200 findings, and both analyzer
capture and raw-ring replay counted 2,200 packets. Installed launchers, loopback
viewer, private ACLs, Ctrl+C shutdown, and offline replay were also exercised.
These are the published 2026-09-16 results, not a physical-adapter or throughput
qualification. See [WINDOWS-VALIDATION.md](WINDOWS-VALIDATION.md) and
[VALIDATION-REPORT.md](VALIDATION-REPORT.md) for limits and deployment checks.

See [WINDOWS.md](WINDOWS.md) for installation. The upstream notes below describe
earlier shared-engine changes; their Linux deployment details are historical
context rather than Windows installation instructions.

---

# Historical Packet Inspector / Packet Audit 0.1.3 release notes

Release date: 2026-09-16

- Nonblocking live capture and main-loop-driven external systemd watchdog.
- Fixed repeated LDAP binds beyond the first 64 bytes of a scan window.
- SMB2 session-scoped NTLM correlation, including concurrent sessions.
- HTTP SPNEGO and mail-protocol base64 NTLM wrappers.
- Bounded Redis AUTH/HELLO AUTH and PostgreSQL password-message coverage.
- Expanded synthetic replay/fault tests and Linux Python 3.11/3.13 CI gates.
- Explicit protocol coverage and live-host qualification documents.

This build is not a universal-protocol or lossless-capture guarantee. Native
live-host latency, saturation, restart and long-soak qualification remain
separate acceptance gates. Existing deployed installations are not upgraded
merely by publishing this source.

---

# Historical Packet Audit 0.1.2 release notes

Release date: 2026-09-16

- Source-backed HTTP login identity/password families documented in LOGIN_FIELDS.md.
- Testfire uid/passw, WordPress log/pwd, Drupal name/pass, Roundcube _user/_pass,
  framework prefixes, nested fields, case/separator/camelCase variants.
- Password-change and explicit OTP/MFA-code candidates; no authentication-success claim.
- Weak identity hints cannot override explicit username/email fields. Equally
  preferred multiple identities remain unpaired; username-only data is not a secret.
- Whole/terminal-component matching avoids unrelated password-policy/count fields.
- One classification per parsed field, bounded tables, unchanged retry handling.
- Includes the operator-requested token-free loopback dashboard mode. CLI token
  mode remains available; shipped systemd web service uses --no-auth.

Existing evidence/configuration are preserved during deployment. Encrypted or
unsupported body formats remain outside the documented coverage. This is not
a measured global field-name popularity ranking or a lossless-capture guarantee.

---

# Historical Packet Audit 0.1.1 release notes

Release date: 2026-09-16

## Immediate login and visibility fixes

- Bounded HTTP/1 request framing for Content-Length and chunked requests.
- Complete final form fields are recognized without requiring a trailing delimiter.
- Common nonstandard password fields, including `tfUPass`, and typed JSON secrets.
- Companion username context when unambiguous; no authentication-success claim.
- Split packets, pipelining, repeated attempts, and provenance regression coverage.
- Separate source/destination IP and port fields in new findings.
- Independent authenticated localhost-only live dashboard with search, health,
  legacy endpoint support, bounded reads, safe text rendering, and private token.
- Installer `--skip-system-deps`, active-service upgrade refusal, readable code
  permissions, and independent hardened dashboard unit.

The dashboard is read-only and does not control capture. Its recent-history
limits do not suppress evidence exports. Access remotely through an SSH tunnel,
not a public bind. Neither service is automatically enabled at boot.

Correctly encrypted HTTPS/TLS/QUIC is not decrypted. HTTP/2, multipart and
compressed request bodies remain outside typed form coverage. Limits and
unsupported framing are visible in HTTP detector health counters; see README.

Validation includes synthetic split/pipeline/retry tests, end-to-end worker
replay, dashboard authentication/XSS/read-bound tests, and native Kali checks.
Synthetic test rates are regression evidence, not a promise of lossless capture
at every load. Validate capture health on the intended deployment host.

---

# Historical Packet Audit 0.1.0 release notes

Release date: 2026-08-27

## Outcome

Packet Audit is a Kali-first live packet-audit sensor with an offline replay
path for tests and raw-ring recovery. The live supervisor keeps packet capture,
bounded parsing, and flow-affine dispatch short; worker processes perform IP/TCP
reconstruction and sensitive-material detection; one restricted writer appends
unredacted JSONL; and an independent rotating `dumpcap` PCAPNG ring preserves
recent frames.

Credential retries at new stream offsets or in new TCP connection epochs are
never suppressed. Exact retransmitted bytes at an already-consumed TCP sequence
position are treated as transport mechanics, not fabricated login attempts.

## Release hardening

- Per-worker queues are bounded by both batch count and an atomic 64 MiB
  captured-payload reservation. Count- and byte-budget drops are separately
  reported and force an incomplete verdict.
- TCP, fragment, detector-tail, metadata, provenance, NTLM correlation, and
  multi-step SMTP/IMAP/FTP-POP state all have explicit global and per-flow
  bounds. Cap pressure, eviction, trimming, or correlation loss is visible.
- Findings carry exact contributing packet IDs for retained byte spans.
  `packet_ids_complete=false` and limitations make bounded or missing
  provenance explicit.
- Final worker PIDs and the writer must acknowledge durable shutdown. Packet,
  finding, queue-byte, child-state, and available capture-drop counts must agree
  for a complete verdict.
- Evidence parents are private real directories, JSONL files are mode `0600`,
  symlink and same-inode/hardlink destinations are rejected, and a non-newline
  partial tail fails closed. The read-only doctor enforces the same invariants.
- The source manifest includes the Kali installer, doctor, systemd unit,
  configuration, tests, benchmark, notices, and release notes. Runtime binding
  behavior is pinned to `pcapy-ng==1.1.0`.

## Release verification

- 135 deterministic tests passed. Six POSIX permission/symlink cases were
  skipped on the Windows development host; the corresponding implementation
  paths remain target-host release gates.
- Coverage includes packet decoding, IPv4/IPv6 fragments, TCP
  ordering/retransmission/gaps/epochs, detector families, repeated attempts,
  exact and bounded provenance, retained-state pressure, writer security,
  queue-byte races, child lifecycle acknowledgements, offline multiprocess
  replay, configuration, doctor, and deployment contracts.
- Malformed-input smoke coverage includes 1,000 random frames and 1,000 random
  detector payloads in addition to hand-built truncated protocol cases.
- Python byte-compilation passed on Python 3.12.13.
- On the Windows development host, the synthetic parser benchmark processed
  100,000 Ethernet/IPv4/TCP frames at 172,487.7 packets/s. The combined
  sequential TCP reconstruction plus detector path processed 10,000 repeated
  synthetic HTTP Basic attempts at 3,293.6 attempts/s and emitted all 10,000
  findings.

Synthetic rates are regression evidence only. They are not a live line-rate
guarantee; traffic mix, frame size, CPU scheduling, storage, kernel/libpcap
drops, and raw-ring contention materially affect capacity.

## Validation boundary

The development host is Windows and does not expose the target Kali `eth0`,
libpcap permissions, systemd, Bash syntax execution, or `dumpcap`. A native
Kali installation and live interface smoke test therefore remain host-specific
release gates. On the authorized capture host, run the installer, review the
config, run the doctor, start the service, and confirm increasing capture and
worker counters plus a healthy raw ring before beginning any separately
approved interception.

## Known limits

- Correctly encrypted TLS, QUIC/HTTP/3, SSH, SNMPv3, LDAPS, IMAPS, SMTPS, and
  similar payloads are not decrypted.
- Capture loss, a truncated snap length, unsupported encapsulation, missing
  first fragments, capture started mid-flow, or configured memory/queue limits
  can make findings incomplete. Observable cases are counted and force an
  incomplete verdict.
- Stream provenance retains a bounded recent span history. Findings explicitly
  mark packet-ID provenance incomplete when older or capped context is needed.
- Generic secret and payment-card matches are candidates, not proof of validity
  or usability. Multipart form bodies are not deeply decoded.
- Unredacted JSONL and raw PCAPNG are restricted plaintext evidence. Store the
  state directory on an approved encrypted volume when at-rest encryption is
  required by the engagement.
