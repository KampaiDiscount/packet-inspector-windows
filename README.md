# Packet Inspector - Windows fork

This is the **0.1.4+win.1 Windows test release**, branched from the Linux
0.1.4 engine. Start with [WINDOWS.md](WINDOWS.md), not the Linux installation
commands below. Native Windows capture uses Npcap, an independent Wireshark
dumpcap ring, and the existing multiprocessing analysis engine. The package
includes Windows launchers and a loopback-only dashboard on port 8766.
See [WINDOWS-VALIDATION.md](WINDOWS-VALIDATION.md) for the actual test boundary.

The following upstream documentation remains applicable to the shared engine;
its Bash/systemd installation instructions are Linux-only.

## Packet Inspector engine

Packet Inspector uses the Packet Audit engine. The Python package, commands,
and service names remain `packet-audit` for compatibility with existing installs.

**Qualification status:** this is an actively tested assessment tool, not a
certified lossless sensor. See [COVERAGE.md](COVERAGE.md) for supported wire
formats and [RELIABILITY.md](RELIABILITY.md) for regression evidence and the
live-host acceptance gate. A healthy process alone is not proof of coverage.

Packet Audit is a loss-visible, stream-aware network evidence tool for authorized
security assessments. It captures IPv4/IPv6 traffic, rebuilds bounded TCP flows,
applies protocol-aware sensitive-information detectors, and writes structured
JSONL findings with packet and stream provenance. A separate rotating `dumpcap`
ring preserves recent raw traffic so an analyst can verify or recover an event
without making the Python analysis path responsible for durable capture.

Packet Audit is an auditor, not a decryption product. It cannot see credentials
inside TLS, QUIC/HTTP/3, SSH, SNMPv3, LDAPS, IMAPS, SMTPS, or other correctly
encrypted application payloads
unless authorized decrypted traffic is supplied separately. A captured
challenge-response, token, username, endpoint, or client-supplied identity field
is evidence of an observation; by itself it does not prove account compromise,
endpoint ownership, exploitability, or Internet exposure.

## Authorization and handling boundary

Use Packet Audit only on interfaces, traffic, systems, and time windows covered
by explicit authorization. Prefer a network TAP, switch mirror/SPAN port, or an
approved offline PCAP. Active interception such as ARP MITM materially changes a
network and needs a separately approved runbook covering exact targets,
production-safety controls, forwarding behavior, rollback, and evidence
retention.

The installer and service deliberately do **not** run Ettercap, poison ARP
caches, enable IP forwarding, or alter firewall/nftables rules. If an authorized
engagement uses Ettercap, keep it in a separate terminal and lifecycle:

1. Record the approved target pair/subnet and verify the Kali interface, route,
   gateway, addressing, link state, and existing neighbor/forwarding/firewall
   state.
2. Start Packet Audit and confirm increasing capture counters and a healthy raw
   ring before starting active interception.
3. Run only the exact Ettercap/ARP action from the approved engagement runbook.
   Packet Audit does not select or broaden interception targets.
4. Stop Ettercap first. Confirm its cleanup completed and verify neighbor,
   forwarding, route, and firewall state returned to the recorded baseline.
5. Stop Packet Audit cleanly so workers and JSONL writers flush, then restrict
   and inventory the evidence.

Do not infer that an ARP/Ettercap command shown in unrelated terminal output is
authorized for the current interface. Never replay pasted commands without
validating the target and current scope.

## Evidence model and privacy

`findings-unredacted.jsonl` may contain plaintext credentials, API tokens,
authentication challenge-response material, personal data, and other secrets.
It must remain mode `0600`, with its parent evidence directory mode `0700` and a
process umask of `0077`. The raw PCAP ring is at least as sensitive and uses the
same restricted handling. Do not paste unredacted material into tickets, chat,
email, or a broadly readable report. Derive a separately sanitized export for
stakeholders and validate it before release. Place the evidence directory on an
approved encrypted volume when the engagement requires encryption at rest.

The finding path has **no credential-level suppression**: a later protocol
attempt is not discarded merely because the same username or material appeared
earlier. The exact same detector span at the same absolute stream offset is
emitted once; an identical retry at a new stream offset is always emitted as a
new attempt. `attempt_ordinal`, packet IDs, timestamps, flow identity,
completeness, absolute stream offset, and limitations preserve the observation
context. When IP fragments are reassembled, the finding carries the IDs of all
captured packets that contributed first-seen bytes. TCP retransmitted bytes are
handled as stream transport mechanics rather than fabricated new login attempts.
`packet_ids` is the exact set of retained capture IDs whose byte spans intersect
the finding. `packet_ids_complete = false` means a configured provenance limit,
earlier stream history, or incomplete correlation state prevented a complete
mapping; the reason is also exposed through finding limitations and health
counters. This differs from username-only
deduplication, which can make a long-running sniffer look healthy but silently
hide later authentication exchanges.

Operational health events contain counts and state, not secret material.
Per-finding console notices are disabled by default so terminal or journald I/O
cannot throttle the evidence writer. `--console-findings` enables redacted
notices; keep unredacted console output disabled for the system service because
journald commonly has different access and retention rules from the evidence
directory.

## Architecture

The live capture path is deliberately short:

1. `pcapy-ng` reads frames and records libpcap receive/drop counters.
2. A bounded dispatcher consistently shards a flow to one worker. Fragment
   affinity is bounded and loss-visible. Queue overflow is counted; it is never
   hidden.
3. Workers parse link/network/transport layers, expire bounded fragment/flow
   state, reconstruct TCP byte ranges, and call detector plugins.
4. A single restricted writer appends every finding to JSONL, acknowledges
   durable shutdown, and records a SHA-256 over the finding lines written in
   that session.
5. Independently, `dumpcap` writes a fixed-size rotating raw-capture ring.

The raw ring is important because a per-packet keyword flagger cannot reliably
recognize a credential split across TCP segments. The default ring rotates when
either 256 MiB or 300 seconds is reached and retains 24 files. Its nominal size
ceiling is about 6 GiB; at lower traffic rates that is roughly two hours, while
high traffic can fill files sooner and shorten the time window. These are
retention bounds, not a completeness guarantee. Monitor raw-ring failures and
disk capacity. The shipped profile sets `stop_on_raw_capture_failure = true`,
so loss of the independent ring is a visible terminal condition. Turning that
off is an explicit weakening and produces an incomplete-verdict reason.

The analyzer and `dumpcap` intentionally use independent capture handles. The
analyzer's monotonically assigned packet IDs therefore are not frame numbers in
the raw ring. Correlate a finding to PCAPNG using its timestamp, interface,
VLAN, protocol, endpoints, ports, direction, and raw payload evidence; allow for
small capture-order differences under load. This independence keeps raw capture
alive when analysis is busy, but it is not a cryptographic one-to-one mapping.

Default worker state is bounded independently: 128 MiB for queued TCP
reassembly bytes and 128 MiB for detector payload tails per worker, in addition
to flow-count and per-direction limits. Evictions, trimming, gaps, fragment
fallbacks, queue drops, parser errors, child restarts, stale progress, and
writer acknowledgements all feed the final completeness verdict. The default
queue holds at most 64 batches per worker; a batch contains at most 128 captured
packets, and each worker queue also has an atomic 64 MiB payload reservation
budget. Dispatch drops are counted when either the batch-count or byte budget is
full. These are overload buffers, not claims that every traffic rate can be
analysed without loss.

## Detection coverage

Packet Audit performs stateful, offset-aware detection rather than a single
packet keyword search. Implemented families are:

- raw and HTTP-wrapped NTLMSSP Type 2/3 correlation, with NetNTLMv1 mode 5500
  and NetNTLMv2 mode 5600 material where a challenge and response are safely
  paired;
- SMB2/3 clear SESSION_SETUP session-ID correlation, HTTP SPNEGO NTLM, and
  base64 NTLM/SPNEGO authentication tokens on SMTP/POP3/IMAP ports;
- HTTP Basic, Bearer, Digest and NTLM/Negotiate headers, cookies, query strings,
  and URL-encoded sensitive fields; bounded HTTP/1.x Content-Length/chunked
  request framing, final form fields, typed JSON secrets, common password-field
  aliases (including `tfUPass`), and companion usernames;
- FTP/POP3 USER/PASS, SMTP AUTH PLAIN/LOGIN, IMAP LOGIN/AUTHENTICATE,
  IRC registration secrets, and Telnet-like login fields;
- LDAP simple bind, SNMP v1/v2c communities, and MSSQL TDS Login7;
- Redis RESP/inline AUTH and HELLO AUTH on port 6379; PostgreSQL password
  messages on port 5432 (confirmed plaintext only with a server cleartext
  authentication request, otherwise explicitly method-unknown);
- Kerberos AS-REQ etype 23 mode 7500 and SIP Digest mode 11400 when the required
  fields are complete;
- JWTs, selected cloud/source-control/chat/payment token formats, named secret
  assignments, PEM private keys, and Luhn-valid payment-card candidates.

The generic matches are candidates with explicit confidence and limitations;
the tool never tests whether a token, account, card, response, or key is valid.
Typed HTTP request parsing is limited to the configured detector tail (128 KiB
by default), 32 KiB of headers, 256 fields, and 8 KiB URL-encoded field values.
JSON nesting and chunk counts are bounded. Unsupported encodings, ambiguous
framing, and limits appear in `http_*` detector health counters, and observed
coverage limitations make the final session verdict incomplete. A complete
request boundary, not the end of a TCP segment, finalizes a trailing form value.
New stream offsets and connection epochs remain distinct attempts.
HTTP/2 header compression, compressed request bodies, and multipart forms are
not deeply decoded. Correctly encrypted payloads remain out
of scope unless an authorized decrypted stream is supplied.

## Kali installation

For upgrades, stop the capture and dashboard services before replacing their
shared Python environment. The installer refuses to upgrade running instances.
Preserve the configuration and evidence directory. On a host whose system
dependencies are already installed, use
`sudo bash ./scripts/install-kali.sh --skip-system-deps` to avoid apt/debconf
changes. This mode checks the required tools, Python headers, and libpcap.

Run the installer from the repository root:

```bash
cd /path/to/packet_audit
sudo bash ./scripts/install-kali.sh
```

The installer is idempotent. It installs Python, venv/build dependencies,
`tshark`/`dumpcap`, and libpcap through `apt`; creates the locked
`packet-audit` service account and restricted state/configuration directories;
builds `/opt/packet-audit/venv`; installs the doctor and systemd template; and
configures the packaged `dumpcap` capability boundary. It preserves an existing
`/etc/packet-audit/packet-audit.toml`. It calls `systemctl daemon-reload` but
does not enable or start a capture service and does not configure interception.

The Python package pins `pcapy-ng` 1.1.0 for reproducible libpcap binding
behavior. The Kali host still builds that native extension locally against its
installed compiler and `libpcap-dev`, so the host-specific install smoke test is
a release gate.

Review the installed configuration:

```bash
sudoedit /etc/packet-audit/packet-audit.toml
```

Relative evidence paths are resolved below the service instance directory,
`/var/lib/packet-audit/INTERFACE/`. Separate interface instances therefore do
not share writers or raw-ring filenames.

## Login-field coverage (0.1.2)

The typed HTTP detector covers representative WordPress, Django, Spring,
Keycloak, ASP.NET Identity, Drupal, phpMyAdmin, Roundcube and Symfony forms,
plus the observed Testfire and Vulnweb lab forms. It handles bounded case,
separator, camelCase and nested-field variants. See [LOGIN_FIELDS.md](LOGIN_FIELDS.md)
for exact names, primary sources, false-positive guards and limitations.
Identity fields are context only, ambiguous identities remain unpaired, and
distinct repeated attempts are still exported independently.

## Private live dashboard (0.1.2)

After starting a capture instance, start its separate read-only dashboard:

```bash
sudo systemctl start packet-audit-web@eth0.service
sudo systemctl status packet-audit-web@eth0.service --no-pager
```

Open `http://127.0.0.1:8765/` in a browser on Kali; no token is needed. The page
displays unredacted sensitive findings, directional IP/port endpoints, and
operational health. The supplied service uses `--no-auth`: every local user or
process that can reach the loopback listener (including the workstation's SSH
tunnel endpoint) can read the results. Host/Origin checks, no-CORS, and safe text
rendering remain enabled. The dashboard does not control capture or modify evidence.
For optional token authentication, omit `--no-auth` and set `--token-file` to a
private writable path. These options are mutually exclusive.

For access from the workstation, keep this SSH tunnel running in a terminal
(replace `audit-sensor` with the SSH alias for the intended sensor):

```bash
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:8765:127.0.0.1:8765 audit-sensor
```

Then open `http://127.0.0.1:8765/` on that workstation. No LAN-facing dashboard
port is opened. Do not bind this unredacted interface to a public address or
put it behind an unauthenticated proxy. Port 8765 supports one interface
dashboard at a time. Stop it independently with
`sudo systemctl stop packet-audit-web@eth0.service`.

New finding records expose `source_ip`, `source_port`, `destination_ip`, and
`destination_port`, plus `source`/`destination` objects. These are the direction
of the observed material, not a guess at client/server roles. A response finding
can therefore run from server to client. Unknown directions remain null. The
dashboard can also interpret older `flow_id`/`direction` records.

## Verify the interface before capture

Interface names and traffic paths change when Kali uses USB adapters, bridges,
VPNs, bonds, or a VM. Verify them immediately before each run:

```bash
ip -brief link
ip -brief address
ip route
/opt/packet-audit/venv/bin/packet-audit list-interfaces
dumpcap -D
```

On the first run, start the service as shown below: systemd creates the private
evidence directories before running the doctor automatically. After that,
the installed preflight can also be run manually:

```bash
sudo -u packet-audit /usr/local/libexec/packet-audit-doctor \
  --config /etc/packet-audit/packet-audit.toml --interface eth0
```

The wrapper above is the normal installed preflight. For a direct CLI
diagnostic, run it from the instance state directory so relative evidence paths
resolve exactly as they do for the service:

```bash
cd /var/lib/packet-audit/eth0
sudo -u packet-audit /opt/packet-audit/venv/bin/packet-audit doctor \
  --config /etc/packet-audit/packet-audit.toml \
  --interface eth0
```

The doctor checks the named kernel interface, service account, config, output
permissions, `dumpcap` file capabilities/group access, disk capacity, CLI
self-check, and the interface inventory. It does not send packets or change
network state. A capture interface bound to a deleted/recreated ifindex may stay
open but stop receiving; compare Packet Audit counters with a fresh, scoped
control capture if that is suspected.

## Exact live lifecycle

For a simple interface name such as `eth0`:

```bash
sudo systemctl start packet-audit@eth0.service
sudo systemctl status packet-audit@eth0.service --no-pager
sudo journalctl -u packet-audit@eth0.service -f
sudo tail -F /var/lib/packet-audit/eth0/evidence/operations.jsonl
```

The service runs the equivalent of:

```bash
packet-audit live \
  --config /etc/packet-audit/packet-audit.toml \
  --interface eth0
```

Use `systemd-escape --template=packet-audit@.service "$INTERFACE"` for an
unusual interface name. Do not enable the unit unless persistent boot-time
capture is explicitly wanted and approved.

Stop capture cleanly:

```bash
sudo systemctl stop packet-audit@eth0.service
sudo systemctl is-active packet-audit@eth0.service
sudo journalctl -u packet-audit@eth0.service -n 100 --no-pager
sudo find /var/lib/packet-audit/eth0/evidence -type f \
  -name '*unredacted*' -printf '%m %u:%g %p\n'
```

`systemctl stop` sends `SIGINT` to the supervisor and gives it time to flush and
close its workers and `dumpcap` child. If that grace period expires, systemd
terminates the remaining service control group. Avoid `kill -9` except for an
emergency because it can leave the last
JSONL record or PCAP segment incomplete.

CLI overrides supported by live mode are:

```text
--interface NAME
--output PATH
--workers N
--console-findings
--console-unredacted
--no-raw-ring
```

`--console-findings` prints redacted notices and can still create backpressure at
high finding rates. `--console-unredacted` implies console notices and is
intentionally unsuitable for the system service.
`--no-raw-ring` weakens later verification and must be an explicit assessment
decision.

## Offline replay and export validation

Replay never starts a raw ring and does not require capture privileges. Create a
restricted destination, then run as the service account:

```bash
sudo install -d -m 0700 -o packet-audit -g packet-audit \
  /var/lib/packet-audit/replay-001
sudo install -m 0600 -o packet-audit -g packet-audit \
  /evidence/input.pcapng /var/lib/packet-audit/replay-001/input.pcapng
sudo -u packet-audit sh -c \
  'cd /var/lib/packet-audit/replay-001 && \
   exec /opt/packet-audit/venv/bin/packet-audit replay \
     ./input.pcapng \
     --config /etc/packet-audit/packet-audit.toml \
     --output ./findings-unredacted.jsonl \
     --workers 4'
sudo chmod 0600 \
  /var/lib/packet-audit/replay-001/findings-unredacted.jsonl
```

Validate the restrictive filesystem permissions of a candidate export before
using it downstream:

```bash
sudo -u packet-audit /opt/packet-audit/venv/bin/packet-audit validate-export \
  /var/lib/packet-audit/replay-001/findings-unredacted.jsonl
```

Replay output is evidence derived from the supplied capture; it does not prove
that the original live sensor had zero packet loss. `validate-export` checks
existence, regular-file/no-symlink status, and permission mode; it does not prove
integrity, sanitization, or the truth of a finding.

At shutdown the CLI reports `verdict: complete` only when capture/worker/writer
acknowledgements and available drop counters agree. Otherwise it reports
`incomplete`, lists exact reasons, and exits nonzero. `session_findings_sha256`
covers the UTF-8 JSONL finding lines appended by that run; it is not a hash of
older records already present in the same append-only file.

## Health counters

Heartbeats are written to the operational JSONL at the configured interval.
The supervisor also receives a separate low-volume internal progress channel
from workers and the writer, allowing it to stop on a live-but-stalled child.
The service journal receives startup/final CLI output and optional finding
notices, not a duplicate of every operational heartbeat. Treat the following
as a pipeline, not as one generic "running" indicator.

Capture heartbeat:

- `captured_packets`: frames returned to the application.
- `dispatched_packets`: frames accepted by a worker queue.
- `userspace_queue_drops`: frames rejected because a bounded queue was full.
- `worker_queue_byte_budget_dropped_packets` and
  `worker_queue_byte_budget_dropped_bytes`: work rejected specifically by the
  atomic per-worker payload-byte limit. Any nonzero value makes the session
  verdict incomplete.
- `worker_queue_byte_health`: current and peak reserved bytes per worker and in
  aggregate, together with configured per-worker and total maxima. A clean
  shutdown returns every current reservation to zero.
- `libpcap_received`: libpcap receive counter; platform semantics vary, so use
  deltas.
- `libpcap_dropped`: packets dropped because the capture buffer could not keep
  up.
- `interface_dropped`: interface/driver-reported capture drops where available.
- `last_packet_age_seconds`: monotonic age of the most recent captured frame.

Worker heartbeat:

- `packets`, `bytes_seen`, and `queue_depth` show forward progress/backlog.
- `active_flows` and `reassembly_bytes` show bounded state pressure.
- `findings` counts detector emissions; it is not a packet-health counter.
- `parser_errors` makes malformed/unsupported traffic visible.
- `truncated_packets` and `truncated_missing_bytes` expose snap-length or source
  capture truncation; any nonzero truncated-packet count makes the session
  verdict incomplete.
- reassembly, detector-tail, fragment, and eviction counters show where bounded
  state forced a gap or lost correlation context. A nonzero
  `fragment_active_datagrams` count at shutdown means incomplete datagrams were
  still awaiting fragments and also makes the verdict incomplete.
- detector metadata entry/peak/max and cap-pressure counters cover the bounded
  high-water state used to prevent rescans of the same byte positions. A
  metadata-cap eviction or saturation makes the verdict incomplete; it never
  licenses credential-value or username-level suppression.
- `worker_health_totals` prefixes detector state counters with `detector_`.
  Provenance loss is visible through `detector_provenance_cap_*`,
  `detector_provenance_packet_ids_truncated`, and
  `detector_provenance_incomplete_findings`; NTLM challenge/response state loss
  is visible through `detector_ntlm_correlation_cap_*`. Multi-step
  SMTP/IMAP/FTP-POP state contributes to the same retained-byte ceiling;
  `detector_pending_auth_bytes` and `detector_peak_pending_auth_bytes` show its
  current/peak allocation, while `detector_pending_auth_cap_*` exposes any
  pressure, eviction, or drop. Nonzero loss, pressure, or truncation counters
  make the final verdict incomplete.

Interpret common combinations:

| Observation | Likely layer to inspect |
| --- | --- |
| Kernel/interface RX and a fresh `dumpcap` rise, but `captured_packets` does not | stale handle, wrong interface, permissions, or capture filter |
| `captured_packets` rises but `dispatched_packets` stalls | dispatcher failure or blocked queue path |
| `userspace_queue_drops` rises | workers cannot keep up; reduce load or add workers |
| queue byte-budget drops rise or byte health stays near its maximum | captured payload volume exceeds worker capacity even if batch slots remain |
| `libpcap_dropped` rises | capture buffer/CPU/I/O overload before Python can read |
| worker `packets` rises but `findings` does not | no matching cleartext attempt, encrypted traffic, gaps, or parser limitation |
| findings rise but output size does not | writer/disk/permission failure; this is never expected dedup behavior |
| `active_flows` or `reassembly_bytes` stays near its cap | long-lived/gapped flows or insufficient expiry/capacity |

An idle network can legitimately leave counters unchanged. Generate only an
approved benign control flow or compare with a fresh passive capture before
declaring the handle stalled.

## Troubleshooting

### Service will not start

```bash
sudo /usr/local/libexec/packet-audit-doctor \
  --config /etc/packet-audit/packet-audit.toml \
  --interface eth0
sudo systemctl status packet-audit@eth0.service --no-pager -l
sudo journalctl -u packet-audit@eth0.service -b --no-pager
```

Confirm that the config names a real interface, Python is at least 3.11, the
service account belongs to the `wireshark` group, and `dumpcap` reports
`cap_net_raw` and `cap_net_admin`. The systemd unit separately grants only those
two capabilities to the live service so the Python interpreter is never given
global file capabilities.

### Process is alive but no findings appear

First check capture and worker heartbeats rather than restarting blindly.
Finding notices are absent from the console by default, and encrypted
application traffic is expected to produce no plaintext credential material.
Confirm the correct interface and BPF,
check all three drop counters and queue depth, inspect `parser_errors`, and verify
that a new, approved test exchange is actually present in the raw ring. Packet
Audit does not intentionally suppress a repeated user or later authentication
attempt.

### Raw ring is missing or stopped

```bash
getcap "$(command -v dumpcap)"
id packet-audit
sudo -u packet-audit dumpcap -D
df -h /var/lib/packet-audit
df -i /var/lib/packet-audit
```

Treat a stopped ring as a health failure even if live findings continue. Copy a
needed segment to a separate restricted case directory before it rotates; do not
change the live ring's filenames or permissions in place.

### Drops or growing backlog

Reduce unrelated traffic with a scope-safe BPF, increase the configured capture
buffer, increase workers within CPU/memory limits, or move capture to a quieter
TAP/SPAN source. A narrow port filter can hide dynamic RPC or protocols on
non-standard ports. Do not solve overload by making queues unbounded: that merely
turns visible loss into memory exhaustion and stale analysis.

### Permissions or log rotation

The installed service uses one writer, `UMask=0077`, and per-interface state
directories. Operational JSONL is the detailed health source; journald records
service lifecycle output. Do not point
unredacted JSONL at OneDrive, an NFS share, a world-readable directory, or a file
managed by an external rotate job. Stop the service before moving evidence, then
hash/inventory the preserved copy according to the engagement procedure.

An emergency kill or host failure can leave the final JSONL line incomplete.
This is deliberately fail-closed: the next start refuses to append to a file
whose last byte is not a newline. Keep the service stopped, preserve and hash
the original file in a restricted case directory, and record the forced-stop
event. The safest recovery is to quarantine the affected original under a new
evidence name and let the writer create a fresh configured destination at mode
`0600`; do this separately for findings and operations as required. If an
engagement procedure instead permits tail repair, repair only a working copy to
the last complete newline and retain the untouched original plus both hashes.
Never truncate or overwrite the sole evidence copy merely to make the service
start.

## Development tests

From an activated development environment:

```bash
python -m pytest
bash -n scripts/install-kali.sh scripts/packet-audit-doctor.sh
python tools/benchmark_core.py --packets 100000 --attempts 10000
```

The benchmark uses documentation-range addresses and synthetic credentials; it
opens no capture interface. Its rates are useful for comparing builds on the
same host, not as a promise of live line-rate performance. Live capacity also
depends on frame size, protocol mix, detector matches, storage, kernel/libpcap
drops, and whether the independent raw ring shares the same disk or CPU budget.

The scripts are intended for current Kali/Debian systems using systemd. Read
them before running on an assessment host; installation changes packages,
accounts, file capabilities, and systemd files, but never network interception
state.
