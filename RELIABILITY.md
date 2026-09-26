# Reliability and acceptance gate

## What 0.1.5 changes

- Validated SMB2 frames with a zero SessionId retain that value. A Type 3
  response can correlate with the sole unresolved Type 2 challenge in the same
  TCP connection at high confidence; competing challenges stay unpaired and
  raise a coverage counter. Deferred reassembly and sequential exchanges have
  regressions.
- Offline replay waits for worker queue capacity so a readable PCAP burst does
  not become an artificial userspace loss. Live capture remains bounded and
  reports queue drops.
- The default analyzer and raw-ring filter admits recognized outer VLAN tags.
  The decoder handles up to eight stacked Ethernet/Linux cooked tags and drops
  non-IP traffic admitted by the broad filter. Npcap native replay tests check
  tagged Ethernet and Windows loopback capture filter behavior.

## What 0.1.4 changes

- Capture uses bounded `next()` reads instead of native callback dispatch when
  available. A Kali Python 3.13 binding reproduced a callback argument error;
  the previous fallback could consume a packet and then silently skip it.
  Callback-only compatibility paths now fail visibly on errors or count
  disagreement instead of falling through after consuming data.
- A native libpcap offline regression checks every packet, byte and timestamp
  across multiple batch boundaries. Live acceptance must still be run on the
  actual sensor; mocked capture tests alone did not detect this binding fault.

## Reliability controls introduced in 0.1.3

- Live libpcap must support nonblocking mode. Idle reads wait at most 100ms
  between iterations instead of depending on a blocking packet-buffer timeout.
- The shipped systemd service is Type=notify with a 90-second watchdog. The
  main process sends progress only after a completed capture/read/dispatch and
  child-health iteration. There is no timer thread that can hide a wedged loop.
- systemd readiness follows initialization of capture, workers and writer;
  startup has a 90-second limit. Notify failures fail visibly.
- The external watchdog detects missing progress after 90 seconds. Actual
  termination/restart follows systemd stop/restart policy; do not interpret
  that as a promise to recover all packets or restart within 90 seconds.
- Existing worker/writer progress checks, bounded queues, loss counters, raw
  ring checks, crash-loop circuit breaker and durable shutdown acknowledgement
  remain. Standalone CLI execution does not have systemd's external watchdog.

A restart loses in-memory reassembly state and can miss traffic during recovery.
It is a visible recovery mechanism, not seamless capture. A forced kill may not
write a final summary: absence of a completed session verdict is itself a gap.
Preserve journald/service events and the independent raw ring with JSONL evidence.

## Automated evidence

All fixtures use synthetic credentials and generated traffic; no assessment
captures are committed. The test suite includes:

- 1,500 repeated HTTP logins over five flows/two worker processes, 6,010 packets,
  reordered segments, retransmissions and a split final field; exactly 1,500
  expected credential events and reconciled worker/writer counts.
- NetNTLMv1/v2, raw/HTTP/SPNEGO wrappers, distinct retries, missing/wrong-flow
  challenges, connection epochs, and interleaved SMB2 session identifiers.
- Byte-by-byte and whole-buffer protocol tests, including repeated LDAP binds.
- Redis frame-cursor retention over 1,000 attempts and PostgreSQL method guards.
- Alive-but-stale workers, writer death, worker restarts/circuit breaking,
  bounded startup, injected ENOSPC write/fsync failures and a genuinely blocked
  synthetic capture read that cannot keep sending watchdog heartbeats.
- Real Unix datagram notification tests on Linux; these are skipped on Windows.

The synthetic benchmark is a regression comparison, not a live-NIC capacity
measurement. A short burst is not a long-duration soak. Unit fault injection is
not an actual full disk, interface disconnect or OS/kernel failure exercise.

## Required before depending on a sensor for an assessment

1. Verify the installed build, interface, capture filter, raw ring, free disk,
   permissions, systemd readiness and advancing capture/worker/writer counters.
2. With synthetic lab accounts and a known ground-truth count, exercise actual
   NTLM SMB and required cleartext applications across the approved sensor path.
   Count complete exchanges independently from preserved PCAP and compare both
   endpoints, challenges/responses, retries, JSONL records and dashboard entries.
3. Measure detection/export latency from the last required packet, at idle and
   under the expected traffic mix/load; record p50/p95/p99 and maximum latency.
4. Run a multi-hour representative soak. Record libpcap/interface/raw-ring
   losses, queue peaks, process RSS/CPU, parser/coverage counters, disk use and
   final acknowledgements. Missing counters are unknown, not zero.
5. In an isolated test instance, inject a blocked read, worker/writer failure,
   full disk and link interruption. Prove visible failure, service behaviour and
   evidence preservation; do not inject faults into the production assessment.

There is no universal pass rate or throughput figure without that host-specific
qualification. A final "complete" verdict means available accounting and
configured coverage checks reconciled; it does not certify every protocol or
prove that all network traffic reached the capture interface.
