# Windows release validation - 0.1.4+win.1

Candidate build, validated on 2026-09-16. Source baseline: upstream 0.1.4,
commit `575dc2364d20bb7e7e36d96edeaef207c61ff41f`. Test traffic is synthetic;
no physical LAN adapter was used for live validation of this Windows port.

## Completed native checks

- Native Npcap 1.88 / libpcap 1.10.6 loaded from the Windows system Npcap
  directory; interface enumeration and BPF compilation succeeded.
- Offline native PCAP and PCAPNG iteration, Unicode filenames, more records
  than a read batch, EOF/error distinction and byte-copy bounds are tested.
- A native loopback live run sent **200 separate, identical synthetic HTTP
  Basic logins**, after an idle interval across raw-ring rotation. The analyzer
  emitted **200 findings**. Analysis capture and replay of the independent raw
  ring each counted **2,200 packets**. Verdict: **complete**, with no forced raw
  termination, no incomplete reasons and a verified private export ACL.
- The complete shared-engine test suite and Windows-specific tests pass:
  **649 passed, 10 skipped**. See [VALIDATION-REPORT.md](VALIDATION-REPORT.md)
  for skip reasons and installed-package checks.
- The installed PowerShell 5.1 launcher, running from a path containing spaces,
  captured another 12 synthetic loopback logins. Its token-free loopback HTTP
  viewer returned all 12 with both endpoints. A real Ctrl+C event sent only to
  that owned test console drained all workers and the writer, stopped dumpcap
  gracefully, printed a complete verdict, closed the viewer and exited zero.
- The installed replay launcher decoded the resulting 132-packet PCAPNG and
  exported the same 12 findings, with a complete verdict.
- Windows tests exercise broad-ACL refusal, private ACL inheritance, junction
  and hardlink refusal, local-path restrictions, native loopback decoding,
  raw-ring filename uniqueness, and worker/export drain after injected raw
  shutdown failure. Synthetic tests also retain the existing protocol and
  reliability regression coverage.

The 200-attempt run is a functional smoke test, not a throughput benchmark,
long-duration soak, proof of zero loss, or live SMB/LDAP qualification. Its
captures and unredacted synthetic findings are kept outside the distribution.

## Required acceptance checks on each deployment

1. Verify package SHA-256, Python architecture, Npcap access and adapter choice.
2. Generate known authorized cleartext HTTP logins and repeated test attempts;
   compare expected count, endpoint addresses/ports, dashboard and JSONL.
3. Generate a known NTLM SMB exchange on the controlled rig where both
   directions are visible. Verify the challenge/response against the saved
   raw capture. Repeat for LDAP and the other protocols in assessment scope.
   A successful SMB login using Kerberos is not an NTLM capture test.
4. Leave capture idle, resume traffic, and cross several ring rotations. Test
   the real expected load and assessment duration, measuring driver drops,
   queue pressure, worker heartbeats, writer acknowledgements and coverage
   counters. Compare with an independent expected-flow/packet baseline.
5. Press Ctrl+C and wait for drain/final verdict. Verify the final PCAPNG opens
   and that no owned dumpcap/worker remains. Do not equate process liveness
   with healthy capture.
6. Test permission denial, unavailable/full evidence storage and interruption
   safely with disposable synthetic evidence. Confirm incomplete/failure is
   visible rather than a false complete result.

Windows versions, USB/Wi-Fi drivers, Npcap admin-only installations, interface
disconnect/reconnect, sustained line-rate load and endpoint-security products
need deployment-specific qualification. This package is not yet certified for
those combinations. Consult the existing RELIABILITY.md for shared-engine
limits; its Linux/Kali results do not constitute Windows hardware validation.
