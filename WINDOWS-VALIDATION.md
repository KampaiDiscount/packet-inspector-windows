# Windows release validation - 0.1.6+win.2

Candidate checked on 2026-09-26 with 64-bit Python 3.12.14 and Npcap 1.88.
The current isolated Windows source passed these checks:

- **695 passed, 9 skipped, 28 subtests passed** in the complete native suite.
  The skips require Linux/POSIX behavior rather than Windows Npcap.
- The token regressions cover short explicit Bearer values, preference and
  session-cookie classification, signed and unsigned JWT structure, malformed
  and five-part non-JWT shapes, and a 5.3 KiB JWT split across four packets.
- The file regressions cover PNG, JPEG, GIF, WebP, PDF and ZIP signatures in
  HTTP/1 uploads and downloads, every two-packet split of a PNG request,
  provenance, bounded metadata, filename sanitization, MIME disagreement,
  first-part multipart and byte-zero partial responses. Unsupported framing
  and compressed/HTTP/2 cases raise visible coverage counters.
- Native Windows replay of a **12-packet Kali-to-Linode PNG HTTP PCAPNG**
  produced one high-confidence file-signature finding with complete packet provenance.
  Capture and dispatch counted 12 packets each, with zero reported drops or
  gaps and a complete verdict.
- A distinct **42-frame live Win11-to-Linode PNG exchange** was captured by Kali
  and replayed on Windows. The Win11 VM requested the file and received an HTTP
  200 PNG response; replay processed 42/42 packets, with a complete verdict and
  zero reported drops. It produced one high-confidence server-to-Win11 PNG
  file-signature finding with complete provenance (packet 19), plus two
  medium-confidence cookie candidates from the Win11 requests. The live Kali
  session counted 4,910 captured and dispatched packets with zero queue drops;
  forwarding was restored after the bounded test.
- A separate **46-packet synthetic valid-PNG upload/download PCAP** produced
  two file-signature findings and no credential finding from text embedded in
  the image. Its verdict was incomplete because the existing generic HTTP
  parser counted one image content type as unsupported; this does not erase
  the two file-signature observations.
- The candidate deployment ZIP's external SHA-256 and all **91 internal
  manifest entries** matched. It held one 0.1.6+win.2 wheel and one source
  archive. Setup from the extracted package installed that wheel offline and
  the isolated CLI reported `packet-audit 0.1.6+win.2`.

The older 12-packet PNG PCAPNG originated from Kali 192.168.1.10 communicating
with Linode; Windows was its replay host. This corrects its Win11 attribution
in the 0.1.6+win.1 notes. The 42-frame live Win11 PNG test above and the separate
real Win11 HTTP authentication matrix are distinct validation exercises.

The 0.1.5+win.1 results below are historical, including its live-loopback
and installed-launcher checks; those were not repeated for this candidate.
Physical Ethernet/Wi-Fi, live Windows SMB/LDAP, sustained load and
long-duration capture remain deployment-specific acceptance checks.

---

# Historical Windows release validation - 0.1.5+win.1

Candidate checked on 2026-09-26 with 64-bit Python 3.12.14 and Npcap 1.88.
The 0.1.5+win.1 source and extracted deployment ZIP passed these checks:

- **670 passed, 9 skipped, 28 subtests passed** in the complete Windows suite.
  The skipped tests require Linux/POSIX behavior rather than Windows Npcap.
- Native Npcap offline filtering retained untagged IPv4/IPv6, single- and
  double-tag Ethernet IP using 802.1Q, 802.1ad, 0x9100 and 0x9200, plus
  Windows loopback IPv4/IPv6. It also verified the shared analyzer/raw-ring
  default filter.
- The deployment ZIP's external SHA-256 and all 89 internal manifest entries
  matched. It contained one 0.1.5+win.1 wheel and one source archive. Fresh
  offline setup installed the wheel in its package-local environment.
- A native loopback run sent **12 synthetic HTTP Basic logins**; it emitted 12
  findings, and both the analyzer and independent raw ring counted 132 packets.
  Verdict: complete; private ACL verified; no forced raw termination.
- The installed PowerShell 5.1 launcher captured another 12/12 synthetic
  logins. Its dashboard showed all 12 with endpoints. A Ctrl+C event sent to
  that owned test console drained capture and viewer, exited zero and produced
  a complete verdict. Installed replay of its 132-packet raw ring reproduced
  12 findings with zero queue drops and a complete verdict.

These checks used synthetic loopback traffic and offline Ethernet frames. They
do not qualify a physical Ethernet/Wi-Fi adapter, live Windows SMB/LDAP,
sustained capture load, or every host/security-software combination. Apply the
deployment acceptance steps below before relying on a sensor in an assessment.

## Deployment acceptance checks

1. Verify the package checksum, Python architecture, Npcap access and exact
   interface. Confirm the default or explicit capture filter on the live host.
2. Generate authorized ground-truth authentication on each required protocol;
   compare both directions, raw capture, expected attempts and exported
   findings. For SMB, check both nonzero and zero SessionId exchanges if the
   target and test tooling exercise them.
3. Check loss and coverage counters, worker progress, raw-ring rotation and
   the final verdict across idle periods and representative load. Preserve
   evidence before the bounded raw ring rotates it out.
4. Confirm a clean Ctrl+C drain and private evidence access on the intended
   host. Treat missing or incomplete verdicts as unresolved coverage.

---

# Historical Windows release validation - 0.1.4+win.1

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
