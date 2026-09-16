# Packet Audit notices

Copyright (C) 2026 Packet Audit contributors.

Packet Audit is distributed under the GNU General Public License, version 3 or
(at your option) any later version. See `LICENSE`.

## Authorized assessment use

This software observes and may record authentication material, secrets,
personal data, and complete network payloads. Possession of the software is not
authorization to intercept traffic. Operators are responsible for a written scope,
lawful authority, change approval for any active interception, data
minimization, access control, retention, and cleanup.

Unredacted JSONL and raw PCAP/PCAPNG files are restricted evidence. The supplied
Kali service uses a `0077` umask; unredacted files must remain mode `0600` and raw
capture directories mode `0700`. Do not publish raw authentication material or
mistake a captured challenge-response for a password, reusable NT hash, verified
identity, or proof of compromise.

The Windows launcher uses protected Windows ACLs for its evidence directories
and validates existing destinations through Windows security APIs. Unix mode
bits and Kali service settings above do not describe the Windows permission
boundary. See `WINDOWS.md` for Windows evidence and local-dashboard access.

Packet Audit does not configure Ettercap, ARP poisoning, packet forwarding,
bridging, firewall rules, credential relay, credential use, cracking, lateral
movement, command-and-control, or persistence. Those activities are outside the
program and require their own explicit scope and controls.

## Third-party software

Packet Audit uses or interoperates with separately distributed software,
including:

- Python, from the Python Software Foundation.
- libpcap, from The Tcpdump Group.
- Npcap, distributed separately by the Nmap Project for native Windows capture.
  Review its installation and licensing terms at https://npcap.com/.
- `pcapy-ng`, maintained as a Python interface to libpcap.
- Wireshark command-line tools, particularly `dumpcap` and `tshark`, from the
  Wireshark Foundation and contributors.
- systemd, used by the optional Kali service template.

Those components retain their own copyright notices and license terms. Kali and
Debian packages install the corresponding notices under
`/usr/share/doc/PACKAGE/copyright`.
The Windows deployment ZIP does not redistribute Python, Npcap, or Wireshark
binaries; install these dependencies separately under their own license terms.

PCredz by Laurent Gaffie is an established GPL-licensed credential extraction
tool and informed the problem comparison that motivated Packet Audit's
loss-visible, stream-aware design. No claim is made here that PCredz authors
endorse Packet Audit. If PCredz source or another third-party implementation is
later incorporated, its original copyright, GPL notices, and source history must
be retained in the affected files and distribution metadata.

Protocol names, product names, and trademarks belong to their respective
owners. Their mention describes interoperability only.

## Security limitations

Detection is best-effort and bounded. Packet loss, snap-length truncation,
unsupported encapsulation, out-of-order data beyond configured limits, capture
started mid-flow, malformed traffic, and encryption can cause incomplete or
absent findings. TLS, QUIC/HTTP/3, SSH, and other protected application payloads
are not decrypted. Findings preserve completeness and limitation fields so that
an observation is not silently promoted into a stronger conclusion.

The software is provided without warranty; see the GPL for the controlling
terms.
