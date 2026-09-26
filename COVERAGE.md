# Protocol coverage: Packet Inspector 0.1.5

Coverage describes wire formats, not a guarantee that every login is visible.
The sensor needs the relevant traffic, both directions for correlation, and
complete bytes within configured retention/reassembly limits. A network path,
capture filter, missing packet, encryption, or unsupported encoding can prevent
extraction. An SMB login does not necessarily use NTLM.

| Family | Implemented detection | Important boundaries |
| --- | --- | --- |
| SMB / NTLM | Raw NTLM Type 2/3, NetNTLMv1/v2 exports; direct-TCP SMB2/3 SESSION_SETUP session IDs keep concurrent sessions separate | Clear authentication exchange required. SMB1 and other raw wrappers have flow/direction correlation, not their own session dissectors. No SMB encrypted/compressed transform decoding or cross-connection/multichannel authentication correlation. |
| HTTP NTLM | Direct NTLM and bounded ASN.1 SPNEGO NegTokenInit/NegTokenResp in authentication headers | No Kerberos-to-NTLM conversion, HTTPS decryption, or arbitrary ASN.1 search. |
| Mail NTLM | Complete base64 NTLM/SPNEGO tokens in SMTP/POP3/IMAP lines on 25/587/110/143 | 16 KiB encoded token limit; not encrypted SMTP/IMAP/POP3 sessions. |
| LDAP | BER simple bind credentials; embedded raw NTLM in SASL exchanges | Does not decode every SASL mechanism, signed/sealed application data, or LDAPS. Repeated binds are separately emitted. |
| HTTP cleartext | Basic, form/query fields, typed JSON secrets, cookies, Bearer, Digest | HTTP/1 framing. See LOGIN_FIELDS.md. No deep HTTP/2, multipart, or compressed body decoding. |
| FTP / POP3 | USER/PASS correlation | Clear command channel only. |
| SMTP | AUTH PLAIN and LOGIN, including multistep forms | No TLS or every SASL mechanism. |
| IMAP | LOGIN, AUTHENTICATE PLAIN/LOGIN | Not a complete IMAP literal/extension implementation. |
| Redis | RESP AUTH, HELLO AUTH, simple/matched-quote inline AUTH, username and password | Port 6379; bounded fields/frames; escaped inline forms are not guessed. |
| PostgreSQL | PasswordMessage; confirmed cleartext when server requests method 3 | Port 5432; otherwise method-unknown candidate. MD5/SASL responses are not labeled plaintext. No username pairing yet. |
| MSSQL | TDS Login7 deobfuscation | Not TLS, TDS8 encryption, or arbitrary multi-packet TDS framing. |
| SNMP | v1/v2c communities | Not SNMPv3 decryption. |
| IRC / Telnet-like | Registration secrets and recognizable login/password fields | Telnet prompt/field patterns, not a full negotiated terminal/keystroke reassembler. |
| Other authentication | Kerberos AS-REQ etype 23 and SIP Digest when required fields are present | Not universal Kerberos, RADIUS, EAP or VPN decoding. |
| Generic secrets | Named secret fields, selected tokens, JWTs, PEM private keys and Luhn-valid card candidates | Candidates are not validity or successful-authentication claims. |

The table deliberately does not claim "all protocols." Dedicated MySQL
mysql_clear_password, PostgreSQL SCRAM/MD5 export, RADIUS/PAP, MQTT CONNECT,
AMQP/SASL, XMPP SASL, SOCKS5 username/password, and full Telnet handling are not
implemented/qualified here. These are potential additions, not advertised
coverage. Protocols on nonstandard ports need a dedicated test before relying
on the port-gated detectors.

The default capture filter admits IPv4/IPv6 and recognized outer VLAN tags
(802.1Q, 802.1ad, 0x9100 and 0x9200) on Ethernet and Linux cooked links. The
decoder then checks up to eight stacked tags and processes only inner IP. The
filter deliberately includes non-IP traffic inside those VLANs, which the
decoder discards; qualify the resulting capture load on the target host.
Physical-adapter VLAN delivery on Windows also depends on the Npcap driver and
network adapter; validate with traffic from the intended capture interface.

## Correlation and bounds

SMB2 session scoping validates the enclosing SESSION_SETUP security-buffer
offset/length and direct-TCP header. It uses already-retained stream data, not
an unbounded session cache. Its challenges share the existing per-flow and
global NTLM budgets. If a recognized SMB2 flow loses session framing, raw Type
2/3 evidence is exported with a limitation; a paired hash is not guessed and a
coverage counter marks the session incomplete. Unscoped raw NTLM correlation
outside the SMB2 parser assumes sequential exchanges within one TCP epoch.
For a validated SMB2 SessionId of zero, a response pairs only with the sole
unresolved challenge in that TCP connection and is marked high confidence;
competing challenges remain unpaired and raise a coverage counter.

Redis and PostgreSQL use persistent frame-boundary cursors, so ordinary tail
rotation does not rescan nested values as commands. Fields are bounded to
8 KiB and authentication messages to 32 KiB. If an unfinished frame exceeds
retained data, that direction is marked coverage-incomplete until a new
connection; the parser does not invent a resynchronization point inside a value.
Oversized/unsupported recognized auth records are reported as coverage limits.

Distinct protocol retries are retained. TCP retransmission of the same stream
bytes is not an additional authentication attempt. NetNTLM material is a
challenge/response, not a plaintext password or the account's reusable NT hash.

## Primary protocol references

- [Microsoft SMB2 authentication relationship](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/06451bf2-578a-4b9d-94c0-8ce531bf14c4)
- [SMB2 SESSION_SETUP response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/0324190f-a31b-4666-9fa9-5c624273a694)
- [SMB2 SESSION_SETUP request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a3c2c28-d6b0-48ed-b917-a86b2ca4575f)
- [SPNEGO ASN.1 definitions, RFC 4178](https://www.rfc-editor.org/rfc/rfc4178.html)
- [Redis AUTH](https://redis.io/docs/latest/commands/auth/), [HELLO](https://redis.io/docs/latest/commands/hello/)
- [PostgreSQL message formats](https://www.postgresql.org/docs/current/protocol-message-formats.html)
