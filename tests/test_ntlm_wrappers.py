"""Synthetic SMB2/SPNEGO correlation regression, no network authentication."""
import base64
import struct

import pytest

from packet_audit.detectors import SensitiveDetector
from packet_audit.ntlm_wrappers import smb2_session_for_token, unwrap_ntlm
from tests.test_detectors import by_type, der, flow, ntlm_type2, ntlm_type3
from tests.test_protocol_coverage import feed


def spnego(token, *, initial=False):
    value = der(0xA0 if initial else 0xA1, der(0x30, der(0xA2, der(4, token))))
    return der(0x60, der(6, b"\x2b\x06\x01\x05\x05\x02") + value) if initial else value


def smb2(token, session, *, response=False):
    token = spnego(token)
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    struct.pack_into("<H", header, 4, 64)
    struct.pack_into("<H", header, 12, 1)
    struct.pack_into("<I", header, 16, int(response))
    struct.pack_into("<Q", header, 40, session)
    fixed = bytearray(8 if response else 24)
    struct.pack_into("<H", fixed, 0, len(fixed) + 1)
    struct.pack_into("<HH", fixed, 4 if response else 12, len(header) + len(fixed), len(token))
    frame = bytes(header + fixed) + token
    return b"\x00" + len(frame).to_bytes(3, "big") + frame


@pytest.mark.parametrize("initial", [False, True])
def test_spnego_only_unwraps_explicit_complete_ntlm_token(initial):
    token = ntlm_type2(b"TESTONLY")
    wrapper = spnego(token, initial=initial)
    assert unwrap_ntlm(wrapper) == token
    assert unwrap_ntlm(token) == token
    for end in range(len(wrapper)):
        assert unwrap_ntlm(wrapper[:end]) is None
    assert unwrap_ntlm(spnego(b"not-ntlm")) is None
    assert unwrap_ntlm(der(4, token)) is None
    assert unwrap_ntlm(wrapper + b"junk") is None
    assert unwrap_ntlm(der(0xA1, der(0x30, der(0xA2, der(4, token)) * 2))) is None


@pytest.mark.parametrize("width", [1, 7, 4096])
@pytest.mark.parametrize("version", [1, 2])
def test_concurrent_smb_sessions_never_cross_pair_and_keep_retries(width, version):
    detector = SensitiveDetector("synthetic-smb")
    target = flow(dport=445)
    server = smb2(ntlm_type2(b"SESSIONA"), 101, response=True) + smb2(ntlm_type2(b"SESSIONB"), 202, response=True)
    _, packet_id = feed(detector, server, target, direction=1, width=width)
    nt = b"N" * 24 if version == 1 else b"P" * 16 + b"\x01\x01\x00\x00" + b"B" * 28
    tokens = [smb2(ntlm_type3(nt_response=nt, username=user), session)
              for user, session in (("synthetic-a", 101), ("synthetic-b", 202), ("synthetic-a", 101))]
    findings, _ = feed(detector, b"".join(tokens), target, packet_id=packet_id, width=width)
    pairs = by_type(findings, f"netntlmv{version}")
    assert len(pairs) == 3
    assert [p.material["challenge_hex"] for p in pairs] == [b"SESSIONA".hex(), b"SESSIONB".hex(), b"SESSIONA".hex()]
    assert [p.material["smb_session_id"] for p in pairs] == [101, 202, 101]
    assert all(p.direction == 0 and p.packet_ids_complete for p in pairs)
    assert detector.stats()["parser_errors"] == 0


def test_smb_response_cannot_use_a_different_session_or_unscoped_challenge():
    for challenge in (ntlm_type2(b"TESTONLY"), smb2(ntlm_type2(b"TESTONLY"), 100, response=True)):
        detector = SensitiveDetector("synthetic-smb")
        target = flow(dport=445)
        _, packet_id = feed(detector, challenge, target, direction=1)
        findings, _ = feed(detector, smb2(ntlm_type3(nt_response=b"N" * 24), 200), target, packet_id=packet_id)
        assert by_type(findings, "ntlm_type3_response")
        assert not by_type(findings, "netntlmv1")


def test_smb_scoping_requires_a_valid_security_buffer_and_transport_header():
    wire = smb2(ntlm_type2(b"TESTONLY"), 42, response=True)
    position = wire.index(b"NTLMSSP\x00")
    assert smb2_session_for_token(wire, position) == 42
    assert smb2_session_for_token(wire[4:], position - 4) is None
    bad = bytearray(wire)
    struct.pack_into("<H", bad, 4 + 68, 65535)
    assert smb2_session_for_token(bad, position) is None


@pytest.mark.parametrize("width", [1, 7, 4096])
def test_zero_session_smb2_responder_exchange_is_correlated(width):
    """A Responder-style server can leave SessionId zero through Type 3."""
    detector = SensitiveDetector("synthetic-zero-smb-session")
    target = flow(dport=445)
    challenge = smb2(ntlm_type2(b"TESTONLY"), 0, response=True)
    position = challenge.index(b"NTLMSSP\x00")
    assert smb2_session_for_token(challenge, position) == 0
    _, packet_id = feed(detector, challenge, target, direction=1, width=width)
    response = smb2(
        ntlm_type3(nt_response=b"P" * 16 + b"\x01\x01\x00\x00" + b"B" * 28),
        0,
    )
    findings, _ = feed(detector, response, target, packet_id=packet_id, width=width)
    pairs = by_type(findings, "netntlmv2")
    assert len(pairs) == 1
    assert pairs[0].material["smb_session_id"] == 0
    assert pairs[0].confidence == "high"
    assert detector.stats().get("coverage_ntlm_session_unavailable", 0) == 0


def test_competing_zero_session_challenges_are_not_guessed():
    detector = SensitiveDetector("synthetic-overlapping-zero-sessions")
    target = flow(dport=445)
    challenges = (smb2(ntlm_type2(b"FIRSTONE"), 0, response=True)
                  + smb2(ntlm_type2(b"SECOND__"), 0, response=True))
    _, packet_id = feed(detector, challenges, target, direction=1)
    response = smb2(ntlm_type3(nt_response=b"N" * 24), 0)
    findings, _ = feed(detector, response, target, packet_id=packet_id)
    assert by_type(findings, "ntlm_type3_response")
    assert not by_type(findings, "netntlmv1")
    assert detector.stats()["coverage_ntlm_zero_session_ambiguous"] >= 1


def test_sequential_zero_session_challenges_can_pair():
    detector = SensitiveDetector("synthetic-sequential-zero-sessions")
    target = flow(dport=445)
    packet_id = 1
    server_offset = client_offset = 0
    for value in (b"FIRSTONE", b"SECOND__"):
        challenge = smb2(ntlm_type2(value), 0, response=True)
        response = smb2(ntlm_type3(nt_response=b"N" * 24), 0)
        _, packet_id = feed(detector, challenge, target, direction=1,
                            offset=server_offset, packet_id=packet_id)
        findings, packet_id = feed(detector, response, target,
                                   offset=client_offset, packet_id=packet_id)
        pairs = by_type(findings, "netntlmv1")
        assert len(pairs) == 1
        assert pairs[0].material["challenge_hex"] == value.hex()
        server_offset += len(challenge)
        client_offset += len(response)


def test_smb_signature_without_a_header_does_not_disable_unscoped_ntlm():
    detector = SensitiveDetector("synthetic-smb-decoy")
    target = flow(dport=445)
    _, packet_id = feed(detector, b"decoy-\xfeSMB-" + ntlm_type2(b"TESTONLY"),
                        target, direction=1)
    findings, _ = feed(detector, ntlm_type3(nt_response=b"N" * 24),
                       target, packet_id=packet_id)
    assert len(by_type(findings, "netntlmv1")) == 1


@pytest.mark.parametrize("width", [1, 7, 4096])
def test_http_spnego_challenge_response_and_retries(width):
    detector = SensitiveDetector("synthetic-spnego")
    target = flow(dport=80)
    challenge = (b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate "
                 + base64.b64encode(spnego(ntlm_type2(b"TESTONLY")))
                 + b"\r\nContent-Length: 0\r\n\r\n")
    response = (b"GET / HTTP/1.1\r\nHost: synthetic.invalid\r\nAuthorization: Negotiate "
                + base64.b64encode(spnego(ntlm_type3(nt_response=b"N" * 24), initial=True)) + b"\r\n\r\n")
    _, packet_id = feed(detector, challenge, target, direction=1, width=width)
    findings, _ = feed(detector, response * 3, target, packet_id=packet_id, width=width)
    assert len(by_type(findings, "netntlmv1")) == 3


@pytest.mark.parametrize("port,prefix", [(25, b"334 "), (587, b"334 "), (110, b"+ "), (143, b"+ ")])
@pytest.mark.parametrize("wrapped", [False, True])
@pytest.mark.parametrize("width", [1, 7, 4096])
def test_mail_ntlm_tokens_and_retries(port, prefix, wrapped, width):
    detector = SensitiveDetector("synthetic-mail")
    target = flow(dport=port)
    challenge, response = ntlm_type2(b"TESTONLY"), ntlm_type3(nt_response=b"N" * 24)
    if wrapped:
        challenge, response = spnego(challenge), spnego(response)
    _, packet_id = feed(detector, prefix + base64.b64encode(challenge) + b"\r\n", target, direction=1, width=width)
    findings, _ = feed(detector, (base64.b64encode(response) + b"\r\n") * 3, target, packet_id=packet_id, width=width)
    assert len(by_type(findings, "netntlmv1")) == 3


def test_arbitrary_base64_is_not_mail_ntlm():
    detector = SensitiveDetector("synthetic-mail")
    findings, _ = feed(detector, b"334 " + base64.b64encode(b"ordinary text" * 20) + b"\r\n", flow(dport=25))
    assert not by_type(findings, "ntlm_type2_challenge")
    assert not by_type(findings, "netntlmv1")


def test_known_smb_with_missing_scope_exports_response_without_guessing_hash():
    detector = SensitiveDetector("synthetic-smb")
    target = flow(dport=445)
    server = smb2(ntlm_type2(b"TESTONLY"), 42, response=True)
    _, packet_id = feed(detector, server, target, direction=1)
    response = ntlm_type3(nt_response=b"N" * 24)
    findings, _ = feed(detector, response, target, packet_id=packet_id)
    assert by_type(findings, "ntlm_type3_response")
    assert not by_type(findings, "netntlmv1")
    assert detector.stats()["coverage_ntlm_session_unavailable"] == 1
