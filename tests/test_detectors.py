from __future__ import annotations

import base64
import random

import pytest

from packet_audit.detectors import SensitiveDetector
from packet_audit.models import FlowKey, ParsedPacket, ProvenanceSpan, StreamChunk


def flow(sport: int = 40000, dport: int = 80, protocol: int = 6) -> FlowKey:
    value, _direction = FlowKey.canonical(
        protocol=protocol,
        src="10.0.0.10",
        sport=sport,
        dst="10.0.0.20",
        dport=dport,
        interface="eth0",
    )
    return value


def chunk(
    data: bytes,
    *,
    target_flow: FlowKey | None = None,
    direction: int = 0,
    offset: int = 0,
    packet_id: int = 1,
    timestamp: int | None = None,
    connection_epoch: int = 0,
    provenance_spans: tuple[ProvenanceSpan, ...] | None = None,
) -> StreamChunk:
    return StreamChunk(
        flow=target_flow or flow(),
        direction=direction,
        stream_offset=offset,
        data=data,
        packet_ids=(packet_id,),
        first_timestamp_ns=timestamp or packet_id * 1_000,
        last_timestamp_ns=timestamp or packet_id * 1_000,
        connection_epoch=connection_epoch,
        completeness="complete",
        provenance_spans=(
            ProvenanceSpan(offset, offset + len(data), (packet_id,)),
        )
        if provenance_spans is None
        else provenance_spans,
    )


def datagram(data: bytes, *, dport: int, packet_id: int = 1) -> ParsedPacket:
    return ParsedPacket(
        session_id="capture-session",
        packet_id=packet_id,
        timestamp_ns=packet_id * 1_000,
        interface="eth0",
        captured_length=len(data) + 42,
        wire_length=len(data) + 42,
        ip_version=4,
        src="10.0.0.10",
        dst="10.0.0.20",
        protocol=17,
        vlan_ids=(),
        network_payload=b"",
        transport_parsed=True,
        sport=40000,
        dport=dport,
        transport_payload=data,
    )


def by_type(findings, material_type: str):
    return [item for item in findings if item.material_type == material_type]


def test_detector_flow_state_is_bounded() -> None:
    detector = SensitiveDetector("session", max_flows=2)
    for index, sport in enumerate((41001, 41002, 41003), start=1):
        detector.process_stream(
            chunk(
                b"GET / HTTP/1.1\r\n\r\n",
                target_flow=flow(sport=sport),
                packet_id=index,
            )
        )
    stats = detector.stats()
    assert stats["active_flows"] == 2
    assert stats["evicted_flows"] == 1


def test_flow_lru_keeps_recently_touched_state() -> None:
    detector = SensitiveDetector("session", max_flows=2)
    payload = b"Authorization: Bearer abcdefghijklmnop\r\n"
    flow_a = flow(sport=41001)
    flow_b = flow(sport=41002)
    flow_c = flow(sport=41003)
    assert by_type(detector.process_stream(chunk(payload, target_flow=flow_a)), "bearer_token")
    assert by_type(detector.process_stream(chunk(payload, target_flow=flow_b, packet_id=2)), "bearer_token")
    assert detector.process_stream(chunk(payload, target_flow=flow_a)) == []  # A becomes MRU
    detector.process_stream(chunk(b"GET / HTTP/1.1\r\n\r\n", target_flow=flow_c, packet_id=3))
    assert detector.process_stream(chunk(payload, target_flow=flow_a)) == []
    # B was the least-recently used state and is therefore a fresh attempt.
    assert by_type(detector.process_stream(chunk(payload, target_flow=flow_b, packet_id=4)), "bearer_token")


def test_connection_epoch_isolates_reused_five_tuple() -> None:
    detector = SensitiveDetector("session")
    payload = b"Authorization: Bearer epoch-sensitive-token\r\n"
    first = detector.process_stream(chunk(payload, connection_epoch=11, packet_id=1))
    second = detector.process_stream(chunk(payload, connection_epoch=12, packet_id=2))
    first_token = by_type(first, "bearer_token")[0]
    second_token = by_type(second, "bearer_token")[0]
    assert first_token.connection_epoch == 11
    assert second_token.connection_epoch == 12
    assert first_token.flow_id.endswith("|epoch=11")
    assert second_token.flow_id.endswith("|epoch=12")
    assert first_token.attempt_ordinal == second_token.attempt_ordinal == 1
    assert detector.stats()["active_flows"] == 2
    assert detector.process_stream(chunk(payload, connection_epoch=12, packet_id=2)) == []


def test_finding_provenance_intersects_only_exact_matching_stream_bytes() -> None:
    detector = SensitiveDetector("session")
    prefix = b"GET / HTTP/1.1\r\nX-Audit: harmless\r\n"
    assert detector.process_stream(chunk(prefix, packet_id=10)) == []
    findings = detector.process_stream(
        chunk(
            b"Authorization: Bearer exact-provenance-token\r\n",
            offset=len(prefix),
            packet_id=11,
        )
    )

    finding = by_type(findings, "bearer_token")[0]
    assert finding.packet_ids == (11,)
    assert finding.packet_ids_complete is True


def test_split_match_preserves_more_than_32_exact_packet_contributors() -> None:
    detector = SensitiveDetector("session")
    offset = 0
    packet_id = 1
    for value in b"Authorization: Bearer ":
        detector.process_stream(
            chunk(bytes([value]), offset=offset, packet_id=packet_id)
        )
        offset += 1
        packet_id += 1

    token_packet_ids: list[int] = []
    # Construct an obvious dummy token; keep 40 separate provenance bytes.
    for value in b"X" * 40:
        token_packet_ids.append(packet_id)
        detector.process_stream(
            chunk(bytes([value]), offset=offset, packet_id=packet_id)
        )
        offset += 1
        packet_id += 1
    findings = detector.process_stream(
        chunk(b"\r\n", offset=offset, packet_id=packet_id)
    )

    finding = by_type(findings, "bearer_token")[0]
    assert finding.packet_ids == tuple(token_packet_ids)
    assert len(finding.packet_ids) == 40
    assert finding.packet_ids_complete is True


def test_provenance_cap_is_bounded_and_loss_is_visible_on_spanning_match() -> None:
    detector = SensitiveDetector(
        "session",
        max_provenance_spans=64,
        max_provenance_packet_id_refs=64,
    )
    offset = 0
    packet_id = 1
    payload = b"Authorization: Bearer " + b"A" * 80
    for value in payload:
        detector.process_stream(
            chunk(bytes([value]), offset=offset, packet_id=packet_id)
        )
        offset += 1
        packet_id += 1
    findings = detector.process_stream(
        chunk(b"\r\n", offset=offset, packet_id=packet_id)
    )

    finding = by_type(findings, "bearer_token")[0]
    stats = detector.stats()
    assert stats["provenance_spans"] <= stats["max_provenance_spans"]
    assert stats["provenance_packet_id_refs"] <= stats["max_provenance_packet_id_refs"]
    assert stats["provenance_cap_pressure_events"] > 0
    assert stats["provenance_cap_trimmed_spans"] > 0
    assert finding.packet_ids_complete is False
    assert stats["provenance_incomplete_findings"] > 0


def test_packet_id_per_finding_cap_is_explicit_and_loss_visible() -> None:
    detector = SensitiveDetector("session", max_packet_ids_per_finding=4)
    payload = b"password=abcdef\r\n"
    spans = tuple(
        ProvenanceSpan(index, index + 1, (100 + index,))
        for index in range(len(payload))
    )
    findings = detector.process_stream(
        chunk(payload, packet_id=1, provenance_spans=spans)
    )

    finding = by_type(findings, "sensitive_field")[0]
    assert len(finding.packet_ids) == 4
    assert finding.packet_ids_complete is False
    assert detector.stats()["provenance_packet_ids_truncated"] > 0


def test_global_retained_tail_cap_evicts_lru_and_trims_single_flow() -> None:
    detector = SensitiveDetector(
        "session", overlap_bytes=4096, max_retained_bytes=8192, max_flows=100
    )
    noise = b"x" * 4096
    for packet_id, sport in enumerate((42001, 42002, 42003), start=1):
        detector.process_stream(
            chunk(noise, target_flow=flow(sport=sport), packet_id=packet_id)
        )
    stats = detector.stats()
    assert stats["retained_tail_bytes"] <= 8192
    assert stats["retained_detector_bytes"] <= 8192
    assert stats["active_flows"] == 2
    assert stats["byte_cap_evicted_flows"] == 1
    assert stats["max_metadata_entries"] == 64

    single = SensitiveDetector(
        "session", overlap_bytes=128 * 1024, max_retained_bytes=4096
    )
    single.process_stream(chunk(b"z" * 32_768))
    stats = single.stats()
    assert stats["active_flows"] == 1
    assert stats["retained_tail_bytes"] == 4096
    assert stats["tail_bytes_trimmed"] == 32_768 - 4096


def test_global_metadata_cap_evicts_whole_lru_flows() -> None:
    detector = SensitiveDetector(
        "session",
        max_flows=2_000,
        max_retained_bytes=16 * 1024 * 1024,
        max_metadata_entries=512,
    )
    payload = b"Authorization: Bearer metadata-pressure-token\r\n"
    for packet_id in range(600):
        detector.process_stream(
            chunk(
                payload,
                target_flow=flow(sport=20_000 + packet_id),
                packet_id=packet_id + 1,
                connection_epoch=packet_id + 1,
            )
        )
    stats = detector.stats()
    assert stats["metadata_entries"] <= 512
    assert stats["peak_metadata_entries"] <= 512
    assert stats["max_metadata_entries"] == 512
    assert stats["metadata_cap_pressure_events"] > 0
    assert stats["metadata_cap_evicted_flows"] > 0
    assert stats["metadata_cap_saturated"] == 0


def test_retry_volume_does_not_grow_identity_metadata() -> None:
    detector = SensitiveDetector(
        "session", max_metadata_entries=512, max_retained_bytes=4 * 1024 * 1024
    )
    payload = b"Authorization: Bearer every-retry-token\r\n"
    offset = 0
    findings = 0
    for packet_id in range(2_000):
        emitted = detector.process_stream(
            chunk(payload, offset=offset, packet_id=packet_id + 1)
        )
        findings += len(by_type(emitted, "bearer_token"))
        offset += len(payload)
    assert findings == 2_000
    stats = detector.stats()
    assert stats["metadata_entries"] == 1
    assert stats["metadata_cap_pressure_events"] == 0

    # Replaying identical buffered bytes is still suppressed without adding
    # an identity entry per attempt.
    assert detector.process_stream(
        chunk(payload, offset=offset - len(payload), packet_id=2_000)
    ) == []
    assert detector.stats()["metadata_entries"] == 1


def test_http_material_and_absolute_offset_retry_semantics() -> None:
    detector = SensitiveDetector("session")
    authorization = base64.b64encode(b"alice:correct horse battery staple")
    request = (
        b"POST /login?token=query-token-123 HTTP/1.1\r\n"
        b"Host: audit.example\r\n"
        b"Authorization: Basic " + authorization + b"\r\n"
        b"Cookie: sid=session-abcdef; theme=dark\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
        b"username=alice&password=body-secret-123\r\n"
    )
    first = detector.process_stream(chunk(request, packet_id=1))
    basic = by_type(first, "http_basic_credentials")
    assert len(basic) == 1
    assert basic[0].material["username"] == "alice"
    assert basic[0].material["password"] == "correct horse battery staple"
    assert basic[0].stream_offset == request.index(authorization)
    assert by_type(first, "cookie")[0].material["pairs"][0] == {
        "name": "sid",
        "value": "session-abcdef",
    }
    values = [finding.material["value"] for finding in by_type(first, "sensitive_field")]
    assert "query-token-123" in values
    assert "body-secret-123" in values

    # The exact same stream bytes are not emitted twice.
    assert detector.process_stream(chunk(request, packet_id=1)) == []

    # A genuine retry at a new absolute offset is emitted, even with identical
    # user and password values.
    retry = detector.process_stream(
        chunk(request, offset=len(request), packet_id=2)
    )
    retry_basic = by_type(retry, "http_basic_credentials")
    assert len(retry_basic) == 1
    assert retry_basic[0].attempt_ordinal == 2
    assert retry_basic[0].stream_offset == len(request) + request.index(authorization)


def test_framed_http_form_does_not_become_terminal_authentication() -> None:
    body = b"username=synthetic-user&password=synthetic-password"
    request = (
        b"POST /form HTTP/1.1\r\n"
        b"Host: synthetic.invalid\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    findings = SensitiveDetector("session").process_stream(
        chunk(request, target_flow=flow(40000, 8888))
    )
    assert any(
        item.material["value"] == "synthetic-password"
        for item in by_type(findings, "sensitive_field")
    )
    assert not by_type(findings, "telnet_like_login_field")
    assert not by_type(findings, "http_text_login_field")
    assert not any(
        item.protocol in {"telnet", "plaintext_terminal", "ftp_or_pop3", "ftp", "pop3", "smtp", "imap"}
        for item in findings
    )


def test_http_authorization_scheme_is_not_a_generic_secret() -> None:
    body = b"client_secret=synthetic-secret-123\n"
    request = (
        b"POST /generic HTTP/1.1\r\n"
        b"Host: synthetic.invalid\r\n"
        b"Authorization: Negotiate synthetic-placeholder\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    findings = SensitiveDetector("session").process_stream(
        chunk(request, target_flow=flow(40000, 8888))
    )
    named = by_type(findings, "named_secret")
    assert [(item.material["name"], item.material["value"]) for item in named] == [
        ("client_secret", "synthetic-secret-123")
    ]


def test_short_explicit_http_bearer_is_a_credential() -> None:
    request = (
        b"GET / HTTP/1.1\r\nHost: synthetic.invalid\r\n"
        b"Authorization: Bearer abc123\r\n\r\n"
    )
    findings = SensitiveDetector("session").process_stream(
        chunk(request, target_flow=flow(40000, 8080))
    )
    bearer = by_type(findings, "bearer_token")
    assert len(bearer) == 1
    assert bearer[0].material == "abc123"
    assert bearer[0].protocol == "http"
    assert bearer[0].confidence == "confirmed"

    overlong = request.replace(b"abc123", b"x" * 8193)
    assert not by_type(SensitiveDetector("session").process_stream(chunk(overlong)), "bearer_token")


def test_cookie_observation_does_not_claim_preference_is_a_session() -> None:
    request = (
        b"GET / HTTP/1.1\r\nHost: synthetic.invalid\r\n"
        b"Cookie: theme=dark\r\n\r\n"
    )
    ordinary = by_type(SensitiveDetector("session").process_stream(chunk(request)), "cookie")
    assert len(ordinary) == 1
    assert ordinary[0].material["pairs"] == [{"name": "theme", "value": "dark"}]
    assert ordinary[0].category == "cookie"
    assert ordinary[0].confidence == "medium"

    session_request = request.replace(b"theme=dark", b"__Host-session=synthetic-value")
    session = by_type(SensitiveDetector("session").process_stream(chunk(session_request)), "cookie")
    assert len(session) == 1
    assert session[0].category == "session"
    assert session[0].confidence == "medium"
    assert "not tested" in session[0].limitations[0]


def test_jwt_requires_bounded_json_structure_and_accepts_whitespace() -> None:
    def compact(header: bytes, payload: bytes) -> bytes:
        def encode(value: bytes) -> bytes:
            return base64.urlsafe_b64encode(value).rstrip(b"=")

        return encode(header) + b"." + encode(payload) + b"." + encode(b"synthetic-signature-bytes")

    valid = compact(b' {"alg":"HS256"}', b'{"sub":"synthetic-user"}')
    unsigned = (
        base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=") + b"."
        + base64.urlsafe_b64encode(b'{"sub":"synthetic-user"}').rstrip(b"=") + b"."
    )
    invalid_header = compact(b'{"missing":"alg"}', b'{"sub":"synthetic-user"}')
    invalid_payload = compact(b'{"alg":"HS256"}', b'not-json')
    unsupported_alg = compact(b'{"alg":"none"}', b'{"sub":"synthetic-user"}')
    array_payload = compact(b'{"alg":"HS256"}', b'[]')
    oversized_header = compact(b'{"alg":"HS256","padding":"' + b"x" * 3000 + b'"}', b'{}')
    jwe_like = valid + b".extra.segment"
    for candidate in (invalid_header, invalid_payload, unsupported_alg, array_payload, oversized_header, jwe_like):
        request = b"GET / HTTP/1.1\r\nX-Test: " + candidate + b"\r\n\r\n"
        assert not by_type(SensitiveDetector("session").process_stream(chunk(request)), "jwt")

    request = b"GET / HTTP/1.1\r\nX-Test: " + valid + b"\r\n\r\n"
    detector = SensitiveDetector("session")
    split = request.index(valid) + len(valid) // 2
    assert not by_type(detector.process_stream(chunk(request[:split], packet_id=1)), "jwt")
    findings = detector.process_stream(chunk(request[split:], offset=split, packet_id=2))
    jwt = by_type(findings, "jwt")
    assert len(jwt) == 1
    assert jwt[0].material == valid.decode("ascii")
    assert jwt[0].confidence == "high"
    assert "not verified" in jwt[0].limitations[0]

    unsigned_request = b"GET / HTTP/1.1\r\nX-Test: " + unsigned + b"\r\n\r\n"
    unsigned_findings = by_type(SensitiveDetector("session").process_stream(chunk(unsigned_request)), "jwt")
    assert len(unsigned_findings) == 1
    assert unsigned_findings[0].material == unsigned.decode("ascii")
    assert unsigned_findings[0].confidence == "medium"
    assert "Unsigned" in unsigned_findings[0].limitations[0]

    standalone = SensitiveDetector("session").process_stream(chunk(b"Observed: " + valid + b"\n"))
    assert len(by_type(standalone, "jwt")) == 1


def test_http_text_line_keeps_short_secret_with_http_context() -> None:
    body = b"login: synthetic-user\npassword: x\n"
    request = (
        b"POST /text HTTP/1.1\r\n"
        b"Host: synthetic.invalid\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    findings = SensitiveDetector("session").process_stream(
        chunk(request, target_flow=flow(40000, 8888))
    )
    fields = by_type(findings, "http_text_login_field")
    assert [(item.protocol, item.material["field"], item.material["value"]) for item in fields] == [
        ("http", "login", "synthetic-user"),
        ("http", "password", "x"),
    ]
    assert not by_type(findings, "telnet_like_login_field")


def test_unframed_name_value_is_generic_not_http() -> None:
    line = b"api_key=synthetic-key-123\r\n"
    findings = SensitiveDetector("session").process_stream(
        chunk(line, target_flow=flow(40000, 2323))
    )
    field = by_type(findings, "sensitive_field")[0]
    assert field.protocol == "generic"
    assert field.confidence == "medium"
    assert field.material["source"] == "unframed_name_value"
    assert field.material["value"] == "synthetic-key-123"
    assert by_type(findings, "named_secret")


def test_http_response_start_line_gives_unframed_field_http_context() -> None:
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
        b"api_key=synthetic-key-123\r\n"
    )
    findings = SensitiveDetector("session").process_stream(
        chunk(response, target_flow=flow(40000, 8888), direction=1)
    )
    field = by_type(findings, "sensitive_field")[0]
    assert field.protocol == "http"
    assert field.material["value"] == "synthetic-key-123"


def test_split_stream_header_is_reconstituted_without_partial_false_hit() -> None:
    detector = SensitiveDetector("session")
    whole = b"Authorization: Bearer abcdefghijklmnopqrstuvwxyz\r\n"
    first = whole[:18]
    second = whole[18:]
    assert detector.process_stream(chunk(first, offset=0, packet_id=1)) == []
    findings = detector.process_stream(chunk(second, offset=len(first), packet_id=2))
    assert by_type(findings, "bearer_token")[0].material == "abcdefghijklmnopqrstuvwxyz"


def test_http_valid_prefix_at_segment_end_is_not_a_partial_attempt() -> None:
    detector = SensitiveDetector("session")
    whole = b"Authorization: Bearer abcdefghijklmnopqrstuvwxyz\r\n"
    split = len(whole) - 4  # first segment ends in an already-valid token prefix
    first = detector.process_stream(chunk(whole[:split], packet_id=1))
    assert by_type(first, "bearer_token") == []
    second = detector.process_stream(
        chunk(whole[split:], offset=split, packet_id=2)
    )
    tokens = by_type(second, "bearer_token")
    assert len(tokens) == 1
    assert tokens[0].material == "abcdefghijklmnopqrstuvwxyz"
    assert tokens[0].attempt_ordinal == 1


def test_partial_form_and_named_assignment_emit_only_after_delimiter() -> None:
    detector = SensitiveDetector("session")
    first_bytes = (
        b"POST /login HTTP/1.1\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
        b"password=already-valid"
    )
    first = detector.process_stream(chunk(first_bytes, packet_id=1))
    assert by_type(first, "sensitive_field") == []
    assert by_type(first, "named_secret") == []

    continuation = b"-suffix&other=value\r\n"
    second = detector.process_stream(
        chunk(continuation, offset=len(first_bytes), packet_id=2)
    )
    fields = by_type(second, "sensitive_field")
    named = by_type(second, "named_secret")
    assert len(fields) == 1
    assert fields[0].material["value"] == "already-valid-suffix"
    assert len(named) == 1
    assert named[0].material["value"] == "already-valid-suffix"


def test_query_and_body_sensitive_fields_emit_in_stream_order() -> None:
    detector = SensitiveDetector("session")
    payload = (
        b"POST /one?token=query-one HTTP/1.1\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
        b"password=body-secret&x=1\r\n"
        b"GET /two?token=query-two HTTP/1.1\r\n\r\n"
    )
    findings = detector.process_stream(chunk(payload))
    fields = by_type(findings, "sensitive_field")
    assert [item.material["value"] for item in fields] == [
        "query-one",
        "body-secret",
        "query-two",
    ]
    assert [item.stream_offset for item in fields] == sorted(
        item.stream_offset for item in fields
    )


def test_partial_json_secret_and_fixed_token_wait_for_real_boundary() -> None:
    detector = SensitiveDetector("session")
    first_bytes = b'{"client_secret":"already-valid'
    assert by_type(
        detector.process_stream(chunk(first_bytes, packet_id=1)), "named_secret"
    ) == []
    continuation = b'-suffix"}\r\n'
    findings = detector.process_stream(
        chunk(continuation, offset=len(first_bytes), packet_id=2)
    )
    named = by_type(findings, "named_secret")
    assert len(named) == 1
    assert named[0].material["value"] == "already-valid-suffix"

    aws = b"AKIA" + b"0" * 16  # synthetic format fixture, never a provider key
    offset = len(first_bytes) + len(continuation)
    assert by_type(
        detector.process_stream(chunk(aws, offset=offset, packet_id=3)),
        "cloud_access_key_id",
    ) == []
    findings = detector.process_stream(
        chunk(b"\r\n", offset=offset + len(aws), packet_id=4)
    )
    assert len(by_type(findings, "cloud_access_key_id")) == 1


def test_line_protocol_requires_terminator_but_datagram_boundary_completes_text() -> None:
    detector = SensitiveDetector("session")
    target_flow = flow(40000, 21)
    partial = b"PASS already-valid-secret"
    assert detector.process_stream(chunk(partial, target_flow=target_flow)) == []
    findings = detector.process_stream(
        chunk(b"\r\n", target_flow=target_flow, offset=len(partial), packet_id=2)
    )
    credentials = by_type(findings, "ftp_credentials")
    assert len(credentials) == 1
    assert credentials[0].material["password"] == "already-valid-secret"

    datagram_detector = SensitiveDetector("session")
    findings = datagram_detector.process_datagram(
        datagram(b"Authorization: Bearer datagram-complete-token", dport=8080)
    )
    assert by_type(findings, "bearer_token")[0].material == "datagram-complete-token"


def _secbuf(blob: bytearray, position: int, value: bytes) -> None:
    offset = len(blob)
    blob.extend(value)
    blob[position : position + 2] = len(value).to_bytes(2, "little")
    blob[position + 2 : position + 4] = len(value).to_bytes(2, "little")
    blob[position + 4 : position + 8] = offset.to_bytes(4, "little")


def ntlm_type2(challenge: bytes) -> bytes:
    assert len(challenge) == 8
    blob = bytearray(48)
    blob[:12] = b"NTLMSSP\x00" + (2).to_bytes(4, "little")
    blob[20:24] = (1).to_bytes(4, "little")
    blob[24:32] = challenge
    blob[16:20] = (48).to_bytes(4, "little")
    blob[44:48] = (48).to_bytes(4, "little")
    return bytes(blob)


def ntlm_type3(*, nt_response: bytes, username: str = "alice", domain: str = "LAB") -> bytes:
    blob = bytearray(64)
    blob[:12] = b"NTLMSSP\x00" + (3).to_bytes(4, "little")
    blob[60:64] = (1).to_bytes(4, "little")  # Unicode
    _secbuf(blob, 12, b"L" * 24)
    _secbuf(blob, 20, nt_response)
    _secbuf(blob, 28, domain.encode("utf-16le"))
    _secbuf(blob, 36, username.encode("utf-16le"))
    _secbuf(blob, 44, "WS01".encode("utf-16le"))
    return bytes(blob)


def test_ntlm_type2_type3_correlation_and_every_retry() -> None:
    detector = SensitiveDetector("session")
    target_flow = flow(40000, 445)
    challenge = bytes.fromhex("1122334455667788")
    proof = bytes.fromhex("00112233445566778899aabbccddeeff")
    nt_response = proof + b"\x01\x01\x00\x00" + b"B" * 28
    type2 = ntlm_type2(challenge)
    type3 = ntlm_type3(nt_response=nt_response)

    challenge_findings = detector.process_stream(
        chunk(type2, target_flow=target_flow, direction=1, offset=10, packet_id=1, timestamp=1_000)
    )
    assert len(by_type(challenge_findings, "ntlm_type2_challenge")) == 1

    response_findings = detector.process_stream(
        chunk(type3, target_flow=target_flow, direction=0, offset=100, packet_id=2, timestamp=2_000)
    )
    assert len(by_type(response_findings, "ntlm_type3_response")) == 1
    correlated = by_type(response_findings, "netntlmv2")
    assert len(correlated) == 1
    expected = f"alice::LAB:{challenge.hex()}:{proof.hex()}:{nt_response[16:].hex()}"
    assert correlated[0].material["hashcat"] == expected
    assert correlated[0].material["hashcat_mode"] == 5600
    assert correlated[0].packet_ids == (1, 2)
    assert correlated[0].packet_ids_complete is True
    # The large Type 3 object is removed as soon as it is paired.  Only the
    # small latest-challenge context remains available for retries.
    stats = detector.stats()
    assert stats["ntlm_correlation_objects"] == 1
    assert stats["ntlm_correlation_bytes"] <= 256

    retry_offset = 100 + len(type3) + 10
    retry = detector.process_stream(
        chunk(type3, target_flow=target_flow, direction=0, offset=retry_offset, packet_id=3, timestamp=3_000)
    )
    assert len(by_type(retry, "netntlmv2")) == 1
    assert by_type(retry, "netntlmv2")[0].attempt_ordinal == 2
    assert detector.stats()["ntlm_correlation_objects"] == 1


def test_ntlm_large_unmatched_responses_cannot_bypass_detector_byte_cap() -> None:
    detector = SensitiveDetector(
        "session",
        overlap_bytes=64 * 1024,
        max_retained_bytes=64 * 1024,
        generic_secret_scan=False,
        credit_card_scan=False,
    )
    target_flow = flow(40100, 445)
    response = ntlm_type3(nt_response=b"N" * (60 * 1024))
    offset = 0
    emitted = 0
    for packet_id in range(1, 257):
        findings = detector.process_stream(
            chunk(
                response,
                target_flow=target_flow,
                offset=offset,
                packet_id=packet_id,
                timestamp=packet_id * 1_000,
            )
        )
        emitted += len(by_type(findings, "ntlm_type3_response"))
        offset += len(response)

    assert emitted == 256  # no retry suppression at later absolute offsets
    stats = detector.stats()
    assert stats["retained_detector_bytes"] <= stats["max_retained_bytes"]
    assert stats["ntlm_correlation_bytes"] <= stats["max_ntlm_correlation_bytes"]
    assert stats["ntlm_correlation_objects"] <= stats["max_ntlm_correlation_objects"]
    assert stats["ntlm_correlation_cap_pressure_events"] == 256
    assert stats["ntlm_correlation_cap_dropped_objects"] == 256
    assert stats["ntlm_correlation_objects"] == 0


def test_ntlm_worker_global_object_cap_evicts_oldest_contexts() -> None:
    detector = SensitiveDetector(
        "session",
        overlap_bytes=4096,
        max_retained_bytes=8192,
        generic_secret_scan=False,
        credit_card_scan=False,
    )
    for packet_id in range(1, 21):
        detector.process_stream(
            chunk(
                ntlm_type2(packet_id.to_bytes(8, "little")),
                target_flow=flow(40200 + packet_id, 445),
                direction=1,
                packet_id=packet_id,
                connection_epoch=packet_id,
            )
        )

    stats = detector.stats()
    assert stats["ntlm_correlation_objects"] <= stats["max_ntlm_correlation_objects"]
    assert stats["ntlm_correlation_bytes"] <= stats["max_ntlm_correlation_bytes"]
    assert stats["ntlm_correlation_cap_pressure_events"] > 0
    assert stats["ntlm_correlation_cap_evicted_objects"] > 0


@pytest.mark.parametrize(
    ("port", "payload", "expected", "key", "value"),
    [
        (21, b"USER alice\r\nPASS ftp-secret\r\n", "ftp_credentials", "password", "ftp-secret"),
        (110, b"USER bob\r\nPASS pop-secret\r\n", "pop3_credentials", "password", "pop-secret"),
        (
            25,
            b"AUTH PLAIN " + base64.b64encode(b"\x00carol\x00smtp-secret") + b"\r\n",
            "smtp_auth_plain_credentials",
            "password",
            "smtp-secret",
        ),
        (143, b'A001 LOGIN "dave" "imap-secret"\r\n', "imap_login_credentials", "password", "imap-secret"),
        (6667, b"NICK audit\r\nUSER audit 0 * :Audit\r\nPASS irc-secret\r\n", "irc_pass", "value", "irc-secret"),
        (23, b"login: erin\r\npassword: terminal-secret\r\n", "telnet_like_login_field", "value", "terminal-secret"),
    ],
)
def test_plaintext_protocol_detectors(port, payload, expected, key, value) -> None:
    detector = SensitiveDetector("session")
    findings = detector.process_stream(chunk(payload, target_flow=flow(40000, port)))
    candidates = by_type(findings, expected)
    assert any(item.material[key] == value for item in candidates)


def test_multistep_plaintext_credentials_union_correlated_packet_ids() -> None:
    detector = SensitiveDetector("session")
    target_flow = flow(40000, 21)
    assert by_type(
        detector.process_stream(
            chunk(b"USER alice\r\n", target_flow=target_flow, packet_id=71)
        ),
        "ftp_username",
    )
    findings = detector.process_stream(
        chunk(
            b"PASS audit-secret\r\n",
            target_flow=target_flow,
            offset=len(b"USER alice\r\n"),
            packet_id=72,
        )
    )

    finding = by_type(findings, "ftp_credentials")[0]
    assert finding.packet_ids == (71, 72)
    assert finding.packet_ids_complete is True


def test_pending_auth_state_is_strictly_bounded_across_thousands_of_flows() -> None:
    detector = SensitiveDetector(
        "session",
        overlap_bytes=4096,
        max_retained_bytes=64 * 1024,
        max_flows=5000,
        generic_secret_scan=False,
        credit_card_scan=False,
    )
    username = b"U" * 1024
    smtp_username = base64.b64encode(username)
    for index in range(2000):
        protocol_index = index % 3
        if protocol_index == 0:
            dport = 21
            payload = b"USER " + username + b"\r\n"
        elif protocol_index == 1:
            dport = 25
            payload = b"AUTH LOGIN " + smtp_username + b"\r\n"
        else:
            dport = 143
            payload = b"A1 AUTHENTICATE LOGIN " + smtp_username + b"\r\n"
        detector.process_stream(
            chunk(
                payload,
                target_flow=flow(sport=20_000 + index, dport=dport),
                packet_id=index + 1,
                connection_epoch=index + 1,
            )
        )
        assert detector.stats()["retained_detector_bytes"] <= 64 * 1024

    stats = detector.stats()
    assert stats["retained_detector_bytes"] <= stats["max_retained_bytes"]
    assert stats["pending_auth_bytes"] <= stats["retained_detector_bytes"]
    assert stats["peak_pending_auth_bytes"] > 0
    assert stats["pending_auth_cap_pressure_events"] > 0
    assert stats["pending_auth_cap_evicted_flows"] > 0
    assert stats["pending_auth_cap_evicted_objects"] > 0
    assert stats["pending_auth_cap_evicted_bytes"] > 0


def test_single_flow_pending_auth_drop_is_loss_visible_on_later_pass() -> None:
    detector = SensitiveDetector(
        "session",
        overlap_bytes=4096,
        max_retained_bytes=4096,
        generic_secret_scan=False,
        credit_card_scan=False,
    )
    target_flow = flow(45000, 21)
    username_line = b"USER " + b"A" * 4096 + b"\r\n"
    detector.process_stream(
        chunk(username_line, target_flow=target_flow, packet_id=91)
    )
    after_user = detector.stats()
    assert after_user["retained_detector_bytes"] <= 4096
    assert after_user["pending_auth_cap_dropped_objects"] == 1
    assert after_user["pending_auth_cap_dropped_bytes"] > 0

    findings = detector.process_stream(
        chunk(
            b"PASS later-secret\r\n",
            target_flow=target_flow,
            offset=len(username_line),
            packet_id=92,
        )
    )
    finding = by_type(findings, "ftp_credentials")[0]
    assert finding.material["username"] is None
    assert finding.packet_ids == (92,)
    assert finding.packet_ids_complete is False
    assert any("provenance" in value.lower() for value in finding.limitations)


def test_smtp_multistep_provenance_survives_pending_auth_accounting() -> None:
    detector = SensitiveDetector("session")
    target_flow = flow(46000, 587)
    lines = (
        b"AUTH LOGIN\r\n",
        base64.b64encode(b"alice") + b"\r\n",
        base64.b64encode(b"smtp-secret") + b"\r\n",
    )
    offset = 0
    findings = []
    for packet_id, line in enumerate(lines, start=101):
        findings.extend(
            detector.process_stream(
                chunk(
                    line,
                    target_flow=target_flow,
                    offset=offset,
                    packet_id=packet_id,
                )
            )
        )
        offset += len(line)

    finding = by_type(findings, "smtp_auth_login_credentials")[0]
    assert finding.packet_ids == (101, 102, 103)
    assert finding.packet_ids_complete is True
    stats = detector.stats()
    assert stats["peak_pending_auth_bytes"] > 0
    assert stats["pending_auth_bytes"] == 0


def test_smtp_and_imap_auth_login_state_is_flow_affine() -> None:
    smtp = SensitiveDetector("session")
    smtp_payload = (
        b"AUTH LOGIN\r\n"
        + base64.b64encode(b"alice")
        + b"\r\n"
        + base64.b64encode(b"smtp-pass")
        + b"\r\n"
    )
    smtp_findings = smtp.process_stream(chunk(smtp_payload, target_flow=flow(40000, 587)))
    credentials = by_type(smtp_findings, "smtp_auth_login_credentials")[0]
    assert credentials.material["username"] == "alice"
    assert credentials.material["password"] == "smtp-pass"

    imap = SensitiveDetector("session")
    imap_payload = (
        b"A1 AUTHENTICATE LOGIN\r\n"
        + base64.b64encode(b"bob")
        + b"\r\n"
        + base64.b64encode(b"imap-pass")
        + b"\r\n"
    )
    imap_findings = imap.process_stream(chunk(imap_payload, target_flow=flow(40000, 143)))
    credentials = by_type(imap_findings, "imap_auth_login_credentials")[0]
    assert credentials.material["username"] == "bob"
    assert credentials.material["password"] == "imap-pass"


def der(tag: int, value: bytes) -> bytes:
    if len(value) < 0x80:
        length = bytes([len(value)])
    else:
        encoded = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(encoded)]) + encoded
    return bytes([tag]) + length + value


def der_int(value: int) -> bytes:
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return der(0x02, encoded)


def test_ldap_simple_bind_and_snmp_communities() -> None:
    ldap = der(
        0x30,
        der_int(7)
        + der(
            0x60,
            der_int(3) + der(0x04, b"cn=auditor,dc=lab") + der(0x80, b"ldap-secret"),
        ),
    )
    detector = SensitiveDetector("session")
    findings = detector.process_stream(chunk(ldap, target_flow=flow(40000, 389)))
    bind = by_type(findings, "ldap_simple_bind_credentials")[0]
    assert bind.material["bind_dn"] == "cn=auditor,dc=lab"
    assert bind.material["password"] == "ldap-secret"

    snmp = der(0x30, der_int(1) + der(0x04, b"private-community") + der(0xA0, b""))
    findings = detector.process_datagram(datagram(snmp, dport=161, packet_id=55))
    community = by_type(findings, "snmp_community")[0]
    assert community.material["community"] == "private-community"
    assert community.fields["snmp_version"] == "v2c"

    fragmented = datagram(snmp, dport=161, packet_id=99)
    fragmented.source_packet_ids = (7, 8, 9)
    provenance = SensitiveDetector("session").process_datagram(fragmented)
    assert by_type(provenance, "snmp_community")[0].packet_ids == (7, 8, 9)


def _obfuscate_tds_password(raw: bytes) -> bytes:
    return bytes((((value & 0x0F) << 4) | ((value & 0xF0) >> 4)) ^ 0xA5 for value in raw)


def tds_login7(username: str, password: str, hostname: str = "WS01", database: str = "audit") -> bytes:
    payload = bytearray(94)

    def put(position: int, text: str, *, password_field: bool = False) -> None:
        raw = text.encode("utf-16le")
        stored = _obfuscate_tds_password(raw) if password_field else raw
        offset = len(payload)
        payload.extend(stored)
        payload[position : position + 2] = offset.to_bytes(2, "little")
        payload[position + 2 : position + 4] = (len(raw) // 2).to_bytes(2, "little")

    put(36, hostname)
    put(40, username)
    put(44, password, password_field=True)
    put(68, database)
    payload[0:4] = len(payload).to_bytes(4, "little")
    packet_length = len(payload) + 8
    header = bytes([0x10, 0x01]) + packet_length.to_bytes(2, "big") + b"\x00\x00\x01\x00"
    return header + payload


def test_mssql_login7_password_deobfuscation() -> None:
    detector = SensitiveDetector("session")
    payload = tds_login7("sa-auditor", "SqlSecret!42")
    findings = detector.process_stream(chunk(payload, target_flow=flow(40000, 1433)))
    login = by_type(findings, "mssql_login7_credentials")[0]
    assert login.material["username"] == "sa-auditor"
    assert login.material["password"] == "SqlSecret!42"
    assert login.material["hostname"] == "WS01"


def kerberos_as_req(user: str, realm: str, cipher: bytes) -> bytes:
    encrypted_data = der(
        0x30,
        der(0xA0, der_int(23)) + der(0xA2, der(0x04, cipher)),
    )
    padata_entry = der(
        0x30,
        der(0xA1, der_int(2)) + der(0xA2, der(0x04, encrypted_data)),
    )
    padata = der(0xA3, der(0x30, padata_entry))
    principal = der(
        0x30,
        der(0xA0, der_int(1)) + der(0xA1, der(0x30, der(0x1B, user.encode()))),
    )
    body = der(
        0xA4,
        der(0x30, der(0xA1, principal) + der(0xA2, der(0x1B, realm.encode()))),
    )
    request = der(
        0x30,
        der(0xA1, der_int(5)) + der(0xA2, der_int(10)) + padata + body,
    )
    return der(0x6A, request)


def test_kerberos_etype23_pc_redz_compatible_hashcat_line() -> None:
    cipher = bytes(range(52))
    payload = kerberos_as_req("alice", "LAB.EXAMPLE", cipher)
    detector = SensitiveDetector("session")
    findings = detector.process_datagram(datagram(payload, dport=88))
    kerberos = by_type(findings, "kerberos_as_req_etype23")[0]
    assert kerberos.material["hashcat_mode"] == 7500
    assert kerberos.material["hashcat"] == (
        "$krb5pa$23$alice$LAB.EXAMPLE$dummy$"
        + cipher[16:].hex()
        + cipher[:16].hex()
    )


def test_sip_digest_hashcat_and_generic_secret_patterns_and_card() -> None:
    sip = (
        b"REGISTER sip:pbx.lab SIP/2.0\r\n"
        b'Authorization: Digest username="1001", realm="pbx.lab", '
        b'nonce="abcdef", uri="sip:pbx.lab", response="0123456789abcdef0123456789abcdef", '
        b'algorithm=MD5, qop=auth, nc=00000001, cnonce="1234"\r\n\r\n'
    )
    detector = SensitiveDetector("session")
    findings = detector.process_datagram(datagram(sip, dport=5060))
    digest = by_type(findings, "sip_digest_response")[0]
    assert digest.material["hashcat_mode"] == 11400
    assert digest.material["hashcat"].startswith("$sip$*")
    assert not by_type(findings, "http_digest_response")

    generic = (
        b"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        b"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\r\n"
        + b"api_key=" + b"AKIA" + b"0" * 16 + b"\r\n"
        + b'{"client_secret":"json-secret-123"}\r\n'
        b"card=4111 1111 1111 1111\r\n"
        b"-----BEGIN PRIVATE KEY-----\nQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n-----END PRIVATE KEY-----\r\n"
    )
    findings = detector.process_stream(chunk(generic, target_flow=flow(40001, 8080), packet_id=70))
    assert by_type(findings, "jwt")
    assert by_type(findings, "cloud_access_key_id")
    assert any(item.material["value"] == "json-secret-123" for item in by_type(findings, "named_secret"))
    assert by_type(findings, "payment_card_candidate")[0].material["digits"] == "4111111111111111"
    assert "BEGIN PRIVATE KEY" in by_type(findings, "private_key")[0].material


def test_split_pem_uses_long_scanner_only_while_pending() -> None:
    detector = SensitiveDetector("session")
    pem = (
        b"-----BEGIN PRIVATE KEY-----\n"
        + b"QUJD" * 512
        + b"\n-----END PRIVATE KEY-----\r\n"
    )
    split = 1000
    assert detector.process_stream(chunk(pem[:split], packet_id=1)) == []
    findings = detector.process_stream(
        chunk(pem[split:], offset=split, packet_id=2)
    )
    assert len(by_type(findings, "private_key")) == 1


def test_malformed_protocol_inputs_do_not_escape_detector() -> None:
    detector = SensitiveDetector(
        "session", overlap_bytes=4096, max_retained_bytes=64 * 1024
    )
    malformed = [
        b"NTLMSSP\x00\x03\x00\x00\x00" + b"\xff" * 40,
        b"Authorization: Basic !!!!\r\n",
        b"\x30\x84\xff\xff\xff\xff\x60\x80",
        b"\x10\x01\xff\xff\x00\x00\x01\x00" + b"\x00" * 94,
        b"\x6a\x82\xff\xff\x30\x00",
        b"-----BEGIN PRIVATE KEY-----\nnot-complete",
    ]
    rng = random.Random(20260827)
    malformed.extend(rng.randbytes(rng.randrange(0, 512)) for _ in range(1000))
    offset = 0
    for packet_id, payload in enumerate(malformed, start=1):
        detector.process_stream(
            chunk(payload, offset=offset, packet_id=packet_id)
        )
        offset += len(payload) + 1  # explicit gaps exercise island replacement
        detector.process_datagram(datagram(payload, dport=161, packet_id=10_000 + packet_id))
    stats = detector.stats()
    assert stats["attempts"] == len(malformed) + sum(bool(item) for item in malformed)
    assert stats["retained_tail_bytes"] <= stats["max_retained_bytes"]


def test_expire_and_stats() -> None:
    detector = SensitiveDetector("session")
    target_flow = flow(40000, 80)
    detector.process_stream(chunk(b"Authorization: Bearer abcdefghijklmnop\r\n", target_flow=target_flow, timestamp=100))
    stats = detector.stats()
    assert stats["attempts"] == 1
    assert stats["findings"] >= 1
    assert stats["active_flows"] == 1
    assert detector.expire(cutoff_timestamp_ns=101) == 1
    assert detector.stats()["active_flows"] == 0
