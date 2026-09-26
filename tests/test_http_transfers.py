"""Synthetic, payload-private HTTP/1 transfer-signature regressions."""

from __future__ import annotations

import pytest

from packet_audit.detectors import SensitiveDetector
from packet_audit.models import FlowKey, ProvenanceSpan, StreamChunk


PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 24
JPEG = b"\xff\xd8\xff" + b"\x00" * 24
GIF = b"GIF89a" + b"\x00" * 24
WEBP = b"RIFF\x12\x00\x00\x00WEBP" + b"\x00" * 24
PDF = b"%PDF-1.7\n" + b"\x00" * 24
ZIP = b"PK\x03\x04" + b"\x00" * 24


def chunk(data: bytes, offset: int = 0, packet_id: int = 1, *, response: bool = False) -> StreamChunk:
    flow, request_direction = FlowKey.canonical(
        protocol=6, src="192.0.2.10", sport=43210,
        dst="192.0.2.20", dport=80, interface="eth0",
    )
    return StreamChunk(
        flow=flow, direction=1 - request_direction if response else request_direction,
        stream_offset=offset, data=data, packet_ids=(packet_id,),
        first_timestamp_ns=packet_id * 1000, last_timestamp_ns=packet_id * 1000,
        connection_epoch=0, completeness="complete",
        provenance_spans=(ProvenanceSpan(offset, offset + len(data), (packet_id,)),),
    )


def request(body: bytes, *, content_type: bytes = b"application/octet-stream", extra: bytes = b"") -> bytes:
    return (
        b"POST /upload HTTP/1.1\r\nHost: example.invalid\r\nContent-Type: "
        + content_type + b"\r\n" + extra
        + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )


def response(body: bytes, *, content_type: bytes = b"application/octet-stream", status: bytes = b"200 OK", extra: bytes = b"") -> bytes:
    return (
        b"HTTP/1.1 " + status + b"\r\nContent-Type: " + content_type + b"\r\n" + extra
        + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )


def files(findings):
    return [finding for finding in findings if finding.detector == "http_file_signature"]


@pytest.mark.parametrize("body,kind,mime", [
    (PNG, "png", b"image/png"), (JPEG, "jpeg", b"image/jpeg"),
    (GIF, "gif", b"image/gif"), (WEBP, "webp", b"image/webp"),
    (PDF, "pdf", b"application/pdf"), (ZIP, "zip", b"application/zip"),
])
def test_request_and_response_signatures_have_exact_body_provenance(body, kind, mime):
    for http_role, payload, reverse in (
        ("request_body", request(body, content_type=mime), False),
        ("response_body", response(body, content_type=mime), True),
    ):
        detected = files(SensitiveDetector("test").process_stream(chunk(payload, response=reverse)))
        assert len(detected) == 1
        finding = detected[0]
        assert finding.category == "file_signature"
        assert finding.protocol == "http"
        assert finding.confidence == "high"
        assert finding.material["file_type"] == kind
        assert finding.material["http_role"] == http_role
        assert finding.material["declared_content_type"] == mime.decode()
        assert finding.material["declared_content_length"] == len(body)
        assert finding.stream_offset == payload.index(body)
        assert finding.packet_ids == (1,)
        assert finding.packet_ids_complete
        assert body not in str(finding.material).encode()


def test_png_post_every_two_packet_split_and_provenance():
    payload = request(PNG, content_type=b"image/png")
    magic_offset = payload.index(PNG)
    for split in range(1, len(payload)):
        detector = SensitiveDetector("test")
        found = files(detector.process_stream(chunk(payload[:split])))
        found += files(detector.process_stream(chunk(payload[split:], split, 2)))
        assert len(found) == 1, split
        expected_packets = (1,) if split <= magic_offset or split >= magic_offset + 8 else (1, 2)
        if split <= magic_offset:
            expected_packets = (2,)
        assert found[0].packet_ids == expected_packets, split


def test_zip_data_descriptor_alone_is_not_a_file_header():
    payload = request(b"PK\x07\x08" + b"\x00" * 24, content_type=b"application/zip")
    assert files(SensitiveDetector("test").process_stream(chunk(payload))) == []


def test_keepalive_auth_then_bytewise_file_headers():
    auth = (
        b"POST /auth HTTP/1.1\r\nHost: example.invalid\r\n"
        b"Authorization: Basic dGVzdDp0ZXN0\r\nContent-Length: 0\r\n\r\n"
    )
    upload = request(PNG, content_type=b"image/png")
    detector = SensitiveDetector("test")
    seen = detector.process_stream(chunk(auth))
    for index, byte in enumerate(upload):
        seen += detector.process_stream(chunk(bytes((byte,)), len(auth) + index, index + 2))
    assert len([finding for finding in seen if finding.material_type == "http_basic_credentials"]) == 1
    signatures = files(seen)
    assert len(signatures) == 1
    assert signatures[0].material["file_type"] == "png"


def test_large_body_uses_prefix_without_retaining_file_contents():
    private_marker = b"DO-NOT-RETAIN-PRIVATE-BODY-45819"
    body = PNG + b"z" * 10_000 + private_marker + b"z" * 10_000
    payload = request(body, content_type=b"image/png")
    detector = SensitiveDetector("test", overlap_bytes=4096)
    found = []
    for offset in range(0, len(payload), 1024):
        found += files(detector.process_stream(chunk(payload[offset:offset + 1024], offset, offset // 1024 + 1)))
    assert len(found) == 1
    assert private_marker not in str(found[0].material).encode()
    assert private_marker not in repr(detector._flows).encode()
    assert detector.stats()["retained_tail_bytes"] <= 8192
    assert detector.stats()["http_framing_body_limit"] == 1


def test_pipelined_files_and_mime_mismatch_remain_separate():
    first = request(PNG, content_type=b"application/pdf")
    second = request(ZIP, content_type=b"application/zip")
    found = files(SensitiveDetector("test").process_stream(chunk(first + second)))
    assert [finding.material["file_type"] for finding in found] == ["png", "zip"]
    assert found[0].stream_offset == first.index(PNG)
    assert found[1].stream_offset == len(first) + second.index(ZIP)
    assert any("differs" in item for item in found[0].limitations)
    assert not any("differs" in item for item in found[1].limitations)


def test_truncated_prefix_and_magic_only_in_header_do_not_claim_file():
    payload = request(PNG, content_type=b"image/png")
    detector = SensitiveDetector("test")
    assert files(detector.process_stream(chunk(payload[:payload.index(PNG) + 7]))) == []
    assert len(files(detector.process_stream(chunk(payload[payload.index(PNG) + 7:], payload.index(PNG) + 7, 2)))) == 1

    fake = request(b"plain body without a signature", content_type=b"image/jpeg",
                   extra=b"X-Decoy: \xff\xd8\xff\r\n")
    detector = SensitiveDetector("test")
    assert files(detector.process_stream(chunk(fake))) == []
    assert detector.stats()["http_transfer_declared_file_unverified"] == 1


@pytest.mark.parametrize("reverse", [False, True])
def test_verified_image_bytes_are_not_reported_as_live_credentials(reverse):
    body = PNG + b"\r\npassword=FakePass\r\n" + b'{"token":"FakeToken"}'
    payload = response(body, content_type=b"image/png") if reverse else request(body, content_type=b"image/png")
    found = SensitiveDetector("test").process_stream(chunk(payload, response=reverse))
    assert [finding.detector for finding in found] == ["http_file_signature"]
    assert b"FakePass" not in str(found[0].material).encode()
    assert b"FakeToken" not in str(found[0].material).encode()


def test_real_authorization_header_survives_masked_binary_body():
    body = PNG + b"\r\nAuthorization: Bearer fake-inside-image\r\n"
    payload = request(body, content_type=b"image/png",
                      extra=b"Authorization: Bearer genuine-header-token\r\n")
    found = SensitiveDetector("test").process_stream(chunk(payload))
    assert len(files(found)) == 1
    bearer = [finding for finding in found if finding.detector == "http_bearer"]
    assert len(bearer) == 1
    assert bearer[0].material == "genuine-header-token"
    assert all("fake-inside-image" not in str(finding.material) for finding in found)


def test_query_credential_and_later_login_are_not_hidden_by_file_body():
    image = request(PNG + b"\r\npassword=NotALogin\r\n", content_type=b"image/png")
    image = image.replace(b"POST /upload ", b"POST /upload?token=QuerySecret ")
    login = b"POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 17\r\n\r\npassword=RealPass"
    found = SensitiveDetector("test").process_stream(chunk(image + login))
    assert len(files(found)) == 1
    values = [finding.material.get("value") for finding in found if isinstance(finding.material, dict)]
    assert "QuerySecret" in values
    assert "RealPass" in values
    assert "NotALogin" not in values


def test_filename_is_bounded_basename_and_body_is_not_in_finding():
    secret = b"PRIVATE-IMAGE-CONTENT-8472"
    payload = response(PNG + secret, content_type=b"image/png",
                       extra=b'Content-Disposition: attachment; filename="C:\\private\\folder\\sample.png"\r\n')
    finding = files(SensitiveDetector("test").process_stream(chunk(payload, response=True)))[0]
    assert finding.material["filename"] == "sample.png"
    assert secret not in str(finding.material).encode()
    assert b"private" not in str(finding.material).encode()


def test_partial_range_nonzero_is_not_identified_as_complete_file():
    detector = SensitiveDetector("test")
    payload = response(PNG, content_type=b"image/png", status=b"206 Partial Content",
                       extra=b"Content-Range: bytes 100-131/1000\r\n")
    assert files(detector.process_stream(chunk(payload, response=True))) == []
    assert detector.stats()["http_transfer_partial_range_unverified"] == 1

    first_range = response(PNG, content_type=b"image/png", status=b"206 Partial Content",
                           extra=b"Content-Range: bytes 0-31/1000\r\n")
    found = files(SensitiveDetector("test").process_stream(chunk(first_range, response=True)))
    assert len(found) == 1
    assert any("partial" in item.lower() for item in found[0].limitations)


def test_first_multipart_part_magic_and_filename_are_identified():
    boundary = b"signed-test-boundary"
    part = (b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="photo"; filename="folder\\image.png"\r\n'
            b"Content-Type: image/png\r\n\r\n" + PNG + b"\r\n--" + boundary + b"--\r\n")
    payload = request(part, content_type=b"multipart/form-data; boundary=" + boundary)
    found = files(SensitiveDetector("test").process_stream(chunk(payload)))
    assert len(found) == 1
    assert found[0].material["file_type"] == "png"
    assert found[0].material["filename"] == "image.png"
    assert found[0].stream_offset == payload.index(PNG)


def test_multipart_prefix_limit_and_repeated_set_cookie_are_safe():
    boundary = b"bounded-test"
    too_long = (b"--" + boundary + b"\r\nX-Pad: " + b"x" * 2200
                + b"\r\n\r\n" + PNG + b"\r\n--" + boundary + b"--\r\n")
    detector = SensitiveDetector("test")
    assert files(detector.process_stream(chunk(request(
        too_long, content_type=b"multipart/form-data; boundary=" + boundary,
    )))) == []
    assert detector.stats()["http_transfer_multipart_prefix_unresolved"] == 1

    payload = response(PNG, content_type=b"image/png",
                       extra=b"Set-Cookie: one=1\r\nSet-Cookie: two=2\r\n")
    assert len(files(SensitiveDetector("test").process_stream(chunk(payload, response=True)))) == 1


def test_chunked_compressed_and_unframed_bodies_are_visible_limits():
    chunked = (b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n"
               b"Transfer-Encoding: chunked\r\n\r\n" + hex(len(PNG))[2:].encode() + b"\r\n" + PNG + b"\r\n0\r\n\r\n")
    detector = SensitiveDetector("test")
    assert files(detector.process_stream(chunk(chunked, response=True))) == []
    assert detector.stats()["http_transfer_chunked_unsupported"] == 1

    compressed = response(b"not an image signature", content_type=b"image/png",
                          extra=b"Content-Encoding: gzip\r\n")
    detector = SensitiveDetector("test")
    assert files(detector.process_stream(chunk(compressed, response=True))) == []
    assert detector.stats()["http_transfer_content_encoding_unsupported"] == 1

    unframed = b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n" + PNG
    detector = SensitiveDetector("test")
    assert files(detector.process_stream(chunk(unframed, response=True))) == []
    assert detector.stats()["http_transfer_unbounded_body"] == 1

    h2 = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    detector = SensitiveDetector("test")
    assert files(detector.process_stream(chunk(h2))) == []
    assert detector.stats()["http_transfer_http2_unsupported"] == 1
