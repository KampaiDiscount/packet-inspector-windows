"""Bounded HTTP/1 file-signature observations without file-body retention.

This tracker reads Content-Length-framed request and response bodies. It only
keeps framing offsets and bounded header metadata between packets; the body
prefix is inspected in the caller's existing stream window and never saved.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import re


_METHODS = rb"GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE"
_START_LINE = (
    rb"(?:(?P<method>" + _METHODS + rb") [^\r\n ]{1,8192} HTTP/1\.[01]"
    rb"|HTTP/1\.[01] (?P<status>[1-5][0-9]{2})(?: [^\r\n]{0,128})?)\r\n"
)
_SEARCH_START = re.compile(rb"(?m)^" + _START_LINE)
_MATCH_START = re.compile(_START_LINE)
_HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_BOUNDARY = re.compile(rb"(?:^|;)\s*boundary=(?:\"([^\"\r\n]{1,70})\"|([^;\s\r\n]{1,70}))", re.I)
_FILENAME = re.compile(rb"(?:^|;)\s*filename=(?:\"([^\"\r\n]{1,256})\"|([^;\s\r\n]{1,256}))", re.I)
_CANDIDATE_GATE = re.compile(
    rb"(?im)^(?:content-length:\s*[1-9][0-9]*\s*\r?$|transfer-encoding:"
    rb"|content-type:\s*(?:image/|application/(?:pdf|zip|octet-stream)|multipart/form-data)"
    rb"|content-disposition:[^\r\n]{0,256}filename=)"
)
_MAX_HEADER = 32 * 1024
_MAX_MULTIPART_PREFIX = 2048
_MAGIC_PREFIX = 12


@dataclass(slots=True)
class FileSignature:
    start: int
    end: int
    file_type: str
    http_role: str
    content_type: str | None
    filename: str | None
    declared_content_length: int
    partial_response: bool


@dataclass(slots=True)
class _PendingBody:
    start: int
    end: int
    prefix_length: int
    http_role: str
    content_type: str | None
    filename: str | None
    boundary: bytes | None
    declared_content_length: int
    partial_response: bool


def _headers(raw: bytes) -> dict[bytes, bytes] | None:
    parsed: dict[bytes, bytes] = {}
    for line in raw.split(b"\r\n"):
        if not line:
            continue
        if line[:1] in (b" ", b"\t") or b":" not in line:
            return None
        key, value = line.split(b":", 1)
        if _HEADER_NAME.fullmatch(key) is None:
            return None
        key = key.lower()
        if key in parsed and key in {
            b"content-length", b"transfer-encoding", b"content-type",
            b"content-disposition", b"content-encoding", b"content-range",
        }:
            return None
        parsed.setdefault(key, value.strip())
    return parsed


def _mime(value: bytes) -> str | None:
    token = value.split(b";", 1)[0].strip().lower()
    if not token or len(token) > 128 or re.fullmatch(rb"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+", token) is None:
        return None
    return token.decode("ascii")


def _filename(value: bytes) -> str | None:
    match = _FILENAME.search(value[:1024])
    if match is None:
        return None
    raw = match.group(1) or match.group(2)
    name = raw.decode("utf-8", "replace").replace("\\", "/").split("/")[-1]
    name = "".join(char for char in name if char.isprintable()).strip()
    return name[:128] or None


def _signature(data: bytes) -> tuple[str, int] | None:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png", 8
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg", 3
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "gif", 6
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp", 12
    if data.startswith(b"%PDF-"):
        return "pdf", 5
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip", 4
    return None


def transfer_candidate_in(data: bytes | bytearray, new_bytes: int) -> bool:
    """Avoid a second HTTP parser on body-free authentication traffic."""

    recent = data[-min(len(data), max(256, new_bytes + 128)):]
    if _CANDIDATE_GATE.search(recent) is None:
        return False
    return b"HTTP/1." in data


def _multipart_part(prefix: bytes, boundary: bytes) -> tuple[int, str | None, str | None] | None:
    opening = b"--" + boundary + b"\r\n"
    if not prefix.startswith(opening):
        return None
    header_end = prefix.find(b"\r\n\r\n", len(opening))
    if header_end < 0 or header_end - len(opening) > 1024:
        return None
    headers = _headers(prefix[len(opening):header_end])
    if headers is None:
        return None
    return header_end + 4, _mime(headers.get(b"content-type", b"")), _filename(headers.get(b"content-disposition", b""))


@dataclass(slots=True)
class HTTPTransferTracker:
    """One TCP direction, with no retained body bytes and bounded metadata."""

    cursor: int | None = None
    search_end: int = 0
    pending: _PendingBody | None = None
    blocked: bool = False
    verified_body_ranges: list[tuple[int, int]] = field(default_factory=list)

    def covers_body(self, start: int, end: int) -> bool:
        return any(left <= start and end <= right for left, right in self.verified_body_ranges)

    def masked_body(self, data: bytes | bytearray, base: int) -> bytes | bytearray:
        """Hide verified binary bodies from unrelated credential scanners."""

        masked: bytearray | None = None
        for left, right in self.verified_body_ranges:
            start = max(0, left - base)
            end = min(len(data), right - base)
            if start < end:
                if masked is None:
                    masked = bytearray(data)
                masked[start:end] = b"\x00" * (end - start)
        return masked if masked is not None else data

    def _finish_prefix(self, data: bytes | bytearray, base: int, stats: Counter[str]) -> FileSignature | None:
        pending = self.pending
        if pending is None or base + len(data) <= pending.start:
            return None
        if pending.start < base:
            self.pending = None
            stats["http_transfer_prefix_lost"] += 1
            return None
        relative = pending.start - base
        available_prefix = min(pending.prefix_length, len(data) - relative)
        prefix = bytes(data[relative:relative + available_prefix])
        magic_start = 0
        content_type = pending.content_type
        filename = pending.filename
        if pending.boundary is not None:
            part = _multipart_part(prefix, pending.boundary)
            if part is None:
                if available_prefix >= pending.prefix_length:
                    self.pending = None
                    stats["http_transfer_multipart_prefix_unresolved"] += 1
                return None
            magic_start, part_type, part_filename = part
            content_type = part_type
            filename = part_filename or filename
        signature = _signature(prefix[magic_start:])
        if signature is None:
            if available_prefix < pending.prefix_length:
                return None
            self.pending = None
            if filename or (content_type and content_type.startswith(("image/", "application/pdf", "application/zip"))):
                stats["http_transfer_declared_file_unverified"] += 1
            return None
        self.pending = None
        self.verified_body_ranges.append((pending.start, pending.end))
        if len(self.verified_body_ranges) > 64:
            self.verified_body_ranges.pop(0)
            stats["http_transfer_range_cap"] += 1
        file_type, length = signature
        start = relative + magic_start
        return FileSignature(
            start=start, end=start + length, file_type=file_type,
            http_role=pending.http_role, content_type=content_type,
            filename=filename,
            declared_content_length=pending.declared_content_length,
            partial_response=pending.partial_response,
        )

    def scan(self, data: bytes | bytearray, base: int, stats: Counter[str]) -> list[FileSignature]:
        findings: list[FileSignature] = []
        available_end = base + len(data)
        self.verified_body_ranges = [
            (left, right) for left, right in self.verified_body_ranges if right > base
        ]
        if self.blocked:
            return findings
        if self.pending is not None:
            hit = self._finish_prefix(data, base, stats)
            if hit is not None:
                findings.append(hit)
        if self.cursor is not None and self.cursor < base:
            stats["http_transfer_framing_tail_lost"] += 1
            self.blocked = True
            return findings
        if self.cursor is None:
            start = max(0, self.search_end - base - 8192)
            match = _SEARCH_START.search(data, start)
            self.search_end = available_end
            if match is None:
                return findings
            self.cursor = base + match.start()
        while self.cursor < available_end:
            offset = self.cursor - base
            match = _MATCH_START.match(data, offset)
            if match is None:
                if data.find(b"\n", offset) >= 0 or available_end - self.cursor > _MAX_HEADER:
                    stats["http_transfer_framing_invalid_start"] += 1
                    self.blocked = True
                break
            header_end = data.find(b"\r\n\r\n", match.end() - 2)
            if header_end < 0:
                if available_end - self.cursor > _MAX_HEADER:
                    stats["http_transfer_header_limit"] += 1
                    self.blocked = True
                break
            header_end += 4
            if header_end - offset > _MAX_HEADER:
                stats["http_transfer_header_limit"] += 1
                self.blocked = True
                break
            headers = _headers(bytes(data[match.end():header_end - 2]))
            if headers is None or (b"content-length" in headers and b"transfer-encoding" in headers):
                stats["http_transfer_framing_ambiguous"] += 1
                self.blocked = True
                break
            assert headers is not None
            length_text = headers.get(b"content-length")
            if length_text is None:
                if b"transfer-encoding" in headers:
                    stats["http_transfer_chunked_unsupported"] += 1
                    self.blocked = True
                    break
                status = int(match.group("status")) if match.group("status") else None
                if match.group("method") in (b"POST", b"PUT", b"PATCH") or (
                    status is not None and not (100 <= status < 200 or status in (204, 304))
                ):
                    stats["http_transfer_unbounded_body"] += 1
                    self.blocked = True
                    break
                self.cursor = base + header_end
                continue
            if not length_text.isdigit() or len(length_text) > 10:
                stats["http_transfer_framing_invalid_length"] += 1
                self.blocked = True
                break
            length = int(length_text)
            body_start = base + header_end
            self.cursor = body_start + length
            if length == 0:
                continue
            partial_response = match.group("status") == b"206"
            if partial_response:
                content_range = headers.get(b"content-range", b"")
                range_match = re.fullmatch(rb"bytes\s+([0-9]{1,12})-[0-9]{1,12}/(?:[0-9]{1,12}|\*)", content_range, re.I)
                if range_match is None or int(range_match.group(1)) != 0:
                    stats["http_transfer_partial_range_unverified"] += 1
                    continue
            encoding = headers.get(b"content-encoding", b"identity").lower()
            if encoding not in (b"identity", b""):
                stats["http_transfer_content_encoding_unsupported"] += 1
                continue
            raw_type = headers.get(b"content-type", b"")
            boundary_match = _BOUNDARY.search(raw_type[:256]) if raw_type.lower().startswith(b"multipart/form-data") else None
            boundary = (boundary_match.group(1) or boundary_match.group(2)) if boundary_match else None
            self.pending = _PendingBody(
                start=body_start, end=self.cursor,
                prefix_length=min(length, _MAX_MULTIPART_PREFIX if boundary is not None else _MAGIC_PREFIX),
                http_role="response_body" if match.group("status") else "request_body",
                content_type=_mime(raw_type),
                filename=_filename(headers.get(b"content-disposition", b"")),
                boundary=boundary,
                declared_content_length=length,
                partial_response=partial_response,
            )
            hit = self._finish_prefix(data, base, stats)
            if hit is not None:
                findings.append(hit)
            if self.pending is not None:
                break
        return findings
