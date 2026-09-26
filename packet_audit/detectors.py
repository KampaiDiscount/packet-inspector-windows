"""Stateful, offset-aware sensitive-material detectors.

The detector deliberately does not deduplicate credentials.  A retransmitted
view of the same absolute stream bytes is scanned once, while a repeated login
at a new stream offset is a new finding.  All material in :class:`Finding` is
the original, unredacted material; output policy belongs to the exporter.

The implementation is dependency-free and uses bounded parsers.  It is not a
general protocol dissector: encrypted TLS/QUIC payloads and malformed or
truncated binary messages are reported only when a complete, safely bounded
credential structure is available.

Text completion rule: a TCP buffer boundary is never treated as a line or
value terminator.  Stream headers, commands, form fields, named assignments,
and variable-length tokens require an observed protocol delimiter; a datagram
boundary may serve as the delimiter because the complete datagram is the input
unit.  Pending stream values retain only their bounded detector lookback.
"""

from __future__ import annotations

from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field, replace
import base64
import binascii
import re
import struct
import time
from typing import Any, Iterable
from urllib.parse import unquote_plus
from uuid import uuid4

from .models import Finding, FlowKey, ParsedPacket, ProvenanceSpan, StreamChunk
from .http_forms import HTTPFramer, Message as HTTPMessage, field_role, form_fields, json_fields
from .ntlm_wrappers import smb2_header_seen, smb2_session_for_token, unwrap_ntlm
from .cleartext import scan_redis, scan_postgres, scan_postgres_authentication


_MAX_BINARY_MESSAGE = 1 << 20
_MAX_LINE = 8192
_MAX_ASN1_DEPTH = 12
_MAX_ASN1_NODES = 2048
_DEFAULT_MAX_RETAINED_BYTES = 128 * 1024 * 1024
_DEFAULT_MAX_METADATA_ENTRIES = 131_072
_MAX_NTLM_CORRELATION_BYTES = 16 * 1024 * 1024
_MAX_NTLM_CORRELATION_BYTES_PER_FLOW = 1024 * 1024
_MAX_NTLM_CORRELATION_OBJECTS = 65_536
_MAX_NTLM_CORRELATION_OBJECTS_PER_FLOW = 64
_DEFAULT_MAX_PACKET_IDS_PER_FINDING = 8_192
_MAX_PENDING_PROVENANCE_IDS = 256
_PENDING_AUTH_ENTRY_OVERHEAD = 256
_PENDING_AUTH_MAPPING_SLOT_OVERHEAD = 48
_PENDING_AUTH_SEQUENCE_OVERHEAD = 64
_PENDING_AUTH_LOSS_MARKER_OVERHEAD = 96

_SENSITIVE_FIELDS = {
    "password",
    "passwd",
    "pwd",
    "pass",
    "passphrase",
    "pin",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "apikey",
    "api-key",
    "secret",
    "client_secret",
    "private_key",
    "authorization",
    "auth",
    "session",
    "sessionid",
    "sid",
}

_AUTH_PARAM_RE = re.compile(
    rb"([A-Za-z][A-Za-z0-9_-]{0,63})\s*=\s*(?:\"((?:\\.|[^\"])*)\"|([^,\s]+))"
)
_HTTP_BASIC_RE = re.compile(
    rb"(?im)^(Proxy-Authorization|Authorization)\s*:\s*Basic\s+([A-Za-z0-9+/=_-]{4,})[ \t]*\r?\n"
)
_HTTP_BEARER_RE = re.compile(
    rb"(?im)^(Proxy-Authorization|Authorization)\s*:\s*Bearer\s+([^\s\r\n,]{8,})[ \t]*\r?\n"
)
_HTTP_DIGEST_RE = re.compile(
    rb"(?im)^(Proxy-Authorization|Authorization)\s*:\s*Digest\s+([^\r\n]{8,8192})\r?\n"
)
_HTTP_NTLM_RE = re.compile(
    rb"(?im)^(Proxy-Authorization|Authorization|WWW-Authenticate|Proxy-Authenticate)\s*:\s*(?:NTLM|Negotiate)\s+([A-Za-z0-9+/=_-]{12,})[ \t]*\r?\n"
)
_COOKIE_RE = re.compile(rb"(?im)^(Cookie|Set-Cookie)\s*:\s*([^\r\n]{1,16384})\r?\n")
_FORM_FIELD_RE = re.compile(
    rb"(?i)(?:^|[?&;\s])([A-Za-z][A-Za-z0-9_.-]{0,63})=([^&;\s\r\n]{0,8192})(?=[&;\s\r\n])"
)
_NTLM_SIGNATURE_RE = re.compile(rb"NTLMSSP\x00([\x02\x03])\x00\x00\x00")
_COMPLETE_LINE_RE = re.compile(rb"(?m)([^\r\n]{1,8192})\r?\n")
_GENERIC_SECRET_PATTERNS = (
    (
        "jwt",
        re.compile(rb"(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{8,})\.(eyJ[A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{8,})(?![A-Za-z0-9_-])"),
        "jwt",
        "high",
    ),
    (
        "aws_access_key",
        re.compile(rb"(?<![A-Z0-9])((?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16})(?![A-Z0-9])"),
        "cloud_access_key_id",
        "high",
    ),
    (
        "google_api_key",
        re.compile(rb"(?<![A-Za-z0-9_-])(AIza[0-9A-Za-z_-]{35})(?![A-Za-z0-9_-])"),
        "cloud_api_key",
        "high",
    ),
    (
        "github_token",
        re.compile(rb"(?<![A-Za-z0-9_])((?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{20,255}))(?![A-Za-z0-9_])"),
        "source_control_token",
        "high",
    ),
    (
        "slack_token",
        re.compile(rb"(?<![A-Za-z0-9-])(xox[baprs]-[A-Za-z0-9-]{10,200})(?![A-Za-z0-9-])"),
        "chat_token",
        "high",
    ),
    (
        "stripe_secret",
        re.compile(rb"(?<![A-Za-z0-9_])(sk_(?:live|test)_[A-Za-z0-9]{16,})(?![A-Za-z0-9_])"),
        "payment_api_secret",
        "high",
    ),
)
_GENERIC_ASSIGNMENT_RE = re.compile(
    rb"(?i)(?:^|[\s{,;])[\"']?([A-Za-z][A-Za-z0-9_.-]{1,63})[\"']?\s*[:=]\s*[\"']?([^\s\"'&,;}\]]{8,4096})(?=[\s\"'&,;}\]])"
)
_GENERIC_ASSIGNMENT_OPEN_RE = re.compile(
    rb"(?i)(?:^|[\s{,;])[\"']?([A-Za-z][A-Za-z0-9_.-]{1,63})[\"']?\s*[:=]\s*[\"']?([^\s\"'&,;}\]]{0,4096})$"
)
_PEM_PRIVATE_KEY_RE = re.compile(
    rb"-----BEGIN ([A-Z0-9 ]{0,40}PRIVATE KEY)-----[\s\S]{16,65536}?-----END \1-----"
)
_PAYMENT_CARD_RE = re.compile(rb"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_HTTP_GATE_RE = re.compile(
    rb"(?i)(?:authorization|authenticate|cookie|set-cookie|\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s|(?:password|passwd|pwd|pass|token|api[_-]?key|secret|session|sid)=)"
)
_HTTP_START_LINE_RE = re.compile(
    rb"(?m)^(?:(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE) [^\r\n ]{1,8192} HTTP/1\.[01]|HTTP/1\.[01] [1-5][0-9]{2}(?: [^\r\n]{0,256})?)\r?\n"
)
_HTTP_TEXT_FIELD_RE = re.compile(
    rb"(?im)^(login|logon|username|user|password|passwd|passcode)[ \t]*[:=][ \t]*([^\r\n&;]{1,4096})\r?$"
)
_LINE_GATE_RE = re.compile(
    rb"(?im)(?:^|\r?\n)(?:USER|PASS|AUTH\s|\S+\s+(?:LOGIN|AUTHENTICATE)\s|NICK\s|PRIVMSG\s|JOIN\s|CAP\s|(?:login|logon|username|password|passwd|passcode)\s*[:=])"
)
_GENERIC_STRONG_PREFIXES = (
    b"eyj",
    b"akia",
    b"asia",
    b"aida",
    b"aroa",
    b"aipa",
    b"anpa",
    b"anva",
    b"asca",
    b"aiza",
    b"ghp_",
    b"gho_",
    b"ghu_",
    b"ghs_",
    b"ghr_",
    b"github_pat_",
    b"xox",
    b"sk_live_",
    b"sk_test_",
)
_GENERIC_NAMED_GATE_RE = re.compile(
    rb"(?:password|passwd|pwd|passphrase|token|access_token|refresh_token|id_token|api[_-]?key|apikey|secret|client_secret|private_key|authorization|auth|session(?:id)?|sid|pin)\s*[\"']?\s*[:=]"
)


@dataclass(slots=True)
class _ScanContext:
    flow: FlowKey
    flow_id: str
    connection_epoch: int | None
    direction: int
    base_offset: int | None
    data: bytes | bytearray
    packet_ids: tuple[int, ...]
    provenance_spans: tuple[ProvenanceSpan, ...] | list[ProvenanceSpan] | deque[ProvenanceSpan]
    packet_ids_complete: bool
    observed_timestamp_ns: int
    completeness: str
    is_datagram: bool = False


@dataclass(slots=True)
class _DirectionState:
    base_offset: int = 0
    data: bytearray = field(default_factory=bytearray)
    packet_ids: tuple[int, ...] = ()
    provenance_spans: deque[ProvenanceSpan] = field(default_factory=deque)


@dataclass(slots=True)
class _NtlmChallenge:
    direction: int
    offset: int
    timestamp_ns: int
    challenge: bytes
    packet_ids: tuple[int, ...]
    packet_ids_complete: bool = True
    correlation_id: int = 0
    retained_size: int = 0
    smb_session: int | None = None


@dataclass(slots=True)
class _NtlmResponse:
    direction: int
    offset: int
    timestamp_ns: int
    username: str
    domain: str
    workstation: str
    lm_response: bytes
    nt_response: bytes
    packet_ids: tuple[int, ...]
    packet_ids_complete: bool = True
    correlation_id: int = 0
    retained_size: int = 0
    smb_session: int | None = None


@dataclass(slots=True)
class _FlowState:
    directions: dict[int, _DirectionState] = field(default_factory=dict)
    emitted_highwater: dict[tuple[Any, ...], tuple[int, int]] = field(default_factory=dict)
    state_highwater: dict[tuple[str, int], tuple[int, int]] = field(default_factory=dict)
    attempts: Counter[str] = field(default_factory=Counter)
    # One reusable challenge per direction/SMB2 session. Only
    # unmatched Type 3 messages enter ``ntlm_responses``; paired responses are
    # removed immediately.  Both stores participate in strict per-flow and
    # worker-global correlation budgets.
    ntlm_challenges: dict[int | tuple[int, int], _NtlmChallenge] = field(default_factory=dict)
    ntlm_responses: OrderedDict[int, _NtlmResponse] = field(
        default_factory=OrderedDict
    )
    ntlm_correlation_bytes: int = 0
    ntlm_pair_highwater: dict[int | tuple[int, int], int] = field(default_factory=dict)
    smb2_seen: bool = False
    ntlm_zero_session_ambiguous: bool = False
    ntlm_zero_session_last_type3_ns: int = 0
    cleartext_cursors: dict[int, int] = field(default_factory=dict)
    cleartext_blocked: set[int] = field(default_factory=set)
    postgres_method: int | None = None
    smtp_pending: dict[int, dict[str, Any]] = field(default_factory=dict)
    imap_pending: dict[int, dict[str, Any]] = field(default_factory=dict)
    plaintext_users: dict[tuple[str, int], dict[str, Any]] = field(default_factory=dict)
    pending_auth_loss: set[tuple[str, int]] = field(default_factory=set)
    pending_auth_bytes: int = 0
    pending_auth_objects: int = 0
    scan_cursors: dict[tuple[int, str], int] = field(default_factory=dict)
    ntlm_pending: dict[int, bool] = field(default_factory=dict)
    pem_pending: dict[int, bool] = field(default_factory=dict)
    line_pending: dict[int, bool] = field(default_factory=dict)
    http_pending: dict[int, bool] = field(default_factory=dict)
    http_framers: dict[int, HTTPFramer] = field(default_factory=dict)
    generic_pending: dict[int, bool] = field(default_factory=dict)
    last_timestamp_ns: int = 0
    last_activity_ns: int = 0


@dataclass(slots=True)
class _TLV:
    tag: int
    start: int
    value_start: int
    end: int

    @property
    def value(self) -> slice:
        return slice(self.value_start, self.end)


def _ports(flow: FlowKey) -> set[int]:
    return {flow.endpoint_a.port, flow.endpoint_b.port}


def _safe_text(raw: bytes, *, unicode_hint: bool = False) -> str:
    if unicode_hint and len(raw) % 2 == 0:
        try:
            return raw.decode("utf-16le").rstrip("\x00")
        except UnicodeDecodeError:
            pass
    for encoding in ("utf-8", "latin-1"):
        try:
            return raw.decode(encoding).rstrip("\x00")
        except UnicodeDecodeError:
            continue
    return raw.hex()


def _b64decode(raw: bytes, *, max_output: int = 1 << 20) -> bytes | None:
    value = raw.strip()
    if not value or len(value) > (max_output * 4 // 3) + 16:
        return None
    value += b"=" * ((-len(value)) % 4)
    try:
        decoded = base64.b64decode(value, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        return None
    return decoded if len(decoded) <= max_output else None


def _parse_auth_params(raw: bytes) -> dict[str, str]:
    params: dict[str, str] = {}
    for match in _AUTH_PARAM_RE.finditer(raw[:16384]):
        key = match.group(1).decode("ascii", "ignore").lower()
        value = match.group(2) if match.group(2) is not None else match.group(3)
        params[key] = value.replace(b'\\"', b'"').decode("latin-1")
    return params


def _ber_length(data: bytes, pos: int, limit: int) -> tuple[int, int] | None:
    if pos >= limit:
        return None
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    count = first & 0x7F
    if count == 0 or count > 4 or pos + count > limit:
        return None
    length = int.from_bytes(data[pos : pos + count], "big")
    if length > _MAX_BINARY_MESSAGE:
        return None
    return length, pos + count


def _tlv(data: bytes, pos: int, limit: int | None = None) -> _TLV | None:
    if limit is None:
        limit = len(data)
    if pos >= limit:
        return None
    tag = data[pos]
    if tag & 0x1F == 0x1F:  # high-tag-number form is unnecessary here
        return None
    parsed = _ber_length(data, pos + 1, limit)
    if parsed is None:
        return None
    length, value_start = parsed
    end = value_start + length
    if end > limit:
        return None
    return _TLV(tag, pos, value_start, end)


def _children(data: bytes, node: _TLV) -> list[_TLV] | None:
    result: list[_TLV] = []
    pos = node.value_start
    while pos < node.end:
        child = _tlv(data, pos, node.end)
        if child is None or child.end <= pos:
            return None
        result.append(child)
        if len(result) > _MAX_ASN1_NODES:
            return None
        pos = child.end
    return result


def _inner_single(data: bytes, node: _TLV) -> _TLV | None:
    children = _children(data, node)
    return children[0] if children and len(children) == 1 else None


def _asn1_integer(data: bytes, node: _TLV) -> int | None:
    target = node
    if target.tag != 0x02:
        target = _inner_single(data, node) or target
    if target.tag != 0x02 or target.end <= target.value_start or target.end - target.value_start > 8:
        return None
    return int.from_bytes(data[target.value], "big", signed=False)


def _asn1_string(data: bytes, node: _TLV) -> str | None:
    target = node
    if target.tag not in (0x04, 0x0C, 0x16, 0x1B, 0x1E):
        target = _inner_single(data, node) or target
    if target.tag not in (0x04, 0x0C, 0x16, 0x1B, 0x1E):
        return None
    return _safe_text(data[target.value], unicode_hint=target.tag == 0x1E)


class SensitiveDetector:
    """Detect sensitive material in flow-affine stream chunks and datagrams."""

    def __init__(
        self,
        session_id: str,
        *,
        overlap_bytes: int = 128 * 1024,
        generic_secret_scan: bool = True,
        credit_card_scan: bool = True,
        extra_sensitive_field_names: Iterable[str] = (),
        max_flows: int = 20_000,
        max_retained_bytes: int = _DEFAULT_MAX_RETAINED_BYTES,
        max_metadata_entries: int | None = None,
        max_provenance_spans: int | None = None,
        max_provenance_packet_id_refs: int | None = None,
        max_packet_ids_per_finding: int = _DEFAULT_MAX_PACKET_IDS_PER_FINDING,
    ) -> None:
        if overlap_bytes < 4096:
            raise ValueError("overlap_bytes must be at least 4096")
        self.session_id = session_id
        self.overlap_bytes = overlap_bytes
        self.generic_secret_scan = generic_secret_scan
        self.credit_card_scan = credit_card_scan
        if max_flows < 1:
            raise ValueError("max_flows must be positive")
        if max_retained_bytes < 4096:
            raise ValueError("max_retained_bytes must be at least 4096")
        if max_metadata_entries is None:
            max_metadata_entries = min(
                _DEFAULT_MAX_METADATA_ENTRIES,
                # A high-water record costs materially more than the two
                # integers it contains once Python mapping overhead is
                # included.  Reserve roughly 128 budget bytes per record so
                # metadata pressure can occur before payload-tail eviction.
                max(64, max_retained_bytes // 128),
            )
        if max_metadata_entries < 64:
            raise ValueError("max_metadata_entries must be at least 64")
        if max_provenance_spans is None:
            max_provenance_spans = min(
                _DEFAULT_MAX_METADATA_ENTRIES,
                max(64, max_metadata_entries * 4),
            )
        if max_provenance_packet_id_refs is None:
            max_provenance_packet_id_refs = max(256, max_provenance_spans * 4)
        if max_provenance_spans < 64:
            raise ValueError("max_provenance_spans must be at least 64")
        if max_provenance_packet_id_refs < 64:
            raise ValueError("max_provenance_packet_id_refs must be at least 64")
        if max_packet_ids_per_finding < 1:
            raise ValueError("max_packet_ids_per_finding must be positive")
        self.max_flows = max_flows
        self.max_retained_bytes = max_retained_bytes
        self.max_metadata_entries = max_metadata_entries
        self.max_provenance_spans = max_provenance_spans
        self.max_provenance_packet_id_refs = max_provenance_packet_id_refs
        self.max_packet_ids_per_finding = max_packet_ids_per_finding
        self.sensitive_fields = _SENSITIVE_FIELDS | {
            value.strip().lower() for value in extra_sensitive_field_names if value.strip()
        }
        self._flows: OrderedDict[str, _FlowState] = OrderedDict()
        self._retained_tail_bytes = 0
        self._peak_retained_bytes = 0
        self._peak_retained_tail_bytes = 0
        self._metadata_entries = 0
        self._peak_metadata_entries = 0
        self._provenance_spans = 0
        self._peak_provenance_spans = 0
        self._provenance_packet_id_refs = 0
        self._peak_provenance_packet_id_refs = 0
        self._pending_auth_bytes = 0
        self._peak_pending_auth_bytes = 0
        self._pending_auth_objects = 0
        self._peak_pending_auth_objects = 0
        self.max_ntlm_correlation_bytes = max(
            1024,
            min(_MAX_NTLM_CORRELATION_BYTES, max_retained_bytes // 4),
        )
        self.max_ntlm_correlation_bytes_per_flow = min(
            _MAX_NTLM_CORRELATION_BYTES_PER_FLOW,
            self.max_ntlm_correlation_bytes,
        )
        self.max_ntlm_correlation_objects = max(
            8,
            min(_MAX_NTLM_CORRELATION_OBJECTS, max_retained_bytes // 2048),
        )
        self.max_ntlm_correlation_objects_per_flow = min(
            _MAX_NTLM_CORRELATION_OBJECTS_PER_FLOW,
            self.max_ntlm_correlation_objects,
        )
        self._ntlm_correlation_index: OrderedDict[
            int, tuple[str, str, int | tuple[int, int]]
        ] = OrderedDict()
        self._ntlm_correlation_bytes = 0
        self._peak_ntlm_correlation_bytes = 0
        self._peak_ntlm_correlation_objects = 0
        self._next_ntlm_correlation_id = 1
        self._stats: Counter[str] = Counter()

    def stats(self) -> dict[str, int]:
        pending_cleartext = sum(self._pending_cleartext_frames(state) for state in self._flows.values())
        result = {
            "attempts": self._stats["attempts"],
            "findings": self._stats["findings"],
            "parser_errors": self._stats["parser_errors"],
            "active_flows": len(self._flows),
            "evicted_flows": self._stats["evicted_flows"],
            "expired_flows": self._stats["expired_flows"],
            "byte_cap_evicted_flows": self._stats["byte_cap_evicted_flows"],
            "retained_tail_bytes": self._retained_tail_bytes,
            "peak_retained_tail_bytes": self._peak_retained_tail_bytes,
            "retained_detector_bytes": self._retained_bytes(),
            "peak_retained_detector_bytes": self._peak_retained_bytes,
            "max_retained_bytes": self.max_retained_bytes,
            "tail_bytes_trimmed": self._stats["tail_bytes_trimmed"],
            "metadata_entries": self._metadata_entries,
            "peak_metadata_entries": self._peak_metadata_entries,
            "max_metadata_entries": self.max_metadata_entries,
            "metadata_cap_evicted_flows": self._stats["metadata_cap_evicted_flows"],
            "metadata_cap_pressure_events": self._stats["metadata_cap_pressure_events"],
            "metadata_cap_saturated": self._stats["metadata_cap_saturated"],
            "provenance_spans": self._provenance_spans,
            "peak_provenance_spans": self._peak_provenance_spans,
            "max_provenance_spans": self.max_provenance_spans,
            "provenance_packet_id_refs": self._provenance_packet_id_refs,
            "peak_provenance_packet_id_refs": self._peak_provenance_packet_id_refs,
            "max_provenance_packet_id_refs": self.max_provenance_packet_id_refs,
            "max_packet_ids_per_finding": self.max_packet_ids_per_finding,
            "provenance_cap_pressure_events": self._stats[
                "provenance_cap_pressure_events"
            ],
            "provenance_cap_evicted_flows": self._stats[
                "provenance_cap_evicted_flows"
            ],
            "provenance_cap_evicted_spans": self._stats[
                "provenance_cap_evicted_spans"
            ],
            "provenance_cap_evicted_packet_id_refs": self._stats[
                "provenance_cap_evicted_packet_id_refs"
            ],
            "provenance_cap_trimmed_spans": self._stats[
                "provenance_cap_trimmed_spans"
            ],
            "provenance_cap_trimmed_packet_id_refs": self._stats[
                "provenance_cap_trimmed_packet_id_refs"
            ],
            "provenance_packet_ids_truncated": self._stats[
                "provenance_packet_ids_truncated"
            ],
            "provenance_pending_ids_truncated": self._stats[
                "provenance_pending_ids_truncated"
            ],
            "provenance_incomplete_findings": self._stats[
                "provenance_incomplete_findings"
            ],
            "pending_auth_bytes": self._pending_auth_bytes,
            "peak_pending_auth_bytes": self._peak_pending_auth_bytes,
            "pending_auth_objects": self._pending_auth_objects,
            "peak_pending_auth_objects": self._peak_pending_auth_objects,
            "pending_auth_cap_pressure_events": self._stats[
                "pending_auth_cap_pressure_events"
            ],
            "pending_auth_cap_evicted_flows": self._stats[
                "pending_auth_cap_evicted_flows"
            ],
            "pending_auth_cap_evicted_objects": self._stats[
                "pending_auth_cap_evicted_objects"
            ],
            "pending_auth_cap_evicted_bytes": self._stats[
                "pending_auth_cap_evicted_bytes"
            ],
            "pending_auth_cap_dropped_objects": self._stats[
                "pending_auth_cap_dropped_objects"
            ],
            "pending_auth_cap_dropped_bytes": self._stats[
                "pending_auth_cap_dropped_bytes"
            ],
            "ntlm_correlation_bytes": self._ntlm_correlation_bytes,
            "peak_ntlm_correlation_bytes": self._peak_ntlm_correlation_bytes,
            "max_ntlm_correlation_bytes": self.max_ntlm_correlation_bytes,
            "max_ntlm_correlation_bytes_per_flow": self.max_ntlm_correlation_bytes_per_flow,
            "ntlm_correlation_objects": len(self._ntlm_correlation_index),
            "peak_ntlm_correlation_objects": self._peak_ntlm_correlation_objects,
            "max_ntlm_correlation_objects": self.max_ntlm_correlation_objects,
            "max_ntlm_correlation_objects_per_flow": self.max_ntlm_correlation_objects_per_flow,
            "ntlm_correlation_cap_pressure_events": self._stats[
                "ntlm_correlation_cap_pressure_events"
            ],
            "ntlm_correlation_cap_evicted_objects": self._stats[
                "ntlm_correlation_cap_evicted_objects"
            ],
            "ntlm_correlation_cap_evicted_bytes": self._stats[
                "ntlm_correlation_cap_evicted_bytes"
            ],
            "ntlm_correlation_cap_dropped_objects": self._stats[
                "ntlm_correlation_cap_dropped_objects"
            ],
            "ntlm_correlation_superseded_objects": self._stats[
                "ntlm_correlation_superseded_objects"
            ],
        }
        for key, value in self._stats.items():
            if key.startswith(("parser_error:", "http_", "coverage_")):
                result[key] = value
        result["coverage_cleartext_pending_frames"] = pending_cleartext
        result["coverage_ntlm_unmatched_responses"] = sum(len(state.ntlm_responses) for state in self._flows.values())
        return result

    @staticmethod
    def _pending_cleartext_frames(state: _FlowState) -> int:
        return sum(
            direction not in state.cleartext_blocked
            and direction in state.directions
            and cursor < state.directions[direction].base_offset + len(state.directions[direction].data)
            for direction, cursor in state.cleartext_cursors.items()
        )

    def expire(
        self,
        flow_id: str | None = None,
        cutoff_timestamp_ns: int | None = None,
        cutoff_activity_ns: int | None = None,
    ) -> int:
        """Forget one flow or all flows last observed before ``cutoff``."""

        if flow_id is not None:
            matching = [
                key
                for key in self._flows
                if key == flow_id or key.startswith(f"{flow_id}|epoch=")
            ]
            for key in matching:
                self._drop_flow(key)
            return len(matching)
        if cutoff_timestamp_ns is None and cutoff_activity_ns is None:
            return 0
        stale = [
            key
            for key, state in self._flows.items()
            if (
                cutoff_timestamp_ns is not None
                and state.last_timestamp_ns < cutoff_timestamp_ns
            )
            or (
                cutoff_activity_ns is not None
                and state.last_activity_ns < cutoff_activity_ns
            )
        ]
        for key in stale:
            self._drop_flow(key)
        self._stats["expired_flows"] += len(stale)
        return len(stale)

    def _flow_state(self, flow_id: str) -> _FlowState:
        state = self._flows.get(flow_id)
        if state is None:
            while len(self._flows) >= self.max_flows:
                oldest = next(iter(self._flows))
                self._drop_flow(oldest)
                self._stats["evicted_flows"] += 1
            state = _FlowState()
            self._flows[flow_id] = state
        else:
            self._flows.move_to_end(flow_id)
        state.last_activity_ns = time.monotonic_ns()
        return state

    @staticmethod
    def _state_tail_bytes(state: _FlowState) -> int:
        return sum(len(direction.data) for direction in state.directions.values())

    @classmethod
    def _pending_auth_value_bytes(cls, value: Any) -> int:
        if isinstance(value, str):
            return 64 + len(value.encode("utf-8", "replace"))
        if isinstance(value, bytes):
            return 64 + len(value)
        if isinstance(value, dict):
            return (
                128
                + _PENDING_AUTH_MAPPING_SLOT_OVERHEAD * len(value)
                + sum(
                    cls._pending_auth_value_bytes(key)
                    + cls._pending_auth_value_bytes(item)
                    for key, item in value.items()
                )
            )
        if isinstance(value, (tuple, list, set)):
            return (
                _PENDING_AUTH_SEQUENCE_OVERHEAD
                + 8 * len(value)
                + sum(cls._pending_auth_value_bytes(item) for item in value)
            )
        if isinstance(value, (bool, int)) or value is None:
            return 32
        return 128

    @classmethod
    def _state_pending_auth_size(cls, state: _FlowState) -> tuple[int, int]:
        total = 0
        objects = 0
        for mapping in (
            state.plaintext_users,
            state.smtp_pending,
            state.imap_pending,
        ):
            for key, value in mapping.items():
                total += (
                    _PENDING_AUTH_ENTRY_OVERHEAD
                    + cls._pending_auth_value_bytes(key)
                    + cls._pending_auth_value_bytes(value)
                )
                objects += 1
        for marker in state.pending_auth_loss:
            total += (
                _PENDING_AUTH_LOSS_MARKER_OVERHEAD
                + cls._pending_auth_value_bytes(marker)
            )
            objects += 1
        return total, objects

    def _refresh_pending_auth_accounting(self, state: _FlowState) -> None:
        new_bytes, new_objects = self._state_pending_auth_size(state)
        self._pending_auth_bytes += new_bytes - state.pending_auth_bytes
        self._pending_auth_objects += new_objects - state.pending_auth_objects
        state.pending_auth_bytes = new_bytes
        state.pending_auth_objects = new_objects
        self._pending_auth_bytes = max(0, self._pending_auth_bytes)
        self._pending_auth_objects = max(0, self._pending_auth_objects)
        self._peak_pending_auth_bytes = max(
            self._peak_pending_auth_bytes, self._pending_auth_bytes
        )
        self._peak_pending_auth_objects = max(
            self._peak_pending_auth_objects, self._pending_auth_objects
        )
        self._record_retained_peaks()

    @classmethod
    def _state_retained_bytes(cls, state: _FlowState) -> int:
        return (
            cls._state_tail_bytes(state)
            + state.ntlm_correlation_bytes
            + state.pending_auth_bytes
        )

    def _retained_bytes(self) -> int:
        return (
            self._retained_tail_bytes
            + self._ntlm_correlation_bytes
            + self._pending_auth_bytes
        )

    def _record_retained_peaks(self) -> None:
        self._peak_retained_tail_bytes = max(
            self._peak_retained_tail_bytes, self._retained_tail_bytes
        )
        self._peak_retained_bytes = max(
            self._peak_retained_bytes, self._retained_bytes()
        )

    @staticmethod
    def _provenance_counts(
        spans: Iterable[ProvenanceSpan],
    ) -> tuple[int, int]:
        span_count = 0
        packet_id_refs = 0
        for span in spans:
            span_count += 1
            packet_id_refs += len(span.packet_ids)
        return span_count, packet_id_refs

    @classmethod
    def _flow_provenance_counts(cls, state: _FlowState) -> tuple[int, int]:
        span_count = 0
        packet_id_refs = 0
        for direction in state.directions.values():
            count, refs = cls._provenance_counts(direction.provenance_spans)
            span_count += count
            packet_id_refs += refs
        return span_count, packet_id_refs

    @staticmethod
    def _coalesce_provenance(
        spans: Iterable[ProvenanceSpan],
    ) -> deque[ProvenanceSpan]:
        result: deque[ProvenanceSpan] = deque()
        for span in sorted(
            (value for value in spans if value.stream_end > value.stream_start),
            key=lambda value: (value.stream_start, value.stream_end),
        ):
            packet_ids = tuple(dict.fromkeys(span.packet_ids))
            normalized = ProvenanceSpan(
                span.stream_start,
                span.stream_end,
                packet_ids,
                span.packet_ids_complete,
            )
            if (
                result
                and result[-1].stream_end == normalized.stream_start
                and result[-1].packet_ids == normalized.packet_ids
                and result[-1].packet_ids_complete
                == normalized.packet_ids_complete
            ):
                previous = result.pop()
                result.append(
                    ProvenanceSpan(
                        previous.stream_start,
                        normalized.stream_end,
                        previous.packet_ids,
                        previous.packet_ids_complete,
                    )
                )
            else:
                result.append(normalized)
        return result

    @classmethod
    def _clip_provenance(
        cls,
        spans: Iterable[ProvenanceSpan],
        start: int,
        end: int,
    ) -> deque[ProvenanceSpan]:
        clipped: list[ProvenanceSpan] = []
        for span in spans:
            if span.stream_end <= start:
                continue
            if span.stream_start >= end:
                break
            clipped.append(
                ProvenanceSpan(
                    max(start, span.stream_start),
                    min(end, span.stream_end),
                    span.packet_ids,
                    span.packet_ids_complete,
                )
            )
        return cls._coalesce_provenance(clipped)

    @classmethod
    def _overlay_provenance(
        cls,
        existing: Iterable[ProvenanceSpan],
        replacement: Iterable[ProvenanceSpan],
        start: int,
        end: int,
    ) -> deque[ProvenanceSpan]:
        combined: list[ProvenanceSpan] = []
        for span in existing:
            if span.stream_end <= start or span.stream_start >= end:
                combined.append(span)
                continue
            if span.stream_start < start:
                combined.append(
                    ProvenanceSpan(
                        span.stream_start,
                        start,
                        span.packet_ids,
                        span.packet_ids_complete,
                    )
                )
            if span.stream_end > end:
                combined.append(
                    ProvenanceSpan(
                        end,
                        span.stream_end,
                        span.packet_ids,
                        span.packet_ids_complete,
                    )
                )
        combined.extend(replacement)
        return cls._coalesce_provenance(combined)

    @classmethod
    def _chunk_provenance(cls, chunk: StreamChunk) -> deque[ProvenanceSpan]:
        start = chunk.stream_offset
        end = start + len(chunk.data)
        fallback_ids = tuple(dict.fromkeys(chunk.packet_ids))
        if not chunk.provenance_spans:
            return deque(
                [ProvenanceSpan(start, end, fallback_ids, False)]
                if end > start
                else []
            )

        supplied = cls._clip_provenance(chunk.provenance_spans, start, end)
        result: list[ProvenanceSpan] = []
        cursor = start
        for span in supplied:
            if span.stream_start > cursor:
                result.append(
                    ProvenanceSpan(cursor, span.stream_start, fallback_ids, False)
                )
            if span.stream_end <= cursor:
                continue
            clipped_start = max(cursor, span.stream_start)
            result.append(
                ProvenanceSpan(
                    clipped_start,
                    span.stream_end,
                    span.packet_ids,
                    span.packet_ids_complete,
                )
            )
            cursor = span.stream_end
        if cursor < end:
            result.append(ProvenanceSpan(cursor, end, fallback_ids, False))
        return cls._coalesce_provenance(result)

    def _replace_direction_provenance(
        self,
        direction: _DirectionState,
        spans: Iterable[ProvenanceSpan],
    ) -> None:
        old_count, old_refs = self._provenance_counts(direction.provenance_spans)
        normalized = self._coalesce_provenance(spans)
        new_count, new_refs = self._provenance_counts(normalized)
        direction.provenance_spans = normalized
        self._provenance_spans += new_count - old_count
        self._provenance_packet_id_refs += new_refs - old_refs
        self._provenance_spans = max(0, self._provenance_spans)
        self._provenance_packet_id_refs = max(0, self._provenance_packet_id_refs)
        self._peak_provenance_spans = max(
            self._peak_provenance_spans, self._provenance_spans
        )
        self._peak_provenance_packet_id_refs = max(
            self._peak_provenance_packet_id_refs,
            self._provenance_packet_id_refs,
        )

    def _append_direction_provenance(
        self,
        direction: _DirectionState,
        spans: Iterable[ProvenanceSpan],
    ) -> None:
        for span in spans:
            packet_ids = tuple(dict.fromkeys(span.packet_ids))
            normalized = ProvenanceSpan(
                span.stream_start,
                span.stream_end,
                packet_ids,
                span.packet_ids_complete,
            )
            if normalized.stream_end <= normalized.stream_start:
                continue
            if (
                direction.provenance_spans
                and direction.provenance_spans[-1].stream_end
                == normalized.stream_start
                and direction.provenance_spans[-1].packet_ids
                == normalized.packet_ids
                and direction.provenance_spans[-1].packet_ids_complete
                == normalized.packet_ids_complete
            ):
                previous = direction.provenance_spans.pop()
                direction.provenance_spans.append(
                    ProvenanceSpan(
                        previous.stream_start,
                        normalized.stream_end,
                        previous.packet_ids,
                        previous.packet_ids_complete,
                    )
                )
                continue
            direction.provenance_spans.append(normalized)
            self._provenance_spans += 1
            self._provenance_packet_id_refs += len(normalized.packet_ids)
        self._peak_provenance_spans = max(
            self._peak_provenance_spans, self._provenance_spans
        )
        self._peak_provenance_packet_id_refs = max(
            self._peak_provenance_packet_id_refs,
            self._provenance_packet_id_refs,
        )

    def _enforce_provenance_cap(self, current_flow_id: str) -> None:
        def over_cap() -> bool:
            return (
                self._provenance_spans > self.max_provenance_spans
                or self._provenance_packet_id_refs
                > self.max_provenance_packet_id_refs
            )

        if over_cap():
            self._stats["provenance_cap_pressure_events"] += 1
        while over_cap() and len(self._flows) > 1:
            oldest = next(iter(self._flows))
            if oldest == current_flow_id:
                self._flows.move_to_end(oldest)
                oldest = next(iter(self._flows))
            stale = self._flows.get(oldest)
            if stale is None:
                break
            span_count, refs = self._flow_provenance_counts(stale)
            self._drop_flow(oldest)
            self._stats["evicted_flows"] += 1
            self._stats["provenance_cap_evicted_flows"] += 1
            self._stats["provenance_cap_evicted_spans"] += span_count
            self._stats["provenance_cap_evicted_packet_id_refs"] += refs

        state = self._flows.get(current_flow_id)
        if state is None:
            return
        while over_cap():
            removed = False
            for direction in state.directions.values():
                if not direction.provenance_spans:
                    continue
                span = direction.provenance_spans.popleft()
                self._provenance_spans -= 1
                self._provenance_packet_id_refs -= len(span.packet_ids)
                self._stats["provenance_cap_trimmed_spans"] += 1
                self._stats["provenance_cap_trimmed_packet_id_refs"] += len(
                    span.packet_ids
                )
                removed = True
                if not over_cap():
                    break
            if not removed:
                break

    @staticmethod
    def _ntlm_challenge_size(challenge: _NtlmChallenge) -> int:
        # Include a conservative fixed object/index allowance as well as all
        # variable payload retained by the correlation engine.
        return 160 + len(challenge.challenge) + 8 * len(challenge.packet_ids)

    @staticmethod
    def _ntlm_response_size(response: _NtlmResponse) -> int:
        text_bytes = sum(
            len(value.encode("utf-8", "replace"))
            for value in (response.username, response.domain, response.workstation)
        )
        return (
            224
            + text_bytes
            + len(response.lm_response)
            + len(response.nt_response)
            + 8 * len(response.packet_ids)
        )

    @staticmethod
    def _state_ntlm_objects(state: _FlowState) -> int:
        return len(state.ntlm_challenges) + len(state.ntlm_responses)

    @staticmethod
    def _oldest_state_ntlm_entry(
        state: _FlowState,
    ) -> tuple[str, int | tuple[int, int]] | None:
        candidates: list[tuple[int, str, int | tuple[int, int]]] = []
        for direction, challenge in state.ntlm_challenges.items():
            candidates.append((challenge.correlation_id, "challenge", direction))
        if state.ntlm_responses:
            correlation_id = next(iter(state.ntlm_responses))
            candidates.append((correlation_id, "response", correlation_id))
        if not candidates:
            return None
        _correlation_id, kind, key = min(candidates)
        return kind, key

    def _remove_ntlm_entry(
        self,
        flow_id: str,
        state: _FlowState,
        kind: str,
        key: int | tuple[int, int],
        *,
        cap_eviction: bool = False,
        superseded: bool = False,
    ) -> _NtlmChallenge | _NtlmResponse | None:
        if kind == "challenge":
            entry = state.ntlm_challenges.pop(key, None)
        else:
            entry = state.ntlm_responses.pop(key, None)
        if entry is None:
            return None
        self._ntlm_correlation_index.pop(entry.correlation_id, None)
        state.ntlm_correlation_bytes -= entry.retained_size
        self._ntlm_correlation_bytes -= entry.retained_size
        state.ntlm_correlation_bytes = max(0, state.ntlm_correlation_bytes)
        self._ntlm_correlation_bytes = max(0, self._ntlm_correlation_bytes)
        if cap_eviction:
            self._stats["ntlm_correlation_cap_evicted_objects"] += 1
            self._stats["ntlm_correlation_cap_evicted_bytes"] += entry.retained_size
        if superseded:
            self._stats["ntlm_correlation_superseded_objects"] += 1
        return entry

    def _evict_oldest_ntlm_entry(self) -> bool:
        while self._ntlm_correlation_index:
            _correlation_id, (flow_id, kind, key) = next(
                iter(self._ntlm_correlation_index.items())
            )
            state = self._flows.get(flow_id)
            if state is None:
                self._ntlm_correlation_index.popitem(last=False)
                continue
            return self._remove_ntlm_entry(
                flow_id, state, kind, key, cap_eviction=True
            ) is not None
        return False

    def _reserve_ntlm_entry(
        self, flow_id: str, state: _FlowState, retained_size: int
    ) -> bool:
        flow_objects = self._state_ntlm_objects(state)
        pressure = (
            retained_size > self.max_ntlm_correlation_bytes_per_flow
            or retained_size > self.max_ntlm_correlation_bytes
            or flow_objects >= self.max_ntlm_correlation_objects_per_flow
            or state.ntlm_correlation_bytes + retained_size
            > self.max_ntlm_correlation_bytes_per_flow
            or len(self._ntlm_correlation_index)
            >= self.max_ntlm_correlation_objects
            or self._ntlm_correlation_bytes + retained_size
            > self.max_ntlm_correlation_bytes
        )
        if pressure:
            self._stats["ntlm_correlation_cap_pressure_events"] += 1
        if (
            retained_size > self.max_ntlm_correlation_bytes_per_flow
            or retained_size > self.max_ntlm_correlation_bytes
        ):
            self._stats["ntlm_correlation_cap_dropped_objects"] += 1
            return False

        while (
            self._state_ntlm_objects(state)
            >= self.max_ntlm_correlation_objects_per_flow
            or state.ntlm_correlation_bytes + retained_size
            > self.max_ntlm_correlation_bytes_per_flow
        ):
            oldest = self._oldest_state_ntlm_entry(state)
            if oldest is None:
                break
            kind, key = oldest
            self._remove_ntlm_entry(
                flow_id, state, kind, key, cap_eviction=True
            )

        while (
            len(self._ntlm_correlation_index)
            >= self.max_ntlm_correlation_objects
            or self._ntlm_correlation_bytes + retained_size
            > self.max_ntlm_correlation_bytes
        ):
            if not self._evict_oldest_ntlm_entry():
                break

        if (
            self._state_ntlm_objects(state)
            >= self.max_ntlm_correlation_objects_per_flow
            or state.ntlm_correlation_bytes + retained_size
            > self.max_ntlm_correlation_bytes_per_flow
            or len(self._ntlm_correlation_index)
            >= self.max_ntlm_correlation_objects
            or self._ntlm_correlation_bytes + retained_size
            > self.max_ntlm_correlation_bytes
        ):
            self._stats["ntlm_correlation_cap_dropped_objects"] += 1
            return False
        return True

    def _retain_ntlm_challenge(
        self, flow_id: str, state: _FlowState, challenge: _NtlmChallenge
    ) -> bool:
        key = (challenge.direction, challenge.smb_session) if challenge.smb_session is not None else challenge.direction
        existing = state.ntlm_challenges.get(key)
        if existing is not None:
            self._remove_ntlm_entry(
                flow_id,
                state,
                "challenge",
                key,
                superseded=True,
            )
        challenge.retained_size = self._ntlm_challenge_size(challenge)
        if not self._reserve_ntlm_entry(flow_id, state, challenge.retained_size):
            return False
        challenge.correlation_id = self._next_ntlm_correlation_id
        self._next_ntlm_correlation_id += 1
        state.ntlm_challenges[key] = challenge
        self._ntlm_correlation_index[challenge.correlation_id] = (
            flow_id,
            "challenge",
            key,
        )
        state.ntlm_correlation_bytes += challenge.retained_size
        self._ntlm_correlation_bytes += challenge.retained_size
        self._peak_ntlm_correlation_bytes = max(
            self._peak_ntlm_correlation_bytes, self._ntlm_correlation_bytes
        )
        self._peak_ntlm_correlation_objects = max(
            self._peak_ntlm_correlation_objects,
            len(self._ntlm_correlation_index),
        )
        self._record_retained_peaks()
        return True

    def _retain_ntlm_response(
        self, flow_id: str, state: _FlowState, response: _NtlmResponse
    ) -> bool:
        response.retained_size = self._ntlm_response_size(response)
        if not self._reserve_ntlm_entry(flow_id, state, response.retained_size):
            return False
        response.correlation_id = self._next_ntlm_correlation_id
        self._next_ntlm_correlation_id += 1
        state.ntlm_responses[response.correlation_id] = response
        self._ntlm_correlation_index[response.correlation_id] = (
            flow_id,
            "response",
            response.correlation_id,
        )
        state.ntlm_correlation_bytes += response.retained_size
        self._ntlm_correlation_bytes += response.retained_size
        self._peak_ntlm_correlation_bytes = max(
            self._peak_ntlm_correlation_bytes, self._ntlm_correlation_bytes
        )
        self._peak_ntlm_correlation_objects = max(
            self._peak_ntlm_correlation_objects,
            len(self._ntlm_correlation_index),
        )
        self._record_retained_peaks()
        return True

    @staticmethod
    def _state_metadata_entries(state: _FlowState) -> int:
        return (
            len(state.emitted_highwater)
            + len(state.state_highwater)
            + len(state.ntlm_pair_highwater)
        )

    def _drop_flow(self, flow_id: str) -> _FlowState | None:
        state = self._flows.pop(flow_id, None)
        if state is not None:
            self._stats["coverage_cleartext_incomplete_at_eviction"] += self._pending_cleartext_frames(state)
            self._stats["coverage_ntlm_unmatched_at_eviction"] += len(state.ntlm_responses)
            self._retained_tail_bytes -= self._state_tail_bytes(state)
            self._pending_auth_bytes -= state.pending_auth_bytes
            self._pending_auth_objects -= state.pending_auth_objects
            span_count, packet_id_refs = self._flow_provenance_counts(state)
            self._provenance_spans -= span_count
            self._provenance_packet_id_refs -= packet_id_refs
            for direction in tuple(state.ntlm_challenges):
                self._remove_ntlm_entry(flow_id, state, "challenge", direction)
            for correlation_id in tuple(state.ntlm_responses):
                self._remove_ntlm_entry(
                    flow_id, state, "response", correlation_id
                )
            self._metadata_entries -= self._state_metadata_entries(state)
            if self._retained_tail_bytes < 0:  # defensive accounting invariant
                self._retained_tail_bytes = 0
            if self._metadata_entries < 0:
                self._metadata_entries = 0
            if self._provenance_spans < 0:
                self._provenance_spans = 0
            if self._provenance_packet_id_refs < 0:
                self._provenance_packet_id_refs = 0
            if self._pending_auth_bytes < 0:
                self._pending_auth_bytes = 0
            if self._pending_auth_objects < 0:
                self._pending_auth_objects = 0
        return state

    def _reserve_metadata_entry(self, current_flow_id: str) -> bool:
        """Reserve one bounded high-water entry, evicting whole LRU flows."""

        if self._metadata_entries >= self.max_metadata_entries:
            self._stats["metadata_cap_pressure_events"] += 1
        while self._metadata_entries >= self.max_metadata_entries and len(self._flows) > 1:
            oldest = next(iter(self._flows))
            if oldest == current_flow_id:
                self._flows.move_to_end(oldest)
                oldest = next(iter(self._flows))
            self._drop_flow(oldest)
            self._stats["evicted_flows"] += 1
            self._stats["metadata_cap_evicted_flows"] += 1
        if self._metadata_entries >= self.max_metadata_entries:
            # A single flow has a fixed detector vocabulary well below the
            # enforced minimum cap. Keep this defensive branch explicit so a
            # future dynamic detector name cannot silently violate the cap.
            self._stats["metadata_cap_saturated"] += 1
            return False
        self._metadata_entries += 1
        self._peak_metadata_entries = max(
            self._peak_metadata_entries, self._metadata_entries
        )
        return True

    def _set_highwater(
        self,
        ctx: _ScanContext,
        state: _FlowState,
        mapping: dict[tuple[Any, ...], tuple[int, int]],
        scope: tuple[Any, ...],
        marker: tuple[int, int],
    ) -> bool:
        previous = mapping.get(scope)
        if previous is not None and marker <= previous:
            return False
        if previous is None and not self._reserve_metadata_entry(ctx.flow_id):
            return False
        mapping[scope] = marker
        return True

    @staticmethod
    def _pending_auth_loss_marker(kind: str, key: Any) -> tuple[str, int]:
        if kind == "plaintext":
            protocol, direction = key
            return f"plaintext:{protocol}", int(direction)
        return kind, int(key)

    def _discard_one_pending_auth_entry(self, state: _FlowState) -> bool:
        for kind, mapping in (
            ("plaintext", state.plaintext_users),
            ("smtp", state.smtp_pending),
            ("imap", state.imap_pending),
        ):
            if not mapping:
                continue
            key = min(mapping, key=repr)
            before_bytes = state.pending_auth_bytes
            mapping.pop(key, None)
            state.pending_auth_loss.add(
                self._pending_auth_loss_marker(kind, key)
            )
            self._refresh_pending_auth_accounting(state)
            self._stats["pending_auth_cap_dropped_objects"] += 1
            self._stats["pending_auth_cap_dropped_bytes"] += max(
                0, before_bytes - state.pending_auth_bytes
            )
            return True
        return False

    def _enforce_retained_cap(self, current_flow_id: str) -> None:
        """Enforce the worker-wide tail and correlation-state byte cap."""

        if (
            self._retained_bytes() > self.max_retained_bytes
            and self._pending_auth_bytes
        ):
            self._stats["pending_auth_cap_pressure_events"] += 1

        while self._retained_bytes() > self.max_retained_bytes and len(self._flows) > 1:
            oldest = next(iter(self._flows))
            if oldest == current_flow_id:
                self._flows.move_to_end(oldest)
                oldest = next(iter(self._flows))
            stale = self._flows.get(oldest)
            pending_bytes = stale.pending_auth_bytes if stale is not None else 0
            pending_objects = stale.pending_auth_objects if stale is not None else 0
            self._drop_flow(oldest)
            self._stats["evicted_flows"] += 1
            self._stats["byte_cap_evicted_flows"] += 1
            if pending_bytes or pending_objects:
                self._stats["pending_auth_cap_evicted_flows"] += 1
                self._stats["pending_auth_cap_evicted_bytes"] += pending_bytes
                self._stats["pending_auth_cap_evicted_objects"] += pending_objects

        if self._retained_bytes() > self.max_retained_bytes:
            state = self._flows.get(current_flow_id)
            if state is not None:
                before = self._state_tail_bytes(state)
                directions = list(state.directions.values())
                tail_budget = max(
                    0,
                    self.max_retained_bytes
                    - self._ntlm_correlation_bytes
                    - self._pending_auth_bytes,
                )
                share = tail_budget // max(1, len(directions))
                remainder = tail_budget - share * len(directions)
                for index, direction in enumerate(directions):
                    keep = share + (1 if index < remainder else 0)
                    if len(direction.data) > keep:
                        drop = len(direction.data) - keep
                        del direction.data[:drop]
                        direction.base_offset += drop
                        self._replace_direction_provenance(
                            direction,
                            self._clip_provenance(
                                direction.provenance_spans,
                                direction.base_offset,
                                direction.base_offset + len(direction.data),
                            ),
                        )
                after = self._state_tail_bytes(state)
                self._retained_tail_bytes -= before - after
                self._stats["tail_bytes_trimmed"] += before - after

        # Dedicated NTLM budgets are stricter than the shared byte budget, but
        # keep a defensive final guard in case those limits are changed later.
        while self._retained_bytes() > self.max_retained_bytes:
            if not self._evict_oldest_ntlm_entry():
                break
        state = self._flows.get(current_flow_id)
        while (
            state is not None
            and self._retained_bytes() > self.max_retained_bytes
            and self._discard_one_pending_auth_entry(state)
        ):
            pass
        if self._retained_bytes() > self.max_retained_bytes:
            # All variable pending-auth and NTLM state has been removed and
            # the retained byte tails were trimmed. A final whole-flow drop is
            # preferable to advertising a budget that can be exceeded.
            state = self._flows.get(current_flow_id)
            if state is not None:
                pending_bytes = state.pending_auth_bytes
                pending_objects = state.pending_auth_objects
                self._drop_flow(current_flow_id)
                self._stats["evicted_flows"] += 1
                self._stats["byte_cap_evicted_flows"] += 1
                if pending_bytes or pending_objects:
                    self._stats["pending_auth_cap_evicted_flows"] += 1
                    self._stats["pending_auth_cap_evicted_bytes"] += pending_bytes
                    self._stats["pending_auth_cap_evicted_objects"] += pending_objects
        self._record_retained_peaks()

    def process_stream(self, chunk: StreamChunk) -> list[Finding]:
        self._stats["attempts"] += 1
        flow_id = f"{chunk.flow.stable_text()}|epoch={chunk.connection_epoch}"
        state = self._flow_state(flow_id)
        state.last_timestamp_ns = max(state.last_timestamp_ns, chunk.last_timestamp_ns)
        context = self._merge_stream(state, chunk, flow_id)
        try:
            return self._scan(context, state, datagram=False)
        finally:
            self._refresh_pending_auth_accounting(state)
            self._enforce_retained_cap(flow_id)

    def process_datagram(self, packet: ParsedPacket) -> list[Finding]:
        if not packet.transport_parsed or not packet.transport_payload:
            return []
        self._stats["attempts"] += 1
        flow, direction = packet.flow()
        flow_id = flow.stable_text()
        state = self._flow_state(flow_id)
        state.last_timestamp_ns = max(state.last_timestamp_ns, packet.timestamp_ns)
        completeness = "truncated" if packet.truncated else "complete"
        context = _ScanContext(
            flow=flow,
            flow_id=flow_id,
            connection_epoch=None,
            direction=direction,
            base_offset=None,
            data=packet.transport_payload,
            packet_ids=packet.source_packet_ids or (packet.packet_id,),
            provenance_spans=(
                ProvenanceSpan(
                    0,
                    len(packet.transport_payload),
                    packet.source_packet_ids or (packet.packet_id,),
                    True,
                ),
            ),
            packet_ids_complete=True,
            observed_timestamp_ns=packet.timestamp_ns,
            completeness=completeness,
            is_datagram=True,
        )
        try:
            return self._scan(context, state, datagram=True)
        finally:
            self._refresh_pending_auth_accounting(state)
            self._enforce_retained_cap(flow_id)

    def _merge_stream(
        self, state: _FlowState, chunk: StreamChunk, flow_id: str
    ) -> _ScanContext:
        direction = state.directions.setdefault(chunk.direction, _DirectionState())
        start = chunk.stream_offset
        end = start + len(chunk.data)
        chunk_spans = self._chunk_provenance(chunk)
        old_start = direction.base_offset
        old_end = old_start + len(direction.data)
        old_length = len(direction.data)
        packet_ids = tuple(dict.fromkeys(chunk.packet_ids))
        scan_spans: tuple[ProvenanceSpan, ...] | deque[ProvenanceSpan]

        if not direction.data:
            scan_start = start
            scan_spans = tuple(chunk_spans)
            if len(chunk.data) <= self.overlap_bytes:
                direction.base_offset = start
                direction.data = bytearray(chunk.data)
                scan_data: bytes | bytearray = direction.data
            else:
                scan_data = chunk.data
                direction.base_offset = end - self.overlap_bytes
                direction.data = bytearray(chunk.data[-self.overlap_bytes :])
            direction.packet_ids = packet_ids
            self._replace_direction_provenance(
                direction,
                self._clip_provenance(
                    chunk_spans,
                    direction.base_offset,
                    direction.base_offset + len(direction.data),
                ),
            )
        elif (
            start >= old_start
            and end <= old_end
            and direction.data[start - old_start : end - old_start] == chunk.data
        ):
            # Reassembly should normally consume retransmissions, but an exact
            # contained replay is common enough to make the detector fast-path
            # explicit.  It cannot introduce a new absolute stream span.
            scan_start, scan_data = start, b""
            scan_spans = ()
        elif start > old_end or end < old_start:
            # A true hole cannot be reconstructed by the detector.  Scan the
            # new island independently and retain the most recent island.
            scan_start, scan_data = start, chunk.data
            scan_spans = tuple(chunk_spans)
            retained = chunk.data[-self.overlap_bytes :]
            direction.base_offset = end - len(retained)
            direction.data = bytearray(retained)
            direction.packet_ids = packet_ids
            self._replace_direction_provenance(
                direction,
                self._clip_provenance(
                    chunk_spans,
                    direction.base_offset,
                    direction.base_offset + len(direction.data),
                ),
            )
        elif start == old_end:
            # The overwhelmingly common in-order path mutates the retained
            # bytearray instead of copying the full detector tail per segment.
            direction.data.extend(chunk.data)
            self._append_direction_provenance(direction, chunk_spans)
            if len(chunk.data) > self.overlap_bytes:
                scan_start = old_start
                scan_data = bytes(direction.data)
                scan_spans = tuple(direction.provenance_spans)
                retained = chunk.data[-self.overlap_bytes :]
                direction.base_offset = end - len(retained)
                direction.data = bytearray(retained)
                self._replace_direction_provenance(
                    direction,
                    self._clip_provenance(
                        direction.provenance_spans,
                        direction.base_offset,
                        end,
                    ),
                )
            else:
                # Trim in batches. Deleting a few bytes from the front of a
                # 128 KiB bytearray on every tiny TCP segment otherwise turns
                # retention into an O(tail_size * packets) memmove loop.
                trim_slack = min(64 * 1024, max(4096, self.overlap_bytes // 4))
                if len(direction.data) > self.overlap_bytes + trim_slack:
                    overflow = len(direction.data) - self.overlap_bytes
                    del direction.data[:overflow]
                    direction.base_offset += overflow
                    self._replace_direction_provenance(
                        direction,
                        self._clip_provenance(
                            direction.provenance_spans,
                            direction.base_offset,
                            direction.base_offset + len(direction.data),
                        ),
                    )
                scan_start = direction.base_offset
                scan_data = direction.data
                scan_spans = direction.provenance_spans
            direction.packet_ids = packet_ids
        else:
            scan_start = min(old_start, start)
            scan_end = max(old_end, end)
            merged = bytearray(scan_end - scan_start)
            merged[old_start - scan_start : old_end - scan_start] = direction.data
            merged[start - scan_start : end - scan_start] = chunk.data
            scan_data = merged
            merged_spans = self._overlay_provenance(
                direction.provenance_spans,
                chunk_spans,
                start,
                end,
            )
            scan_spans = tuple(
                self._clip_provenance(merged_spans, scan_start, scan_end)
            )
            if end >= old_end:
                retain = merged[-self.overlap_bytes :]
                direction.base_offset = scan_start + len(merged) - len(retain)
                direction.data = bytearray(retain)
                direction.packet_ids = packet_ids
                self._replace_direction_provenance(
                    direction,
                    self._clip_provenance(
                        merged_spans,
                        direction.base_offset,
                        direction.base_offset + len(direction.data),
                    ),
                )

        self._retained_tail_bytes += len(direction.data) - old_length
        self._record_retained_peaks()
        self._enforce_provenance_cap(flow_id)

        return _ScanContext(
            flow=chunk.flow,
            flow_id=flow_id,
            connection_epoch=chunk.connection_epoch,
            direction=chunk.direction,
            base_offset=scan_start,
            data=scan_data,
            packet_ids=packet_ids,
            provenance_spans=scan_spans,
            packet_ids_complete=True,
            observed_timestamp_ns=chunk.last_timestamp_ns,
            completeness=chunk.completeness,
            is_datagram=False,
        )

    def _scan(self, ctx: _ScanContext, state: _FlowState, *, datagram: bool) -> list[Finding]:
        findings: list[Finding] = []
        framed_http = False
        if not datagram and ctx.data and ctx.base_offset is not None:
            framer = state.http_framers.setdefault(ctx.direction, HTTPFramer())
            messages = framer.scan(ctx.data, ctx.base_offset, self.overlap_bytes, self._stats)
            framed_http = framer.recognized
            for message in messages:
                findings.extend(self._scan_http_message(ctx, state, message))
            if framed_http and framer.cursor is not None:
                pending_start = framer.cursor - ctx.base_offset
                if 0 <= pending_start < len(ctx.data):
                    header_end = ctx.data.find(b"\r\n\r\n", pending_start)
                    header_end = min(len(ctx.data), pending_start + 32768) if header_end < 0 else header_end + 4
                    findings.extend(self._scan_http(replace(
                        ctx, base_offset=framer.cursor,
                        data=ctx.data[pending_start:header_end],
                    ), state))
        scanners = [
            self._scan_ntlm_raw,
            self._scan_ntlm_encoded,
            self._scan_http,
            self._scan_line_protocols,
            self._scan_cleartext,
            self._scan_ldap,
            self._scan_mssql,
            self._scan_kerberos,
        ]
        if datagram:
            scanners.insert(3, self._scan_snmp)
        if self.generic_secret_scan:
            scanners.append(self._scan_generic_secrets)
            scanners.append(self._scan_pem_private_keys)
        if self.credit_card_scan:
            scanners.append(self._scan_cards)

        scanner_overlap = {
            "_scan_ntlm_raw": 16,
            "_scan_ntlm_encoded": min(self.overlap_bytes, 16 * 1024 + 128),
            "_scan_http": 512,
            "_scan_line_protocols": 256,
            "_scan_ldap": min(self.overlap_bytes, 64 * 1024),
            "_scan_mssql": min(self.overlap_bytes, 64 * 1024),
            "_scan_kerberos": min(self.overlap_bytes, 64 * 1024),
            "_scan_generic_secrets": min(self.overlap_bytes, 768),
            "_scan_pem_private_keys": min(self.overlap_bytes, 66 * 1024),
            "_scan_cards": 64,
        }
        for scanner in scanners:
            try:
                scanner_name = scanner.__name__
                if framed_http and scanner_name in {
                    "_scan_http", "_scan_line_protocols", "_scan_generic_secrets", "_scan_pem_private_keys", "_scan_cards"
                }:
                    # These scanners run within individual framed messages
                    # above. Never concatenate a body tail with the next request.
                    self._advance_scanner_cursor(ctx, state, scanner_name)
                    continue
                if not datagram and not self._scanner_gate(ctx, state, scanner_name):
                    self._advance_scanner_cursor(ctx, state, scanner_name)
                    continue
                overlap = scanner_overlap.get(scanner_name, self.overlap_bytes)
                if scanner_name == "_scan_ntlm_raw" and state.ntlm_pending.get(
                    ctx.direction, False
                ):
                    overlap = min(self.overlap_bytes, 128 * 1024)
                elif scanner_name == "_scan_http" and state.http_pending.get(
                    ctx.direction, False
                ):
                    overlap = min(self.overlap_bytes, 16 * 1024 + 256)
                elif scanner_name == "_scan_line_protocols" and state.line_pending.get(
                    ctx.direction, False
                ):
                    overlap = min(self.overlap_bytes, _MAX_LINE + 128)
                elif scanner_name == "_scan_generic_secrets" and state.generic_pending.get(
                    ctx.direction, False
                ):
                    overlap = min(self.overlap_bytes, _MAX_LINE + 128)
                scanner_ctx = (
                    ctx
                    if datagram or scanner_name == "_scan_cleartext"
                    else self._scanner_window(
                        ctx,
                        state,
                        scanner_name,
                        overlap,
                    )
                )
                if scanner_ctx.data:
                    findings.extend(scanner(scanner_ctx, state))
            except (ValueError, IndexError, struct.error, UnicodeError, binascii.Error):
                self._stats["parser_errors"] += 1
                self._stats[f"parser_error:{scanner.__name__}"] += 1
        self._stats["findings"] += len(findings)
        return findings

    @staticmethod
    def _scanner_range(
        ctx: _ScanContext,
        state: _FlowState,
        scanner_name: str,
        lookback: int,
    ) -> tuple[int, int]:
        assert ctx.base_offset is not None
        absolute_end = ctx.base_offset + len(ctx.data)
        cursor = state.scan_cursors.get((ctx.direction, scanner_name), ctx.base_offset)
        start_absolute = max(ctx.base_offset, min(cursor, absolute_end) - lookback)
        return start_absolute - ctx.base_offset, len(ctx.data)

    def _scanner_gate(
        self,
        ctx: _ScanContext,
        state: _FlowState,
        scanner_name: str,
    ) -> bool:
        """Cheap signature/port gates before allocating a scanner window."""

        if not ctx.data:
            return False
        ports = _ports(ctx.flow)
        if scanner_name == "_scan_cards":
            return True
        if scanner_name == "_scan_ntlm_raw":
            start, end = self._scanner_range(ctx, state, scanner_name, 16)
            return state.ntlm_pending.get(ctx.direction, False) or ctx.data.find(
                b"NTLMSSP\x00", start, end
            ) >= 0
        if scanner_name == "_scan_ntlm_encoded":
            return bool(ports & {25, 110, 143, 587})
        if scanner_name == "_scan_cleartext":
            return bool(ports & {5432, 6379}) and not ctx.is_datagram
        if scanner_name == "_scan_http":
            if state.http_pending.get(ctx.direction, False):
                return True
            start, end = self._scanner_range(ctx, state, scanner_name, 256)
            return _HTTP_GATE_RE.search(ctx.data, start, end) is not None
        if scanner_name == "_scan_line_protocols":
            if (
                ctx.direction in state.smtp_pending
                or ctx.direction in state.imap_pending
                or state.line_pending.get(ctx.direction, False)
            ):
                return True
            start, end = self._scanner_range(ctx, state, scanner_name, 128)
            return _LINE_GATE_RE.search(ctx.data, start, end) is not None
        if scanner_name == "_scan_ldap":
            if ports & {389, 636, 3268, 3269}:
                return True
            start, end = self._scanner_range(ctx, state, scanner_name, 64)
            return ctx.data.find(b"\x60", start, end) >= 0
        if scanner_name == "_scan_mssql":
            if 1433 in ports:
                return True
            start, end = self._scanner_range(ctx, state, scanner_name, 8)
            return ctx.data.find(b"\x10", start, end) >= 0
        if scanner_name == "_scan_kerberos":
            if ports & {88, 464}:
                return True
            start, end = self._scanner_range(ctx, state, scanner_name, 8)
            return ctx.data.find(b"\x6a", start, end) >= 0
        if scanner_name == "_scan_generic_secrets":
            if state.generic_pending.get(ctx.direction, False):
                return True
            start, end = self._scanner_range(ctx, state, scanner_name, 512)
            probe = bytes(ctx.data[start:end]).lower()
            if any(token in probe for token in _GENERIC_STRONG_PREFIXES):
                return True
            if _GENERIC_NAMED_GATE_RE.search(probe) is not None:
                return True
            if self.sensitive_fields != _SENSITIVE_FIELDS:
                return any(name.encode("utf-8", "ignore") in probe for name in self.sensitive_fields)
            return False
        if scanner_name == "_scan_pem_private_keys":
            start, end = self._scanner_range(ctx, state, scanner_name, 64)
            return (
                state.pem_pending.get(ctx.direction, False)
                or ctx.data.find(b"-----BEGIN ", start, end) >= 0
                or ctx.data.find(b"-----END ", start, end) >= 0
            )
        return True

    @staticmethod
    def _advance_scanner_cursor(
        ctx: _ScanContext, state: _FlowState, scanner_name: str
    ) -> None:
        assert ctx.base_offset is not None
        key = (ctx.direction, scanner_name)
        absolute_end = ctx.base_offset + len(ctx.data)
        state.scan_cursors[key] = max(state.scan_cursors.get(key, ctx.base_offset), absolute_end)

    @staticmethod
    def _terminated_text_data(ctx: _ScanContext) -> bytes | bytearray:
        """Treat only a datagram boundary as an implicit text terminator."""

        if ctx.is_datagram and ctx.data and not ctx.data.endswith((b"\n", b"\r")):
            return bytes(ctx.data) + b"\n"
        return ctx.data

    @staticmethod
    def _has_observed_match_boundary(
        ctx: _ScanContext, data: bytes | bytearray, match_end: int
    ) -> bool:
        # For streams, end-of-current-buffer is not protocol evidence.  A
        # later segment can extend the same token and must produce one final
        # attempt, not a partial attempt plus a full attempt.
        return ctx.is_datagram or match_end < len(data)

    @staticmethod
    def _scanner_window(
        ctx: _ScanContext,
        state: _FlowState,
        scanner_name: str,
        overlap: int,
    ) -> _ScanContext:
        """Return only new bytes plus a detector-specific boundary window.

        A 128 KiB reassembly tail may be necessary for binary messages, but
        rescanning that entire tail with every regex on every TCP segment is
        needlessly quadratic.  Per-scanner cursors retain just enough lookback
        for a match that began in the previous call.
        """

        assert ctx.base_offset is not None
        key = (ctx.direction, scanner_name)
        absolute_end = ctx.base_offset + len(ctx.data)
        cursor = state.scan_cursors.get(key, ctx.base_offset)
        wanted_start = max(ctx.base_offset, cursor - overlap)
        relative_start = wanted_start - ctx.base_offset
        state.scan_cursors[key] = max(cursor, absolute_end)
        if relative_start <= 0:
            return ctx
        return _ScanContext(
            flow=ctx.flow,
            flow_id=ctx.flow_id,
            connection_epoch=ctx.connection_epoch,
            direction=ctx.direction,
            base_offset=wanted_start,
            data=ctx.data[relative_start:],
            packet_ids=ctx.packet_ids,
            provenance_spans=ctx.provenance_spans,
            packet_ids_complete=ctx.packet_ids_complete,
            observed_timestamp_ns=ctx.observed_timestamp_ns,
            completeness=ctx.completeness,
            is_datagram=ctx.is_datagram,
        )

    def _limit_provenance_ids(
        self,
        packet_ids: Iterable[int],
        complete: bool,
        *,
        limit: int | None = None,
        pending: bool = False,
    ) -> tuple[tuple[int, ...], bool]:
        bounded_limit = self.max_packet_ids_per_finding if limit is None else limit
        unique = tuple(dict.fromkeys(packet_ids))
        if len(unique) > bounded_limit:
            unique = unique[:bounded_limit]
            complete = False
            self._stats[
                "provenance_pending_ids_truncated"
                if pending
                else "provenance_packet_ids_truncated"
            ] += 1
        if not unique:
            complete = False
        return unique, complete

    def _provenance_for_span(
        self,
        ctx: _ScanContext,
        start: int,
        end: int,
        *,
        limit: int | None = None,
        pending: bool = False,
    ) -> tuple[tuple[int, ...], bool]:
        if end <= start:
            return self._limit_provenance_ids(
                ctx.packet_ids,
                False,
                limit=limit,
                pending=pending,
            )
        absolute_start = start if ctx.base_offset is None else ctx.base_offset + start
        absolute_end = end if ctx.base_offset is None else ctx.base_offset + end
        cursor = absolute_start
        packet_ids: list[int] = []
        complete = ctx.packet_ids_complete
        for span in ctx.provenance_spans:
            if span.stream_end <= absolute_start:
                continue
            if span.stream_start >= absolute_end:
                break
            if span.stream_start > cursor:
                complete = False
            intersection_start = max(absolute_start, span.stream_start)
            intersection_end = min(absolute_end, span.stream_end)
            if intersection_end <= intersection_start:
                continue
            packet_ids.extend(span.packet_ids)
            complete = complete and span.packet_ids_complete
            cursor = max(cursor, intersection_end)
        if cursor < absolute_end:
            complete = False
        return self._limit_provenance_ids(
            packet_ids,
            complete,
            limit=limit,
            pending=pending,
        )

    def _combine_provenance(
        self,
        *values: tuple[Iterable[int], bool],
        limit: int | None = None,
        pending: bool = False,
    ) -> tuple[tuple[int, ...], bool]:
        packet_ids: list[int] = []
        complete = True
        for ids, value_complete in values:
            packet_ids.extend(ids)
            complete = complete and value_complete
        return self._limit_provenance_ids(
            packet_ids,
            complete,
            limit=limit,
            pending=pending,
        )

    @staticmethod
    def _position_marker(ctx: _ScanContext, end: int) -> tuple[int, int]:
        if ctx.base_offset is None:
            return (max(ctx.packet_ids, default=0), end)
        return (0, ctx.base_offset + end)

    def _emit(
        self,
        ctx: _ScanContext,
        state: _FlowState,
        *,
        detector: str,
        start: int,
        end: int,
        category: str,
        protocol: str,
        material_type: str,
        material: Any,
        confidence: str = "confirmed",
        completeness: str | None = None,
        fields: dict[str, Any] | None = None,
        limitations: list[str] | None = None,
        identity_suffix: tuple[Any, ...] = (),
        emission_scope: tuple[Any, ...] = (),
        packet_ids_override: Iterable[int] | None = None,
        packet_ids_complete_override: bool | None = None,
    ) -> Finding | None:
        del identity_suffix  # high-water scope intentionally ignores value identity
        scope = (detector, ctx.direction, *emission_scope)
        marker = self._position_marker(ctx, end)
        if not self._set_highwater(
            ctx, state, state.emitted_highwater, scope, marker
        ):
            return None
        state.attempts[material_type] += 1
        stream_offset = None if ctx.base_offset is None else ctx.base_offset + start
        if packet_ids_override is None:
            packet_ids, packet_ids_complete = self._provenance_for_span(
                ctx, start, end
            )
        else:
            packet_ids, packet_ids_complete = self._limit_provenance_ids(
                packet_ids_override,
                bool(packet_ids_complete_override),
            )
        finding_limitations = list(limitations or [])
        if not packet_ids_complete:
            self._stats["provenance_incomplete_findings"] += 1
            finding_limitations.append(
                "Captured-packet provenance is bounded or incomplete for this finding."
            )
        return Finding(
            event_id=uuid4().hex,
            session_id=self.session_id,
            observed_timestamp_ns=ctx.observed_timestamp_ns,
            emitted_timestamp_ns=time.time_ns(),
            category=category,
            protocol=protocol,
            detector=detector,
            material_type=material_type,
            material=material,
            confidence=confidence,  # type: ignore[arg-type]
            completeness=(completeness or ctx.completeness),  # type: ignore[arg-type]
            flow_id=ctx.flow_id,
            direction=ctx.direction,
            packet_ids=packet_ids,
            stream_offset=stream_offset,
            attempt_ordinal=state.attempts[material_type],
            fields=fields or {},
            limitations=finding_limitations,
            connection_epoch=ctx.connection_epoch,
            packet_ids_complete=packet_ids_complete,
        )

    def _state_once(
        self, ctx: _ScanContext, state: _FlowState, name: str, start: int, end: int
    ) -> bool:
        del start
        scope = (name, ctx.direction)
        return self._set_highwater(
            ctx,
            state,
            state.state_highwater,
            scope,
            self._position_marker(ctx, end),
        )

    # -- NTLM -------------------------------------------------------------

    @staticmethod
    def _security_buffer(blob: bytes, position: int) -> bytes | None:
        if position + 8 > len(blob):
            return None
        length = int.from_bytes(blob[position : position + 2], "little")
        offset = int.from_bytes(blob[position + 4 : position + 8], "little")
        if length > 65535 or offset > len(blob) or offset + length > len(blob):
            return None
        return blob[offset : offset + length]

    def _decode_ntlm(self, blob: bytes) -> tuple[int, dict[str, Any], int] | None:
        if len(blob) < 12 or blob[:8] != b"NTLMSSP\x00":
            return None
        message_type = int.from_bytes(blob[8:12], "little")
        if message_type == 2:
            if len(blob) < 32:
                return None
            challenge = blob[24:32]
            ends = [32]
            for position in (12, 40):
                if position + 8 <= len(blob):
                    length = int.from_bytes(blob[position : position + 2], "little")
                    offset = int.from_bytes(blob[position + 4 : position + 8], "little")
                    if length <= 65535 and offset <= len(blob) and offset + length <= len(blob):
                        ends.append(offset + length)
            return 2, {"challenge": challenge}, max(ends)
        if message_type != 3 or len(blob) < 52:
            return None
        lm_response = self._security_buffer(blob, 12)
        nt_response = self._security_buffer(blob, 20)
        domain_raw = self._security_buffer(blob, 28)
        user_raw = self._security_buffer(blob, 36)
        workstation_raw = self._security_buffer(blob, 44)
        if None in (lm_response, nt_response, domain_raw, user_raw, workstation_raw):
            return None
        flags = int.from_bytes(blob[60:64], "little") if len(blob) >= 64 else 1
        unicode_hint = bool(flags & 1)
        ends = [52]
        for position in (12, 20, 28, 36, 44, 52):
            if position + 8 <= len(blob):
                length = int.from_bytes(blob[position : position + 2], "little")
                offset = int.from_bytes(blob[position + 4 : position + 8], "little")
                if offset + length <= len(blob):
                    ends.append(offset + length)
        return (
            3,
            {
                "lm_response": lm_response,
                "nt_response": nt_response,
                "domain": _safe_text(domain_raw or b"", unicode_hint=unicode_hint),
                "username": _safe_text(user_raw or b"", unicode_hint=unicode_hint),
                "workstation": _safe_text(workstation_raw or b"", unicode_hint=unicode_hint),
            },
            max(ends),
        )

    def _handle_ntlm_blob(
        self,
        ctx: _ScanContext,
        state: _FlowState,
        blob: bytes,
        start: int,
        end: int,
        *,
        detector: str,
        encoded_value: str | None = None,
        smb_session: int | None = None,
        correlation_allowed: bool = True,
    ) -> list[Finding]:
        decoded = self._decode_ntlm(blob)
        if decoded is None:
            return []
        message_type, values, message_end = decoded
        absolute = (ctx.base_offset or 0) + start
        raw = blob[:message_end]
        blob_packet_ids, blob_packet_ids_complete = self._provenance_for_span(
            ctx, start, end
        )
        findings: list[Finding] = []
        material: dict[str, Any] = {
            "message_type": message_type,
            "raw_hex": raw.hex(),
        }
        if encoded_value is not None:
            material["encoded"] = encoded_value

        zero_session_ambiguous = smb_session == 0 and state.ntlm_zero_session_ambiguous

        if message_type == 2:
            challenge: bytes = values["challenge"]
            material["challenge_hex"] = challenge.hex()
            finding = self._emit(
                ctx,
                state,
                detector=detector,
                start=start,
                end=end,
                category="authentication",
                protocol="ntlm",
                material_type="ntlm_type2_challenge",
                material=material,
                fields={"hashcat_mode": None},
                identity_suffix=(2,),
            )
            if finding:
                findings.append(finding)
                if not correlation_allowed:
                    if zero_session_ambiguous:
                        finding.limitations.append("Multiple zero-ID SMB2 challenges make correlation ambiguous.")
                        self._stats["coverage_ntlm_zero_session_ambiguous"] += 1
                    else:
                        finding.limitations.append("SMB2 session framing is unavailable; challenge was not correlated.")
                        self._stats["coverage_ntlm_session_unavailable"] += 1
            if not correlation_allowed:
                return findings
            key = (ctx.direction, smb_session) if smb_session is not None else ctx.direction
            existing = state.ntlm_challenges.get(key)
            if existing is None or absolute > existing.offset:
                self._retain_ntlm_challenge(
                    ctx.flow_id,
                    state,
                    _NtlmChallenge(
                        direction=ctx.direction,
                        offset=absolute,
                        timestamp_ns=ctx.observed_timestamp_ns,
                        challenge=challenge,
                        packet_ids=blob_packet_ids,
                        packet_ids_complete=blob_packet_ids_complete,
                        smb_session=smb_session,
                    ),
                )
            findings.extend(self._correlate_pending_ntlm(ctx, state))
            return findings

        response = _NtlmResponse(
            direction=ctx.direction,
            offset=absolute,
            timestamp_ns=ctx.observed_timestamp_ns,
            username=values["username"],
            domain=values["domain"],
            workstation=values["workstation"],
            lm_response=values["lm_response"],
            nt_response=values["nt_response"],
            packet_ids=blob_packet_ids,
            packet_ids_complete=blob_packet_ids_complete,
            smb_session=smb_session,
        )
        material.update(
            {
                "username": response.username,
                "domain": response.domain,
                "workstation": response.workstation,
                "lm_response_hex": response.lm_response.hex(),
                "nt_response_hex": response.nt_response.hex(),
            }
        )
        finding = self._emit(
            ctx,
            state,
            detector=detector,
            start=start,
            end=end,
            category="credential",
            protocol="ntlm",
            material_type="ntlm_type3_response",
            material=material,
            confidence="confirmed",
            limitations=["Type 3 is an authentication response, not a plaintext password or reusable NT hash."],
            identity_suffix=(3,),
        )
        if finding:
            findings.append(finding)
            if not correlation_allowed:
                if zero_session_ambiguous:
                    finding.limitations.append("Multiple zero-ID SMB2 challenges make correlation ambiguous.")
                    self._stats["coverage_ntlm_zero_session_ambiguous"] += 1
                else:
                    finding.limitations.append("SMB2 session framing is unavailable; response was not correlated.")
                    self._stats["coverage_ntlm_session_unavailable"] += 1
        if not correlation_allowed:
            return findings
        has_challenge = any(
            challenge.direction != response.direction
            and challenge.timestamp_ns <= response.timestamp_ns
            and challenge.smb_session == response.smb_session
            for challenge in state.ntlm_challenges.values()
        )
        if has_challenge:
            findings.extend(self._correlate_ntlm(ctx, state, response))
        elif not any(
            queued.direction == response.direction
            and queued.offset == response.offset
            for queued in state.ntlm_responses.values()
        ):
            self._retain_ntlm_response(ctx.flow_id, state, response)
        return findings

    def _correlate_pending_ntlm(self, ctx: _ScanContext, state: _FlowState) -> list[Finding]:
        findings: list[Finding] = []
        for response in tuple(state.ntlm_responses.values()):
            findings.extend(self._correlate_ntlm(ctx, state, response))
        return findings

    def _correlate_ntlm(
        self, ctx: _ScanContext, state: _FlowState, response: _NtlmResponse
    ) -> list[Finding]:
        candidates = [
            challenge
            for challenge in state.ntlm_challenges.values()
            if challenge.direction != response.direction
            and challenge.timestamp_ns <= response.timestamp_ns
            and challenge.smb_session == response.smb_session
        ]
        if not candidates:
            return []
        challenge = max(candidates, key=lambda value: (value.timestamp_ns, value.offset))
        pair = (challenge.direction, challenge.offset, response.direction, response.offset)
        response_scope = (response.direction, response.smb_session) if response.smb_session is not None else response.direction
        previous_response_offset = state.ntlm_pair_highwater.get(response_scope)
        if (
            previous_response_offset is not None
            and response.offset <= previous_response_offset
        ):
            return []
        user = response.username
        domain = response.domain
        nt = response.nt_response
        if len(nt) >= 48 and nt[16:20] == b"\x01\x01\x00\x00":
            proof, blob = nt[:16], nt[16:]
            hashcat = f"{user}::{domain}:{challenge.challenge.hex()}:{proof.hex()}:{blob.hex()}"
            mode = 5600
            material_type = "netntlmv2"
        elif len(nt) == 24 and len(response.lm_response) == 24:
            hashcat = (
                f"{user}::{domain}:{response.lm_response.hex()}:"
                f"{nt.hex()}:{challenge.challenge.hex()}"
            )
            mode = 5500
            material_type = "netntlmv1"
        else:
            if response.correlation_id:
                self._remove_ntlm_entry(ctx.flow_id, state, "response", response.correlation_id)
            self._stats["coverage_ntlm_response_format_unsupported"] += 1
            return []

        # Once a queued Type 3 has a usable challenge it is no longer
        # unmatched.  Remove the large response object before allocating
        # finding metadata; the fixed latest challenge context remains
        # available so later-offset retries still correlate and emit.
        if response.correlation_id:
            self._remove_ntlm_entry(
                ctx.flow_id,
                state,
                "response",
                response.correlation_id,
            )

        if previous_response_offset is None:
            if not self._reserve_metadata_entry(ctx.flow_id):
                return []
        state.ntlm_pair_highwater[response_scope] = response.offset

        # Type 2 can finish reassembly after Type 3. The observation belongs to
        # the client's response, not the packet that triggered correlation.
        response_ctx = replace(ctx, direction=response.direction,
                               base_offset=response.offset,
                               observed_timestamp_ns=response.timestamp_ns)
        pair_packet_ids, pair_packet_ids_complete = self._combine_provenance(
            (challenge.packet_ids, challenge.packet_ids_complete),
            (response.packet_ids, response.packet_ids_complete),
        )
        finding = self._emit(
            response_ctx,
            state,
            detector="ntlm_challenge_response_correlation",
            start=0,
            end=1,
            category="credential",
            protocol="ntlm",
            material_type=material_type,
            material={
                "hashcat": hashcat,
                "hashcat_mode": mode,
                "smb_session_id": response.smb_session,
                "username": user,
                "domain": domain,
                "workstation": response.workstation,
                "challenge_hex": challenge.challenge.hex(),
                "lm_response_hex": response.lm_response.hex(),
                "nt_response_hex": nt.hex(),
            },
            confidence="high" if response.smb_session == 0 else "confirmed",
            fields={
                "challenge_stream_offset": challenge.offset,
                "response_stream_offset": response.offset,
                "hashcat_mode": mode,
            },
            limitations=[
                "Challenge-response material does not demonstrate authentication success.",
                "This is not a plaintext password or a reusable NT hash.",
                *(["SMB2 SessionId is zero; association uses the sole unresolved challenge in this TCP connection."]
                  if response.smb_session == 0 else []),
            ],
            identity_suffix=pair,
            emission_scope=(response.smb_session,),
            packet_ids_override=pair_packet_ids,
            packet_ids_complete_override=pair_packet_ids_complete,
        )
        if finding is not None and response.smb_session == 0:
            state.ntlm_zero_session_last_type3_ns = max(
                state.ntlm_zero_session_last_type3_ns, response.timestamp_ns
            )
        return [finding] if finding else []

    def _scan_ntlm_raw(self, ctx: _ScanContext, state: _FlowState) -> list[Finding]:
        findings: list[Finding] = []
        pending = False
        for match in _NTLM_SIGNATURE_RE.finditer(ctx.data):
            decoded = self._decode_ntlm(ctx.data[match.start() :])
            if decoded is None:
                pending = True
                continue
            _kind, _values, length = decoded
            retained = state.directions.get(ctx.direction)
            smb_session = None
            if retained is not None and ctx.base_offset is not None:
                if not state.smb2_seen and _ports(ctx.flow) & {139, 445} and smb2_header_seen(retained.data):
                    state.smb2_seen = True
                position = ctx.base_offset + match.start() - retained.base_offset
                if 0 <= position < len(retained.data):
                    smb_session = smb2_session_for_token(retained.data, position, length)
            if smb_session == 0 and _kind == 2:
                prior = state.ntlm_challenges.get((ctx.direction, 0))
                if (
                    prior is not None
                    and prior.challenge != _values["challenge"]
                    and (
                        prior.timestamp_ns >= state.ntlm_zero_session_last_type3_ns
                        or ctx.observed_timestamp_ns <= state.ntlm_zero_session_last_type3_ns
                    )
                ):
                    state.ntlm_zero_session_ambiguous = True
            findings.extend(
                self._handle_ntlm_blob(
                    ctx,
                    state,
                    ctx.data[match.start() : match.start() + length],
                    match.start(),
                    match.start() + length,
                    detector="raw_ntlmssp",
                    smb_session=smb_session,
                    correlation_allowed=(not state.smb2_seen or smb_session is not None)
                    and not (smb_session == 0 and state.ntlm_zero_session_ambiguous),
                )
            )
        state.ntlm_pending[ctx.direction] = pending
        return findings

    # -- HTTP and SIP -----------------------------------------------------

    def _scan_ntlm_encoded(self, ctx: _ScanContext, state: _FlowState) -> list[Finding]:
        """SASL-style NTLM tokens in SMTP/POP3/IMAP authentication lines."""
        if not (_ports(ctx.flow) & {25, 110, 143, 587}):
            return []
        findings: list[Finding] = []
        # Only complete bounded line-ending tokens; decode then validate the
        # raw NTLM or explicit SPNEGO shape. Ordinary base64 is not a finding.
        for match in re.finditer(rb"(?:^|[ \t])([A-Za-z0-9+/]{16,16384}={0,2})[ \t]*\r?$", ctx.data, re.M):
            if match.end() >= len(ctx.data) or ctx.data[match.end():match.end() + 1] != b"\n":
                continue
            decoded = _b64decode(match.group(1), max_output=16384)
            token = unwrap_ntlm(decoded) if decoded is not None else None
            if token is None:
                continue
            findings.extend(self._handle_ntlm_blob(
                ctx, state, token, match.start(1), match.end(1),
                detector="mail_ntlm", encoded_value=match.group(1).decode("ascii"),
            ))
        return findings

    def _scan_http_message(
        self, ctx: _ScanContext, state: _FlowState, message: HTTPMessage
    ) -> list[Finding]:
        findings: list[Finding] = []
        message_ctx = replace(
            ctx,
            base_offset=ctx.base_offset + message.start,
            data=bytes(ctx.data[message.start:message.start + message.end]),
        )
        findings.extend(self._scan_http(replace(message_ctx, data=message_ctx.data[:message.header_end]), state))
        collections = []
        if b"?" in message.target:
            query_start = message.target.index(b"?") + 1
            query = message.target[query_start:]
            collections.append((form_fields(query), "query", message.target_start + query_start, False))
        if message.encoded_content:
            self._stats["http_body_unsupported_content_encoding"] += 1
        elif message.content_type == "application/x-www-form-urlencoded":
            collections.append((form_fields(message.body, complete=message.complete), "form", 0, True))
        elif message.content_type == "application/json" or message.content_type.endswith("+json"):
            if message.complete:
                try:
                    collections.append((json_fields(message.body), "json", 0, True))
                except (ValueError, UnicodeError, RecursionError):
                    self._stats["http_body_invalid_json"] += 1
        elif message.body:
            self._stats["http_body_unsupported_content_type"] += 1
        for fields, source, offset, body_field in collections:
            if len(fields) >= 256:
                self._stats["http_body_field_limit"] += 1
            classified = [(value, field_role(value.name, self.sensitive_fields)) for value in fields]
            usernames = [value for value, role in classified if role == "username"]
            if not usernames:
                usernames = [value for value, role in classified if role == "username_weak"]
            for value, role in classified:
                if role != "sensitive":
                    continue
                start, end = message.wire_span(value.start, value.end) if body_field else (offset + value.start, offset + value.end)
                material = {"name": value.name, "encoded_value": value.encoded, "value": value.value, "source": source}
                context_fields: dict[str, Any] = {"http_body_complete": message.complete, "http_content_type": message.content_type}
                packet_ids_override = None
                packet_ids_complete_override = None
                if len(usernames) == 1:
                    companion = usernames[0]
                    material["username"] = companion.value
                    material["username_field"] = companion.name
                    user_start, user_end = message.wire_span(companion.start, companion.end) if body_field else (offset + companion.start, offset + companion.end)
                    packet_ids_override, packet_ids_complete_override = self._combine_provenance(
                        self._provenance_for_span(message_ctx, start, end),
                        self._provenance_for_span(message_ctx, user_start, user_end),
                    )
                    context_fields["username_stream_offset"] = message_ctx.base_offset + user_start
                elif len(usernames) > 1:
                    context_fields["username_context"] = "multiple username fields; association not inferred"
                finding = self._emit(
                    message_ctx, state, detector="sensitive_field", start=start, end=end,
                    category="credential", protocol="http", material_type="sensitive_field",
                    material=material, confidence="high", fields=context_fields,
                    packet_ids_override=packet_ids_override,
                    packet_ids_complete_override=packet_ids_complete_override,
                    limitations=["Field name indicates sensitivity; this request does not establish authentication success."] + (["Companion username is contextual data from the same query/body; the application relationship was not validated."] if usernames else []) + ([] if message.complete else ["HTTP body has no declared length; only delimiter-terminated values were interpreted."]),
                )
                if finding:
                    findings.append(finding)
        # A verified HTTP message boundary is a legitimate text terminator.
        # The sentinel is not part of a match or its packet provenance.
        generic_data = message_ctx.data[:message.header_end] if message.encoded_content else message_ctx.data
        generic_ctx = replace(message_ctx, data=bytes(generic_data) + (b"\n" if message.complete else b""))
        # A framed HTTP body can contain form fields such as
        # "username=...&password=...".  Those are HTTP fields, not a Telnet,
        # FTP, POP3, SMTP, or IMAP exchange even when the line resembles one.
        # Keep the protocol-specific HTTP parser and generic secret scan below.
        if not message.encoded_content and message.content_type not in {
            "application/x-www-form-urlencoded", "application/json"
        } and not message.content_type.endswith("+json"):
            for match in _HTTP_TEXT_FIELD_RE.finditer(
                message.body + (b"\n" if message.complete else b"")
            ):
                value = match.group(2).rstrip(b" \t")
                if not value:
                    continue
                start, end = message.wire_span(match.start(2), match.start(2) + len(value))
                label = match.group(1).decode("ascii")
                finding = self._emit(
                    message_ctx, state, detector="http_text_login_field",
                    start=start, end=end,
                    category="credential" if label.lower() in {"password", "passwd", "passcode"} else "identity",
                    protocol="http", material_type="http_text_login_field",
                    material={"field": label, "value": value.decode("latin-1"), "source": "text_body"},
                    confidence="medium",
                    limitations=["Credential-like line in an HTTP body; application use and authentication success were not established."],
                )
                if finding:
                    findings.append(finding)
        if self.generic_secret_scan:
            findings.extend(self._scan_generic_secrets(generic_ctx, state))
            findings.extend(self._scan_pem_private_keys(generic_ctx, state))
        if self.credit_card_scan:
            findings.extend(self._scan_cards(generic_ctx, state))
        return findings

    def _scan_http(self, ctx: _ScanContext, state: _FlowState) -> list[Finding]:
        data = self._terminated_text_data(ctx)
        findings: list[Finding] = []
        for match in _HTTP_BASIC_RE.finditer(data):
            decoded = _b64decode(match.group(2), max_output=65536)
            if decoded is None or b":" not in decoded:
                continue
            username, password = decoded.split(b":", 1)
            finding = self._emit(
                ctx,
                state,
                detector="http_basic",
                start=match.start(2),
                end=match.end(2),
                category="credential",
                protocol="http",
                material_type="http_basic_credentials",
                material={
                    "header": match.group(1).decode("ascii"),
                    "encoded": match.group(2).decode("ascii"),
                    "username": _safe_text(username),
                    "password": _safe_text(password),
                },
                confidence="confirmed",
            )
            if finding:
                findings.append(finding)

        for match in _HTTP_BEARER_RE.finditer(data):
            finding = self._emit(
                ctx,
                state,
                detector="http_bearer",
                start=match.start(2),
                end=match.end(2),
                category="credential",
                protocol="http",
                material_type="bearer_token",
                material=match.group(2).decode("latin-1"),
                confidence="confirmed",
            )
            if finding:
                findings.append(finding)

        is_sip = b"SIP/2.0" in data[:65536]
        for match in (() if is_sip else _HTTP_DIGEST_RE.finditer(data)):
            params = _parse_auth_params(match.group(2))
            if not {"username", "realm", "nonce", "uri", "response"} <= params.keys():
                continue
            finding = self._emit(
                ctx,
                state,
                detector="http_digest",
                start=match.start(2),
                end=match.end(2),
                category="credential",
                protocol="http",
                material_type="http_digest_response",
                material={"raw": match.group(2).decode("latin-1"), "parameters": params},
                confidence="confirmed",
                limitations=["Digest response does not demonstrate authentication success."],
            )
            if finding:
                findings.append(finding)

        for match in _HTTP_NTLM_RE.finditer(data):
            decoded = _b64decode(match.group(2))
            decoded = unwrap_ntlm(decoded) if decoded is not None else None
            if decoded is None:
                continue
            findings.extend(
                self._handle_ntlm_blob(
                    ctx,
                    state,
                    decoded,
                    match.start(2),
                    match.end(2),
                    detector="http_ntlm",
                    encoded_value=match.group(2).decode("ascii"),
                )
            )

        for match in _COOKIE_RE.finditer(data):
            raw = match.group(2).decode("latin-1")
            pairs: list[dict[str, str]] = []
            for part in raw.split(";"):
                if "=" in part:
                    key, value = part.split("=", 1)
                    pairs.append({"name": key.strip(), "value": value.strip()})
            finding = self._emit(
                ctx,
                state,
                detector="http_cookie",
                start=match.start(2),
                end=match.end(2),
                category="session",
                protocol="http",
                material_type="set_cookie" if match.group(1).lower().startswith(b"set") else "cookie",
                material={"raw": raw, "pairs": pairs},
                confidence="high",
                limitations=["Cookie sensitivity depends on application semantics."],
            )
            if finding:
                findings.append(finding)

        # One stream-ordered pass is important: query and body fields can be
        # interleaved across pipelined requests. Emitting all query matches in
        # a separate pass first would advance the detector high-water beyond
        # a body field that appears between two request lines.
        framer = state.http_framers.get(ctx.direction)
        if framer is None or not framer.recognized:
            # A bare name=value line occurs in many plaintext protocols. Keep
            # the candidate, but claim HTTP only when a start line is visible.
            http_start_seen = _HTTP_START_LINE_RE.search(data) is not None
            findings.extend(self._emit_sensitive_fields(
                ctx, state, data, 0,
                source="url_or_form" if http_start_seen else "unframed_name_value",
                protocol="http" if http_start_seen else "generic",
            ))

        if 5060 in _ports(ctx.flow) or b"SIP/2.0" in data[:65536]:
            findings.extend(self._scan_sip_digest(ctx, state))
        last_lf = ctx.data.rfind(b"\n")
        trailing = ctx.data[last_lf + 1 :]
        state.http_pending[ctx.direction] = (not ctx.is_datagram) and bool(trailing) and (
            _HTTP_GATE_RE.search(trailing) is not None
        )
        return findings

    def _emit_sensitive_fields(
        self,
        ctx: _ScanContext,
        state: _FlowState,
        data: bytes,
        data_offset: int,
        *,
        source: str,
        protocol: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for match in _FORM_FIELD_RE.finditer(data):
            name = match.group(1).decode("ascii", "ignore")
            if name.lower() not in self.sensitive_fields:
                continue
            encoded = match.group(2).decode("latin-1")
            try:
                decoded = unquote_plus(encoded)
            except ValueError:
                decoded = encoded
            finding = self._emit(
                ctx,
                state,
                detector="sensitive_field",
                start=data_offset + match.start(2),
                end=data_offset + match.end(2),
                category="credential",
                protocol=protocol,
                material_type="sensitive_field",
                material={"name": name, "encoded_value": encoded, "value": decoded, "source": source},
                confidence="high" if protocol == "http" else "medium",
                limitations=["Field name indicates sensitivity; application semantics were not validated."] +
                    ([] if protocol == "http" else ["No HTTP start line was observed; protocol is unknown."]),
                identity_suffix=(name.lower(),),
            )
            if finding:
                findings.append(finding)
        return findings

    def _scan_sip_digest(self, ctx: _ScanContext, state: _FlowState) -> list[Finding]:
        findings: list[Finding] = []
        data = self._terminated_text_data(ctx)
        request = re.search(rb"(?im)^([A-Z]{3,16})\s+([^\s]+)\s+SIP/2\.0[ \t]*\r?\n", data)
        method = request.group(1).decode("ascii") if request else ""
        for match in re.finditer(
            rb"(?im)^(?:Proxy-)?Authorization\s*:\s*Digest\s+([^\r\n]+)\r?\n",
            data,
        ):
            params = _parse_auth_params(match.group(1))
            if not {"username", "realm", "nonce", "uri", "response"} <= params.keys():
                continue
            uri = params["uri"]
            parts = uri.split(":", 2)
            prefix = parts[0] if len(parts) > 1 else ""
            resource = parts[1] if len(parts) > 1 else parts[0]
            suffix = parts[2] if len(parts) > 2 else ""
            algorithm = params.get("algorithm", "MD5").upper()
            hashcat = None
            if algorithm == "MD5" and len(params["response"]) == 32:
                fields = [
                    "", "", params["username"], params["realm"], method,
                    prefix, resource, suffix, params["nonce"], params.get("cnonce", ""),
                    params.get("nc", ""), params.get("qop", ""), "MD5", params["response"],
                ]
                hashcat = "$sip$*" + "*".join(fields)
            finding = self._emit(
                ctx,
                state,
                detector="sip_digest",
                start=match.start(1),
                end=match.end(1),
                category="credential",
                protocol="sip",
                material_type="sip_digest_response",
                material={"parameters": params, "method": method, "hashcat": hashcat, "hashcat_mode": 11400 if hashcat else None},
                confidence="confirmed",
                fields={"hashcat_mode": 11400 if hashcat else None},
                limitations=["Digest response does not demonstrate authentication success."],
            )
            if finding:
                findings.append(finding)
        return findings

    # -- plaintext line protocols ---------------------------------------

    def _scan_line_protocols(self, ctx: _ScanContext, state: _FlowState) -> list[Finding]:
        findings: list[Finding] = []
        ports = _ports(ctx.flow)
        data = self._terminated_text_data(ctx)
        is_irc = bool(ports & set(range(6660, 7001))) or bool(
            re.search(rb"(?im)^(?:NICK|PRIVMSG|JOIN|CAP)\s+", data)
        )
        for match in _COMPLETE_LINE_RE.finditer(data):
            raw = match.group(1)
            stripped = raw.strip()
            if not stripped:
                continue
            line = stripped.decode("latin-1")
            upper = stripped.upper()
            start, end = match.start(1), match.end(1)

            # FTP/POP3 share USER/PASS.  Port context determines the label;
            # unknown ports retain a truthful combined protocol label.
            command_match = re.match(rb"(?i)^(USER|PASS)\s+(.{1,4096})$", stripped)
            if command_match and (not is_irc or bool(ports & {21, 110, 995})):
                command = command_match.group(1).decode("ascii").upper()
                value = command_match.group(2).decode("latin-1")
                protocol = "ftp" if 21 in ports else "pop3" if 110 in ports or 995 in ports else "ftp_or_pop3"
                packet_ids_override: tuple[int, ...] | None = None
                packet_ids_complete_override: bool | None = None
                if command == "USER":
                    state.pending_auth_loss.discard(
                        (f"plaintext:{protocol}", ctx.direction)
                    )
                    user_packet_ids, user_packet_ids_complete = self._provenance_for_span(
                        ctx,
                        start,
                        end,
                        limit=_MAX_PENDING_PROVENANCE_IDS,
                        pending=True,
                    )
                    state.plaintext_users[(protocol, ctx.direction)] = {
                        "value": value,
                        "packet_ids": user_packet_ids,
                        "packet_ids_complete": user_packet_ids_complete,
                    }
                    material_type = f"{protocol}_username"
                    material: Any = value
                else:
                    prior_user = state.plaintext_users.get((protocol, ctx.direction))
                    material_type = f"{protocol}_credentials"
                    material = {
                        "username": prior_user.get("value") if prior_user else None,
                        "password": value,
                    }
                    if prior_user is not None:
                        password_packet_ids, password_complete = self._provenance_for_span(
                            ctx, start, end
                        )
                        (
                            packet_ids_override,
                            packet_ids_complete_override,
                        ) = self._combine_provenance(
                            (
                                prior_user.get("packet_ids", ()),
                                bool(prior_user.get("packet_ids_complete", False)),
                            ),
                            (password_packet_ids, password_complete),
                        )
                    elif (
                        f"plaintext:{protocol}", ctx.direction
                    ) in state.pending_auth_loss:
                        (
                            packet_ids_override,
                            _current_complete,
                        ) = self._provenance_for_span(ctx, start, end)
                        packet_ids_complete_override = False
                finding = self._emit(
                    ctx,
                    state,
                    detector=f"{protocol}_user_pass",
                    start=start,
                    end=end,
                    category="credential",
                    protocol=protocol,
                    material_type=material_type,
                    material=material,
                    confidence="confirmed" if protocol != "ftp_or_pop3" else "medium",
                    limitations=[] if protocol != "ftp_or_pop3" else ["Protocol inferred from command syntax without a standard port."],
                    packet_ids_override=packet_ids_override,
                    packet_ids_complete_override=packet_ids_complete_override,
                )
                if finding:
                    findings.append(finding)

            findings.extend(self._scan_smtp_line(ctx, state, stripped, start, end, ports))
            findings.extend(self._scan_imap_line(ctx, state, stripped, start, end, ports))

            irc = re.match(rb"(?i)^(PASS|USER|NICK)\s+(:?.{1,4096})$", stripped)
            if irc and is_irc:
                command = irc.group(1).decode("ascii").upper()
                finding = self._emit(
                    ctx,
                    state,
                    detector="irc_registration",
                    start=start,
                    end=end,
                    category="credential" if command == "PASS" else "identity",
                    protocol="irc",
                    material_type=f"irc_{command.lower()}",
                    material={"command": command, "value": irc.group(2).decode("latin-1")},
                    confidence="confirmed" if ports & set(range(6660, 7001)) else "medium",
                )
                if finding:
                    findings.append(finding)

            telnet = re.match(
                rb"(?i)^(?:login|logon|username|user(?:name)?|password|passwd|passcode)\s*[:=]\s*(.{1,4096})$",
                stripped,
            )
            if telnet:
                label = stripped.split(b":", 1)[0].split(b"=", 1)[0].strip().decode("latin-1")
                finding = self._emit(
                    ctx,
                    state,
                    detector="telnet_like_login",
                    start=start,
                    end=end,
                    category="credential",
                    protocol="telnet" if 23 in ports or 2323 in ports else "plaintext_terminal",
                    material_type="telnet_like_login_field",
                    material={"field": label, "value": telnet.group(1).decode("latin-1"), "raw": line},
                    confidence="high" if 23 in ports or 2323 in ports else "medium",
                    limitations=["Line syntax is credential-like; no authentication success was established."],
                )
                if finding:
                    findings.append(finding)
        last_lf = ctx.data.rfind(b"\n")
        trailing = ctx.data[last_lf + 1 :]
        state.line_pending[ctx.direction] = (not ctx.is_datagram) and bool(trailing) and (
            _LINE_GATE_RE.search(trailing) is not None
        )
        return findings

    def _scan_smtp_line(
        self,
        ctx: _ScanContext,
        state: _FlowState,
        line: bytes,
        start: int,
        end: int,
        ports: set[int],
    ) -> list[Finding]:
        findings: list[Finding] = []
        match = re.match(rb"(?i)^AUTH\s+(PLAIN|LOGIN)(?:\s+([^\s]+))?$", line)
        if match and self._state_once(ctx, state, "smtp_auth", start, end):
            state.pending_auth_loss.discard(("smtp", ctx.direction))
            mechanism = match.group(1).decode("ascii").upper()
            argument = match.group(2)
            if mechanism == "PLAIN" and argument:
                decoded = _b64decode(argument, max_output=65536)
                parsed = self._plain_auth(decoded) if decoded is not None else None
                if parsed:
                    finding = self._emit(
                        ctx,
                        state,
                        detector="smtp_auth_plain",
                        start=start,
                        end=end,
                        category="credential",
                        protocol="smtp",
                        material_type="smtp_auth_plain_credentials",
                        material={**parsed, "encoded": argument.decode("ascii")},
                    )
                    if finding:
                        findings.append(finding)
            elif mechanism == "PLAIN":
                pending_ids, pending_complete = self._provenance_for_span(
                    ctx,
                    start,
                    end,
                    limit=_MAX_PENDING_PROVENANCE_IDS,
                    pending=True,
                )
                state.smtp_pending[ctx.direction] = {
                    "mechanism": "PLAIN",
                    "packet_ids": pending_ids,
                    "packet_ids_complete": pending_complete,
                }
            else:
                username = None
                if argument:
                    decoded = _b64decode(argument, max_output=65536)
                    username = _safe_text(decoded) if decoded is not None else None
                pending_ids, pending_complete = self._provenance_for_span(
                    ctx,
                    start,
                    end,
                    limit=_MAX_PENDING_PROVENANCE_IDS,
                    pending=True,
                )
                state.smtp_pending[ctx.direction] = {
                    "mechanism": "LOGIN",
                    "stage": "password" if username is not None else "username",
                    "username": username,
                    "packet_ids": pending_ids,
                    "packet_ids_complete": pending_complete,
                }

        pending = state.smtp_pending.get(ctx.direction)
        if pending and not match and re.fullmatch(rb"[A-Za-z0-9+/=_-]{4,8192}", line):
            if not self._state_once(ctx, state, "smtp_response", start, end):
                return findings
            decoded = _b64decode(line, max_output=65536)
            if decoded is None:
                return findings
            response_packet_ids, response_complete = self._provenance_for_span(
                ctx, start, end
            )
            if pending["mechanism"] == "PLAIN":
                parsed = self._plain_auth(decoded)
                if parsed:
                    packet_ids, packet_ids_complete = self._combine_provenance(
                        (
                            pending.get("packet_ids", ()),
                            bool(pending.get("packet_ids_complete", False)),
                        ),
                        (response_packet_ids, response_complete),
                    )
                    finding = self._emit(
                        ctx,
                        state,
                        detector="smtp_auth_plain",
                        start=start,
                        end=end,
                        category="credential",
                        protocol="smtp",
                        material_type="smtp_auth_plain_credentials",
                        material={**parsed, "encoded": line.decode("ascii")},
                        packet_ids_override=packet_ids,
                        packet_ids_complete_override=packet_ids_complete,
                    )
                    if finding:
                        findings.append(finding)
                state.smtp_pending.pop(ctx.direction, None)
            elif pending.get("stage") == "username":
                pending["username"] = _safe_text(decoded)
                pending["stage"] = "password"
                packet_ids, packet_ids_complete = self._combine_provenance(
                    (
                        pending.get("packet_ids", ()),
                        bool(pending.get("packet_ids_complete", False)),
                    ),
                    (response_packet_ids, response_complete),
                    limit=_MAX_PENDING_PROVENANCE_IDS,
                    pending=True,
                )
                pending["packet_ids"] = packet_ids
                pending["packet_ids_complete"] = packet_ids_complete
            else:
                packet_ids, packet_ids_complete = self._combine_provenance(
                    (
                        pending.get("packet_ids", ()),
                        bool(pending.get("packet_ids_complete", False)),
                    ),
                    (response_packet_ids, response_complete),
                )
                finding = self._emit(
                    ctx,
                    state,
                    detector="smtp_auth_login",
                    start=start,
                    end=end,
                    category="credential",
                    protocol="smtp",
                    material_type="smtp_auth_login_credentials",
                    material={
                        "username": pending.get("username"),
                        "password": _safe_text(decoded),
                        "encoded_password": line.decode("ascii"),
                    },
                    confidence="confirmed",
                    packet_ids_override=packet_ids,
                    packet_ids_complete_override=packet_ids_complete,
                )
                if finding:
                    findings.append(finding)
                state.smtp_pending.pop(ctx.direction, None)
        return findings

    @staticmethod
    def _plain_auth(decoded: bytes | None) -> dict[str, str] | None:
        if decoded is None:
            return None
        parts = decoded.split(b"\x00")
        if len(parts) < 3:
            return None
        return {
            "authorization_identity": _safe_text(parts[-3]),
            "username": _safe_text(parts[-2]),
            "password": _safe_text(parts[-1]),
        }

    def _scan_imap_line(
        self,
        ctx: _ScanContext,
        state: _FlowState,
        line: bytes,
        start: int,
        end: int,
        ports: set[int],
    ) -> list[Finding]:
        findings: list[Finding] = []
        login = re.match(
            rb"(?i)^(\S+)\s+LOGIN\s+(?:\"([^\"]*)\"|(\S+))\s+(?:\"([^\"]*)\"|(\S+))$",
            line,
        )
        if login:
            username = login.group(2) if login.group(2) is not None else login.group(3)
            password = login.group(4) if login.group(4) is not None else login.group(5)
            finding = self._emit(
                ctx,
                state,
                detector="imap_login",
                start=start,
                end=end,
                category="credential",
                protocol="imap",
                material_type="imap_login_credentials",
                material={"tag": login.group(1).decode("latin-1"), "username": _safe_text(username), "password": _safe_text(password)},
                confidence="confirmed",
            )
            if finding:
                findings.append(finding)

        auth = re.match(rb"(?i)^(\S+)\s+AUTHENTICATE\s+(PLAIN|LOGIN)(?:\s+([^\s]+))?$", line)
        if auth and self._state_once(ctx, state, "imap_auth", start, end):
            state.pending_auth_loss.discard(("imap", ctx.direction))
            mechanism = auth.group(2).decode("ascii").upper()
            argument = auth.group(3)
            if mechanism == "PLAIN" and argument:
                decoded = _b64decode(argument, max_output=65536)
                parsed = self._plain_auth(decoded)
                if parsed:
                    finding = self._emit(
                        ctx,
                        state,
                        detector="imap_auth_plain",
                        start=start,
                        end=end,
                        category="credential",
                        protocol="imap",
                        material_type="imap_auth_plain_credentials",
                        material={**parsed, "encoded": argument.decode("ascii")},
                    )
                    if finding:
                        findings.append(finding)
            else:
                username = None
                if mechanism == "LOGIN" and argument:
                    decoded = _b64decode(argument, max_output=65536)
                    username = _safe_text(decoded) if decoded is not None else None
                pending_ids, pending_complete = self._provenance_for_span(
                    ctx,
                    start,
                    end,
                    limit=_MAX_PENDING_PROVENANCE_IDS,
                    pending=True,
                )
                state.imap_pending[ctx.direction] = {
                    "mechanism": mechanism,
                    "stage": "password" if username is not None else "username",
                    "username": username,
                    "packet_ids": pending_ids,
                    "packet_ids_complete": pending_complete,
                }

        pending = state.imap_pending.get(ctx.direction)
        if pending and not auth and re.fullmatch(rb"[A-Za-z0-9+/=_-]{4,8192}", line):
            if not self._state_once(ctx, state, "imap_response", start, end):
                return findings
            decoded = _b64decode(line, max_output=65536)
            if decoded is None:
                return findings
            response_packet_ids, response_complete = self._provenance_for_span(
                ctx, start, end
            )
            if pending["mechanism"] == "PLAIN":
                parsed = self._plain_auth(decoded)
                if parsed:
                    packet_ids, packet_ids_complete = self._combine_provenance(
                        (
                            pending.get("packet_ids", ()),
                            bool(pending.get("packet_ids_complete", False)),
                        ),
                        (response_packet_ids, response_complete),
                    )
                    finding = self._emit(
                        ctx,
                        state,
                        detector="imap_auth_plain",
                        start=start,
                        end=end,
                        category="credential",
                        protocol="imap",
                        material_type="imap_auth_plain_credentials",
                        material={**parsed, "encoded": line.decode("ascii")},
                        packet_ids_override=packet_ids,
                        packet_ids_complete_override=packet_ids_complete,
                    )
                    if finding:
                        findings.append(finding)
                state.imap_pending.pop(ctx.direction, None)
            elif pending["stage"] == "username":
                pending["username"] = _safe_text(decoded)
                pending["stage"] = "password"
                packet_ids, packet_ids_complete = self._combine_provenance(
                    (
                        pending.get("packet_ids", ()),
                        bool(pending.get("packet_ids_complete", False)),
                    ),
                    (response_packet_ids, response_complete),
                    limit=_MAX_PENDING_PROVENANCE_IDS,
                    pending=True,
                )
                pending["packet_ids"] = packet_ids
                pending["packet_ids_complete"] = packet_ids_complete
            else:
                packet_ids, packet_ids_complete = self._combine_provenance(
                    (
                        pending.get("packet_ids", ()),
                        bool(pending.get("packet_ids_complete", False)),
                    ),
                    (response_packet_ids, response_complete),
                )
                finding = self._emit(
                    ctx,
                    state,
                    detector="imap_auth_login",
                    start=start,
                    end=end,
                    category="credential",
                    protocol="imap",
                    material_type="imap_auth_login_credentials",
                    material={"username": pending.get("username"), "password": _safe_text(decoded), "encoded_password": line.decode("ascii")},
                    confidence="confirmed",
                    packet_ids_override=packet_ids,
                    packet_ids_complete_override=packet_ids_complete,
                )
                if finding:
                    findings.append(finding)
                state.imap_pending.pop(ctx.direction, None)
        return findings

    # -- bounded binary protocols ---------------------------------------

    def _scan_cleartext(self, ctx: _ScanContext, state: _FlowState) -> list[Finding]:
        """Framed cleartext database commands, preserving cursors across tails."""
        if ctx.base_offset is None or ctx.direction in state.cleartext_blocked:
            return []
        source, destination = (ctx.flow.endpoint_a, ctx.flow.endpoint_b) if ctx.direction == 0 else (ctx.flow.endpoint_b, ctx.flow.endpoint_a)
        if destination.port == 6379:
            parser, protocol = scan_redis, "redis"
        elif source.port == 5432:
            parser, protocol = scan_postgres_authentication, "postgresql"
        elif destination.port == 5432:
            parser, protocol = scan_postgres, "postgresql"
        else:
            return []
        cursor = state.cleartext_cursors.setdefault(ctx.direction, ctx.base_offset)
        if cursor < ctx.base_offset:
            # Do not resynchronize by searching inside unrelated values. Losing
            # a frame boundary is a coverage gap, visible until a new connection.
            state.cleartext_blocked.add(ctx.direction)
            self._stats["coverage_cleartext_frame_boundary_lost"] += 1
            return []
        relative = cursor - ctx.base_offset
        data = bytes(ctx.data[relative:])
        records, consumed = parser(data, state.postgres_method) if parser is scan_postgres else parser(data)
        state.cleartext_cursors[ctx.direction] = cursor + consumed
        findings: list[Finding] = []
        for record in records:
            kind = record.material["kind"]
            if kind == "cleartext_coverage":
                self._stats["coverage_cleartext_" + record.material["reason"]] += 1
                continue
            if kind == "postgres_authentication_request":
                state.postgres_method = record.material["authentication_method"]
                if record.material.get("coverage_reason"):
                    self._stats["coverage_cleartext_" + record.material["coverage_reason"]] += 1
                continue
            unknown = kind == "postgres_password_message"
            if unknown:
                self._stats["coverage_postgres_auth_method_unknown"] += 1
            finding = self._emit(
                ctx, state, detector=kind, start=relative + record.start,
                end=relative + record.end, category="authentication" if unknown else "credential",
                protocol=protocol, material_type=kind, material=record.material,
                confidence="medium" if unknown else "confirmed",
                limitations=list(record.limitations) + ["Observed submission does not demonstrate authentication success."],
            )
            if finding:
                findings.append(finding)
        return findings

    def _scan_ldap(self, ctx: _ScanContext, state: _FlowState) -> list[Finding]:
        if not (_ports(ctx.flow) & {389, 636, 3268, 3269}) and b"\x60" not in ctx.data:
            return []
        findings: list[Finding] = []
        data = ctx.data
        # Inspect every candidate in the bounded scanner window, not only
        # its first 64 bytes: pipelined/repeated binds can start much later.
        for match in re.finditer(b"\x30", data):
            start = match.start()
            outer = _tlv(data, start)
            if outer is None:
                continue
            outer_children = _children(data, outer)
            if not outer_children or len(outer_children) < 2 or outer_children[0].tag != 0x02:
                continue
            bind = outer_children[1]
            if bind.tag != 0x60:
                continue
            bind_children = _children(data, bind)
            if not bind_children or len(bind_children) < 3:
                continue
            version, name, auth = bind_children[:3]
            if version.tag != 0x02 or name.tag != 0x04 or auth.tag != 0x80:
                continue
            password = data[auth.value]
            if not password:
                continue
            finding = self._emit(
                ctx,
                state,
                detector="ldap_simple_bind",
                start=start,
                end=outer.end,
                category="credential",
                protocol="ldap",
                material_type="ldap_simple_bind_credentials",
                material={"bind_dn": _safe_text(data[name.value]), "password": _safe_text(password), "password_hex": password.hex()},
                confidence="confirmed",
                fields={"ldap_version": _asn1_integer(data, version)},
                limitations=["Bind request does not demonstrate authentication success."],
            )
            if finding:
                findings.append(finding)
        return findings

    def _scan_snmp(self, ctx: _ScanContext, state: _FlowState) -> list[Finding]:
        data = ctx.data
        outer = _tlv(data, 0)
        if outer is None or outer.tag != 0x30 or outer.end != len(data):
            return []
        children = _children(data, outer)
        if not children or len(children) < 3 or children[0].tag != 0x02 or children[1].tag != 0x04:
            return []
        version = _asn1_integer(data, children[0])
        if version not in (0, 1):
            return []
        if not (0xA0 <= children[2].tag <= 0xA8):
            return []
        community = data[children[1].value]
        if not community or len(community) > 255:
            return []
        finding = self._emit(
            ctx,
            state,
            detector="snmp_community",
            start=children[1].value_start,
            end=children[1].end,
            category="credential",
            protocol="snmp",
            material_type="snmp_community",
            material={"community": _safe_text(community), "community_hex": community.hex()},
            confidence="confirmed",
            fields={"snmp_version": "v1" if version == 0 else "v2c"},
            limitations=["Community observation does not establish write access or successful authorization."],
        )
        return [finding] if finding else []

    @staticmethod
    def _tds_utf16_field(payload: bytes, offset_pos: int) -> bytes | None:
        if offset_pos + 4 > len(payload):
            return None
        offset = int.from_bytes(payload[offset_pos : offset_pos + 2], "little")
        chars = int.from_bytes(payload[offset_pos + 2 : offset_pos + 4], "little")
        length = chars * 2
        if offset > len(payload) or length > 65535 or offset + length > len(payload):
            return None
        return payload[offset : offset + length]

    def _scan_mssql(self, ctx: _ScanContext, state: _FlowState) -> list[Finding]:
        data = ctx.data
        findings: list[Finding] = []
        pos = 0
        while pos + 8 <= len(data):
            if data[pos] != 0x10:
                next_pos = data.find(b"\x10", pos + 1, min(len(data), pos + 65536))
                if next_pos < 0:
                    break
                pos = next_pos
                continue
            packet_length = int.from_bytes(data[pos + 2 : pos + 4], "big")
            if packet_length < 8 + 94 or packet_length > _MAX_BINARY_MESSAGE or pos + packet_length > len(data):
                pos += 1
                continue
            payload = data[pos + 8 : pos + packet_length]
            declared = int.from_bytes(payload[0:4], "little")
            if declared < 94 or declared > len(payload):
                pos += packet_length
                continue
            username_raw = self._tds_utf16_field(payload, 40)
            password_enc = self._tds_utf16_field(payload, 44)
            hostname_raw = self._tds_utf16_field(payload, 36)
            database_raw = self._tds_utf16_field(payload, 68)
            if username_raw is None or password_enc is None or not password_enc:
                pos += packet_length
                continue
            password_raw = bytes(
                ((((value ^ 0xA5) & 0x0F) << 4) | (((value ^ 0xA5) & 0xF0) >> 4))
                for value in password_enc
            )
            finding = self._emit(
                ctx,
                state,
                detector="mssql_tds_login7",
                start=pos,
                end=pos + packet_length,
                category="credential",
                protocol="mssql",
                material_type="mssql_login7_credentials",
                material={
                    "username": _safe_text(username_raw, unicode_hint=True),
                    "password": _safe_text(password_raw, unicode_hint=True),
                    "obfuscated_password_hex": password_enc.hex(),
                    "hostname": _safe_text(hostname_raw or b"", unicode_hint=True),
                    "database": _safe_text(database_raw or b"", unicode_hint=True),
                },
                confidence="confirmed",
                limitations=["Login7 request does not demonstrate authentication success."],
            )
            if finding:
                findings.append(finding)
            pos += packet_length
        return findings

    def _scan_kerberos(self, ctx: _ScanContext, state: _FlowState) -> list[Finding]:
        data = ctx.data
        # TCP Kerberos messages may carry a four-byte record length.
        starts = [0]
        if len(data) > 4 and int.from_bytes(data[:4], "big") == len(data) - 4:
            starts.insert(0, 4)
        findings: list[Finding] = []
        for start in starts:
            app = _tlv(data, start)
            if app is None or app.tag != 0x6A:  # [APPLICATION 10] AS-REQ
                continue
            parsed = self._parse_krb5_as_req(data, app)
            if parsed is None:
                continue
            user, realm, cipher = parsed
            if len(cipher) != 52:
                continue
            # Hashcat mode 7500 stores the 36-byte encrypted timestamp first,
            # followed by the 16-byte checksum; the wire EncryptedData cipher
            # is checksum || encrypted timestamp.
            hashcat = (
                f"$krb5pa$23${user}${realm}$dummy$"
                f"{cipher[16:].hex()}{cipher[:16].hex()}"
            )
            finding = self._emit(
                ctx,
                state,
                detector="kerberos_as_req_etype23",
                start=start,
                end=app.end,
                category="credential",
                protocol="kerberos",
                material_type="kerberos_as_req_etype23",
                material={"username": user, "realm": realm, "cipher_hex": cipher.hex(), "hashcat": hashcat, "hashcat_mode": 7500},
                confidence="confirmed",
                fields={"etype": 23, "hashcat_mode": 7500},
                limitations=["Pre-authentication material does not demonstrate authentication success."],
            )
            if finding:
                findings.append(finding)
            break
        return findings

    def _parse_krb5_as_req(self, data: bytes, app: _TLV) -> tuple[str, str, bytes] | None:
        sequence = _inner_single(data, app)
        if sequence is None or sequence.tag != 0x30:
            return None
        top = _children(data, sequence)
        if not top:
            return None
        padata_ctx = next((node for node in top if node.tag == 0xA3), None)
        body_ctx = next((node for node in top if node.tag == 0xA4), None)
        if padata_ctx is None or body_ctx is None:
            return None

        body_seq = _inner_single(data, body_ctx)
        body = _children(data, body_seq) if body_seq and body_seq.tag == 0x30 else None
        if not body:
            return None
        realm_ctx = next((node for node in body if node.tag == 0xA2), None)
        cname_ctx = next((node for node in body if node.tag == 0xA1), None)
        if realm_ctx is None or cname_ctx is None:
            return None
        realm = _asn1_string(data, realm_ctx)
        cname_seq = _inner_single(data, cname_ctx)
        cname_fields = _children(data, cname_seq) if cname_seq and cname_seq.tag == 0x30 else None
        if not cname_fields:
            return None
        names_ctx = next((node for node in cname_fields if node.tag == 0xA1), None)
        names_seq = _inner_single(data, names_ctx) if names_ctx else None
        names = _children(data, names_seq) if names_seq and names_seq.tag == 0x30 else None
        user = _asn1_string(data, names[0]) if names else None
        if not user or not realm:
            return None

        padata_seq = _inner_single(data, padata_ctx)
        entries = _children(data, padata_seq) if padata_seq and padata_seq.tag == 0x30 else None
        if not entries:
            return None
        for entry in entries:
            if entry.tag != 0x30:
                continue
            fields = _children(data, entry)
            if not fields:
                continue
            type_ctx = next((node for node in fields if node.tag == 0xA1), None)
            value_ctx = next((node for node in fields if node.tag == 0xA2), None)
            if type_ctx is None or value_ctx is None or _asn1_integer(data, type_ctx) != 2:
                continue
            octet = _inner_single(data, value_ctx)
            if octet is None or octet.tag != 0x04:
                continue
            encrypted = data[octet.value]
            enc_seq = _tlv(encrypted, 0)
            if enc_seq is None or enc_seq.tag != 0x30 or enc_seq.end != len(encrypted):
                continue
            enc_fields = _children(encrypted, enc_seq)
            if not enc_fields:
                continue
            etype_ctx = next((node for node in enc_fields if node.tag == 0xA0), None)
            cipher_ctx = next((node for node in enc_fields if node.tag == 0xA2), None)
            if etype_ctx is None or cipher_ctx is None or _asn1_integer(encrypted, etype_ctx) != 23:
                continue
            cipher_octet = _inner_single(encrypted, cipher_ctx)
            if cipher_octet is None or cipher_octet.tag != 0x04:
                continue
            return user, realm, encrypted[cipher_octet.value]
        return None

    # -- generic secrets and payment-card candidates --------------------

    def _scan_generic_secrets(self, ctx: _ScanContext, state: _FlowState) -> list[Finding]:
        findings: list[Finding] = []
        data = self._terminated_text_data(ctx)
        pending = False
        for detector, regex, material_type, confidence in _GENERIC_SECRET_PATTERNS:
            for match in regex.finditer(data):
                if not self._has_observed_match_boundary(ctx, data, match.end()):
                    pending = True
                    continue
                raw = match.group(0)
                finding = self._emit(
                    ctx,
                    state,
                    detector=detector,
                    start=match.start(),
                    end=match.end(),
                    category="secret",
                    protocol="generic",
                    material_type=material_type,
                    material=raw.decode("latin-1"),
                    confidence=confidence,
                    limitations=["Pattern match; issuer validity and current usability were not tested."],
                )
                if finding:
                    findings.append(finding)

        for match in _GENERIC_ASSIGNMENT_RE.finditer(data):
            name = match.group(1).decode("ascii", "ignore")
            if name.lower() not in self.sensitive_fields:
                continue
            # The assignment scanner stops at whitespace.  In an HTTP
            # Authorization header it otherwise treats "Negotiate" as the
            # secret and emits a false candidate for the authentication
            # scheme, leaving the real token to the protocol parser.
            if name.lower() == "authorization" and match.group(2).lower() in {
                b"basic", b"bearer", b"digest", b"negotiate", b"ntlm"
            }:
                continue
            finding = self._emit(
                ctx,
                state,
                detector="generic_secret_assignment",
                start=match.start(2),
                end=match.end(2),
                category="secret",
                protocol="generic",
                material_type="named_secret",
                material={"name": name, "value": match.group(2).decode("latin-1")},
                confidence="medium",
                limitations=["Name/value pattern indicates sensitivity; validity was not tested."],
            )
            if finding:
                findings.append(finding)

        if not ctx.is_datagram:
            pending_tail = ctx.data[-(_MAX_LINE + 128) :]
            open_assignment = _GENERIC_ASSIGNMENT_OPEN_RE.search(pending_tail)
            if open_assignment is not None:
                name = open_assignment.group(1).decode("ascii", "ignore").lower()
                pending = pending or name in self.sensitive_fields
            trailing_token = re.search(rb"[A-Za-z0-9_.-]{1,8192}$", pending_tail)
            if trailing_token is not None:
                trailing = trailing_token.group(0).lower()
                pending = pending or any(
                    trailing.startswith(prefix) or prefix.startswith(trailing)
                    for prefix in _GENERIC_STRONG_PREFIXES
                )
        state.generic_pending[ctx.direction] = pending

        return findings

    def _scan_pem_private_keys(
        self, ctx: _ScanContext, state: _FlowState
    ) -> list[Finding]:
        findings: list[Finding] = []
        for match in _PEM_PRIVATE_KEY_RE.finditer(ctx.data):
            finding = self._emit(
                ctx,
                state,
                detector="pem_private_key",
                start=match.start(),
                end=match.end(),
                category="secret",
                protocol="generic",
                material_type="private_key",
                material=match.group(0).decode("ascii", "replace"),
                confidence="confirmed",
                limitations=["Key syntax was observed; cryptographic validity was not tested."],
            )
            if finding:
                findings.append(finding)
        last_begin = ctx.data.rfind(b"-----BEGIN ")
        last_end = ctx.data.rfind(b"-----END ")
        state.pem_pending[ctx.direction] = last_begin >= 0 and last_begin > last_end
        return findings

    @staticmethod
    def _luhn(number: str) -> bool:
        total = 0
        parity = len(number) % 2
        for index, char in enumerate(number):
            digit = ord(char) - 48
            if index % 2 == parity:
                digit *= 2
                if digit > 9:
                    digit -= 9
            total += digit
        return total % 10 == 0

    def _scan_cards(self, ctx: _ScanContext, state: _FlowState) -> list[Finding]:
        findings: list[Finding] = []
        data = self._terminated_text_data(ctx)
        for match in _PAYMENT_CARD_RE.finditer(data):
            if not self._has_observed_match_boundary(ctx, data, match.end()):
                continue
            raw = match.group(0)
            number = re.sub(rb"[ -]", b"", raw).decode("ascii")
            if not 13 <= len(number) <= 19 or len(set(number)) == 1 or not self._luhn(number):
                continue
            finding = self._emit(
                ctx,
                state,
                detector="luhn_payment_card",
                start=match.start(),
                end=match.end(),
                category="financial",
                protocol="generic",
                material_type="payment_card_candidate",
                material={"raw": raw.decode("ascii"), "digits": number},
                confidence="medium",
                limitations=["Luhn-valid numeric candidate; issuer assignment, account validity, and context were not verified."],
            )
            if finding:
                findings.append(finding)
        return findings


# Backwards/semantic alias for callers that prefer the longer name.
SensitiveMaterialDetector = SensitiveDetector


__all__ = ["SensitiveDetector", "SensitiveMaterialDetector"]
