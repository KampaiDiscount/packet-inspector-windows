"""Bounded NTLM transport metadata; no authentication or network operations."""
from __future__ import annotations


def _tlv(data: bytes, start: int, limit: int):
    if start + 2 > limit:
        return None
    tag, size = data[start:start + 2]
    value = start + 2
    if size & 128:
        count = size & 127
        if not 1 <= count <= 3 or value + count > limit:
            return None
        size = int.from_bytes(data[value:value + count], "big")
        value += count
    end = value + size
    return (tag, value, end) if end <= limit else None


def unwrap_ntlm(token: bytes) -> bytes | None:
    """Direct NTLM or RFC 4178 NegTokenInit/Resp mech/responseToken only.

    Do not search arbitrary base64-decoded data for an embedded signature.
    Kerberos tokens and malformed/ambiguous ASN.1 are not NTLM.
    """
    if len(token) > 65536:
        return None
    if token.startswith(b"NTLMSSP\x00"):
        return token
    node = _tlv(token, 0, len(token))
    if node is None or node[2] != len(token):
        return None
    tag, value, end = node
    if tag == 0x60:  # GSS InitialContextToken with SPNEGO OID
        oid = _tlv(token, value, end)
        if oid is None or oid[0] != 6 or token[oid[1]:oid[2]] != b"\x2b\x06\x01\x05\x05\x02":
            return None
        node = _tlv(token, oid[2], end)
        if node is None or node[2] != end:
            return None
        tag, value, end = node
    if tag not in (0xA0, 0xA1):
        return None
    seq = _tlv(token, value, end)
    if seq is None or seq[0] != 0x30 or seq[2] != end:
        return None
    cursor = seq[1]
    found = None
    count = 0
    while cursor < end and count < 8:
        child = _tlv(token, cursor, end)
        if child is None:
            return None
        if child[0] == 0xA2:
            inner = _tlv(token, child[1], child[2])
            if inner is None or inner[0] != 4 or inner[2] != child[2] or found is not None:
                return None
            found = token[inner[1]:inner[2]]
        cursor = child[2]
        count += 1
    if cursor != end or found is None or not found.startswith(b"NTLMSSP\x00"):
        return None
    return found


def smb2_header_seen(data: bytes | bytearray) -> bool:
    """Recognize an SMB2 header, including when capture begins mid-record.

    A bare signature can occur inside unrelated data, so it cannot by itself
    disable unscoped NTLM correlation for the rest of a TCP connection.
    """
    cursor = data.find(b"\xfeSMB")
    while cursor >= 0:
        if (
            cursor + 64 <= len(data)
            and data[cursor + 4:cursor + 6] == b"\x40\x00"
            and int.from_bytes(data[cursor + 12:cursor + 14], "little") <= 18
        ):
            return True
        cursor = data.find(b"\xfeSMB", cursor + 4)
    return False


def smb2_session_for_token(data: bytes | bytearray, token_start: int, token_length: int = 12) -> int | None:
    """Find a validated enclosing SMB2 SESSION_SETUP security buffer.

    Work is bounded by the retained detector window and the 16-bit security
    offset. A header may precede the current NTLM scanner window. The caller
    therefore supplies the existing retained direction buffer, not extra state.
    SMB3 encrypted/compressed transform records are deliberately not parsed.
    """
    lower = max(0, token_start - 65535)
    cursor = token_start
    for _ in range(64):
        header = data.rfind(b"\xfeSMB", lower, cursor)
        if header < 0:
            return None
        cursor = header
        if header + 72 > len(data):
            continue
        if data[header + 4:header + 6] != b"\x40\x00" or data[header + 12:header + 14] != b"\x01\x00":
            continue
        response = bool(int.from_bytes(data[header + 16:header + 20], "little") & 1)
        fixed_size, offset_pos, minimum = (9, 68, 72) if response else (25, 76, 88)
        if header + minimum > len(data) or int.from_bytes(data[header + 64:header + 66], "little") != fixed_size:
            continue
        offset = int.from_bytes(data[header + offset_pos:header + offset_pos + 2], "little")
        length = int.from_bytes(data[header + offset_pos + 2:header + offset_pos + 4], "little")
        if token_length < 12 or offset < minimum or not header + offset <= token_start < token_start + token_length <= header + offset + length:
            continue
        # SESSION_SETUP is not compound; require the direct-TCP record header
        # so a signature inside unrelated application data cannot create scope.
        if header < 4 or data[header - 4] != 0:
            continue
        frame_length = int.from_bytes(data[header - 3:header], "big")
        if frame_length < offset + length or data[header + 20:header + 24] != bytes(4):
            continue
        # Some responder implementations use zero throughout the exchange.
        # Zero means a framed token with no assigned session, not missing
        # framing; the caller handles its weaker correlation scope.
        return int.from_bytes(data[header + 40:header + 48], "little")
    return None
