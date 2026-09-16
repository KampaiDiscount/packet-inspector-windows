"""Bounds-checked link, IP, TCP, and UDP packet decoding.

The capture process deliberately does not depend on Scapy.  This module only
extracts the small amount of metadata needed to shard packets by flow and to
feed the bounded reassemblers.
"""

from __future__ import annotations

from dataclasses import replace
import ipaddress
import struct

from .models import CapturedPacket, ParsedPacket


# libpcap data-link types used by Linux and native Npcap capture paths.
DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 12
DLT_LINUX_SLL = 113
DLT_IPV4 = 228
DLT_IPV6 = 229
DLT_LINUX_SLL2 = 276

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
VLAN_ETHERTYPES = frozenset((0x8100, 0x88A8, 0x9100, 0x9200))

IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_FRAGMENT = 44

_IPV6_EXTENSION_HEADERS = frozenset((0, 43, 60, 135, 139, 140))
_MAX_VLAN_TAGS = 8
_MAX_IPV6_EXTENSION_HEADERS = 16


class PacketDecodeError(ValueError):
    """Raised by strict decoding helpers for malformed or truncated input."""


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise PacketDecodeError("two-byte field extends past captured data")
    return struct.unpack_from("!H", data, offset)[0]


def _link_payload(raw: bytes, datalink: int) -> tuple[int, bytes, tuple[int, ...]]:
    """Return ``(ethertype, network_bytes, vlan_ids)`` for supported DLTs."""

    if datalink == DLT_NULL:
        # Npcap loopback: native-endian family 2 (IPv4) or 24 (IPv6).
        # Accept either capture-host byte order for offline cross-host replay.
        if len(raw) < 4:
            raise PacketDecodeError("short Npcap loopback header")
        family = int.from_bytes(raw[:4], 'little')
        if family not in (2, 24):
            family = int.from_bytes(raw[:4], 'big')
        if family not in (2, 24):
            raise PacketDecodeError(f"unsupported loopback address family {family}")
        return (ETHERTYPE_IPV4 if family == 2 else ETHERTYPE_IPV6), raw[4:], ()

    if datalink == DLT_EN10MB:
        if len(raw) < 14:
            raise PacketDecodeError("short Ethernet header")
        ether_type = _u16(raw, 12)
        offset = 14
        vlans: list[int] = []
        while ether_type in VLAN_ETHERTYPES:
            if len(vlans) >= _MAX_VLAN_TAGS:
                raise PacketDecodeError("too many stacked VLAN tags")
            if offset + 4 > len(raw):
                raise PacketDecodeError("short VLAN header")
            tci = _u16(raw, offset)
            vlans.append(tci & 0x0FFF)
            ether_type = _u16(raw, offset + 2)
            offset += 4
        return ether_type, raw[offset:], tuple(vlans)

    if datalink == DLT_LINUX_SLL:
        # Linux cooked capture v1 has a fixed 16-byte header and stores the
        # protocol value in its final two bytes.
        if len(raw) < 16:
            raise PacketDecodeError("short Linux SLL header")
        return _u16(raw, 14), raw[16:], ()

    if datalink == DLT_LINUX_SLL2:
        # SLL2 is 20 bytes and moved the protocol field to the beginning.
        if len(raw) < 20:
            raise PacketDecodeError("short Linux SLL2 header")
        return _u16(raw, 0), raw[20:], ()

    if datalink == DLT_RAW:
        if not raw:
            raise PacketDecodeError("empty raw IP packet")
        version = raw[0] >> 4
        if version == 4:
            return ETHERTYPE_IPV4, raw, ()
        if version == 6:
            return ETHERTYPE_IPV6, raw, ()
        raise PacketDecodeError("raw packet is neither IPv4 nor IPv6")

    if datalink == DLT_IPV4:
        return ETHERTYPE_IPV4, raw, ()
    if datalink == DLT_IPV6:
        return ETHERTYPE_IPV6, raw, ()

    raise PacketDecodeError(f"unsupported libpcap datalink type {datalink}")


def parse_packet_strict(packet: CapturedPacket) -> ParsedPacket | None:
    """Decode one captured packet and raise for malformed supported frames.

    Unsupported non-IP frames return ``None``.
    A packet with a complete IP header but a short transport payload is still
    returned with ``truncated=True`` so health accounting stays loss-visible.
    """

    ether_type, network, vlan_ids = _link_payload(packet.raw, packet.datalink)
    if ether_type == ETHERTYPE_IPV4:
        parsed = _parse_ipv4(packet, network, vlan_ids)
    elif ether_type == ETHERTYPE_IPV6:
        parsed = _parse_ipv6(packet, network, vlan_ids)
    else:
        return None
    return parse_transport(parsed)


def parse_packet(packet: CapturedPacket) -> ParsedPacket | None:
    """Lenient adapter returning ``None`` for malformed/unsupported frames."""

    try:
        return parse_packet_strict(packet)
    except (PacketDecodeError, struct.error, ValueError):
        return None


def _parse_ipv4(
    packet: CapturedPacket, network: bytes, vlan_ids: tuple[int, ...]
) -> ParsedPacket:
    if len(network) < 20:
        raise PacketDecodeError("short IPv4 header")
    if network[0] >> 4 != 4:
        raise PacketDecodeError("invalid IPv4 version")
    ihl = (network[0] & 0x0F) * 4
    if ihl < 20 or ihl > len(network):
        raise PacketDecodeError("invalid or truncated IPv4 header length")
    total_length = _u16(network, 2)
    if total_length < ihl:
        raise PacketDecodeError("IPv4 total length is shorter than its header")

    available_length = min(len(network), total_length)
    truncated = (
        len(network) < total_length
        or packet.captured_length < packet.wire_length
    )
    flags_and_offset = _u16(network, 6)
    fragment_offset = (flags_and_offset & 0x1FFF) * 8
    more_fragments = bool(flags_and_offset & 0x2000)
    fragmented = more_fragments or fragment_offset != 0

    return ParsedPacket(
        session_id=packet.session_id,
        packet_id=packet.packet_id,
        timestamp_ns=packet.timestamp_ns,
        interface=packet.interface,
        captured_length=packet.captured_length,
        wire_length=packet.wire_length,
        ip_version=4,
        src=str(ipaddress.IPv4Address(network[12:16])),
        dst=str(ipaddress.IPv4Address(network[16:20])),
        protocol=network[9],
        vlan_ids=vlan_ids,
        network_payload=network[ihl:available_length],
        truncated=truncated,
        fragment_id=_u16(network, 4) if fragmented else None,
        fragment_offset=fragment_offset,
        more_fragments=more_fragments,
    )


def _parse_ipv6(
    packet: CapturedPacket, network: bytes, vlan_ids: tuple[int, ...]
) -> ParsedPacket:
    if len(network) < 40:
        raise PacketDecodeError("short IPv6 header")
    if network[0] >> 4 != 6:
        raise PacketDecodeError("invalid IPv6 version")

    payload_length = _u16(network, 4)
    # A zero payload length can be a valid empty packet or a jumbogram.  Using
    # captured bytes in that case lets the extension walker find a Jumbo
    # Payload option without ever reading beyond the capture buffer.
    declared_end = 40 + payload_length if payload_length else len(network)
    available_end = min(len(network), declared_end)
    truncated = (
        (payload_length != 0 and len(network) < declared_end)
        or packet.captured_length < packet.wire_length
    )

    next_header = network[6]
    offset = 40
    fragment_id: int | None = None
    fragment_offset = 0
    more_fragments = False

    for _ in range(_MAX_IPV6_EXTENSION_HEADERS):
        if next_header == IPPROTO_FRAGMENT:
            if offset + 8 > available_end:
                raise PacketDecodeError("short IPv6 fragment header")
            fragment_next = network[offset]
            fragment_bits = _u16(network, offset + 2)
            fragment_offset = ((fragment_bits >> 3) & 0x1FFF) * 8
            more_fragments = bool(fragment_bits & 0x0001)
            fragment_id = struct.unpack_from("!I", network, offset + 4)[0]
            offset += 8
            next_header = fragment_next
            break

        if next_header in _IPV6_EXTENSION_HEADERS:
            if offset + 2 > available_end:
                raise PacketDecodeError("short IPv6 extension header")
            following = network[offset]
            header_length = (network[offset + 1] + 1) * 8
            if header_length < 8 or offset + header_length > available_end:
                raise PacketDecodeError("invalid IPv6 extension header length")
            next_header = following
            offset += header_length
            continue

        if next_header == 51:  # Authentication Header
            if offset + 2 > available_end:
                raise PacketDecodeError("short IPv6 authentication header")
            following = network[offset]
            header_length = (network[offset + 1] + 2) * 4
            if header_length < 8 or offset + header_length > available_end:
                raise PacketDecodeError("invalid IPv6 authentication header length")
            next_header = following
            offset += header_length
            continue
        break
    else:
        raise PacketDecodeError("too many IPv6 extension headers")

    return ParsedPacket(
        session_id=packet.session_id,
        packet_id=packet.packet_id,
        timestamp_ns=packet.timestamp_ns,
        interface=packet.interface,
        captured_length=packet.captured_length,
        wire_length=packet.wire_length,
        ip_version=6,
        src=str(ipaddress.IPv6Address(network[8:24])),
        dst=str(ipaddress.IPv6Address(network[24:40])),
        protocol=next_header,
        vlan_ids=vlan_ids,
        network_payload=network[offset:available_end],
        truncated=truncated,
        # Atomic fragments can be parsed immediately, but keeping their ID is
        # useful evidence that a fragment header was present.
        fragment_id=fragment_id,
        fragment_offset=fragment_offset,
        more_fragments=more_fragments,
    )


def normalize_reassembled_ipv6(packet: ParsedPacket) -> ParsedPacket:
    """Walk extension headers that occurred after an IPv6 fragment header."""

    if packet.ip_version != 6:
        return packet
    next_header = packet.protocol
    payload = packet.network_payload
    offset = 0
    for _ in range(_MAX_IPV6_EXTENSION_HEADERS):
        if next_header in _IPV6_EXTENSION_HEADERS:
            if offset + 2 > len(payload):
                return replace(packet, truncated=True, transport_parsed=False)
            following = payload[offset]
            length = (payload[offset + 1] + 1) * 8
            if length < 8 or offset + length > len(payload):
                return replace(packet, truncated=True, transport_parsed=False)
            next_header = following
            offset += length
            continue
        if next_header == 51:
            if offset + 2 > len(payload):
                return replace(packet, truncated=True, transport_parsed=False)
            following = payload[offset]
            length = (payload[offset + 1] + 2) * 4
            if length < 8 or offset + length > len(payload):
                return replace(packet, truncated=True, transport_parsed=False)
            next_header = following
            offset += length
            continue
        break
    return replace(packet, protocol=next_header, network_payload=payload[offset:])


def parse_transport(packet: ParsedPacket) -> ParsedPacket:
    """Decode TCP/UDP after IP (or fragment) reconstruction.

    Non-initial or incomplete fragmented datagrams are intentionally left for
    :class:`packet_audit.reassembly.FragmentReassembler`.
    """

    if packet.fragment_offset or packet.more_fragments:
        return packet

    payload = packet.network_payload
    if packet.protocol == IPPROTO_TCP:
        if len(payload) < 20:
            return replace(packet, truncated=True, transport_parsed=False)
        data_offset = (payload[12] >> 4) * 4
        if data_offset < 20 or data_offset > len(payload):
            return replace(packet, truncated=True, transport_parsed=False)
        return replace(
            packet,
            sport=_u16(payload, 0),
            dport=_u16(payload, 2),
            tcp_seq=struct.unpack_from("!I", payload, 4)[0],
            tcp_ack=struct.unpack_from("!I", payload, 8)[0],
            tcp_flags=payload[13],
            transport_payload=payload[data_offset:],
            transport_parsed=True,
        )

    if packet.protocol == IPPROTO_UDP:
        if len(payload) < 8:
            return replace(packet, truncated=True, transport_parsed=False)
        udp_length = _u16(payload, 4)
        if udp_length == 0 and packet.ip_version == 6:
            # UDP jumbograms encode their true length in the IPv6 Jumbo option.
            udp_end = len(payload)
        elif udp_length < 8:
            return replace(packet, truncated=True, transport_parsed=False)
        else:
            udp_end = min(len(payload), udp_length)
        return replace(
            packet,
            sport=_u16(payload, 0),
            dport=_u16(payload, 2),
            transport_payload=payload[8:udp_end],
            transport_parsed=True,
            truncated=packet.truncated or (udp_length != 0 and len(payload) < udp_length),
        )

    return packet


class PacketParser:
    """Small state-free adapter suitable for worker dependency injection."""

    def parse(self, packet: CapturedPacket) -> ParsedPacket | None:
        return parse_packet(packet)
