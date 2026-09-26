from __future__ import annotations

import struct
import unittest
from unittest import mock

from packet_audit.models import ParsedPacket, ProvenanceSpan
from packet_audit.reassembly import FragmentReassembler, TCPReassembler


def parsed(
    *,
    packet_id: int,
    payload: bytes,
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    sport: int = 1234,
    dport: int = 80,
    protocol: int = 6,
    ip_version: int = 4,
    sequence: int = 1000,
    flags: int = 0x18,
    fragment_id: int | None = None,
    fragment_offset: int = 0,
    more_fragments: bool = False,
    transport_parsed: bool = True,
) -> ParsedPacket:
    return ParsedPacket(
        session_id="test",
        packet_id=packet_id,
        timestamp_ns=packet_id * 1_000_000_000,
        interface="eth0",
        captured_length=len(payload),
        wire_length=len(payload),
        ip_version=ip_version,
        src=src,
        dst=dst,
        protocol=protocol,
        vlan_ids=(),
        network_payload=payload,
        fragment_id=fragment_id,
        fragment_offset=fragment_offset,
        more_fragments=more_fragments,
        transport_parsed=transport_parsed,
        sport=sport if transport_parsed else 0,
        dport=dport if transport_parsed else 0,
        tcp_seq=sequence,
        tcp_flags=flags,
        transport_payload=payload if transport_parsed else b"",
    )


def test_ipv4_fragments_reassemble_out_of_order() -> None:
    udp = struct.pack("!HHHH", 4444, 53, 8 + 16, 0) + b"0123456789abcdef"
    second = parsed(
        packet_id=2,
        payload=udp[16:],
        protocol=17,
        fragment_id=99,
        fragment_offset=16,
        more_fragments=False,
        transport_parsed=False,
    )
    first = parsed(
        packet_id=1,
        payload=udp[:16],
        protocol=17,
        fragment_id=99,
        fragment_offset=0,
        more_fragments=True,
        transport_parsed=False,
    )
    reassembler = FragmentReassembler()

    assert reassembler.process(second) is None
    complete = reassembler.process(first)

    assert complete is not None
    assert complete.fragment_id is None
    assert complete.transport_parsed
    assert (complete.sport, complete.dport) == (4444, 53)
    assert complete.transport_payload == b"0123456789abcdef"
    assert complete.source_packet_ids == (2, 1)
    assert reassembler.active_datagrams == 0
    assert reassembler.buffered_bytes == 0


def test_fragment_conflicting_overlap_discards_datagram() -> None:
    reassembler = FragmentReassembler()
    first = parsed(
        packet_id=1,
        payload=b"A" * 16,
        protocol=17,
        fragment_id=5,
        more_fragments=True,
        transport_parsed=False,
    )
    overlap = parsed(
        packet_id=2,
        payload=b"B" * 16,
        protocol=17,
        fragment_id=5,
        fragment_offset=8,
        more_fragments=False,
        transport_parsed=False,
    )

    assert reassembler.process(first) is None
    assert reassembler.process(overlap) is None
    assert reassembler.overlap_conflicts == 1
    assert reassembler.active_datagrams == 0


def test_fragment_expiry_releases_memory() -> None:
    reassembler = FragmentReassembler(idle_seconds=1)
    fragment = parsed(
        packet_id=1,
        payload=b"A" * 16,
        protocol=17,
        fragment_id=8,
        more_fragments=True,
        transport_parsed=False,
    )
    reassembler.process(fragment)

    assert reassembler.expire(2_000_000_001) == 1
    assert reassembler.buffered_bytes == 0


def test_fragment_adjacent_ranges_coalesce_and_counters_release() -> None:
    reassembler = FragmentReassembler(idle_seconds=1)
    for packet_id, offset in ((1, 0), (2, 8)):
        assert reassembler.process(
            parsed(
                packet_id=packet_id,
                payload=bytes((64 + packet_id,)) * 8,
                protocol=17,
                fragment_id=88,
                fragment_offset=offset,
                more_fragments=True,
                transport_parsed=False,
            )
        ) is None

    state = next(iter(reassembler._states.values()))
    assert len(state.ranges) == 1
    assert reassembler.buffered_ranges == 1
    assert reassembler.buffered_provenance_entries == 2

    assert reassembler.expire(3_000_000_001) == 1
    assert reassembler.buffered_ranges == 0
    assert reassembler.buffered_provenance_entries == 0


def test_global_fragment_range_budget_evicts_lru_datagram() -> None:
    reassembler = FragmentReassembler(
        max_datagrams=4,
        max_buffered_ranges=2,
        max_buffered_provenance_entries=100,
    )

    for fragment_id in (1, 2, 3):
        assert reassembler.process(
            parsed(
                packet_id=fragment_id,
                payload=b"A" * 8,
                protocol=17,
                fragment_id=fragment_id,
                more_fragments=True,
                transport_parsed=False,
            )
        ) is None

    assert {key.fragment_id for key in reassembler._states} == {2, 3}
    assert reassembler.buffered_ranges == 2
    assert reassembler.evicted_datagrams == 1


def test_global_fragment_provenance_budget_evicts_lru_datagram() -> None:
    reassembler = FragmentReassembler(
        max_datagrams=4,
        max_buffered_ranges=100,
        max_buffered_provenance_entries=2,
    )

    for fragment_id in (1, 2, 3):
        fragment = parsed(
            packet_id=fragment_id,
            payload=b"A" * 8,
            protocol=17,
            fragment_id=fragment_id,
            more_fragments=True,
            transport_parsed=False,
        )
        fragment.source_packet_ids = (fragment_id * 10,)
        assert reassembler.process(fragment) is None

    assert {key.fragment_id for key in reassembler._states} == {2, 3}
    assert reassembler.buffered_provenance_entries == 2
    assert reassembler.evicted_datagrams == 1


def test_ipv6_fragmentable_extension_is_normalized_after_reassembly() -> None:
    udp = struct.pack("!HHHH", 123, 456, 16, 0) + b"password"
    destination_options = bytes((17, 0)) + b"\x00" * 6
    fragmentable = destination_options + udp
    first = parsed(
        packet_id=1,
        payload=fragmentable[:16],
        src="2001:db8::1",
        dst="2001:db8::2",
        protocol=60,
        ip_version=6,
        fragment_id=123456,
        more_fragments=True,
        transport_parsed=False,
    )
    second = parsed(
        packet_id=2,
        payload=fragmentable[16:],
        src="2001:db8::1",
        dst="2001:db8::2",
        protocol=60,
        ip_version=6,
        fragment_id=123456,
        fragment_offset=16,
        transport_parsed=False,
    )
    reassembler = FragmentReassembler()

    assert reassembler.process(first) is None
    complete = reassembler.process(second)
    assert complete is not None
    assert complete.protocol == 17
    assert complete.transport_parsed
    assert complete.transport_payload == b"password"


def tcp_packet(
    packet_id: int,
    data: bytes,
    sequence: int,
    *,
    flags: int = 0x18,
    reverse: bool = False,
) -> ParsedPacket:
    return parsed(
        packet_id=packet_id,
        payload=data,
        src="10.0.0.2" if reverse else "10.0.0.1",
        dst="10.0.0.1" if reverse else "10.0.0.2",
        sport=80 if reverse else 1234,
        dport=1234 if reverse else 80,
        sequence=sequence,
        flags=flags,
    )


def test_tcp_out_of_order_reassembly_and_exactly_once() -> None:
    reassembler = TCPReassembler()
    assert reassembler.process(tcp_packet(1, b"", 1000, flags=0x02)) == []
    assert reassembler.process(tcp_packet(2, b"world", 1006)) == []
    chunks = reassembler.process(tcp_packet(3, b"hello", 1001))

    assert len(chunks) == 1
    assert chunks[0].data == b"helloworld"
    assert chunks[0].stream_offset == 0
    assert chunks[0].packet_ids == (3, 2)
    assert chunks[0].completeness == "complete"

    assert reassembler.process(tcp_packet(4, b"helloworld", 1001)) == []
    suffix = reassembler.process(tcp_packet(5, b"rld!!!", 1008))
    assert [chunk.data for chunk in suffix] == [b"!!!"]
    assert suffix[0].stream_offset == 10


def test_tcp_consumed_conflicting_retransmission_is_visible_with_new_suffix() -> None:
    reassembler = TCPReassembler(consumed_history_bytes=16)
    assert reassembler.process(tcp_packet(1, b"", 100, flags=0x02)) == []

    first = reassembler.process(tcp_packet(2, b"abc", 101))
    assert [chunk.data for chunk in first] == [b"abc"]

    # An exact retransmission remains deduplicated and is not a conflict.
    assert reassembler.process(tcp_packet(3, b"abc", 101)) == []
    assert reassembler.overlap_conflicts == 0

    # The already-emitted prefix is contradictory, while the unseen suffix
    # must still be emitted exactly once.
    suffix = reassembler.process(tcp_packet(4, b"XYZd", 101))
    assert [chunk.data for chunk in suffix] == [b"d"]
    assert suffix[0].stream_offset == 3
    assert reassembler.overlap_conflicts == 1
    assert reassembler.retransmitted_bytes == 6


def test_tcp_acknowledged_one_byte_keepalives_do_not_report_conflicts() -> None:
    reassembler = TCPReassembler()
    assert reassembler.process(tcp_packet(1, b"", 100, flags=0x02)) == []
    first = reassembler.process(tcp_packet(2, b"abc", 101))
    assert [chunk.data for chunk in first] == [b"abc"]

    acknowledgment = tcp_packet(3, b"", 500, flags=0x10, reverse=True)
    acknowledgment.tcp_ack = 104
    assert reassembler.process(acknowledgment) == []

    for packet_id in (4, 5, 6):
        assert reassembler.process(tcp_packet(packet_id, b"X", 103, flags=0x10)) == []
    assert reassembler.overlap_conflicts == 0
    assert reassembler.retransmitted_bytes == 0

    next_data = reassembler.process(tcp_packet(7, b"def", 104))
    assert [chunk.data for chunk in next_data] == [b"def"]
    assert next_data[0].stream_offset == 3


def test_tcp_unacknowledged_or_longer_conflicting_retransmissions_stay_visible() -> None:
    reassembler = TCPReassembler()
    assert reassembler.process(tcp_packet(1, b"", 100, flags=0x02)) == []
    reassembler.process(tcp_packet(2, b"abc", 101))

    # Without peer confirmation, one changed byte is not a proven keepalive.
    assert reassembler.process(tcp_packet(3, b"X", 103, flags=0x10)) == []
    assert reassembler.overlap_conflicts == 1

    acknowledgment = tcp_packet(4, b"", 500, flags=0x10, reverse=True)
    acknowledgment.tcp_ack = 104
    reassembler.process(acknowledgment)
    assert reassembler.process(tcp_packet(5, b"XY", 102, flags=0x10)) == []
    assert reassembler.overlap_conflicts == 2


def test_tcp_consumed_history_is_strictly_bounded() -> None:
    reassembler = TCPReassembler(consumed_history_bytes=4)
    syn = tcp_packet(1, b"", 100, flags=0x02)
    reassembler.process(syn)
    reassembler.process(tcp_packet(2, b"abcdef", 101))

    _flow, direction = syn.flow()
    state = next(iter(reassembler._flows.values())).directions[direction]
    assert state.consumed_history_start == 103
    assert bytes(state.consumed_history) == b"cdef"

    # Differences older than the retained suffix cannot be compared, while a
    # difference inside the retained window remains visible.
    assert reassembler.process(tcp_packet(3, b"XXcdef", 101)) == []
    assert reassembler.overlap_conflicts == 0
    assert reassembler.process(tcp_packet(4, b"XXCdef", 101)) == []
    assert reassembler.overlap_conflicts == 1


def test_tcp_chunk_preserves_all_fragment_packet_ids() -> None:
    reassembler = TCPReassembler()
    packet = tcp_packet(9, b"fragmented", 1000)
    packet.source_packet_ids = (7, 8, 9)

    chunks = reassembler.process(packet)

    assert len(chunks) == 1
    assert chunks[0].packet_ids == (7, 8, 9)


def test_tcp_chunk_has_exact_absolute_provenance_spans() -> None:
    reassembler = TCPReassembler()
    reassembler.process(tcp_packet(1, b"", 1000, flags=0x02))
    reassembler.process(tcp_packet(2, b"world", 1006))
    chunks = reassembler.process(tcp_packet(3, b"hello", 1001))

    assert chunks[0].provenance_spans == (
        ProvenanceSpan(0, 5, (3,)),
        ProvenanceSpan(5, 10, (2,)),
    )

    # Adjacent spans coalesce only when their packet provenance is identical.
    coalesced = TCPReassembler()
    coalesced.process(tcp_packet(4, b"", 2000, flags=0x02))
    later = tcp_packet(5, b"world", 2006)
    later.source_packet_ids = (40, 41)
    coalesced.process(later)
    earlier = tcp_packet(6, b"hello", 2001)
    earlier.source_packet_ids = (40, 41)
    merged = coalesced.process(earlier)[0]
    assert merged.provenance_spans == (
        ProvenanceSpan(0, 10, (40, 41)),
    )


def test_tcp_gap_is_preserved_in_absolute_stream_offset() -> None:
    reassembler = TCPReassembler()
    reassembler.process(tcp_packet(1, b"", 100, flags=0x02))
    reassembler.process(tcp_packet(2, b"tail", 111))
    chunks = reassembler.process(tcp_packet(3, b"", 115, flags=0x11))

    assert len(chunks) == 1
    assert chunks[0].data == b"tail"
    assert chunks[0].stream_offset == 10
    assert chunks[0].completeness == "gapped"
    assert reassembler.gap_bytes == 10


def test_tcp_midstream_and_bidirectional_direction() -> None:
    reassembler = TCPReassembler()
    forward = reassembler.process(tcp_packet(1, b"request", 5000))[0]
    reverse = reassembler.process(
        tcp_packet(2, b"response", 9000, reverse=True)
    )[0]

    assert forward.completeness == "midstream"
    assert reverse.completeness == "midstream"
    assert forward.direction != reverse.direction
    assert forward.stream_offset == reverse.stream_offset == 0


def test_tcp_sequence_wrap() -> None:
    reassembler = TCPReassembler()
    reassembler.process(tcp_packet(1, b"", 0xFFFFFFFD, flags=0x02))
    first = reassembler.process(tcp_packet(2, b"ab", 0xFFFFFFFE))
    second = reassembler.process(tcp_packet(3, b"cd", 0))

    assert first[0].data == b"ab"
    assert second[0].data == b"cd"
    assert second[0].stream_offset == 2


def test_idle_expiry_flushes_pending_gap() -> None:
    reassembler = TCPReassembler(idle_seconds=1)
    reassembler.process(tcp_packet(1, b"", 100, flags=0x02))
    reassembler.process(tcp_packet(2, b"later", 200))
    chunks = reassembler.expire(3_000_000_001)

    assert [chunk.data for chunk in chunks] == [b"later"]
    assert chunks[0].stream_offset == 99
    assert chunks[0].completeness == "gapped"
    assert reassembler.active_flows == 0
    assert reassembler.buffered_bytes == 0


def test_tuple_reuse_gets_distinct_connection_epochs() -> None:
    for terminal_flags in (0x14, 0x11):  # RST+ACK and FIN+ACK
        reassembler = TCPReassembler()
        reassembler.process(tcp_packet(1, b"", 100, flags=0x02))
        first = reassembler.process(tcp_packet(2, b"same", 101))[0]
        reassembler.process(tcp_packet(3, b"", 105, flags=terminal_flags))

        reassembler.process(tcp_packet(4, b"", 500, flags=0x02))
        second = reassembler.process(tcp_packet(5, b"same", 501))[0]

        assert first.data == second.data == b"same"
        assert first.stream_offset == second.stream_offset == 0
        assert first.connection_epoch > 0
        assert second.connection_epoch > first.connection_epoch


def test_fragment_lru_eviction_is_constant_time_and_tracks_recency() -> None:
    reassembler = FragmentReassembler(max_datagrams=2)

    def fragment(packet_id: int, fragment_id: int) -> ParsedPacket:
        return parsed(
            packet_id=packet_id,
            payload=b"A" * 16,
            protocol=17,
            fragment_id=fragment_id,
            more_fragments=True,
            transport_parsed=False,
        )

    reassembler.process(fragment(1, 1))
    reassembler.process(fragment(2, 2))
    reassembler.process(fragment(3, 1))  # touch ID 1, making ID 2 the LRU
    with mock.patch("builtins.min", side_effect=AssertionError("full scan")):
        reassembler.process(fragment(4, 3))

    assert [key.fragment_id for key in reassembler._states] == [1, 3]
    assert reassembler.evicted_datagrams == 1


def test_tcp_lru_eviction_is_constant_time_and_tracks_recency() -> None:
    reassembler = TCPReassembler(max_flows=2)

    def syn(packet_id: int, sport: int) -> ParsedPacket:
        return parsed(
            packet_id=packet_id,
            payload=b"",
            sport=sport,
            sequence=packet_id * 100,
            flags=0x02,
        )

    first = syn(1, 1001)
    second = syn(2, 1002)
    reassembler.process(first)
    reassembler.process(second)
    # A same-ISN SYN retransmission is activity, not a new connection epoch.
    reassembler.process(first)
    with mock.patch("builtins.min", side_effect=AssertionError("full scan")):
        reassembler.process(syn(3, 1003))

    active_ports = {
        endpoint.port
        for _session, flow in reassembler._flows
        for endpoint in (flow.endpoint_a, flow.endpoint_b)
    }
    assert 1001 in active_ports
    assert 1002 not in active_ports
    assert 1003 in active_ports
    assert reassembler.evicted_flows == 1


def test_global_tcp_reassembly_budget_lru_flushes_without_data_loss() -> None:
    reassembler = TCPReassembler(
        max_flows=4,
        max_out_of_order_bytes_per_direction=100,
        max_stream_bytes_per_direction=100,
        max_buffered_bytes=4,
    )

    def packet(
        packet_id: int, sport: int, data: bytes, sequence: int, flags: int = 0x18
    ) -> ParsedPacket:
        return parsed(
            packet_id=packet_id,
            payload=data,
            sport=sport,
            sequence=sequence,
            flags=flags,
        )

    reassembler.process(packet(1, 1001, b"", 100, 0x02))
    assert reassembler.process(packet(2, 1001, b"old1", 110)) == []
    reassembler.process(packet(3, 1002, b"", 200, 0x02))
    flushed = reassembler.process(packet(4, 1002, b"new2", 210))

    assert [chunk.data for chunk in flushed] == [b"old1"]
    assert flushed[0].completeness == "gapped"
    assert flushed[0].connection_epoch == 1
    assert reassembler.buffered_bytes <= 4
    assert reassembler.budget_evicted_flows == 1


def test_global_tcp_pending_segment_budget_uses_visible_lru_eviction() -> None:
    reassembler = TCPReassembler(
        max_flows=4,
        max_out_of_order_bytes_per_direction=100,
        max_stream_bytes_per_direction=100,
        max_buffered_bytes=100,
        max_buffered_segments=2,
    )

    def packet(
        packet_id: int, sport: int, data: bytes, sequence: int, flags: int = 0x18
    ) -> ParsedPacket:
        return parsed(
            packet_id=packet_id,
            payload=data,
            sport=sport,
            sequence=sequence,
            flags=flags,
        )

    for index, sport in enumerate((1001, 1002), start=1):
        reassembler.process(packet(index * 2 - 1, sport, b"", 100, 0x02))
        assert reassembler.process(
            packet(index * 2, sport, bytes((96 + index,)), 110)
        ) == []

    reassembler.process(packet(5, 1003, b"", 100, 0x02))
    flushed = reassembler.process(packet(6, 1003, b"c", 110))

    assert [chunk.data for chunk in flushed] == [b"a"]
    assert flushed[0].completeness == "gapped"
    assert reassembler.buffered_segments == 2
    assert reassembler.peak_buffered_segments == 3
    assert reassembler.budget_evicted_flows == 1
    active_ports = {
        endpoint.port
        for _session, flow in reassembler._flows
        for endpoint in (flow.endpoint_a, flow.endpoint_b)
    }
    assert 1001 not in active_ports
    assert {1002, 1003}.issubset(active_ports)


class ReassemblyTests(unittest.TestCase):
    def test_reassembly_cases(self) -> None:
        cases = (
            test_ipv4_fragments_reassemble_out_of_order,
            test_fragment_conflicting_overlap_discards_datagram,
            test_fragment_expiry_releases_memory,
            test_fragment_adjacent_ranges_coalesce_and_counters_release,
            test_global_fragment_range_budget_evicts_lru_datagram,
            test_global_fragment_provenance_budget_evicts_lru_datagram,
            test_ipv6_fragmentable_extension_is_normalized_after_reassembly,
            test_tcp_out_of_order_reassembly_and_exactly_once,
            test_tcp_consumed_conflicting_retransmission_is_visible_with_new_suffix,
            test_tcp_consumed_history_is_strictly_bounded,
            test_tcp_chunk_has_exact_absolute_provenance_spans,
            test_tcp_gap_is_preserved_in_absolute_stream_offset,
            test_tcp_midstream_and_bidirectional_direction,
            test_tcp_sequence_wrap,
            test_idle_expiry_flushes_pending_gap,
            test_tuple_reuse_gets_distinct_connection_epochs,
            test_fragment_lru_eviction_is_constant_time_and_tracks_recency,
            test_tcp_lru_eviction_is_constant_time_and_tracks_recency,
            test_global_tcp_reassembly_budget_lru_flushes_without_data_loss,
            test_global_tcp_pending_segment_budget_uses_visible_lru_eviction,
        )
        for case in cases:
            with self.subTest(case=case.__name__):
                case()


if __name__ == "__main__":
    unittest.main()
