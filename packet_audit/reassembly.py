"""Bounded IP-fragment and bidirectional TCP stream reconstruction."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field, replace
import time

from .config import AuditConfig
from .models import FlowKey, ParsedPacket, ProvenanceSpan, StreamChunk
from .packets import (
    IPPROTO_TCP,
    normalize_reassembled_ipv6,
    parse_transport,
)


_TCP_FIN = 0x01
_TCP_SYN = 0x02
_TCP_RST = 0x04
_TCP_ACK = 0x10
_SEQ_MODULUS = 1 << 32
_SEQ_HALF = 1 << 31
_DEFAULT_MAX_BUFFERED_SEGMENTS = 65_536
_DEFAULT_CONSUMED_HISTORY_BYTES = 128 * 1024
_DEFAULT_MAX_BUFFERED_FRAGMENT_RANGES = 65_536
_DEFAULT_MAX_BUFFERED_FRAGMENT_PROVENANCE = 65_536


@dataclass(frozen=True, slots=True)
class _FragmentKey:
    session_id: str
    interface: str
    vlan_ids: tuple[int, ...]
    ip_version: int
    src: str
    dst: str
    protocol: int
    fragment_id: int


@dataclass(slots=True)
class _ByteRange:
    start: int
    data: bytearray

    @property
    def end(self) -> int:
        return self.start + len(self.data)


@dataclass(slots=True)
class _FragmentState:
    first_fragment: ParsedPacket | None = None
    ranges: list[_ByteRange] = field(default_factory=list)
    final_end: int | None = None
    last_seen_ns: int = 0
    activity_ns: int = 0
    first_seen_ns: int = 0
    latest_packet_id: int = 0
    truncated: bool = False
    buffered_bytes: int = 0
    source_packet_ids: dict[int, None] = field(default_factory=dict)


def _uncovered_byte_ranges(
    start: int, data: bytes, existing: list[_ByteRange]
) -> list[_ByteRange]:
    """Return parts of a byte range not already represented in ``existing``."""

    pieces = [_ByteRange(start, bytearray(data))] if data else []
    for old in existing:
        remaining: list[_ByteRange] = []
        for piece in pieces:
            if piece.end <= old.start or piece.start >= old.end:
                remaining.append(piece)
                continue
            if piece.start < old.start:
                left_len = old.start - piece.start
                remaining.append(_ByteRange(piece.start, piece.data[:left_len]))
            if piece.end > old.end:
                right_offset = old.end - piece.start
                remaining.append(_ByteRange(old.end, piece.data[right_offset:]))
        pieces = remaining
        if not pieces:
            break
    return pieces


def _merge_adjacent_byte_ranges(ranges: list[_ByteRange]) -> None:
    """Coalesce sorted adjacent ranges without creating more range objects."""

    if len(ranges) < 2:
        return
    ranges.sort(key=lambda item: item.start)
    merged = [ranges[0]]
    for item in ranges[1:]:
        previous = merged[-1]
        if previous.end == item.start:
            previous.data.extend(item.data)
        else:
            merged.append(item)
    ranges[:] = merged


def _has_conflicting_overlap(
    start: int, data: bytes, existing: list[_ByteRange]
) -> bool:
    end = start + len(data)
    for old in existing:
        overlap_start = max(start, old.start)
        overlap_end = min(end, old.end)
        if overlap_start >= overlap_end:
            continue
        new_slice = data[overlap_start - start : overlap_end - start]
        old_slice = old.data[overlap_start - old.start : overlap_end - old.start]
        if new_slice != old_slice:
            return True
    return False


class FragmentReassembler:
    """Reassemble IPv4/IPv6 fragments with strict ambiguity and memory limits."""

    def __init__(
        self,
        config: AuditConfig | None = None,
        *,
        idle_seconds: int | None = None,
        timeout_seconds: int | None = None,
        max_datagrams: int = 4_096,
        max_datagram_bytes: int = 2 * 1024 * 1024,
        max_buffered_bytes: int = 64 * 1024 * 1024,
        max_ranges_per_datagram: int = 4_096,
        max_buffered_ranges: int = _DEFAULT_MAX_BUFFERED_FRAGMENT_RANGES,
        max_buffered_provenance_entries: int = (
            _DEFAULT_MAX_BUFFERED_FRAGMENT_PROVENANCE
        ),
        max_bytes: int | None = None,
    ) -> None:
        if timeout_seconds is not None:
            idle_seconds = timeout_seconds
        if max_bytes is not None:
            max_buffered_bytes = max_bytes
        if (
            max_datagrams < 1
            or max_datagram_bytes < 1
            or max_buffered_bytes < 1
            or max_ranges_per_datagram < 1
            or max_buffered_ranges < 1
            or max_buffered_provenance_entries < 1
        ):
            raise ValueError("fragment reassembly limits must be positive")
        self.idle_ns = int(
            (idle_seconds if idle_seconds is not None else (
                config.fragment_idle_seconds if config else 30
            ))
            * 1_000_000_000
        )
        self.max_datagrams = max_datagrams
        self.max_datagram_bytes = max_datagram_bytes
        self.max_buffered_bytes = max_buffered_bytes
        self.max_ranges_per_datagram = max_ranges_per_datagram
        self.max_buffered_ranges = max_buffered_ranges
        self.max_buffered_provenance_entries = max_buffered_provenance_entries
        self._states: OrderedDict[_FragmentKey, _FragmentState] = OrderedDict()
        self._buffered_bytes = 0
        self._buffered_ranges = 0
        self._buffered_provenance_entries = 0
        self.peak_buffered_ranges = 0
        self.peak_buffered_provenance_entries = 0
        self.expired_datagrams = 0
        self.evicted_datagrams = 0
        self.overlap_conflicts = 0
        self.malformed_fragments = 0

    @property
    def active_datagrams(self) -> int:
        return len(self._states)

    @property
    def buffered_bytes(self) -> int:
        return self._buffered_bytes

    @property
    def buffered_ranges(self) -> int:
        return self._buffered_ranges

    @property
    def buffered_provenance_entries(self) -> int:
        return self._buffered_provenance_entries

    def _key(self, packet: ParsedPacket) -> _FragmentKey:
        assert packet.fragment_id is not None
        return _FragmentKey(
            packet.session_id,
            packet.interface,
            packet.vlan_ids,
            packet.ip_version,
            packet.src,
            packet.dst,
            packet.protocol,
            packet.fragment_id,
        )

    def _discard(self, key: _FragmentKey) -> None:
        state = self._states.pop(key, None)
        if state is not None:
            self._buffered_bytes -= state.buffered_bytes
            self._buffered_ranges -= len(state.ranges)
            self._buffered_provenance_entries -= len(state.source_packet_ids)

    def _evict_to_limits(self) -> None:
        while (
            len(self._states) > self.max_datagrams
            or self._buffered_bytes > self.max_buffered_bytes
            or self._buffered_ranges > self.max_buffered_ranges
            or self._buffered_provenance_entries
            > self.max_buffered_provenance_entries
        ):
            oldest_key = next(iter(self._states))
            self._discard(oldest_key)
            self.evicted_datagrams += 1

    def process(self, packet: ParsedPacket) -> ParsedPacket | None:
        """Return a transport-ready datagram, or ``None`` while incomplete."""

        if packet.fragment_id is None or (
            packet.fragment_offset == 0 and not packet.more_fragments
        ):
            return packet

        offset = packet.fragment_offset
        data = packet.network_payload
        if (
            offset < 0
            or offset + len(data) > self.max_datagram_bytes
            or (packet.more_fragments and (not data or len(data) % 8 != 0))
        ):
            self.malformed_fragments += 1
            if packet.fragment_id is not None:
                self._discard(self._key(packet))
            return None

        key = self._key(packet)
        state = self._states.get(key)
        if state is None:
            state = _FragmentState(
                last_seen_ns=packet.timestamp_ns,
                activity_ns=time.monotonic_ns(),
                first_seen_ns=packet.timestamp_ns,
                latest_packet_id=packet.packet_id,
            )
            self._states[key] = state
        else:
            self._states.move_to_end(key)

        state.last_seen_ns = max(state.last_seen_ns, packet.timestamp_ns)
        state.activity_ns = time.monotonic_ns()
        state.latest_packet_id = max(state.latest_packet_id, packet.packet_id)
        state.truncated = state.truncated or packet.truncated
        if offset == 0 and state.first_fragment is None:
            state.first_fragment = packet

        final_end = offset + len(data)
        if not packet.more_fragments:
            if state.final_end is not None and state.final_end != final_end:
                self.overlap_conflicts += 1
                self._discard(key)
                return None
            state.final_end = final_end

        if _has_conflicting_overlap(offset, data, state.ranges):
            # RFC 5722 requires dropping ambiguous IPv6 fragments.  Applying
            # the same safe rule to IPv4 avoids IDS-evasion differences.
            self.overlap_conflicts += 1
            self._discard(key)
            return None

        additions = _uncovered_byte_ranges(offset, data, state.ranges)
        if additions:
            contributing_ids = packet.source_packet_ids or (packet.packet_id,)
            for packet_id in contributing_ids:
                if packet_id not in state.source_packet_ids:
                    state.source_packet_ids[packet_id] = None
                    self._buffered_provenance_entries += 1
        prior_range_count = len(state.ranges)
        state.ranges.extend(additions)
        _merge_adjacent_byte_ranges(state.ranges)
        self._buffered_ranges += len(state.ranges) - prior_range_count
        self.peak_buffered_ranges = max(
            self.peak_buffered_ranges, self._buffered_ranges
        )
        self.peak_buffered_provenance_entries = max(
            self.peak_buffered_provenance_entries,
            self._buffered_provenance_entries,
        )
        added = sum(len(item.data) for item in additions)
        state.buffered_bytes += added
        self._buffered_bytes += added
        if len(state.ranges) > self.max_ranges_per_datagram:
            self._discard(key)
            self.evicted_datagrams += 1
            return None
        self._evict_to_limits()
        if key not in self._states:
            return None

        if (
            state.first_fragment is None
            or state.final_end is None
            or state.truncated
        ):
            return None

        cursor = 0
        assembled: list[bytes] = []
        for item in state.ranges:
            if item.start != cursor:
                return None
            if item.end > state.final_end:
                self.overlap_conflicts += 1
                self._discard(key)
                return None
            assembled.append(item.data)
            cursor = item.end
            if cursor == state.final_end:
                break
        if cursor != state.final_end:
            return None

        payload = b"".join(assembled)
        base = state.first_fragment
        completed = replace(
            base,
            packet_id=state.latest_packet_id,
            timestamp_ns=state.last_seen_ns,
            network_payload=payload,
            truncated=False,
            fragment_id=None,
            fragment_offset=0,
            more_fragments=False,
            transport_parsed=False,
            sport=0,
            dport=0,
            tcp_seq=0,
            tcp_ack=0,
            tcp_flags=0,
            transport_payload=b"",
            source_packet_ids=tuple(state.source_packet_ids),
        )
        self._discard(key)
        completed = normalize_reassembled_ipv6(completed)
        return parse_transport(completed)

    def expire(self, now_ns: int | None = None) -> int:
        """Discard stale incomplete datagrams and return the number removed."""

        explicit_capture_clock = now_ns is not None
        now = time.monotonic_ns() if now_ns is None else now_ns
        if explicit_capture_clock:
            # Capture timestamps can arrive out of order in replay, so an
            # explicit capture-clock expiry retains the original full semantic
            # check rather than assuming LRU order also sorts timestamps.
            stale = [
                key
                for key, state in self._states.items()
                if now - state.last_seen_ns >= self.idle_ns
            ]
        else:
            stale = []
            for key, state in self._states.items():
                if now - state.activity_ns < self.idle_ns:
                    break
                stale.append(key)
        for key in stale:
            self._discard(key)
        self.expired_datagrams += len(stale)
        return len(stale)


@dataclass(slots=True)
class _TcpSegment:
    start: int
    data: bytes
    packet_ids: tuple[int, ...]
    timestamp_ns: int

    @property
    def end(self) -> int:
        return self.start + len(self.data)


@dataclass(slots=True)
class _DirectionState:
    connection_epoch: int = 0
    next_seq: int | None = None
    stream_offset: int = 0
    midstream: bool = False
    had_gap: bool = False
    syn_seq: int | None = None
    pending: list[_TcpSegment] = field(default_factory=list)
    pending_bytes: int = 0
    consumed_history_start: int | None = None
    consumed_history: bytearray = field(default_factory=bytearray)
    peer_acked_seq: int | None = None
    last_seen_ns: int = 0
    closed: bool = False


@dataclass(slots=True)
class _FlowState:
    flow: FlowKey
    connection_epoch: int
    directions: tuple[_DirectionState, _DirectionState] = field(
        default_factory=lambda: (_DirectionState(), _DirectionState())
    )
    last_seen_ns: int = 0
    activity_ns: int = 0


def _unwrap_sequence(sequence: int, reference: int) -> int:
    """Map a TCP 32-bit sequence number into the epoch nearest ``reference``."""

    candidate = (reference & ~0xFFFFFFFF) | (sequence & 0xFFFFFFFF)
    if candidate - reference > _SEQ_HALF:
        candidate -= _SEQ_MODULUS
    elif reference - candidate > _SEQ_HALF:
        candidate += _SEQ_MODULUS
    return candidate


def _tcp_uncovered_segments(
    start: int,
    data: bytes,
    packet_ids: tuple[int, ...],
    timestamp_ns: int,
    existing: list[_TcpSegment],
) -> list[_TcpSegment]:
    pieces = [_TcpSegment(start, data, packet_ids, timestamp_ns)] if data else []
    for old in existing:
        remaining: list[_TcpSegment] = []
        for piece in pieces:
            if piece.end <= old.start or piece.start >= old.end:
                remaining.append(piece)
                continue
            if piece.start < old.start:
                left_len = old.start - piece.start
                remaining.append(
                    _TcpSegment(
                        piece.start,
                        piece.data[:left_len],
                        piece.packet_ids,
                        piece.timestamp_ns,
                    )
                )
            if piece.end > old.end:
                right_offset = old.end - piece.start
                remaining.append(
                    _TcpSegment(
                        old.end,
                        piece.data[right_offset:],
                        piece.packet_ids,
                        piece.timestamp_ns,
                    )
                )
        pieces = remaining
        if not pieces:
            break
    return pieces


class TCPReassembler:
    """Flow-affine, bounded TCP byte-stream reconstruction.

    Each byte is emitted at most once.  Sequence discontinuities advance the
    stream offset, preventing detectors from accidentally matching across a
    missing region.  Repeated credentials at later offsets remain distinct and
    are never suppressed here.
    """

    def __init__(
        self,
        config: AuditConfig | None = None,
        *,
        idle_seconds: int | None = None,
        idle_timeout_seconds: int | None = None,
        max_flows: int | None = None,
        max_out_of_order_bytes_per_direction: int | None = None,
        max_stream_bytes_per_direction: int | None = None,
        max_buffered_bytes: int | None = None,
        max_buffered_segments: int | None = None,
        consumed_history_bytes: int | None = None,
        max_segments_per_direction: int = 4_096,
        epoch_namespace: int = 0,
    ) -> None:
        if idle_timeout_seconds is not None:
            idle_seconds = idle_timeout_seconds
        self.idle_ns = int(
            (idle_seconds if idle_seconds is not None else (
                config.flow_idle_seconds if config else 300
            ))
            * 1_000_000_000
        )
        self.max_flows = int(
            max_flows if max_flows is not None else (
                config.max_flows_per_worker if config else 20_000
            )
        )
        self.max_out_of_order = int(
            max_out_of_order_bytes_per_direction
            if max_out_of_order_bytes_per_direction is not None
            else (
                config.max_out_of_order_bytes_per_direction
                if config
                else 512 * 1024
            )
        )
        # This bounds queued, not lifetime, stream bytes.  Exceeding it forces
        # a visible gapped flush; long-lived streams continue to be analysed.
        self.max_stream_bytes_per_direction = int(
            max_stream_bytes_per_direction
            if max_stream_bytes_per_direction is not None
            else (
                config.max_stream_bytes_per_direction
                if config
                else 2 * 1024 * 1024
            )
        )
        self.max_pending_per_direction = min(
            self.max_out_of_order, self.max_stream_bytes_per_direction
        )
        self.max_buffered_bytes = int(
            max_buffered_bytes
            if max_buffered_bytes is not None
            else (
                config.max_reassembly_bytes_per_worker
                if config
                else 128 * 1024 * 1024
            )
        )
        self.max_buffered_segments = int(
            max_buffered_segments
            if max_buffered_segments is not None
            else _DEFAULT_MAX_BUFFERED_SEGMENTS
        )
        self.consumed_history_bytes = int(
            consumed_history_bytes
            if consumed_history_bytes is not None
            else (
                config.detector_overlap_bytes
                if config
                else _DEFAULT_CONSUMED_HISTORY_BYTES
            )
        )
        self.max_segments_per_direction = max_segments_per_direction
        if (
            self.idle_ns < 0
            or self.max_flows < 1
            or self.max_out_of_order < 1
            or self.max_stream_bytes_per_direction < 1
            or self.max_buffered_bytes < 1
            or self.max_buffered_segments < 1
            or self.consumed_history_bytes < 1
            or self.max_segments_per_direction < 1
        ):
            raise ValueError("invalid TCP reassembly limits")
        self._flows: OrderedDict[tuple[str, FlowKey], _FlowState] = OrderedDict()
        if epoch_namespace < 0:
            raise ValueError("epoch_namespace cannot be negative")
        self._next_connection_epoch = (int(epoch_namespace) << 32) | 1
        self._buffered_bytes = 0
        self._buffered_segments = 0
        self._peak_buffered_segments = 0
        self.evicted_flows = 0
        self.budget_evicted_flows = 0
        self.expired_flows = 0
        self.retransmitted_bytes = 0
        self.overlap_conflicts = 0
        self.gap_bytes = 0

    @property
    def active_flows(self) -> int:
        return len(self._flows)

    @property
    def active_flow_count(self) -> int:
        return len(self._flows)

    @property
    def buffered_bytes(self) -> int:
        return self._buffered_bytes

    @property
    def buffered_segments(self) -> int:
        return self._buffered_segments

    @property
    def peak_buffered_segments(self) -> int:
        return self._peak_buffered_segments

    def _remove_flow(self, key: tuple[str, FlowKey]) -> _FlowState | None:
        state = self._flows.pop(key, None)
        if state is not None:
            pending = sum(direction.pending_bytes for direction in state.directions)
            pending_segments = sum(
                len(direction.pending) for direction in state.directions
            )
            self._buffered_bytes -= pending
            self._buffered_segments -= pending_segments
        return state

    def _remember_consumed(
        self, state: _DirectionState, start: int, data: bytes
    ) -> None:
        """Retain a bounded suffix of bytes already emitted for overlap checks."""

        if not data:
            return
        history = state.consumed_history
        history_end = (
            None
            if state.consumed_history_start is None
            else state.consumed_history_start + len(history)
        )
        if history_end != start:
            history.clear()
            state.consumed_history_start = start
        history.extend(data)
        excess = len(history) - self.consumed_history_bytes
        if excess > 0:
            del history[:excess]
            if state.consumed_history_start is not None:
                state.consumed_history_start += excess

    @staticmethod
    def _conflicts_with_consumed(
        state: _DirectionState, start: int, data: bytes
    ) -> bool:
        """Compare the retained portion of a retransmission to emitted bytes."""

        history_start = state.consumed_history_start
        history = state.consumed_history
        if history_start is None or not history or not data:
            return False
        overlap_start = max(start, history_start)
        overlap_end = min(start + len(data), history_start + len(history))
        if overlap_start >= overlap_end:
            return False
        retransmitted = data[
            overlap_start - start : overlap_end - start
        ]
        consumed = history[
            overlap_start - history_start : overlap_end - history_start
        ]
        return retransmitted != consumed

    def _drain(
        self,
        state: _DirectionState,
        flow: FlowKey,
        direction: int,
        *,
        forced_gap: bool = False,
    ) -> list[StreamChunk]:
        if state.next_seq is None or not state.pending:
            return []

        parts: list[bytes] = []
        packet_ids: list[int] = []
        provenance_spans: list[ProvenanceSpan] = []
        timestamps: list[int] = []
        start_offset = state.stream_offset
        while state.pending:
            segment = state.pending[0]
            if segment.end <= state.next_seq:
                state.pending.pop(0)
                state.pending_bytes -= len(segment.data)
                self._buffered_bytes -= len(segment.data)
                self._buffered_segments -= 1
                self.retransmitted_bytes += len(segment.data)
                continue
            if segment.start > state.next_seq:
                break
            state.pending.pop(0)
            state.pending_bytes -= len(segment.data)
            self._buffered_bytes -= len(segment.data)
            self._buffered_segments -= 1
            trim = max(0, state.next_seq - segment.start)
            if trim:
                self.retransmitted_bytes += trim
            new_data = segment.data[trim:]
            if not new_data:
                continue
            parts.append(new_data)
            for packet_id in segment.packet_ids:
                if packet_id not in packet_ids:
                    packet_ids.append(packet_id)
            timestamps.append(segment.timestamp_ns)
            span = ProvenanceSpan(
                stream_start=state.stream_offset,
                stream_end=state.stream_offset + len(new_data),
                packet_ids=segment.packet_ids,
            )
            if (
                provenance_spans
                and provenance_spans[-1].stream_end == span.stream_start
                and provenance_spans[-1].packet_ids == span.packet_ids
                and provenance_spans[-1].packet_ids_complete
                == span.packet_ids_complete
            ):
                previous = provenance_spans[-1]
                provenance_spans[-1] = ProvenanceSpan(
                    stream_start=previous.stream_start,
                    stream_end=span.stream_end,
                    packet_ids=previous.packet_ids,
                    packet_ids_complete=previous.packet_ids_complete,
                )
            else:
                provenance_spans.append(span)
            self._remember_consumed(state, state.next_seq, new_data)
            state.next_seq += len(new_data)
            state.stream_offset += len(new_data)

        if not parts:
            return []
        completeness = (
            "gapped" if forced_gap or state.had_gap else (
                "midstream" if state.midstream else "complete"
            )
        )
        return [
            StreamChunk(
                flow=flow,
                direction=direction,
                stream_offset=start_offset,
                data=b"".join(parts),
                packet_ids=tuple(packet_ids),
                first_timestamp_ns=min(timestamps),
                last_timestamp_ns=max(timestamps),
                connection_epoch=state.connection_epoch,
                completeness=completeness,
                provenance_spans=tuple(provenance_spans),
            )
        ]

    def _skip_to_next_segment(
        self, state: _DirectionState, flow: FlowKey, direction: int
    ) -> list[StreamChunk]:
        if state.next_seq is None or not state.pending:
            return []
        first = state.pending[0]
        if first.start > state.next_seq:
            gap = first.start - state.next_seq
            state.next_seq = first.start
            state.stream_offset += gap
            state.had_gap = True
            self.gap_bytes += gap
        return self._drain(state, flow, direction, forced_gap=True)

    def _flush_direction(
        self, state: _DirectionState, flow: FlowKey, direction: int
    ) -> list[StreamChunk]:
        chunks: list[StreamChunk] = []
        while state.pending:
            before = len(state.pending)
            chunks.extend(self._drain(state, flow, direction))
            if state.pending and len(state.pending) == before:
                chunks.extend(self._skip_to_next_segment(state, flow, direction))
        return chunks

    def _evict_oldest(self, *, budget: bool = False) -> list[StreamChunk]:
        if not self._flows:
            return []
        key = next(iter(self._flows))
        state = self._flows[key]
        chunks: list[StreamChunk] = []
        for direction, directional in enumerate(state.directions):
            chunks.extend(self._flush_direction(directional, state.flow, direction))
        self._remove_flow(key)
        self.evicted_flows += 1
        if budget:
            self.budget_evicted_flows += 1
        return chunks

    def process(self, packet: ParsedPacket) -> list[StreamChunk]:
        """Accept one parsed TCP packet and return newly contiguous bytes."""

        if packet.protocol != IPPROTO_TCP or not packet.transport_parsed:
            return []
        flow, direction = packet.flow()
        key = (packet.session_id, flow)
        chunks: list[StreamChunk] = []
        state = self._flows.get(key)

        syn = bool(packet.tcp_flags & _TCP_SYN)
        ack = bool(packet.tcp_flags & _TCP_ACK)
        if syn and not ack and state is not None:
            prior = state.directions[direction]
            if prior.syn_seq != packet.tcp_seq or prior.closed:
                for index, directional in enumerate(state.directions):
                    chunks.extend(self._flush_direction(directional, flow, index))
                self._remove_flow(key)
                state = None

        if state is not None:
            self._flows.move_to_end(key)

        if state is None:
            while len(self._flows) >= self.max_flows:
                chunks.extend(self._evict_oldest())
            connection_epoch = self._next_connection_epoch
            self._next_connection_epoch += 1
            state = _FlowState(
                flow=flow,
                connection_epoch=connection_epoch,
                last_seen_ns=packet.timestamp_ns,
                activity_ns=time.monotonic_ns(),
            )
            for item in state.directions:
                item.connection_epoch = connection_epoch
            self._flows[key] = state

        state.last_seen_ns = max(state.last_seen_ns, packet.timestamp_ns)
        state.activity_ns = time.monotonic_ns()
        directional = state.directions[direction]
        directional.last_seen_ns = max(directional.last_seen_ns, packet.timestamp_ns)

        if ack:
            opposite = state.directions[1 - direction]
            if opposite.next_seq is not None:
                peer_ack = _unwrap_sequence(packet.tcp_ack, opposite.next_seq)
                if opposite.peer_acked_seq is None or peer_ack > opposite.peer_acked_seq:
                    opposite.peer_acked_seq = peer_ack

        raw_payload_sequence = (packet.tcp_seq + (1 if syn else 0)) & 0xFFFFFFFF
        if directional.next_seq is None:
            if syn:
                directional.syn_seq = packet.tcp_seq
                directional.next_seq = raw_payload_sequence
                directional.midstream = False
            elif packet.transport_payload:
                directional.next_seq = raw_payload_sequence
                directional.midstream = True

        if syn and directional.syn_seq is None:
            directional.syn_seq = packet.tcp_seq

        payload = packet.transport_payload
        if payload and directional.next_seq is not None:
            start = _unwrap_sequence(raw_payload_sequence, directional.next_seq)
            end = start + len(payload)
            if (
                len(payload) == 1
                and ack
                and not packet.tcp_flags & (_TCP_SYN | _TCP_FIN | _TCP_RST)
                and start == directional.next_seq - 1
                and directional.peer_acked_seq is not None
                and directional.peer_acked_seq >= directional.next_seq
            ):
                # RFC 9293 permits an idle TCP keepalive at SND.NXT-1 with
                # one garbage octet. The peer has already acknowledged this
                # byte, so it cannot replace application data or create an
                # actual conflicting retransmission.
                return chunks
            if (
                start < directional.next_seq
                and self._conflicts_with_consumed(directional, start, payload)
            ):
                self.overlap_conflicts += 1
            if end <= directional.next_seq:
                self.retransmitted_bytes += len(payload)
            else:
                if start < directional.next_seq:
                    trim = directional.next_seq - start
                    self.retransmitted_bytes += trim
                    payload = payload[trim:]
                    start = directional.next_seq

                # Count conflicting retransmission overlap for diagnostics, but
                # preserve first-seen bytes so each stream position is emitted
                # exactly once and the parser cannot be desynchronised.
                for old in directional.pending:
                    overlap_start = max(start, old.start)
                    overlap_end = min(start + len(payload), old.end)
                    if overlap_start < overlap_end:
                        new_slice = payload[
                            overlap_start - start : overlap_end - start
                        ]
                        old_slice = old.data[
                            overlap_start - old.start : overlap_end - old.start
                        ]
                        if new_slice != old_slice:
                            self.overlap_conflicts += 1

                additions = _tcp_uncovered_segments(
                    start,
                    payload,
                    packet.source_packet_ids or (packet.packet_id,),
                    packet.timestamp_ns,
                    directional.pending,
                )
                covered = len(payload) - sum(len(item.data) for item in additions)
                self.retransmitted_bytes += covered
                directional.pending.extend(additions)
                directional.pending.sort(key=lambda item: item.start)
                added = sum(len(item.data) for item in additions)
                directional.pending_bytes += added
                self._buffered_bytes += added
                self._buffered_segments += len(additions)
                self._peak_buffered_segments = max(
                    self._peak_buffered_segments, self._buffered_segments
                )
                chunks.extend(self._drain(directional, flow, direction))

                if (
                    directional.pending_bytes > self.max_pending_per_direction
                    or len(directional.pending) > self.max_segments_per_direction
                ):
                    while (
                        directional.pending_bytes > self.max_pending_per_direction
                        or len(directional.pending) > self.max_segments_per_direction
                    ):
                        forced = self._skip_to_next_segment(directional, flow, direction)
                        if not forced:
                            break
                        chunks.extend(forced)

                while (
                    (
                        self._buffered_bytes > self.max_buffered_bytes
                        or self._buffered_segments > self.max_buffered_segments
                    )
                    and self._flows
                ):
                    chunks.extend(self._evict_oldest(budget=True))
                if key not in self._flows:
                    return chunks

        if packet.tcp_flags & (_TCP_FIN | _TCP_RST):
            chunks.extend(self._flush_direction(directional, flow, direction))
            directional.closed = True

        if packet.tcp_flags & _TCP_RST or all(
            item.closed for item in state.directions
        ):
            # Flush the opposite direction too before deleting the tuple epoch.
            for index, item in enumerate(state.directions):
                if item is not directional:
                    chunks.extend(self._flush_direction(item, flow, index))
            self._remove_flow(key)
        return chunks

    def expire(self, now_ns: int | None = None) -> list[StreamChunk]:
        """Flush and evict idle flows, preserving queued bytes as gapped chunks."""

        explicit_capture_clock = now_ns is not None
        now = time.monotonic_ns() if now_ns is None else now_ns
        if explicit_capture_clock:
            stale = [
                key
                for key, state in self._flows.items()
                if now - state.last_seen_ns >= self.idle_ns
            ]
        else:
            stale = []
            for key, state in self._flows.items():
                if now - state.activity_ns < self.idle_ns:
                    break
                stale.append(key)
        chunks: list[StreamChunk] = []
        for key in stale:
            state = self._flows[key]
            for direction, directional in enumerate(state.directions):
                chunks.extend(self._flush_direction(directional, state.flow, direction))
            self._remove_flow(key)
        self.expired_flows += len(stale)
        return chunks

    def flush_all(self, completeness: str | None = None) -> list[StreamChunk]:
        chunks: list[StreamChunk] = []
        for key in list(self._flows):
            state = self._flows[key]
            for direction, directional in enumerate(state.directions):
                emitted = self._flush_direction(directional, state.flow, direction)
                if completeness is not None:
                    for chunk in emitted:
                        chunk.completeness = completeness  # StreamChunk is mutable.
                chunks.extend(emitted)
            self._remove_flow(key)
        return chunks


# Common spelling variants for integration code.
TcpReassembler = TCPReassembler
TCPStreamReassembler = TCPReassembler
