"""Flow-affine reconstruction and detection worker process."""

from __future__ import annotations

from dataclasses import asdict
import os
import queue
import time
import traceback

from .config import AuditConfig
from .detectors import SensitiveDetector
from .models import ParsedPacket, STOP_SENTINEL, WorkerHeartbeat
from .packets import PacketDecodeError, parse_transport
from .process_signals import ignore_windows_child_interrupts
from .reassembly import FragmentReassembler, TCPReassembler


def _queue_depth(input_queue) -> int | None:
    try:
        return input_queue.qsize()
    except (NotImplementedError, AttributeError, OSError):
        return None


def _emit_operation(operational_queue, record: dict) -> bool:
    try:
        operational_queue.put_nowait(record)
        return True
    except queue.Full:
        # Operational telemetry must never block traffic analysis. The missing
        # telemetry is reflected by the supervisor's queue-pressure counters.
        return False


def _release_reserved_queue_bytes(queued_byte_counter, reserved_bytes: int) -> None:
    if queued_byte_counter is None or reserved_bytes <= 0:
        return
    lock = queued_byte_counter.get_lock()
    with lock:
        queued_byte_counter.value = max(
            0, int(queued_byte_counter.value) - int(reserved_bytes)
        )


def worker_process(
    worker_id: int,
    input_queue,
    finding_queue,
    operational_queue,
    config: AuditConfig,
    session_id: str,
    control_queue=None,
    epoch_namespace: int = 0,
    queued_byte_counter=None,
) -> None:
    ignore_windows_child_interrupts()
    fragments = FragmentReassembler(
        timeout_seconds=config.fragment_idle_seconds,
        max_datagrams=max(1024, config.max_flows_per_worker // 4),
        max_bytes=max(
            1_048_576,
            min(config.max_reassembly_bytes_per_worker // 4, 64 * 1024 * 1024),
        ),
    )
    tcp = TCPReassembler(
        idle_timeout_seconds=config.flow_idle_seconds,
        max_flows=config.max_flows_per_worker,
        max_stream_bytes_per_direction=config.max_stream_bytes_per_direction,
        max_out_of_order_bytes_per_direction=config.max_out_of_order_bytes_per_direction,
        max_buffered_bytes=config.max_reassembly_bytes_per_worker,
        epoch_namespace=epoch_namespace,
    )
    detector = SensitiveDetector(
        session_id=session_id,
        overlap_bytes=config.detector_overlap_bytes,
        generic_secret_scan=config.generic_secret_scan,
        credit_card_scan=config.credit_card_scan,
        extra_sensitive_field_names=config.extra_sensitive_field_names,
        max_flows=config.max_flows_per_worker,
        max_retained_bytes=config.max_detector_bytes_per_worker,
    )
    packets = 0
    bytes_seen = 0
    findings = 0
    parser_errors = 0
    truncated_packets = 0
    truncated_missing_bytes = 0
    operational_drops = 0
    last_heartbeat = time.monotonic()

    def control(state: str, **fields) -> None:
        if control_queue is None:
            return
        control_queue.put(
            {
                "role": "worker",
                "state": state,
                "worker_id": worker_id,
                "pid": os.getpid(),
                "epoch_namespace": epoch_namespace,
                "monotonic_ns": time.monotonic_ns(),
                "packets": packets,
                "findings": findings,
                "parser_errors": parser_errors,
                "truncated_packets": truncated_packets,
                "truncated_missing_bytes": truncated_missing_bytes,
                **fields,
            }
        )

    control("ready")
    if not _emit_operation(
        operational_queue,
        {
            "event": "worker_started",
            "timestamp_ns": time.time_ns(),
            "worker_id": worker_id,
            "pid": os.getpid(),
            "session_id": session_id,
        },
    ):
        operational_drops += 1

    stopping = False
    while not stopping:
        now = time.monotonic()
        try:
            item = input_queue.get(timeout=min(1.0, config.heartbeat_seconds))
        except queue.Empty:
            item = None

        if item == STOP_SENTINEL:
            stopping = True
        else:
            reserved_queue_bytes = 0
            if (
                isinstance(item, tuple)
                and len(item) == 2
                and isinstance(item[0], list)
                and isinstance(item[1], int)
            ):
                packet_batch = item[0]
                reserved_queue_bytes = max(0, item[1])
            else:
                packet_batch = item if isinstance(item, list) else [item]
            try:
                for packet_item in packet_batch:
                    if not isinstance(packet_item, ParsedPacket):
                        continue
                    try:
                        item = packet_item
                        packets += 1
                        bytes_seen += item.captured_length
                        if item.truncated:
                            truncated_packets += 1
                            truncated_missing_bytes += max(
                                0, item.wire_length - item.captured_length
                            )
                        packet = item
                        if packet.fragment_id is not None:
                            packet = fragments.process(packet)
                            if packet is None:
                                packet = None
                        if packet is not None and not packet.transport_parsed:
                            packet = parse_transport(packet)
                        if packet is not None and packet.truncated and not item.truncated:
                            truncated_packets += 1
                            truncated_missing_bytes += max(
                                0, packet.wire_length - packet.captured_length
                            )
                        emitted = []
                        if packet is not None and packet.transport_parsed:
                            if packet.protocol == 6:
                                for chunk in tcp.process(packet):
                                    emitted.extend(detector.process_stream(chunk))
                            elif packet.protocol == 17:
                                emitted.extend(detector.process_datagram(packet))
                        for finding in emitted:
                            finding_queue.put(finding)
                            findings += 1
                    except PacketDecodeError as exc:  # isolate malformed captured packets
                        parser_errors += 1
                        if not _emit_operation(
                            operational_queue,
                            {
                                "event": "worker_packet_error",
                                "timestamp_ns": time.time_ns(),
                                "worker_id": worker_id,
                                "packet_id": item.packet_id,
                                "exception": type(exc).__name__,
                                "message": str(exc)[:500],
                                "traceback": traceback.format_exc(limit=8),
                            },
                        ):
                            operational_drops += 1
                    except Exception as exc:
                        _emit_operation(
                            operational_queue,
                            {
                                "event": "worker_fatal_error",
                                "timestamp_ns": time.time_ns(),
                                "worker_id": worker_id,
                                "packet_id": item.packet_id,
                                "exception": type(exc).__name__,
                                "message": str(exc)[:500],
                                "traceback": traceback.format_exc(limit=12),
                            },
                        )
                        control(
                            "fatal",
                            packet_id=item.packet_id,
                            exception=type(exc).__name__,
                            message=str(exc)[:500],
                        )
                        raise
            finally:
                _release_reserved_queue_bytes(
                    queued_byte_counter, reserved_queue_bytes
                )

        now = time.monotonic()
        if now - last_heartbeat >= config.heartbeat_seconds:
            fragment_expired = fragments.expire()
            expired_chunks = tcp.expire()
            detector_expired = detector.expire(
                cutoff_activity_ns=(
                    time.monotonic_ns()
                    - config.flow_idle_seconds * 1_000_000_000
                )
            )
            for chunk in expired_chunks:
                try:
                    for finding in detector.process_stream(chunk):
                        finding_queue.put(finding)
                        findings += 1
                except Exception as exc:
                    _emit_operation(
                        operational_queue,
                        {
                            "event": "expired_flow_detection_fatal",
                            "timestamp_ns": time.time_ns(),
                            "worker_id": worker_id,
                            "flow_id": chunk.flow.stable_text(),
                            "exception": type(exc).__name__,
                            "message": str(exc)[:500],
                        },
                    )
                    control(
                        "fatal",
                        exception=type(exc).__name__,
                        message=str(exc)[:500],
                    )
                    raise
            detector_snapshot = detector.stats()
            detector_attempts = detector_snapshot.get("attempts", 0)
            detector_errors = detector_snapshot.get("parser_errors", 0)
            if (
                detector_errors >= 100
                and detector_errors * 10 >= max(1, detector_attempts)
            ):
                _emit_operation(
                    operational_queue,
                    {
                        "event": "detector_error_circuit_breaker",
                        "timestamp_ns": time.time_ns(),
                        "worker_id": worker_id,
                        "detector_attempts": detector_attempts,
                        "detector_parser_errors": detector_errors,
                    },
                )
                control(
                    "fatal",
                    exception="DetectorErrorCircuitBreaker",
                    detector=detector_snapshot,
                )
                raise RuntimeError(
                    "detector parser errors exceeded 100 and 10% of scan attempts"
                )
            if fragment_expired or expired_chunks or detector_expired:
                if not _emit_operation(
                    operational_queue,
                    {
                        "event": "state_expired",
                        "timestamp_ns": time.time_ns(),
                        "worker_id": worker_id,
                        "fragment_datagrams": fragment_expired,
                        "stream_chunks": len(expired_chunks),
                        "detector_flows": detector_expired,
                    },
                ):
                    operational_drops += 1
            heartbeat = WorkerHeartbeat(
                worker_id=worker_id,
                timestamp_ns=time.time_ns(),
                packets=packets,
                bytes_seen=bytes_seen,
                active_flows=tcp.active_flow_count,
                reassembly_bytes=tcp.buffered_bytes,
                findings=findings,
                parser_errors=parser_errors,
                queue_depth=_queue_depth(input_queue),
            )
            if not _emit_operation(
                operational_queue,
                {
                    "event": "worker_heartbeat",
                    **asdict(heartbeat),
                    "operational_queue_drops": operational_drops,
                    "detector": detector_snapshot,
                    "tcp_retransmitted_bytes": tcp.retransmitted_bytes,
                    "tcp_overlap_conflicts": tcp.overlap_conflicts,
                    "tcp_gap_bytes": tcp.gap_bytes,
                    "tcp_evicted_flows": tcp.evicted_flows,
                    "tcp_budget_evicted_flows": tcp.budget_evicted_flows,
                    "tcp_buffered_segments": tcp.buffered_segments,
                    "tcp_peak_buffered_segments": tcp.peak_buffered_segments,
                    "tcp_max_buffered_segments": tcp.max_buffered_segments,
                    "fragment_active_datagrams": fragments.active_datagrams,
                    "fragment_buffered_bytes": fragments.buffered_bytes,
                    "fragment_buffered_ranges": fragments.buffered_ranges,
                    "fragment_peak_buffered_ranges": fragments.peak_buffered_ranges,
                    "fragment_max_buffered_ranges": fragments.max_buffered_ranges,
                    "fragment_buffered_provenance_entries": fragments.buffered_provenance_entries,
                    "fragment_peak_buffered_provenance_entries": fragments.peak_buffered_provenance_entries,
                    "fragment_max_buffered_provenance_entries": fragments.max_buffered_provenance_entries,
                    "fragment_overlap_conflicts": fragments.overlap_conflicts,
                    "fragment_evicted_datagrams": fragments.evicted_datagrams,
                },
            ):
                operational_drops += 1
            control(
                "heartbeat",
                active_flows=tcp.active_flow_count,
                reassembly_bytes=tcp.buffered_bytes,
                operational_queue_drops=operational_drops,
                tcp_gap_bytes=tcp.gap_bytes,
                tcp_overlap_conflicts=tcp.overlap_conflicts,
                tcp_evicted_flows=tcp.evicted_flows,
                tcp_budget_evicted_flows=tcp.budget_evicted_flows,
                tcp_buffered_segments=tcp.buffered_segments,
                tcp_peak_buffered_segments=tcp.peak_buffered_segments,
                tcp_max_buffered_segments=tcp.max_buffered_segments,
                fragment_evicted_datagrams=fragments.evicted_datagrams,
                fragment_expired_datagrams=fragments.expired_datagrams,
                fragment_overlap_conflicts=fragments.overlap_conflicts,
                fragment_malformed=fragments.malformed_fragments,
                fragment_buffered_ranges=fragments.buffered_ranges,
                fragment_peak_buffered_ranges=fragments.peak_buffered_ranges,
                fragment_max_buffered_ranges=fragments.max_buffered_ranges,
                fragment_buffered_provenance_entries=fragments.buffered_provenance_entries,
                fragment_peak_buffered_provenance_entries=fragments.peak_buffered_provenance_entries,
                fragment_max_buffered_provenance_entries=fragments.max_buffered_provenance_entries,
                truncated_packets=truncated_packets,
                truncated_missing_bytes=truncated_missing_bytes,
                detector=detector_snapshot,
            )
            last_heartbeat = now

    try:
        for chunk in tcp.flush_all(completeness="gapped"):
            for finding in detector.process_stream(chunk):
                finding_queue.put(finding)
                findings += 1
    except Exception as exc:
        if not _emit_operation(
            operational_queue,
            {
                "event": "worker_flush_fatal",
                "timestamp_ns": time.time_ns(),
                "worker_id": worker_id,
                "exception": type(exc).__name__,
                "message": str(exc)[:500],
            },
        ):
            operational_drops += 1
        control("fatal", exception=type(exc).__name__, message=str(exc)[:500])
        raise
    if not _emit_operation(
        operational_queue,
        {
            "event": "worker_stopped",
            "timestamp_ns": time.time_ns(),
            "worker_id": worker_id,
            "packets": packets,
            "bytes_seen": bytes_seen,
            "findings": findings,
            "parser_errors": parser_errors,
            "truncated_packets": truncated_packets,
            "truncated_missing_bytes": truncated_missing_bytes,
            "operational_queue_drops": operational_drops,
        },
    ):
        operational_drops += 1
    control(
        "stopped",
        operational_queue_drops=operational_drops,
        tcp_gap_bytes=tcp.gap_bytes,
        tcp_overlap_conflicts=tcp.overlap_conflicts,
        tcp_evicted_flows=tcp.evicted_flows,
        tcp_budget_evicted_flows=tcp.budget_evicted_flows,
        tcp_buffered_segments=tcp.buffered_segments,
        tcp_peak_buffered_segments=tcp.peak_buffered_segments,
        tcp_max_buffered_segments=tcp.max_buffered_segments,
        fragment_evicted_datagrams=fragments.evicted_datagrams,
        fragment_expired_datagrams=fragments.expired_datagrams,
        fragment_overlap_conflicts=fragments.overlap_conflicts,
        fragment_malformed=fragments.malformed_fragments,
        fragment_active_datagrams=fragments.active_datagrams,
        fragment_buffered_bytes=fragments.buffered_bytes,
        fragment_buffered_ranges=fragments.buffered_ranges,
        fragment_peak_buffered_ranges=fragments.peak_buffered_ranges,
        fragment_max_buffered_ranges=fragments.max_buffered_ranges,
        fragment_buffered_provenance_entries=fragments.buffered_provenance_entries,
        fragment_peak_buffered_provenance_entries=fragments.peak_buffered_provenance_entries,
        fragment_max_buffered_provenance_entries=fragments.max_buffered_provenance_entries,
        truncated_packets=truncated_packets,
        truncated_missing_bytes=truncated_missing_bytes,
        detector=detector.stats(),
    )
