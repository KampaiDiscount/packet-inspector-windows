"""Capture hot path, flow sharding, worker supervision, and lifecycle control."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import multiprocessing as mp
import os
from pathlib import Path
import queue
import signal
import time
import uuid

from .capture import PcapyLiveSource, PcapyOfflineSource
from .config import AuditConfig
from .models import CaptureHeartbeat, FlowKey, ParsedPacket, STOP_SENTINEL
from .packets import PacketDecodeError, parse_packet_strict
from .raw_capture import DumpcapRing
from .service_watchdog import ServiceWatchdog, ServiceWatchdogError
from .worker import worker_process
from .writer import prepare_private_directory, prepare_private_parent, writer_process


class AuditRuntimeError(RuntimeError):
    pass


def _stable_shard(text: str, workers: int) -> int:
    digest = hashlib.blake2b(text.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big") % workers


def _fragment_route_key(packet: ParsedPacket) -> str:
    vlans = ",".join(str(v) for v in packet.vlan_ids)
    return (
        f"frag|{packet.interface}|{vlans}|{packet.ip_version}|{packet.src}|"
        f"{packet.dst}|{packet.protocol}|{packet.fragment_id}"
    )


def _fragment_flow_hint(packet: ParsedPacket) -> str | None:
    """Return the eventual flow key when a first TCP/UDP fragment exposes ports."""

    if packet.fragment_offset != 0 or packet.protocol not in (6, 17):
        return None
    if len(packet.network_payload) < 4:
        return None
    sport = int.from_bytes(packet.network_payload[0:2], "big")
    dport = int.from_bytes(packet.network_payload[2:4], "big")
    flow, _ = FlowKey.canonical(
        protocol=packet.protocol,
        src=packet.src,
        sport=sport,
        dst=packet.dst,
        dport=dport,
        interface=packet.interface,
        vlan_ids=packet.vlan_ids,
    )
    return flow.stable_text()


class AuditSupervisor:
    def __init__(self, config: AuditConfig, offline_path: str | Path | None = None):
        self.config = config
        self.offline_path = Path(offline_path) if offline_path else None
        self.session_id = str(uuid.uuid4())
        self.stop_requested = False
        self.ctx = mp.get_context("spawn")
        self.worker_queues = [self.ctx.Queue(maxsize=config.queue_size) for _ in range(config.workers)]
        self.worker_queue_byte_counters = [
            self.ctx.Value("Q", 0) for _ in range(config.workers)
        ]
        self.worker_queue_byte_peaks = [
            self.ctx.Value("Q", 0) for _ in range(config.workers)
        ]
        self.finding_queue = self.ctx.Queue(maxsize=config.queue_size * 2)
        self.operational_queue = self.ctx.Queue(maxsize=config.queue_size)
        # Low-volume lifecycle acknowledgements bypass the evidence writer so
        # the supervisor can distinguish alive from making progress.
        self.control_queue = self.ctx.Queue()
        self.workers: list[mp.Process] = []
        self.writer: mp.Process | None = None
        self.raw_ring = DumpcapRing(config)
        self.fragment_routes: dict[str, tuple[int, float]] = {}
        self.flow_route_overrides: dict[str, tuple[int, float]] = {}
        self.fragment_route_evictions = 0
        self.flow_route_override_evictions = 0
        self.fragment_route_fallbacks = 0
        self.captured_packets = 0
        self.dispatched_packets = 0
        self.userspace_queue_drops = 0
        self.worker_queue_byte_budget_dropped_packets = 0
        self.worker_queue_byte_budget_dropped_bytes = 0
        self.capture_parse_errors = 0
        self.operational_queue_drops = 0
        self.last_packet_monotonic: float | None = None
        self.writer_last_seen: float | None = None
        self.writer_report: dict | None = None
        self.worker_last_seen: dict[tuple[int, int], float] = {}
        self.worker_reports: dict[tuple[int, int], dict] = {}
        self.worker_restart_history: dict[int, list[float]] = {
            worker_id: [] for worker_id in range(config.workers)
        }
        self.worker_restarts = 0
        self.next_worker_epoch_namespace = 1
        self.incomplete_reasons: list[str] = []
        self.service_watchdog = ServiceWatchdog()

    def _operation(self, event: str, **fields) -> None:
        record = {
            "event": event,
            "timestamp_ns": time.time_ns(),
            "session_id": self.session_id,
            **fields,
        }
        try:
            self.operational_queue.put_nowait(record)
        except queue.Full:
            self.operational_queue_drops += 1

    def _mark_incomplete(self, reason: str) -> None:
        if reason not in self.incomplete_reasons:
            self.incomplete_reasons.append(reason)

    def _worker_queue_byte_health(self) -> dict[str, object]:
        current = [int(counter.value) for counter in self.worker_queue_byte_counters]
        peaks = [int(counter.value) for counter in self.worker_queue_byte_peaks]
        return {
            "current_bytes_by_worker": current,
            "peak_bytes_by_worker": peaks,
            "max_bytes_per_worker": self.config.max_worker_queue_bytes,
            "current_bytes": sum(current),
            "peak_bytes_sum": sum(peaks),
            "max_bytes_total": self.config.max_worker_queue_bytes * self.config.workers,
            "byte_budget_dropped_packets": self.worker_queue_byte_budget_dropped_packets,
            "byte_budget_dropped_bytes": self.worker_queue_byte_budget_dropped_bytes,
        }

    def _start_writer(self) -> None:
        self.writer = self.ctx.Process(
            name="packet-audit-writer",
            target=writer_process,
            args=(
                self.finding_queue,
                self.operational_queue,
                str(self.config.output_jsonl),
                str(self.config.operational_jsonl),
                self.config.console_unredacted,
                self.config.console_findings,
                self.control_queue,
                max(0.5, min(2.0, self.config.heartbeat_seconds / 2)),
            ),
        )
        self.writer.start()

    def _spawn_worker(self, worker_id: int) -> mp.Process:
        epoch_namespace = self.next_worker_epoch_namespace
        self.next_worker_epoch_namespace += 1
        process = self.ctx.Process(
            name=f"packet-audit-worker-{worker_id}",
            target=worker_process,
            args=(
                worker_id,
                self.worker_queues[worker_id],
                self.finding_queue,
                self.operational_queue,
                self.config,
                self.session_id,
                self.control_queue,
                epoch_namespace,
                self.worker_queue_byte_counters[worker_id],
            ),
        )
        process.start()
        return process

    def _start_workers(self) -> None:
        self.workers = [self._spawn_worker(worker_id) for worker_id in range(self.config.workers)]

    def _drain_control(self) -> None:
        while True:
            try:
                report = self.control_queue.get_nowait()
            except queue.Empty:
                return
            if not isinstance(report, dict):
                continue
            received = time.monotonic()
            if report.get("role") == "writer":
                self.writer_last_seen = received
                self.writer_report = report
            elif report.get("role") == "worker":
                try:
                    key = (int(report["worker_id"]), int(report["pid"]))
                except (KeyError, TypeError, ValueError):
                    continue
                self.worker_last_seen[key] = received
                self.worker_reports[key] = report

    def _drain_control_wait(self, seconds: float = 0.2) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self._drain_control()
            time.sleep(0.01)
        self._drain_control()

    def _put_until(self, target_queue, item, deadline: float) -> bool:
        while time.monotonic() < deadline:
            try:
                target_queue.put(item, timeout=min(0.25, deadline - time.monotonic()))
                return True
            except queue.Full:
                self._drain_control()
        return False

    def _await_writer_ready(self, timeout: float = 10.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.stop_requested:
                raise KeyboardInterrupt
            self._drain_control()
            if (
                self.writer
                and self.writer_report
                and self.writer_report.get("state") == "ready"
                and self.writer_report.get("pid") == self.writer.pid
                and self.writer.is_alive()
            ):
                return
            if self.writer and self.writer.exitcode is not None:
                raise AuditRuntimeError(
                    f"evidence writer failed during startup with exit code {self.writer.exitcode}"
                )
            time.sleep(0.02)
        raise AuditRuntimeError("evidence writer did not acknowledge startup")

    def _await_workers_ready(self, worker_ids: set[int], timeout: float = 10.0) -> None:
        deadline = time.monotonic() + timeout
        pending = set(worker_ids)
        while pending and time.monotonic() < deadline:
            if self.stop_requested:
                raise KeyboardInterrupt
            self._drain_control()
            for worker_id in tuple(pending):
                process = self.workers[worker_id]
                report = self.worker_reports.get((worker_id, process.pid or -1))
                if report and report.get("state") == "ready" and process.is_alive():
                    pending.remove(worker_id)
                elif process.exitcode is not None:
                    raise AuditRuntimeError(
                        f"worker {worker_id} failed during startup with exit code {process.exitcode}"
                    )
            if pending:
                time.sleep(0.02)
        if pending:
            raise AuditRuntimeError(f"workers did not acknowledge startup: {sorted(pending)}")

    def _validate_worker_stopped_acknowledgements(self) -> None:
        for worker_id, process in enumerate(self.workers):
            pid = process.pid or -1
            report = self.worker_reports.get((worker_id, pid))
            state = report.get("state") if report else None
            if state != "stopped":
                self._mark_incomplete(
                    "worker did not acknowledge a clean stopped state: "
                    f"worker_id={worker_id}, pid={pid}, observed_state={state!r}"
                )

    def _check_children(self) -> None:
        self._drain_control()
        if not self.writer or not self.writer.is_alive():
            raise AuditRuntimeError("evidence writer stopped; capture halted to prevent silent evidence loss")
        for worker_id, process in enumerate(tuple(self.workers)):
            if process.is_alive():
                continue
            exitcode = process.exitcode
            now = time.monotonic()
            history = [
                seen
                for seen in self.worker_restart_history[worker_id]
                if now - seen <= 60.0
            ]
            history.append(now)
            self.worker_restart_history[worker_id] = history
            self.worker_restarts += 1
            reason = f"worker {worker_id} restarted after exit code {exitcode}; flow state gap"
            if reason not in self.incomplete_reasons:
                self.incomplete_reasons.append(reason)
            if len(history) >= 3:
                raise AuditRuntimeError(
                    f"worker {worker_id} failed {len(history)} times within 60 seconds"
                )
            replacement = self._spawn_worker(worker_id)
            self.workers[worker_id] = replacement
            self._await_workers_ready({worker_id})
            self._operation(
                "worker_restarted",
                worker_id=worker_id,
                previous_exitcode=exitcode,
                replacement_pid=replacement.pid,
                limitation="active flow state was lost; consult raw PCAP ring for the gap",
            )
        watchdog_seconds = max(10.0, self.config.heartbeat_seconds * 3.0)
        now = time.monotonic()
        if self.writer_last_seen is None or now - self.writer_last_seen > watchdog_seconds:
            raise AuditRuntimeError("evidence writer is alive but its progress heartbeat is stale")
        for worker_id, process in enumerate(self.workers):
            last_seen = self.worker_last_seen.get((worker_id, process.pid or -1))
            if last_seen is None or now - last_seen > watchdog_seconds:
                raise AuditRuntimeError(
                    f"worker {worker_id} is alive but its progress heartbeat is stale"
                )
        if not self.offline_path and self.config.raw_capture_enabled:
            raw_status = self.raw_ring.status()
            if not raw_status.running:
                self._operation(
                    "raw_capture_failed",
                    returncode=raw_status.returncode,
                    stderr_path=raw_status.stderr_path,
                )
                if self.config.stop_on_raw_capture_failure:
                    raise AuditRuntimeError("raw dumpcap ring stopped")
                reason = "independent raw capture ring stopped during analysis"
                if reason not in self.incomplete_reasons:
                    self.incomplete_reasons.append(reason)

    def _startup_failure_cleanup(self) -> None:
        """Stop already-created children when capture initialization fails."""

        self.raw_ring.stop()
        for worker_queue in self.worker_queues:
            try:
                worker_queue.put_nowait(STOP_SENTINEL)
            except queue.Full:
                pass
        for process in self.workers:
            process.join(timeout=3)
            if process.is_alive():
                process.terminate()
                process.join(timeout=2)
        try:
            self.finding_queue.put_nowait(STOP_SENTINEL)
            self.operational_queue.put_nowait(STOP_SENTINEL)
        except queue.Full:
            pass
        if self.writer:
            self.writer.join(timeout=3)
            if self.writer.is_alive():
                self.writer.terminate()
                self.writer.join(timeout=2)

    def _route(self, packet: ParsedPacket) -> int:
        now = time.monotonic()
        if packet.fragment_id is not None:
            key = _fragment_route_key(packet)
            flow_hint = _fragment_flow_hint(packet)
            existing = self.fragment_routes.pop(key, None)
            if existing:
                self.fragment_routes[key] = (existing[0], now)
                if flow_hint:
                    self._remember_flow_override(flow_hint, existing[0], now)
                return existing[0]
            if flow_hint:
                shard = _stable_shard(flow_hint, self.config.workers)
                self._remember_flow_override(flow_hint, shard, now)
            else:
                shard = _stable_shard(key, self.config.workers)
                self.fragment_route_fallbacks += 1
            if len(self.fragment_routes) >= self.config.max_fragment_routes:
                oldest = next(iter(self.fragment_routes))
                self.fragment_routes.pop(oldest, None)
                self.fragment_route_evictions += 1
            self.fragment_routes[key] = (shard, now)
            return shard
        flow_text = packet.flow()[0].stable_text()
        override = self.flow_route_overrides.pop(flow_text, None)
        if override:
            self.flow_route_overrides[flow_text] = (override[0], now)
            return override[0]
        return _stable_shard(flow_text, self.config.workers)

    def _remember_flow_override(self, flow_text: str, shard: int, now: float) -> None:
        self.flow_route_overrides.pop(flow_text, None)
        if len(self.flow_route_overrides) >= self.config.max_fragment_routes:
            oldest = next(iter(self.flow_route_overrides))
            self.flow_route_overrides.pop(oldest, None)
            self.flow_route_override_evictions += 1
        self.flow_route_overrides[flow_text] = (shard, now)

    def _expire_fragment_routes(self) -> None:
        cutoff = time.monotonic() - self.config.fragment_idle_seconds
        self.fragment_routes = {
            key: value for key, value in self.fragment_routes.items() if value[1] >= cutoff
        }
        flow_cutoff = time.monotonic() - self.config.flow_idle_seconds
        self.flow_route_overrides = {
            key: value
            for key, value in self.flow_route_overrides.items()
            if value[1] >= flow_cutoff
        }

    def _dispatch_batch(self, shard: int, packets: list[ParsedPacket]) -> None:
        if not packets:
            return
        batch_bytes = sum(max(0, int(packet.captured_length)) for packet in packets)
        counter = self.worker_queue_byte_counters[shard]
        peak = self.worker_queue_byte_peaks[shard]
        with counter.get_lock():
            next_bytes = int(counter.value) + batch_bytes
            if next_bytes > self.config.max_worker_queue_bytes:
                reserved = False
            else:
                counter.value = next_bytes
                with peak.get_lock():
                    peak.value = max(int(peak.value), next_bytes)
                reserved = True
        if not reserved:
            self.userspace_queue_drops += len(packets)
            self.worker_queue_byte_budget_dropped_packets += len(packets)
            self.worker_queue_byte_budget_dropped_bytes += batch_bytes
            self._operation(
                "analysis_queue_drop",
                first_packet_id=packets[0].packet_id,
                last_packet_id=packets[-1].packet_id,
                packet_count=len(packets),
                captured_bytes=batch_bytes,
                worker_id=shard,
                drop_reason="worker_queue_byte_budget",
                queued_payload_bytes=int(counter.value),
                max_worker_queue_bytes=self.config.max_worker_queue_bytes,
                limitation=(
                    "verify the independent raw-ring health and retention window before "
                    "assuming these packets are recoverable"
                ),
            )
            return
        try:
            self.worker_queues[shard].put_nowait((packets, batch_bytes))
            self.dispatched_packets += len(packets)
        except queue.Full:
            with counter.get_lock():
                counter.value = max(0, int(counter.value) - batch_bytes)
            self.userspace_queue_drops += len(packets)
            self._operation(
                "analysis_queue_drop",
                first_packet_id=packets[0].packet_id,
                last_packet_id=packets[-1].packet_id,
                packet_count=len(packets),
                captured_bytes=batch_bytes,
                worker_id=shard,
                drop_reason="worker_queue_slots",
                limitation=(
                    "verify the independent raw-ring health and retention window before "
                    "assuming these packets are recoverable"
                ),
            )
        except BaseException:
            with counter.get_lock():
                counter.value = max(0, int(counter.value) - batch_bytes)
            raise

    def _source(self):
        if self.offline_path:
            return PcapyOfflineSource(
                self.offline_path,
                interface_name=f"pcap:{self.offline_path.name}",
                session_id=self.session_id,
                batch_size=self.config.capture_batch_size,
            )
        return PcapyLiveSource(
            interface=self.config.interface,
            snaplen=self.config.snaplen,
            promiscuous=self.config.promiscuous,
            timeout_ms=self.config.read_timeout_ms,
            buffer_size_mb=self.config.capture_buffer_mb,
            bpf=self.config.bpf,
            batch_size=self.config.capture_batch_size,
            session_id=self.session_id,
        )

    def request_stop(self, *_args) -> None:
        self.stop_requested = True

    def run(self) -> dict:
        self.config.validate()
        prepare_private_parent(self.config.output_jsonl)
        prepare_private_parent(self.config.operational_jsonl)
        old_handlers: dict[int, object] = {}
        stop_signals = [signal.SIGINT, signal.SIGTERM]
        if os.name == "nt":
            stop_signals.append(signal.SIGBREAK)
        for sig in stop_signals:
            try:
                old_handlers[sig] = signal.signal(sig, self.request_stop)
            except (ValueError, OSError):
                pass
        source = None
        try:
            if not self.offline_path:
                self.service_watchdog = ServiceWatchdog.from_environment()
            self._start_writer()
            self._await_writer_ready()
            self._start_workers()
            self._await_workers_ready(set(range(self.config.workers)))
            if not self.offline_path and self.config.raw_capture_enabled:
                prepare_private_directory(self.config.raw_capture_dir)
                ok, detail = self.raw_ring.preflight()
                if self.stop_requested:
                    raise KeyboardInterrupt
                if not ok:
                    self._operation("raw_capture_preflight_failed", detail=detail)
                    if self.config.stop_on_raw_capture_failure:
                        raise AuditRuntimeError(detail)
                    self.incomplete_reasons.append(
                        f"independent raw capture ring unavailable at startup: {detail}"
                    )
                else:
                    status = self.raw_ring.start()
                    self._operation("raw_capture_started", **asdict(status))
            source = self._source()
            if self.stop_requested:
                raise KeyboardInterrupt
            self.service_watchdog.ready()
        except BaseException:
            if source is not None:
                try:
                    source.close()
                except Exception:
                    pass
            self._startup_failure_cleanup()
            for sig, old_handler in old_handlers.items():
                try:
                    signal.signal(sig, old_handler)
                except (ValueError, OSError):
                    pass
            raise
        self._operation(
            "session_started",
            mode="offline" if self.offline_path else "live",
            interface=self.config.interface,
            capture_path=str(self.offline_path) if self.offline_path else None,
            workers=self.config.workers,
            bpf=self.config.bpf,
            unredacted_export=str(self.config.output_jsonl),
        )
        last_heartbeat = time.monotonic()
        eof = False
        fatal_error: str | None = None
        final_capture_stats = {
            "libpcap_received": None,
            "libpcap_dropped": None,
            "interface_dropped": None,
        }
        worker_packets_processed = 0
        worker_findings_emitted = 0
        worker_parser_errors = 0
        writer_findings_written = 0
        session_findings_sha256: str | None = None
        worker_health_totals: dict[str, int] = {}
        worker_queue_byte_health: dict[str, object] = self._worker_queue_byte_health()
        try:
            while not self.stop_requested and not eof:
                batch = source.read_batch()
                if not batch:
                    eof = bool(source.eof)
                pending: list[list[ParsedPacket]] = [[] for _ in range(self.config.workers)]
                for captured in batch:
                    self.captured_packets += 1
                    self.last_packet_monotonic = time.monotonic()
                    try:
                        parsed = parse_packet_strict(captured)
                    except PacketDecodeError as exc:
                        self.capture_parse_errors += 1
                        self._operation(
                            "capture_parse_error",
                            packet_id=captured.packet_id,
                            exception=type(exc).__name__,
                            message=str(exc)[:500],
                        )
                        continue
                    except Exception as exc:
                        self._operation(
                            "capture_parser_fatal",
                            packet_id=captured.packet_id,
                            exception=type(exc).__name__,
                            message=str(exc)[:500],
                        )
                        raise
                    if parsed is not None:
                        pending[self._route(parsed)].append(parsed)
                for shard, packets in enumerate(pending):
                    self._dispatch_batch(shard, packets)
                # Liveness and progress are checked per capture batch so a
                # short offline replay cannot outrun startup/runtime failures.
                self._check_children()
                now = time.monotonic()
                if now - last_heartbeat >= self.config.heartbeat_seconds:
                    stats = source.stats()
                    heartbeat = CaptureHeartbeat(
                        timestamp_ns=time.time_ns(),
                        captured_packets=self.captured_packets,
                        dispatched_packets=self.dispatched_packets,
                        userspace_queue_drops=self.userspace_queue_drops,
                        libpcap_received=stats.received,
                        libpcap_dropped=stats.dropped,
                        interface_dropped=stats.interface_dropped,
                        last_packet_age_seconds=(
                            now - self.last_packet_monotonic if self.last_packet_monotonic else None
                        ),
                    )
                    self._operation(
                        "capture_heartbeat",
                        **asdict(heartbeat),
                        capture_parse_errors=self.capture_parse_errors,
                        operational_queue_drops=self.operational_queue_drops,
                        fragment_route_entries=len(self.fragment_routes),
                        fragment_route_evictions=self.fragment_route_evictions,
                        fragment_route_fallbacks=self.fragment_route_fallbacks,
                        flow_route_override_entries=len(self.flow_route_overrides),
                        flow_route_override_evictions=self.flow_route_override_evictions,
                        worker_restarts=self.worker_restarts,
                        worker_queue_byte_health=self._worker_queue_byte_health(),
                    )
                    self._expire_fragment_routes()
                    last_heartbeat = now
                # This is the only watchdog keep-alive site. A blocked capture
                # read, dispatcher, parser or child-health check cannot be
                # concealed by a background heartbeat thread.
                self.service_watchdog.progress()
        except Exception as exc:
            fatal_error = f"{type(exc).__name__}: {exc}"
            self._operation("session_error", error=fatal_error)
            raise
        finally:
            try:
                self.service_watchdog.stopping()
            except ServiceWatchdogError as exc:
                self._mark_incomplete(f"service watchdog shutdown notification failed: {exc}")
                self._operation("service_watchdog_error", error=str(exc))
            if source is not None:
                try:
                    stats = source.stats()
                    final_capture_stats = {
                        "libpcap_received": stats.received,
                        "libpcap_dropped": stats.dropped,
                        "interface_dropped": stats.interface_dropped,
                    }
                except Exception as exc:
                    self._mark_incomplete(
                        f"final capture statistics unavailable: {type(exc).__name__}"
                    )
                finally:
                    source.close()
            raw_before_stop = self.raw_ring.status()
            raw_stop_event = "raw_capture_stopped"
            try:
                raw_status = self.raw_ring.stop()
            except Exception as exc:
                # Raw-child cleanup must not prevent worker drain and durable
                # export finalization. A failed stop is never a complete run.
                self._mark_incomplete(f"raw capture shutdown failed: {type(exc).__name__}")
                self._operation("raw_capture_shutdown_error", error=f"{type(exc).__name__}: {exc}")
                raw_status = raw_before_stop
                raw_stop_event = "raw_capture_stop_unverified"
            if getattr(raw_status, "forced_termination", False):
                self._mark_incomplete("raw capture required forced termination; final ring flush is unverified")
            if self.config.raw_capture_enabled:
                self._operation(raw_stop_event, **asdict(raw_status))
                if not self.offline_path and not raw_before_stop.running:
                    self._mark_incomplete(
                        "independent raw capture ring was not running at shutdown"
                    )

            worker_deadline = time.monotonic() + 25.0
            for worker_id, worker_queue in enumerate(self.worker_queues):
                if not self._put_until(worker_queue, STOP_SENTINEL, worker_deadline):
                    self._mark_incomplete(
                        f"worker {worker_id} queue did not accept the graceful-stop marker"
                    )

            while any(process.is_alive() for process in self.workers):
                self._drain_control()
                if time.monotonic() >= worker_deadline:
                    break
                if self.writer and not self.writer.is_alive():
                    self._mark_incomplete("evidence writer stopped while workers were draining")
                    break
                for process in self.workers:
                    process.join(timeout=0.05)

            for process in self.workers:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=2)
                    self._mark_incomplete(f"{process.name} required forced termination")
                    self._operation(
                        "worker_forced_termination",
                        worker=process.name,
                        exitcode=process.exitcode,
                    )
                elif process.exitcode != 0:
                    self._mark_incomplete(
                        f"{process.name} exited with code {process.exitcode}"
                    )

            self._drain_control_wait()
            self._validate_worker_stopped_acknowledgements()
            worker_queue_byte_health = self._worker_queue_byte_health()
            worker_packets_processed = sum(
                int(report.get("packets", 0)) for report in self.worker_reports.values()
            )
            worker_findings_emitted = sum(
                int(report.get("findings", 0)) for report in self.worker_reports.values()
            )
            worker_parser_errors = sum(
                int(report.get("parser_errors", 0)) for report in self.worker_reports.values()
            )
            health_keys = (
                "operational_queue_drops",
                "tcp_gap_bytes",
                "tcp_overlap_conflicts",
                "tcp_evicted_flows",
                "tcp_budget_evicted_flows",
                "tcp_buffered_segments",
                "tcp_peak_buffered_segments",
                "tcp_max_buffered_segments",
                "fragment_evicted_datagrams",
                "fragment_expired_datagrams",
                "fragment_overlap_conflicts",
                "fragment_malformed",
                "fragment_active_datagrams",
                "fragment_buffered_bytes",
                "fragment_buffered_ranges",
                "fragment_peak_buffered_ranges",
                "fragment_max_buffered_ranges",
                "fragment_buffered_provenance_entries",
                "fragment_peak_buffered_provenance_entries",
                "fragment_max_buffered_provenance_entries",
                "truncated_packets",
                "truncated_missing_bytes",
            )
            worker_health_totals = {
                key: sum(int(report.get(key, 0)) for report in self.worker_reports.values())
                for key in health_keys
            }
            detector_evictions = sum(
                int((report.get("detector") or {}).get("evicted_flows", 0))
                for report in self.worker_reports.values()
            )
            worker_health_totals["detector_evicted_flows"] = detector_evictions
            worker_health_totals["detector_byte_cap_evicted_flows"] = sum(
                int((report.get("detector") or {}).get("byte_cap_evicted_flows", 0))
                for report in self.worker_reports.values()
            )
            worker_health_totals["detector_tail_bytes_trimmed"] = sum(
                int((report.get("detector") or {}).get("tail_bytes_trimmed", 0))
                for report in self.worker_reports.values()
            )
            worker_health_totals["detector_parser_errors"] = sum(
                int((report.get("detector") or {}).get("parser_errors", 0))
                for report in self.worker_reports.values()
            )
            coverage_counters = {
                name
                for report in self.worker_reports.values()
                for name in (report.get("detector") or {})
                if name.startswith(("http_", "coverage_"))
            }
            for name in sorted(coverage_counters):
                total = sum(
                    int((report.get("detector") or {}).get(name, 0))
                    for report in self.worker_reports.values()
                )
                worker_health_totals[f"detector_{name}"] = total
                if total and name != "http_framed_requests":
                    family = "HTTP" if name.startswith("http_") else "Protocol"
                    self._mark_incomplete(f"{family} coverage limitation {name}={total}")
            for total_name, detector_name in (
                ("detector_metadata_entries", "metadata_entries"),
                ("detector_peak_metadata_entries", "peak_metadata_entries"),
                ("detector_max_metadata_entries", "max_metadata_entries"),
                (
                    "detector_metadata_cap_evicted_flows",
                    "metadata_cap_evicted_flows",
                ),
                (
                    "detector_metadata_cap_pressure_events",
                    "metadata_cap_pressure_events",
                ),
                ("detector_metadata_cap_saturated", "metadata_cap_saturated"),
                ("detector_provenance_spans", "provenance_spans"),
                ("detector_peak_provenance_spans", "peak_provenance_spans"),
                ("detector_max_provenance_spans", "max_provenance_spans"),
                (
                    "detector_provenance_packet_id_refs",
                    "provenance_packet_id_refs",
                ),
                (
                    "detector_peak_provenance_packet_id_refs",
                    "peak_provenance_packet_id_refs",
                ),
                (
                    "detector_max_provenance_packet_id_refs",
                    "max_provenance_packet_id_refs",
                ),
                (
                    "detector_provenance_cap_pressure_events",
                    "provenance_cap_pressure_events",
                ),
                (
                    "detector_provenance_cap_evicted_flows",
                    "provenance_cap_evicted_flows",
                ),
                (
                    "detector_provenance_cap_evicted_spans",
                    "provenance_cap_evicted_spans",
                ),
                (
                    "detector_provenance_cap_evicted_packet_id_refs",
                    "provenance_cap_evicted_packet_id_refs",
                ),
                (
                    "detector_provenance_cap_trimmed_spans",
                    "provenance_cap_trimmed_spans",
                ),
                (
                    "detector_provenance_cap_trimmed_packet_id_refs",
                    "provenance_cap_trimmed_packet_id_refs",
                ),
                (
                    "detector_provenance_packet_ids_truncated",
                    "provenance_packet_ids_truncated",
                ),
                (
                    "detector_provenance_pending_ids_truncated",
                    "provenance_pending_ids_truncated",
                ),
                (
                    "detector_provenance_incomplete_findings",
                    "provenance_incomplete_findings",
                ),
                ("detector_pending_auth_bytes", "pending_auth_bytes"),
                (
                    "detector_peak_pending_auth_bytes",
                    "peak_pending_auth_bytes",
                ),
                ("detector_pending_auth_objects", "pending_auth_objects"),
                (
                    "detector_peak_pending_auth_objects",
                    "peak_pending_auth_objects",
                ),
                (
                    "detector_pending_auth_cap_pressure_events",
                    "pending_auth_cap_pressure_events",
                ),
                (
                    "detector_pending_auth_cap_evicted_flows",
                    "pending_auth_cap_evicted_flows",
                ),
                (
                    "detector_pending_auth_cap_evicted_objects",
                    "pending_auth_cap_evicted_objects",
                ),
                (
                    "detector_pending_auth_cap_evicted_bytes",
                    "pending_auth_cap_evicted_bytes",
                ),
                (
                    "detector_pending_auth_cap_dropped_objects",
                    "pending_auth_cap_dropped_objects",
                ),
                (
                    "detector_pending_auth_cap_dropped_bytes",
                    "pending_auth_cap_dropped_bytes",
                ),
                ("detector_ntlm_correlation_bytes", "ntlm_correlation_bytes"),
                (
                    "detector_peak_ntlm_correlation_bytes",
                    "peak_ntlm_correlation_bytes",
                ),
                (
                    "detector_max_ntlm_correlation_bytes",
                    "max_ntlm_correlation_bytes",
                ),
                (
                    "detector_ntlm_correlation_objects",
                    "ntlm_correlation_objects",
                ),
                (
                    "detector_peak_ntlm_correlation_objects",
                    "peak_ntlm_correlation_objects",
                ),
                (
                    "detector_max_ntlm_correlation_objects",
                    "max_ntlm_correlation_objects",
                ),
                (
                    "detector_ntlm_correlation_cap_pressure_events",
                    "ntlm_correlation_cap_pressure_events",
                ),
                (
                    "detector_ntlm_correlation_cap_evicted_objects",
                    "ntlm_correlation_cap_evicted_objects",
                ),
                (
                    "detector_ntlm_correlation_cap_evicted_bytes",
                    "ntlm_correlation_cap_evicted_bytes",
                ),
                (
                    "detector_ntlm_correlation_cap_dropped_objects",
                    "ntlm_correlation_cap_dropped_objects",
                ),
            ):
                worker_health_totals[total_name] = sum(
                    int((report.get("detector") or {}).get(detector_name, 0))
                    for report in self.worker_reports.values()
                )
            worker_health_totals["worker_queue_current_bytes"] = int(
                worker_queue_byte_health["current_bytes"]
            )
            worker_health_totals["worker_queue_peak_bytes_sum"] = int(
                worker_queue_byte_health["peak_bytes_sum"]
            )
            worker_health_totals["worker_queue_max_bytes_total"] = int(
                worker_queue_byte_health["max_bytes_total"]
            )
            worker_health_totals["worker_queue_byte_budget_dropped_packets"] = (
                self.worker_queue_byte_budget_dropped_packets
            )
            worker_health_totals["worker_queue_byte_budget_dropped_bytes"] = (
                self.worker_queue_byte_budget_dropped_bytes
            )
            if worker_packets_processed != self.dispatched_packets:
                self._mark_incomplete(
                    "worker acknowledgement mismatch: "
                    f"processed={worker_packets_processed}, dispatched={self.dispatched_packets}"
                )
            if worker_parser_errors:
                self._mark_incomplete(
                    f"workers reported {worker_parser_errors} malformed-packet/parser errors"
                )
            for key in (
                "operational_queue_drops",
                "tcp_gap_bytes",
                "tcp_overlap_conflicts",
                "tcp_evicted_flows",
                "tcp_budget_evicted_flows",
                "fragment_evicted_datagrams",
                "fragment_expired_datagrams",
                "fragment_overlap_conflicts",
                "fragment_malformed",
                "fragment_active_datagrams",
                "truncated_packets",
                "detector_evicted_flows",
                "detector_byte_cap_evicted_flows",
                "detector_tail_bytes_trimmed",
                "detector_parser_errors",
                "detector_metadata_cap_evicted_flows",
                "detector_metadata_cap_saturated",
                "detector_provenance_cap_pressure_events",
                "detector_provenance_cap_evicted_flows",
                "detector_provenance_cap_evicted_spans",
                "detector_provenance_cap_evicted_packet_id_refs",
                "detector_provenance_cap_trimmed_spans",
                "detector_provenance_cap_trimmed_packet_id_refs",
                "detector_provenance_packet_ids_truncated",
                "detector_provenance_pending_ids_truncated",
                "detector_provenance_incomplete_findings",
                "detector_pending_auth_cap_pressure_events",
                "detector_pending_auth_cap_evicted_flows",
                "detector_pending_auth_cap_evicted_objects",
                "detector_pending_auth_cap_evicted_bytes",
                "detector_pending_auth_cap_dropped_objects",
                "detector_pending_auth_cap_dropped_bytes",
                "detector_ntlm_correlation_cap_pressure_events",
                "detector_ntlm_correlation_cap_evicted_objects",
                "detector_ntlm_correlation_cap_evicted_bytes",
                "detector_ntlm_correlation_cap_dropped_objects",
            ):
                if worker_health_totals.get(key, 0):
                    self._mark_incomplete(
                        f"worker health counter {key}={worker_health_totals[key]}"
                    )

            if self.userspace_queue_drops:
                self._mark_incomplete(
                    f"userspace analysis queues dropped {self.userspace_queue_drops} packets"
                )
            if self.worker_queue_byte_budget_dropped_packets:
                self._mark_incomplete(
                    "worker queue byte budgets dropped "
                    f"{self.worker_queue_byte_budget_dropped_packets} packets / "
                    f"{self.worker_queue_byte_budget_dropped_bytes} captured bytes"
                )
            if int(worker_queue_byte_health["current_bytes"]):
                self._mark_incomplete(
                    "worker queue byte reservations remained at shutdown: "
                    f"{worker_queue_byte_health['current_bytes']} bytes"
                )
            if self.capture_parse_errors:
                self._mark_incomplete(
                    f"capture parser rejected {self.capture_parse_errors} packets"
                )
            if self.operational_queue_drops:
                self._mark_incomplete(
                    f"operational telemetry queue dropped {self.operational_queue_drops} events"
                )
            if self.fragment_route_evictions:
                self._mark_incomplete(
                    f"fragment route table evicted {self.fragment_route_evictions} entries"
                )
            if self.flow_route_override_evictions:
                self._mark_incomplete(
                    "fragment-derived flow route table evicted "
                    f"{self.flow_route_override_evictions} entries"
                )
            if self.fragment_route_fallbacks:
                self._mark_incomplete(
                    "fragment routing lacked a first-fragment flow hint for "
                    f"{self.fragment_route_fallbacks} datagrams"
                )
            for counter_name in ("libpcap_dropped", "interface_dropped"):
                value = final_capture_stats[counter_name]
                if value:
                    self._mark_incomplete(f"{counter_name} reported {value} dropped packets")

            writer_deadline = time.monotonic() + 15.0
            stop_record = {
                "event": "session_stopped",
                "timestamp_ns": time.time_ns(),
                "session_id": self.session_id,
                "captured_packets": self.captured_packets,
                "dispatched_packets": self.dispatched_packets,
                "worker_packets_processed": worker_packets_processed,
                "worker_findings_emitted": worker_findings_emitted,
                "userspace_queue_drops": self.userspace_queue_drops,
                "worker_queue_byte_budget_dropped_packets": self.worker_queue_byte_budget_dropped_packets,
                "worker_queue_byte_budget_dropped_bytes": self.worker_queue_byte_budget_dropped_bytes,
                "worker_queue_byte_health": worker_queue_byte_health,
                "capture_parse_errors": self.capture_parse_errors,
                "operational_queue_drops": self.operational_queue_drops,
                "fragment_route_evictions": self.fragment_route_evictions,
                "fragment_route_fallbacks": self.fragment_route_fallbacks,
                "flow_route_override_evictions": self.flow_route_override_evictions,
                "worker_restarts": self.worker_restarts,
                "worker_health_totals": worker_health_totals,
                "fatal_error": fatal_error,
                "pre_writer_incomplete_reasons": list(self.incomplete_reasons),
                **final_capture_stats,
            }
            if not self._put_until(self.operational_queue, stop_record, writer_deadline):
                self._mark_incomplete("session-stop record was not accepted by the writer queue")
            if not self._put_until(self.finding_queue, STOP_SENTINEL, writer_deadline):
                self._mark_incomplete("finding writer did not accept its graceful-stop marker")
            if not self._put_until(self.operational_queue, STOP_SENTINEL, writer_deadline):
                self._mark_incomplete("operational writer did not accept its graceful-stop marker")

            if self.writer:
                remaining = max(0.0, writer_deadline - time.monotonic())
                self.writer.join(timeout=remaining)
                if self.writer.is_alive():
                    self.writer.terminate()
                    self.writer.join(timeout=2)
                    self._mark_incomplete("evidence writer required forced termination")
                elif self.writer.exitcode != 0:
                    self._mark_incomplete(
                        f"evidence writer exited with code {self.writer.exitcode}"
                    )
            self._drain_control_wait()
            if not self.writer_report or self.writer_report.get("state") != "stopped":
                self._mark_incomplete("evidence writer did not acknowledge a durable close")
            else:
                writer_findings_written = int(
                    self.writer_report.get("findings_written", 0)
                )
                session_findings_sha256 = self.writer_report.get(
                    "session_findings_sha256"
                )
            if writer_findings_written != worker_findings_emitted:
                self._mark_incomplete(
                    "finding acknowledgement mismatch: "
                    f"written={writer_findings_written}, emitted={worker_findings_emitted}"
                )
            for sig, old_handler in old_handlers.items():
                try:
                    signal.signal(sig, old_handler)
                except (ValueError, OSError):
                    pass

        return {
            "session_id": self.session_id,
            "captured_packets": self.captured_packets,
            "dispatched_packets": self.dispatched_packets,
            "userspace_queue_drops": self.userspace_queue_drops,
            "worker_queue_byte_budget_dropped_packets": self.worker_queue_byte_budget_dropped_packets,
            "worker_queue_byte_budget_dropped_bytes": self.worker_queue_byte_budget_dropped_bytes,
            "worker_queue_byte_health": worker_queue_byte_health,
            "capture_parse_errors": self.capture_parse_errors,
            "operational_queue_drops": self.operational_queue_drops,
            "fragment_route_evictions": self.fragment_route_evictions,
            "fragment_route_fallbacks": self.fragment_route_fallbacks,
            "flow_route_override_evictions": self.flow_route_override_evictions,
            "worker_restarts": self.worker_restarts,
            "worker_packets_processed": worker_packets_processed,
            "worker_findings_emitted": worker_findings_emitted,
            "worker_parser_errors": worker_parser_errors,
            "worker_health_totals": worker_health_totals,
            "writer_findings_written": writer_findings_written,
            "session_findings_sha256": session_findings_sha256,
            **final_capture_stats,
            "verdict": "complete" if not self.incomplete_reasons else "incomplete",
            "incomplete_reasons": list(self.incomplete_reasons),
            "output": str(self.config.output_jsonl),
            "operations": str(self.config.operational_jsonl),
        }
