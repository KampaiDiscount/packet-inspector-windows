from dataclasses import replace
from pathlib import Path
import queue
from types import SimpleNamespace

import pytest

from packet_audit.config import AuditConfig
from packet_audit.models import ParsedPacket
from packet_audit.supervisor import AuditSupervisor
from packet_audit.worker import worker_process


def _fragment(packet_id: int) -> ParsedPacket:
    return ParsedPacket(
        session_id="route-test",
        packet_id=packet_id,
        timestamp_ns=packet_id,
        interface="eth0",
        captured_length=100,
        wire_length=100,
        ip_version=4,
        src=f"10.0.{packet_id // 256}.{packet_id % 256}",
        dst="10.255.255.254",
        protocol=6,
        vlan_ids=(),
        network_payload=b"x" * 8,
        fragment_id=packet_id,
        fragment_offset=8,
        more_fragments=True,
    )


def test_fragment_route_table_is_bounded(tmp_path: Path):
    config = AuditConfig(
        workers=1,
        max_fragment_routes=1024,
        raw_capture_enabled=False,
        output_jsonl=tmp_path / "findings.jsonl",
        operational_jsonl=tmp_path / "operations.jsonl",
    )
    supervisor = AuditSupervisor(config)
    for packet_id in range(1, 1026):
        supervisor._route(_fragment(packet_id))
    assert len(supervisor.fragment_routes) == 1024
    assert supervisor.fragment_route_evictions == 1


def test_first_fragment_pins_the_rest_of_tcp_flow_to_same_worker(tmp_path: Path):
    config = AuditConfig(
        workers=4,
        raw_capture_enabled=False,
        output_jsonl=tmp_path / "findings.jsonl",
        operational_jsonl=tmp_path / "operations.jsonl",
    )
    supervisor = AuditSupervisor(config)
    first = _fragment(44)
    first.fragment_offset = 0
    first.network_payload = (50000).to_bytes(2, "big") + (80).to_bytes(2, "big") + b"x" * 4
    fragment_shard = supervisor._route(first)
    ordinary = replace(
        first,
        fragment_id=None,
        more_fragments=False,
        transport_parsed=True,
        sport=50000,
        dport=80,
    )
    assert supervisor._route(ordinary) == fragment_shard


def test_dispatch_queue_byte_budget_rejects_before_queue_growth(tmp_path: Path):
    config = AuditConfig(
        workers=1,
        raw_capture_enabled=False,
        output_jsonl=tmp_path / "findings.jsonl",
        operational_jsonl=tmp_path / "operations.jsonl",
        max_worker_queue_bytes=1024 * 1024,
    )
    supervisor = AuditSupervisor(config)
    with supervisor.worker_queue_byte_counters[0].get_lock():
        supervisor.worker_queue_byte_counters[0].value = (
            config.max_worker_queue_bytes - 50
        )

    supervisor._dispatch_batch(0, [_fragment(1)])

    assert supervisor.dispatched_packets == 0
    assert supervisor.userspace_queue_drops == 1
    assert supervisor.worker_queue_byte_budget_dropped_packets == 1
    assert supervisor.worker_queue_byte_budget_dropped_bytes == 100
    assert (
        supervisor.worker_queue_byte_counters[0].value
        == config.max_worker_queue_bytes - 50
    )


def test_dispatch_queue_full_releases_reserved_bytes(tmp_path: Path):
    class FullQueue:
        def put_nowait(self, _item):
            raise queue.Full

    config = AuditConfig(
        workers=1,
        raw_capture_enabled=False,
        output_jsonl=tmp_path / "findings.jsonl",
        operational_jsonl=tmp_path / "operations.jsonl",
    )
    supervisor = AuditSupervisor(config)
    supervisor.worker_queues[0] = FullQueue()

    supervisor._dispatch_batch(0, [_fragment(2)])

    assert supervisor.worker_queue_byte_counters[0].value == 0
    assert supervisor.worker_queue_byte_peaks[0].value == 100
    assert supervisor.userspace_queue_drops == 1
    assert supervisor.worker_queue_byte_budget_dropped_packets == 0


def test_offline_replay_waits_for_worker_queue_capacity(tmp_path: Path):
    class TemporarilyFullQueue:
        def __init__(self):
            self.calls = 0
            self.item = None

        def put(self, item, timeout):
            assert timeout > 0
            self.calls += 1
            if self.calls == 1:
                raise queue.Full
            self.item = item

    config = AuditConfig(
        workers=1,
        raw_capture_enabled=False,
        output_jsonl=tmp_path / "findings.jsonl",
        operational_jsonl=tmp_path / "operations.jsonl",
    )
    supervisor = AuditSupervisor(config, offline_path=tmp_path / "input.pcap")
    supervisor._check_children = lambda: None
    temporary = TemporarilyFullQueue()
    supervisor.worker_queues[0] = temporary

    supervisor._dispatch_batch(0, [_fragment(4)])

    assert temporary.calls == 2
    assert supervisor.dispatched_packets == 1
    assert supervisor.userspace_queue_drops == 0
    assert supervisor.worker_queue_byte_counters[0].value == 100


def test_offline_replay_waits_for_worker_byte_budget(tmp_path: Path):
    config = AuditConfig(
        workers=1,
        raw_capture_enabled=False,
        output_jsonl=tmp_path / "findings.jsonl",
        operational_jsonl=tmp_path / "operations.jsonl",
        max_worker_queue_bytes=1024 * 1024,
    )
    supervisor = AuditSupervisor(config, offline_path=tmp_path / "input.pcap")
    with supervisor.worker_queue_byte_counters[0].get_lock():
        supervisor.worker_queue_byte_counters[0].value = config.max_worker_queue_bytes - 50

    def worker_released_bytes():
        with supervisor.worker_queue_byte_counters[0].get_lock():
            supervisor.worker_queue_byte_counters[0].value = 0

    supervisor._check_children = worker_released_bytes
    supervisor._dispatch_batch(0, [_fragment(5)])

    assert supervisor.dispatched_packets == 1
    assert supervisor.userspace_queue_drops == 0
    assert supervisor.worker_queue_byte_budget_dropped_packets == 0
    assert supervisor.worker_queue_byte_counters[0].value == 100


def test_worker_fatal_path_releases_dequeued_batch_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    config = AuditConfig(
        workers=1,
        raw_capture_enabled=False,
        output_jsonl=tmp_path / "findings.jsonl",
        operational_jsonl=tmp_path / "operations.jsonl",
    )
    input_queue: queue.Queue = queue.Queue()
    finding_queue: queue.Queue = queue.Queue()
    operational_queue: queue.Queue = queue.Queue()
    control_queue: queue.Queue = queue.Queue()
    counter = AuditSupervisor(config).ctx.Value("Q", 100)
    input_queue.put(([_fragment(3)], 100))

    def fail_fragment(_self, _packet):
        raise RuntimeError("synthetic worker failure")

    monkeypatch.setattr(
        "packet_audit.worker.FragmentReassembler.process", fail_fragment
    )
    with pytest.raises(RuntimeError, match="synthetic worker failure"):
        worker_process(
            0,
            input_queue,
            finding_queue,
            operational_queue,
            config,
            "test-session",
            control_queue,
            1,
            counter,
        )

    assert counter.value == 0


def test_worker_final_telemetry_drop_is_included_in_stopped_ack(tmp_path: Path):
    class AlwaysFullQueue:
        def put_nowait(self, _item):
            raise queue.Full

    config = AuditConfig(
        workers=1,
        raw_capture_enabled=False,
        output_jsonl=tmp_path / "findings.jsonl",
        operational_jsonl=tmp_path / "operations.jsonl",
    )
    input_queue: queue.Queue = queue.Queue()
    finding_queue: queue.Queue = queue.Queue()
    control_queue: queue.Queue = queue.Queue()
    input_queue.put(("__PACKET_AUDIT_STOP__",))

    worker_process(
        0,
        input_queue,
        finding_queue,
        AlwaysFullQueue(),
        config,
        "test-session",
        control_queue,
        1,
    )

    reports = []
    while not control_queue.empty():
        reports.append(control_queue.get_nowait())
    stopped = [report for report in reports if report.get("state") == "stopped"]
    assert len(stopped) == 1
    # Both worker_started and worker_stopped telemetry records were rejected.
    assert stopped[0]["operational_queue_drops"] == 2


def test_supervisor_requires_stopped_ack_from_each_exact_final_worker_pid(
    tmp_path: Path,
):
    config = AuditConfig(
        workers=2,
        raw_capture_enabled=False,
        output_jsonl=tmp_path / "findings.jsonl",
        operational_jsonl=tmp_path / "operations.jsonl",
    )
    supervisor = AuditSupervisor(config)
    supervisor.workers = [
        SimpleNamespace(pid=1111),
        SimpleNamespace(pid=2222),
    ]
    supervisor.worker_reports = {
        (0, 9999): {"state": "stopped"},  # wrong generation/PID
        (1, 2222): {"state": "heartbeat"},  # stale, not a stopped ack
    }

    supervisor._validate_worker_stopped_acknowledgements()

    assert len(supervisor.incomplete_reasons) == 2
    assert any("worker_id=0, pid=1111" in value for value in supervisor.incomplete_reasons)
    assert any("worker_id=1, pid=2222" in value for value in supervisor.incomplete_reasons)
