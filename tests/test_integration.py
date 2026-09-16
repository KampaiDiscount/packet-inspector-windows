from __future__ import annotations

import json
from pathlib import Path

import pytest

from packet_audit.config import AuditConfig
from packet_audit.supervisor import AuditRuntimeError, AuditSupervisor
from tests.pcap_builder import ethernet_ipv4_fragment, ethernet_ipv4_tcp, write_pcap


def test_replay_preserves_repeated_http_basic_attempts(tmp_path: Path):
    first = b"GET /login HTTP/1.1\r\nHost: audit.test\r\nAuthorization: Basic YWxpY2U6U3ludGhldGljU2VjcmV0IQ==\r\n\r\n"
    second = b"GET /again HTTP/1.1\r\nHost: audit.test\r\nAuthorization: Basic YWxpY2U6U3ludGhldGljU2VjcmV0IQ==\r\n\r\n"
    split = 57
    seq = 1001
    packets = [ethernet_ipv4_tcp(b"", seq=1000, flags=0x02)]
    packets.append(ethernet_ipv4_tcp(first[:split], seq=seq))
    packets.append(ethernet_ipv4_tcp(first[split:], seq=seq + split))
    packets.append(ethernet_ipv4_tcp(second, seq=seq + len(first)))
    capture = tmp_path / "repeat.pcap"
    write_pcap(capture, packets)

    output = tmp_path / "findings.jsonl"
    operations = tmp_path / "operations.jsonl"
    config = AuditConfig(
        interface="offline",
        workers=1,
        queue_size=128,
        raw_capture_enabled=False,
        output_jsonl=output,
        operational_jsonl=operations,
        heartbeat_seconds=1,
    )
    result = AuditSupervisor(config, offline_path=capture).run()
    assert result["userspace_queue_drops"] == 0
    assert result["verdict"] == "complete", result["incomplete_reasons"]
    assert result["worker_packets_processed"] == result["dispatched_packets"]
    assert result["writer_findings_written"] == result["worker_findings_emitted"]
    assert result["worker_queue_byte_health"]["current_bytes"] == 0
    assert result["worker_queue_byte_health"]["peak_bytes_sum"] > 0
    assert result["worker_queue_byte_budget_dropped_packets"] == 0
    records = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    basic = [
        record
        for record in records
        if record["protocol"].upper() == "HTTP"
        and record["material_type"].lower()
        in {"http_basic", "http_basic_credentials", "basic_auth", "credential"}
    ]
    assert len(basic) >= 2
    assert all("SyntheticSecret!" in json.dumps(record["material"]) for record in basic[:2])


def test_replay_same_tuple_new_tcp_epoch_is_not_suppressed(tmp_path: Path):
    request = (
        b"GET /login HTTP/1.1\r\nHost: audit.test\r\n"
        b"Authorization: Basic YWxpY2U6U3ludGhldGljU2VjcmV0IQ==\r\n\r\n"
    )
    packets = [
        ethernet_ipv4_tcp(b"", seq=1000, flags=0x02),
        ethernet_ipv4_tcp(request, seq=1001),
        ethernet_ipv4_tcp(b"", seq=1001 + len(request), flags=0x04),
        ethernet_ipv4_tcp(b"", seq=5000, flags=0x02),
        ethernet_ipv4_tcp(request, seq=5001),
        ethernet_ipv4_tcp(b"", seq=5001 + len(request), flags=0x04),
    ]
    capture = tmp_path / "tuple-reuse.pcap"
    write_pcap(capture, packets)
    output = tmp_path / "findings.jsonl"
    config = AuditConfig(
        interface="offline",
        workers=1,
        queue_size=64,
        raw_capture_enabled=False,
        output_jsonl=output,
        operational_jsonl=tmp_path / "operations.jsonl",
        heartbeat_seconds=1,
    )

    result = AuditSupervisor(config, offline_path=capture).run()
    assert result["verdict"] == "complete", result["incomplete_reasons"]
    records = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    basic = [record for record in records if record["detector"] == "http_basic"]
    assert len(basic) == 2
    assert len({record["connection_epoch"] for record in basic}) == 2


def test_replay_fails_if_evidence_writer_cannot_acknowledge_startup(tmp_path: Path):
    capture = tmp_path / "empty.pcap"
    write_pcap(capture, [])
    directory_instead_of_file = tmp_path / "not-a-file"
    directory_instead_of_file.mkdir()
    config = AuditConfig(
        interface="offline",
        workers=1,
        queue_size=64,
        raw_capture_enabled=False,
        # Opening a directory as the JSONL file must fail inside the spawned writer.
        output_jsonl=directory_instead_of_file,
        operational_jsonl=tmp_path / "operations.jsonl",
        heartbeat_seconds=1,
    )
    with pytest.raises(AuditRuntimeError, match="writer"):
        AuditSupervisor(config, offline_path=capture).run()


def test_replay_marks_truncated_capture_incomplete(tmp_path: Path):
    request = (
        b"GET /login HTTP/1.1\r\nHost: audit.test\r\n"
        b"Authorization: Basic YWxpY2U6U3ludGhldGljU2VjcmV0IQ==\r\n\r\n"
    )
    full_packet = ethernet_ipv4_tcp(request, seq=1001)
    captured_packet = full_packet[:-12]
    capture = tmp_path / "truncated.pcap"
    write_pcap(capture, [captured_packet], wire_lengths=[len(full_packet)])
    config = AuditConfig(
        interface="offline",
        workers=1,
        queue_size=64,
        raw_capture_enabled=False,
        output_jsonl=tmp_path / "findings.jsonl",
        operational_jsonl=tmp_path / "operations.jsonl",
        heartbeat_seconds=1,
    )

    result = AuditSupervisor(config, offline_path=capture).run()

    assert result["captured_packets"] == 1
    assert result["worker_packets_processed"] == 1
    assert result["verdict"] == "incomplete"
    assert result["worker_health_totals"]["truncated_packets"] == 1
    assert result["worker_health_totals"]["truncated_missing_bytes"] == 12
    assert any("truncated_packets=1" in reason for reason in result["incomplete_reasons"])


def test_replay_marks_unfinished_fragment_datagram_incomplete(tmp_path: Path):
    # A valid first fragment with no matching tail must remain visible in the
    # final health verdict rather than disappearing during worker shutdown.
    first_fragment = ethernet_ipv4_fragment(
        b"\xc3\x50\x00\x50" + b"X" * 20,
        more_fragments=True,
    )
    capture = tmp_path / "unfinished-fragment.pcap"
    write_pcap(capture, [first_fragment])
    config = AuditConfig(
        interface="offline",
        workers=1,
        queue_size=64,
        raw_capture_enabled=False,
        output_jsonl=tmp_path / "findings.jsonl",
        operational_jsonl=tmp_path / "operations.jsonl",
        heartbeat_seconds=1,
    )

    result = AuditSupervisor(config, offline_path=capture).run()

    assert result["verdict"] == "incomplete"
    assert result["worker_health_totals"]["fragment_active_datagrams"] == 1
    assert result["worker_health_totals"]["fragment_buffered_bytes"] == 24
    assert any(
        "fragment_active_datagrams=1" in reason
        for reason in result["incomplete_reasons"]
    )


def test_fragment_spanning_finding_preserves_all_capture_packet_ids(tmp_path: Path):
    request = (
        b"GET /login HTTP/1.1\r\nHost: audit.test\r\n"
        b"Authorization: Basic YWxpY2U6U3ludGhldGljU2VjcmV0IQ==\r\n\r\n"
    )
    complete_frame = ethernet_ipv4_tcp(request, seq=1001)
    tcp_datagram = complete_frame[14 + 20 :]
    split = 48  # IPv4 non-final fragment payloads must be eight-byte aligned.
    packets = [
        ethernet_ipv4_fragment(
            tcp_datagram[:split], fragment_id=0xBEEF, more_fragments=True
        ),
        ethernet_ipv4_fragment(
            tcp_datagram[split:],
            fragment_id=0xBEEF,
            fragment_offset=split,
            more_fragments=False,
        ),
    ]
    capture = tmp_path / "fragmented-basic.pcap"
    write_pcap(capture, packets)
    output = tmp_path / "findings.jsonl"
    config = AuditConfig(
        interface="offline",
        workers=1,
        queue_size=64,
        raw_capture_enabled=False,
        output_jsonl=output,
        operational_jsonl=tmp_path / "operations.jsonl",
        heartbeat_seconds=1,
    )

    result = AuditSupervisor(config, offline_path=capture).run()
    records = [
        json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()
    ]
    basic = [record for record in records if record["detector"] == "http_basic"]

    assert result["verdict"] == "complete", result["incomplete_reasons"]
    assert len(basic) == 1
    assert basic[0]["packet_ids"] == [1, 2]


def test_detector_metadata_cap_eviction_makes_session_incomplete(tmp_path: Path):
    request = (
        b"GET / HTTP/1.1\r\nHost: audit.test\r\n"
        b"Authorization: Bearer synthetic-metadata-pressure-token\r\n\r\n"
    )
    packets = [
        ethernet_ipv4_tcp(request, seq=1001, sport=40_000 + index)
        for index in range(520)
    ]
    capture = tmp_path / "metadata-pressure.pcap"
    write_pcap(capture, packets)
    config = AuditConfig(
        interface="offline",
        workers=1,
        queue_size=64,
        raw_capture_enabled=False,
        output_jsonl=tmp_path / "findings.jsonl",
        operational_jsonl=tmp_path / "operations.jsonl",
        detector_overlap_bytes=4096,
        max_detector_bytes_per_worker=8192,
        max_flows_per_worker=1024,
        heartbeat_seconds=1,
    )

    result = AuditSupervisor(config, offline_path=capture).run()

    health = result["worker_health_totals"]
    assert result["verdict"] == "incomplete"
    assert health["detector_metadata_cap_evicted_flows"] > 0
    assert health["detector_metadata_cap_pressure_events"] > 0
    assert health["detector_metadata_cap_saturated"] == 0
    assert any(
        "detector_metadata_cap_evicted_flows=" in reason
        for reason in result["incomplete_reasons"]
    )
