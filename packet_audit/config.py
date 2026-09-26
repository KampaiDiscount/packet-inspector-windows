"""Configuration loading and validation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import tomllib


_CONFIG_SECTION_KEYS: dict[str, frozenset[str]] = {
    "capture": frozenset(
        {
            "interface",
            "bpf",
            "workers",
            "queue_size",
            "max_worker_queue_bytes",
            "snaplen",
            "capture_buffer_mb",
            "promiscuous",
            "read_timeout_ms",
            "capture_batch_size",
        }
    ),
    "analysis": frozenset(
        {
            "flow_idle_seconds",
            "fragment_idle_seconds",
            "max_flows_per_worker",
            "max_stream_bytes_per_direction",
            "max_out_of_order_bytes_per_direction",
            "max_reassembly_bytes_per_worker",
            "detector_overlap_bytes",
            "max_detector_bytes_per_worker",
            "max_fragment_routes",
            "heartbeat_seconds",
            "generic_secret_scan",
            "credit_card_scan",
            "extra_sensitive_field_names",
        }
    ),
    "output": frozenset(
        {
            "output_jsonl",
            "operational_jsonl",
            "console_findings",
            "console_unredacted",
        }
    ),
    "raw_capture": frozenset(
        {
            "raw_capture_enabled",
            "raw_capture_dir",
            "raw_capture_file_mb",
            "raw_capture_files",
            "raw_capture_duration_seconds",
            "dumpcap_path",
            "stop_on_raw_capture_failure",
        }
    ),
}


# Keep IP fragments while admitting VLAN-tagged IP on Ethernet and Linux cooked
# captures. A plain "ip or ip6" BPF only checks the outer EtherType and silently
# drops tagged frames before either the analyzer or the independent raw ring.
# The link offsets are Ethernet, Linux SLL v1 and Linux SLL v2 respectively;
# non-IP frames admitted by a coincidental match are rejected by the decoder.
_VLAN_ETHERTYPES = (0x8100, 0x88A8, 0x9100, 0x9200)
DEFAULT_BPF = "ip or ip6 or " + " or ".join(
    f"link[{offset}:2] = 0x{ethertype:04x}"
    for offset in (12, 14, 0)
    for ethertype in _VLAN_ETHERTYPES
)


@dataclass(slots=True)
class AuditConfig:
    interface: str = "eth0"
    bpf: str = DEFAULT_BPF
    workers: int = max(1, min(8, (os.cpu_count() or 2) - 1))
    queue_size: int = 64
    max_worker_queue_bytes: int = 64 * 1024 * 1024
    snaplen: int = 262_144
    capture_buffer_mb: int = 128
    promiscuous: bool = True
    read_timeout_ms: int = 100
    flow_idle_seconds: int = 300
    fragment_idle_seconds: int = 30
    max_flows_per_worker: int = 20_000
    max_stream_bytes_per_direction: int = 2 * 1024 * 1024
    max_out_of_order_bytes_per_direction: int = 512 * 1024
    max_reassembly_bytes_per_worker: int = 128 * 1024 * 1024
    detector_overlap_bytes: int = 128 * 1024
    max_detector_bytes_per_worker: int = 128 * 1024 * 1024
    max_fragment_routes: int = 65_536
    heartbeat_seconds: int = 10
    output_jsonl: Path = Path("./evidence/findings-unredacted.jsonl")
    operational_jsonl: Path = Path("./evidence/operations.jsonl")
    console_findings: bool = False
    console_unredacted: bool = False
    raw_capture_enabled: bool = True
    raw_capture_dir: Path = Path("./evidence/pcap-ring")
    raw_capture_file_mb: int = 256
    raw_capture_files: int = 24
    raw_capture_duration_seconds: int = 300
    dumpcap_path: str = "dumpcap"
    stop_on_raw_capture_failure: bool = True
    generic_secret_scan: bool = True
    credit_card_scan: bool = True
    capture_batch_size: int = 128
    extra_sensitive_field_names: tuple[str, ...] = ()

    @classmethod
    def from_toml(cls, path: str | Path) -> "AuditConfig":
        raw = tomllib.loads(Path(path).read_text(encoding="utf-8"))

        unknown_sections = sorted(set(raw) - set(_CONFIG_SECTION_KEYS))
        if unknown_sections:
            names = ", ".join(f"[{name}]" for name in unknown_sections)
            raise ValueError(f"unknown top-level configuration section(s): {names}")

        sections: dict[str, dict[str, object]] = {}
        for section in _CONFIG_SECTION_KEYS:
            value = raw.get(section, {})
            if not isinstance(value, dict):
                raise ValueError(f"configuration section [{section}] must be a table")
            sections[section] = value

        key_locations: dict[str, list[str]] = {}
        for section, values in sections.items():
            for key in values:
                key_locations.setdefault(key, []).append(section)
        duplicate_keys = {
            key: locations
            for key, locations in key_locations.items()
            if len(locations) > 1
        }
        if duplicate_keys:
            details = "; ".join(
                f"{key!r} in " + ", ".join(f"[{name}]" for name in sorted(locations))
                for key, locations in sorted(duplicate_keys.items())
            )
            raise ValueError(f"configuration key(s) appear in multiple sections: {details}")

        for section, allowed_keys in _CONFIG_SECTION_KEYS.items():
            unknown_keys = sorted(set(sections[section]) - set(allowed_keys))
            if unknown_keys:
                names = ", ".join(repr(name) for name in unknown_keys)
                raise ValueError(f"unknown configuration key(s) in [{section}]: {names}")

        flat: dict[str, object] = {}
        for section in _CONFIG_SECTION_KEYS:
            flat.update(sections[section])
        for key in ("output_jsonl", "operational_jsonl", "raw_capture_dir"):
            if key in flat:
                if not isinstance(flat[key], str):
                    raise ValueError(f"{key} must be a TOML string path")
                flat[key] = Path(flat[key])
        if "extra_sensitive_field_names" in flat:
            if not isinstance(flat["extra_sensitive_field_names"], list):
                raise ValueError("extra_sensitive_field_names must be a TOML array of strings")
            if not all(
                isinstance(value, str)
                for value in flat["extra_sensitive_field_names"]
            ):
                raise ValueError("extra_sensitive_field_names must be a TOML array of strings")
            flat["extra_sensitive_field_names"] = tuple(flat["extra_sensitive_field_names"])
        cfg = cls(**flat)
        cfg.validate()
        return cfg

    def validate(self) -> None:
        integer_fields = (
            "workers",
            "queue_size",
            "max_worker_queue_bytes",
            "snaplen",
            "capture_buffer_mb",
            "read_timeout_ms",
            "flow_idle_seconds",
            "fragment_idle_seconds",
            "max_flows_per_worker",
            "max_stream_bytes_per_direction",
            "max_out_of_order_bytes_per_direction",
            "max_reassembly_bytes_per_worker",
            "detector_overlap_bytes",
            "max_detector_bytes_per_worker",
            "max_fragment_routes",
            "heartbeat_seconds",
            "raw_capture_file_mb",
            "raw_capture_files",
            "raw_capture_duration_seconds",
            "capture_batch_size",
        )
        for name in integer_fields:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an integer")
        for name in (
            "promiscuous",
            "console_findings",
            "console_unredacted",
            "raw_capture_enabled",
            "stop_on_raw_capture_failure",
            "generic_secret_scan",
            "credit_card_scan",
        ):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be true or false")
        if not isinstance(self.interface, str) or not self.interface:
            raise ValueError("capture interface cannot be empty")
        if not isinstance(self.bpf, str):
            raise ValueError("bpf must be a string")
        if not 1 <= self.workers <= 64:
            raise ValueError("workers must be between 1 and 64")
        if not 8 <= self.queue_size <= 4096:
            raise ValueError("queue_size must be between 8 and 4096 batches")
        if not 1 * 1024 * 1024 <= self.max_worker_queue_bytes <= 2 * 1024 * 1024 * 1024:
            raise ValueError(
                "max_worker_queue_bytes must be between 1048576 and 2147483648"
            )
        if not 65_535 <= self.snaplen <= 16 * 1024 * 1024:
            raise ValueError("snaplen must be between 65535 and 16777216 bytes")
        if not 1 <= self.capture_buffer_mb <= 16_384:
            raise ValueError("capture_buffer_mb must be between 1 and 16384")
        if not 1 <= self.read_timeout_ms <= 5_000:
            raise ValueError("read_timeout_ms must be between 1 and 5000")
        if not 1 <= self.capture_batch_size <= 65_536:
            raise ValueError("capture_batch_size must be between 1 and 65536")
        if self.max_worker_queue_bytes < self.snaplen * self.capture_batch_size:
            raise ValueError(
                "max_worker_queue_bytes must hold one worst-case capture batch"
            )
        if self.workers * self.max_worker_queue_bytes > 2 * 1024 * 1024 * 1024:
            raise ValueError(
                "aggregate worker queue byte budget must not exceed 2147483648"
            )
        if self.flow_idle_seconds <= 0:
            raise ValueError("flow_idle_seconds must be positive")
        if self.fragment_idle_seconds <= 0:
            raise ValueError("fragment_idle_seconds must be positive")
        if self.max_flows_per_worker < 1:
            raise ValueError("max_flows_per_worker must be positive")
        if self.max_stream_bytes_per_direction < 1:
            raise ValueError("max_stream_bytes_per_direction must be positive")
        if self.max_out_of_order_bytes_per_direction < 1:
            raise ValueError("max_out_of_order_bytes_per_direction must be positive")
        if self.max_reassembly_bytes_per_worker < self.max_out_of_order_bytes_per_direction:
            raise ValueError(
                "max_reassembly_bytes_per_worker must cover one out-of-order direction"
            )
        if self.detector_overlap_bytes < 4096:
            raise ValueError("detector_overlap_bytes must be at least 4096")
        if self.max_stream_bytes_per_direction < self.detector_overlap_bytes:
            raise ValueError("stream cap must be at least as large as detector overlap")
        if self.max_detector_bytes_per_worker < 2 * self.detector_overlap_bytes:
            raise ValueError(
                "max_detector_bytes_per_worker must hold two detector overlap windows"
            )
        if not 1024 <= self.max_fragment_routes <= 10_000_000:
            raise ValueError("max_fragment_routes must be between 1024 and 10000000")
        if self.heartbeat_seconds <= 0:
            raise ValueError("heartbeat_seconds must be positive")
        if self.read_timeout_ms > self.heartbeat_seconds * 1_000:
            raise ValueError("read_timeout_ms must not exceed the heartbeat interval")
        if not all(
            isinstance(value, Path)
            for value in (self.output_jsonl, self.operational_jsonl, self.raw_capture_dir)
        ):
            raise ValueError("output and raw capture paths must be pathlib.Path values")
        if self.output_jsonl.resolve() == self.operational_jsonl.resolve():
            raise ValueError("findings and operational JSONL paths must be different")
        if not isinstance(self.dumpcap_path, str) or not self.dumpcap_path:
            raise ValueError("dumpcap_path cannot be empty")
        if self.raw_capture_file_mb < 1:
            raise ValueError("raw_capture_file_mb must be positive")
        if self.raw_capture_files < 1:
            raise ValueError("raw_capture_files must be positive")
        if self.raw_capture_duration_seconds < 1:
            raise ValueError("raw_capture_duration_seconds must be positive")
        if not isinstance(self.extra_sensitive_field_names, tuple) or not all(
            isinstance(value, str) and value.strip()
            for value in self.extra_sensitive_field_names
        ):
            raise ValueError(
                "extra_sensitive_field_names must be a tuple of non-empty strings"
            )
