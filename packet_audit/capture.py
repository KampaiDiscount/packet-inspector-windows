"""Thin pcapy-ng capture sources with loss-visible statistics.

Live capture is intentionally kept separate from parsing.  ``read_batch``
copies packet bytes into immutable Python ``bytes`` objects and returns quickly;
callers can then dispatch those records to flow-affine worker processes.
"""

from __future__ import annotations

from dataclasses import dataclass
import importlib
import os
from pathlib import Path
import struct
import threading
from typing import Any, Iterator
from uuid import uuid4

from .config import AuditConfig
from .models import CapturedPacket


# Capturing all IP traffic is deliberate: a transport-only filter loses
# non-initial IP fragments before reassembly ever sees them.
DEFAULT_BPF = "ip or ip6"


class CaptureError(RuntimeError):
    """A capture handle could not be opened or read."""


class PcapyUnavailable(CaptureError):
    """pcapy-ng is not importable in the active Python environment."""


@dataclass(frozen=True, slots=True)
class CaptureStats:
    received: int | None
    dropped: int | None
    interface_dropped: int | None


def _load_pcapy() -> Any:
    if os.name == "nt":
        from . import npcap
        try:
            npcap.lib_version()
        except (OSError, RuntimeError) as exc:
            raise PcapyUnavailable(f"Npcap is unavailable: {exc}") from exc
        return npcap
    try:
        return importlib.import_module("pcapy")
    except ImportError as exc:
        raise PcapyUnavailable(
            "pcapy-ng is required for live/offline capture; install the project dependencies"
        ) from exc


def _timestamp_ns(header: Any) -> int:
    seconds, fraction = header.getts()
    # pcapy-ng exposes libpcap's traditional timeval (microseconds).  A future
    # binding returning nanoseconds can opt in by exposing a precision marker.
    precision = getattr(header, "timestamp_precision", None)
    multiplier = 1 if precision in ("nano", "nanosecond", 9) else 1_000
    return int(seconds) * 1_000_000_000 + int(fraction) * multiplier


@dataclass(frozen=True, slots=True)
class _ClassicPcapHeader:
    seconds: int
    fraction: int
    captured_length: int
    wire_length: int
    timestamp_precision: str

    def getts(self) -> tuple[int, int]:
        return self.seconds, self.fraction

    def getcaplen(self) -> int:
        return self.captured_length

    def getlen(self) -> int:
        return self.wire_length


class _ClassicPcapHandle:
    """Minimal stdlib classic-PCAP reader used when pcapy is unavailable."""

    _MAGIC = {
        b"\xd4\xc3\xb2\xa1": ("<", "micro"),
        b"\xa1\xb2\xc3\xd4": (">", "micro"),
        b"\x4d\x3c\xb2\xa1": ("<", "nano"),
        b"\xa1\xb2\x3c\x4d": (">", "nano"),
    }

    def __init__(self, path: Path) -> None:
        try:
            self._file = path.open("rb")
        except OSError as exc:
            raise CaptureError(f"unable to open capture file {path}: {exc}") from exc
        header = self._file.read(24)
        if len(header) != 24:
            self._file.close()
            raise CaptureError(f"capture file {path} has a short global header")
        if header[:4] == b"\x0a\x0d\x0d\x0a":
            self._file.close()
            raise PcapyUnavailable(
                "pcapng replay requires Npcap on Windows or pcapy-ng on Linux (classic pcap needs neither)"
            )
        details = self._MAGIC.get(header[:4])
        if details is None:
            self._file.close()
            raise CaptureError(f"capture file {path} has an unknown pcap magic value")
        self._endian, self._precision = details
        major, minor, _zone, _sigfigs, snaplen, network = struct.unpack(
            f"{self._endian}HHIIII", header[4:]
        )
        if major != 2 or minor != 4:
            self._file.close()
            raise CaptureError(
                f"unsupported classic pcap version {major}.{minor} in {path}"
            )
        self._datalink = int(network)
        self._snaplen = int(snaplen)
        if self._snaplen < 1 or self._snaplen > 16 * 1024 * 1024:
            self._file.close()
            raise CaptureError(f"capture file {path} declares an unsafe snaplen")
        self._received = 0
        self._closed = False

    def datalink(self) -> int:
        return self._datalink

    def next(self) -> tuple[_ClassicPcapHeader | None, bytes | None]:
        if self._closed:
            return None, None
        record_header = self._file.read(16)
        if not record_header:
            return None, None
        if len(record_header) != 16:
            raise CaptureError("classic pcap ends inside a packet header")
        seconds, fraction, captured_length, wire_length = struct.unpack(
            f"{self._endian}IIII", record_header
        )
        fraction_limit = 1_000_000_000 if self._precision == "nano" else 1_000_000
        if fraction >= fraction_limit:
            raise CaptureError("classic pcap packet has an invalid timestamp fraction")
        if captured_length > self._snaplen or captured_length > 16 * 1024 * 1024:
            raise CaptureError(
                "classic pcap packet length exceeds its snapshot or safety limit"
            )
        if wire_length < captured_length:
            raise CaptureError("classic pcap wire length is shorter than captured length")
        data = self._file.read(captured_length)
        if len(data) != captured_length:
            raise CaptureError("classic pcap ends inside packet data")
        self._received += 1
        return (
            _ClassicPcapHeader(
                seconds,
                fraction,
                captured_length,
                wire_length,
                self._precision,
            ),
            data,
        )

    def stats(self) -> tuple[int, int, int]:
        return self._received, 0, 0

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._file.close()


class _PcapySource:
    """Common batching, record construction, iteration, and statistics."""

    def __init__(
        self,
        handle: Any,
        *,
        interface: str,
        session_id: str | None,
        batch_size: int,
        offline: bool,
    ) -> None:
        if batch_size < 1:
            raise ValueError("batch_size must be positive")
        self._handle = handle
        self.interface = interface
        self.session_id = session_id or uuid4().hex
        self.batch_size = batch_size
        self.offline = offline
        self.datalink = int(handle.datalink())
        self._packet_id = 0
        self._closed = False
        self._eof = False

    @property
    def eof(self) -> bool:
        return self._eof

    @property
    def closed(self) -> bool:
        return self._closed

    def _record(self, header: Any, data: bytes | bytearray | memoryview) -> CapturedPacket:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise CaptureError("capture record payload is not bytes-like")
        raw = bytes(data)
        getcaplen = getattr(header, "getcaplen", None)
        getlen = getattr(header, "getlen", None)
        captured_length = int(getcaplen()) if callable(getcaplen) else len(raw)
        wire_length = int(getlen()) if callable(getlen) else captured_length
        if captured_length != len(raw) or wire_length < captured_length:
            raise CaptureError("capture record lengths do not match its payload")
        timestamp_ns = _timestamp_ns(header)
        self._packet_id += 1
        return CapturedPacket(
            session_id=self.session_id,
            packet_id=self._packet_id,
            timestamp_ns=timestamp_ns,
            interface=self.interface,
            datalink=self.datalink,
            captured_length=captured_length,
            wire_length=wire_length,
            raw=raw,
        )

    def read_batch(self, max_packets: int | None = None) -> list[CapturedPacket]:
        """Read up to ``max_packets`` records, or return an empty timeout batch."""

        if self._closed or self._eof:
            return []
        limit = self.batch_size if max_packets is None else max_packets
        if limit < 1:
            raise ValueError("max_packets must be positive")

        batch: list[CapturedPacket] = []

        # Prefer the documented record-returning API over native callbacks.
        # Some binding/Python combinations consume a packet before failing to
        # invoke dispatch's callback correctly. Falling back after that failure
        # silently loses the consumed packet; never switch APIs after a read.
        next_packet = getattr(self._handle, "next", None)
        if callable(next_packet):
            try:
                # Live handles have already enabled nonblocking mode before
                # reaching this class, so a bounded batch cannot multiply the
                # configured blocking timeout by the packet count.
                for _ in range(limit):
                    item = next_packet()
                    if not isinstance(item, (tuple, list)) or len(item) != 2:
                        raise CaptureError("capture next() returned a malformed record")
                    header, data = item
                    if header is None:
                        # Native pcapy-ng uses (None, b''); the stdlib reader and
                        # several other bindings use (None, None).
                        if data is not None and not (
                            isinstance(data, (bytes, bytearray, memoryview))
                            and len(data) == 0
                        ):
                            raise CaptureError("capture next() returned data without a header")
                        if self.offline:
                            self._eof = True
                        break
                    if data is None:
                        raise CaptureError("capture next() returned a header without data")
                    batch.append(self._record(header, data))
            except CaptureError:
                raise
            except Exception as exc:
                raise CaptureError(f"capture next() failed: {type(exc).__name__}") from exc
            return batch

        # Compatibility for dispatch-only adapters. A count/callback mismatch
        # or callback exception is fatal, never an idle/EOF indication and never
        # a reason to retry another read API after packets may be consumed.
        dispatch = getattr(self._handle, "dispatch", None)
        if not callable(dispatch):
            raise CaptureError("pcapy handle exposes neither next nor dispatch")

        def collect(header: Any, data: bytes) -> None:
            if len(batch) >= limit:
                raise CaptureError("capture dispatch exceeded its bounded packet count")
            batch.append(self._record(header, data))

        try:
            result = dispatch(limit, collect)
        except CaptureError:
            raise
        except Exception as exc:
            raise CaptureError(f"capture dispatch failed: {type(exc).__name__}") from exc
        if result == -1:
            geterr = getattr(self._handle, "geterr", None)
            detail = geterr() if callable(geterr) else "libpcap dispatch failed"
            raise CaptureError(str(detail))
        if type(result) is not int or result < 0 or result != len(batch):
            raise CaptureError("capture dispatch count does not match delivered records")
        if self.offline and result == 0:
            self._eof = True
        return batch

    def packets(
        self, stop_event: threading.Event | Any | None = None
    ) -> Iterator[CapturedPacket]:
        """Yield packets until EOF, close, or an optional event is set."""

        while not self._closed and not self._eof:
            if stop_event is not None and stop_event.is_set():
                break
            batch = self.read_batch()
            if not batch:
                continue
            yield from batch

    def __iter__(self) -> Iterator[CapturedPacket]:
        return self.packets()

    def stats(self) -> CaptureStats:
        getter = getattr(self._handle, "stats", None)
        if not callable(getter):
            return CaptureStats(None, None, None)
        try:
            values = getter()
        except Exception:
            return CaptureStats(None, None, None)
        if values is None:
            return CaptureStats(None, None, None)
        values = tuple(values)
        return CaptureStats(
            int(values[0]) if len(values) > 0 else None,
            int(values[1]) if len(values) > 1 else None,
            int(values[2]) if len(values) > 2 else None,
        )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        closer = getattr(self._handle, "close", None)
        if callable(closer):
            closer()

    def __enter__(self) -> "_PcapySource":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class PcapyLiveSource(_PcapySource):
    """Configured pcapy-ng live capture source."""

    def __init__(
        self,
        interface: str,
        *,
        snaplen: int = 262_144,
        promiscuous: bool = True,
        read_timeout_ms: int = 100,
        buffer_mb: int = 128,
        timeout_ms: int | None = None,
        buffer_size_mb: int | None = None,
        bpf: str = DEFAULT_BPF,
        batch_size: int = 128,
        session_id: str | None = None,
        pcapy_module: Any | None = None,
    ) -> None:
        if timeout_ms is not None:
            read_timeout_ms = timeout_ms
        if buffer_size_mb is not None:
            buffer_mb = buffer_size_mb
        if not interface:
            raise ValueError("interface cannot be empty")
        if snaplen < 1 or not 1 <= read_timeout_ms <= 5_000 or buffer_mb < 1:
            raise ValueError("invalid live capture sizing")
        pcapy = pcapy_module or _load_pcapy()

        handle = None
        try:
            create = getattr(pcapy, "create", None)
            if callable(create):
                handle = create(interface)
                handle.set_snaplen(int(snaplen))
                handle.set_promisc(bool(promiscuous))
                handle.set_timeout(int(read_timeout_ms))
                set_buffer_size = getattr(handle, "set_buffer_size", None)
                if callable(set_buffer_size):
                    set_buffer_size(int(buffer_mb) * 1024 * 1024)
                handle.activate()
            else:
                handle = pcapy.open_live(
                    interface, int(snaplen), bool(promiscuous), int(read_timeout_ms)
                )
            if bpf:
                handle.setfilter(bpf)
            setnonblock = getattr(handle, "setnonblock", None)
            if not callable(setnonblock):
                raise CaptureError("live capture requires pcapy setnonblock support")
            result = setnonblock(1)
            if result not in (None, 0):
                raise CaptureError("unable to enable non-blocking live capture")
            getnonblock = getattr(handle, "getnonblock", None)
            if callable(getnonblock) and getnonblock() != 1:
                raise CaptureError("live capture handle remained blocking")
        except Exception as exc:
            closer = getattr(handle, "close", None)
            if callable(closer):
                try:
                    closer()
                except Exception:
                    pass
            raise CaptureError(f"unable to open live capture on {interface}: {exc}") from exc

        super().__init__(
            handle,
            interface=interface,
            session_id=session_id,
            batch_size=batch_size,
            offline=False,
        )
        self.bpf = bpf
        self._idle_wait_seconds = min(read_timeout_ms / 1000.0, 0.1)
        self._idle_stop = threading.Event()

    def read_batch(self, max_packets: int | None = None) -> list[CapturedPacket]:
        batch = super().read_batch(max_packets)
        if not batch and not self.closed:
            # No packet arrivals is normal. Nonblocking dispatch plus a bounded,
            # close-interruptible wait keeps both CPU usage and health-check
            # latency bounded without relying on libpcap's buffer timeout.
            self._idle_stop.wait(self._idle_wait_seconds)
        return batch

    def close(self) -> None:
        self._idle_stop.set()
        super().close()

    @classmethod
    def from_config(
        cls, config: AuditConfig, *, session_id: str | None = None
    ) -> "PcapyLiveSource":
        return cls(
            config.interface,
            snaplen=config.snaplen,
            promiscuous=config.promiscuous,
            read_timeout_ms=config.read_timeout_ms,
            buffer_mb=config.capture_buffer_mb,
            bpf=config.bpf or DEFAULT_BPF,
            batch_size=config.capture_batch_size,
            session_id=session_id,
        )


class PcapyOfflineSource(_PcapySource):
    """pcap/pcapng replay source using libpcap's offline reader."""

    def __init__(
        self,
        path: str | Path,
        *,
        bpf: str | None = None,
        batch_size: int = 128,
        session_id: str | None = None,
        interface: str | None = None,
        interface_name: str | None = None,
        pcapy_module: Any | None = None,
    ) -> None:
        capture_path = Path(path)
        try:
            pcapy = pcapy_module or _load_pcapy()
        except PcapyUnavailable:
            if bpf:
                raise PcapyUnavailable(
                    "offline BPF filtering requires Npcap on Windows or pcapy-ng on Linux"
                ) from None
            handle = _ClassicPcapHandle(capture_path)
        else:
            try:
                handle = pcapy.open_offline(str(capture_path))
                if bpf:
                    handle.setfilter(bpf)
            except Exception as exc:
                raise CaptureError(
                    f"unable to open capture file {capture_path}: {exc}"
                ) from exc
        super().__init__(
            handle,
            interface=interface_name or interface or capture_path.name,
            session_id=session_id,
            batch_size=batch_size,
            offline=True,
        )
        self.path = capture_path
        self.bpf = bpf


# Concise aliases for callers that do not need to expose the binding name.
LiveCaptureSource = PcapyLiveSource
OfflineCaptureSource = PcapyOfflineSource
