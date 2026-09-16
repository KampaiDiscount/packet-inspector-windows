"""Read-only Npcap adapter for the small pcapy API used by capture.py.

Importing this module does not load a DLL or open a capture. Npcap must already
be installed; it is never downloaded, installed, started, or reconfigured here.
Only the OS system-directory Npcap DLL is loaded, with a restricted dependency
search. No injection, remote-capture, or packet-sampling API is exposed.

ABI references: Npcap SDK 1.16 Include/pcap/pcap.h and Include/pcap/bpf.h;
https://npcap.com/guide/wpcap/pcap_next_ex.html
https://npcap.com/guide/wpcap/pcap_init.html
"""

from __future__ import annotations

import ctypes as C
from dataclasses import dataclass
import os
from pathlib import Path
import stat
import threading
from typing import Any


PCAP_ERRBUF_SIZE = 256
MAX_PACKET_BYTES = 16 * 1024 * 1024
_LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x100
_LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x800
_PCAP_TSTAMP_PRECISION_NANO = 1
_PCAP_CHAR_ENC_UTF_8 = 1


class NpcapError(RuntimeError):
    """A native capture operation failed; never an idle/EOF indication."""


class NpcapUnavailable(NpcapError):
    """The trusted Npcap installation or required native API is unavailable."""


# Windows uses LLP64: timeval's signed long fields are 32-bit on x86 AND x64.
# Fixed widths keep mock ABI tests correct even when run on a Unix host.
class _Timeval(C.Structure):
    _fields_ = [("tv_sec", C.c_int32), ("tv_usec", C.c_int32)]


class _PcapHeader(C.Structure):
    _fields_ = [("ts", _Timeval), ("caplen", C.c_uint32), ("len", C.c_uint32)]


class _PcapStat(C.Structure):
    # The final three fields MUST be allocated even though pcapy exposes only
    # the first three. A Unix-sized buffer would permit a native overwrite.
    _fields_ = [(name, C.c_uint32) for name in
                ("ps_recv", "ps_drop", "ps_ifdrop", "ps_capt", "ps_sent", "ps_netdrop")]


class _BpfProgram(C.Structure):
    _fields_ = [("bf_len", C.c_uint32), ("bf_insns", C.c_void_p)]


class _PcapIf(C.Structure):
    pass


_PcapIf._fields_ = [
    ("next", C.POINTER(_PcapIf)), ("name", C.c_char_p),
    ("description", C.c_char_p), ("addresses", C.c_void_p),
    ("flags", C.c_uint32),
]


@dataclass(frozen=True, slots=True)
class PacketHeader:
    seconds: int
    fraction: int
    captured_length: int
    wire_length: int
    timestamp_precision: str = "micro"

    def getts(self) -> tuple[int, int]:
        return self.seconds, self.fraction

    def getcaplen(self) -> int:
        return self.captured_length

    def getlen(self) -> int:
        return self.wire_length


def _text(value: bytes | None) -> str:
    return value.decode("utf-8", errors="replace") if value else "no native detail"


def _encode(value: str, label: str) -> bytes:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{label} must be nonempty text without NUL characters")
    return value.encode("utf-8", errors="strict")


def _system_directory() -> Path:
    if os.name != "nt":
        raise NpcapUnavailable("Npcap is available only on Windows")
    # Do not trust SystemRoot/WINDIR, the working directory, PATH, or DLL names
    # supplied by configuration. kernel32 itself is a Windows KnownDLL.
    kernel = C.WinDLL("kernel32.dll", winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32,
                      use_last_error=True)
    get_directory = kernel.GetSystemDirectoryW
    get_directory.argtypes = [C.POINTER(C.c_wchar), C.c_uint32]
    get_directory.restype = C.c_uint32
    buffer = C.create_unicode_buffer(32768)
    size = get_directory(buffer, len(buffer))
    if not size or size >= len(buffer):
        raise NpcapUnavailable("Windows system directory could not be resolved")
    directory = Path(buffer.value)
    if not directory.is_absolute():
        raise NpcapUnavailable("Windows returned a non-absolute system directory")
    return directory


def _load_dll() -> Any:
    path = _system_directory() / "Npcap" / "wpcap.dll"
    try:
        # Reject redirection out of the trusted install path. No fallback to
        # legacy WinPcap in System32 or to an application-local DLL is allowed.
        for component in (path, *path.parents):
            info = component.lstat()
            if getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                raise NpcapUnavailable(f"Reparse point in Npcap DLL path: {component}")
        if not path.is_file():
            raise NpcapUnavailable(f"Npcap DLL is not a regular file: {path}")
        # libpcap's exported C functions use cdecl (CDLL), not stdcall (WinDLL).
        return C.CDLL(str(path), winmode=(
            _LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | _LOAD_LIBRARY_SEARCH_SYSTEM32))
    except (OSError, AttributeError) as exc:
        raise NpcapUnavailable(
            f"Cannot load installed Npcap at {path}; install Npcap matching Python's architecture"
        ) from exc


class _NativeApi:
    def __init__(self, dll: Any) -> None:
        self.dll = dll
        pointer = C.c_void_p
        char_buffer = C.POINTER(C.c_char)
        signatures = {
            "pcap_init": ([C.c_uint32, char_buffer], C.c_int),
            "pcap_lib_version": ([], C.c_char_p),
            "pcap_create": ([C.c_char_p, char_buffer], pointer),
            "pcap_open_offline_with_tstamp_precision":
                ([C.c_char_p, C.c_uint32, char_buffer], pointer),
            "pcap_findalldevs": ([C.POINTER(C.POINTER(_PcapIf)), char_buffer], C.c_int),
            "pcap_freealldevs": ([C.POINTER(_PcapIf)], None),
            "pcap_activate": ([pointer], C.c_int),
            "pcap_datalink": ([pointer], C.c_int),
            "pcap_snapshot": ([pointer], C.c_int),
            "pcap_get_tstamp_precision": ([pointer], C.c_int),
            "pcap_geterr": ([pointer], C.c_char_p),
            "pcap_next_ex": ([pointer, C.POINTER(C.POINTER(_PcapHeader)),
                              C.POINTER(C.POINTER(C.c_ubyte))], C.c_int),
            "pcap_stats": ([pointer, C.POINTER(_PcapStat)], C.c_int),
            "pcap_close": ([pointer], None),
            "pcap_compile": ([pointer, C.POINTER(_BpfProgram), C.c_char_p,
                              C.c_int, C.c_uint32], C.c_int),
            "pcap_setfilter": ([pointer, C.POINTER(_BpfProgram)], C.c_int),
            "pcap_freecode": ([C.POINTER(_BpfProgram)], None),
            "pcap_setnonblock": ([pointer, C.c_int, char_buffer], C.c_int),
            "pcap_getnonblock": ([pointer, char_buffer], C.c_int),
        }
        for name in ("snaplen", "promisc", "timeout", "buffer_size"):
            signatures[f"pcap_set_{name}"] = ([pointer, C.c_int], C.c_int)
        try:
            for name, (arguments, result) in signatures.items():
                function = getattr(dll, name)
                function.argtypes = arguments
                function.restype = result
                setattr(self, name, function)
        except AttributeError as exc:
            raise NpcapUnavailable("Installed Npcap lacks a required capture API") from exc
        self.version = _text(self.pcap_lib_version())
        if not self.version.startswith("Npcap version "):
            raise NpcapUnavailable("The trusted DLL does not identify itself as Npcap")
        error = C.create_string_buffer(PCAP_ERRBUF_SIZE)
        if self.pcap_init(_PCAP_CHAR_ENC_UTF_8, error) != 0:
            raise NpcapUnavailable(f"Npcap UTF-8 initialization failed: {_text(error.value)}")


_api: _NativeApi | None = None
_api_lock = threading.Lock()


def _get_api() -> _NativeApi:
    global _api
    with _api_lock:
        if _api is None:
            _api = _NativeApi(_load_dll())
        return _api


def lib_version() -> str:
    return _get_api().version


def findalldevs() -> list[str]:
    """Enumerate local capture names without opening a live capture handle."""
    api = _get_api()
    head = C.POINTER(_PcapIf)()
    error = C.create_string_buffer(PCAP_ERRBUF_SIZE)
    result = api.pcap_findalldevs(C.byref(head), error)
    if result != 0:
        # libpcap owns/frees a failed enumeration; head is only caller-owned on
        # success, per pcap_findalldevs' API contract.
        raise NpcapError(f"Npcap interface enumeration failed ({result}): {_text(error.value)}")
    names: list[str] = []
    seen: set[int] = set()
    try:
        current = head
        while current:
            address = C.addressof(current.contents)
            if address in seen or len(seen) >= 4096:
                raise NpcapError("Npcap returned an invalid interface list")
            seen.add(address)
            item = current.contents
            if not item.name:
                raise NpcapError("Npcap returned an interface without a name")
            names.append(item.name.decode("utf-8", errors="strict"))
            current = item.next
    finally:
        if head:
            api.pcap_freealldevs(head)
    return names


class NpcapHandle:
    """Owned, serialized native handle; close cannot race a packet copy."""

    def __init__(self, api: _NativeApi, pointer: Any, *, offline: bool) -> None:
        if not pointer:
            raise NpcapError("Npcap returned a null capture handle")
        self._api = api
        self._pointer = pointer
        self._offline = offline
        self._active = offline
        self._nonblocking = False
        self._eof = False
        self._received = 0
        self._snapshot = MAX_PACKET_BYTES
        self._precision = "micro"
        self._lock = threading.RLock()

    def _require(self, *, active: bool = True) -> None:
        if self._pointer is None:
            raise NpcapError("Npcap capture handle is closed")
        if active and not self._active:
            raise NpcapError("Npcap capture handle is not activated")

    def geterr(self) -> str:
        with self._lock:
            self._require(active=False)
            return _text(self._api.pcap_geterr(self._pointer))

    def _check(self, operation: str, result: int) -> None:
        if result != 0:
            raise NpcapError(f"{operation} failed ({result}): {self.geterr()}")

    def _set(self, name: str, value: int, maximum: int = 2**31 - 1) -> None:
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError(f"{name} must be an integer from 1 to {maximum}")
        with self._lock:
            self._require(active=False)
            if self._active:
                raise NpcapError("Capture options must be set before activation")
            self._check(name, getattr(self._api, f"pcap_set_{name}")(self._pointer, value))

    def set_snaplen(self, value: int) -> None:
        self._set("snaplen", value, MAX_PACKET_BYTES)

    def set_timeout(self, value: int) -> None:
        self._set("timeout", value)

    def set_buffer_size(self, value: int) -> None:
        self._set("buffer_size", value)

    def set_promisc(self, value: bool | int) -> None:
        if value not in (False, True) or not isinstance(value, (bool, int)):
            raise ValueError("promiscuous mode must be 0 or 1")
        with self._lock:
            self._require(active=False)
            if self._active:
                raise NpcapError("Capture options must be set before activation")
            self._check("set_promisc", self._api.pcap_set_promisc(self._pointer, int(value)))

    def _read_metadata(self) -> None:
        snapshot = self._api.pcap_snapshot(self._pointer)
        precision = self._api.pcap_get_tstamp_precision(self._pointer)
        if snapshot <= 0:
            raise NpcapError(f"Npcap returned an invalid snapshot length: {snapshot}")
        if precision not in (0, 1):
            raise NpcapError(f"Npcap returned an unsupported timestamp precision: {precision}")
        self._snapshot = min(snapshot, MAX_PACKET_BYTES)
        self._precision = "nano" if precision else "micro"

    def activate(self) -> None:
        with self._lock:
            self._require(active=False)
            if self._active:
                raise NpcapError("Npcap handle is already activated")
            result = self._api.pcap_activate(self._pointer)
            if result < 0:
                self._check("activate", result)
            self._active = True
            if result > 0:
                # A warning (e.g. promiscuous mode unavailable) means requested
                # capture semantics did not hold. Never silently downgrade.
                raise NpcapError(f"Npcap activation warning ({result}); capture refused: {self.geterr()}")
            self._read_metadata()

    def datalink(self) -> int:
        with self._lock:
            self._require()
            result = self._api.pcap_datalink(self._pointer)
            if result < 0:
                self._check("datalink", result)
            return result

    def setfilter(self, expression: str) -> None:
        encoded = _encode(expression, "BPF filter")
        with self._lock:
            self._require()
            program = _BpfProgram()
            self._check("compile BPF", self._api.pcap_compile(
                self._pointer, C.byref(program), encoded, 1, 0xFFFFFFFF))
            try:
                self._check("set BPF", self._api.pcap_setfilter(self._pointer, C.byref(program)))
            finally:
                self._api.pcap_freecode(C.byref(program))

    def setnonblock(self, value: int) -> int:
        if type(value) is not int or value not in (0, 1):
            raise ValueError("nonblocking mode must be 0 or 1")
        with self._lock:
            self._require()
            error = C.create_string_buffer(PCAP_ERRBUF_SIZE)
            result = self._api.pcap_setnonblock(self._pointer, value, error)
            if result != 0:
                raise NpcapError(f"setnonblock failed ({result}): {_text(error.value)}")
            observed = self.getnonblock()
            if not self._offline and observed != value:
                raise NpcapError("Npcap did not apply the requested nonblocking state")
            return 0

    def getnonblock(self) -> int:
        with self._lock:
            self._require()
            error = C.create_string_buffer(PCAP_ERRBUF_SIZE)
            result = self._api.pcap_getnonblock(self._pointer, error)
            if result not in (0, 1):
                raise NpcapError(f"getnonblock failed ({result}): {_text(error.value)}")
            self._nonblocking = bool(result)
            return result

    def next(self) -> tuple[PacketHeader | None, bytes]:
        with self._lock:
            self._require()
            if not self._offline and not self._nonblocking:
                raise NpcapError("Live reads require verified nonblocking mode")
            if self._eof:
                return None, b""
            native_header = C.POINTER(_PcapHeader)()
            native_data = C.POINTER(C.c_ubyte)()
            result = self._api.pcap_next_ex(self._pointer, C.byref(native_header), C.byref(native_data))
            if result == 0 and not self._offline:
                return None, b""
            if result == -2 and self._offline:
                self._eof = True
                return None, b""
            if result != 1:
                raise NpcapError(f"pcap_next_ex failed or returned unexpected status ({result}): {self.geterr()}")
            if not native_header:
                raise NpcapError("Npcap returned a packet without a header")
            header = native_header.contents
            captured, wire = int(header.caplen), int(header.len)
            fraction = int(header.ts.tv_usec)
            if captured > self._snapshot or wire < captured:
                raise NpcapError("Npcap packet lengths exceed the snapshot/safety limit or wire length")
            if not 0 <= fraction < (1_000_000_000 if self._precision == "nano" else 1_000_000):
                raise NpcapError("Npcap returned an invalid timestamp fraction")
            if captured and not native_data:
                raise NpcapError("Npcap returned a packet without captured data")
            # Copy both metadata and payload before the next native call can
            # invalidate their borrowed pointers. Never copy unbounded lengths.
            copied_header = PacketHeader(int(header.ts.tv_sec), fraction, captured,
                                         wire, self._precision)
            data = C.string_at(native_data, captured) if captured else b""
            self._received += 1
            return copied_header, data

    def stats(self) -> tuple[int, int, int]:
        with self._lock:
            self._require()
            if self._offline:
                return self._received, 0, 0
            values = _PcapStat()
            self._check("stats", self._api.pcap_stats(self._pointer, C.byref(values)))
            return int(values.ps_recv), int(values.ps_drop), int(values.ps_ifdrop)

    def close(self) -> None:
        with self._lock:
            if self._pointer is not None:
                pointer, self._pointer = self._pointer, None
                self._api.pcap_close(pointer)

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


def create(interface: str) -> NpcapHandle:
    encoded = _encode(interface, "interface")
    if not interface.startswith("\\Device\\NPF_"):
        raise ValueError("Use an exact local Npcap device name from findalldevs()")
    api = _get_api()
    error = C.create_string_buffer(PCAP_ERRBUF_SIZE)
    pointer = api.pcap_create(encoded, error)
    if not pointer:
        raise NpcapError(f"Npcap create failed: {_text(error.value)}")
    return NpcapHandle(api, pointer, offline=False)


def open_offline(path: str | os.PathLike[str]) -> NpcapHandle:
    filename = os.fspath(path)
    encoded = _encode(filename, "capture path")
    if filename == "-":
        raise ValueError("Standard-input capture is not supported")
    api = _get_api()
    error = C.create_string_buffer(PCAP_ERRBUF_SIZE)
    pointer = api.pcap_open_offline_with_tstamp_precision(
        encoded, _PCAP_TSTAMP_PRECISION_NANO, error)
    if not pointer:
        raise NpcapError(f"Npcap offline open failed: {_text(error.value)}")
    handle = NpcapHandle(api, pointer, offline=True)
    try:
        handle._read_metadata()
    except Exception:
        handle.close()
        raise
    return handle
