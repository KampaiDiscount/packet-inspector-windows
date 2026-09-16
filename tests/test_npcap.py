"""Npcap adapter regressions. No test opens a real live capture handle."""

import ctypes as C
import os
from pathlib import Path
import struct
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from packet_audit import npcap as n
from packet_audit.capture import PcapyOfflineSource


@pytest.fixture
def api():
    result = SimpleNamespace()
    for name in ("activate", "set_snaplen", "set_promisc", "set_timeout", "set_buffer_size",
                 "setnonblock", "compile", "setfilter", "stats", "close", "freecode",
                 "freealldevs"):
        setattr(result, "pcap_" + name, Mock(return_value=0))
    result.pcap_snapshot = Mock(return_value=65535)
    result.pcap_get_tstamp_precision = Mock(return_value=0)
    result.pcap_datalink = Mock(return_value=1)
    result.pcap_getnonblock = Mock(return_value=1)
    result.pcap_geterr = Mock(return_value=b"synthetic native failure")
    result.pcap_next_ex = Mock(return_value=-2)
    result.pcap_create = Mock(return_value=123)
    result.pcap_open_offline_with_tstamp_precision = Mock(return_value=123)
    return result


def handle(api, *, offline=True):
    capture = n.NpcapHandle(api, 123, offline=offline)
    if offline:
        capture._read_metadata()
    return capture


def packet_result(api, raw=b"abc", *, captured=None, wire=None, fraction=123456):
    header = n._PcapHeader(n._Timeval(1700000000, fraction),
                           len(raw) if captured is None else captured,
                           len(raw) if wire is None else wire)
    data = (C.c_ubyte * len(raw)).from_buffer_copy(raw)

    def read(_pointer, header_out, data_out):
        C.cast(header_out, C.POINTER(C.POINTER(n._PcapHeader)))[0] = C.pointer(header)
        C.cast(data_out, C.POINTER(C.POINTER(C.c_ubyte)))[0] = C.cast(data, C.POINTER(C.c_ubyte))
        return 1

    api.pcap_next_ex.side_effect = read
    return header, data


def test_windows_abi_layout_is_explicit():
    assert C.sizeof(n._Timeval) == 8
    assert C.sizeof(n._PcapHeader) == 16
    assert n._PcapHeader.caplen.offset == 8
    assert n._PcapHeader.len.offset == 12
    assert C.sizeof(n._PcapStat) == 24
    assert n._PcapStat.ps_netdrop.offset == 20
    assert n._BpfProgram.bf_insns.offset == C.sizeof(C.c_void_p)


def test_dll_loader_never_searches_working_directory_or_path(tmp_path, monkeypatch):
    installed = tmp_path / "Npcap"
    installed.mkdir()
    dll_path = installed / "wpcap.dll"
    dll_path.write_bytes(b"mock DLL; never executed")
    monkeypatch.setattr(n, "_system_directory", lambda: tmp_path)
    loader = Mock(return_value=object())
    monkeypatch.setattr(n.C, "CDLL", loader)
    n._load_dll()
    loader.assert_called_once_with(str(dll_path), winmode=0x900)


def test_missing_trusted_dll_does_not_fall_back(tmp_path, monkeypatch):
    monkeypatch.setattr(n, "_system_directory", lambda: tmp_path)
    loader = Mock()
    monkeypatch.setattr(n.C, "CDLL", loader)
    with pytest.raises(n.NpcapUnavailable, match="Cannot load installed"):
        n._load_dll()
    loader.assert_not_called()


def test_missing_native_api_is_visible():
    with pytest.raises(n.NpcapUnavailable, match="required capture API"):
        n._NativeApi(SimpleNamespace())


def test_read_copies_header_and_data_before_next_native_call(api):
    native, buffer = packet_result(api, wire=9)
    capture = handle(api)
    header, raw = capture.next()
    native.ts.tv_sec = 5
    buffer[0] = ord("z")
    assert raw == b"abc"
    assert header.getts() == (1700000000, 123456)
    assert header.getcaplen() == 3
    assert header.getlen() == 9
    assert header.timestamp_precision == "micro"
    assert capture.stats() == (1, 0, 0)


@pytest.mark.parametrize("captured,wire,fraction", [
    (65536, 65536, 0), (n.MAX_PACKET_BYTES + 1, n.MAX_PACKET_BYTES + 1, 0),
    (3, 2, 0), (3, 3, -1), (3, 3, 1_000_000),
])
def test_invalid_packet_metadata_is_rejected_before_copy(api, monkeypatch, captured, wire, fraction):
    packet_result(api, captured=captured, wire=wire, fraction=fraction)
    capture = handle(api)
    copy = Mock(side_effect=AssertionError("unsafe packet copy"))
    monkeypatch.setattr(n.C, "string_at", copy)
    with pytest.raises(n.NpcapError):
        capture.next()
    copy.assert_not_called()


@pytest.mark.parametrize("which", ["header", "data"])
def test_null_native_packet_pointers_are_errors(api, which):
    native = n._PcapHeader(n._Timeval(1, 0), 3, 3)

    def read(_pointer, header_out, _data_out):
        if which == "data":
            C.cast(header_out, C.POINTER(C.POINTER(n._PcapHeader)))[0] = C.pointer(native)
        return 1

    api.pcap_next_ex.side_effect = read
    with pytest.raises(n.NpcapError, match="without"):
        handle(api).next()


def test_zero_length_packet_is_not_eof(api):
    packet_result(api, raw=b"")
    header, raw = handle(api).next()
    assert header is not None
    assert header.getcaplen() == 0
    assert raw == b""


def test_offline_eof_is_sticky_and_does_not_read_again(api):
    capture = handle(api)
    assert capture.next() == (None, b"")
    assert capture.next() == (None, b"")
    api.pcap_next_ex.assert_called_once()


def test_live_timeout_is_not_eof_and_reads_are_nonblocking(api):
    capture = handle(api, offline=False)
    capture.activate()
    with pytest.raises(n.NpcapError, match="verified nonblocking"):
        capture.next()
    api.pcap_next_ex.assert_not_called()
    capture.setnonblock(1)
    api.pcap_next_ex.return_value = 0
    assert capture.next() == (None, b"")
    packet_result(api)
    assert capture.next()[1] == b"abc"


@pytest.mark.parametrize("offline,status", [
    (True, 0), (False, -2), (True, -1), (False, -1), (True, -3), (True, 2),
])
def test_native_errors_and_wrong_mode_status_never_look_idle(api, offline, status):
    capture = handle(api, offline=offline)
    if not offline:
        capture.activate()
        capture.setnonblock(1)
    api.pcap_next_ex.return_value = status
    with pytest.raises(n.NpcapError, match=f"status \\({status}\\)"):
        capture.next()


@pytest.mark.parametrize("method,value", [
    ("set_snaplen", 0), ("set_snaplen", n.MAX_PACKET_BYTES + 1),
    ("set_timeout", -1), ("set_buffer_size", 2**31),
    ("set_promisc", 2), ("setnonblock", 2),
])
def test_bad_numeric_options_cannot_overflow_native_int(api, method, value):
    capture = handle(api, offline=False)
    with pytest.raises(ValueError):
        getattr(capture, method)(value)


@pytest.mark.parametrize("method,value", [
    ("set_snaplen", 65535), ("set_promisc", True),
    ("set_timeout", 100), ("set_buffer_size", 8 * 1024 * 1024),
])
def test_pre_activation_options_and_native_failures(api, method, value):
    capture = handle(api, offline=False)
    native = getattr(api, "pcap_" + method)
    getattr(capture, method)(value)
    native.assert_called_once_with(123, int(value))
    native.return_value = -1
    with pytest.raises(n.NpcapError, match="failed"):
        getattr(capture, method)(value)
    native.return_value = 0
    capture.activate()
    with pytest.raises(n.NpcapError, match="before activation"):
        getattr(capture, method)(value)


@pytest.mark.parametrize("status", [-1, 1, 2])
def test_activation_errors_and_warnings_are_visible(api, status):
    api.pcap_activate.return_value = status
    capture = handle(api, offline=False)
    with pytest.raises(n.NpcapError):
        capture.activate()
    capture.close()
    api.pcap_close.assert_called_once_with(123)


def test_nonblock_must_be_confirmed(api):
    capture = handle(api, offline=False)
    capture.activate()
    api.pcap_getnonblock.return_value = 0
    with pytest.raises(n.NpcapError, match="did not apply"):
        capture.setnonblock(1)
    api.pcap_setnonblock.return_value = -1
    with pytest.raises(n.NpcapError, match="setnonblock failed"):
        capture.setnonblock(1)
    api.pcap_getnonblock.return_value = -1
    with pytest.raises(n.NpcapError, match="getnonblock failed"):
        capture.getnonblock()


def test_bpf_program_is_freed_on_install_failure(api):
    capture = handle(api)
    api.pcap_setfilter.return_value = -1
    with pytest.raises(n.NpcapError, match="set BPF"):
        capture.setfilter("ip or ip6")
    api.pcap_freecode.assert_called_once()


def test_bpf_compile_failure_is_visible(api):
    capture = handle(api)
    api.pcap_compile.return_value = -1
    with pytest.raises(n.NpcapError, match="compile BPF"):
        capture.setfilter("not valid")
    api.pcap_setfilter.assert_not_called()
    api.pcap_freecode.assert_not_called()


def test_windows_extended_stats_buffer_and_errors(api):
    capture = handle(api, offline=False)
    capture.activate()

    def stats(_pointer, output):
        values = C.cast(output, C.POINTER(n._PcapStat)).contents
        for index, (field, _) in enumerate(n._PcapStat._fields_):
            setattr(values, field, 10 + index)
        return 0

    api.pcap_stats.side_effect = stats
    assert capture.stats() == (10, 11, 12)
    api.pcap_stats.side_effect = None
    api.pcap_stats.return_value = -1
    with pytest.raises(n.NpcapError, match="stats failed"):
        capture.stats()


def test_close_is_idempotent_and_closed_reads_are_errors(api):
    capture = handle(api)
    capture.close()
    capture.close()
    api.pcap_close.assert_called_once_with(123)
    with pytest.raises(n.NpcapError, match="closed"):
        capture.next()
    api.pcap_next_ex.assert_not_called()


def test_interface_enumeration_copies_names_and_frees_list(api, monkeypatch):
    second = n._PcapIf()
    second.name = b"\\Device\\NPF_Loopback"
    first = n._PcapIf()
    first.name = b"\\Device\\NPF_{synthetic}"
    first.next = C.pointer(second)

    def enumerate_devices(output, _error):
        C.cast(output, C.POINTER(C.POINTER(n._PcapIf)))[0] = C.pointer(first)
        return 0

    api.pcap_findalldevs = Mock(side_effect=enumerate_devices)
    monkeypatch.setattr(n, "_get_api", lambda: api)
    assert n.findalldevs() == ["\\Device\\NPF_{synthetic}", "\\Device\\NPF_Loopback"]
    api.pcap_freealldevs.assert_called_once()
    api.pcap_create.assert_not_called()


def test_interface_enumeration_failure_is_not_an_empty_list(api, monkeypatch):
    api.pcap_findalldevs = Mock(return_value=-1)
    monkeypatch.setattr(n, "_get_api", lambda: api)
    with pytest.raises(n.NpcapError, match="enumeration failed"):
        n.findalldevs()


def test_create_accepts_only_exact_local_names_and_rejects_null_handle(api, monkeypatch):
    monkeypatch.setattr(n, "_get_api", lambda: api)
    for invalid in ("", "Ethernet", "rpcap://remote/device", "\\Device\\NPF_x\x00y"):
        with pytest.raises(ValueError):
            n.create(invalid)
    api.pcap_create.assert_not_called()
    api.pcap_create.return_value = None
    with pytest.raises(n.NpcapError, match="create failed"):
        n.create("\\Device\\NPF_Loopback")


def test_offline_open_uses_utf8_nano_and_closes_on_metadata_failure(api, monkeypatch):
    monkeypatch.setattr(n, "_get_api", lambda: api)
    api.pcap_snapshot.return_value = -1
    with pytest.raises(n.NpcapError, match="snapshot"):
        n.open_offline("synthetic-\u00e9.pcapng")
    assert api.pcap_open_offline_with_tstamp_precision.call_args.args[:2] == (
        "synthetic-\u00e9.pcapng".encode(), 1)
    api.pcap_close.assert_called_once_with(123)


def _native_or_skip():
    if os.name != "nt":
        pytest.skip("Native offline Npcap probe requires Windows")
    try:
        n.lib_version()
    except n.NpcapUnavailable as exc:
        pytest.skip(str(exc))


def _synthetic_pcap(records):
    output = struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1)
    for index, raw in enumerate(records):
        output += struct.pack("<IIII", 100 + index, 123456789, len(raw), len(raw) + index) + raw
    return output


def _synthetic_pcapng(records):
    output = struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    output += struct.pack("<IIHHII", 1, 20, 1, 0, 65535, 20)
    for index, raw in enumerate(records):
        padded = raw + b"\x00" * (-len(raw) % 4)
        length = 32 + len(padded)
        timestamp = (100 + index) * 1_000_000 + 123456
        output += struct.pack("<IIIIIII", 6, length, 0, timestamp >> 32,
                              timestamp & 0xFFFFFFFF, len(raw), len(raw) + index)
        output += padded + struct.pack("<I", length)
    return output


@pytest.mark.parametrize("format", ["pcap", "pcapng"])
def test_native_offline_all_records_timestamps_and_batch_boundaries(tmp_path, format):
    _native_or_skip()
    # Synthetic only; no native create()/activate() call occurs here.
    records = [b"\x00" * 12 + b"\x08\x00" + bytes([index]) * 51 for index in range(37)]
    path = tmp_path / ("synthetic-\u00e9." + format)
    path.write_bytes(_synthetic_pcap(records) if format == "pcap" else _synthetic_pcapng(records))
    with PcapyOfflineSource(path, batch_size=7, pcapy_module=n) as source:
        captured = list(source)
        assert source.eof
        assert source.read_batch() == []
        assert source.stats().received == 37
    assert [packet.raw for packet in captured] == records
    assert [packet.packet_id for packet in captured] == list(range(1, 38))
    fraction = 123456789 if format == "pcap" else 123456000
    assert [packet.timestamp_ns for packet in captured] == [
        (100 + index) * 1_000_000_000 + fraction for index in range(37)]
    assert [packet.wire_length for packet in captured] == [len(raw) + index for index, raw in enumerate(records)]


def test_native_offline_bpf_and_corruption_are_not_silent(tmp_path):
    _native_or_skip()
    ipv4 = b"\x00" * 12 + b"\x08\x00" + b"\x45" + b"\x00" * 45
    arp = b"\x00" * 12 + b"\x08\x06" + b"\x00" * 46
    path = tmp_path / "filter.pcap"
    path.write_bytes(_synthetic_pcap([arp, ipv4, arp, ipv4]))
    with PcapyOfflineSource(path, bpf="ip", pcapy_module=n) as source:
        assert [packet.raw for packet in source] == [ipv4, ipv4]
    path.write_bytes(_synthetic_pcap([ipv4])[:-4])
    capture = n.open_offline(path)
    try:
        with pytest.raises(n.NpcapError, match="pcap_next_ex"):
            capture.next()
    finally:
        capture.close()
