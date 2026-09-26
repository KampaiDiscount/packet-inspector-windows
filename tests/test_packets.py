from __future__ import annotations

import ipaddress
from pathlib import Path
import random
import struct
import tempfile
import unittest
from unittest import mock

from packet_audit import capture
from packet_audit.capture import (
    CaptureError,
    DEFAULT_BPF,
    PcapyLiveSource,
    PcapyOfflineSource,
    PcapyUnavailable,
)
from packet_audit.models import CapturedPacket
from packet_audit.packets import (
    DLT_EN10MB,
    DLT_LINUX_SLL,
    DLT_LINUX_SLL2,
    DLT_RAW,
    parse_packet,
    parse_packet_strict,
    PacketDecodeError,
)


def tcp_segment(
    payload: bytes,
    *,
    sport: int = 12345,
    dport: int = 80,
    sequence: int = 10,
    flags: int = 0x18,
) -> bytes:
    return struct.pack(
        "!HHIIBBHHH", sport, dport, sequence, 0, 0x50, flags, 65535, 0, 0
    ) + payload


def udp_datagram(
    payload: bytes, *, sport: int = 5353, dport: int = 53
) -> bytes:
    return struct.pack("!HHHH", sport, dport, len(payload) + 8, 0) + payload


def ipv4(
    payload: bytes,
    *,
    protocol: int = 6,
    identification: int = 7,
    fragment_offset: int = 0,
    more_fragments: bool = False,
) -> bytes:
    flags_offset = (0x2000 if more_fragments else 0) | (fragment_offset // 8)
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        identification,
        flags_offset,
        64,
        protocol,
        0,
        ipaddress.IPv4Address("10.0.0.1").packed,
        ipaddress.IPv4Address("10.0.0.2").packed,
    ) + payload


def ipv6(payload: bytes, *, next_header: int = 17) -> bytes:
    return struct.pack(
        "!IHBB16s16s",
        6 << 28,
        len(payload),
        next_header,
        64,
        ipaddress.IPv6Address("2001:db8::1").packed,
        ipaddress.IPv6Address("2001:db8::2").packed,
    ) + payload


def ethernet(payload: bytes, *, vlan_ids: tuple[int, ...] = ()) -> bytes:
    macs = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b"
    if not vlan_ids:
        return macs + struct.pack("!H", 0x0800) + payload
    frame = macs + struct.pack("!H", 0x88A8)
    for index, vlan_id in enumerate(vlan_ids):
        following = 0x0800 if index == len(vlan_ids) - 1 else 0x8100
        frame += struct.pack("!HH", vlan_id, following)
    return frame + payload


def captured(raw: bytes, datalink: int, *, packet_id: int = 1) -> CapturedPacket:
    return CapturedPacket(
        session_id="test",
        packet_id=packet_id,
        timestamp_ns=1_000_000_000 + packet_id,
        interface="eth0",
        datalink=datalink,
        captured_length=len(raw),
        wire_length=len(raw),
        raw=raw,
    )


class PacketParsingTests(unittest.TestCase):
    def test_live_source_configures_pcapy_and_batches(self) -> None:
        frame = ethernet(ipv4(tcp_segment(b"batch")))

        class Header:
            def getts(self):
                return 7, 8

            def getcaplen(self):
                return len(frame)

            def getlen(self):
                return len(frame)

        class Handle:
            def __init__(self):
                self.frames = [(Header(), frame), (Header(), frame)]
                self.settings = {}

            def set_snaplen(self, value):
                self.settings["snaplen"] = value

            def set_promisc(self, value):
                self.settings["promisc"] = value

            def set_timeout(self, value):
                self.settings["timeout"] = value

            def set_buffer_size(self, value):
                self.settings["buffer"] = value

            def activate(self):
                self.settings["active"] = True

            def setnonblock(self, value):
                self.settings["nonblock"] = value

            def setfilter(self, value):
                self.settings["filter"] = value

            def datalink(self):
                return DLT_EN10MB

            def dispatch(self, limit, callback):
                selected = self.frames[:limit]
                self.frames = self.frames[limit:]
                for header, data in selected:
                    callback(header, data)
                return len(selected)

            def stats(self):
                return 20, 2, 1

            def close(self):
                self.settings["closed"] = True

        class Pcapy:
            def __init__(self):
                self.handle = Handle()

            def create(self, interface):
                self.handle.settings["interface"] = interface
                return self.handle

        pcapy = Pcapy()
        source = PcapyLiveSource(
            "eth0",
            timeout_ms=25,
            buffer_size_mb=4,
            batch_size=16,
            pcapy_module=pcapy,
        )
        batch = source.read_batch()

        self.assertEqual([packet.packet_id for packet in batch], [1, 2])
        self.assertEqual(batch[0].timestamp_ns, 7_000_008_000)
        self.assertEqual(source.stats().dropped, 2)
        self.assertEqual(pcapy.handle.settings["buffer"], 4 * 1024 * 1024)
        self.assertEqual(pcapy.handle.settings["filter"], DEFAULT_BPF)
        self.assertEqual(pcapy.handle.settings["nonblock"], 1)
        source.close()
        self.assertTrue(pcapy.handle.settings["closed"])

    def test_ethernet_stacked_vlan_ipv4_tcp(self) -> None:
        frame = ethernet(ipv4(tcp_segment(b"user=alice")), vlan_ids=(100, 200))
        result = parse_packet(captured(frame, DLT_EN10MB))

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.vlan_ids, (100, 200))
        self.assertEqual((result.src, result.dst), ("10.0.0.1", "10.0.0.2"))
        self.assertEqual((result.sport, result.dport), (12345, 80))
        self.assertEqual(result.transport_payload, b"user=alice")
        self.assertTrue(result.transport_parsed)

    def test_live_dispatch_error_is_fatal_instead_of_looking_idle(self) -> None:
        class Handle:
            def set_snaplen(self, _value): pass
            def set_promisc(self, _value): pass
            def set_timeout(self, _value): pass
            def set_buffer_size(self, _value): pass
            def activate(self): pass
            def setnonblock(self, _value): pass
            def setfilter(self, _value): pass
            def datalink(self): return DLT_EN10MB
            def dispatch(self, _limit, _callback): return -1
            def geterr(self): return "synthetic capture failure"

        class Pcapy:
            @staticmethod
            def create(_interface): return Handle()

        source = PcapyLiveSource("eth0", pcapy_module=Pcapy())
        with self.assertRaisesRegex(CaptureError, "synthetic capture failure"):
            source.read_batch()

    def test_live_source_rejects_blocking_or_excessive_read_timeout(self) -> None:
        for timeout_ms in (0, 5_001):
            with self.subTest(timeout_ms=timeout_ms):
                with self.assertRaisesRegex(ValueError, "invalid live capture sizing"):
                    PcapyLiveSource("eth0", read_timeout_ms=timeout_ms)

    def test_lenient_packet_parser_contains_random_malformed_frames(self) -> None:
        rng = random.Random(20260827)
        datalinks = (DLT_EN10MB, DLT_LINUX_SLL, DLT_LINUX_SLL2, DLT_RAW)
        for packet_id in range(1, 1001):
            raw = rng.randbytes(rng.randrange(0, 768))
            packet = CapturedPacket(
                session_id="malformed-smoke",
                packet_id=packet_id,
                timestamp_ns=packet_id,
                interface="fuzz0",
                datalink=rng.choice(datalinks),
                captured_length=len(raw),
                wire_length=len(raw),
                raw=raw,
            )
            parse_packet(packet)

    def test_linux_cooked_headers(self) -> None:
        network = ipv4(udp_datagram(b"dns"), protocol=17)
        for datalink in (DLT_LINUX_SLL, DLT_LINUX_SLL2):
            with self.subTest(datalink=datalink):
                if datalink == DLT_LINUX_SLL:
                    raw = b"\x00" * 14 + struct.pack("!H", 0x0800) + network
                else:
                    raw = struct.pack("!H", 0x0800) + b"\x00" * 18 + network
                result = parse_packet(captured(raw, datalink))
                self.assertIsNotNone(result)
                assert result is not None
                self.assertEqual(result.protocol, 17)
                self.assertEqual(result.transport_payload, b"dns")

    def test_raw_ipv6_udp_and_extension_header(self) -> None:
        udp = udp_datagram(b"secret", sport=123, dport=456)
        destination_options = bytes((17, 0)) + b"\x00" * 6
        result = parse_packet(
            captured(ipv6(destination_options + udp, next_header=60), DLT_RAW)
        )

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.ip_version, 6)
        self.assertEqual(result.src, "2001:db8::1")
        self.assertEqual((result.sport, result.dport), (123, 456))
        self.assertEqual(result.transport_payload, b"secret")

    def test_fragment_is_not_misparsed_as_transport(self) -> None:
        first = ipv4(
            tcp_segment(b"split")[:24],
            identification=55,
            fragment_offset=0,
            more_fragments=True,
        )
        result = parse_packet(captured(first, DLT_RAW))

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.fragment_id, 55)
        self.assertTrue(result.more_fragments)
        self.assertFalse(result.transport_parsed)

    def test_short_or_invalid_packets_fail_closed(self) -> None:
        cases = [
            (b"\x00" * 13, DLT_EN10MB),
            (b"\x45" + b"\x00" * 10, DLT_RAW),
            (b"\x60" + b"\x00" * 30, DLT_RAW),
            (b"\x70" + b"\x00" * 50, DLT_RAW),
        ]
        for raw, datalink in cases:
            with self.subTest(datalink=datalink, length=len(raw)):
                self.assertIsNone(parse_packet(captured(raw, datalink)))
        with self.assertRaises(PacketDecodeError):
            parse_packet_strict(captured(b"\x00", DLT_EN10MB))

    def test_classic_pcap_stdlib_replay(self) -> None:
        frame = ethernet(ipv4(tcp_segment(b"hello")))
        global_header = b"\xd4\xc3\xb2\xa1" + struct.pack(
            "<HHIIII", 2, 4, 0, 0, 65535, DLT_EN10MB
        )
        record = struct.pack("<IIII", 10, 123, len(frame), len(frame)) + frame

        def unavailable():
            raise PcapyUnavailable("not installed")

        with tempfile.TemporaryDirectory() as directory:
            pcap = Path(directory) / "sample.pcap"
            pcap.write_bytes(global_header + record)
            with mock.patch.object(capture, "_load_pcapy", unavailable):
                source = PcapyOfflineSource(
                    pcap, session_id="replay", batch_size=8
                )
                batch = source.read_batch()
                self.assertEqual(len(batch), 1)
                self.assertEqual(batch[0].timestamp_ns, 10_000_123_000)
                self.assertEqual(batch[0].raw, frame)
                self.assertEqual(source.stats().received, 1)
                self.assertEqual(source.read_batch(), [])
                self.assertTrue(source.eof)
                source.close()


if __name__ == "__main__":
    unittest.main()
