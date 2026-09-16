import struct
import pytest
from packet_audit.packets import _link_payload, PacketDecodeError


@pytest.mark.parametrize('order', ['<', '>'])
@pytest.mark.parametrize('family,ethertype,body', [(2, 0x800, b'\x45packet'), (24, 0x86dd, b'\x60packet')])
def test_loopback_link_headers(order, family, ethertype, body):
    assert _link_payload(struct.pack(order + 'I', family) + body, 0) == (ethertype, body, ())


@pytest.mark.parametrize('data', [b'', b'\x02\x00', b'\x99\x00\x00\x00'])
def test_loopback_invalid_headers_fail_visibly(data):
    with pytest.raises(PacketDecodeError):
        _link_payload(data, 0)
