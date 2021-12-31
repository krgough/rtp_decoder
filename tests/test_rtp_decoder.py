"""
Tests for rtp_decoder
"""

import pytest

from rtp_decoder import __version__
from rtp_decoder import rtp_packets as rtp


def test_version():
    """ Confirm version is correct
    """
    assert __version__ == '0.1.0'


test_packets = [
    # Simple packet - no extensions
    ('8008d4340000303c0b12671a'
     'd5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5'
     'd5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5'
     'd5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5'
     'd5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5'
     'd5d5d5d5d5d5d5d5'),

    # Packet with extensions
    # 88 = Byte 1, Bit 3 set means extension(s) in packets
    # alba = Byte 12/13 = extension 'name'
    # deadbeaf = bytes 14-17 = 1st 32bit extension
    # cab00d1e = bytes 18-21 = 2nd 32bit extension
    ('8808d4340000303c0b12671aalba0002deadbeafcab00d1e'
     'd5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5'
     'd5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5'
     'd5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5'
     'd5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5'
     'd5d5d5d5d5d5d5d5'),
]


@pytest.mark.parametrize("test_data", test_packets)
def test_rtp_code_decode(test_data):
    """ With the given raw rtp bytes,
        decode those bytes to get the fields and data
        Recontruct packet with that data and confirm it
        matches the original raw data
    """
    packet_bytes = ('8008d4340000303c0b12671ad5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d'
                    '5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5'
                    'd5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d'
                    '5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5'
                    'd5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d'
                    '5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5'
                    'd5d5d5d5d5d5d5')
    packet_bytes = test_data
    d_pkt = rtp.decode_rtp_packet(packet_bytes)
    # print(d_pkt)

    # Test building a packet
    # print()
    pkt = rtp.generate_rtp_packet(d_pkt)
    # print(pkt)
    assert pkt == packet_bytes
