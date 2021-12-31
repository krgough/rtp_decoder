"""
Tests for rtp_decoder
"""
from rtp_decoder import __version__
from rtp_decoder import rtp_packets as rtp
# import pytest


def test_version():
    """ Confirm version is correct
    """
    assert __version__ == '0.1.0'


def test_rtp_code_decode():
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
    d_pkt = rtp.decode_rtp_packet(packet_bytes)
    # print(d_pkt)

    # Test building a packet
    # print()
    pkt = rtp.generate_rtp_packet(d_pkt)
    # print(pkt)
    assert pkt == packet_bytes
