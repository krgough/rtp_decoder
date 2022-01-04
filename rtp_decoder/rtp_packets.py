#!/usr/bin/env python3
"""
RTP Packet Decoder

Takes a pcap file, extracts UDP frames where:

IP_src is 10.xx.xx.xx and UDP data starts with 0x90

These are the RTC audio frames (as used by webRTC)

RTC Specification:
https://datatracker.ietf.org/doc/html/rfc3550

"""

import logging
import csv

import dpkt

LOGGER = logging.getLogger(__name__)

IP_PROTOCOL_UDP = 17

FILES = [
    {"rate": 6, "file": "neo_6kbs_2g_20121220_1153.pcap"},
    {"rate": 10, "file": "neo_10kbs_2g_20211220_1142.pcap"},
    {"rate": 30, "file": "neo_30kbs_2g_20211220_1133.pcap"},
    {"rate": 40, "file": "neo_40kbs_2g_20211220_1110.pcap"},
]

FILE_PATH = "/Users/keithgough/Vodafone/saved_neo_logs/codec_logs/"


def extract_rtp_from_pcap(filename):
    # pylint: disable=invalid-name
    """Decode RTP frames from a pcap file
    RTP is used by webrtc for audio data
    """
    rtp_frames = []
    with open(filename, mode="rb") as file:
        pcap = dpkt.pcap.Reader(file)

        for t_stamp, buf in pcap:
            # print(ts, len(buf))
            # eth = dpkt.ethernet.Ethernet(buf)
            # eth = dpkt.sll.SLL2(buf)
            try:
                if pcap.datalink() == dpkt.pcap.DLT_LINUX_SLL2:
                    eth = dpkt.sll2.SLL2(buf)
                else:
                    eth = dpkt.ethernet.Ethernet(buf)
            except dpkt.dpkt.NeedData:
                # We can't work out the packet type
                # So skip it
                continue

            try:
                ip = eth.data
            except dpkt.PackError:
                continue

            # Find UDP packets
            try:
                if ip.p != IP_PROTOCOL_UDP:
                    continue
            except AttributeError:
                continue

            try:
                udp = ip.data
            except dpkt.PackError:
                continue

            src = ".".join([str(i) for i in list(ip.src)])
            dst = ".".join([str(i) for i in list(ip.dst)])

            # Our src device will always have a 10.xx.xx.xx IP addr
            # The wanted rtp frames start with 0x90
            if src.startswith("10") and udp.data.hex().startswith("90"):
                rtp_frames.append({"timestamp": t_stamp, "udp_data": udp.data.hex()})

            LOGGER.debug("%s, %s, %s, %s", t_stamp, src, dst, ip)

    return rtp_frames


def load_data(filename):
    """Load data from a csv file"""
    with open(filename, mode="r", encoding="utf-8") as file:
        data = [dict(row.items()) for row in csv.DictReader(file)]
    return data


def generate_rtp_packet(packet_vars):
    """Generate an RTP packet with the given data

    Example Usage:

    payload = ("d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5"
               "d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5"
               "d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5"
               "d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5"
               "d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5"
               "d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5")

    packet_vars = {"version": 2,
                   "padding": 0,
                   "extension": 0,
                   "csi_count": 0,
                   "marker": 0,
                   "payload_type": 8,
                   "sequence_number": 306,
                   "timestamp": 306,
                   "ssrc": 185755418,
                   "payload": payload}

    GenerateRTPpacket(packet_vars)
    The first twelve octets are present in every RTP packet, while the
    list of CSRC identifiers is present only when inserted by a mixer.
    """
    # RFC189 Version (Typically 2)
    version = f"{packet_vars['version']:02b}"
    # Padding - Typically false (0))
    padding = str(packet_vars["padding"])
    # Extension - Disabled
    extension = str(packet_vars["extension"])
    # Contributing Source Identifiers Count - typically 0
    csi_count = f"{packet_vars['csi_count']:04b}"

    byte1 = f"{int(version + padding + extension + csi_count, 2):02x}"
    # Generate second byte of header as binary string:
    # Marker (Typically false)
    marker = str(packet_vars["marker"])
    # 7 bit Payload Type (From https://tools.ietf.org/html/rfc3551#section-6)
    payload_type = f"{packet_vars['payload_type']:07b}"
    # Convert binary values to an int then format that as hex
    # with 2 bytes of padding if required
    byte2 = f"{int(marker + payload_type, 2):02x}"
    # 16 bit seq num - Starts from a random position and increments per packet
    seq_num = f"{packet_vars['sequence_number']:04x}"
    # Typically incrimented by the fixed time between packets
    t_stamp = f"{packet_vars['timestamp']:08x}"
    # SSRC 32 bits - Typ. randomly generated for each stream for uniqueness
    ssrc = f"{packet_vars['ssrc']:08x}"

    return "".join([byte1, byte2, seq_num, t_stamp, ssrc, packet_vars["payload"]])


def decode_rtp_packet(packet_bytes):
    """Decode an RTP packet

    Example Usage:

    packet_bytes = ("8008d4340000303c0b12671ad5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5"
                    "d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5"
                    "d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5"
                    "d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5"
                    "d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5"
                    "d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5"
                    "d5d5d5d5")

    rtp_params = DecodeRTPpacket(packet_bytes)

    Returns dict of variables from packet (packet_vars{})
    """
    packet_vars = {}

    # Get byte0 and convert to binary
    byte0 = f"{int(packet_bytes[0:2], 16):b}"

    # Get RTP Version
    packet_vars["version"] = int(byte0[0:2], 2)
    # Get padding bit
    packet_vars["padding"] = int(byte0[2:3])
    # Get extension bit
    packet_vars["extension"] = int(byte0[3:4])
    # Get csrc count
    packet_vars["csi_count"] = int(byte0[4:8], 2)

    # Get byte1 and Convert to Binary
    byte1 = f"{int(packet_bytes[2:4], 16):08b}"
    packet_vars["marker"] = int(byte1[0:1])
    packet_vars["payload_type"] = int(byte1[1:8], 2)

    # bytes 2,3 are the sequence number
    packet_vars["sequence_number"] = int(packet_bytes[4:8], 16)

    # bytes 4,5,6,7 are timestamp
    packet_vars["timestamp"] = int(packet_bytes[8:16], 16)

    # bytes 8,9,10,11 are sequence number
    packet_vars["ssrc"] = int(packet_bytes[16:24], 16)

    # If we have a header extension then we must extract
    # those extensions before we get the raw data
    if packet_vars["extension"]:
        # Bytes 12,13 are the hdr extension "name"
        # Bytes 14,15 are the length of the extension
        # defined as a count of 32bit words
        packet_vars["hdr_extension"] = packet_bytes[24:28]
        h_len = int(packet_bytes[28:32], 16)
        packet_vars["hdr_length"] = h_len
        data_idx = 32 + (h_len * 2 * 8)
        packet_vars["hdr_ext_data"] = packet_bytes[32:data_idx]
    else:
        data_idx = 24

    packet_vars["payload"] = packet_bytes[data_idx:]

    return packet_vars


def get_rtc_data(filename):
    """Extract RTC data from packets in the file"""
    rtp_data = extract_rtp_from_pcap(filename)
    raw_data = []
    seq_nums = []

    for rtp in rtp_data:
        d_pkt = decode_rtp_packet(rtp["udp_data"])

        # print(d_pkt)
        assert d_pkt["payload_type"] == 111
        assert d_pkt["version"] == 2
        assert d_pkt["padding"] == 0
        assert d_pkt["extension"] == 1
        assert d_pkt["csi_count"] == 0
        # Check if we have any repeated packets
        assert d_pkt["sequence_number"] not in seq_nums
        seq_nums.append(d_pkt["sequence_number"])

        raw_data.append(d_pkt["payload"])

        # Crude check for duplicate packets
        assert len(raw_data) == len(set(raw_data))

    duration = rtp_data[-1]["timestamp"] - rtp_data[0]["timestamp"]

    total_bytes = sum([len(c) for c in raw_data]) / 2
    # duration = len(raw_data) * 0.02
    data_rate = int(round(total_bytes * 8 / duration, 0))
    return data_rate, raw_data


def main():
    """Extract the RTC data from the given pcap files"""
    for file in FILES:
        filename = FILE_PATH + file["file"]
        data_rate, _ = get_rtc_data(filename)
        print(f"Data rate for {file['rate']}: {data_rate}bps")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
