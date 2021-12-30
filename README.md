# Packet Decoder - RTP from PCAP files
Packets are captured using tcpdump running on the device.   
Audio is encoded in RTP over UDP.   
RTP packets are encrypted so we cannot fully decode but we can extract the headers and the raw data.

## RTP Decode
Originally taken from https://gitlab.com/nickvsnetworking/pyrtp/-/blob/master/pyrtp.py

