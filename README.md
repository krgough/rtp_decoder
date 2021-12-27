# Packet Decoder for NEO Smartwatch
Packets are captures using tcpdump running on the watch.
Audio is encoded in RTP over UDP.  RTP packets are encrypted
so we cannot fully decode but we can extract the headers and
the raw data.

## RTP Decode
Originally taken from https://gitlab.com/nickvsnetworking/pyrtp/-/blob/master/pyrtp.py

