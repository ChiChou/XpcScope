import struct
import sys
import time
from typing import BinaryIO


class Pcap:
    output: BinaryIO

    def __init__(self, output: BinaryIO = sys.stdout.buffer):
        self.output = output

    def write_header(self):
        ETHERNET = 1

        FMT = "@ I H H i I I I "
        PCAP_MAGICAL_NUMBER = 0xA1B23C4D
        PCAP_MJ_VERN_NUMBER = 2
        PCAP_MI_VERN_NUMBER = 4
        PCAP_LOCAL_CORECTIN = 0
        PCAP_ACCUR_TIMSTAMP = 0
        PCAP_MAX_LENGTH_CAP = 65535
        PCAP_DATA_LINK_TYPE = ETHERNET

        pcap_header = struct.pack(
            FMT,
            PCAP_MAGICAL_NUMBER,
            PCAP_MJ_VERN_NUMBER,
            PCAP_MI_VERN_NUMBER,
            PCAP_LOCAL_CORECTIN,
            PCAP_ACCUR_TIMSTAMP,
            PCAP_MAX_LENGTH_CAP,
            PCAP_DATA_LINK_TYPE,
        )

        self.output.write(pcap_header)

    def write(self, packet: bytes, original_len: int):
        ts = time.time()
        sec = int(ts)
        ns = int((ts - sec) * 1_000_000_000)

        FMT = "@ I I I I"
        pcap_packet = struct.pack(
            FMT,
            sec,
            ns,
            len(packet),
            original_len,
        )

        try:
            self.output.write(pcap_packet)
            self.output.write(packet)
        except BrokenPipeError:
            sys.stderr.write('Broken pipe, WireShark exited?\n')
            return False

        self.output.flush()
        return True
