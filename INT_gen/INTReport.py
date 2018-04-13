#!/usr/bin/python
from scapy.all import *
import time

class TelemetryReport(Packet):

    name = "INT telemetry report"
    
    # default value a for telemetry report with INT
    fields_desc = [ BitField("ver" , 1 , 4),
        BitField("nProto", 0, 4),
        BitField("d", 0, 1),
        BitField("q", 0, 1),
        BitField("f", 1, 1),
        BitField("reserved", None, 15),
        BitField("hw_id", None, 6),

        IntField("seqNumber", None),
        IntField("ingressTimestamp", None) ]


class INT(Packet):

    name = "INT"

    fields_desc = [ XByteField("type", 1),
        XByteField("shimRsvd1", None),
        XByteField("length", None),
        XByteField("shimRsvd2", None),

        BitField("ver", 0, 4),
        BitField("rep", 0, 2),
        BitField("c", 0, 1),
        BitField("e", 0, 1),
        BitField("r", 0, 3),
        BitField("insCnt", None, 5),

        XByteField("maxHopCnt", 8),
        XByteField("totalHopCnt", 0),
        XShortField("ins", None),
        XShortField("res", 0),

        FieldListField("INTMetadata", [], XIntField("", None), count_from=lambda p:p.totalHopCnt*p.insCnt),

        XByteField("proto", None),
        XShortField("port", None),
        XByteField("originDSCP", 0)]

if __name__ == "__main__":

    p = Ether()/ \
        IP(tos=0x17<<2)/ \
        UDP(sport=5000, dport=54321)/ \
        TelemetryReport()/ \
        Ether()/ \
        IP(src="10.0.0.1", dst="10.0.0.2")/ \
        UDP(sport=5000, dport=5000)/ \
        INT(insCnt=8, totalHopCnt=3, ins=(1<<7 | 1 << 6 | 1<<5 | 1<<4 | 1 << 3 | 1<<2 | 1<<1 | 1)<<8,
            INTMetadata=[1, 2<<16| 3, 4, 5<<16| 6, 7, 8, 9<<16| 10, 11,
                        13, 21<<16| 31, 41, 51<<16| 33, 43, 14, 91<<16| 7, 8,
                        12, 22<<16| 32, 42, 52<<16| 37, 47, 15, 92<<16| 9, 101],
            originDSCP=14)

    # p = INT(insCnt=2, totalHopCnt=3, ins=(1<<7 | 1<<5)<<8, INTMetadata=[1, 0x10, 2, 0x41, 4, 0x22])
    
    # p = Ether()/ \
    #     IP(tos=0x17<<2)/ \
    #     UDP(sport=5000, dport=54321)/ \
    #     TelemetryReport(ver=1, seqNumber=1234)

    sendp(p, iface="veth0")
    # sendp(p, iface="veth0")

    # vars(p)

    # pkts = (p * 10)
    # wrpcap("int_rp.pcap", pkts)