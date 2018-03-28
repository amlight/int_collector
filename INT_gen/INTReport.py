#!/usr/bin/python
from scapy.all import *

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

        # FieldListField("INTMetadata", [], IntField, count_from=lambda p:p[INT].totalHopCnt*p[INT].insCnt),
        FieldListField("INTMetadata", [], XByteField("", None), count_from=lambda p:p.totalHopCnt*p.insCnt),

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
        INT(insCnt=2, totalHopCnt=3, ins=(1<<7 | 1<<5)<<8, INTMetadata=[1, 0x10, 2, 0x41, 4, 0x22])

    # p = INT(insCnt=2, totalHopCnt=3, ins=(1<<7 | 1<<5)<<8, INTMetadata=[1, 0x10, 2, 0x41, 4, 0x22])
    
    # p = Ether()/ \
    #     IP(tos=0x17<<2)/ \
    #     UDP(sport=5000, dport=54321)/ \
    #     TelemetryReport(ver=1, seqNumber=1234)

    sendp(p, iface="veth0")

    # vars(p)