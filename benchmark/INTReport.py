#!/usr/bin/python
from scapy.all import *
import time
import argparse

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

    parser = argparse.ArgumentParser(description='INT Telemetry Report pkt gen.')
    parser.add_argument("-t1", "--test1", action='store_true',
        help="Gen pcaps for Test 1")    
    parser.add_argument("-t2", "--test2", action='store_true',
        help="Gen pcaps for Test 2")    
    parser.add_argument("-t3", "--test3", action='store_true',
        help="Gen pcaps for Test 3")    
    parser.add_argument("-t4", "--test4", action='store_true',
        help="Gen pcaps for Test 4")    
    parser.add_argument("-t5", "--test_out_of_interval", action='store_true',
        help="Test out of interval")    
    args = parser.parse_args()

    # p_3sw_8d = []
    # p_6sw_8d = []
    # p_6sw_f_id = []
    # tcp_p_3sw_8d = []

    # TEST 1: How does number of flow affect CPU usage?
    # -- 6sw, flow_path only
    # -- num flow: 10, 100, 500, 1000, 2000, 5000
    if args.test1:
        n_sw = 6
        n_flows = [10, 100, 500, 1000, 2000, 5000]
        for n_fl in n_flows:    
            p=[]
            for i in range(0, n_fl):
                p.append(Ether()/ \
                    IP(tos=0x17<<2)/ \
                    UDP(sport=5000, dport=54321)/ \
                    TelemetryReport(ingressTimestamp= 1524138290)/ \
                    Ether()/ \
                    IP(src="10.0.0.1", dst="10.0.{0}.{1}".format(i/256, i%256))/ \
                    UDP(sport=5000, dport=5000)/ \
                    INT(insCnt=1, totalHopCnt=n_sw, ins=(1<<7)<<8, \
                        INTMetadata=[i%4+j for j in range(0,6)], \
                        originDSCP=14))
            wrpcap("pcaps/t1_{0}sw_{1}fl_swid.pcap".format(n_sw, n_fl), p)
            print "Done: t1_{0}sw_{1}fl_swid.pcap".format(n_sw, n_fl)



    # TEST2: How does the number of sw affect CPU usage?
    # -- flow_path only, num flow = 100
    # -- all fields, num flow = 100
    # -- 1, 2, 3, 4, 5, 6 sws
    if args.test2:
        n_sws = [1, 2, 3, 4, 5, 6]
        n_fl = 100
        for n_sw in n_sws:
            # flow path only
            p=[]
            for i in range(0, n_fl):
                p.append(Ether()/ \
                    IP(tos=0x17<<2)/ \
                    UDP(sport=5000, dport=54321)/ \
                    TelemetryReport(ingressTimestamp= 1524138290)/ \
                    Ether()/ \
                    IP(src="10.0.0.1", dst="10.0.{0}.{1}".format(i/256, i%256))/ \
                    UDP(sport=5000, dport=5000)/ \
                    INT(insCnt=1, totalHopCnt=n_sw, ins=(1<<7)<<8, \
                        INTMetadata=[i%16+j for j in range(0,n_sw)], \
                        originDSCP=14))
            wrpcap("pcaps/t2_{0}sw_{1}fl_swid.pcap".format(n_sw, n_fl), p)
            print "Done: t2_{0}sw_{1}fl_swid.pcap".format(n_sw, n_fl)

            # all fields
            p=[]
            for i in range(0, n_fl):
                INTdata = []
                for j in range(0,n_sw):
                    INTdata += [i%16+j, 2<<16| 3, 4+j, 5<<16| 6, 7+j, 1524234560, 9<<16| 10+j, 11+j]
                p.append(Ether()/ \
                    IP(tos=0x17<<2)/ \
                    UDP(sport=5000, dport=54321)/ \
                    TelemetryReport(ingressTimestamp= 1524138290)/ \
                    Ether()/ \
                    IP(src="10.0.0.1", dst="10.0.{0}.{1}".format(i/256, i%256))/ \
                    UDP(sport=5000, dport=5000)/ \
                    INT(insCnt=8, totalHopCnt=n_sw, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                        INTMetadata= INTdata,
                        originDSCP=14))
            wrpcap("pcaps/t2_{0}sw_{1}fl_all.pcap".format(n_sw, n_fl), p)
            print "Done: t2_{0}sw_{1}fl_all.pcap".format(n_sw, n_fl)



    # TEST3: How does number of INT metadata affect CPU usage?
    # -- 3 sw, 100 flow
    # -- 6 sw, 100 flow
    # -- sw_id; sw_id + hop latency; sw_id + tx_utilize; sw_id + q occ + q congest; all fields
    if args.test3:
        n_sws = [3, 6]
        n_fl = 100
        for n_sw in n_sws:
            # flow path only
            p=[]
            for i in range(0, n_fl):
                p.append(Ether()/ \
                    IP(tos=0x17<<2)/ \
                    UDP(sport=5000, dport=54321)/ \
                    TelemetryReport(ingressTimestamp= 1524138290)/ \
                    Ether()/ \
                    IP(src="10.0.0.1", dst="10.0.{0}.{1}".format(i/256, i%256))/ \
                    UDP(sport=5000, dport=5000)/ \
                    INT(insCnt=1, totalHopCnt=n_sw, ins=(1<<7)<<8, \
                        INTMetadata=[i%16+j for j in range(0,n_sw)], \
                        originDSCP=14))
            wrpcap("pcaps/t3_{0}sw_{1}fl_swid.pcap".format(n_sw, n_fl), p)
            print "Done: t3_{0}sw_{1}fl_swid.pcap".format(n_sw, n_fl)

            # sw_id + hop latency
            p=[]
            for i in range(0, n_fl):
                INTdata = []
                for j in range(0,n_sw):
                    INTdata += [i%16+j, 4+j]
                p.append(Ether()/ \
                    IP(tos=0x17<<2)/ \
                    UDP(sport=5000, dport=54321)/ \
                    TelemetryReport(ingressTimestamp= 1524138290)/ \
                    Ether()/ \
                    IP(src="10.0.0.1", dst="10.0.{0}.{1}".format(i/256, i%256))/ \
                    UDP(sport=5000, dport=5000)/ \
                    INT(insCnt=2, totalHopCnt=n_sw, ins=(1<<7|1<<5)<<8,
                        INTMetadata= INTdata,
                        originDSCP=14))
            wrpcap("pcaps/t3_{0}sw_{1}fl_swid_hoplatency.pcap".format(n_sw, n_fl), p)
            print "Done: t3_{0}sw_{1}fl_swid_hoplatency.pcap".format(n_sw, n_fl)

            # sw_id + txutilize
            p=[]
            for i in range(0, n_fl):
                INTdata = []
                for j in range(0,n_sw):
                    INTdata += [i%16+j, 4+j]
                p.append(Ether()/ \
                    IP(tos=0x17<<2)/ \
                    UDP(sport=5000, dport=54321)/ \
                    TelemetryReport(ingressTimestamp= 1524138290)/ \
                    Ether()/ \
                    IP(src="10.0.0.1", dst="10.0.{0}.{1}".format(i/256, i%256))/ \
                    UDP(sport=5000, dport=5000)/ \
                    INT(insCnt=2, totalHopCnt=n_sw, ins=(1<<7|1)<<8,
                        INTMetadata= INTdata,
                        originDSCP=14))
            wrpcap("pcaps/t3_{0}sw_{1}fl_swid_txutilize.pcap".format(n_sw, n_fl), p)
            print "Done: t3_{0}sw_{1}fl_swid_txutilize.pcap".format(n_sw, n_fl)

            # sw_id + qoccup + qcongest
            p=[]
            for i in range(0, n_fl):
                INTdata = []
                for j in range(0,n_sw):
                    INTdata += [i%16+j, (5+j)<<16| 6, (9+i%16)<<16| 10+j]
                p.append(Ether()/ \
                    IP(tos=0x17<<2)/ \
                    UDP(sport=5000, dport=54321)/ \
                    TelemetryReport(ingressTimestamp= 1524138290)/ \
                    Ether()/ \
                    IP(src="10.0.0.1", dst="10.0.{0}.{1}".format(i/256, i%256))/ \
                    UDP(sport=5000, dport=5000)/ \
                    INT(insCnt=3, totalHopCnt=n_sw, ins=(1<<7|1<<4|1<<1)<<8,
                        INTMetadata= INTdata,
                        originDSCP=14))
            wrpcap("pcaps/t3_{0}sw_{1}fl_swid_qoccup_qcongest.pcap".format(n_sw, n_fl), p)
            print "Done: t3_{0}sw_{1}fl_swid_qoccup_qcongest.pcap".format(n_sw, n_fl)

            # all fields
            p=[]
            for i in range(0, n_fl):
                INTdata = []
                for j in range(0,n_sw):
                    INTdata += [i%16+j, 2<<16| 3, 4+j, 5<<16| 6, 7+j, 1524234560, 9<<16| 10+j, 11+j]
                p.append(Ether()/ \
                    IP(tos=0x17<<2)/ \
                    UDP(sport=5000, dport=54321)/ \
                    TelemetryReport(ingressTimestamp= 1524138290)/ \
                    Ether()/ \
                    IP(src="10.0.0.1", dst="10.0.{0}.{1}".format(i/256, i%256))/ \
                    UDP(sport=5000, dport=5000)/ \
                    INT(insCnt=8, totalHopCnt=n_sw, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                        INTMetadata= INTdata,
                        originDSCP=14))
            wrpcap("pcaps/t3_{0}sw_{1}fl_all.pcap".format(n_sw, n_fl), p)
            print "Done: t3_{0}sw_{1}fl_all.pcap".format(n_sw, n_fl)



    # TEST4: How does number of event affect CPU usage?
    # -- 3sw, all fields, 5000 flow
    # -- num of event per seconds:
    if args.test4:
        n_sw = 3
        n_fl = 100
        n_events = [20, 50, 100, 200, 500]
        TMP = 1000000*2/100
        for n_event in n_events:
            # all fields
            p=[]
            for i in range(0, n_fl):
                print "flow: ", i
                # 1000000 pps; 1 abnormal packet is 2 events (11+j -> 1000, and 1000 -> 11+j)
                for l in range(0, TMP/n_event):
                    INTdata = []
                    for j in range(0,n_sw):
                        addedINT = [j, 2<<16| 3, 4+j, 5<<16| 6, 7+j, 1524234560, 9<<16| 10+j, 11+j]
                        if (l < TMP/(n_event*2) and i==0 and j==0):
                            # use j as sw_id to ensure diff switches so that the number of event is correct
                            addedINT = [j, 2<<16| 3, 4+j, 5<<16| 6, 7+j, 1524234560, 9<<16| 10+j, 5000]
                        INTdata += addedINT
                    p.append(Ether()/ \
                        IP(tos=0x17<<2)/ \
                        UDP(sport=5000, dport=54321)/ \
                        TelemetryReport(ingressTimestamp= 1524138290)/ \
                        Ether()/ \
                        IP(src="10.0.0.1", dst="10.0.{0}.{1}".format(i/256, i%256))/ \
                        UDP(sport=5000, dport=5000)/ \
                        INT(insCnt=8, totalHopCnt=n_sw, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                            INTMetadata= INTdata,
                            originDSCP=14))
            wrpcap("pcaps/t4_{0}sw_{1}fl_{2}event_all.pcap".format(n_sw, n_fl, n_event), p)
            print "Done: t4_{0}sw_{1}fl_{2}event_all.pcap".format(n_sw, n_fl, n_event)

    
    # test out of gap detection
    if args.test_out_of_interval:
        p0 = Ether()/ \
            IP(tos=0x17<<2)/ \
            UDP(sport=5000, dport=54321)/ \
            TelemetryReport(ingressTimestamp= 1524138290)/ \
            Ether()/ \
            IP(src="10.0.0.1", dst="10.0.0.2")/ \
            UDP(sport=5000, dport=5000)/ \
            INT(insCnt=8, totalHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                INTMetadata= [4, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 9<<16| 10, 1,
                5, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 9<<16| 10, 1,
                6, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 9<<16| 10, 1],
                originDSCP=14)
        
        p1 = Ether()/ \
            IP(tos=0x17<<2)/ \
            UDP(sport=5000, dport=54321)/ \
            TelemetryReport(ingressTimestamp= 1524138290)/ \
            Ether()/ \
            IP(src="10.0.0.1", dst="10.0.0.2")/ \
            UDP(sport=5000, dport=5000)/ \
            INT(insCnt=8, totalHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                INTMetadata= [4, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 9<<16| 10, 1000,
                5, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 9<<16| 10, 1,
                6, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 9<<16| 10, 1],
                originDSCP=14)

        iface = "vtap0"

        try:
            while 1:
                sendp(p0, iface=iface)
                time.sleep(5)
                sendp(p1, iface=iface)
                time.sleep(5)
        
        except KeyboardInterrupt:
            pass
