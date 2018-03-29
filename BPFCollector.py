#!/usr/bin/python

from bcc import BPF
from pyroute2 import IPRoute
# from collections import defaultdict
import time
# import netifaces
# import sys
# import os
# import json
# import ipaddress


# ipr = IPRoute()
# iface = "enp0s3" 
iface = "veth1" 

BPFCollector = BPF(src_file="BPFCollector.c", debug=0)

fn_collector = BPFCollector.load_func("collector", BPF.XDP)
BPFCollector.attach_xdp(iface, fn_collector, 0)

# fn_collector = BPFCollector.load_func("collector", BPF.SCHED_CLS)
# idx0 = ipr.link_lookup(ifname=iface)[0]
# ipr.tc("add", "clsact", idx0)
# ipr.tc("add-filter", "bpf", idx0, ":1", fd=fn_collector.fd, name=fn_collector.name,
#        parent="ffff:fff3", classid=1, direct_action=True)


# idx1 = ipr.link_lookup(ifname="vnet1")[0]

# test tb_tap
# tb_tap = bpf_simple_sw.get_table("tb_tap")
# key = tb_tap.Key(0)
# leaf = tb_tap.Leaf(0, 0,
#                    int(ipaddress.IPv4Address(u'10.0.0.2')),
#                    int('0xffffffff', 16),
#                    0, 0, 0, idx2, 1)
# tb_tap[key] = leaf
try:
    print "eBPF progs Loaded"
    time.sleep(600)

except KeyboardInterrupt:
    pass

finally:
    BPFCollector.remove_xdp(iface, 0)
    # ipr.tc("del", "clsact", idx0)
    # print "tb_ifaces: ", tb_ifaces.items()
    print("Done")

print "Exit"
