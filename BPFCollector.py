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
import ctypes as ct

def process_event(ctx, data, size):

	MAX_INT_HOP = 4
	class Event(ct.Structure):
		_fields_ =  [("src_ip", ct.c_uint32),
					 ("dst_ip", ct.c_uint32),
					 ("src_port", ct.c_ushort),
					 ("dst_port", ct.c_ushort),
					 ("ip_proto", ct.c_ushort),
					 
					 ("pkt_cnt", ct.c_uint64),
					 ("byte_cnt", ct.c_uint64),

					 ("sw_ids", ct.c_uint32 * MAX_INT_HOP),
					 ("in_port_ids", ct.c_uint16 * MAX_INT_HOP),
					 ("e_port_ids", ct.c_uint16 * MAX_INT_HOP),
					 ("hop_latencies", ct.c_uint32 * MAX_INT_HOP),
					 ("queue_ids", ct.c_uint16 * MAX_INT_HOP),
					 ("queue_occups", ct.c_uint16 * MAX_INT_HOP),
					 ("ingr_times", ct.c_uint32 * MAX_INT_HOP),
					 ("egr_times", ct.c_uint32 * MAX_INT_HOP),
					 ("queue_congests", ct.c_uint16 * MAX_INT_HOP),
					 ("tx_utilizes", ct.c_uint32 * MAX_INT_HOP),

					 ("is_path", ct.c_ubyte),
					 ("is_hop_latency", ct.c_ubyte),
					 ("is_queue_occup", ct.c_ubyte),
					 ("is_queue_congest", ct.c_ubyte),
					 ("is_tx_utilize", ct.c_ubyte)
					 ]

	event = ct.cast(data, ct.POINTER(Event)).contents
	
	print "-------------------------------------------------------"
	for field_name, field_type in event._fields_:
		field_arr = getattr(event, field_name)

		if field_name in ["sw_ids","in_port_ids","e_port_ids","hop_latencies","queue_occups",
						  "queue_ids","ingr_times","egr_times","queue_congests","tx_utilizes"]:
			_len = len(field_arr)
			s = ""
			for e in field_arr:
				s = s+str(e)+", " 
			print field_name+": ", s
		else:
			print field_name+": ", field_arr



# ipr = IPRoute()
iface = "veth1" 

BPFCollector = BPF(src_file="BPFCollector.c", debug=0)

fn_collector = BPFCollector.load_func("collector", BPF.XDP)
BPFCollector.attach_xdp(iface, fn_collector, 0)

# fn_collector = BPFCollector.load_func("collector", BPF.SCHED_CLS)
# idx0 = ipr.link_lookup(ifname=iface)[0]
# ipr.tc("add", "clsact", idx0)
# ipr.tc("add-filter", "bpf", idx0, ":1", fd=fn_collector.fd, name=fn_collector.name,
#        parent="ffff:fff3", classid=1, direct_action=True)




try:
    print "eBPF progs Loaded"
    BPFCollector["events"].open_perf_buffer(process_event)
    while 1:
    	BPFCollector.kprobe_poll()

except KeyboardInterrupt:
    pass

finally:
    BPFCollector.remove_xdp(iface, 0)
    # ipr.tc("del", "clsact", idx0)
    # print "tb_ifaces: ", tb_ifaces.items()
    print("Done")

print "Exit"
