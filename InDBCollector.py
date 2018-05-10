#!/usr/bin/python

from bcc import BPF
from pyroute2 import IPRoute
from prometheus_client import start_http_server, Summary
from prometheus_client import Gauge
from influxdb import InfluxDBClient
# from collections import defaultdict
from ipaddress import IPv4Address
import time
import json
import multiprocessing
import sys
# import netifaces
# import os
import argparse
import ctypes as ct

class InDBCollector(object):
    """docstring for InDBCollector"""

    def __init__(self):
        super(InDBCollector, self).__init__()

        self.MAX_INT_HOP = 6
        self.SERVER_MODE = "INFLUXDB"

        self.ifaces = set()

        #load eBPF program
        self.bpf_collector = BPF(src_file="BPFCollector.c", debug=0,
            cflags=["-w", 
                    "-D_MAX_INT_HOP=%s" % self.MAX_INT_HOP,
                    "-D_SERVER_MODE=%s" % self.SERVER_MODE])
        self.fn_collector = self.bpf_collector.load_func("collector", BPF.XDP)

        # get all the info table
        self.tb_flow  = self.bpf_collector.get_table("tb_flow")
        self.tb_egr   = self.bpf_collector.get_table("tb_egr")
        self.tb_queue = self.bpf_collector.get_table("tb_queue")
        # self.tb_test = self.bpf_collector.get_table("tb_test")

        self.flow_paths = {}

        # self.flow_pkt_cnt = []
        # self.flow_byte_cnt = []
        self.flow_latency = []
        self.flow_hop_latency = []
        self.tx_utilize = []
        self.queue_occup = []
        self.queue_congest = []

        self.client = InfluxDBClient(database="INTdatabase")


    def attach_iface(self, iface):
        if iface in self.ifaces:
            print "already attached to ", iface
            return
        self.bpf_collector.attach_xdp(iface, self.fn_collector, 0)
        self.ifaces.add(iface)

    def detach_iface(self, iface):
        if iface not in self.ifaces:
            print "no program attached to ", iface
            return
        self.bpf_collector.remove_xdp(iface, 0)
        self.ifaces.remove(iface)

    def detach_all_iface(self):
        for iface in self.ifaces:
            self.bpf_collector.remove_xdp(iface, 0)
        self.ifaces = set()

        
    def open_events(self):
        def _process_event(ctx, data, size):
            class Event(ct.Structure):
                _fields_ =  [("src_ip", ct.c_uint32),
                             ("dst_ip", ct.c_uint32),
                             ("src_port", ct.c_ushort),
                             ("dst_port", ct.c_ushort),
                             ("ip_proto", ct.c_ushort),
                             
                             # ("pkt_cnt", ct.c_uint64),
                             # ("byte_cnt", ct.c_uint64),

                             ("num_INT_hop", ct.c_ubyte),

                             ("sw_ids", ct.c_uint32 * self.MAX_INT_HOP),
                             ("in_port_ids", ct.c_uint16 * self.MAX_INT_HOP),
                             ("e_port_ids", ct.c_uint16 * self.MAX_INT_HOP),
                             ("hop_latencies", ct.c_uint32 * self.MAX_INT_HOP),
                             ("queue_ids", ct.c_uint16 * self.MAX_INT_HOP),
                             ("queue_occups", ct.c_uint16 * self.MAX_INT_HOP),
                             ("ingr_times", ct.c_uint32 * self.MAX_INT_HOP),
                             ("egr_times", ct.c_uint32 * self.MAX_INT_HOP),
                             ("queue_congests", ct.c_uint16 * self.MAX_INT_HOP),
                             ("tx_utilizes", ct.c_uint32 * self.MAX_INT_HOP),

                             ("flow_latency", ct.c_uint32),
                             ("flow_sink_time", ct.c_uint32),

                             ("is_n_flow", ct.c_ubyte),
                             # ("is_n_hop_latency", ct.c_ubyte),
                             # ("is_n_queue_occup", ct.c_ubyte),
                             # ("is_n_queue_congest", ct.c_ubyte),
                             # ("is_n_tx_utilize", ct.c_ubyte),

                             ("is_path", ct.c_ubyte),
                             ("is_hop_latency", ct.c_ubyte),
                             ("is_queue_occup", ct.c_ubyte),
                             ("is_queue_congest", ct.c_ubyte),
                             ("is_tx_utilize", ct.c_ubyte)
                             ]

            event = ct.cast(data, ct.POINTER(Event)).contents

            # push data
            
            event_data = []
            
            if event.is_n_flow or event.is_path:
                path_str = ":".join(str(event.sw_ids[i]) for i in reversed(range(0, event.num_INT_hop)))
                event_data.append({"measurement": "flow_stat,{0}:{1}->{2}:{3},proto={4}".format(
                                                    str(IPv4Address(event.src_ip)),
                                                    event.src_port,
                                                    str(IPv4Address(event.dst_ip)),
                                                    event.dst_port,
                                                    event.ip_proto),
                                    "time": event.flow_sink_time*1000000000,
                                    "fields": {
                                        # "pkt_cnt"  : event.pkt_cnt,
                                        # "byte_cnt" : event.byte_cnt,
                                        "flow_latency" : event.flow_latency,
                                        "path": path_str
                                    }
                                })

            if event.is_hop_latency:
                for i in range(0, event.num_INT_hop):
                    if ((is_hop_latency >> i) & 0x01):
                        event_data.append({"measurement": "flow_hop_latency,{0}:{1}->{2}:{3},proto={4},sw_id={5}".format(
                                                            str(IPv4Address(event.src_ip)),
                                                            event.src_port,
                                                            str(IPv4Address(event.dst_ip)),
                                                            event.dst_port,
                                                            event.ip_proto,
                                                            event.sw_ids[i]),
                                            "time": event.egr_times[i]*1000000000,
                                            "fields": {
                                                "value" : event.hop_latencies[i]
                                            }
                                        })


            if event.is_tx_utilize:
                for i in range(0, event.num_INT_hop):
                    if ((is_tx_utilize >> i) & 0x01):
                        event_data.append({"measurement": "port_tx_utilize,sw_id={0},port_id={1}".format(
                                                           event.sw_ids[i], event.e_port_ids[i]),
                                            "time": event.egr_times[i]*1000000000,
                                            "fields": {
                                                "value": event.tx_utilizes[i]
                                            }
                                        })

            if event.is_queue_occup:
                for i in range(0, event.num_INT_hop):
                    if ((is_queue_occup >> i) & 0x01):
                        event_data.append({"measurement": "queue_occupancy,sw_id={0},queue_id={1}".format(
                                                            event.sw_ids[i], event.queue_ids[i]),
                                            "time": event.egr_times[i]*1000000000,
                                            "fields": {
                                                "value": event.queue_occups[i],
                                            }
                                        })

            if event.is_queue_congest:
                for i in range(0, event.num_INT_hop):
                    if ((is_queue_congest >> i) & 0x01):
                        event_data.append({"measurement": "queue_congestion,sw_id={0},queue_id={1}".format(
                                                            event.sw_ids[i], event.queue_ids[i]),
                                            "time": event.egr_times[i]*1000000000,
                                            "fields": {
                                                "value": event.queue_congests[i]
                                            }
                                        })

            self.client.write_points(points=event_data)
            
            # Print event data for debug
            print "*" * 20
            for field_name, field_type in event._fields_:
                field_arr = getattr(event, field_name)
                if field_name in ["sw_ids","in_port_ids","e_port_ids","hop_latencies",
                                "queue_occups", "queue_ids","ingr_times","egr_times",
                                "queue_congests","tx_utilizes"]:
                    _len = len(field_arr)
                    s = ""
                    for e in field_arr:
                        s = s+str(e)+", " 
                    print field_name+": ", s
                else:
                    print field_name+": ", field_arr

        self.bpf_collector["events"].open_perf_buffer(_process_event)
    
    def poll_events(self):
        self.bpf_collector.kprobe_poll()

    def collect_data(self):
        # json_str = json.dumps(self.tb_egr.items())
        # print json_str

        data = []

        for (flow_id, flow_info) in self.tb_flow.items():
            path_str = ":".join(str(flow_info.sw_ids[i]) for i in reversed(range(0, flow_info.num_INT_hop)))
            data.append({"measurement": "flow_stat,{0}:{1}->{2}:{3},proto={4}".format(
                                                    str(IPv4Address(flow_id.src_ip)),
                                                    flow_id.src_port,
                                                    str(IPv4Address(flow_id.dst_ip)),
                                                    flow_id.dst_port,
                                                    flow_id.ip_proto),
                            "time": flow_info.flow_sink_time*1000000000,
                            "fields": {
                                # "pkt_cnt"  : flow_info.pkt_cnt,
                                # "byte_cnt" : flow_info.byte_cnt,
                                # dont need path here. if there is path change, it should
                                "flow_latency" : flow_info.flow_latency,
                                "path" : path_str
                            }
                        })

            for i in range(0, flow_info.num_INT_hop):
                data.append({"measurement": "flow_hop_latency,{0}:{1}->{2}:{3},proto={4},sw_id={5}".format(
                                                            str(IPv4Address(flow_id.src_ip)),
                                                            flow_id.src_port,
                                                            str(IPv4Address(flow_id.dst_ip)),
                                                            flow_id.dst_port,
                                                            flow_id.ip_proto,
                                                            flow_info.sw_ids[i]),
                                "time": flow_info.egr_times[i]*1000000000,
                                "fields": {
                                    "value" : flow_info.hop_latencies[i]
                                }
                            })


        for (egr_id, egr_info) in self.tb_egr.items():
            data.append({"measurement": "port_tx_utilize,sw_id={0},port_id={1}".format(
                                        egr_id.sw_id, egr_id.p_id),
                            "time": egr_info.egr_time*1000000000,
                            "fields": {
                                "value": egr_info.tx_utilize
                            }
                        })

        for (queue_id, queue_info) in self.tb_queue.items():
            data.append({"measurement": "queue_occupancy,sw_id={0},queue_id={1}".format(
                                        queue_id.sw_id, queue_id.q_id),
                            "time": queue_info.q_time*1000000000,
                            "fields": {
                                "value": queue_info.occup,
                            }
                        })

            data.append({"measurement": "queue_congestion,sw_id={0},queue_id={1}".format(
                                        queue_id.sw_id, queue_id.q_id),
                            "time": queue_info.q_time*1000000000,
                            "fields": {
                                "value": queue_info.congest
                            }
                        })


        return data




#---------------------------------------------------------------------------
if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='InfluxBD client.')
    parser.add_argument("ifaces", nargs='+',
        help="List of ifaces to receive INT reports")
    args = parser.parse_args()

    collector = InDBCollector()
    for iface in args.ifaces:
        collector.attach_iface(iface)

    # clear all old dbs. For easy testing
    for db in collector.client.get_list_database():
        collector.client.drop_database(db["name"])
    collector.client.create_database("INTdatabase")

    # run poll event
    poll_stop_flag = 0
    
    def _poll_event_proc():
        # only run when put open_events here. maybe st with thread
        collector.open_events()
        while not poll_stop_flag:
            collector.poll_events()
        return

    poll_event_proc = multiprocessing.Process(target=_poll_event_proc)
    poll_event_proc.start()


    try:
        print "eBPF progs Loaded"
        while 1:

            time.sleep(5)

            data = collector.collect_data()

            if not data:
                continue

            collector.client.write_points(points=data)


    except KeyboardInterrupt:
        pass

    finally:

        poll_stop_flag = 1
        # poll_event_proc.join()

        # print "flow_pkt_cnt: ", collector.client.query(query="select * from \"flow_stat,10.0.0.1:5000->10.0.0.2:5000,proto=17\""), "\n"
        # print "flow_byte_cnt: ", collector.client.query(query="select * from flow_byte_cnt"), "\n"
        # print "flow_latency: ", collector.client.query(query="select * from flow_latency"), "\n"
        # print "flow_hop_latency: ", collector.client.query(query="select * from flow_hop_latency"), "\n"
        # print "tx_utilize: ", collector.client.query(query="select * from tx_utilize"), "\n"
        # print "queue_occup: ", collector.client.query(query="select * from queue_occup"), "\n"
        # print "queue_congest: ", collector.client.query(query="select * from queue_congest"), "\n"

        collector.detach_all_iface()
        print("Done")

    print "Exit"
