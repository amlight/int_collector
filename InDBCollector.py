#!/usr/bin/python

from bcc import BPF
from pyroute2 import IPRoute
from prometheus_client import start_http_server, Summary
from prometheus_client import Gauge
from influxdb import InfluxDBClient
# from collections import defaultdict
import time
import json
import multiprocessing
import sys
# import netifaces
# import os
# import ipaddress
import ctypes as ct

class InDBCollector(object):
    """docstring for InDBCollector"""

    def __init__(self):
        super(InDBCollector, self).__init__()

        self.MAX_INT_HOP = 4

        self.ifaces = set()

        #load eBPF program
        self.bpf_collector = BPF(src_file="BPFCollector.c", debug=0)
        self.fn_collector = self.bpf_collector.load_func("collector", BPF.XDP)

        # get all the info table
        self.tb_flow  = self.bpf_collector.get_table("tb_flow")
        self.tb_egr   = self.bpf_collector.get_table("tb_egr")
        self.tb_queue = self.bpf_collector.get_table("tb_queue")
        self.tb_test = self.bpf_collector.get_table("tb_test")

        self.flow_paths = {}

        self.flow_pkt_cnt = []
        self.flow_byte_cnt = []
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

        
    def open_events(self):
        def _process_event(ctx, data, size):
            class Event(ct.Structure):
                _fields_ =  [("src_ip", ct.c_uint32),
                             ("dst_ip", ct.c_uint32),
                             ("src_port", ct.c_ushort),
                             ("dst_port", ct.c_ushort),
                             ("ip_proto", ct.c_ushort),
                             
                             ("pkt_cnt", ct.c_uint64),
                             ("byte_cnt", ct.c_uint64),

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
                             ("is_n_hop_latency", ct.c_ubyte),
                             ("is_n_queue_occup", ct.c_ubyte),
                             ("is_n_queue_congest", ct.c_ubyte),
                             ("is_n_tx_utilize", ct.c_ubyte),

                             ("is_path", ct.c_ubyte),
                             ("is_hop_latency", ct.c_ubyte),
                             ("is_queue_occup", ct.c_ubyte),
                             ("is_queue_congest", ct.c_ubyte),
                             ("is_tx_utilize", ct.c_ubyte)
                             ]

            event = ct.cast(data, ct.POINTER(Event)).contents

            # push data
            
            event_data = []
            
            if event.is_n_flow:
                event_data.append({"measurement": "flow_pkt_cnt",
                            "time": event.flow_sink_time,
                            "fields": {
                                "src_ip"  : event.src_ip,
                                "dst_ip"  : event.dst_ip,
                                "src_port": event.src_port,
                                "dst_port": event.dst_port,
                                "ip_proto": event.ip_proto,
                                "value"   : event.pkt_cnt
                            }
                        })

                event_data.append({"measurement": "flow_byte_cnt",
                            "time": event.flow_sink_time,
                            "fields": {
                                "src_ip"  : event.src_ip,
                                "dst_ip"  : event.dst_ip,
                                "src_port": event.src_port,
                                "dst_port": event.dst_port,
                                "ip_proto": event.ip_proto,
                                "value"   : event.byte_cnt
                            }
                        })

                event_data.append({"measurement": "flow_latency",
                            "time": event.flow_sink_time,
                            "fields": {
                                "src_ip"  : event.src_ip,
                                "dst_ip"  : event.dst_ip,
                                "src_port": event.src_port,
                                "dst_port": event.dst_port,
                                "ip_proto": event.ip_proto,
                                "value"   : event.flow_latency
                            }
                        })

                if event.is_n_hop_latency:
                    for i in range(0, event.num_INT_hop):
                        if ((event.is_n_hop_latency >> i) & 0x01):
                            event_data.append({"measurement": "flow_hop_latency",
                                        "time": event.egr_times[i],
                                        "fields": {
                                            "src_ip"  : event.src_ip,
                                            "dst_ip"  : event.dst_ip,
                                            "src_port": event.src_port,
                                            "dst_port": event.dst_port,
                                            "ip_proto": event.ip_proto,
                                            "sw_id"   : event.sw_ids[i],
                                            "value"   : event.hop_latencies[i]
                                        }
                                    })


            if event.is_n_tx_utilize:
                for i in range(0, event.num_INT_hop):
                    if ((event.is_n_tx_utilize >> i) & 0x01):
                        event_data.append({"measurement": "tx_utilize",
                                    "time": event.egr_times[i],
                                    "fields": {
                                        "sw_id": event.sw_ids[i],
                                        "p_id" : event.e_port_ids[i],
                                        "value": event.tx_utilizes[i]
                                    }
                                })

            if event.is_n_queue_occup:
                for i in range(0, event.num_INT_hop):
                    if ((event.is_n_queue_occup >> i) & 0x01):
                        event_data.append({"measurement": "queue_occup",
                                    "time": event.egr_times[i],
                                    "fields": {
                                        "sw_id": event.sw_ids[i],
                                        "q_id" : event.queue_ids[i],
                                        "value": event.queue_occups[i]
                                    }
                                })

            if event.is_n_queue_congest:
                for i in range(0, event.num_INT_hop):
                    if ((event.is_n_queue_congest >> i) & 0x01):
                        event_data.append({"measurement": "queue_congest",
                                    "time": event.egr_times[i],
                                    "fields": {
                                        "sw_id": event.sw_ids[i],
                                        "q_id" : event.queue_ids[i],
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
            data.append({"measurement": "flow_pkt_cnt",
                        "time": flow_info.flow_sink_time,
                        "fields": {
                            "src_ip"  : flow_id.src_ip,
                            "dst_ip"  : flow_id.dst_ip,
                            "src_port": flow_id.src_port,
                            "dst_port": flow_id.dst_port,
                            "ip_proto": flow_id.ip_proto,
                            "value"   : flow_info.pkt_cnt
                        }
                    })

            data.append({"measurement": "flow_byte_cnt",
                        "time": flow_info.flow_sink_time,
                        "fields": {
                            "src_ip"  : flow_id.src_ip,
                            "dst_ip"  : flow_id.dst_ip,
                            "src_port": flow_id.src_port,
                            "dst_port": flow_id.dst_port,
                            "ip_proto": flow_id.ip_proto,
                            "value"   : flow_info.byte_cnt
                        }
                    })

            data.append({"measurement": "flow_latency",
                        "time": flow_info.flow_sink_time,
                        "fields": {
                            "src_ip"  : flow_id.src_ip,
                            "dst_ip"  : flow_id.dst_ip,
                            "src_port": flow_id.src_port,
                            "dst_port": flow_id.dst_port,
                            "ip_proto": flow_id.ip_proto,
                            "value"   : flow_info.flow_latency
                        }
                    })

            for i in range(0, flow_info.num_INT_hop):
                data.append({"measurement": "flow_hop_latency",
                            "time": flow_info.egr_times[i],
                            "fields": {
                                "src_ip"  : flow_id.src_ip,
                                "dst_ip"  : flow_id.dst_ip,
                                "src_port": flow_id.src_port,
                                "dst_port": flow_id.dst_port,
                                "ip_proto": flow_id.ip_proto,
                                "sw_id"   : flow_info.sw_ids[i],
                                "value"   : flow_info.hop_latencies[i]
                            }
                        })


        for (egr_id, egr_info) in self.tb_egr.items():
            data.append({"measurement": "tx_utilize",
                        "time": egr_info.egr_time,
                        "fields": {
                            "sw_id": egr_id.sw_id,
                            "p_id" : egr_id.p_id,
                            "value": egr_info.tx_utilize
                        }
                    })

        for (queue_id, queue_info) in self.tb_queue.items():
            data.append({"measurement": "queue_occup",
                        "time": queue_info.q_time,
                        "fields": {
                            "sw_id": queue_id.sw_id,
                            "q_id" : queue_id.q_id,
                            "value": queue_info.occup
                        }
                    })

            data.append({"measurement": "queue_congest",
                        "time": queue_info.q_time,
                        "fields": {
                            "sw_id": queue_id.sw_id,
                            "q_id" : queue_id.q_id,
                            "value": queue_info.congest
                        }
                    })


        return data




#---------------------------------------------------------------------------
if __name__ == "__main__":

    collector = InDBCollector()
    collector.attach_iface("veth1")

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

            time.sleep(2)

            data = collector.collect_data()

            if not data:
                continue

            collector.client.write_points(points=data)


    except KeyboardInterrupt:
        pass

    finally:

        poll_stop_flag = 1
        poll_event_proc.join()

        print "flow_pkt_cnt: ", collector.client.query(query="select * from flow_pkt_cnt"), "\n"
        print "flow_byte_cnt: ", collector.client.query(query="select * from flow_byte_cnt"), "\n"
        print "flow_latency: ", collector.client.query(query="select * from flow_latency"), "\n"
        print "flow_hop_latency: ", collector.client.query(query="select * from flow_hop_latency"), "\n"
        print "tx_utilize: ", collector.client.query(query="select * from tx_utilize"), "\n"
        print "queue_occup: ", collector.client.query(query="select * from queue_occup"), "\n"
        print "queue_congest: ", collector.client.query(query="select * from queue_congest"), "\n"

        collector.detach_iface("veth1")
        print("Done")

    print "Exit"
