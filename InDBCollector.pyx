#
#  This file is part of the INT Collector distribution (https://github.com/amlight/int_collector).
#  Copyright (c) [2018] [Nguyen Van Tu],
#  Copyright (c) [2022] [AmLight SDN Team]
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#


from __future__ import print_function
import threading
import time
from bcc import BPF
from influxdb import InfluxDBClient
from libc.stdint cimport uintptr_t


cdef enum: __MAX_INT_HOP = 10  # 10 is the max for noviflow
cdef struct Event:
    unsigned int seqNumber
    unsigned short vlan_id
    unsigned char  num_INT_hop
    unsigned int   sw_ids[__MAX_INT_HOP]
    unsigned short in_port_ids[__MAX_INT_HOP]
    unsigned short e_port_ids[__MAX_INT_HOP]
    unsigned int   hop_latencies[__MAX_INT_HOP]
    unsigned short  queue_ids[__MAX_INT_HOP]
    unsigned int   queue_occups[__MAX_INT_HOP]
    unsigned int   ingr_times[__MAX_INT_HOP]
    unsigned int   egr_times[__MAX_INT_HOP]
    unsigned int   flow_latency
    unsigned long int   flow_sink_time
    unsigned char  is_n_flow
    unsigned char  is_flow
    unsigned short  is_hop_latency
    unsigned short  is_queue_occup


class InDBCollector(object):
    """docstring for InDBCollector"""

    def __init__(self,
                 int_dst_port,
                 debug_int,
                 host,
                 database,
                 flags,
                 hop_latency,
                 flow_latency,
                 queue_occ,
                 flow_keepalive,
                 enable_counter_mode,
                 enable_threshold_mode):

        super(InDBCollector, self).__init__()

        self.int_dst_port = int_dst_port
        self.hop_latency = hop_latency
        self.flow_latency = flow_latency
        self.queue_occ = queue_occ
        self.flow_keepalive = flow_keepalive
        self.enable_counter_mode = enable_counter_mode
        self.enable_threshold_mode = enable_threshold_mode

        self.int_time = False

        self.ifaces = set()

        #load eBPF program
        self.bpf_collector = BPF(src_file="BPFCollector.c", debug=0,
                                 cflags=["-w",
                                         "-D_INT_DST_PORT=%s" % self.int_dst_port,
                                         "-D_HOP_LATENCY=%s" % self.hop_latency,
                                         "-D_FLOW_LATENCY=%s" % self.flow_latency,
                                         "-D_QUEUE_OCCUP=%s" % self.queue_occ,
                                         "-D_TIME_GAP_W=%s" % self.flow_keepalive,
                                         "-D_ENABLE_COUNTER_MODE=%s" % self.enable_counter_mode,
                                         "-D_ENABLE_THRESHOLD_MODE=%s" % self.enable_threshold_mode
                                         ])

        self.fn_collector = self.bpf_collector.load_func("collector", BPF.XDP)

        # Table maps
        self.tb_flow  = self.bpf_collector.get_table("tb_flow")
        self.tb_queue = self.bpf_collector.get_table("tb_queue")
        self.tb_egr   = self.bpf_collector.get_table("tb_egr_vlan_util")
        self.tb_egr_q   = self.bpf_collector.get_table("tb_egr_queue_util")
        self.tb_egr_int   = self.bpf_collector.get_table("tb_egr_interface_util")

        self.packet_counter_all = self.bpf_collector.get_table("counter_all")
        self.packet_counter_int = self.bpf_collector.get_table("counter_int")
        self.packet_counter_errors = self.bpf_collector.get_table("counter_error")

        self.lock = threading.Lock()
        self.event_data = []

        self.client = InfluxDBClient(host=host, database=database)

        self.debug_mode = debug_int

        self.flags = 0 | (1 << 3) if flags else 0


    def attach_iface(self, iface):
        if iface in self.ifaces:
            print("already attached to ", iface)
            return

        self.bpf_collector.attach_xdp(iface, self.fn_collector, self.flags)
        self.ifaces.add(iface)

    def detach_iface(self, iface):
        if iface not in self.ifaces:
            print("no program attached to ", iface)
            return
        self.bpf_collector.remove_xdp(iface, 0)
        self.ifaces.remove(iface)

    def detach_all_iface(self):
        for iface in self.ifaces:
            self.bpf_collector.remove_xdp(iface, 0)
        self.ifaces = set()

    def poll_events(self):
        self.bpf_collector.kprobe_poll()

    def open_events(self):

        def _process_event(ctx, data, size):

            cdef uintptr_t _event =  <uintptr_t> data
            cdef Event *event = <Event*> _event

            # Print event data for debug
            if self.debug_mode==1:
                print("*********")
                print("seqNumber", event.seqNumber)
                print("vlan", event.vlan_id)
                print("num_INT_hop", event.num_INT_hop)
                print("sw_ids", event.sw_ids)
                print("in_port_ids", event.in_port_ids)
                print("e_port_ids", event.e_port_ids)
                print("hop_latencies", event.hop_latencies)
                print("queue_ids", event.queue_ids)
                print("queue_occups", event.queue_occups)
                print("ingr_times", event.ingr_times)
                print("egr_times", event.egr_times)
                print("flow_latency", event.flow_latency)
                print("flow_sink_time", event.flow_sink_time)
                print("is_n_flow", event.is_n_flow)
                print("is_flow", event.is_flow)
                print("is_hop_latency", event.is_hop_latency)
                print("is_queue_occup", event.is_queue_occup)

            event_data = []

            # Commented out because by April 2021, there is only one switch.
            # if event.is_n_flow or event.is_flow:
            #     path_str = ":".join(str(event.sw_ids[i]) for i in reversed(range(0, event.num_INT_hop)))
            #
            #     event_data.append(u"flow_lat_path\\,vlan_id=%d\\,sw_id=%i\\,port=%d flow_latency=%d,path=\"%s\"%s" % (
            #                         event.vlan_id,
            #                         event.sw_ids[0],
            #                         event.e_port_ids[0],
            #                         event.flow_latency,
            #                         path_str,
            #                         int(round(time.time() * 1000000000)))))

            if event.is_hop_latency:
                for i in range(0, event.num_INT_hop):
                    if (event.is_hop_latency >> i) & 0x01:
                        event_data.append(u"latency\\,vlan\\=%d\\,sw\\=%i\\,port\\=%d\\,hop\\=%i value=%d %s" %
                                          (event.vlan_id,
                                           event.sw_ids[0],
                                           event.e_port_ids[0],
                                           event.sw_ids[i],
                                           event.hop_latencies[i],
                                           int(round(time.time() * 1000000000))))

            if event.is_queue_occup:
                for i in range(0, event.num_INT_hop):
                    if (event.is_queue_occup >> i) & 0x01:
                        event_data.append(u"queue_occ\\,sw\\=%d\\,port\\=%d\\,queue\\=%d value=%d %s" %
                                          (event.sw_ids[i],
                                           event.e_port_ids[i],
                                           event.queue_ids[i],
                                           event.queue_occups[i],
                                           int(round(time.time() * 1000000000))))

            self.lock.acquire()
            self.event_data.extend(event_data)
            self.lock.release()

        self.bpf_collector["events"].open_perf_buffer(_process_event, page_cnt=1024)
