#!/usr/bin/python
from InDBCollector import InDBCollector

from libc.stdint cimport uintptr_t
import pyximport; pyximport.install()
from cy_line_protocol import make_line

# change array len of sw_ids.. to .. tx_utilizes to match with max_int_hop in the collector
cdef enum: __MAX_INT_HOP = 6
_MAX_INT_HOP = __MAX_INT_HOP
cdef struct Event:
    unsigned int   src_ip
    unsigned int   dst_ip
    unsigned short src_port
    unsigned short dst_port
    unsigned short ip_proto
    unsigned char  num_INT_hop
    unsigned int   sw_ids[__MAX_INT_HOP]
    unsigned short in_port_ids[__MAX_INT_HOP]
    unsigned short e_port_ids[__MAX_INT_HOP]
    unsigned int   hop_latencies[__MAX_INT_HOP]
    unsigned short queue_ids[__MAX_INT_HOP]
    unsigned short queue_occups[__MAX_INT_HOP]
    unsigned int   ingr_times[__MAX_INT_HOP]
    unsigned int   egr_times[__MAX_INT_HOP]
    unsigned short queue_congests[__MAX_INT_HOP]
    unsigned int   tx_utilizes[__MAX_INT_HOP]
    unsigned int   flow_latency
    unsigned int   flow_sink_time
    unsigned char  is_n_flow
    unsigned char  is_flow
    unsigned char  is_hop_latency
    unsigned char  is_queue_occup
    unsigned char  is_queue_congest
    unsigned char  is_tx_utilize

class Cy_InDBCollector(InDBCollector):
    """docstring for InDBCollector"""

    def __init__(self, max_int_hop=6, debug_mode=0, host="localhost", database="INTdatabase"):
        super(Cy_InDBCollector, self).__init__(max_int_hop=max_int_hop,
            debug_mode=debug_mode, host=host, database=database)

    def int_2_ip4_str(self, ipint):
            cdef unsigned char i
            return '.'.join([str(ipint >> (i << 3) & 0xFF) for i in [3, 2, 1, 0]])

    def open_events(self):
        def _process_event(ctx, data, size):
            
            cdef uintptr_t _event =  <uintptr_t> data
            cdef Event *event = <Event*> _event

            # push data
            
            event_data = []
            
            if event.is_n_flow or event.is_flow:
                path_str = ":".join(str(event.sw_ids[i]) for i in reversed(range(0, event.num_INT_hop)))

                event_data.append(make_line(measurement="flow_stat,%s:%d->%s:%d,proto=%d" % (
                                                            self.int_2_ip4_str(event.src_ip),
                                                            event.src_port,
                                                            self.int_2_ip4_str(event.dst_ip),
                                                            event.dst_port,
                                                            event.ip_proto),
                                          key_val_list=[("flow_latency" , event.flow_latency),
                                                        ("path"         , path_str)],
                                          time=None 
                                          # time=event.flow_sink_time, 
                                         ))

            if event.is_hop_latency:
                for i in range(0, event.num_INT_hop):
                    if ((event.is_hop_latency >> i) & 0x01):
                        event_data.append(make_line(measurement="flow_hop_latency,%s:%d->%s:%d,proto=%d,sw_id=%d" % (
                                                                self.int_2_ip4_str(event.src_ip),
                                                                event.src_port,
                                                                self.int_2_ip4_str(event.dst_ip),
                                                                event.dst_port,
                                                                event.ip_proto,
                                                                event.sw_ids[i]),
                                  key_val_list=[("value", event.hop_latencies[i])],
                                  time=None 
                                  # time=event.egr_times[i], 
                                 ))

            if event.is_tx_utilize:
                for i in range(0, event.num_INT_hop):
                    if ((event.is_tx_utilize >> i) & 0x01):
                        event_data.append(make_line(measurement="port_tx_utilize,sw_id=%d,port_id=%d" % (
                                                           event.sw_ids[i], event.e_port_ids[i]),
                                  key_val_list=[("value", event.tx_utilizes[i])],
                                  time=None 
                                  # time=event.egr_times[i], 
                                 ))

            if event.is_queue_occup:
                for i in range(0, event.num_INT_hop):
                    if ((event.is_queue_occup >> i) & 0x01):
                        event_data.append(make_line(measurement="queue_occupancy,sw_id=%d,queue_id=%d" % (
                                                            event.sw_ids[i], event.queue_ids[i]),
                                  key_val_list=[("value", event.queue_occups[i])],
                                  time=None 
                                  # time=event.egr_times[i],, 
                                 ))

            if event.is_queue_congest:
                for i in range(0, event.num_INT_hop):
                    if ((event.is_queue_congest >> i) & 0x01):
                        event_data.append(make_line(measurement="queue_congestion,sw_id=%d,queue_id=%d" % (
                                                            event.sw_ids[i], event.queue_ids[i]),
                                  key_val_list=[("value", event.queue_congests[i])],
                                  time=None 
                                  # time=event.egr_times[i], 
                                 ))

            # self.client.write_points(points=event_data)
            self.lock.acquire()
            self.event_data.extend(event_data)
            self.lock.release()

            # Print event data for debug
            if self.debug_mode==1:
                print "*" * 20
                print "src_ip", event.src_ip
                print "dst_ip", event.dst_ip
                print "src_port", event.src_port
                print "dst_port", event.dst_port
                print "ip_proto", event.ip_proto
                print "num_INT_hop", event.num_INT_hop
                print "sw_ids", event.sw_ids
                print "in_port_ids", event.in_port_ids
                print "e_port_ids", event.e_port_ids
                print "hop_latencies", event.hop_latencies
                print "queue_ids", event.queue_ids
                print "queue_occups", event.queue_occups
                print "ingr_times", event.ingr_times
                print "egr_times", event.egr_times
                print "queue_congests", event.queue_congests
                print "tx_utilizes", event.tx_utilizes
                print "flow_latency", event.flow_latency
                print "flow_sink_time", event.flow_sink_time
                print "is_n_flow", event.is_n_flow
                print "is_flow", event.is_flow
                print "is_hop_latency", event.is_hop_latency
                print "is_queue_occup", event.is_queue_occup
                print "is_queue_congest", event.is_queue_congest
                print "is_tx_utilize", event.is_tx_utilize
                
        self.bpf_collector["events"].open_perf_buffer(_process_event, page_cnt=512)


    def collect_data(self):

        data = []

        for (flow_id, flow_info) in self.tb_flow.iteritems():
            path_str = ":".join(str(flow_info.sw_ids[i]) for i in reversed(range(0, flow_info.num_INT_hop)))
            
            flow_id_str = "%s:%d->%s:%d,proto=%d" % (self.int_2_ip4_str(flow_id.src_ip), \
                                                    flow_id.src_port, \
                                                    self.int_2_ip4_str(flow_id.dst_ip), \
                                                    flow_id.dst_port, \
                                                    flow_id.ip_proto)

            data.append(make_line(measurement="flow_stat,%s" % flow_id_str,
                                  key_val_list=[("flow_latency" , flow_info.flow_latency),
                                                ("path"         , path_str)],
                                  time=None 
                                  # time=flow_info.flow_sink_time, 
                                 ))
            
            if flow_info.is_hop_latency:
                for i in range(0, flow_info.num_INT_hop):
                    data.append(make_line(measurement="flow_hop_latency,%s,sw_id=%d" %(flow_id_str, flow_info.sw_ids[i]),
                                  key_val_list=[("value", flow_info.hop_latencies[i])],
                                  time=None 
                                  # time=flow_info.egr_times[i], 
                                 ))

        for (egr_id, egr_info) in self.tb_egr.items():
            data.append(make_line(measurement="port_tx_utilize,sw_id=%d,port_id=%d" % (egr_id.sw_id, egr_id.p_id),
                                  key_val_list=[("value", egr_info.tx_utilize)],
                                  time=None 
                                  # time=egr_info.egr_time, 
                                 ))

        for (queue_id, queue_info) in self.tb_queue.items():
            data.append(make_line(measurement="queue_occupancy,sw_id=%d,queue_id=%d" % (queue_id.sw_id, queue_id.q_id),
                                  key_val_list=[("value", queue_info.occup)],
                                  time=None 
                                  # time=queue_info.q_time, 
                                 ))

            data.append(make_line(measurement="queue_congestion,sw_id=%d,queue_id=%d" % (queue_id.sw_id, queue_id.q_id),
                                  key_val_list=[("value", queue_info.congest)],
                                  time=None 
                                  # time=queue_info.q_time, 
                                 ))

        return data