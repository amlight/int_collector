from __future__ import print_function
import threading
from bcc import BPF
from influxdb import InfluxDBClient
from libc.stdint cimport uintptr_t

# # TODO: FIX01
cdef enum: __MAX_INT_HOP = 6  # Change to 10, max from noviflow
# _MAX_INT_HOP = __MAX_INT_HOP
cdef struct Event:
    unsigned int seqNumber
    unsigned short vlan_id
    unsigned char  num_INT_hop
    unsigned char  hop_negative
    unsigned int   sw_ids[__MAX_INT_HOP]
    unsigned short in_port_ids[__MAX_INT_HOP]
    unsigned short e_port_ids[__MAX_INT_HOP]
    unsigned int   hop_latencies[__MAX_INT_HOP]
    unsigned short queue_ids[__MAX_INT_HOP]
    unsigned short queue_occups[__MAX_INT_HOP]
    unsigned int   ingr_times[__MAX_INT_HOP]
    unsigned int   egr_times[__MAX_INT_HOP]
    unsigned long int tx_utilize[__MAX_INT_HOP]
    unsigned long int tx_utilize_delta[__MAX_INT_HOP]
    unsigned int   flow_latency
    unsigned long int   flow_sink_time
    unsigned char  is_n_flow
    unsigned char  is_flow
    unsigned char  is_hop_latency
    unsigned char  is_queue_occup
    unsigned char  is_tx_utilize


class InDBCollector(object):
    """docstring for InDBCollector"""

    def __init__(self,
                 int_dst_port=5900,
                 debug_mode=0,
                 host="localhost",
                 database="INTdatabase",
                 flags=0,
                 hop_latency=2000,  # 2 us
                 flow_latency=50000,  # 50 us
                 queue_occ=80,  # 80x80 = 6400 Bytes
                 intf_util_interval=500000000,  # 50 ms
                 max_hops=6,  # 6 switches (Max supported under 4096 instructions. Line 8
                 flow_keepalive=1000000000):  # 1 s

        super(InDBCollector, self).__init__()

        self.max_int_hops = max_hops
        self.int_dst_port = int_dst_port
        self.hop_latency = hop_latency
        self.flow_latency = flow_latency
        self.queue_occ = queue_occ
        self.intf_util_interval = intf_util_interval
        self.flow_keepalive = flow_keepalive

        self.int_time = False

        self.ifaces = set()

        #load eBPF program
        self.bpf_collector = BPF(src_file="BPFCollector.c", debug=0,
                                 cflags=["-w",
                                         "-D_MAX_INT_HOP=%s" % self.max_int_hops,
                                         "-D_INT_DST_PORT=%s" % self.int_dst_port,
                                         "-D_HOP_LATENCY=%s" % self.int_dst_port,
                                         "-D_FLOW_LATENCY=%s" % self.flow_latency,
                                         "-D_QUEUE_OCCUP=%s" % self.queue_occ,
                                         "-D_BW_INTERVAL=%s" % self.intf_util_interval,
                                         "-D_TIME_GAP_W=%s" % self.flow_keepalive
                                         ])

        self.fn_collector = self.bpf_collector.load_func("collector", BPF.XDP)

        # get all the info table for the future.
        self.tb_flow  = self.bpf_collector.get_table("tb_flow")
        self.tb_queue = self.bpf_collector.get_table("tb_queue")
        self.tb_egr   = self.bpf_collector.get_table("tb_egr_util")

        self.packet_counter_all = self.bpf_collector.get_table("counter_all")
        self.packet_counter_int = self.bpf_collector.get_table("counter_int")

        self.lock = threading.Lock()
        self.event_data = []

        self.client = InfluxDBClient(host=host, database=database)

        self.debug_mode = debug_mode

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
                print("hop_negative", event.hop_negative)
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
                print("tx_utilize", event.tx_utilize)
                print("tx_utilize_delta", event.tx_utilize_delta)
                print("flow_latency", event.flow_latency)
                print("flow_sink_time", event.flow_sink_time)
                print("is_n_flow", event.is_n_flow)
                print("is_flow", event.is_flow)
                print("is_hop_latency", event.is_hop_latency)
                print("is_queue_occup", event.is_queue_occup)
                print("is_tx_utilize", event.is_tx_utilize)

            event_data = []

            # TODO: FIX02: Review these inputs
            if event.is_n_flow or event.is_flow:
                path_str = ":".join(str(event.sw_ids[i]) for i in reversed(range(0, event.num_INT_hop)))

                event_data.append(u"flow_lat_path\\,vlan_id=%d\\,sw_id=%i\\,eg_id=%d flow_latency=%d,path=\"%s\"%s" % (
                                    event.vlan_id,
                                    event.sw_ids[0],
                                    event.e_port_ids[0],
                                    event.flow_latency,
                                    path_str,
                                    ' %d' % event.flow_sink_time if self.int_time else ''))

            if event.is_hop_latency:
                for i in range(0, event.num_INT_hop):
                    if (event.is_hop_latency >> i) & 0x01:
                        event_data.append(u"flow_hop_latency\\,vlan_id=%d\\,sw_id=%i\\,eg_id=%d\\,sw_hop=%i value=%d%s" % (
                                    event.vlan_id,
                                    event.sw_ids[0],
                                    event.e_port_ids[0],
                                    event.sw_ids[i],
                                    event.hop_latencies[i],
                                    ' %d' % event.egr_times[i] if self.int_time else ''))

            if event.is_tx_utilize:
                for i in range(0, event.num_INT_hop):
                    if (event.is_tx_utilize >> i) & 0x01:
                        bw = (event.tx_utilize[i])/(event.tx_utilize_delta[i]/1000000000.0)
                        event_data.append(u"port_tx_utilize\\,sw_id\\=%d\\,eg_id\\=%d\\,queue_id\\=%d value=%d%s" % (
                                           event.sw_ids[i], event.e_port_ids[i], event.queue_ids[i], bw,
                                           ' %d' % event.egr_times[i] if self.int_time else ''))

            # This is ready:
            if event.is_queue_occup:
                for i in range(0, event.num_INT_hop):
                    if (event.is_queue_occup >> i) & 0x01:
                        event_data.append("queue_occupancy\\,sw_id\\=%d\\,eg_id\\=%d\\,queue_id\\=%d value=%d%s" %
                                          (event.sw_ids[i],
                                           event.e_port_ids[i],
                                           event.queue_ids[i],
                                           event.queue_occups[i],
                                           ' %d' % event.egr_times[i] if self.int_time else ''))

            for k, v in sorted(self.packet_counter_all.items()):
                # print("DEST_PORT : %10d, COUNT : %10d" % (k.value, v.value))
                event_data.append("telemetry_packet_counter\\,type\\=%d value=%d" % (k.value, v.value))

            for k, v in sorted(self.packet_counter_int.items()):
                # print("DEST_PORT : %10d, COUNT : %10d" % (k.value, v.value))
                event_data.append("telemetry_packet_counter\\,type\\=%d value=%d" % (k.value, v.value))

            self.lock.acquire()
            self.event_data.extend(event_data)
            self.lock.release()

        self.bpf_collector["events"].open_perf_buffer(_process_event, page_cnt=512)
