from __future__ import print_function
import threading
from bcc import BPF
from influxdb import InfluxDBClient
import ctypes as ct

_MAX_INT_HOP = 6

class FlowID(ct.Structure):
    _fields_ = [
        ("vlan_id", ct.c_ushort),
        ("last_sw_id", ct.c_uint),
        ("last_egr_id", ct.c_ushort),
    ]

class Event(ct.Structure):
    __MAX_INT_HOP = _MAX_INT_HOP
    _fields_ = [
        ("seqNumber", ct.c_uint),
        ("vlan_id", ct.c_ushort),
        ("num_INT_hop", ct.c_ubyte),
        ("hop_negative", ct.c_ubyte),

        ("sw_ids", ct.c_uint * __MAX_INT_HOP),
        ("int_port_ids", ct.c_ushort * __MAX_INT_HOP),
        ("e_port_ids", ct.c_ushort * __MAX_INT_HOP),
        ("hop_latencies", ct.c_uint * __MAX_INT_HOP),
        ("queue_ids", ct.c_ushort * __MAX_INT_HOP),
        ("queue_occups", ct.c_ushort * __MAX_INT_HOP),
        ("ingr_times", ct.c_uint * __MAX_INT_HOP),
        ("egr_times", ct.c_uint * __MAX_INT_HOP),

        ("tx_utilize", ct.c_ulong * __MAX_INT_HOP),
        ("tx_utilize_delta", ct.c_ulong * __MAX_INT_HOP),

        ("flow_latency", ct.c_uint),
        ("flow_sink_time", ct.c_ulong),

        ("is_n_flow", ct.c_ubyte),
        ("is_flow", ct.c_ubyte),

        ("is_hop_latency", ct.c_ubyte),
        ("is_queue_occup", ct.c_ubyte),
        ("is_tx_utilize", ct.c_ubyte),
    ]

class InDBCollector(object):
    """docstring for InDBCollector"""

    def __init__(self,
                 int_dst_port=5900,
                 debug_mode=0,
                 host="localhost",
                 database="INTdatabase",
                 flags=0):

        super(InDBCollector, self).__init__()

        self.MAX_INT_HOP = _MAX_INT_HOP
        # self.SERVER_MODE = "INFLUXDB"
        self.INT_DST_PORT = int_dst_port
        self.int_time = False

        self.ifaces = set()

        #load eBPF program
        self.bpf_collector = BPF(src_file="BPFCollector.c", debug=0,
                                 cflags=["-w",
                                         "-D_MAX_INT_HOP=%s" % self.MAX_INT_HOP,
                                         "-D_INT_DST_PORT=%s" % self.INT_DST_PORT])
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

            flow_id = ct.cast(data, ct.POINTER(FlowID)).contents

            event = ct.cast(self.tb_flow[flow_id], ct.POINTER(Event)).contents

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
