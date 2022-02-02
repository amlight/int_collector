from __future__ import print_function

import os
import argparse
import threading
import time
import sys

import pyximport; pyximport.install()
import InDBCollector


def parse_params():
    parser = argparse.ArgumentParser(description='InfluxBD INTCollector client.')

    parser.add_argument("ifaces", nargs='+',
                        help="List of ifaces to receive INT reports")

    parser.add_argument("-i", "--int-port", default=5900, type=int,
                        help="Destination port of INT Telemetry reports")

    parser.add_argument("-H", "--host", default="localhost",
                        help="InfluxDB server address")

    parser.add_argument("-D", "--database", default="INTdatabase",
                        help="Database name")

    parser.add_argument("-P", "--event-period", default=0.5, type=float,
                        help="Interval in seconds to push event data. Default: 0.5 seconds.")

    parser.add_argument("-d", "--debug-mode", default=0, type=int,
                        help="Set to 1 to print event")

    parser.add_argument("-n", "--new-measurements", default=0, type=int,
                        help="Set to 1 to delete influxdb measurements")

    parser.add_argument("-m", "--xdp-mode", default=0, type=int,
                        help="Set to 1 to hardware off. Default is Native mode")

    parser.add_argument("--hop-latency", default=2000, type=int,
                        help="Hop Latency variation in nanoseconds to monitor")

    parser.add_argument("--flow-latency", default=50000, type=int,
                        help="Flow Latency variation in nanoseconds to monitor")

    parser.add_argument("--queue-occ", default=80, type=int,
                        help="Queue Occupancy threshold to monitor")

    parser.add_argument("--interface-util-interval", default=0.5, type=int,
                        help="Interval in seconds between recording interface egress utilization")

    parser.add_argument("--max-number-int-hops", default=10, type=int,
                        help="Max number of INT metadata to process")

    parser.add_argument("--flow-keepalive", default=2000000000, type=int,
                        help="Interval in ns to report flows even if there are no changes")

    parser.add_argument("--run-counter-mode-only", default=0, type=int,
                        help="Run on Counter mode (only statistics)")

    parser.add_argument("--run-threshold-mode-only", default=0, type=int,
                        help="Run on Threshold mode (only queues and delays)")

    return parser.parse_args()


if __name__ == "__main__":

    args = parse_params()

    enable_threshold = 0 if args.run_counter_mode_only else 1
    enable_counter = 0 if args.run_threshold_mode_only else 1

    collector = InDBCollector.InDBCollector(int_dst_port=args.int_port,
                                            debug_int=args.debug_mode,
                                            host=args.host,
                                            database=args.database,
                                            flags=args.xdp_mode,
                                            hop_latency=args.hop_latency,
                                            flow_latency=args.flow_latency,
                                            queue_occ=args.queue_occ,
                                            max_hops=args.max_number_int_hops,
                                            flow_keepalive=args.flow_keepalive,
                                            enable_counter_mode=enable_counter,
                                            enable_threshold_mode=enable_threshold)

    for iface in args.ifaces:
        _ = os.system("ifconfig %s promisc" % iface)
        collector.attach_iface(iface)

    # Test if database is not found,create one
    if args.database not in collector.client.get_list_database():
        collector.client.create_database(args.database)

    # If database is needs to be recreated
    if args.new_measurements:
        if args.database in collector.client.get_list_database():
            collector.client.drop_database(args.database)
        collector.client.create_database(args.database)

    push_stop_flag = threading.Event()

    # A separated thread to push event data to the database
    def _event_push():

        while not push_stop_flag.is_set():

            time.sleep(args.event_period)

            collector.lock.acquire()
            data = collector.event_data
            collector.event_data = []
            collector.lock.release()

            if args.debug_mode == 2:
                print("Len of events: ", len(data))

            if data:
                collector.client.write_points(points=data, protocol="line")

    event_push = threading.Thread(target=_event_push)
    event_push.start()

    # Collecting and exporting data from tables instead of events.
    gather_stop_flag = threading.Event()

    def _gather_counters():

        while not gather_stop_flag.is_set():

            time.sleep(args.interface_util_interval)
            event_data = []

            for k, v in sorted(collector.packet_counter_all.items()):
                event_data.append("int_reports\\,type\\=%d value=%d" % (k.value, v.value))

            for k, v in sorted(collector.packet_counter_int.items()):
                event_data.append("int_reports\\,type\\=%d value=%d" % (k.value, v.value))

            for k, v in sorted(collector.packet_counter_errors.items()):
                event_data.append("int_reports\\,type\\=%d value=%d" % (k.value, v.value))

            for k, v in collector.tb_egr.items():
                event_data.append("tx_octs\\,sw\\=%d\\,port\\=%d\\,queue\\=%d\\,vlan\\=%d value=%d" %
                                  (k.sw_id, k.p_id, k.q_id, k.v_id, v.octets))
                event_data.append("tx_pkts\\,sw\\=%d\\,port\\=%d\\,queue\\=%d\\,vlan\\=%d value=%d" %
                                  (k.sw_id, k.p_id, k.q_id, k.v_id, v.packets))

            for k, v in collector.tb_egr_q.items():
                event_data.append(
                    "tx_octs_queue\\,sw\\=%d\\,port\\=%d\\,queue\\=%d value=%d" %
                    (k.sw_id, k.p_id, k.q_id, v.octets))
                event_data.append(
                    "tx_pkts_queue\\,sw\\=%d\\,port\\=%d\\,queue\\=%d value=%d" %
                    (k.sw_id, k.p_id, k.q_id, v.packets))

            for k, v in collector.tb_egr_int.items():
                event_data.append(
                    "tx_octs_int\\,sw\\=%d\\,port\\=%d value=%d" %
                    (k.sw_id, k.p_id, v.octets))
                event_data.append(
                    "tx_pkts_int\\,sw\\=%d\\,port\\=%d value=%d" %
                    (k.sw_id, k.p_id, v.packets))

            if event_data:
                # TODO: handle timeouts
                # Exception in thread Thread-1:
                # Traceback (most recent call last):
                #   File "/usr/lib/python3.6/threading.py", line 916, in _bootstrap_inner
                #     self.run()
                #   File "/usr/lib/python3.6/threading.py", line 864, in run
                #     self._target(*self._args, **self._kwargs)
                #   File "InDBClient.py", line 104, in _event_push
                #     collector.client.write_points(points=data, protocol="line")
                #   File "/usr/local/lib/python3.6/dist-packages/influxdb/client.py", line 599, in write_points
                #     consistency=consistency)
                #   File "/usr/local/lib/python3.6/dist-packages/influxdb/client.py", line 676, in _write_points
                #     protocol=protocol
                #   File "/usr/local/lib/python3.6/dist-packages/influxdb/client.py", line 410, in write
                #     headers=headers
                #   File "/usr/local/lib/python3.6/dist-packages/influxdb/client.py", line 364, in request
                #     raise InfluxDBServerError(reformat_error(response))
                # influxdb.exceptions.InfluxDBServerError: b'{"error":"timeout"}\n'
                collector.client.write_points(points=event_data, protocol="line")
            del event_data

    gather_counters = threading.Thread(target=_gather_counters)
    gather_counters.start()

    # Start polling events
    collector.open_events()

    print("eBPF progs Loaded.")
    sys.stdout.flush()

    try:
        while 1:
            collector.poll_events()

    except KeyboardInterrupt:
        pass

    finally:
        push_stop_flag.set()
        gather_stop_flag.set()
        event_push.join()
        gather_counters.join()

        collector.detach_all_iface()
        for iface in args.ifaces:
            _ = os.system("ifconfig %s -promisc" % iface)
        print("Done")
