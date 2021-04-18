from __future__ import print_function

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

    parser.add_argument("-i", "--int_port", default=5900, type=int,
                        help="Destination port of INT Telemetry reports")

    parser.add_argument("-H", "--host", default="localhost",
                        help="InfluxDB server address")

    parser.add_argument("-D", "--database", default="INTdatabase",
                        help="Database name")

    parser.add_argument("-P", "--event_period", default=0.2, type=float,
                        help="Interval in seconds to push event data. Default: 0.2 seconds.")

    parser.add_argument("-d", "--debug_mode", default=0, type=int,
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
                        help="Queue Occupancy variation to monitor")

    parser.add_argument("--interface-util-interval", default=500000000, type=int,
                        help="Interval in ns between recording interface egress utilization")

    parser.add_argument("--max-number-int-hops", default=6, type=int,
                        help="Max number of INT metadata to process")

    parser.add_argument("--flow_keepalive", default=1000000000, type=int,
                        help="Interval in ns to report flows even if there are no changes")

    return parser.parse_args()


if __name__ == "__main__":

    args = parse_params()

    collector = InDBCollector.InDBCollector(int_dst_port=args.int_port,
                                            debug_mode=args.debug_mode,
                                            host=args.host,
                                            database=args.database,
                                            flags=args.xdp_mode,
                                            hop_latency=args.hop_latency,
                                            flow_latency=args.flow_latency,
                                            queue_occ=args.queue_occ,
                                            intf_util_interval=args.interface_util_interval,
                                            max_hops=args.max_number_int_hops)

    for iface in args.ifaces:
        collector.attach_iface(iface)

    # Test if database is not found,create one
    if not len(collector.client.get_list_database()):
        collector.client.create_database(args.database)

    if args.new_measurements:
        for db in collector.client.get_list_database():
            collector.client.drop_database(db["name"])
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
    def _gather_counters():

        while not push_stop_flag.is_set():

            time.sleep(args.event_period)
            event_data = []

            for k, v in sorted(collector.packet_counter_all.items()):
                # print("DEST_PORT : %10d, COUNT : %10d" % (k.value, v.value))
                event_data.append("telemetry_packet_counter\\,type\\=%d value=%d" % (k.value, v.value))

            for k, v in sorted(collector.packet_counter_int.items()):
                # print("DEST_PORT : %10d, COUNT : %10d" % (k.value, v.value))
                event_data.append("telemetry_packet_counter\\,type\\=%d value=%d" % (k.value, v.value))

            if event_data:
                collector.client.write_points(points=event_data, protocol="line")
            del event_data

    gather_counters = threading.Thread(target=_gather_counters)
    gather_counters.start()

    # Start polling events
    collector.open_events()

    print("eBPF progs Loaded")
    sys.stdout.flush()

    try:
        while 1:
            collector.poll_events()

    except KeyboardInterrupt:
        pass

    finally:
        push_stop_flag.set()
        event_push.join()
        gather_counters.join()

        collector.detach_all_iface()
        print("Done")
