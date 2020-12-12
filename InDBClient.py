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

    parser.add_argument("-P", "--event_period", default=1, type=float,
                        help="Time period to push event data")

    parser.add_argument("-d", "--debug_mode", default=0, type=int,
                        help="Set to 1 to print event")

    parser.add_argument("-n", "--new-measurements", default=0, type=int,
                        help="Set to 1 to delete influxdb measurements")

    parser.add_argument("-m", "--xdp-mode", default=0, type=int,
                        help="Set to 1 to hardware off. Default is Native mode")

    return parser.parse_args()


if __name__ == "__main__":

    args = parse_params()

    collector = InDBCollector.InDBCollector(int_dst_port=args.int_port,
                                            debug_mode=args.debug_mode,
                                            host=args.host,
                                            database=args.database,
                                            flags=args.xdp_mode)

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

    # A separated thread to push event data
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

        collector.detach_all_iface()
        print("Done")
