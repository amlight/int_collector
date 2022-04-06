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
""" This module is used to load individual instances of the INT Collector.
It is called by int_collector.py via Popen as an independent process. """

import os
import threading
import time
import sys
import pyximport; pyximport.install()  # pylint: disable=C0321
import libs.xdp_code.InDBCollector as Collector  # pylint: disable=C0413
from libs.input.parse_cli import parse_params  # pylint: disable=C0413


def start_collector_instance():
    """ This function loads the INT Collector. This instance is loaded via Popen() """

    args = parse_params()

    print(f"Loading INT_Collector on interface {args.interface}")

    enable_threshold = 0 if args.run_counter_mode_only else 1
    enable_counter = 0 if args.run_threshold_mode_only else 1

    collector = Collector.Collector(int_dst_port=args.int_port,
                                    debug_int=args.debug_mode,
                                    host=args.host,
                                    database=args.db_name,
                                    flags=args.xdp_mode,
                                    hop_latency=args.hop_latency,
                                    flow_latency=args.flow_latency,
                                    queue_occ=args.queue_occ,
                                    flow_keepalive=args.flow_keepalive,
                                    enable_counter_mode=enable_counter,
                                    enable_threshold_mode=enable_threshold)

    # Attach XDP code to interface
    if args.promisc:
        _ = os.system(f"ifconfig {args.interface} promisc")
    collector.attach_iface(args.interface)

    # Test if db_name is not found,create one
    if args.db_name not in collector.client.get_list_database():
        collector.client.create_database(args.db_name)

    # If db_name is needs to be recreated
    if args.drop_db:
        if args.db_name in collector.client.get_list_db_name():
            collector.client.drop_db_name(args.db_name)
        collector.client.create_database(args.db_name)

    push_stop_flag = threading.Event()

    # A separated thread to push event data to the db_name
    def _event_push():

        while not push_stop_flag.is_set():

            time.sleep(args.save_interval)

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

            time.sleep(args.counters_interval)
            event_data = []

            for k, v in sorted(collector.packet_counter_all.items()):
                event_data.append("int_reports\\,type\\=%d value=%d" % (k.value, v.value))

            for k, v in sorted(collector.packet_counter_int.items()):
                event_data.append("int_reports\\,type\\=%d value=%d" % (k.value, v.value))

            for k, v in sorted(collector.packet_counter_errors.items()):
                event_data.append("int_reports\\,type\\=%d value=%d" % (k.value, v.value))

            for k, v in collector.tb_egr.items():
                insert = "tx_octs\\,sw\\=%d\\,port\\=%d\\,queue\\=%d\\,vlan\\=%d value=%d"
                event_data.append(insert % (k.sw_id, k.p_id, k.q_id, k.v_id, v.octets))
                insert = "tx_pkts\\,sw\\=%d\\,port\\=%d\\,queue\\=%d\\,vlan\\=%d value=%d"
                event_data.append(insert % (k.sw_id, k.p_id, k.q_id, k.v_id, v.packets))

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

        if args.promisc:
            _ = os.system(f"ifconfig {args.interface} -promisc")
        print("Done")


if __name__ == "__main__":
    start_collector_instance()
