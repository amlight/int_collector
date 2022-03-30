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


import os
import threading
import time
import sys

import pyximport; pyximport.install()
import InDBCollector
import cli


if __name__ == "__main__":

    args = cli.parse_params()

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
                                            flow_keepalive=args.flow_keepalive,
                                            enable_counter_mode=enable_counter,
                                            enable_threshold_mode=enable_threshold)

    # Attach XDP code to interface
    _ = os.system("ifconfig %s promisc" % args.interface)
    collector.attach_iface(args.interface)

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

        _ = os.system("ifconfig %s -promisc" % args.interface)
        print("Done")
