#!/usr/bin/python
import argparse

# we parse argument first to decide whether or not importing cython module
parser = argparse.ArgumentParser(description='InfluxBD client.')
parser.add_argument("ifaces", nargs='+',
help="List of ifaces to receive INT reports")
parser.add_argument("-m", "--max_int_hop", default=6, type=int,
    help="MAX INT HOP")
parser.add_argument("-H", "--host", default="localhost",
    help="InfluxDB server address")
parser.add_argument("-D", "--database", default="INTTdatabase",
    help="Database name")
parser.add_argument("-c", "--cython", action='store_true',
    help="Use Cython")    
parser.add_argument("-p", "--period", default=10, type=int,
    help="Time period to push data in normal condition")
parser.add_argument("-d", "--debug_mode", default=0, type=int,
    help="Set to 1 to print event")
args = parser.parse_args()

from bcc import BPF
from pyroute2 import IPRoute
from prometheus_client import start_http_server, Summary
from prometheus_client import Gauge
from influxdb import InfluxDBClient

from ipaddress import IPv4Address
import threading
import time
import json
import multiprocessing
import sys
import ctypes as ct

if args.cython == False:
    from InDBCollector import InDBCollector
else:
    import pyximport; pyximport.install()
    from xy_InDBCollector import Cy_InDBCollector
    from cy_InDBCollector import _MAX_INT_HOP

if __name__ == "__main__":

    if args.cython == True:
        if _MAX_INT_HOP != args.max_int_hop:
            raise NameError("Set _MAX_INT_HOP in cy_InDBCollector to match \
                input max_int_hop and recompile")
        
        collector = Cy_InDBCollector(max_int_hop=args.max_int_hop, 
            debug_mode=args.debug_mode, host=args.host, database=args.database)
    else:
        collector = InDBCollector(max_int_hop=args.max_int_hop,
            debug_mode=args.debug_mode, host=args.host, database=args.database)
    
    for iface in args.ifaces:
        collector.attach_iface(iface)

    # clear all old dbs. For easy testing
    for db in collector.client.get_list_database():
        collector.client.drop_database(db["name"])
    collector.client.create_database(args.database)

    
    push_stop_flag = threading.Event()

    # A separated thread to push data
    def _periodically_push():
        push_cnt = 1
        _period_push_event = 2
        _period_normal = args.period/_period_push_event

        while not push_stop_flag.is_set():
            time.sleep(_period_push_event)

            push_cnt += 1
            if push_cnt == _period_normal:
                push_cnt = 0
            
            data = []
            collector.lock.acquire()
            data = collector.event_data
            collector.event_data = []
            collector.lock.release()
            
            if args.debug_mode==2:
                print "len of events: ", len(data)
            
            if data:
                collector.client.write_points(points=data)

            if push_cnt == 0:
                data = collector.collect_data()
                if data:
                    collector.client.write_points(points=data)

    periodically_push = threading.Thread(target=_periodically_push)
    periodically_push.start()


    # Start polling events
    collector.open_events()
    try:
        print "eBPF progs Loaded"
        while 1:
            collector.poll_events()

    except KeyboardInterrupt:
        pass

    finally:
        push_stop_flag.set()
        periodically_push.join()

        collector.detach_all_iface()
        print("Done")

    print "Exit"