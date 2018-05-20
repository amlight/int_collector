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
parser.add_argument("-D", "--database", default="INTdatabase",
    help="Database name")
parser.add_argument("-c", "--cython", action='store_true',
    help="Use Cython")    
parser.add_argument("-p", "--period", default=10, type=int,
    help="Time period to push data in normal condition")
parser.add_argument("-P", "--event_period", default=1, type=float,
    help="Time period to push event data")
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
    from cy_InDBCollector import Cy_InDBCollector, _MAX_INT_HOP

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

    # A separated thread to push event data
    def _event_push():

        while not push_stop_flag.is_set():
            
            time.sleep(args.event_period)
            
            collector.lock.acquire()
            data = collector.event_data
            collector.event_data = []
            collector.lock.release()
            
            if args.debug_mode==2:
                print "Len of events: ", len(data)
            
            if data:
                collector.client.write_points(points=data)


    # A separated thread to push data
    def _periodically_push():
        while not push_stop_flag.is_set():
            
            time.sleep(args.period)

            data = collector.collect_data()
            if data:
                collector.client.write_points(points=data)
                if args.debug_mode==2:
                    print "Periodically push: ", len(data)


    periodically_push = threading.Thread(target=_periodically_push)
    periodically_push.start()
    event_push = threading.Thread(target=_event_push)
    event_push.start()


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
        event_push.join()

        collector.detach_all_iface()
        print("Done")

    print "Exit"