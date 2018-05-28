#!/usr/bin/python
import argparse
import threading
import time

# we parse argument first to decide whether or not importing cython module
parser = argparse.ArgumentParser(description='InfluxBD client.')

parser.add_argument("ifaces", nargs='+',
help="List of ifaces to receive INT reports")

parser.add_argument("-m", "--max_int_hop", default=6, type=int,
    help="MAX INT HOP")

parser.add_argument("-i", "--int_port", default=54321, type=int,
        help="Destination port of INT Telemetry reports")

parser.add_argument("-H", "--host", default="localhost",
    help="InfluxDB server address")

parser.add_argument("-D", "--database", default="INTdatabase",
    help="Database name")

parser.add_argument("--non_perf", action='store_true',
    help="Disable peformance optimization. Use when cannot install cython \
        or cython compiler error")    

parser.add_argument("-p", "--period", default=10, type=int,
    help="Time period to push data in normal condition")

parser.add_argument("-P", "--event_period", default=1, type=float,
    help="Time period to push event data")

parser.add_argument("-t", "--int_time", action='store_true',
    help="Use INT timestamp instead of local time. Only available for perf mode")

parser.add_argument("-d", "--debug_mode", default=0, type=int,
    help="Set to 1 to print event")
args = parser.parse_args()


if args.non_perf == True:
    from InDBCollector import InDBCollector
else:
    import pyximport; pyximport.install()
    from cy_InDBCollector import Cy_InDBCollector, _MAX_INT_HOP


if __name__ == "__main__":

    if args.non_perf == False:
        if _MAX_INT_HOP != args.max_int_hop:
            raise NameError("Set _MAX_INT_HOP in cy_InDBCollector to match \
                input max_int_hop and recompile")
        
        collector = Cy_InDBCollector(max_int_hop=args.max_int_hop,
            int_dst_port=args.int_port, debug_mode=args.debug_mode,
            host=args.host, database=args.database, int_time=args.int_time)

        protocol = "line" 

    else:
        collector = InDBCollector(max_int_hop=args.max_int_hop,
            int_dst_port=args.int_port, debug_mode=args.debug_mode,
            host=args.host, database=args.database)

        protocol = "json" 
    
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
                collector.client.write_points(points=data, protocol=protocol)


    # A separated thread to push data
    def _periodically_push():
        cnt = 0
        while not push_stop_flag.is_set():
            # use cnt to partition sleep time, so Ctrl-C could terminate the program earlier
            time.sleep(1)
            cnt += 1
            if cnt < args.period:
                continue
            cnt = 0

            data = collector.collect_data()
            if data:
                collector.client.write_points(points=data, protocol=protocol)
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