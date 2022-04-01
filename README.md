# AmLight INT Collector

The AmLight INT Collector is a telemetry solution that collects In-band Network Telemetry (INT) reports exported by NoviFlow Tofino-based switches. The NoviFlow Tofino-based switches export INT reports following the INT specification version 1.0.

## Installation on Debian Bullseye

* Install BCC:
```Shell
Follow instruction from https://github.com/iovisor/bcc/
```
* Install Python 3.9 or newer

* Install Git

* Install influxdb

* Install Grafana

* Clone the repository
```Shell
git clone https://github.com/amlight/int_collector.git
```
* Install dependencies using your Python virtual environment  
```Shell
cd int_collector
pip3 install -r requirements.txt
```
* Run it to make sure everything is in place (use CTRL+C to end it)
```Shell
python InDBClient.py -i lo
```
* Import the dashboards from folder ./grafana-dashboards.
* Done.

## Running the INT Collector

The AmLight INT Collector has several options. Use --help to access them:

```Shell
python InDBClient.py --help
usage: InDBClient.py [-h] [-i INTERFACE] [-p INT_PORT] [-H HOST] [-D DATABASE] [-P EVENT_PERIOD] [-d DEBUG_MODE] [-n NEW_MEASUREMENTS] [-m XDP_MODE]
                     [--hop-latency HOP_LATENCY] [--flow-latency FLOW_LATENCY] [--queue-occ QUEUE_OCC] [--interface-util-interval INTERFACE_UTIL_INTERVAL]
                     [--flow-keepalive FLOW_KEEPALIVE] [--run-counter-mode-only RUN_COUNTER_MODE_ONLY] [--run-threshold-mode-only RUN_THRESHOLD_MODE_ONLY]

InfluxBD INTCollector client.

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Interface to receive INT reports
  -p INT_PORT, --int-port INT_PORT
                        Destination port of INT Telemetry reports
  -H HOST, --host HOST  InfluxDB server address
  -D DATABASE, --database DATABASE
                        Database name
  -P EVENT_PERIOD, --event-period EVENT_PERIOD
                        Interval in seconds to push event data. Default: 0.1 seconds.
  -d DEBUG_MODE, --debug-mode DEBUG_MODE
                        Set to 1 to print event
  -n NEW_MEASUREMENTS, --new-measurements NEW_MEASUREMENTS
                        Set to 1 to delete influxdb measurements
  -m XDP_MODE, --xdp-mode XDP_MODE
                        Set to 1 to hardware off. Default is Native mode
  --hop-latency HOP_LATENCY
                        Hop Latency variation in nanoseconds to monitor
  --flow-latency FLOW_LATENCY
                        Flow Latency variation in nanoseconds to monitor
  --queue-occ QUEUE_OCC
                        Queue Occupancy threshold to monitor
  --interface-util-interval INTERFACE_UTIL_INTERVAL
                        Interval in seconds between recording interface egress utilization
  --flow-keepalive FLOW_KEEPALIVE
                        Interval in ns to report flows even if there are no changes
  --run-counter-mode-only RUN_COUNTER_MODE_ONLY
                        Run on Counter mode (only statistics)
  --run-threshold-mode-only RUN_THRESHOLD_MODE_ONLY
                        Run on Threshold mode (only queues and delays)
```

Each option is explained in more details below:

* -i or --interface: Interface where the INT Collector will be expecting INT reports. If the received IP packets are not IPv4+UDP+port provided in option -p (default is 5900), they are forwarded to the default Linux networking stack.
* -p or --int-port: INT reports are exported as IPv4 + UDP packets. This option defines the UDP port selected at the INT switch to listen. Default is 5900.
* -H or --host: IP address of the InFluxDB server. All reports are stored on InFluxDB. Only InFluxDB 1.x is supported. Default is localhost.
* -D or --database: Name of the InFluxDB database. Default is INT-database
* -P or --event-period: How often will reports be pushed to InfluxDB. Default is 0.1 seconds.
* -d or --debug-mode: When set to 1, enables printing of reports to be saved to InFluxDB. Default is 0.
* -n or --new-measurements: when set to 1, deletes the inFluxDb specified in -D before starting. ALL DATA IS LOST!
* -m or --xdp-mode: Mode how XDP will be loaded: native or offloaded to the NIC. At this moment, only native is supported.
* --hop-latency: number of nanoseconds to compare between INT reports' hop delay field. It is varies more than provided via this option, it is saved. Default is 50,000 nanoseconds or 50 microseconds.
* --flow-latency: number of nanoseconds to compare between INT reports' flow latency field. It is varies more than provided via this option, it is saved. Default is 100,000 nanoseconds or 100 microseconds.
* --queue-occ: number of cells of 80 bytes to compare between INT reports' queue occupancy field. Default is 80 cells, or 6,400 bytes.
* --interface-util-interval: Interface to record interface, queue, and vlan utilization in bits per second and packets per second. Default is 0.5 seconds.
* --flow-keepalive: Interval in nanoseconds to store INT reports even if there are no changes in the thresholds defined in previous options.
* --run-counter-mode-only: For scalability, operator could set this to 1 to only process INT reports for interface utilization/statistics. 
* --run-threshold-mode-only: For scalability, operator could set this to 1 to only process INT reports for queue occupancy and hop delay monitoring. 

At AmLight, the INT Collector node has a quad-10G Intel NIC, all four ports receiving the INT reports. For scalability purposes, we use the options --run-counter-mode-only and --run-threshold-mode-only, each listing on a different NIC:

```Shell
python InDBClient.py --interface=intel-10g-02 --run-counter-mode-only=1 --database=INT-Counters --interface-util-interval=0.4 --int-port=5900 &
python InDBClient.py --interface=intel-10g-03 --run-threshold-mode-only=1 --database=INT-Thresholds --hop-latency=80000 --queue-occ=160 --flow-keepalive=4 --int-port=5900 &
```

For more defails about the INT deployment at AmLight, watch our presentation at the ESnet CI Lunch and Learn:

https://www.es.net/science-engagement/ci-engineering-lunch-and-learn-series/
https://youtu.be/CRnKKuP9I3Y

The AmLight INT Collector version 1.0 is experimental. In case of comments: <sdn at amlight dot net>

The AmLight INT Collector follows the GPL v3 license.