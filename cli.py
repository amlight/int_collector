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


import argparse


def parse_params():
    parser = argparse.ArgumentParser(description='InfluxBD INTCollector client.')

    parser.add_argument("-i", "--interface", default="eth0",
                        help="Interface to receive INT reports")

    parser.add_argument("-p", "--int-port", default=5900, type=int,
                        help="Destination port of INT Telemetry reports")

    parser.add_argument("-H", "--host", default="localhost",
                        help="InfluxDB server address")

    parser.add_argument("-D", "--database", default="INTdatabase",
                        help="Database name")

    parser.add_argument("-P", "--event-period", default=0.1, type=float,
                        help="Interval in seconds to push event data. Default: 0.1 seconds.")

    parser.add_argument("-d", "--debug-mode", default=0, type=int,
                        help="Set to 1 to print event")

    parser.add_argument("-n", "--new-measurements", default=0, type=int,
                        help="Set to 1 to delete influxdb measurements")

    parser.add_argument("-m", "--xdp-mode", default=0, type=int,
                        help="Set to 1 to hardware off. Default is Native mode")

    parser.add_argument("--hop-latency", default=50000, type=int,
                        help="Hop Latency variation in nanoseconds to monitor")

    parser.add_argument("--flow-latency", default=100000, type=int,
                        help="Flow Latency variation in nanoseconds to monitor")

    parser.add_argument("--queue-occ", default=80, type=int,
                        help="Queue Occupancy threshold to monitor")

    parser.add_argument("--interface-util-interval", default=0.5, type=float,
                        help="Interval in seconds between recording interface egress utilization")

    parser.add_argument("--flow-keepalive", default=3000000000, type=int,
                        help="Interval in ns to report flows even if there are no changes")

    parser.add_argument("--run-counter-mode-only", default=0, type=int,
                        help="Run on Counter mode (only statistics)")

    parser.add_argument("--run-threshold-mode-only", default=0, type=int,
                        help="Run on Threshold mode (only queues and delays)")

    return parser.parse_args()
