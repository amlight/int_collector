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
""" This module handles CLI parameters via argparse"""


import argparse


def parse_params():
    """ This module handles CLI parameters via argparse"""

    parser = argparse.ArgumentParser(description='INT Collector CLI Options')

    # Mandatory if --config-file not used. It's handled later.
    parser.add_argument("-i", "--interface",
                        help="Interface to receive INT reports")

    parser.add_argument("-D", "--db-name",
                        help="InFluxDB Database name")

    # Optional

    parser.add_argument("--name",
                        help="Label for this instance.")

    parser.add_argument("-c", "--config-file",
                        help="Use configs from file.")

    parser.add_argument("--numa-group",
                        help="Set the proper NUMA_GROUP for CPU affinity/better performance")

    parser.add_argument("-p", "--int-port", default=5900, type=int,
                        help="Destination port of the INT Telemetry reports")

    parser.add_argument("-H", "--host", default="localhost",
                        help="InfluxDB server address")

    parser.add_argument("--save-interval", default=0.1, type=float,
                        help="Interval in seconds to save data to database. Default: 0.1 seconds.")

    parser.add_argument("-d", "--debug-mode", action="store_true",
                        help="Enable debug mode")

    parser.add_argument("--drop-db", action="store_true",
                        help="Delete ALL Influxdb measurements from database provided via -D")

    parser.add_argument("-m", "--xdp-mode", action="store_true",
                        help="Enable hardware offload. Default is Native mode")

    parser.add_argument("--flow-keepalive", default=3000000000, type=int,
                        help="Interval in nanoseconds to report flows even if there are no changes")

    parser.add_argument("--promisc", action="store_true",
                        help="Change the interface to operate in promisc mode.")

    # Counter mode options
    parser.add_argument("--run-counter-mode-only", action="store_true",
                        help="Run on Counter mode (only counters gathering)")

    parser.add_argument("--counters-interval", default=0.5, type=float,
                        help="Interval in seconds between recording interface egress utilization")

    # Threshold mode options
    parser.add_argument("--run-threshold-mode-only", action="store_true",
                        help="Run on Threshold mode (only queues and delays)")

    parser.add_argument("--hop-latency", default=50000, type=int,
                        help="Hop Latency variation in nanoseconds to monitor")

    parser.add_argument("--flow-latency", default=100000, type=int,
                        help="Flow Latency variation in nanoseconds to monitor")

    parser.add_argument("--queue-occ", default=80, type=int,
                        help="Queue Occupancy threshold to monitor in cells of 80 bytes")

    return parser.parse_args()
