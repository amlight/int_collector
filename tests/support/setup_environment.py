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


""" This module creates a decorator to instantiate the INT_Collector before and kill it after the tests """

import os
import sys
import time


def setup_env(function):
    """ """
    def wrapper(*args, **kwargs):
        print(f"Running tests for test {function.__name__}")
        os.system("kill `ps -ef |grep load_instances | grep python | awk '{print $2}'`")
        os.system(f"python3 {sys.path[0]}/int_collector.py -c {sys.path[0]}/tests/data/collector-e2e.ini")
        time.sleep(2)
        function(*args, **kwargs)
        os.system("kill `ps -ef |grep load_instances | grep python | awk '{print $2}'`")

    return wrapper
