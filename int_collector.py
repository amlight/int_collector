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
""" The int_collector.py is responsible for starting the INT Collector's instances """

import sys
import os
import shlex
import subprocess

from libs.input.cli import get_options


VERSION = "1.1"

# Get CLI vs. Config options.
instances = get_options()

if not instances:
    print("No options provided. Exiting.")
    sys.exit(2)

# Popen each instance requested. If request came from CLI there will be only one instance.
for instance in instances:
    # Get current full path
    full_path = "%s %s/load_instances.py " % (sys.executable, os.getcwd())
    # Get the params per instance in Shell format (--command=etc)
    cmd = full_path + str(instance)
    # Split the options in Shell format
    cmds = shlex.split(cmd)

    # Add option for --numa-group
    # If --numa-group is provided, use the value provided with Linux command numaclt as below:
    #   numactl -C <VALUE> python3 ....
    numa_value = None
    for cmd in cmds:
        if "--numa-group=" in cmd:
            numa_value = cmd.split("=")[1]

    if isinstance(numa_value, int):
        cmds.insert(0, str(numa_value))
        cmds.insert(0, "-C")
        cmds.insert(0, "/usr/bin/numactl")

    # Start the instance as a process in background
    process = subprocess.Popen(cmds, start_new_session=True)  # pylint: disable=R1732

    # Write PID file
    pidfile = open(instance.name + '.pid', 'w')
    pidfile.write(str(process.pid))
    pidfile.close()
    print(f"INT Collector: Instance {instance.name} (PID {process.pid}) is running on {instance.interface}.")

sys.exit(0)
