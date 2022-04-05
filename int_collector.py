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

import sys
import os
import shlex
import subprocess

from libs.input.cli import get_options


VERSION = "version1.1"

# Get CLI vs. Config options.
instances = get_options()

if not instances:
    print("No options provided. Exiting.")
    sys.exit(2)

# Popen each instance requested. If request came from CLI there will be only one instance.
for instance in instances:
    # Get current full path
    full_path = "%s %s/load_instances.py " % (sys.executable, os.getcwd())
    cmd = full_path + str(instance)

    cmds = shlex.split(cmd)
    p = subprocess.Popen(cmds, start_new_session=True)
