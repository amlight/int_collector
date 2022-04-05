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


class MyDefaultConfig(object):
    """ Default attributes as of version 1.1 """

    def __init__(self, section_name, section_config):
        self.name = section_name
        self._enable = False
        self._interface = None
        self._mode = 0
        self._xdp_mode = False
        self._numa_group = None
        self._int_port = 5900
        self._save_interval = 0.1
        self._debug = False
        self._db_host = "localhost"
        self._db_name = None
        self._drop_db = False
        self._counters_interval = 0.5
        self._flow_keepalive = 3
        self._queue_occ = 225
        self._flow_latency = 100000
        self._hop_latency = 50000
        self._promisc = False

        self.import_config(section_config)

    @property
    def enable(self):
        return self._enable

    @enable.setter
    def enable(self, value):
        self._enable = True if value == "True" else False

    @property
    def interface(self):
        return self._interface

    @interface.setter
    def interface(self, value):
        self._interface = value

    @property
    def mode(self):
        return self._mode

    @mode.setter
    def mode(self, value):
        self._mode = int(value) if int(value) in [1, 2] else 0

    @property
    def xdp_mode(self):
        return self._xdp_mode

    @xdp_mode.setter
    def xdp_mode(self, value):
        self._xdp_mode = bool(value)

    @property
    def numa_group(self):
        return self._numa_group

    @numa_group.setter
    def numa_group(self, value):
        self._numa_group = int(value)

    @property
    def int_port(self):
        return self._int_port

    @int_port.setter
    def int_port(self, value):
        self._int_port = int(value)

    @property
    def debug(self):
        return self._debug

    @debug.setter
    def debug(self, value):
        self._debug = bool(value)

    @property
    def db_host(self):
        return self._db_host

    @db_host.setter
    def db_host(self, value):
        self._db_host = value

    @property
    def db_name(self):
        return self._db_name

    @db_name.setter
    def db_name(self, value):
        self._db_name = value

    @property
    def drop_db(self):
        return self._drop_db

    @drop_db.setter
    def drop_db(self, value):
        self._drop_db = bool(value)

    @property
    def counters_interval(self):
        return self._counters_interval

    @counters_interval.setter
    def counters_interval(self, value):
        self._counters_interval = float(value)

    @property
    def save_interval(self):
        return self._save_interval

    @save_interval.setter
    def save_interval(self, value):
        self._save_interval = float(value)

    @property
    def flow_keepalive(self):
        return self._flow_keepalive

    @flow_keepalive.setter
    def flow_keepalive(self, value):
        self._flow_keepalive = int(value)

    @property
    def queue_occ(self):
        return self._queue_occ

    @queue_occ.setter
    def queue_occ(self, value):
        self._queue_occ = int(value)

    @property
    def flow_latency(self):
        return self._flow_latency

    @flow_latency.setter
    def flow_latency(self, value):
        self._flow_latency = int(value)

    @property
    def hop_latency(self):
        return self._hop_latency

    @hop_latency.setter
    def hop_latency(self, value):
        self._hop_latency = int(value)

    @property
    def promisc(self):
        return self._promisc

    @promisc.setter
    def promisc(self, value):
        self._promisc = True if value == "True" else False

    def import_config(self, configs):
        """ Import configs from dictionary """

        if "enable" in configs:
            self.enable = configs["enable"]

        if "mode" in configs:
            self.mode = configs["mode"]

        if "interface" in configs:
            self.interface = configs["interface"]

        if "xdp_mode" in configs:
            self.xdp_mode = configs["xdp_mode"]

        if "numa_group" in configs:
            self.numa_group = configs["numa_group"]

        if "int_port" in configs:
            self.int_port = configs["int_port"]

        if "counters_interval" in configs:
            self.counters_interval = configs["counters_interval"]

        if "debug" in configs:
            self.debug = configs["debug"]

        if "db_host" in configs:
            self.db_host = configs["db_host"]

        if "db_name" in configs:
            self.db_name = configs["db_name"]

        if "drop_db" in configs:
            self.drop_db = configs["drop_db"]

        if "save_interval" in configs:
            self.save_interval = configs["save_interval"]

        if "flow_keepalive" in configs:
            self.flow_keepalive = configs["flow_keepalive"]

        if "queue_occ" in configs:
            self.queue_occ = configs["queue_occ"]

        if "flow_latency" in configs:
            self.flow_latency = configs["flow_latency"]

        if "hop_latency" in configs:
            self.hop_latency = configs["hop_latency"]

        if "numa_group" in configs:
            self.numa_group = configs["numa_group"]

        if "promisc" in configs:
            self.promisc = configs["promisc"]

    def is_config_accurate(self):
        """ Other than validating the inputs in the setter methods, here we evaluate what is
        mandatory. """
        if not self.interface or not self.db_name:
            print("Error reading section %s" % self.name)
            return False

        if not self.enable:
            return False
        return True

    def __str__(self):
        """ Convert all options into a string and remove options with default values """

        params = list()
        methods = []
        for method in dir(MyDefaultConfig):
            if not (method.startswith('__') or method.startswith('is_') or method.startswith('import')):
                if method != "enable":
                    methods.append(method)

        for method in methods:
            value = getattr(self, method)

            # In the config file, we use mode. In the CLI, we use the options below.
            if method == "mode":
                if value == 1:
                    params.append("--run-counter-mode-only")
                elif value == 2:
                    params.append("--run-threshold-mode-only")

            elif isinstance(value, bool) and value is True:
                # Boolean options have no values
                params.append("--%s" % method)

            # Remove default values
            elif (value and
                  not (method == "int_port" and value == 5900) and
                  not (method == "db_host" and value == "localhost")):

                if ((self.mode == 1 and
                     method not in ["queue_occ", "flow_latency", "hop_latency", "save_interval"]) or
                        (self.mode == 2 and method not in ["save_interval"]) or self.mode == 0):

                    params.append("--%s=%s" % (method.replace("_", "-"), value))

        return ' '.join(params)
