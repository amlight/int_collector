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


""" Test CLI inputs """

import os
import unittest
from configparser import ConfigParser
from libs.input.config_class import MyDefaultConfig


class TestCLI(unittest.TestCase):
    """ Test all combinations for evaluate_str """

    def setUp(self):
        """ setUp """
        self.my_configs = list()
        config = ConfigParser()
        config.sections()
        config.read(os.getcwd() + "/tests/data/collector.ini")
        for section in config.sections():
            if section != 'DEFAULT':
                self.my_configs.append(dict(config[section]))

    def test_correct_number_configs(self):
        """ Count the number of instances in the config.ini file"""
        assert len(self.my_configs) == 7

    def test_correct_my_instance_1(self):
        """ """
        my_config = MyDefaultConfig("instance_1", self.my_configs[0])
        assert my_config.is_config_accurate() is True
        assert my_config.enable is True
        assert my_config.promisc is True
        assert my_config.xdp_mode is False
        assert my_config.debug is False
        assert my_config.drop_db is False
        assert my_config.mode == 0
        assert my_config.interface == "lo"
        assert my_config.numa_group == 8
        assert my_config.int_port == 5900
        assert my_config.save_interval == 0.1
        assert my_config.db_host == "localhost"
        assert my_config.db_name == "my_database"
        assert my_config.counters_interval == 0.5
        assert my_config.flow_keepalive == 3
        assert my_config.queue_occ == 225
        assert my_config.flow_latency == 100000
        assert my_config.hop_latency == 50000
        assert "--run-counters-mode-only " not in str(my_config)
        assert "--run-threshold-mode-only " not in str(my_config)
        assert "--drop-db " not in str(my_config)
        assert "--db-host " not in str(my_config)
        assert "--debug " not in str(my_config)
        assert "--xdp-mode " not in str(my_config)
        assert "--numa-group " not in str(my_config)
        assert "--counters-interval=0.5" in str(my_config)
        assert "--db-name=my_database" in str(my_config)
        assert "--flow-keepalive=3" in str(my_config)
        assert "--flow-latency=100000" in str(my_config)
        assert "--hop-latency=50000" in str(my_config)
        assert "--interface=lo" in str(my_config)
        assert "--numa-group=8" in str(my_config)
        assert "--promisc" in str(my_config)
        assert "--save-interval=0.1" in str(my_config)
        assert "--name=instance_1" in str(my_config)
        assert len(str(my_config).split()) == 11

    def test_correct_my_instance_2(self):
        """ """
        my_config = MyDefaultConfig("instance_2", self.my_configs[1])
        assert my_config.is_config_accurate() is True
        assert my_config.enable is True
        assert my_config.promisc is True
        assert my_config.xdp_mode is False
        assert my_config.debug is False
        assert my_config.drop_db is False
        assert my_config.mode == 1
        assert my_config.interface == "eth0"
        assert my_config.int_port == 5900
        assert my_config.save_interval == 0.1
        assert my_config.db_host == "localhost"
        assert my_config.db_name == "testing-db-counters"
        assert my_config.counters_interval == 0.5
        assert my_config.flow_keepalive == 3
        assert my_config.queue_occ == 225
        assert "--numa-group" not in str(my_config)
        assert "--drop-db" not in str(my_config)
        assert "--db-host " not in str(my_config)
        assert "--debug " not in str(my_config)
        assert "--xdp-mode " not in str(my_config)
        assert "--hop-latency" not in str(my_config)
        assert "--flow-latency" not in str(my_config)
        assert "--queue-occ" not in str(my_config)
        assert "--run-threshold-mode-only " not in str(my_config)
        assert "--run-counter-mode-only " in str(my_config)
        assert "--counters-interval=0.5" in str(my_config)
        assert "--db-name=testing-db-counters" in str(my_config)
        assert "--flow-keepalive=3" in str(my_config)
        assert "--interface=eth0" in str(my_config)
        assert "--promisc" in str(my_config)
        assert "--name=instance_2" in str(my_config)
        assert len(str(my_config).split()) == 7

    def test_correct_my_instance_3(self):
        """ """
        my_config = MyDefaultConfig("instance_3", self.my_configs[2])
        assert my_config.is_config_accurate() is True
        assert my_config.enable is True
        assert my_config.promisc is True
        assert my_config.xdp_mode is False
        assert my_config.debug is False
        assert my_config.drop_db is False
        assert my_config.mode == 2
        assert my_config.interface == "eth1"
        assert my_config.int_port == 5901
        assert my_config.save_interval == 0.1
        assert my_config.db_host == "localhost"
        assert my_config.db_name == "testing-db-thresholds"
        assert my_config.flow_keepalive == 2
        assert my_config.queue_occ == 300
        assert my_config.flow_latency == 110000
        assert my_config.hop_latency == 60000
        assert "--run-counter-mode-only" not in str(my_config)
        assert "--counters-interval" not in str(my_config)
        assert "--numa-group" not in str(my_config)
        assert "--db-host " not in str(my_config)
        assert "--debug " not in str(my_config)
        assert "--xdp-mode " not in str(my_config)
        assert "--run-threshold-mode-only" in str(my_config)
        assert "--db-name=testing-db-thresholds" in str(my_config)
        assert "--flow-keepalive=2" in str(my_config)
        assert "--flow-latency=110000" in str(my_config)
        assert "--hop-latency=60000" in str(my_config)
        assert "--int-port=5901" in str(my_config)
        assert "--interface=eth1" in str(my_config)
        assert "--promisc" in str(my_config)
        assert "--queue-occ=300" in str(my_config)
        assert "--save-interval=0.1" in str(my_config)
        assert "--name=instance_3" in str(my_config)
        assert len(str(my_config).split()) == 11

    def test_correct_my_instance_4_disabled(self):
        """ """
        my_config = MyDefaultConfig("instance_4", self.my_configs[3])
        assert my_config.is_config_accurate() is False  # Disabled
        assert my_config.enable is False
        assert my_config.promisc is False
        assert my_config.xdp_mode is True
        assert my_config.debug is True
        assert my_config.drop_db is True
        assert my_config.mode == 0
        assert my_config.interface == "lo"
        assert my_config.int_port == 5000
        assert my_config.save_interval == 0.8
        assert my_config.counters_interval == 0.9
        assert my_config.db_host == "1.2.3.4"
        assert my_config.db_name == "new_database"
        assert my_config.flow_keepalive == 5
        assert my_config.queue_occ == 300
        assert my_config.flow_latency == 200000
        assert my_config.hop_latency == 100000
        assert "--run-counter-mode-only " not in str(my_config)
        assert "--run-threshold-mode-only " not in str(my_config)
        assert "--promisc" not in str(my_config)
        assert "--counters-interval=0.9" in str(my_config)
        assert "--numa-group=10" in str(my_config)
        assert "--db-host=1.2.3.4" in str(my_config)
        assert "--debug" in str(my_config)
        assert "--drop-db" in str(my_config)
        assert "--xdp-mode" in str(my_config)
        assert "--db-name=new_database" in str(my_config)
        assert "--flow-keepalive=5" in str(my_config)
        assert "--flow-latency=200000" in str(my_config)
        assert "--hop-latency=100000" in str(my_config)
        assert "--int-port=5000" in str(my_config)
        assert "--interface=lo" in str(my_config)
        assert "--queue-occ=300" in str(my_config)
        assert "--save-interval=0.8" in str(my_config)
        assert "--name=instance_4" in str(my_config)
        assert len(str(my_config).split()) == 15

    def test_incorrect_missing_params(self):
        """ String cannot be empty"""
        my_config = MyDefaultConfig("instance_5", self.my_configs[4])
        assert my_config.is_config_accurate() is False  # not interface or db_name
        my_config_2 = MyDefaultConfig("instance_6", self.my_configs[5])
        assert my_config_2.is_config_accurate() is False  # not interface or db_name
        my_config_3 = MyDefaultConfig("instance_7", self.my_configs[6])
        assert my_config_3.is_config_accurate() is False  # not interface or db_name

    def test_correct_mode(self):
        """ Test if mode is 0, 1, or 2 """
        my_config = MyDefaultConfig("instance_5", self.my_configs[0])
        assert my_config.is_config_accurate() is True

        my_config.mode = 0
        assert my_config.mode == 0
        my_config.mode = 1
        assert my_config.mode == 1
        my_config.mode = 2
        assert my_config.mode == 2

    def test_incorrect_mode(self):
        """ String cannot be empty"""
        my_config = MyDefaultConfig("instance_5", self.my_configs[0])
        assert my_config.is_config_accurate() is True

        with self.assertRaises(ValueError):
            my_config.mode = 3  # Any other integer set mode to 0.
        # If value can't be converted to int, raise ValueError
        with self.assertRaises(ValueError):
            my_config.mode = 'a'
        with self.assertRaises(ValueError):
            my_config.mode = None
