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
from configparser import ConfigParser, DuplicateOptionError
from libs.input.config_class import MyDefaultConfig


def evaluate_configs(configs):
    """ Make sure that two configs don't share the same network interface """
    interfaces = []

    for config in configs:
        if config.interface in interfaces:
            print("Error: Interface %s can't be used in two instances." % config.interface)
            return False
        else:
            interfaces.append(config.interface)
    return True


def read_config_file(config_file):
    """ """
    config = ConfigParser()
    config.sections()
    try:
        config.read(config_file)
    except DuplicateOptionError as error:
        print(error)
        sys.exit(3)

    my_configs = []

    for section in config.sections():

        if section != 'DEFAULT':
            my_config = MyDefaultConfig(section, dict(config[section]))
            if my_config.is_config_accurate():
                my_configs.append(my_config)
            del my_config

    if not evaluate_configs(my_configs):
        print("Error: fix config file %s and try it again." % config_file)
        sys.exit(1)

    return my_configs


if __name__ == "__main__":
    my = read_config_file("../../etc/collector.ini")
    for i in my:
        print(i)

