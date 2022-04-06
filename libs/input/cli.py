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
""" Evaluate the input options """

from libs.input.parse_cli import parse_params
from libs.input.read_configs import read_config_file


def get_options():
    """ Evaluate the input options """
    configs = parse_params()

    if not (configs.interface or configs.config_file):
        # If CLI is being used, check for interface (mandatory).
        # Otherwise, check if config_file was provided.
        # If neither is provided, stop execution.
        return False

    # If config is provided, at this moment, its content is used instead of CLI.
    # That happens because the config file supports sections,
    #  or multiple instances while CLI supports a single
    # instance running per call.
    if configs.config_file is not None:
        return read_config_file(configs.config_file)
    else:
        return configs
