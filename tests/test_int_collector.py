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

""" This module tests the INT Collector using an end to end approach """

import time
import sys
from influxdb import InfluxDBClient
import unittest

if __name__ == "__main__":
    sys.path.insert(0, sys.path[0] + '/support')
else:
    sys.path.insert(0, sys.path[0] + '/tests/support')
from packet_gen import generate_metadata
from packet_gen import generate_packet
from packet_gen import send_packet
from setup_environment import setup_env


class TestE2E(unittest.TestCase):
    """ Test all combinations for evaluate_str """

    def setUp(self):
        """ setUp """
        self.db_handler = InfluxDBClient(host="localhost", database="e2e_testing")

    @setup_env
    def test_thresholds_keepalive(self) -> None:
        """ Test flow keepalives
            Sends 50 packets, one packet every 500ms. Default keepalive is 3. We are supposed to see
            At the end, we are supposed to see 9 entries on influx. All with value
              980327060 - 980325604 = 1456
        """

        for _ in range(0, 50):
            p = generate_packet()
            send_packet(p)
            time.sleep(0.5)

        time.sleep(1.5)
        assert len(self.db_handler.get_list_measurements()) == 5

        r = self.db_handler.query("select count(*) "
                                  "from \"latency,vlan=42,sw=4217755253,port=11,hop=4217755253\" "
                                  "where value=1456")
        point = next(r.get_points())
        assert point["count_value"] == 9

        r = self.db_handler.query("select count(*) "
                                  "from \"queue_occ,sw=4217755253,port=11,queue=2\" "
                                  "where value=111")
        point = next(r.get_points())
        assert point["count_value"] == 9

    @setup_env
    def test_queue_occupancy_variation(self) -> None:
        """ Test if the queue_occ config is being followed. Default is 255 cells or 18,000 bytes
            Send INT reports with the following queue occupancy for queue 1

        # 10, first, saves
        # 300 saves (10 + 255 = 265)
        # 600 saves
        # 100 saves
        # 1000, 2000 saves
        # 10000 saves
        # 10 saves

        # 2000, 1500 saves  # Saves 10 measurements"""

        values = [10, 100, 300, 300, 600, 700, 400, 100, 1000, 2000, 2100, 2000, 1900, 10000, 10100, 10, 100, 2000, 1500]

        for key, queue_occ in enumerate(values):
            metadata = generate_metadata(queue_id=1, queue_occ=queue_occ)
            p = generate_packet(metadata=metadata)
            send_packet(p)

        time.sleep(1)
        assert len(self.db_handler.get_list_measurements()) == 5

        r = self.db_handler.query("select count(*) "
                                  "from \"queue_occ,sw=4217755253,port=11,queue=1\"")
        point = next(r.get_points())
        assert point["count_value"] == 10

    @setup_env
    def test_multiple_ten_metadata(self) -> None:
        """ Test if the controller can support 10 metadata """

        def gen_pcks(queue_id=5):
            for _ in range(0, 10):
                sw_ids = [1, 10, 20, 30, 40, 50, 60, 70, 80, 90]
                metadatas = list()
                for sw_id in sw_ids:
                    metadatas.append(generate_metadata(switch_id=sw_id,
                                                       egress_id=sw_id,
                                                       queue_id=queue_id,
                                                       queue_occ=16777215))
                # (Shim header = 4 + INT Md Header 8 + Metadata 24 * number switches 10) / 4
                shim_len = int((12 + (len(metadatas) * 24)) / 4)
                p = generate_packet(int_shim_len=shim_len, int_md_hdr_rhc=0, metadata=metadatas)
                # print(p.show())
                send_packet(p)

        # First round
        gen_pcks()

        time.sleep(2)
        # print(len(self.db_handler.get_list_measurements()))
        assert len(self.db_handler.get_list_measurements()) == 23

        r = self.db_handler.query("select count(*) from \"flow_lat_path,vlan_id=42,sw_id=1,port=1\"")
        point = next(r.get_points())
        assert point["count_path"] == 1

        r = self.db_handler.query("select * from \"flow_lat_path,vlan_id=42,sw_id=1,port=1\"")
        point = next(r.get_points())
        p = '23-90-90.5,23-80-80.5,23-70-70.5,23-60-60.5,23-50-50.5,23-40-40.5,23-30-30.5,23-20-20.5,23-10-10.5,' \
            '23-1-1.5'
        assert point["path"] == p

        # Second round
        gen_pcks(queue_id=6)

        time.sleep(2)
        assert len(self.db_handler.get_list_measurements()) == 33  # Adds latency measurement and queue_id = 6

        r = self.db_handler.query("select count(*) from \"flow_lat_path,vlan_id=42,sw_id=1,port=1\"")
        point = next(r.get_points())
        assert point["count_path"] == 2

        r = self.db_handler.query("select * from \"flow_lat_path,vlan_id=42,sw_id=1,port=1\" "
                                  "GROUP BY * ORDER BY DESC LIMIT 1")
        point = next(r.get_points())  # second entry

        p = '23-90-90.6,23-80-80.6,23-70-70.6,23-60-60.6,23-50-50.6,23-40-40.6,23-30-30.6,23-20-20.6,23-10-10.6,' \
            '23-1-1.6'
        assert point["path"] == p

    @setup_env
    def test_lost_int_report(self) -> None:
        """ Test if the controller can support 10 metadata """

        def gen_pcks(tm_rp_seq):
            p = generate_packet(tm_rp_seq=tm_rp_seq)
            # print(p.show())
            send_packet(p)

        # First round
        gen_pcks(tm_rp_seq=1)
        gen_pcks(tm_rp_seq=2)
        gen_pcks(tm_rp_seq=4)
        gen_pcks(tm_rp_seq=6)
        gen_pcks(tm_rp_seq=9)
        gen_pcks(tm_rp_seq=11)
        gen_pcks(tm_rp_seq=12)
        gen_pcks(tm_rp_seq=15)

        time.sleep(2)

        int_report_type_4 = False
        for measurement in self.db_handler.get_list_measurements():
            if measurement['name'] == "int_reports,type=4":
                int_report_type_4 = True

        assert int_report_type_4 is True

        r = self.db_handler.query("select * from \"int_reports,type=4\""
                                  "GROUP BY * ORDER BY DESC LIMIT 1")
        point = next(r.get_points())
        assert point["value"] == 7

        # Second round
        gen_pcks(tm_rp_seq=16)
        gen_pcks(tm_rp_seq=20)
        gen_pcks(tm_rp_seq=22)

        time.sleep(2)

        r = self.db_handler.query("select * from \"int_reports,type=4\""
                                  "GROUP BY * ORDER BY DESC LIMIT 1")
        point = next(r.get_points())
        assert point["value"] == 11


if __name__ == "__main__":
    a = TestE2E()
    a.setUp()
    a.test_queue_occupancy_variation()
    # a.test_multiple_ten_metadata()
    # a.test_lost_int_report()
