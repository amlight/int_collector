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


from scapy.all import Packet, BitField, IntField, XByteField, XShortField


class TelemetryReport(Packet):
    name = "INT telemetry report"

    # default value a for telemetry report with INT
    fields_desc = [
        BitField("ver", 1, 4),
        BitField("len", 4, 4),
        BitField("nProto", 0, 3),
        BitField("repMdBits", 0, 6),
        BitField("reserved", 0, 6),
        BitField("d", 0, 1),
        BitField("q", 0, 1),
        BitField("f", 0, 1),
        BitField("hw_id", None, 6),
        IntField("swid", None),
        IntField("seqNumber", None),
        IntField("ingress_ts", None)]


class IntShim(Packet):
    name = "INT Shim"

    fields_desc = [
        XByteField("type", 1),
        XByteField("shimRsvd1", 0),
        XByteField("length", None),
        BitField("dscp", 0, 6),
        BitField("shimRsvd2", 0, 2)
    ]


class IntMetadataHeader(Packet):
    name = "INT Metadata Header"

    fields_desc = [
        BitField("ver", 1, 4),
        BitField("rep", 0, 2),
        BitField("c", 0, 1),
        BitField("e", 0, 1),
        BitField("m", 0, 1),
        BitField("rsvd1", 0, 7),
        BitField("rsvd2", 0, 3),
        BitField("hopMLen", 6, 5),
        XByteField("remainHopCnt", None),
        XShortField("ins", 64512),
        XShortField("res", 0)
    ]


class IntMetadata(Packet):
    name = "INT Metadata"

    fields_desc = [
        IntField("switch_id", None),
        XShortField("ingress_id", None),
        XShortField("egress_id", None),
        IntField("hop_latency", 4294967295),
        BitField("queue_id", 2, 8),
        BitField("queue_occ", 0, 24),
        IntField("ingress_ts", None),
        IntField("egress_ts", None)
    ]