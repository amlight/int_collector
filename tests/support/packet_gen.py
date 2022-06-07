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
""" This module is used to generate the telemetry report packets """


from scapy.all import Packet, Ether, IP, UDP
from scapy.all import Dot1Q, sendp
from int_specs import TelemetryReport, IntShim, IntMetadataHeader, IntMetadata


def generate_metadata(switch_id: int = 0xFB65D675,
                      ingress_id: int = 23, egress_id: int = 11,
                      queue_id: int = 2, queue_occ: int = 111,
                      ingress_ts: int = 980325604, egress_ts: int = 980327060) -> IntMetadata:
    """ Generate IntMetadata """
    return IntMetadata(
            switch_id=switch_id,
            ingress_id=ingress_id,
            egress_id=egress_id,
            queue_id=queue_id,
            queue_occ=queue_occ,
            ingress_ts=ingress_ts,
            egress_ts=egress_ts
    )


def generate_packet(mac_dst: str = "00:90:fb:65:d6:75", mac_src: str = "00:0e:1e:d7:0d:a3",
                    out_ip_src: str = "10.0.0.2", out_ip_dst: str = "10.0.0.1",
                    out_udp_src: int = 6000, out_udp_dst: int = 5900,
                    tm_rp_swid: int = 4217755253, tm_rp_seq: int = 1408972298, tm_rp_ts: int = 980327565,
                    vlan_vid: int = 42,
                    in_ip_src: str = "9.9.9.9", in_ip_dst: str = "8.8.8.8",
                    in_udp_src: int = 50000, in_udp_dst: int = 50001,
                    int_shim_len: int = 9, int_shim_dscp: int = 0x02,
                    int_md_hdr_rhc: int = 9,
                    metadata: list = None
                    ) -> Packet:
    """ Creates a packet using Scapy """

    if metadata is None:
        metadata = [generate_metadata()]

    p = Ether(dst=mac_dst, src=mac_src) / \
        IP(src=out_ip_src, dst=out_ip_dst) / \
        UDP(sport=out_udp_src, dport=out_udp_dst) / \
        TelemetryReport(
            swid=tm_rp_swid,
            seqNumber=tm_rp_seq,
            ingress_ts=tm_rp_ts) / \
        Ether() / \
        Dot1Q(vlan=vlan_vid) / \
        IP(src=in_ip_src, dst=in_ip_dst, tos=0x17 << 2) / \
        UDP(sport=in_udp_src, dport=in_udp_dst) / \
        IntShim(length=int_shim_len, dscp=int_shim_dscp) / \
        IntMetadataHeader(remainHopCnt=int_md_hdr_rhc)

    if metadata is None:
        p = p / generate_metadata()
    elif isinstance(metadata, IntMetadata):
        p = p / metadata
    elif isinstance(metadata, list):
        for md in metadata:
            if not isinstance(md, IntMetadata):
                raise TypeError("Metadata has the wrong type")
            p = p / md

    return p


def send_packet(packet: Packet, interface: str = "veth_0", verbose: int = 0):
    """ Send packet using Scapy sendp """
    sendp(packet, iface=interface, verbose=verbose)
