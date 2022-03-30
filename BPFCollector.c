/*
 * This file is part of the INT Collector distribution (https://github.com/amlight/int_collector).
 *  Copyright (c) [2018] [Nguyen Van Tu],
 *  Copyright (c) [2022] [AmLight SDN Team]
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#define KBUILD_MODNAME "int_collector"
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#define MAX_INT_HOP 10  // Noviflow only supports reports with 10 metadata

// User Variables
#define INT_DST_PORT _INT_DST_PORT
#define HOP_LATENCY _HOP_LATENCY
#define FLOW_LATENCY _FLOW_LATENCY
#define QUEUE_OCCUP _QUEUE_OCCUP
#define TIME_GAP_W _TIME_GAP_W
#define ENABLE_COUNTER_MODE _ENABLE_COUNTER_MODE
#define ENABLE_THRESHOLD_MODE _ENABLE_THRESHOLD_MODE

// __packet__ numbers
#define ETHTYPE_IP 0x0800
#define ETHTYPE_VLAN 33024

// __packed__ size
#define ETH_SIZE 14
#define VLAN_SIZE 2
#define TCPHDR_SIZE 20
#define UDPHDR_SIZE 8
#define INT_SHIM_SIZE 4

#define CURSOR_ADVANCE(_target, _cursor, _len,_data_end) \
    ({  _target = _cursor; _cursor += _len; \
        if(unlikely(_cursor > _data_end)) return XDP_DROP; })

#define CURSOR_ADVANCE_NO_PARSE(_cursor, _len, _data_end) \
    ({  _cursor += _len; \
        if(unlikely(_cursor > _data_end)) return XDP_DROP; })

#define ABS(a, b) ((a>b)? (a-b):(b-a))


//--------------------------------------------------------------------

// Protocols

/* Ethernet frame */
struct eth_tp {
    u64 dst:48;
    u64 src:48;
    u16 type;
} __attribute__((packed));

/* VLAN Ethertype */
struct vlan_tp {
    u16 vid;
    u16 type;
} __attribute__((packed));

/* INT Telemetry report */
struct telemetry_report_v10_t {
#if defined(__BIG_ENDIAN_BITFIELD)
    u8  ver:4,
        len:4;
    u16 nProto:3,
        repMdBits:6,
        reserved:6,
        d:1;
    u8  q:1,
        f:1,
        hw_id:6;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    u8  len:4,
        ver:4;
    u16 d:1,
        reserved:6,
        repMdBits:6,
        nProto:3;
    u8  hw_id:6,
        f:1,
        q:1;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
    u32 sw_id;
    u32 seqNumber;
    u32 ingressTimestamp;
} __attribute__((packed));

/* INT shim */
struct INT_shim_v10_t {
    u8 type;
    u8 rsvd_1;
    u8 length;
#if defined(__BIG_ENDIAN_BITFIELD)
    u8  DSCP:6,
        rsvd_2:2;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    u8  rsvd_2:2,
        DSCP:6;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
} __attribute__((packed));

/* INT metadata header */
struct INT_md_hdr_v10_t {
#if defined(__BIG_ENDIAN_BITFIELD)
    u8  ver:4,
        rep:2,
        c:1,
        e:1;
    u8  m:1,
        rsvd_1:7;
    u8  rsvd_2:3,
        hopMlen:5,
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    u8  e:1,
        c:1,
        rep:2,
        ver:4;
    u8  rsvd_1:7,
        m:1;
    u8  hopMlen:5,
        rsvd_2:3;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
    u8  remainHopCnt;
    u16 ins;
    u16 rsvd2;
} __attribute__((packed));

// Data

/* Identifying a flow at AmLight (L2VPN) */
struct flow_id_t {
    u16 vlan_id;
    u32 last_sw_id;
    u16 last_egr_id;
};

/* Identifying a network interface's queue */
struct queue_id_t {
    u32 sw_id;
    u16 p_id;
    u16 q_id;
};

/* Queue Occupancy */
struct queue_info_t {
    u16 occup;
    u64 q_time;
//    u32 q_time;
};

/* Identifying a network interface & VLAN */
struct egress_eg_q_vlan_id_t {
    u32 sw_id;  // Switch ID
    u16 p_id;  // Egress Port ID
    u16 q_id;  // Egress Queue ID
    u16 v_id;  // VLAN ID
};

/* Identifying a network interface  */
struct egress_queue_util_id_t {
    u32 sw_id;  // Switch ID
    u16 p_id;  // Egress Port ID
    u16 q_id;  // Egress Queue ID
};

/* Identifying a network interface  */
struct egress_util_id_t {
    u32 sw_id;  // Switch ID
    u16 p_id;  // Egress Port ID
};

/* Egress Interface utilization */
struct egr_tx_info_t {
    u64 octets;
    u64 packets;
};

// Events
struct flow_info_t {
    u32 seqNumber;
    u16 vlan_id;
    u8 num_INT_hop;
    u32 sw_ids[MAX_INT_HOP];
    u16 in_port_ids[MAX_INT_HOP];
    u16 e_port_ids[MAX_INT_HOP];
    u32 hop_latencies[MAX_INT_HOP];
    u16 queue_ids[MAX_INT_HOP];
    u32 queue_occups[MAX_INT_HOP];
    u32 ingr_times[MAX_INT_HOP];
    u32 egr_times[MAX_INT_HOP];
    u32 flow_latency;
    u64 flow_sink_time;  // sink timestamp provided
    u8 is_n_flow;  // is new flow?
    u8 is_flow;
    u16 is_hop_latency;
    u16 is_queue_occup;
};

BPF_PERF_OUTPUT(events);

// Maps
BPF_TABLE("lru_hash", struct flow_id_t, struct flow_info_t, tb_flow, 10000);
BPF_TABLE("lru_hash", struct queue_id_t, struct queue_info_t, tb_queue, 3200);
BPF_TABLE("lru_hash", struct egress_eg_q_vlan_id_t, struct egr_tx_info_t, tb_egr_vlan_util, 5120);
BPF_TABLE("lru_hash", struct egress_queue_util_id_t, struct egr_tx_info_t, tb_egr_queue_util, 520);
BPF_TABLE("lru_hash", struct egress_util_id_t, struct egr_tx_info_t, tb_egr_interface_util, 400);

BPF_HISTOGRAM(counter_all, u64);
BPF_HISTOGRAM(counter_int, u64);
BPF_HISTOGRAM(counter_error, u64);

//--------------------------------------------------------------------

int collector(struct xdp_md *ctx) {

    /* Timestamp when packet was received */
    u64 current_time_ns = bpf_ktime_get_ns();

    // Counter
    u64 value = 0;  // Packets received == 0
    counter_all.increment(value);

    void* data_end = (void*)(long)ctx->data_end;
    void* cursor = (void*)(long)ctx->data;

    /*
        Parse outer: Ether->[VLAN]->IP->UDP->TelemetryReport.
    */

    struct eth_tp *eth;
    CURSOR_ADVANCE(eth, cursor, sizeof(*eth), data_end);
    if (unlikely(ntohs(eth->type) != ETHTYPE_IP))
        goto PASS;

    // Consider a VLAN (8021q)
    struct vlan_tp *vlan;
    if (unlikely(ntohs(eth->type) == ETHTYPE_VLAN))
        CURSOR_ADVANCE_NO_PARSE(cursor, sizeof(*vlan), data_end);

    struct iphdr *ip;
    CURSOR_ADVANCE(ip, cursor, sizeof(*ip), data_end);
    if (unlikely(ip->protocol != IPPROTO_UDP))
        goto PASS;

    struct udphdr *udp;
    CURSOR_ADVANCE(udp, cursor, sizeof(*udp), data_end);
    if (unlikely(ntohs(udp->dest) != INT_DST_PORT))
        goto PASS;

    struct telemetry_report_v10_t *tm_rp;
    CURSOR_ADVANCE(tm_rp, cursor, sizeof(*tm_rp), data_end);

    /*
        Parse Inner: Ether->Vlan->[Vlan]->IP->UDP/TCP->INT.
        we only consider Telemetry report with INT
    */

    CURSOR_ADVANCE_NO_PARSE(cursor, ETH_SIZE, data_end);
    CURSOR_ADVANCE(vlan, cursor, sizeof(*vlan), data_end);

    // Consider an extra VLAN (QinQ)
    if (unlikely(ntohs(vlan->type) == ETHTYPE_VLAN))
        CURSOR_ADVANCE_NO_PARSE(cursor, sizeof(*vlan), data_end);

    struct iphdr *in_ip;
    CURSOR_ADVANCE(in_ip, cursor, sizeof(*in_ip), data_end);

    // NoviFlow adds INT between TCP and TCP Options
    u8 remain_size = (in_ip->protocol == IPPROTO_UDP)?
                      (UDPHDR_SIZE):(TCPHDR_SIZE);
    CURSOR_ADVANCE_NO_PARSE(cursor, remain_size, data_end);

    struct INT_shim_v10_t *INT_shim;
    CURSOR_ADVANCE(INT_shim, cursor, sizeof(*INT_shim), data_end);
    // Validation against damaged reports
    if (INT_shim->type != 1)   goto ERROR;
    if (INT_shim->rsvd_1 != 0) goto ERROR;
    if (INT_shim->length == 0) goto ERROR;
    if (INT_shim->rsvd_2 != 0) goto ERROR;

    struct INT_md_hdr_v10_t *INT_md_fix;
    CURSOR_ADVANCE(INT_md_fix, cursor, sizeof(*INT_md_fix), data_end);
    // Validation against damaged reports
    if (INT_md_fix->ver != 1)          goto ERROR;
    if (INT_md_fix->rep != 0)          goto ERROR;
    if (INT_md_fix->c != 0)            goto ERROR;
    if (INT_md_fix->hopMlen != 6)      goto ERROR;
    if (INT_md_fix->remainHopCnt > 10) goto ERROR;

    /* ****************  Parse INT data **************** */

    u8 num_INT_hop = ABS(MAX_INT_HOP, INT_md_fix->remainHopCnt);

    struct flow_info_t flow_info = {
        .seqNumber = ntohl(tm_rp->seqNumber),
        .vlan_id = ntohs(vlan->vid) & 0x0fff,
        .num_INT_hop = num_INT_hop,
        .flow_sink_time = current_time_ns
    };

    u16 INT_ins = ntohs(INT_md_fix->ins);
    // Validation against damaged reports
    if ((INT_ins >> 15) & 0x01 != 1) goto ERROR;
    if ((INT_ins >> 14) & 0x01 != 1) goto ERROR;
    if ((INT_ins >> 13) & 0x01 != 1) goto ERROR;
    if ((INT_ins >> 12) & 0x01 != 1) goto ERROR;
    if ((INT_ins >> 11) & 0x01 != 1) goto ERROR;
    if ((INT_ins >> 10) & 0x01 != 1) goto ERROR;
    /* NoviFlow doesn't support other instructions */

    u8 is_in_e_port_ids  = (INT_ins >> 14) & 0x1;
    u8 is_ingr_times 	 = (INT_ins >> 11) & 0x1;
    u8 is_egr_times 	 = (INT_ins >> 10) & 0x1;

    u32* INT_data;

    u8 _num_INT_hop = num_INT_hop;
    #pragma unroll
    for (u8 i = 0; i < MAX_INT_HOP; i++) {
        CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
        flow_info.sw_ids[i] = ntohl(*INT_data);

        CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
        flow_info.in_port_ids[i] = (ntohl(*INT_data) >> 16) & 0xffff;
        flow_info.e_port_ids[i] = ntohl(*INT_data) & 0xffff;

        /* NoviFlow doesn't support it but adds the field for compatibility */
        CURSOR_ADVANCE_NO_PARSE(cursor, sizeof(*INT_data), data_end);

        CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
        flow_info.queue_ids[i] = (ntohl(*INT_data) >> 8) & 0xff;
        flow_info.queue_occups[i] = ntohl(*INT_data) & 0xffffff;
        // Validation against damaged reports
        if ((ntohl(*INT_data) >> 8) & 0xff > 7) goto ERROR;

        CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
        flow_info.ingr_times[i] = ntohl(*INT_data);

        CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
        flow_info.egr_times[i] = ntohl(*INT_data);

        /* NoviFlow doesn't support hop_latency. Let's calculate it from timestamps */
        if (flow_info.egr_times[i] > flow_info.ingr_times[i]){
            flow_info.hop_latencies[i] = flow_info.egr_times[i] - flow_info.ingr_times[i];
            flow_info.flow_latency += flow_info.hop_latencies[i];
        }
        else{
            // Validation against damaged reports: Reports can't be negative.
            goto ERROR;
        }

        if (i < MAX_INT_HOP - 1) {
            _num_INT_hop--;
            if (_num_INT_hop <= 0)
                break;
        }

    }

    /*************** flow data structure  ***************/
    struct flow_id_t flow_id = {};

    flow_id.vlan_id = flow_info.vlan_id;
    flow_id.last_sw_id = flow_info.sw_ids[0];
    flow_id.last_egr_id = flow_info.e_port_ids[0];

    /***************  Path store and change-detection  ***************/
    u8 is_update = 0;

#if ENABLE_THRESHOLD_MODE == 1

    struct flow_info_t *flow_info_p = tb_flow.lookup(&flow_id);
    if (unlikely(!flow_info_p)) {

        flow_info.is_n_flow = 1;
        is_update = 1;

        switch (num_INT_hop) {
            case 1: flow_info.is_hop_latency = 0x01; break;
            case 2: flow_info.is_hop_latency = 0x03; break;
            case 3: flow_info.is_hop_latency = 0x07; break;
            case 4: flow_info.is_hop_latency = 0x0f; break;
            case 5: flow_info.is_hop_latency = 0x1f; break;
            case 6: flow_info.is_hop_latency = 0x3f; break;
            case 7: flow_info.is_hop_latency = 0x7f; break;
            case 8: flow_info.is_hop_latency = 0xff; break;
             // FIX01: MAX 8 for now
            // case 9: flow_info.is_hop_latency = 0x1ff; break;
            // case 10: flow_info.is_hop_latency = 0x3ff; break;
            default: break;
        }


    } else {

        // If flow latency changed over the threshold, record it.
        if (ABS(flow_info.flow_latency, flow_info_p->flow_latency) > FLOW_LATENCY){
            flow_info.is_flow = 1;
            is_update = 1;
        }

        // From here is hop delay, not flow latency.
        _num_INT_hop = num_INT_hop;
        #pragma unroll
        for (u8 i = 0; i < MAX_INT_HOP; i++) {

            // Check if path changed
            if (unlikely(flow_info.sw_ids[i] != flow_info_p->sw_ids[i])) {
                is_update = 1;
                flow_info.is_flow = 1;
                flow_info.is_hop_latency |= 1 << i;
            }

            // If hop latency changed over the threshold, record it.
            if (unlikely(ABS(flow_info.hop_latencies[i], flow_info_p->hop_latencies[i]) > HOP_LATENCY)) {
                is_update = 1;
                flow_info.is_hop_latency |= 1 << i;
            }

            // Interval between the current and last packet is more than TIME_GAP_W
            // even if it doesn't reach the thresholds (keepalive)
            if (unlikely(!is_update) & (flow_info_p->flow_sink_time + TIME_GAP_W < flow_info.flow_sink_time)){
                is_update = 1;
                flow_info.is_hop_latency |= 1 << i;
                flow_info.is_flow = 1;
            }

            if (i < MAX_INT_HOP - 1) {
                _num_INT_hop--;
                if (_num_INT_hop <= 0)
                    break;
            }

        }
    }

    if (is_update)
        tb_flow.update(&flow_id, &flow_info);

    /*****************  Queue info  *****************/

    struct queue_info_t *queue_info_p;
    struct queue_id_t queue_id = {};
    struct queue_info_t queue_info = {};

    _num_INT_hop = num_INT_hop;
    #pragma unroll
    for (u8 i = 0; i < MAX_INT_HOP; i++) {

        queue_id.sw_id = flow_info.sw_ids[i];
        queue_id.p_id = flow_info.e_port_ids[i];
        queue_id.q_id = flow_info.queue_ids[i];

        queue_info.occup = flow_info.queue_occups[i];
        queue_info.q_time = flow_info.flow_sink_time;

        is_update = 0;

        queue_info_p = tb_queue.lookup(&queue_id);
        if(unlikely(!queue_info_p)) {
            flow_info.is_queue_occup |= 1 << i;
            is_update = 1;
        } else {

            // Threshold for queue occupancy
            if (unlikely(ABS(queue_info.occup, queue_info_p->occup) > QUEUE_OCCUP)) {
                flow_info.is_queue_occup |= 1 << i;
                is_update = 1;
            }

            // Flow keepalive if threshold is not reached
            if (unlikely((!is_update) & (queue_info_p->q_time + TIME_GAP_W < flow_info.flow_sink_time))){
                flow_info.is_queue_occup |= 1 << i;
                is_update = 1;
            }
        }

        if (is_update)
            tb_queue.update(&queue_id, &queue_info);

        if (i < MAX_INT_HOP - 1) {
            _num_INT_hop--;
            if (_num_INT_hop <= 0)
                break;
        }
    }

#endif

    /*****************  Egress info and flow bandwidth *****************/

#if ENABLE_COUNTER_MODE == 1

    struct egr_tx_info_t *egr_info_p_v;
    struct egr_tx_info_t *egr_info_p_q;
    struct egr_tx_info_t *egr_info_p_i;
    struct egr_tx_info_t egr_info_v;
    struct egr_tx_info_t egr_info_q;
    struct egr_tx_info_t egr_info_i;
    struct egress_eg_q_vlan_id_t egr_id = {};
    struct egress_queue_util_id_t egr_q_id = {};
    struct egress_util_id_t egr_int_id = {};
    u64 packet_len = 18 + ntohs(in_ip->tot_len);

    _num_INT_hop = num_INT_hop;
    #pragma unroll
    for (u8 i = 0; i < MAX_INT_HOP; i++) {

        // Full details: interface + queue + vlan
        egr_id.sw_id  = flow_info.sw_ids[i];
        egr_id.p_id = flow_info.e_port_ids[i];
        egr_id.q_id = flow_info.queue_ids[i];
        egr_id.v_id = flow_info.vlan_id;

        egr_info_p_v = tb_egr_vlan_util.lookup(&egr_id);
        if(unlikely(!egr_info_p_v)) {
            egr_info_v.octets = 0;
            egr_info_v.packets = 0;
        }
        else {
            egr_info_v.octets = packet_len + egr_info_p_v->octets;
            egr_info_v.packets = 1 + egr_info_p_v->packets;
        }
        tb_egr_vlan_util.update(&egr_id, &egr_info_v);

        // interface + queue details
        egr_q_id.sw_id  = flow_info.sw_ids[i];
        egr_q_id.p_id = flow_info.e_port_ids[i];
        egr_q_id.q_id = flow_info.queue_ids[i];

        egr_info_p_q = tb_egr_queue_util.lookup(&egr_q_id);
        if(unlikely(!egr_info_p_q)) {
            egr_info_q.octets = 0;
            egr_info_q.packets = 0;
        }
        else {
            egr_info_q.octets = packet_len + egr_info_p_q->octets;
            egr_info_q.packets = 1 + egr_info_p_q->packets;
        }
        tb_egr_queue_util.update(&egr_q_id, &egr_info_q);

        // interface details
        egr_int_id.sw_id  = flow_info.sw_ids[i];
        egr_int_id.p_id = flow_info.e_port_ids[i];

        egr_info_p_i = tb_egr_interface_util.lookup(&egr_int_id);
        if(unlikely(!egr_info_p_i)) {
            egr_info_i.octets = 0;
            egr_info_i.packets = 0;
        }
        else {
            egr_info_i.octets = packet_len + egr_info_p_i->octets;
            egr_info_i.packets = 1 + egr_info_p_i->packets;
        }
        tb_egr_interface_util.update(&egr_int_id, &egr_info_i);

        if (i < MAX_INT_HOP - 1) {
            _num_INT_hop--;
            if (_num_INT_hop <= 0)
                break;
        }
    }

#endif

    // submit event info to user space
    if (unlikely(flow_info.is_n_flow |
                 flow_info.is_hop_latency |
                 flow_info.is_queue_occup |
                 flow_info.is_flow)){
        events.perf_submit(ctx, &flow_info, sizeof(flow_info));
        value = 2;
        counter_int.increment(value);
    }

DROP:
    return XDP_DROP;

PASS:
    return XDP_PASS;

ERROR:
    value = 3;
    counter_error.increment(value);
    return XDP_DROP;
}
