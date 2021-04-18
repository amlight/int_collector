#define KBUILD_MODNAME "xdp_collector"
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>  // <-- if removed, UDP errors. Find out why

// User Variables
#define INT_DST_PORT _INT_DST_PORT
#define MAX_INT_HOP _MAX_INT_HOP
#define HOP_LATENCY _HOP_LATENCY
#define FLOW_LATENCY _FLOW_LATENCY
#define QUEUE_OCCUP _QUEUE_OCCUP
#define TIME_GAP_W _TIME_GAP_W

#define MAX_INT_HOP_NOVIFLOW 10

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
    u8 shimRsvd1;
    u8 length;
#if defined(__BIG_ENDIAN_BITFIELD)
    u8  DSCP:6,
        r:2;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    u8  r:2,
        DSCP:6;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
} __attribute__((packed));

/* INT metadata header */
struct INT_md_fix_v10_t {
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
    u32 q_time;
};

/* Identifying a network interface */
struct egr_tx_id_t {
    u32 sw_id;  // Switch ID
    u16 p_id;  // Egress Port ID
    u16 q_id;  // Egress Queue ID
};

/* Egress Interface utilization */
struct egr_tx_info_t {
    u64 octets;
    u64 packets;
};

// Events

// TODO: flow ID is just vlan_id. Extend it to be <last_sw, eg_id, vlan>
// TODO: Change to u16 is_hop_latency:12 since we plan to use 10 switches (12 bits)
struct flow_info_t {
    u32 seqNumber;
    u16 vlan_id;
    u8 num_INT_hop;
    u8 hop_negative; // In case there is an error

    u32 sw_ids[MAX_INT_HOP];
    u16 in_port_ids[MAX_INT_HOP];
    u16 e_port_ids[MAX_INT_HOP];
    u32 hop_latencies[MAX_INT_HOP];
    u16 queue_ids[MAX_INT_HOP];
    u16 queue_occups[MAX_INT_HOP];
    u32 ingr_times[MAX_INT_HOP];
    u32 egr_times[MAX_INT_HOP];
    u32 flow_latency;
    u64 flow_sink_time;  // sink timestamp provided
    u8 is_n_flow;  // is new flow?
    u8 is_flow;
    u8 is_hop_latency;
    u8 is_queue_occup;
};

BPF_PERF_OUTPUT(events);

BPF_TABLE("lru_hash", struct flow_id_t, struct flow_info_t, tb_flow, 1000);
BPF_TABLE("lru_hash", struct queue_id_t, struct queue_info_t, tb_queue, 3200);
BPF_TABLE("lru_hash", struct egr_tx_id_t, struct egr_tx_info_t, tb_egr_util, 5120);

BPF_HISTOGRAM(counter_all, u64);
BPF_HISTOGRAM(counter_int, u64);

//--------------------------------------------------------------------

int collector(struct xdp_md *ctx) {

    // Counter
    u64 value = 0;  // Packets received == 0
    counter_all.increment(value);

    /* Timestamp when packet was received */
    u64 current_time_ns = bpf_ktime_get_ns();

    void* data_end = (void*)(long)ctx->data_end;
    void* cursor = (void*)(long)ctx->data;

    /*
        Parse outer: Ether->IP->UDP->TelemetryReport.
        TODO: add VLAN
    */

    struct eth_tp *eth;
    CURSOR_ADVANCE(eth, cursor, sizeof(*eth), data_end);
    if (unlikely(ntohs(eth->type) != ETHTYPE_IP))
        goto PASS;

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
        Parse Inner: Ether->Vlan->IP->UDP/TCP->INT.
        we only consider Telemetry report with INT
    */

    CURSOR_ADVANCE_NO_PARSE(cursor, ETH_SIZE, data_end);

    struct vlan_tp *vlan;
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

    struct INT_md_fix_v10_t *INT_md_fix;
    CURSOR_ADVANCE(INT_md_fix, cursor, sizeof(*INT_md_fix), data_end);

    if (unlikely(INT_shim->length != 9))
        // TODO: Identify which packets have length > 9 since there is only one switch
        goto PASS;

    /*****************  Parse INT data ***************** /

    /* TODO: Get the max_int_hop from the telemetry report */
    // u8 num_INT_hop = MAX_INT_HOP_NOVIFLOW - htons(INT_md_fix->remainHopCnt);
    u8 num_INT_hop = MAX_INT_HOP_NOVIFLOW - 9;

    struct flow_info_t flow_info = {
        .seqNumber = ntohl(tm_rp->seqNumber),
        .vlan_id = ntohs(vlan->vid) & 0x0fff,
        .num_INT_hop = INT_md_fix->remainHopCnt,
        // .num_INT_hop = INT_shim->length, // debug
        .flow_sink_time = current_time_ns
    };

    u16 INT_ins = ntohs(INT_md_fix->ins);
    // Assume that sw_id is always presented.
    if ((INT_ins >> 15) & 0x01 != 1) return XDP_DROP;

    u8 is_in_e_port_ids  = (INT_ins >> 14) & 0x1;
    u8 is_hop_latencies  = (INT_ins >> 13) & 0x1;
    u8 is_queue_occups 	 = (INT_ins >> 12) & 0x1;
    u8 is_ingr_times 	 = (INT_ins >> 11) & 0x1;
    u8 is_egr_times 	 = (INT_ins >> 10) & 0x1;
    /* NoviFlow doesn't support other instructions */

    u32* INT_data;

    #pragma unroll
    for (u8 i = 0; i < num_INT_hop; i++) {
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
            flow_info.hop_negative = 1;
            flow_info.hop_latencies[i] = 400;
        }

    }

    /***************  Path store and change-detection  ***************/

    u8 is_update = 0;

    struct flow_id_t flow_id = {};

    flow_id.vlan_id = flow_info.vlan_id;
    flow_id.last_sw_id = flow_info.sw_ids[0];  // Last switch
    flow_id.last_egr_id = flow_info.e_port_ids[0];

    struct flow_info_t *flow_info_p = tb_flow.lookup(&flow_id);
    if (unlikely(!flow_info_p)) {

        flow_info.is_n_flow = 1;
        is_update = 1;

        if (is_hop_latencies) {
            switch (num_INT_hop) {
                case 1: flow_info.is_hop_latency = 0x01; break;
                case 2: flow_info.is_hop_latency = 0x03; break;
                case 3: flow_info.is_hop_latency = 0x07; break;
                case 4: flow_info.is_hop_latency = 0x0f; break;
                case 5: flow_info.is_hop_latency = 0x1f; break;
                case 6: flow_info.is_hop_latency = 0x3f; break;
                // FIX01: MAX 6 for now
                // case 7: flow_info.is_hop_latency = 0x7f; break;
                // case 8: flow_info.is_hop_latency = 0xff; break;
                // case 9: flow_info.is_hop_latency = 0x1ff; break;
                // case 10: flow_info.is_hop_latency = 0x3ff; break;
                default: break;
            }
        }

    } else {

        // only need periodically push for flow info, so we can know the live status of the flow
        // the current timestamp is only 32 bits. Only supports 4 seconds.
        // If there is no alarm, just one record per second should suffice as keepalive.
        // The issue is that flow_sink_time will zero too fast.

        if ((flow_info_p->flow_sink_time + TIME_GAP_W < flow_info.flow_sink_time)
            | (is_hop_latencies & (ABS(flow_info.flow_latency, flow_info_p->flow_latency) > FLOW_LATENCY))
            ) {

            flow_info.is_flow = 1;
            is_update = 1;
        }

        #pragma unroll
        for (u8 i = 0; i < num_INT_hop; i++) {

            if (unlikely(flow_info.sw_ids[i] != flow_info_p->sw_ids[i])) {
                is_update = 1;

                flow_info.is_flow = 1;

                if (is_hop_latencies) {
                    flow_info.is_hop_latency |= 1 << i;
                }
            }

            if (unlikely(is_hop_latencies &
                (ABS(flow_info.hop_latencies[i], flow_info_p->hop_latencies[i]) > HOP_LATENCY))) {

                flow_info.is_hop_latency |= 1 << i;
                is_update = 1;
            }

        }
    }

    if (is_update)
        tb_flow.update(&flow_id, &flow_info);


    /*****************  Egress info and flow bandwidth *****************/

    struct egr_tx_info_t *egr_info_p;
    struct egr_tx_info_t egr_info;
    struct egr_tx_id_t egr_id = {};

    #pragma unroll
    for (u8 i = 0; i < num_INT_hop; i++) {

        egr_id.sw_id  = flow_info.sw_ids[i];
        egr_id.p_id = flow_info.e_port_ids[i];
        egr_id.q_id = flow_info.queue_ids[i];

        egr_info_p = tb_egr_util.lookup(&egr_id);
        if(unlikely(!egr_info_p)) {
            egr_info.octets = 0;
            egr_info.packets = 0;
        }
        else {
            egr_info.octets = 18 + ntohs(in_ip->tot_len) + egr_info_p->octets;
            egr_info.packets = 1 + egr_info_p->packets;
        }
        tb_egr_util.update(&egr_id, &egr_info);
    }


    /*****************  Queue info  *****************/

    struct queue_info_t *queue_info_p;
    struct queue_id_t queue_id = {};
    struct queue_info_t queue_info = {};

    #pragma unroll
    for (u8 i = 0; i < num_INT_hop; i++) {
        if (is_queue_occups) {

            queue_id.sw_id = flow_info.sw_ids[i];
            queue_id.p_id = flow_info.e_port_ids[i];
            queue_id.q_id = flow_info.queue_ids[i];

            queue_info.occup = flow_info.queue_occups[i];
            queue_info.q_time = flow_info.egr_times[i];

            is_update = 0;

            queue_info_p = tb_queue.lookup(&queue_id);
            if(unlikely(!queue_info_p)) {

                flow_info.is_queue_occup |= 1 << i;
                is_update = 1;

            } else {

                if (unlikely(ABS(queue_info.occup, queue_info_p->occup) > QUEUE_OCCUP)) {
                    flow_info.is_queue_occup |= 1 << i;
                    is_update = 1;
                }
            }

            if (is_update)
                tb_queue.update(&queue_id, &queue_info);

        }
    }
    // debug:
    //flow_info.is_flow = 1;
    // submit event info to user space
    if (unlikely(flow_info.is_n_flow |
                 flow_info.is_hop_latency |
                 flow_info.is_queue_occup |
                 flow_info.is_flow
                 )){
        events.perf_submit(ctx, &flow_info, sizeof(flow_info));
        value = 2;
        counter_int.increment(value);
    }

DROP:
    return XDP_DROP;

PASS:
    return XDP_PASS;
}
