#define KBUILD_MODNAME "xdp_collector"
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>


#define ETHTYPE_IP 0x0800
#define INT_DST_PORT 54321

// #define IPPROTO_UDP 17
// #define IPPROTO_TCP 6

#define MAX_INT_HOP 4

#define TO_EGRESS 0
#define TO_INGRESS 1
#define BROADCAST_MAC 0xFFFFFFFFFFFF
#define NULL32 0xFFFFFFFF
#define NULL16 0xFFFF


// TODO: set these values from use space
#define HOP_LATENCY 50
#define QUEUE_OCCUP 50
#define QUEUE_CONGEST 50
#define TX_UTILIZE 50
#define TIME_GAP_W 100 //ns

#define CURSOR_ADVANCE(_target, _cursor, _len,_data_end) \
	({  _target = _cursor; _cursor += _len; \
  		if(unlikely(_cursor > _data_end)) return XDP_DROP; })

//--------------------------------------------------------------------
// Protocols
struct eth_tp {
    u64 dst:48;
    u64 src:48;
    u16 type;
} __attribute__((packed));

struct telemetry_report_t {
#if defined(__BIG_ENDIAN_BITFIELD)
    u8  ver:4,
        nProto:4;
    u8  d:1,
        q:1,
        f:1,
        rsvd1:5;
    u16 rsvd2:10,
        hw_id:6;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    u8  nProto:4,
        ver:4;
    u8  rsvd1:5,
        f:1,
        q:1,
        d:1;
    u16 hw_id:6,
        rsvd2:10;  
#else
#error  "Please fix <asm/byteorder.h>"
#endif

    u32 seqNumber;
    u32 ingressTimestamp;
} __attribute__((packed));

struct INT_shim_t {
    u8 type;
    u8 shimRsvd1;
    u8 length;
    u8 shimRsvd2;
} __attribute__((packed));

struct INT_md_fix_t {
#if defined(__BIG_ENDIAN_BITFIELD)
    u8  ver:4,
        rep:2,
        c:1,
        e:1;
    u8  rsvd1:3,
        insCnt:5;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    u8  e:1,
        c:1,
        rep:2,
        ver:4;
    u8  insCnt:5,
        rsvd1:3;
#else
#error  "Please fix <asm/byteorder.h>"
#endif

    u8 maxHopCnt;
    u8 totalHopCnt;
    u16 ins;
    u16 rsvd2;
} __attribute__((packed));


struct INT_data_t {
    u32 data;
} __attribute__((packed));

struct INT_tail_t {
    u8 nextProto;
    u16 destPort;
    u8 originDSCP;
} __attribute__((packed));


// Data

struct stat_t {
    u64 pkt_cnt;
    u64 len_cnt;
};

struct flow_id_t {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
	u16 ip_proto;
};

struct ingr_id_t {
	u32 sw_id;
	u16 in_p_id;
};

struct ingr_info_t {
	u32 ingr_time;
};

struct egr_id_t {
	u32 sw_id;
	u16 p_id;
};

struct egr_info_t {
	u32 tx_utilize;
	u8 utilize_ex;

    u32 egr_time;
};

struct queue_id_t {
	u32 sw_id;
	u16 q_id;
};

struct queue_info_t {
	u16 occup;
	u8 occup_ex;

	u16 congest;
    u8 congest_ex;

    u32 q_time;
};


// Events

struct flow_info_t {
    // flow
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u16 ip_proto;

    u64 pkt_cnt;
    u64 byte_cnt;

    u8 num_INT_hop;

    u32 sw_ids[MAX_INT_HOP];
    u16 in_port_ids[MAX_INT_HOP];
    u16 e_port_ids[MAX_INT_HOP];
    u32 hop_latencies[MAX_INT_HOP];
    u16 queue_ids[MAX_INT_HOP];
    u16 queue_occups[MAX_INT_HOP];
    u32 ingr_times[MAX_INT_HOP];
    u32 egr_times[MAX_INT_HOP];
    u16 queue_congests[MAX_INT_HOP];
    u32 tx_utilizes[MAX_INT_HOP];

    u32 flow_latency;
    u32 flow_sink_time;

    u8 is_n_flow;
    u8 is_n_hop_latency;
    u8 is_n_queue_occup;
    u8 is_n_queue_congest;
    u8 is_n_tx_utilize;

    u8 is_path;
    u8 is_hop_latency;
    u8 is_queue_occup;
    u8 is_queue_congest;
    u8 is_tx_utilize;
};

BPF_PERF_OUTPUT(events);

BPF_TABLE("hash", struct flow_id_t, struct flow_info_t, tb_flow, 1024);
// nothing to store in tb_ingr yet
// BPF_TABLE("hash", struct ingr_id_t, struct ingr_info_t, tb_ingr, 256);
BPF_TABLE("hash", struct egr_id_t, struct egr_info_t, tb_egr, 256);
BPF_TABLE("hash", struct queue_id_t, struct queue_info_t, tb_queue, 256);
BPF_TABLE("hash", u32, struct flow_info_t, tb_test, 256);


//--------------------------------------------------------------------

int collector(struct xdp_md *ctx) {

    // bpf_trace_printk("recv pkt! \n");

    // return XDP_DROP;

    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    void* cursor = data;


    /*
        Parse outer: Ether->IP->UDP->TelemetryReport.
    */  

    struct eth_tp *eth;
    CURSOR_ADVANCE(eth, cursor, sizeof(*eth), data_end);

    if (unlikely(ntohs(eth->type) != ETHTYPE_IP))
        return XDP_PASS;
    struct iphdr *ip;
    CURSOR_ADVANCE(ip, cursor, sizeof(*ip), data_end);

    if (unlikely(ip->protocol != IPPROTO_UDP))
        return XDP_PASS;
    struct udphdr *udp;
    CURSOR_ADVANCE(udp, cursor, sizeof(*udp), data_end);

    if (unlikely(ntohs(udp->dest) != INT_DST_PORT))
        return XDP_PASS;
    struct telemetry_report_t *tm_rp;
    CURSOR_ADVANCE(tm_rp, cursor, sizeof(*tm_rp), data_end);


	/*
        Parse Inner: Ether->IP->UDP->INT. 
        we only consider Telemetry report with INT
	*/

    struct eth_tp *in_eth;
    CURSOR_ADVANCE(in_eth, cursor, sizeof(*in_eth), data_end);

    struct iphdr *in_ip;
    CURSOR_ADVANCE(in_ip, cursor, sizeof(*in_ip), data_end);    

    struct udphdr *in_udp;
    CURSOR_ADVANCE(in_udp, cursor, sizeof(*in_udp), data_end);

    struct INT_shim_t *INT_shim;
    CURSOR_ADVANCE(INT_shim, cursor, sizeof(*INT_shim), data_end);

    struct INT_md_fix_t *INT_md_fix;
    CURSOR_ADVANCE(INT_md_fix, cursor, sizeof(*INT_md_fix), data_end);


    /*
    	Parse INT data
    */

    u8 num_INT_hop = INT_md_fix->totalHopCnt;

    struct INT_data_t *INT_data;

    static const struct flow_info_t empty_flow_info;
    struct flow_info_t flow_info = empty_flow_info;
    flow_info.src_ip = ntohl(in_ip->saddr);
    flow_info.dst_ip = ntohl(in_ip->daddr);
    flow_info.src_port = ntohs(in_udp->source);
    flow_info.dst_port = ntohs(in_udp->dest);
    flow_info.ip_proto = in_ip->protocol;

    flow_info.num_INT_hop = INT_md_fix->totalHopCnt;
    flow_info.flow_sink_time = ntohl(tm_rp->ingressTimestamp);

    // flow_info.pkt_cnt = 0;
    // flow_info.byte_cnt = 0;

    // #pragma unroll
    // for (u8 i = 0; i < MAX_INT_HOP; i++) {
    //     flow_info.sw_ids[i] = 0;
    //     flow_info.in_port_ids[i] = 0;
    //     flow_info.e_port_ids[i] = 0;
    //     flow_info.hop_latencies[i] = 0;
    //     flow_info.queue_ids[i] = 0;
    //     flow_info.queue_occups[i] = 0;
    //     flow_info.ingr_times[i] = 0;
    //     flow_info.egr_times[i] = 0;
    //     flow_info.queue_congests[i] = 0;
    //     flow_info.tx_utilizes[i] = 0;
    // }


    // flow_info.is_n_flow = 0;
    // flow_info.is_n_hop_latency = 0;
    // flow_info.is_n_queue_occup = 0;
    // flow_info.is_n_queue_congest = 0;
    // flow_info.is_n_tx_utilize = 0;

    // flow_info.is_path = 0;
    // flow_info.is_hop_latency = 0;
    // flow_info.is_queue_congest = 0;
    // flow_info.is_queue_occup = 0;
    // flow_info.is_tx_utilize = 0;


    u16 INT_ins = ntohs(INT_md_fix->ins);
    u8 is_sw_ids 		 = (INT_ins >> 15) & 0x01;
    u8 is_in_e_port_ids  = (INT_ins >> 14) & 0x01;
    u8 is_hop_latencies  = (INT_ins >> 13) & 0x01;
    u8 is_queue_occups 	 = (INT_ins >> 12) & 0x01;
    u8 is_ingr_times 	 = (INT_ins >> 11) & 0x01;
    u8 is_egr_times 	 = (INT_ins >> 10) & 0x01;
    u8 is_queue_congests = (INT_ins >> 9) & 0x01;
    u8 is_tx_utilizes 	 = (INT_ins >> 8) & 0x01;

    #pragma unroll
    for (u8 i = 0; i < MAX_INT_HOP; i++) {

        if (likely(is_sw_ids)) {
            CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
            flow_info.sw_ids[i] = ntohl(INT_data->data);
        }
        if (is_in_e_port_ids) {
            CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
            flow_info.in_port_ids[i] = (ntohl(INT_data->data) >> 16) & 0xff;
            flow_info.e_port_ids[i] = ntohl(INT_data->data) & 0xff;
        }
        if (is_hop_latencies) {
            CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
            flow_info.hop_latencies[i] = ntohl(INT_data->data);
            flow_info.flow_latency += flow_info.hop_latencies[i];
        }
        if (is_queue_occups) {
            CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
            flow_info.queue_ids[i] = (ntohl(INT_data->data) >> 16) & 0xff;
            flow_info.queue_occups[i] = ntohl(INT_data->data) & 0xff;
        }
        if (is_ingr_times) {
            CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
            flow_info.ingr_times[i] = ntohl(INT_data->data);
        }
        if (is_egr_times) {
            CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
            flow_info.egr_times[i] = ntohl(INT_data->data);
        }
        if (is_queue_congests) {
            CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
            flow_info.queue_ids[i] = (ntohl(INT_data->data) >> 16) & 0xff;
            flow_info.queue_congests[i] = ntohl(INT_data->data) & 0xff;
        }
        if (is_tx_utilizes) {
            CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
            flow_info.tx_utilizes[i] = ntohl(INT_data->data);
        }

        // no need for the final round
        if (i < MAX_INT_HOP - 1) {  	
        	num_INT_hop--;
	        if (num_INT_hop <= 0)
	            break;
	    }
    }


    // parse INT tail
    struct INT_tail_t *INT_tail;
    CURSOR_ADVANCE(INT_tail, cursor, sizeof(*INT_tail), data_end);


    /*
        Store data and event detection. New event when: 
        - New data
        - Path change
        - Exceed threshold (hop latency, queue occupancy, queue congestion)
    */

    // Assume that sw_id is alway presented.
    if (unlikely(!is_sw_ids)) return XDP_PASS;

    /*
        Path store and change-detection
    */

    struct flow_id_t flow_id = {};
    flow_id.src_ip = flow_info.src_ip;
    flow_id.dst_ip = flow_info.dst_ip;
    flow_id.src_port = flow_info.src_port;
    flow_id.dst_port = flow_info.dst_port;
    flow_id.ip_proto = flow_info.ip_proto;

    struct flow_info_t *flow_info_p = tb_flow.lookup(&flow_id);
    if (unlikely(!flow_info_p)) {
        
        flow_info.is_n_flow = 1;

        switch (INT_md_fix->totalHopCnt) {
            case 1: flow_info.is_n_hop_latency = 0x01; break;
            case 2: flow_info.is_n_hop_latency = 0x03; break;
            case 3: flow_info.is_n_hop_latency = 0x07; break;
            case 4: flow_info.is_n_hop_latency = 0x0f; break;
            case 5: flow_info.is_n_hop_latency = 0x1f; break;
            case 6: flow_info.is_n_hop_latency = 0x3f; break;
            case 7: flow_info.is_n_hop_latency = 0x7f; break;
            case 8: flow_info.is_n_hop_latency = 0xff; break;
            default: break;
        }

        flow_info.pkt_cnt++;
        flow_info.byte_cnt += ntohs(ip->tot_len);

    } else {

        num_INT_hop = INT_md_fix->totalHopCnt;
        #pragma unroll
        for (u8 i = 0; i < MAX_INT_HOP; i++) {
            

            if (unlikely(flow_info.sw_ids[i] != flow_info_p->sw_ids[i])) {
                flow_info.is_path = 1;
                if (is_hop_latencies)
                    flow_info.is_n_hop_latency |= 1 << i;
            }

            if (is_hop_latencies && (flow_info.hop_latencies[i] > HOP_LATENCY))
                flow_info.is_hop_latency |= 1 << i;

            // no need for the final round
            if (i < MAX_INT_HOP - 1) {      
                num_INT_hop--;
                if (num_INT_hop <= 0)
                    break;
            }
        }

        flow_info.pkt_cnt = flow_info_p->pkt_cnt + 1;
        flow_info.byte_cnt = flow_info_p->byte_cnt + ntohs(ip->tot_len);
    }

    tb_flow.update(&flow_id, &flow_info);



    /*
        Egress info
    */

    u8 is_update = 0;

    struct egr_info_t *egr_info_p;
    struct egr_id_t egr_id = {};
    struct egr_info_t egr_info = {};

    num_INT_hop = INT_md_fix->totalHopCnt;
    #pragma unroll
    for (u8 i = 0; i < MAX_INT_HOP; i++) {
        if (is_in_e_port_ids && is_tx_utilizes) {
            if (num_INT_hop <= 0)
                break;
                      
            egr_id.sw_id  = flow_info.sw_ids[i];
            egr_id.p_id = flow_info.e_port_ids[i];
          
            egr_info.egr_time    = flow_info.egr_times[i];
            egr_info.tx_utilize  = flow_info.tx_utilizes[i];

            is_update = 0;

            egr_info_p = tb_egr.lookup(&egr_id);
            if(unlikely(!egr_info_p)) {
                flow_info.is_n_tx_utilize |= 1 << i;
                is_update = 1; 
            } else if (egr_info.egr_time > egr_info_p->egr_time + TIME_GAP_W) {
                is_update = 1;
            }

            if (unlikely(egr_info.tx_utilize > TX_UTILIZE)) {
                flow_info.is_tx_utilize |= 1 << i;
                is_update = 1;
            }

            if (is_update)
                tb_egr.update(&egr_id, &egr_info);

            num_INT_hop--;
        }
    }


    /*
        Queue info
    */
    
    struct queue_info_t *queue_info_p;
    struct queue_id_t queue_id = {};
    struct queue_info_t queue_info = {};

    num_INT_hop = INT_md_fix->totalHopCnt;
    #pragma unroll
    for (u8 i = 0; i < MAX_INT_HOP; i++) {
        if (is_queue_occups | is_queue_congests) {
            if (num_INT_hop <= 0)
                break;
                      
            queue_id.sw_id = flow_info.sw_ids[i];
            queue_id.q_id = flow_info.queue_ids[i];
          
            queue_info.occup = flow_info.queue_occups[i];
            queue_info.congest = flow_info.queue_congests[i];
            queue_info.q_time = flow_info.egr_times[i];

            is_update = 0;

            queue_info_p = tb_queue.lookup(&queue_id);
            if(unlikely(!queue_info_p)) {
                if (is_queue_occups)
                    flow_info.is_n_queue_occup |= 1 << i;
                if (is_queue_congests)
                    flow_info.is_n_queue_congest |= 1 << i;

                is_update = 1;

            } else if (queue_info.q_time > queue_info_p->q_time + TIME_GAP_W) {
                is_update = 1;
            }

            if (unlikely(is_queue_occups & (queue_info.occup > QUEUE_OCCUP))) {
                flow_info.is_queue_occup |= 1 << i;
                is_update = 1;
            }
            if (unlikely(is_queue_congests & (queue_info.congest > QUEUE_CONGEST))) {
                flow_info.is_queue_congest |= 1 << i;
                is_update = 1;
            }

            if (is_update)
                tb_queue.update(&queue_id, &queue_info);

            num_INT_hop--;
        }
    }


    // submit event info to user space
    if (unlikely(flow_info.is_n_flow | flow_info.is_n_hop_latency |
        flow_info.is_n_queue_occup | flow_info.is_n_queue_congest | 
        flow_info.is_n_tx_utilize | flow_info.is_path | flow_info.is_hop_latency | 
        flow_info.is_queue_occup | flow_info.is_queue_congest | flow_info.is_tx_utilize)
    )
        events.perf_submit(ctx, &flow_info, sizeof(flow_info));


	return XDP_DROP;
}
