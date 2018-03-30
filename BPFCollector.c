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

#define MAX_INT_HOP 6

#define TO_EGRESS 0
#define TO_INGRESS 1
#define BROADCAST_MAC 0xFFFFFFFFFFFF
#define NULL32 0xFFFFFFFF
#define NULL16 0xFFFF

#define CURSOR_ADVANCE(_target, _cursor, _len,_data_end) \
	({  _target = _cursor; _cursor += _len; \
  		if(_cursor > _data_end) return XDP_DROP; })

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

struct flow_path_t {
	u32 path[MAX_INT_HOP];
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
	u16 e_p_id;
};

struct egr_info_t {
	u32 hop_latency;
	u8 lantency_ex;

	u32 egr_time;

	u32 tx_utilize;
	u8 utilize_ex;
};

struct queue_id_t {
	u32 sw_id;
	u16 queue_id;
};

struct queue_info_t {
	u16 occup;
	u8 occup_ex;

	u16 congest;
	u8 congest_ex;      
};


// Events

struct event_t {
	// flow
	u32 src_ip;
	u32 dst_ip;
	u16 src_port;
	u16 dst_port;
	u16 ip_proto;

	u32 path[MAX_INT_HOP];

	// switch
	u32 sw_id[MAX_INT_HOP];
	u16 ingr_id[MAX_INT_HOP];
	u16 egr_id[MAX_INT_HOP];
	u16 queue_id[MAX_INT_HOP];


	u8 is_path;
	u8 is_hop_latency;
	u8 is_queue_occup;
	u8 is_tx_utilize;
};

BPF_TABLE("hash", struct flow_id_t, struct flow_path_t, tb_path, 1024);
BPF_TABLE("hash", struct ingr_id_t, struct ingr_info_t, tb_ingr, 256);
BPF_TABLE("hash", struct egr_id_t, struct egr_info_t, tb_egr, 256);
BPF_TABLE("hash", struct queue_id_t, struct queue_info_t, tb_queue, 256);

BPF_PERF_OUTPUT(events);

//--------------------------------------------------------------------

int collector(struct xdp_md *ctx) {

    // bpf_trace_printk("recv pkt! \n");

    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    void* cursor = data;

    // parse outer: Ether->IP->UDP->TelemetryReport.
    
    struct eth_tp *eth;
    CURSOR_ADVANCE(eth, cursor, sizeof(*eth), data_end);
    // bpf_trace_printk("eth type: %x, dst_mac: %llx \n", ntohs(eth->type), eth->dst);

    if (ntohs(eth->type) != ETHTYPE_IP)
        return XDP_PASS;
    struct iphdr *ip;
    CURSOR_ADVANCE(ip, cursor, sizeof(*ip), data_end);
    // bpf_trace_printk("src ip: %x, nextp: %d \n", ntohl(ip->saddr), ip->protocol);

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;
    struct udphdr *udp;
    CURSOR_ADVANCE(udp, cursor, sizeof(*udp), data_end);
    // bpf_trace_printk("src port: %d, dst port: %d \n",
    //     ntohs(udp->source), ntohs(udp->dest));

    if (ntohs(udp->dest) != INT_DST_PORT)
        return XDP_PASS;
    struct telemetry_report_t *tm_rp;
    CURSOR_ADVANCE(tm_rp, cursor, sizeof(*tm_rp), data_end);
    // bpf_trace_printk("ver: %d, f: %d, seq; %d \n",
    //     tm_rp->ver, tm_rp->f, ntohl(tm_rp->seqNumber));

	/*
	    parse Inner: Ether->IP->UDP->INT. 
	    we only consider Telemetry report with INT
	*/

    struct eth_tp *in_eth;
    CURSOR_ADVANCE(in_eth, cursor, sizeof(*in_eth), data_end);
    // bpf_trace_printk("inner eth type: %x, inner dst_mac: %llx \n",
    //     ntohs(in_eth->type), in_eth->dst);

    struct iphdr *in_ip;
    CURSOR_ADVANCE(in_ip, cursor, sizeof(*in_ip), data_end);    
    // bpf_trace_printk("inner src ip: %x, inner nextp: %d \n",
    //     ntohl(in_ip->saddr), in_ip->protocol);

    struct udphdr *in_udp;
    CURSOR_ADVANCE(in_udp, cursor, sizeof(*in_udp), data_end);
    // bpf_trace_printk("inner src port: %d, inner dst port: %d \n",
    //     ntohs(in_udp->source), ntohs(in_udp->dest));

    struct INT_shim_t *INT_shim;
    CURSOR_ADVANCE(INT_shim, cursor, sizeof(*INT_shim), data_end);

    struct INT_md_fix_t *INT_md_fix;
    CURSOR_ADVANCE(INT_md_fix, cursor, sizeof(*INT_md_fix), data_end);

    // bpf_trace_printk("inscnt: %d, ins: %x, hop: %d \n",
    //     INT_md_fix->insCnt, ntohs(INT_md_fix->ins), INT_md_fix->totalHopCnt);

    /*
    	Parse INT data
    */

    u8 num_INT_hop = INT_md_fix->totalHopCnt;

    struct INT_data_t *INT_data;

    // FIXME: harcoded
	u32 sw_ids[MAX_INT_HOP] 		= {NULL32, NULL32, NULL32, NULL32, NULL32, NULL32};
	u32 in_e_port_ids[MAX_INT_HOP] 	= {NULL32, NULL32, NULL32, NULL32, NULL32, NULL32};
	u32 hop_latencies[MAX_INT_HOP] 	= {NULL32, NULL32, NULL32, NULL32, NULL32, NULL32};
	u32 queue_occups[MAX_INT_HOP] 	= {NULL32, NULL32, NULL32, NULL32, NULL32, NULL32};
	u32 ingr_times[MAX_INT_HOP] 	= {NULL32, NULL32, NULL32, NULL32, NULL32, NULL32};
	u32 egr_times[MAX_INT_HOP] 		= {NULL32, NULL32, NULL32, NULL32, NULL32, NULL32};
	u32 queue_congests[MAX_INT_HOP] = {NULL32, NULL32, NULL32, NULL32, NULL32, NULL32};
	u32 tx_utilizes[MAX_INT_HOP] 	= {NULL32, NULL32, NULL32, NULL32, NULL32, NULL32};

    u16 INT_ins = ntohs(INT_md_fix->ins);
    u8 is_sw_ids 		 = (INT_ins >> 15) & 0x01;
    u8 is_in_e_port_ids  = (INT_ins >> 14) & 0x01;
    u8 is_hop_latencies  = (INT_ins >> 13) & 0x01;
    u8 is_queue_occups 	 = (INT_ins >> 12) & 0x01;
    u8 is_ingr_times 	 = (INT_ins >> 11) & 0x01;
    u8 is_egr_times 	 = (INT_ins >> 10) & 0x01;
    u8 is_queue_congests = (INT_ins >> 9) & 0x01;
    u8 is_tx_utilizes 	 = (INT_ins >> 8) & 0x01;

    // bpf_trace_printk("is sw_id: %d, is hop_latencies: %d, is queue_occups: %d \n",
    //     is_sw_ids, is_hop_latencies, is_queue_occups);


    #pragma unroll
    for (u8 i = 0; i < MAX_INT_HOP; i++) {

        if (is_sw_ids) {
            CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
            sw_ids[i] = ntohl(INT_data->data);
        }
        if (is_in_e_port_ids) {
            CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
            in_e_port_ids[i] = ntohl(INT_data->data);
        }
        if (is_hop_latencies) {
            CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
            hop_latencies[i] = ntohl(INT_data->data);
        }
        if (is_queue_occups) {
            CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
            queue_occups[i] = ntohl(INT_data->data);
        }
        if (is_ingr_times) {
            CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
            ingr_times[i] = ntohl(INT_data->data);
        }
        if (is_egr_times) {
            CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
            egr_times[i] = ntohl(INT_data->data);
        }
        if (is_queue_congests) {
            CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
            queue_congests[i] = ntohl(INT_data->data);
        }
        if (is_tx_utilizes) {
            CURSOR_ADVANCE(INT_data, cursor, sizeof(*INT_data), data_end);
            tx_utilizes[i] = ntohl(INT_data->data);
        }

        // no need for the final round
        if (i < MAX_INT_HOP - 1) {  	
        	num_INT_hop--;
	        if (num_INT_hop <= 0)
	            break;
	    }
    }

    // bpf_trace_printk("sw_ids: %d - %d - %d \n", sw_ids[0], sw_ids[1], sw_ids[2]);
    // bpf_trace_printk("hop_latencies: %x - %x - %x \n",
    // 	hop_latencies[0], hop_latencies[1], hop_latencies[2]);

    // parse INT tail
    struct INT_tail_t *INT_tail;
    CURSOR_ADVANCE(INT_tail, cursor, sizeof(*INT_tail), data_end);
    bpf_trace_printk("origin DSCP: %d\n", INT_tail->originDSCP);


    /*
     	Store data and event detection. New event when: 
    	- New data
    	- Path change
    	- Exceed threshold (hop latency, queue occupancy, queue congestion)
    */

    // Assume that sw_id is alway presented.
    if (!is_sw_ids) return XDP_PASS;

    struct event_t event = {};

    event.src_ip = ntohl(in_ip->saddr);
	event.dst_ip = ntohl(in_ip->daddr);
	event.src_port = ntohs(in_udp->source);
	event.dst_port = ntohs(in_udp->dest);
	event.ip_proto = in_ip->protocol;

	/*
    	Path store and change-detection
	*/

	struct flow_id_t flow_id = {};
	flow_id.src_ip = event.src_ip;
	flow_id.dst_ip = event.dst_ip;
	flow_id.src_port = event.src_port;
	flow_id.dst_port = event.dst_port;
	flow_id.ip_proto = event.ip_proto;

	// FIXME: harcoded
	struct flow_path_t flow_path = {};
	#pragma unroll
    for (u8 i = 0; i < MAX_INT_HOP; i++) {
    	flow_path.path[i] = sw_ids[i];
    }

    // bpf_trace_printk("path: %x - %x \n", 
    // 	flow_path.path[0], flow_path.path[5]);

	struct flow_path_t *old_flow_path_p = tb_path.lookup(&flow_id);
	if (!old_flow_path_p) { // new flows
		
		event.is_path = 1;

	} else { // compare with old flow
		#pragma unroll
	    for (u8 i = 0; i < MAX_INT_HOP; i++) {
	    	if (sw_ids[i] == old_flow_path_p->path[i]) {
	    		event.is_path = 1;
	    		break;
	    	}
	    }
	}

	if (event.is_path) {
		tb_path.update(&flow_id, &flow_path);
			#pragma unroll
	    for (u8 i = 0; i < MAX_INT_HOP; i++) {
	    	event.path[i] = sw_ids[i];
	    }
	}




	if (event.is_path | event.is_hop_latency | event.is_queue_occup | event.is_tx_utilize)
		events.perf_submit(ctx, &event, sizeof(event));
















    // struct flow_id_t flow_id = {};
    // flow_id.src_ip = ntohl(in_ip->saddr);
    // flow_id.dst_ip = ntohl(in_ip->daddr);
    // flow_id.src_port = ntohs(in_udp->source);
    // flow_id.dst_port = ntohs(in_udp->dest);




    // // int ingress_if = skb->ingress_ifindex;

    // //---------------------------------------------------
    // // // MONITORING

    // // // parse IP
    // // if (eth->type != 0x0800) {
    // //     struct ip_t *ip = data + sizeof(*eth);
    // //     if (ip + 1 > data_end) {
    // //         return XDP_DROP;
    // //     }
    // // } else {
    // //     return XDP_DROP;
    // // }

    // // struct five_tuple_t five_tuple = {};
    // // five_tuple.protocol = ip->nextp;
    // // five_tuple.src_ip = ip->src;
    // // five_tuple.dst_ip = ip->dst;
    
    // // struct statistic_t init_stat = {};
    // // init_stat.pkt_cnt = 0;
    // // init_stat.len_cnt = 0;

    // // if (ip->nextp == IPPROTO_TCP) {
    // //     struct tcp_t *tcp;
    // //     tcp = data + sizeof(*ip);
        
    // //     if (tcp + 1 > data_end) {
    // //         return XDP_DROP;
    // //     }
        
    // //     five_tuple.src_port = tcp->src_port;
    // //     five_tuple.dst_port = tcp->dst_port;

    // // } else if (ip->nextp == IPPROTO_UDP) {
    // //     struct udp_t *udp;
    // //     udp = data + sizeof(*ip);

    // //     if (udp + 1 > data_end) {
    // //         return XDP_DROP;
    // //     }
        
    // //     five_tuple.src_port = udp->sport;
    // //     five_tuple.dst_port = udp->dport;

    // // } else {
    // //     five_tuple.src_port = 0;
    // //     five_tuple.dst_port = 0;
    // // }

    // // // write statistic to table
    // // struct statistic_t *cur_stat = tb_statistic.lookup_or_init(&five_tuple, &init_stat);
    
    // // if (cur_stat) {
    // //     cur_stat->pkt_cnt += 1;
    // //     cur_stat->len_cnt += skb->len;
    // // }


    // //-------------------------------------------------
    // // FORWARDING

    // // tb_forward.update(&src_mac, &ingress_if);

    // // forward to dst port
    // int *ifindex = tb_forward.lookup(&dst_mac);
    
    // if(ifindex) {
    //     // bpf_trace_printk("to %d\n", *ifindex);
    //     bpf_trace_printk("redirected! \n");
    //     return bpf_redirect(*ifindex, TO_EGRESS);
    //     // return XDP_DROP;

    // } else {
    //     // TODO: FLOOD
    //     bpf_trace_printk("drop! \n");
    //     return XDP_DROP;
    // }


	return XDP_DROP;
}
