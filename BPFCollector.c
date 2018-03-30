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


//--------------------------------------------------------------------

struct five_tuple_t {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u16 protocol;
};

struct statistic_t {
    u64 pkt_cnt;
    u64 len_cnt;

};


// BPF_TABLE("hash", struct five_tuple_t, struct statistic_t, tb_statistic, 10240);
// BPF_TABLE("hash", u64, int, tb_forward, 256);
// BPF_TABLE("hash", int, int, tb_ifaces, MAX_IFACES);
// BPF_ARRAY(tb_tap, struct tap_rule_t, MAX_TAPS);


int collector(struct xdp_md *ctx) {

    // bpf_trace_printk("recv pkt! \n");


    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    void* cursor = data;

    //--------------------------------------------------------------------
    // parse outer: Ether->IP->UDP->TelemetryReport.
    
    struct eth_tp *eth = cursor;
    cursor += sizeof(*eth);
    if (cursor > data_end)
        goto DROP;

    // bpf_trace_printk("eth type: %x, dst_mac: %llx \n", ntohs(eth->type), eth->dst);

    if (ntohs(eth->type) != ETHTYPE_IP)
        goto PASS;
    struct iphdr *ip = cursor;
    cursor += sizeof(*ip); // TODO: Consider ip options (ip len)
    if (cursor > data_end)
        goto DROP;
    
    // bpf_trace_printk("src ip: %x, nextp: %d \n", ntohl(ip->saddr), ip->protocol);

    if (ip->protocol != IPPROTO_UDP)
        goto PASS;
    struct udphdr *udp = cursor;
    cursor += sizeof(*udp);
    if (cursor > data_end)
        goto DROP;

    // bpf_trace_printk("src port: %d, dst port: %d \n",
    //     ntohs(udp->source), ntohs(udp->dest));

    if (ntohs(udp->dest) != INT_DST_PORT)
        goto PASS;
    struct telemetry_report_t *tm_rp = cursor;
    cursor += sizeof(*tm_rp);
    if (cursor > data_end)
        goto DROP;

    // bpf_trace_printk("ver: %d, f: %d, seq; %d \n",
    //     tm_rp->ver, tm_rp->f, ntohl(tm_rp->seqNumber));


    //--------------------------------------------------------------------
    // parse Inner: Ether->IP->UDP->INT. we only consider Telemetry report with INT

    struct eth_tp *in_eth = cursor;
    cursor += sizeof(*in_eth);
    if (cursor > data_end)
        goto DROP;

    // bpf_trace_printk("inner eth type: %x, inner dst_mac: %llx \n",
    //     ntohs(in_eth->type), in_eth->dst);

    struct iphdr *in_ip = cursor;
    cursor += sizeof(*in_ip); // TODO: Consider ip options (ip len)
    if (cursor > data_end)
        goto DROP;
    
    // bpf_trace_printk("inner src ip: %x, inner nextp: %d \n",
    //     ntohl(in_ip->saddr), in_ip->protocol);

    struct udphdr *in_udp = cursor;
    cursor += sizeof(*in_udp);
    if (cursor > data_end)
        goto DROP;

    // bpf_trace_printk("inner src port: %d, inner dst port: %d \n",
    //     ntohs(in_udp->source), ntohs(in_udp->dest));

    struct INT_shim_t *INT_shim = cursor;
    cursor += sizeof(*INT_shim);
    if (cursor > data_end)
        goto DROP;

    struct INT_md_fix_t *INT_md_fix = cursor;
    cursor += sizeof(*INT_md_fix);
    if (cursor > data_end)
        goto DROP;

    bpf_trace_printk("inscnt: %d, ins: %x, hop: %d \n",
        INT_md_fix->insCnt, ntohs(INT_md_fix->ins), INT_md_fix->totalHopCnt);

    //------------------------------------------------------------
    // parse INT data

    u8 num_INT_data = INT_md_fix->totalHopCnt * INT_md_fix->insCnt;
    u8 num_INT_hop = INT_md_fix->totalHopCnt;

    struct INT_data_t *INT_data;

	u32 d0[MAX_INT_HOP] = {0};
	u32 d1[MAX_INT_HOP] = {0};
	u32 d2[MAX_INT_HOP] = {0};
	u32 d3[MAX_INT_HOP] = {0};
	u32 d4[MAX_INT_HOP] = {0};
	u32 d5[MAX_INT_HOP] = {0};
	u32 d6[MAX_INT_HOP] = {0};
	u32 d7[MAX_INT_HOP] = {0};

    u16 INT_ins = ntohs(INT_md_fix->ins);
    u8 is_sw_ids 		 = (INT_ins >> 15) & 0x01;
    u8 is_in_e_port_ids  = (INT_ins >> 14) & 0x01;
    u8 is_hop_latencies  = (INT_ins >> 13) & 0x01;
    u8 is_queue_occups 	 = (INT_ins >> 12) & 0x01;
    u8 is_in_times 		 = (INT_ins >> 11) & 0x01;
    u8 is_e_times 		 = (INT_ins >> 10) & 0x01;
    u8 is_queue_congests = (INT_ins >> 9) & 0x01;
    u8 is_tx_utilizes 	 = (INT_ins >> 8) & 0x01;

    bpf_trace_printk("is sw_id: %d, is hop_latencies: %d, is queue_occups: %d \n",
        is_sw_ids, is_hop_latencies, is_queue_occups);


    #pragma unroll
    for (u8 i = 0; i < MAX_INT_HOP; i++) {

        if (is_sw_ids) {
            INT_data = cursor;
            cursor += sizeof(*INT_data);
            if (cursor > data_end) goto DROP;
            d0[i] = ntohl(INT_data->data);
        }
        if (is_in_e_port_ids) {
            INT_data = cursor;
            cursor += sizeof(*INT_data);
            if (cursor > data_end) goto DROP;
            d1[i] = ntohl(INT_data->data);
        }
        if (is_hop_latencies) {
            INT_data = cursor;
            cursor += sizeof(*INT_data);
            if (cursor > data_end) goto DROP;
            d2[i] = ntohl(INT_data->data);
        }
        if (is_queue_occups) {
            INT_data = cursor;
            cursor += sizeof(*INT_data);
            if (cursor > data_end) goto DROP;
            d3[i] = ntohl(INT_data->data);
        }
        if (is_in_times) {
            INT_data = cursor;
            cursor += sizeof(*INT_data);
            if (cursor > data_end) goto DROP;
            d4[i] = ntohl(INT_data->data);
        }
        if (is_e_times) {
            INT_data = cursor;
            cursor += sizeof(*INT_data);
            if (cursor > data_end) goto DROP;
            d5[i] = ntohl(INT_data->data);
        }
        if (is_queue_congests) {
            INT_data = cursor;
            cursor += sizeof(*INT_data);
            if (cursor > data_end) goto DROP;
            d6[i] = ntohl(INT_data->data);
        }
        if (is_tx_utilizes) {
            INT_data = cursor;
            cursor += sizeof(*INT_data);
            if (cursor > data_end) goto DROP;
            d7[i] = ntohl(INT_data->data);
        }

        // no need for the final round
        if (i < MAX_INT_HOP - 1) {  	
        	num_INT_hop--;
	        if (num_INT_hop <= 0)
	            break;
	    }
    }

    bpf_trace_printk("d00: %d, d20: %d, d75: %d \n", d0[0], d2[0], d7[5]);
    bpf_trace_printk("d20: %x, d21: %x, d22: %x \n", d2[0], d2[1], d2[2]);

    // parse INT tail
    struct INT_tail_t *INT_tail = cursor;
    cursor += sizeof(*INT_tail);
    if (cursor > data_end)
        goto DROP;
    bpf_trace_printk("origin DSCP: %d\n", INT_tail->originDSCP);


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

DROP:
    return XDP_DROP;

PASS:
    return XDP_PASS;
}
