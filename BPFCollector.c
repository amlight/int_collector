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
#define MAX_IFACES 8
#define MAX_TAPS 8
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

struct telemetry_report_tp {
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

struct INT_shim_tp {
    u8 type;
    u8 shimRsvd1;
    u8 length;
    u8 shimRsvd2;
} __attribute__((packed));

struct INT_md_fix_yp {
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


struct INT_tail_tp {
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

    // parse outer: Ether->IP->UDP->TelemetryReport.
    struct eth_tp *eth = cursor;
    cursor += sizeof(*eth);
    if (cursor > data_end)
        goto DROP;

    bpf_trace_printk("eth type: %x, dst_mac: %llx \n", ntohs(eth->type), eth->dst);

    if (ntohs(eth->type) != ETHTYPE_IP)
        goto PASS;
    struct iphdr *ip = cursor;
    cursor += sizeof(*ip);
    if (cursor > data_end)
        goto DROP;

    bpf_trace_printk("src ip: %x, nextp: %d \n", ntohl(ip->saddr), ip->protocol);

    if (ip->protocol != IPPROTO_UDP)
        goto PASS;
    struct udphdr *udp = cursor;
    cursor += sizeof(*udp);
    if (cursor > data_end)
        goto DROP;

    bpf_trace_printk("src port: %d, dst port: %d \n", ntohs(udp->source), ntohs(udp->dest));

    if (ntohs(udp->dest) != INT_DST_PORT)
        goto PASS;
    struct telemetry_report_tp *tm_rp = cursor;
    cursor += sizeof(*tm_rp);
    if (cursor > data_end)
        goto DROP;

    bpf_trace_printk("ver: %d, f: %d, seq; %d \n", tm_rp->ver, tm_rp->f, ntohl(tm_rp->seqNumber));

    // parse Inner: Ether->IP->UDP->INT. we only consider Telemetry report with INT






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
