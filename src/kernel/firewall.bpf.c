#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h> 
#include <bpf/bpf_endian.h>
#include "common_kern.h"


char LICENSE[] SEC("license") = "Dual BSD/GPL";


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} firewall_events SEC(".maps");


struct {

    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct rule_key);
    __type(value, enum ip_status);
} rules_map SEC(".maps");
// struct {
//     __uint(type, BPF_MAP_TYPE_LPM_TRIE);
//     __uint(max_entries, 1024);
//     __type(key, struct rule_key);
//     __type(value, enum ip_status);
//     __uint(map_flags, BPF_F_NO_PREALLOC);
// } rules_map SEC(".maps");

// static function
static __always_inline void send_event(enum firewall_event_type type, void *data) {
    struct ioc_event *evt;

    evt = bpf_ringbuf_reserve(&firewall_events, sizeof(*evt), 0);
    if (!evt) {
        return;
    }

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->timestamp_ns = bpf_ktime_get_ns();

    evt->type = type;

    // Copy payload 
    if (type == FIREWALL_EVT_CONNECT_IP) {
        const struct net_payload *p = data;
        evt->net.family   = p->family;
        evt->net.daddr_v4 = p->daddr_v4;
        evt->net.saddr_v4 = p->saddr_v4;
        if (p->family == AF_INET6) {
            __builtin_memcpy(evt->net.daddr_v6, p->daddr_v6, sizeof(p->daddr_v6));
        } else {
            __builtin_memset(evt->net.daddr_v6, 0, sizeof(evt->net.daddr_v6));
        }
        evt->net.dport    = p->dport;
        evt->net.src_port  = p->src_port;
        evt->net.protocol = p->protocol;
    } else if(type == FIREWALL_EVT_BLOCKED_IP) {
        const struct net_payload *p = data;
        evt->net.family   = p->family;
        evt->net.daddr_v4 = p->daddr_v4;
        evt->net.saddr_v4 = p->saddr_v4;
        if (p->family == AF_INET6) {
            __builtin_memcpy(evt->net.daddr_v6, p->daddr_v6, sizeof(p->daddr_v6));
            __builtin_memcpy(evt->net.saddr_v6, p->saddr_v6, sizeof(p->saddr_v6));
        } else {
            __builtin_memset(evt->net.daddr_v6, 0, sizeof(evt->net.daddr_v6));
            __builtin_memset(evt->net.saddr_v6, 0, sizeof(evt->net.saddr_v6));
        }
        evt->net.dport    = p->dport;
        evt->net.src_port  = p->src_port;
        evt->net.protocol = p->protocol;
    }
    else {
        // TODO
    }
    bpf_ringbuf_submit(evt, 0);
}

SEC("xdp")
int xdp_block(struct xdp_md *ctx)
{
    struct net_payload np = {};
    np.status = ALLOW;

    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = bpf_ntohs(eth->h_proto);

    struct ip_lpm_key lpm_key = {};
    struct rule_key full_key = {};

    /* -------------------- IPv4 -------------------- */
    if (h_proto == ETH_P_IP) {
        struct iphdr *ip4 = (void *)(eth + 1);
        if ((void *)(ip4 + 1) > data_end)
            return XDP_PASS;
        if (ip4->ihl < 5)
            return XDP_PASS;

        lpm_key.prefixlen = 32;
        __u32 ip_be = ip4->saddr;
        __builtin_memcpy(lpm_key.data, &ip_be, 4);

        np.family   = AF_INET;
        np.saddr_v4 = ip4->saddr;   

        np.protocol = ip4->protocol;

        void *l4 = (void *)ip4 + ip4->ihl * 4;
        if (l4 + 1 > data_end)
            return XDP_PASS;

        if (ip4->protocol == IPPROTO_TCP) {
            struct tcphdr *th = l4;
            if ((void *)(th + 1) > data_end)
                return XDP_PASS;
            bpf_printk("TCP src=%u dst=%u ihl=%d tot_len=%u\n",
                        bpf_ntohs(th->source),
                        bpf_ntohs(th->dest),
                        ip4->ihl,
                        bpf_ntohs(ip4->tot_len));
            np.src_port = bpf_ntohs(th->source);
            // np.dport    = bpf_ntohs(th->dest);
        } else if (ip4->protocol == IPPROTO_UDP) {
            struct udphdr *uh = l4;
            if ((void *)(uh + 1) > data_end)
                return XDP_PASS;
            np.src_port = bpf_ntohs(uh->source);
            // np.dport    = bpf_ntohs(uh->dest);
        }

        full_key.ip_version = 4;
        __builtin_memcpy(&full_key.src.data, &ip4->saddr, 4);
        full_key.src.prefixlen = 32;
        // __builtin_memcpy(&full_key.dst.data, &ip4->daddr, 4);
        // full_key.dst.prefixlen = 32;
        full_key.protocol = ip4->protocol;
        full_key.src_port = np.src_port;
        // full_key.dst_port = np.dport;
        
    }

    /* -------------------- IPv6 -------------------- */
    else if (h_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;

        lpm_key.prefixlen = 128;
        __builtin_memcpy(lpm_key.data, &ip6->saddr, 16);
        np.family   = AF_INET6;
        __builtin_memcpy(np.saddr_v6, &ip6->saddr, 16);
        np.protocol = ip6->nexthdr;

        void *l4 = (void *)(ip6 + 1);
        if (l4 + 1 > data_end)
            return XDP_PASS;

        if (ip6->nexthdr == IPPROTO_TCP) {
            struct tcphdr *th = l4;
            if ((void *)(th + 1) > data_end)
                return XDP_PASS;
            np.src_port = bpf_ntohs(th->source);
            // np.dport    = bpf_ntohs(th->dest);
        } else if (ip6->nexthdr == IPPROTO_UDP) {
            struct udphdr *uh = l4;
            if ((void *)(uh + 1) > data_end)
                return XDP_PASS;
            np.src_port = bpf_ntohs(uh->source);
            // np.dport    = bpf_ntohs(uh->dest);
        }

        full_key.ip_version = 6;
        __builtin_memcpy(&full_key.src.data, &ip6->saddr, 16);
        full_key.src.prefixlen = 128;
        // __builtin_memcpy(&full_key.dst.data, &ip6->daddr, 16);
        // full_key.dst.prefixlen = 128;
        full_key.protocol = ip6->nexthdr;
        full_key.src_port = np.src_port;
        // full_key.dst_port = np.dport;
    }

    /* -------------------- Non-IP -------------------- */
    else {
        return XDP_PASS;
    }

    /* -------------------- Lookup rule -------------------- */
    enum ip_status *verdict = bpf_map_lookup_elem(&rules_map, &full_key);
    if (verdict)
        np.status = *verdict;

    if (np.status == DENY) {
        send_event(FIREWALL_EVT_BLOCKED_IP, &np);
        return XDP_DROP;
    } else {
        send_event(FIREWALL_EVT_CONNECT_IP, &np);
    }

    return XDP_PASS;
}

