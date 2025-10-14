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
        if (p->family == AF_INET6) {
            __builtin_memcpy(evt->net.daddr_v6, p->daddr_v6, sizeof(p->daddr_v6));
        } else {
            __builtin_memset(evt->net.daddr_v6, 0, sizeof(evt->net.daddr_v6));
        }
        evt->net.dport    = p->dport;
        evt->net.protocol = p->protocol;
    } else if(type == FIREWALL_EVT_BLOCKED_IP) {
        const struct net_payload *p = data;
        evt->net.family   = p->family;
        evt->net.daddr_v4 = p->daddr_v4;
        if (p->family == AF_INET6) {
            __builtin_memcpy(evt->net.daddr_v6, p->daddr_v6, sizeof(p->daddr_v6));
        } else {
            __builtin_memset(evt->net.daddr_v6, 0, sizeof(evt->net.daddr_v6));
        }
        evt->net.dport    = p->dport;
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
    if (h_proto == ETH_P_IP) {
        struct iphdr *ip4 = (void *)(eth + 1);
        if ((void *)(ip4 + 1) > data_end) return XDP_PASS;
        lpm_key.prefixlen = 32;
        __u32 ip_be = ip4->saddr; 
        __builtin_memcpy(lpm_key.data, &ip_be, 4);  
        np.family   = AF_INET;
        np.daddr_v4 = ip4->saddr;
        np.protocol = ip4->protocol;

        void *l4 = (void *)ip4 + ip4->ihl*4;
        if (l4 <= data_end) {
            if (ip4->protocol == IPPROTO_TCP) {
                struct tcphdr *th = l4;
                if ((void *)(th + 1) <= data_end)
                    np.dport = th->dest;
            } else if (ip4->protocol == IPPROTO_UDP) {
                struct udphdr *uh = l4;
                if ((void *)(uh + 1) <= data_end)
                    np.dport = uh->dest;
            }
        }
    }
    else if (h_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) return XDP_PASS;
        lpm_key.prefixlen = 128;
        __builtin_memcpy(lpm_key.data, &ip6->saddr, 16);
        np.family   = AF_INET6;
        __builtin_memcpy(np.daddr_v6, &ip6->saddr, 16);
        np.protocol = ip6->nexthdr;
        void *l4 = (void *)(ip6 + 1);
        if (l4 <= data_end) {
            if (ip6->nexthdr == IPPROTO_TCP) {
                struct tcphdr *th = l4;
                if ((void *)(th + 1) <= data_end)
                    np.dport = th->dest;
            } else if (ip6->nexthdr == IPPROTO_UDP) {
                struct udphdr *uh = l4;
                if ((void *)(uh + 1) <= data_end)
                    np.dport = uh->dest;
            }
        }
    } 
    else {
        return XDP_PASS; // non-IP
    }
    send_event(FIREWALL_EVT_CONNECT_IP, &np);
    // enum ip_status *ip_pass = bpf_map_lookup_elem(&block_list_ip, &lpm_key);
    // if (ip_pass) {
    //     if ((*ip_pass) == ALLOW) {
    //         return XDP_PASS;
    //     }
    // }
    // // lookup IOC map
    // enum ip_status *verdict = bpf_map_lookup_elem(&ioc_ip_map, &lpm_key);
    // if (verdict) {
    //     np.status = *verdict;
    // }
    // // drop if DENY
    // if (np.status == DENY) {
    //     send_ioc_event(IOC_EVT_CONNECT_IP, &np);
    //     return XDP_DROP;
    // }
    // else {
    //     // bpf_printk("insert new ip\n");
    //     bpf_map_update_elem(&block_list_ip, &lpm_key, &np.status, BPF_ANY);
    // }
    return XDP_PASS;
}

