#ifndef __COMMON_KERN_H
#define __COMMON_KERN_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>      // eBPF helper macro
#include <bpf/bpf_tracing.h>   // bpf_trace_printk


#define LOG_MSG_MAX_LEN 128
#define TASK_COMM_LEN 32
#define MAX_PATH_LEN 128
#define MAX_POLICY_ENTRIES 64
#define NAME_MAX 255
#define EPERM 1

#define S_ISLNK(m) (((m) & 0170000) == 0120000)
#define EPERM 1
#define AF_INET 2
#define AF_INET6 10
#define ECONNREFUSED 111
#define ETH_P_IP    0x0800  /* IPv4 */
#define ETH_P_IPV6  0x86DD  /* IPv6 */

enum log_level {
    INFO,
    WARNING,
    ERROR,
    BLOCKED_ACTION
};
struct log_debug {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u32 level; // Corresponds to enum log_level
    char comm[TASK_COMM_LEN];
    char msg[LOG_MSG_MAX_LEN];
};

enum firewall_event_type {
    FIREWALL_EVT_CONNECT_IP = 0,
    FIREWALL_EVT_BLOCKED_IP
};

struct ip_lpm_key {
    __u32 prefixlen;   // bit length: 32 for IPv4, 128 for IPv6
    __u8  data[16];    // IPv4 for 4 first byte, IPv6 for 16 byte
};
struct rule_key {
    struct ip_lpm_key src;  // source
    struct ip_lpm_key dst;  // destination
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;         // IPPROTO_TCP, UDP, ICMP
    __u8  ip_version;       // 4 or 6
};
// struct rule_val {
//     __u8 action;  // 0=DROP, 1=ALLOW, 2=LOG
// };
enum ip_status {
    ALLOW = 0,
    DENY = 1
};
struct net_payload {
    // enum ip_status status;
    __u32 status;
    __u8  family;       // AF_INET / AF_INET6
    __u8  pad[3];
    __u32 saddr_v4;     // IPv4 source
    __u32 daddr_v4;     // IPv4 dest
    __u8  saddr_v6[16]; // IPv6 source
    __u8  daddr_v6[16]; // IPv6 dest
    __u16 src_port;      // source port
    __u16 dport;        // dest port
    __u32 protocol;     // TCP/UDP
};

// Event sent from kernel to user
struct ioc_event {
    __u64 timestamp_ns;       // Time of occurrence
    __u32 pid;                // PID of the process
    __u32 tgid;               // TGID (parent pid)
    __u32 ppid;               // parent PID
    __u32 uid;                // UID of the user running the process
    __u32 gid;                // GID of the user running the process
    enum firewall_event_type type; // Type of event
    union {
        struct net_payload net;
    };
};
#endif // __COMMON_KERN_H