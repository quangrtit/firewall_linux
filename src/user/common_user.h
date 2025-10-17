#ifndef __COMMON_USER_H
#define __COMMON_USER_H

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <optional>
#include <memory>
#include <thread>
#include <mutex>
#include <future>
#include <atomic>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
// ===== Linux system =====
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <sys/sysmacros.h>
#include <limits.h>
#include <libgen.h>
#include <elf.h>
#include <sys/prctl.h>
// ===== Security / crypto =====
#include <openssl/sha.h>
#include <openssl/evp.h>

// ===== eBPF / networking =====
#include <bpf/libbpf.h>
#include <linux/types.h>

// ===== JSON config =====
#include <cjson/cJSON.h>

// ===== eBPF generated header =====
#define LOG_MSG_MAX_LEN 128
#define TASK_COMM_LEN 32
#define MAX_PATH_LEN 128
#define MAX_POLICY_ENTRIES 64
#define NAME_MAX 255
#define EPERM     1
#define __u64 long long unsigned int
#define __s64 int64_t
#define KERNEL_MINORBITS 20
#define KERNEL_MKDEV(major, minor) ((__u64)(major) << KERNEL_MINORBITS | (minor))
#define BUFFER_SIZE 1024
#define MAX_IFACES 16

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
    __u32 level;
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
struct CallbackContext {
    int dummy; // Placeholder for future use
};
#endif // __COMMON_USER_H