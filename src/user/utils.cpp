#include "utils.h"



// Convert "TCP", "UDP", "ICMP" to corresponding numeric codes
static __u8 parse_protocol(const char *proto) {
    if (!proto) return 0;
    if (strcasecmp(proto, "TCP") == 0)  return IPPROTO_TCP;
    if (strcasecmp(proto, "UDP") == 0)  return IPPROTO_UDP;
    if (strcasecmp(proto, "ICMP") == 0) return IPPROTO_ICMP;
    return 0;
}

// Parse IP string (IPv4/IPv6/"any")
static void parse_ip_lpm(const char *ip_str, struct ip_lpm_key *key, __u8 *ip_version) {
    memset(key, 0, sizeof(*key));

    if (!ip_str || strcmp(ip_str, "any") == 0) {
        key->prefixlen = 0;
        *ip_version = 4;
        return;
    }

    if (strchr(ip_str, ':')) {
        *ip_version = 6;
        key->prefixlen = 128;
        inet_pton(AF_INET6, ip_str, key->data);
    } else {
        *ip_version = 4;
        key->prefixlen = 32;
        inet_pton(AF_INET, ip_str, key->data);
    }
}
bool load_firewall_rules_into_map(int map_fd, const char *json_path) {
    FILE *f = fopen(json_path, "r");
    if (!f) {
        perror("fopen json");
        return false;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);

    char *buffer = calloc(1, size + 1);
    fread(buffer, 1, size, f);
    fclose(f);

    cJSON *root = cJSON_Parse(buffer);
    free(buffer);

    if (!root || !cJSON_IsArray(root)) {
        fprintf(stderr, "Invalid JSON rule file!\n");
        cJSON_Delete(root);
        return false;
    }

    int rule_count = cJSON_GetArraySize(root);
    for (int i = 0; i < rule_count; i++) {
        cJSON *item = cJSON_GetArrayItem(root, i);
        if (!cJSON_IsObject(item)) continue;

        struct rule_key key = {};
        enum ip_status verdict = ALLOW;

        const char *src_ip   = cJSON_GetObjectItem(item, "src_ip")->valuestring;
        const char *dst_ip   = cJSON_GetObjectItem(item, "dst_ip")->valuestring;
        const char *src_port = cJSON_GetObjectItem(item, "src_port")->valuestring;
        const char *dst_port = cJSON_GetObjectItem(item, "dst_port")->valuestring;
        const char *proto    = cJSON_GetObjectItem(item, "protocol")->valuestring;
        const char *action   = cJSON_GetObjectItem(item, "action")->valuestring;

        parse_ip_lpm(src_ip, &key.src, &key.ip_version);
        parse_ip_lpm(dst_ip, &key.dst, &key.ip_version);

        key.src_port = (strcmp(src_port, "any") == 0) ? 0 : (__u16)atoi(src_port);
        key.dst_port = (strcmp(dst_port, "any") == 0) ? 0 : (__u16)atoi(dst_port);
        key.protocol = parse_protocol(proto);
        verdict = (strcasecmp(action, "DENY") == 0) ? DENY : ALLOW;

        if (bpf_map_update_elem(map_fd, &key, &verdict, BPF_ANY) != 0) {
            perror("bpf_map_update_elem");
            fprintf(stderr, "❌ Failed rule %d: %s -> %s\n", i, src_ip, dst_ip);
        } else {
            printf("✅ Loaded rule %d: %s:%s -> %s:%s (%s) = %s\n",
                   i, src_ip, src_port, dst_ip, dst_port, proto, action);
        }
    }

    cJSON_Delete(root);
    return true;
}
// Check interface IPv4
int has_default_route4(const char *ifname) {
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) return 0;

    char line[256];
    fgets(line, sizeof(line), f); // skip header
    int found = 0;

    while (fgets(line, sizeof(line), f)) {
        char iface[IFNAMSIZ];
        unsigned long dest;
        if (sscanf(line, "%s %lx", iface, &dest) != 2) continue;
        if (dest == 0 && strcmp(iface, ifname)==0) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

// Check interface IPv6
int has_default_route6(const char *ifname) {
    if (!ifname) return 0;

    // Get ifindex from /sys/class/net/<ifname>/ifindex
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s/ifindex", ifname);
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    int ifidx = -1;
    if (fscanf(f, "%d", &ifidx) != 1 || ifidx <= 0) {
        fclose(f);
        return 0;
    }
    fclose(f);

    // Open /proc/net/ipv6_route
    f = fopen("/proc/net/ipv6_route", "r");
    if (!f) {
        perror("open /proc/net/ipv6_route");
        return 0;
    }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char dest[33], plen[3], src[33], splen[3], nexthop[33];
        unsigned long metric, refcnt, use, flags, route_ifidx;

        int n = sscanf(line,
                       "%32s %2s %32s %2s %32s %lx %lx %lx %lx %lx",
                       dest, plen, src, splen, nexthop,
                       &metric, &refcnt, &use, &flags, &route_ifidx);

        if (n == 10) {
            // check default route (dest = all zero, plen = 00)
            if (strcmp(dest, "00000000000000000000000000000000") == 0 &&
                strcmp(plen, "00") == 0) {
                if ((int)route_ifidx == ifidx) {
                    fclose(f);
                    return 1;
                }
            }
        }
    }

    fclose(f);
    return 0;
}

std::vector<unsigned int> get_all_default_ifindexes() {
    std::vector<unsigned int> res;
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return res;
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name || !(ifa->ifa_flags & IFF_UP)) continue;

        unsigned int idx = if_nametoindex(ifa->ifa_name);

        // check dup
        if (std::find(res.begin(), res.end(), idx) != res.end())
            continue;

        if (has_default_route4(ifa->ifa_name) || has_default_route6(ifa->ifa_name)) {
            res.push_back(idx);
            std::cerr << "Found default route on " << ifa->ifa_name
                      << " (ifindex=" << idx << ")\n";
        }
    }

    freeifaddrs(ifaddr);
    return res;
}