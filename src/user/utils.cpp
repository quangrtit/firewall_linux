#include "utils.h"
#include <sys/sysmacros.h>
#include <errno.h>
#include <unistd.h> 
#include <sys/stat.h>


// Convert "TCP", "UDP", "ICMP" to corresponding numeric codes
__u8 parse_protocol(const char *proto) {
    if (!proto) return 0;
    if (strcasecmp(proto, "TCP") == 0)  return IPPROTO_TCP;
    if (strcasecmp(proto, "UDP") == 0)  return IPPROTO_UDP;
    if (strcasecmp(proto, "ICMP") == 0) return IPPROTO_ICMP;
    return 0;
}

// Parse IP string (IPv4/IPv6/"any")
void parse_ip_lpm(const char *ip_str, struct ip_lpm_key *key, __u8 *ip_version) {
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

int load_firewall_rules_into_map(struct firewall_bpf *skel, int map_fd, const char *json_path) {
    FILE *fp = fopen(json_path, "r");
    if (!fp) {
        fprintf(stderr, "Error opening policy file '%s': %s\n", json_path, strerror(errno));
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *json_string = (char *)malloc(fsize + 1);
    if (!json_string) {
        fclose(fp);
        return -1;
    }
    fread(json_string, 1, fsize, fp);
    fclose(fp);
    json_string[fsize] = '\0';

    cJSON *root = cJSON_Parse(json_string);
    free(json_string);
    if (!root) {
        fprintf(stderr, "Error parsing JSON\n");
        return -1;
    }

    int rule_count = cJSON_GetArraySize(root);
    for (int i = 0; i < rule_count; i++) {
        cJSON *item = cJSON_GetArrayItem(root, i);
        if (!cJSON_IsObject(item)) continue;

        const char *src_ip   = cJSON_GetObjectItem(item, "src_ip")->valuestring;
        const char *dst_ip   = cJSON_GetObjectItem(item, "dst_ip")->valuestring;
        const char *src_port = cJSON_GetObjectItem(item, "src_port")->valuestring;
        const char *dst_port = cJSON_GetObjectItem(item, "dst_port")->valuestring;
        const char *proto    = cJSON_GetObjectItem(item, "protocol")->valuestring;
        const char *action   = cJSON_GetObjectItem(item, "action")->valuestring;

        enum ip_status verdict = (strcasecmp(action, "DENY") == 0) ? DENY : ALLOW;

        /* -------------------- Full map -------------------- */
        struct rule_key full_key = {};
        parse_ip_lpm(src_ip, &full_key.src, &full_key.ip_version);
        // parse_ip_lpm(dst_ip, &full_key.dst, &full_key.ip_version);

        full_key.src_port = (strcmp(src_port, "any") == 0) ? 0 : (__u16)atoi(src_port);
        // full_key.dst_port = (strcmp(dst_port, "any") == 0) ? 0 : (__u16)atoi(dst_port);
        full_key.protocol = parse_protocol(proto);
        if (bpf_map__update_elem(skel->maps.rules_map, &full_key, sizeof(full_key), &verdict, sizeof(verdict), BPF_ANY) != 0) {
            perror("Failed to insert into rules_map");
        }

        // /* -------------------- IP-only map -------------------- */
        // if (strcmp(proto, "any") == 0 || strcmp(src_port, "any") == 0) {
        //     struct ip_lpm_key ip_key = {};
        //     __u8 ip_ver = 0;
        //     parse_ip_lpm(src_ip, &ip_key, &ip_ver);
        //     if (bpf_map__update_elem(skel->maps.rules_map_only_ip, &ip_key, sizeof(ip_key), &verdict, sizeof(verdict), BPF_ANY) != 0) {
        //         perror("Failed to insert into rules_map_only_ip");
        //     }
        // }

        // /* -------------------- Port-only map -------------------- */
        // if (strcmp(src_ip, "any") == 0 ||strcmp(proto, "any") == 0) {
        //     __u16 port = (__u16)atoi(src_port);
        //     if (bpf_map__update_elem(skel->maps.rules_map_only_port, &port, sizeof(port), &verdict, sizeof(verdict), BPF_ANY) != 0) {
        //         perror("Failed to insert into rules_map_only_port");
        //     }
        // }

        // /* -------------------- Protocol-only map -------------------- */
        // if (strcmp(src_ip, "any") == 0 && strcmp(src_port, "any") == 0) {
        //     __u8 p = parse_protocol(proto);
        //     if (bpf_map__update_elem(skel->maps.rules_map_only_protocol, &p, sizeof(p), &verdict, sizeof(verdict), BPF_ANY) != 0) {
        //         perror("Failed to insert into rules_map_only_protocol");
        //     }
        // }

        printf("Loaded rule %d: %s:%s -> %s:%s (%s) = %s\n",
               i, src_ip, src_port, dst_ip, dst_port, proto, action);
    }

    cJSON_Delete(root);
    return 0;
}
// int load_firewall_rules_into_map(struct firewall_bpf *skel, int map_fd, const char *json_path) {
//     FILE *fp = fopen(json_path, "r");
//     if (fp == NULL) {
//         fprintf(stderr, "[user space policy_manager.cpp] Error: Could not open policy file '%s': %s\n", json_path, strerror(errno));
//         return -1;
//     }

//     fseek(fp, 0, SEEK_END);
//     long fsize = ftell(fp);
//     fseek(fp, 0, SEEK_SET);
//     char *json_string = (char*)malloc(fsize + 1);
//     fread(json_string, 1, fsize, fp);
//     fclose(fp);
//     json_string[fsize] = '\0';
//     cJSON *root = cJSON_Parse(json_string);
//     if (root == NULL) {
//         const char *error_ptr = cJSON_GetErrorPtr();
//         if (error_ptr != NULL) {
//             fprintf(stderr, "[user space policy_manager.cpp] Error parsing JSON: %s\n", error_ptr);
//         }
//         free(json_string);
//         return -1;
//     }

//     int rule_count = cJSON_GetArraySize(root);
//     for (int i = 0; i < rule_count; i++) {
//         cJSON *item = cJSON_GetArrayItem(root, i);
//         if (!cJSON_IsObject(item)) continue;

//         struct rule_key key = {};
//         enum ip_status verdict = ALLOW;

//         const char *src_ip   = cJSON_GetObjectItem(item, "src_ip")->valuestring;
//         const char *dst_ip   = cJSON_GetObjectItem(item, "dst_ip")->valuestring;
//         const char *src_port = cJSON_GetObjectItem(item, "src_port")->valuestring;
//         const char *dst_port = cJSON_GetObjectItem(item, "dst_port")->valuestring;
//         const char *proto    = cJSON_GetObjectItem(item, "protocol")->valuestring;
//         const char *action   = cJSON_GetObjectItem(item, "action")->valuestring;

//         parse_ip_lpm(src_ip, &key.src, &key.ip_version);
//         //parse_ip_lpm(dst_ip, &key.dst, &key.ip_version);

//         key.src_port = (strcmp(src_port, "any") == 0) ? 0 : (__u16)atoi(src_port);
//         //key.dst_port = (strcmp(dst_port, "any") == 0) ? 0 : (__u16)atoi(dst_port);
//         key.protocol = parse_protocol(proto);
//         verdict = (strcasecmp(action, "DENY") == 0) ? DENY : ALLOW;
//         printf("Loaded rule %d: %s:%s -> %s:%s (%s) = %s\n",
//                    i, src_ip, src_port, dst_ip, dst_port, proto, action);
//         if (bpf_map__update_elem(
//                 skel->maps.rules_map,
//                 &key, sizeof(key),
//                 &verdict, sizeof(verdict),
//                 BPF_ANY) != 0) {
//             perror("bpf_map__update_elem false\n");
//         }
//         else {
//             // printf("Loaded rule %d: %s:%s -> %s:%s (%s) = %s\n",
//             //        i, src_ip, src_port, dst_ip, dst_port, proto, action);
//         }
//     }

//     cJSON_Delete(root);
//     return 0;
// }
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

bool append_rule_to_json(const char *filepath,
                         const char *src_ip,
                         const char *dst_ip,
                         const char *src_port,
                         const char *dst_port,
                         const char *protocol,
                         const char *action)
{
    std::ifstream in(filepath);
    std::string content((std::istreambuf_iterator<char>(in)),
                         std::istreambuf_iterator<char>());
    in.close();

    cJSON *root = nullptr;
    if (content.empty()) {
        root = cJSON_CreateArray();
    } else {
        root = cJSON_Parse(content.c_str());
        if (!root || !cJSON_IsArray(root)) {
            if (root) cJSON_Delete(root);
            root = cJSON_CreateArray(); 
        }
    }

    cJSON *rule = cJSON_CreateObject();
    cJSON_AddStringToObject(rule, "src_ip", src_ip);
    cJSON_AddStringToObject(rule, "dst_ip", dst_ip);
    cJSON_AddStringToObject(rule, "src_port", src_port);
    cJSON_AddStringToObject(rule, "dst_port", dst_port);
    cJSON_AddStringToObject(rule, "protocol", protocol);
    cJSON_AddStringToObject(rule, "action", action);

    cJSON_AddItemToArray(root, rule);

    char *out = cJSON_Print(root);
    std::ofstream outFile(filepath, std::ios::trunc);
    outFile << out;
    outFile.close();

    cJSON_Delete(root);
    free(out);

    return true;
}