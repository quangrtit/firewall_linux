#ifndef __UTILS_H
#define __UTILS_H

#include "common_user.h"
extern "C" {
    #include "firewall.skel.h"
}

__u8 parse_protocol(const char *proto);

void parse_ip_lpm(const char *ip_str, struct ip_lpm_key *key, __u8 *ip_version);

int load_firewall_rules_into_map(struct firewall_bpf *skel, int map_fd, const char *json_path);

int has_default_route4(const char *ifname);

int has_default_route6(const char *ifname);

std::vector<unsigned int> get_all_default_ifindexes();

bool append_rule_to_json(const char *filepath,
                         const char *src_ip,
                         const char *dst_ip,
                         const char *src_port,
                         const char *dst_port,
                         const char *protocol,
                         const char *action);
#endif // __UTILS_H