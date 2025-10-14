#include "utils.h"



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