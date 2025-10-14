#ifndef __UTILS_H
#define __UTILS_H

#include "common_user.h"
extern "C" {
    #include "firewall.skel.h"
}

int has_default_route4(const char *ifname);

int has_default_route6(const char *ifname);

std::vector<unsigned int> get_all_default_ifindexes();

#endif // __UTILS_H