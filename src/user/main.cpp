#include "common_user.h"

extern "C" {
    #include "firewall.skel.h"
}
#include "utils.h"

static volatile sig_atomic_t exiting = 0;
static int ifindex;

static int handle_firewall_event(void *ctx, void *data, size_t data_sz) {
    const struct ioc_event *evt = (const struct ioc_event *)data;
    // CallbackContext *rb_ctx = (CallbackContext*)ctx; // will use in the future
    // Convert timestamp
    struct timespec ts;
    char timestamp_str[32];
    ts.tv_sec = evt->timestamp_ns / 1000000000ULL;
    ts.tv_nsec = evt->timestamp_ns % 1000000000ULL;
    strftime(timestamp_str, sizeof(timestamp_str), "%H:%M:%S", localtime(&ts.tv_sec));
    snprintf(timestamp_str + strlen(timestamp_str),
             sizeof(timestamp_str) - strlen(timestamp_str),
             ".%06lu", ts.tv_nsec / 1000);

    // Firewall event type
    const char *type_str = "UNKNOWN";
    if (evt->type == FIREWALL_EVT_BLOCKED_IP) type_str = "NET_BLOCKED";
    else if (evt->type == FIREWALL_EVT_CONNECT_IP) type_str = "NET_CONNECTED";
  
    // use std::cerr all
    switch (evt->type) {
        case FIREWALL_EVT_BLOCKED_IP:
            char ip_str[INET6_ADDRSTRLEN];
            if (evt->net.family == AF_INET) {
                // IPv4
                struct in_addr addr4;
                addr4.s_addr = evt->net.saddr_v4;
                inet_ntop(AF_INET, &addr4, ip_str, sizeof(ip_str));
            } else if (evt->net.family == AF_INET6) {
                struct in6_addr addr6;
                memcpy(&addr6, evt->net.saddr_v6, sizeof(addr6));
                if (inet_ntop(AF_INET6, &addr6, ip_str, sizeof(ip_str)) == NULL) {
                    perror("inet_ntop");
                    snprintf(ip_str, sizeof(ip_str), "InvalidIPv6");

                }
            } else {
                snprintf(ip_str, sizeof(ip_str), "UnknownFamily");
                
            }
            
            std::cerr << "[PACKET CONNECT_EVENT_BLOCKED] " << (evt->net.family == AF_INET ? "AF_INET" : "AF_INET6")
                      << " protocol=" << (evt->net.protocol == 6 ? "TCP" : "UDP")
                      << " -> " << ip_str << ":" << evt->net.src_port << std::endl;

            break;
        // case FIREWALL_EVT_BLOCKED_IP:
        //     char ip_str2[INET6_ADDRSTRLEN];
        //     if (evt->net.family == AF_INET) {
        //         // IPv4
        //         struct in_addr addr4;
        //         addr4.s_addr = evt->net.saddr_v4;   
        //         inet_ntop(AF_INET, &addr4, ip_str2, sizeof(ip_str2));
        //     } else if (evt->net.family == AF_INET6) {
        //         struct in6_addr addr6;
        //         memcpy(&addr6, evt->net.saddr_v6, sizeof(addr6));   
        //         if (inet_ntop(AF_INET6, &addr6, ip_str2, sizeof(ip_str2)) == NULL) {
        //             perror("inet_ntop");
        //             snprintf(ip_str2, sizeof(ip_str2), "InvalidIPv6");
        //         }
        //     } else {
        //         snprintf(ip_str2, sizeof(ip_str2), "UnknownFamily");
        //     }
        default:
            // std::cerr << "Unknown FIREWALL type" << std::endl;
            break;
    }
    return 0;
}

void *firewall_thread(void *arg) {
    struct ring_buffer *rb = (struct ring_buffer*)arg;
    while (!exiting) {
        int err = ring_buffer__poll(rb, 10); 
        if (err < 0) {
            fprintf(stderr, "Error polling firewall: %d\n", err);
            break;
        }
    }
    return NULL;
}
static void sig_handler(int sig) {
    exiting = 1;
    printf("[Signal Handler] Received signal %d but ignoring.\n", sig);
}

int main() {
    CallbackContext rb_ctx;
    pthread_t firewall_thread_id;
    struct firewall_bpf *skel_firewall = NULL;
    struct ring_buffer *rb_firewall = NULL;
    int err_all; 
    std::vector<unsigned int> all_val;
    pid_t pid = getpid();         // Process ID
    pid_t ppid = getppid();       // Parent PID
    char process_name[17] = {0};
    prctl(PR_GET_NAME, (unsigned long)process_name);
    
    // Load and verify BPF program
    skel_firewall = firewall_bpf__open_and_load();
    if (!skel_firewall) {
        std::cerr << "Failed to open and load BPF skeleton" << std::endl;
        goto cleanup;
    }
    err_all = load_firewall_rules_into_map(skel_firewall, bpf_map__fd(skel_firewall->maps.rules_map), "firewall_configs.json");
    // Attach XDP program
    err_all = firewall_bpf__attach(skel_firewall);
    ifindex = if_nametoindex("ens33"); 
    bpf_program__attach_xdp(skel_firewall->progs.xdp_block, ifindex);
    all_val = get_all_default_ifindexes();
    if(err_all) {
        std::cerr << "Failed to attach BPF program to interface ens33" << std::endl;
        goto cleanup;
    }
    std::cerr << "Welcome to the Firewall Linux Project!" << std::endl;
    // Set up ring buffer to receive events
    rb_firewall = ring_buffer__new(bpf_map__fd(skel_firewall->maps.firewall_events),
                                   handle_firewall_event,
                                   &rb_ctx,
                                   NULL);
    if (!rb_firewall) {
        std::cerr << "Failed to create ring buffer for firewall events" << std::endl;
        goto cleanup;
    }
    std::cerr <<  "PID: " << pid << ", Name: " << process_name << " [user space main.c] Watching for network events... Ctrl+C to stop." << std::endl;
    if (pthread_create(&firewall_thread_id, NULL, firewall_thread, rb_firewall) != 0) {
        std::cerr << "Failed to create firewall thread" << std::endl;
    }
    while (!exiting) {
        sleep(1);
    }
    pthread_join(firewall_thread_id, NULL);
cleanup:
    if (rb_firewall) {
        ring_buffer__free(rb_firewall);
    }
    if (skel_firewall) {
        firewall_bpf__destroy(skel_firewall);
    }
    return 0;
}
//https://medium.com/@seantywork/firewall-iptables-netfilter-kernel-module-and-ebpf-xdp-b7a563711ee6