#ifndef CONNECTION_H
#define CONNECTION_H

#include <string>
#include <thread>
#include <atomic>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "common_user.h"
extern "C" {
    #include "firewall.skel.h"
}
class UnixServer {
public:
    UnixServer(const std::string &socket_path, struct firewall_bpf *skel, volatile sig_atomic_t* external_exit);
    ~UnixServer();

    bool start();
    void stop();

private:
    void run();
    void handleClient(int client_fd);

    std::string socket_path_;
    int server_fd_;
    std::thread server_thread_;
    volatile sig_atomic_t* exiting;
    std::atomic<bool> running_;
    struct firewall_bpf *skel_;
};

#endif // CONNECTION_H