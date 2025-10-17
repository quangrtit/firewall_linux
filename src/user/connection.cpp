#include "connection.h"
#include "utils.h"
#include <iostream>
#include <cstring>
#include <fcntl.h>
#include <sys/sysmacros.h>
#include <errno.h>
#include <unistd.h> 
#include <sys/stat.h>

UnixServer::UnixServer(const std::string &socket_path, struct firewall_bpf *skel, volatile sig_atomic_t* external_exit)
    : socket_path_(socket_path),
      server_fd_(-1),
      exiting(external_exit),
      running_(false),
      skel_(skel) {}

UnixServer::~UnixServer() {
    stop();
}

bool UnixServer::start() {
    if (running_) return true;  // đang chạy rồi thì không start lại

    server_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd_ < 0) {
        perror("socket");
        return false;
    }

    unlink(socket_path_.c_str()); // xóa socket cũ

    struct sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    if (bind(server_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd_);
        return false;
    }

    if (listen(server_fd_, 5) < 0) {
        perror("listen");
        close(server_fd_);
        return false;
    }

    running_ = true;
    server_thread_ = std::thread(&UnixServer::run, this);
    return true;
}

void UnixServer::stop() {
    if (!running_) return;

    running_ = false;
    shutdown(server_fd_, SHUT_RDWR);
    close(server_fd_);
    server_fd_ = -1;

    if (server_thread_.joinable())
        server_thread_.join();

    unlink(socket_path_.c_str());
    std::cerr << "[UnixServer] Cleanly stopped.\n";
}

void UnixServer::run() {
    std::cerr << "[UnixServer] Listening on " << socket_path_ << std::endl;

    while (running_ && !(*exiting)) {
        int client_fd = accept(server_fd_, nullptr, nullptr);
        if (client_fd < 0) {
            if (running_ && !(*exiting))
                perror("accept");
            continue;
        }
        handleClient(client_fd);
        close(client_fd);
    }

    std::cerr << "[UnixServer] Listener loop exited.\n";
}

void UnixServer::handleClient(int client_fd) {
    char buf[1024];
    ssize_t n = read(client_fd, buf, sizeof(buf) - 1);
    if (n <= 0) return;

    buf[n] = '\0';
    std::string request(buf);
    std::cerr << "[UnixServer] Received: " << request << std::endl;


    // TODO: parse JSON request ở đây
    // - Cập nhật firewall_configs.json
    // - Gọi bpf_map_update_elem() hoặc bpf_map_delete_elem()

    cJSON *root = cJSON_Parse(request.c_str());
    if (!root) {
        std::string err = "{\"status\":\"error\",\"msg\":\"invalid_json\"}";
        write(client_fd, err.c_str(), err.size());
        return;
    }

    const cJSON *cmd = cJSON_GetObjectItem(root, "cmd");
    if (!cmd || !cJSON_IsString(cmd)) {
        cJSON_Delete(root);
        std::string err = "{\"status\":\"error\",\"msg\":\"missing_cmd\"}";
        write(client_fd, err.c_str(), err.size());
        return;
    }

    std::string command = cmd->valuestring;
    if (command == "add_rule") {
        cJSON *rule = cJSON_GetObjectItem(root, "rule");
        if (!rule) {
            std::string err = "{\"status\":\"error\",\"msg\":\"missing_rule\"}";
            write(client_fd, err.c_str(), err.size());
            cJSON_Delete(root);
            return;
        }

        const char *src_ip   = cJSON_GetObjectItem(rule, "src_ip")->valuestring;
        const char *dst_ip   = cJSON_GetObjectItem(rule, "dst_ip")->valuestring;
        const char *src_port = cJSON_GetObjectItem(rule, "src_port")->valuestring;
        const char *dst_port = cJSON_GetObjectItem(rule, "dst_port")->valuestring;
        const char *protocol = cJSON_GetObjectItem(rule, "protocol")->valuestring;
        const char *action   = cJSON_GetObjectItem(rule, "action")->valuestring;

        struct rule_key key {};
        parse_ip_lpm(src_ip, &key.src, &key.ip_version);
        parse_ip_lpm(dst_ip, &key.dst, &key.ip_version);

        key.src_port = (strcmp(src_port, "any") == 0) ? 0 : (__u16)atoi(src_port);
        key.dst_port = (strcmp(dst_port, "any") == 0) ? 0 : (__u16)atoi(dst_port);
        key.protocol = parse_protocol(protocol);

        enum ip_status verdict = (strcasecmp(action, "ALLOW") == 0) ? ALLOW : DENY;
        append_rule_to_json("firewall_configs.json",
                            src_ip, dst_ip,
                            src_port, dst_port,
                            protocol, action);

        if (bpf_map__update_elem(
                skel_->maps.rules_map,
                &key, sizeof(key),
                &verdict, sizeof(verdict),
                BPF_ANY) != 0) {
            perror("bpf_map__update_elem false\n");
        }
        else {
            std::cerr << "updated BPF map rule\n";
        }

        std::string ok = "{\"status\":\"ok\"}";
        write(client_fd, ok.c_str(), ok.size());
    }
    else if (command == "remove_rule") {
        cJSON *rule = cJSON_GetObjectItem(root, "rule");
        if (!rule) {
            std::string err = "{\"status\":\"error\",\"msg\":\"missing_rule\"}";
            write(client_fd, err.c_str(), err.size());
            cJSON_Delete(root);
            return;
        }

        const char *src_ip   = cJSON_GetObjectItem(rule, "src_ip")->valuestring;
        const char *dst_ip   = cJSON_GetObjectItem(rule, "dst_ip")->valuestring;
        const char *src_port = cJSON_GetObjectItem(rule, "src_port")->valuestring;
        const char *dst_port = cJSON_GetObjectItem(rule, "dst_port")->valuestring;
        const char *protocol = cJSON_GetObjectItem(rule, "protocol")->valuestring;

        struct rule_key key {};
        parse_ip_lpm(src_ip, &key.src, &key.ip_version);
        parse_ip_lpm(dst_ip, &key.dst, &key.ip_version);

        key.src_port = (strcmp(src_port, "any") == 0) ? 0 : (__u16)atoi(src_port);
        key.dst_port = (strcmp(dst_port, "any") == 0) ? 0 : (__u16)atoi(dst_port);
        key.protocol = parse_protocol(protocol);

        if (bpf_map__delete_elem(
                skel_->maps.rules_map,
                &key, sizeof(key), 0) != 0) {
            perror("bpf_map__delete_elem false\n");
        }
        else {
            std::cerr << "removed BPF map rule\n";
        }

        std::string ok = "{\"status\":\"ok\"}";
        write(client_fd, ok.c_str(), ok.size());
    }
    else {
        std::string err = "{\"status\":\"error\",\"msg\":\"unknown_cmd\"}";
        write(client_fd, err.c_str(), err.size());
    }
    cJSON_Delete(root);
}