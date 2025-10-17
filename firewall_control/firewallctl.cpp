#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include "cJSON.h"

#define SOCKET_PATH "/var/run/firewall.sock"
#define BUF_SIZE 4096

// ==============================
// 🔹 Utility: send JSON request
// ==============================
bool send_json_to_daemon(const char *json_str, char *response_buf, size_t resp_size) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return false;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock);
        return false;
    }

    if (write(sock, json_str, strlen(json_str)) < 0) {
        perror("write");
        close(sock);
        return false;
    }

    ssize_t len = read(sock, response_buf, resp_size - 1);
    if (len > 0)
        response_buf[len] = '\0';
    else
        response_buf[0] = '\0';

    close(sock);
    return true;
}

// =========================================
// 🔹 Build JSON command for add/del/list
// =========================================
char *build_add_rule_json(const char *src_ip, const char *dst_ip,
                          const char *src_port, const char *dst_port,
                          const char *protocol, const char *action) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "cmd", "add_rule");

    cJSON *rule = cJSON_CreateObject();
    cJSON_AddStringToObject(rule, "src_ip", src_ip);
    cJSON_AddStringToObject(rule, "dst_ip", dst_ip);
    cJSON_AddStringToObject(rule, "src_port", src_port);
    cJSON_AddStringToObject(rule, "dst_port", dst_port);
    cJSON_AddStringToObject(rule, "protocol", protocol);
    cJSON_AddStringToObject(rule, "action", action);

    cJSON_AddItemToObject(root, "rule", rule);

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json_str;
}

char *build_del_rule_json(const char *src_ip, const char *dst_ip,
                          const char *src_port, const char *dst_port,
                          const char *protocol, const char *action) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "cmd", "remove_rule");

    cJSON *rule = cJSON_CreateObject();
    cJSON_AddStringToObject(rule, "src_ip", src_ip);
    cJSON_AddStringToObject(rule, "dst_ip", dst_ip);
    cJSON_AddStringToObject(rule, "src_port", src_port);
    cJSON_AddStringToObject(rule, "dst_port", dst_port);
    cJSON_AddStringToObject(rule, "protocol", protocol);
    cJSON_AddStringToObject(rule, "action", action);

    cJSON_AddItemToObject(root, "rule", rule);

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json_str;
}

char *build_list_json(const char *config_path) {
    FILE *fp = fopen(config_path, "r");
    if (!fp) {
        perror("fopen");
        // Nếu chưa có file, trả về rỗng
        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "cmd", "list_rules");
        cJSON *rules = cJSON_CreateArray();
        cJSON_AddItemToObject(root, "rules", rules);
        char *empty_json = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
        return empty_json;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    rewind(fp);

    char *data = (char *)malloc(fsize + 1);
    if (!data) {
        fclose(fp);
        return NULL;
    }
    fread(data, 1, fsize, fp);
    data[fsize] = '\0';
    fclose(fp);
    cJSON *rule_array = cJSON_Parse(data);
    free(data);

    if (!rule_array || !cJSON_IsArray(rule_array)) {
        rule_array = cJSON_CreateArray();
    }

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "cmd", "list_rules");
    cJSON_AddItemToObject(root, "rules", rule_array);

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    return json_str;
}

// ==============================
// 🔹 CLI usage
// ==============================
void print_usage(const char *prog) {
    printf("Usage:\n");
    printf("  %s add --src_ip <ip> --dst_ip <ip> --src_port <p> --dst_port <p> --protocol <tcp|udp> --action <ALLOW|DENY>\n", prog);
    printf("  %s del <rule_id>\n", prog);
    printf("  %s list\n", prog);
}

// ==============================
// 🔹 main()
// ==============================
int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    char *cmd = argv[1];
    char response[BUF_SIZE];
    char *json_str = NULL;

    if (strcmp(cmd, "add") == 0) {
        const char *src_ip = "any", *dst_ip = "any";
        const char *src_port = "any", *dst_port = "any";
        const char *protocol = "TCP", *action = "ALLOW";

        for (int i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "--src_ip") && i + 1 < argc) src_ip = argv[++i];
            else if (!strcmp(argv[i], "--dst_ip") && i + 1 < argc) dst_ip = argv[++i];
            else if (!strcmp(argv[i], "--src_port") && i + 1 < argc) src_port = argv[++i];
            else if (!strcmp(argv[i], "--dst_port") && i + 1 < argc) dst_port = argv[++i];
            else if (!strcmp(argv[i], "--protocol") && i + 1 < argc) protocol = argv[++i];
            else if (!strcmp(argv[i], "--action") && i + 1 < argc) action = argv[++i];
        }

        json_str = build_add_rule_json(src_ip, dst_ip, src_port, dst_port, protocol, action);

    } else if (strcmp(cmd, "del") == 0) {
        const char *src_ip = "any", *dst_ip = "any";
        const char *src_port = "any", *dst_port = "any";
        const char *protocol = "TCP", *action = "ALLOW";

        for (int i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "--src_ip") && i + 1 < argc) src_ip = argv[++i];
            else if (!strcmp(argv[i], "--dst_ip") && i + 1 < argc) dst_ip = argv[++i];
            else if (!strcmp(argv[i], "--src_port") && i + 1 < argc) src_port = argv[++i];
            else if (!strcmp(argv[i], "--dst_port") && i + 1 < argc) dst_port = argv[++i];
            else if (!strcmp(argv[i], "--protocol") && i + 1 < argc) protocol = argv[++i];
            else if (!strcmp(argv[i], "--action") && i + 1 < argc) action = argv[++i];
        }
        json_str = build_del_rule_json(src_ip, dst_ip, src_port, dst_port, protocol, action);

    } else if (strcmp(cmd, "list") == 0) {
        json_str = build_list_json("/home/quang/lib/firewall_linux/build/firewall_configs.json");
        printf("%s\n", json_str);
    } else {
        print_usage(argv[0]);
        return 1;
    }

    if (!json_str) {
        fprintf(stderr, "Failed to build JSON.\n");
        return 1;
    }

    if (send_json_to_daemon(json_str, response, sizeof(response))) {
        printf("%s\n", response);
    } else {
        fprintf(stderr, "Failed to communicate with firewall_daemon.\n");
    }

    free(json_str);
    return 0;
}
