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

// ===== Security / crypto =====
#include <openssl/sha.h>
#include <openssl/evp.h>

// ===== eBPF / networking =====
#include <bpf/libbpf.h>
#include <linux/types.h>

// ===== JSON config =====
#include <cjson/cJSON.h>