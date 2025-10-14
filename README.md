# T32: eBPF-based Packet Filtering and Firewall

## Overview

This project implements a custom packet filtering and firewall system using **eBPF** (extended Berkeley Packet Filter), a high-performance Linux kernel technology for programmable packet processing. The system provides real-time packet inspection, rule-based filtering, and traffic shaping, offering a modern alternative to tools like iptables. By leveraging eBPF's kernel-level capabilities, it achieves low-latency, high-throughput network security with dynamic rule updates.

### Key Features
- **Packet Inspection**: Analyzes packet headers and payloads to detect malicious or anomalous traffic.
- **Rule Engine**: Supports customizable rules for allowing/denying traffic based on IP, port, protocol, etc.
- **Traffic Shaping**: Implements bandwidth management through rate limiting and Quality of Service (QoS).
- **Innovation**: Utilizes eBPF for efficient kernel-level processing, enabling dynamic updates without service restarts.
- **Technologies**:
  - eBPF programs in **C** (compiled with LLVM/Clang).
  - Userspace tools in **Python** (using BCC or libbpf) or **Go** (using cilium/ebpf).
- **Difficulty**: Challenging, requiring system-level programming with kernel hooks (XDP, TC).

## Setup and Installation Guide

### Prerequisites
- **Operating System**: Linux (Ubuntu 20.04+ or equivalent, kernel 5.10+ for full eBPF support).
- **Dependencies**:
  - **LLVM/Clang**: `sudo apt install clang llvm`
  - **libbpf**: `sudo apt install libbpf-dev`
  - **BCC**: `sudo apt install bpfcc-tools libbpfcc-dev python3-bpfcc` (for Python userspace).
  - **Go**: Version 1.21+ [](https://go.dev/dl/) (for Go userspace).
  - **Python**: Version 3.10+ with pip (for Python userspace).
  - **Kernel Headers**: `sudo apt install linux-headers-$(uname -r)`
- **Optional Tools**:
  - **bpftool**: `sudo apt install linux-tools-common linux-tools-$(uname -r)`
  - **tcpdump** or **Wireshark**: For packet capture and testing.
- **Permissions**: Root access (`sudo`) required for eBPF program loading and network interface management.

### Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/quangrtit/firewall_linux
   cd firewall_linux
   cmake .. && make && sudo ./firewall_linux