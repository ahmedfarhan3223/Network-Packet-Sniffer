# Network-Packet-Sniffer

# Installation Requirements

First, install the required dependencies:

sudo apt update
sudo apt install python3 python3-pip
sudo pip3 install scapy matplotlib numpy

# Usage
chmod +x packet_sniffer.py
sudo ./packet_sniffer.py

**Command Line Options:**

Basic usage (will show interface selection)
sudo ./packet_sniffer.py

Sniff on specific interface
sudo ./packet_sniffer.py -i eth0

Capture only HTTP traffic
sudo ./packet_sniffer.py -f "tcp port 80"

Capture traffic from specific host
sudo ./packet_sniffer.py -f "host 192.168.1.100"

Capture limited number of packets
sudo ./packet_sniffer.py -c 100

Verbose mode (show each packet)
sudo ./packet_sniffer.py -v

Complex filter
sudo ./packet_sniffer.py -f "tcp and not port 22"

# Features

This packet sniffer provides:

Live Packet Capture: Real-time network traffic monitoring

Protocol Detection: Identifies TCP, UDP, ICMP, ARP, DNS, HTTP, etc.

Comprehensive Statistics:

Protocol distribution

Top source/destination IPs

Port activity

Traffic rates and volumes

Real-time Monitoring: Live updating display every 2 seconds

BPF Filter Support: Use standard tcpdump-style filters

Packet Analysis: Detailed information for each protocol type

Interactive Interface Selection: Choose from available interfaces

# Advanced Features

The tool also includes:

TCP Flag Analysis: Shows SYN, ACK, FIN, RST flags

HTTP Request/Response Detection

DNS Query/Response Analysis

Traffic Rate Calculation: Packets/sec and data rate

Color-coded output (can be enhanced with colorama library)

Thread-safe operation for smooth real-time updates
