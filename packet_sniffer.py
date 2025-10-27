#!/usr/bin/env python3
"""
Advanced Network Packet Sniffer
Live network traffic capture and analysis tool
"""

import os
import sys
import time
import threading
from collections import defaultdict, Counter
import argparse
from datetime import datetime
import subprocess

# Third-party imports
try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.dns import DNS
    from scapy.layers.http import HTTPRequest, HTTPResponse
    import numpy as np
except ImportError as e:
    print(f"Missing required dependencies: {e}")
    print("Please install with: sudo pip3 install scapy matplotlib numpy")
    sys.exit(1)

class NetworkPacketSniffer:
    def __init__(self, interface=None, filter_str="", max_packets=0, verbose=False):
        self.interface = interface
        self.filter_str = filter_str
        self.max_packets = max_packets
        self.verbose = verbose
        
        # Statistics
        self.packet_count = 0
        self.start_time = time.time()
        self.protocol_stats = defaultdict(int)
        self.source_ips = Counter()
        self.dest_ips = Counter()
        self.port_stats = defaultdict(lambda: defaultdict(int))
        self.packet_sizes = []
        
        # Real-time monitoring
        self.running = True
        self.captured_packets = []
        self.recent_activity = []
        
        # Thread control
        self.stats_thread = None
        
    def get_available_interfaces(self):
        """Get list of available network interfaces"""
        try:
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            interfaces = []
            for line in result.stdout.split('\n'):
                if ': ' in line and 'LOOPBACK' not in line:
                    ifname = line.split(': ')[1].split('@')[0]
                    if ifname and ifname != 'lo':
                        interfaces.append(ifname)
            return interfaces
        except:
            return ['eth0', 'wlan0']  # Fallback
    
    def detect_protocol(self, packet):
        """Detect and return the protocol of the packet"""
        if packet.haslayer(TCP):
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                return "HTTP"
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                return "HTTPS"
            elif packet[TCP].dport == 22 or packet[TCP].sport == 22:
                return "SSH"
            elif packet[TCP].dport == 53 or packet[TCP].sport == 53:
                return "DNS"
            elif packet[TCP].dport == 21 or packet[TCP].sport == 21:
                return "FTP"
            else:
                return "TCP"
        elif packet.haslayer(UDP):
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                return "DNS"
            elif packet[UDP].dport == 67 or packet[UDP].sport == 67:
                return "DHCP"
            elif packet[UDP].dport == 123 or packet[UDP].sport == 123:
                return "NTP"
            else:
                return "UDP"
        elif packet.haslayer(ICMP):
            return "ICMP"
        elif packet.haslayer(ARP):
            return "ARP"
        elif packet.haslayer(DNS):
            return "DNS"
        else:
            return "Other"
    
    def analyze_packet(self, packet):
        """Analyze a single packet and extract information"""
        analysis = {
            'timestamp': datetime.now(),
            'size': len(packet),
            'protocol': 'Unknown',
            'src_ip': 'Unknown',
            'dst_ip': 'Unknown',
            'src_port': None,
            'dst_port': None,
            'info': ''
        }
        
        # Ethernet layer
        if packet.haslayer(Ether):
            analysis['src_mac'] = packet[Ether].src
            analysis['dst_mac'] = packet[Ether].dst
        
        # IP layer
        if packet.haslayer(IP):
            analysis['src_ip'] = packet[IP].src
            analysis['dst_ip'] = packet[IP].dst
            analysis['ttl'] = packet[IP].ttl
            
            self.source_ips[packet[IP].src] += 1
            self.dest_ips[packet[IP].dst] += 1
        
        # Protocol detection
        protocol = self.detect_protocol(packet)
        analysis['protocol'] = protocol
        self.protocol_stats[protocol] += 1
        
        # TCP analysis
        if packet.haslayer(TCP):
            analysis['src_port'] = packet[TCP].sport
            analysis['dst_port'] = packet[TCP].dport
            analysis['flags'] = self.get_tcp_flags(packet[TCP].flags)
            
            self.port_stats['TCP'][packet[TCP].dport] += 1
            self.port_stats['TCP'][packet[TCP].sport] += 1
            
            # HTTP analysis
            if packet.haslayer(HTTPRequest):
                http = packet[HTTPRequest]
                analysis['info'] = f"HTTP Request: {http.Method.decode()} {http.Host.decode()}{http.Path.decode()}"
            elif packet.haslayer(HTTPResponse):
                analysis['info'] = "HTTP Response"
        
        # UDP analysis
        elif packet.haslayer(UDP):
            analysis['src_port'] = packet[UDP].sport
            analysis['dst_port'] = packet[UDP].dport
            
            self.port_stats['UDP'][packet[UDP].dport] += 1
            self.port_stats['UDP'][packet[UDP].sport] += 1
            
            # DNS analysis
            if packet.haslayer(DNS):
                dns = packet[DNS]
                if dns.qr == 0:  # Query
                    if dns.qd:
                        analysis['info'] = f"DNS Query: {dns.qd.qname.decode()}"
                else:  # Response
                    analysis['info'] = "DNS Response"
        
        # ICMP analysis
        elif packet.haslayer(ICMP):
            analysis['info'] = f"ICMP Type: {packet[ICMP].type}"
        
        # ARP analysis
        elif packet.haslayer(ARP):
            analysis['info'] = f"ARP {packet[ARP].op} - {packet[ARP].psrc} -> {packet[ARP].pdst}"
        
        return analysis
    
    def get_tcp_flags(self, flags):
        """Convert TCP flags to human-readable format"""
        flag_names = []
        if flags & 0x01: flag_names.append("FIN")
        if flags & 0x02: flag_names.append("SYN")
        if flags & 0x04: flag_names.append("RST")
        if flags & 0x08: flag_names.append("PSH")
        if flags & 0x10: flag_names.append("ACK")
        if flags & 0x20: flag_names.append("URG")
        return "/".join(flag_names) if flag_names else "None"
    
    def packet_handler(self, packet):
        """Callback function for each captured packet"""
        if not self.running:
            return
        
        self.packet_count += 1
        self.packet_sizes.append(len(packet))
        
        # Analyze packet
        analysis = self.analyze_packet(packet)
        self.captured_packets.append(analysis)
        self.recent_activity.append(analysis)
        
        # Keep only recent activity (last 100 packets for display)
        if len(self.recent_activity) > 100:
            self.recent_activity.pop(0)
        
        # Display packet info if verbose
        if self.verbose:
            self.display_packet_info(analysis)
        
        # Check if we've reached max packets
        if self.max_packets > 0 and self.packet_count >= self.max_packets:
            self.running = False
    
    def display_packet_info(self, analysis):
        """Display information about a single packet"""
        timestamp = analysis['timestamp'].strftime("%H:%M:%S")
        protocol = analysis['protocol']
        src_ip = analysis['src_ip']
        dst_ip = analysis['dst_ip']
        
        if analysis['src_port'] and analysis['dst_port']:
            port_info = f"{analysis['src_port']} -> {analysis['dst_port']}"
        else:
            port_info = ""
        
        info = analysis['info']
        size = analysis['size']
        
        print(f"{timestamp} | {protocol:6} | {src_ip:15} -> {dst_ip:15} | {port_info:12} | {size:4} bytes | {info}")
    
    def display_statistics(self):
        """Display comprehensive statistics"""
        os.system('clear')
        current_time = time.time()
        duration = current_time - self.start_time
        
        print("=" * 80)
        print(f"NETWORK PACKET SNIFFER - Running for {duration:.1f} seconds")
        print(f"Captured: {self.packet_count} packets | Interface: {self.interface}")
        print("=" * 80)
        
        # Protocol Statistics
        print("\n📊 PROTOCOL STATISTICS:")
        print("-" * 40)
        total_protocols = sum(self.protocol_stats.values())
        for protocol, count in sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_protocols * 100) if total_protocols > 0 else 0
            print(f"  {protocol:8}: {count:6} packets ({percentage:5.1f}%)")
        
        # Top Source IPs
        print("\n🌐 TOP SOURCE IP ADDRESSES:")
        print("-" * 40)
        for ip, count in self.source_ips.most_common(5):
            print(f"  {ip:15}: {count:6} packets")
        
        # Top Destination IPs
        print("\n🎯 TOP DESTINATION IP ADDRESSES:")
        print("-" * 40)
        for ip, count in self.dest_ips.most_common(5):
            print(f"  {ip:15}: {count:6} packets")
        
        # Port Statistics
        print("\n🔌 PORT ACTIVITY:")
        print("-" * 40)
        for proto in ['TCP', 'UDP']:
            if proto in self.port_stats:
                print(f"  {proto} Ports:")
                for port, count in sorted(self.port_stats[proto].items(), key=lambda x: x[1], reverse=True)[:3]:
                    print(f"    Port {port:5}: {count:6} packets")
        
        # Traffic Statistics
        if self.packet_sizes:
            avg_size = sum(self.packet_sizes) / len(self.packet_sizes)
            max_size = max(self.packet_sizes)
            min_size = min(self.packet_sizes)
            print(f"\n📈 TRAFFIC STATISTICS:")
            print("-" * 40)
            print(f"  Average packet size: {avg_size:.1f} bytes")
            print(f"  Min/Max packet size: {min_size}/{max_size} bytes")
            print(f"  Packets per second:  {self.packet_count / duration:.1f}")
            print(f"  Data rate:           {(sum(self.packet_sizes) / duration / 1024):.1f} KB/s")
        
        # Recent Activity
        print(f"\n🔄 RECENT ACTIVITY (last {len(self.recent_activity)} packets):")
        print("-" * 80)
        for packet in self.recent_activity[-10:]:  # Show last 10 packets
            self.display_packet_info(packet)
        
        print(f"\nPress Ctrl+C to stop sniffing...")
    
    def start_statistics_display(self):
        """Start the periodic statistics display"""
        while self.running:
            self.display_statistics()
            time.sleep(2)  # Update every 2 seconds
    
    def start_sniffing(self):
        """Start the packet sniffing process"""
        print(f"Starting packet sniffer on interface {self.interface}...")
        print(f"Filter: {self.filter_str if self.filter_str else 'None'}")
        print("Press Ctrl+C to stop\n")
        
        # Start statistics display in separate thread
        self.stats_thread = threading.Thread(target=self.start_statistics_display)
        self.stats_thread.daemon = True
        self.stats_thread.start()
        
        try:
            # Start packet capture
            sniff(
                iface=self.interface,
                filter=self.filter_str,
                prn=self.packet_handler,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except KeyboardInterrupt:
            print("\nStopping packet sniffer...")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            self.running = False
            self.display_final_statistics()
    
    def display_final_statistics(self):
        """Display final statistics when stopping"""
        print("\n" + "=" * 80)
        print("FINAL STATISTICS")
        print("=" * 80)
        
        duration = time.time() - self.start_time
        
        print(f"Total duration: {duration:.1f} seconds")
        print(f"Total packets:  {self.packet_count}")
        print(f"Average rate:   {self.packet_count / duration:.1f} packets/sec")
        
        if self.packet_sizes:
            total_data = sum(self.packet_sizes)
            print(f"Total data:     {total_data / 1024 / 1024:.2f} MB")
            print(f"Data rate:      {total_data / duration / 1024:.1f} KB/s")
        
        print("\nProtocol Distribution:")
        for protocol, count in sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / self.packet_count * 100) if self.packet_count > 0 else 0
            print(f"  {protocol:8}: {count:6} packets ({percentage:5.1f}%)")

def main():
    parser = argparse.ArgumentParser(description="Advanced Network Packet Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on")
    parser.add_argument("-f", "--filter", default="", help="BPF filter string")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output (show each packet)")
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("Error: This script requires root privileges for packet capture.")
        print("Please run with: sudo python3 packet_sniffer.py")
        sys.exit(1)
    
    # Get interface if not specified
    if not args.interface:
        sniffer = NetworkPacketSniffer()
        interfaces = sniffer.get_available_interfaces()
        if interfaces:
            print("Available interfaces:")
            for i, iface in enumerate(interfaces):
                print(f"  {i + 1}. {iface}")
            try:
                choice = int(input("Select interface (number): ")) - 1
                args.interface = interfaces[choice]
            except (ValueError, IndexError):
                print("Invalid selection. Using first available interface.")
                args.interface = interfaces[0] if interfaces else 'eth0'
        else:
            args.interface = 'eth0'
    
    # Create and start sniffer
    sniffer = NetworkPacketSniffer(
        interface=args.interface,
        filter_str=args.filter,
        max_packets=args.count,
        verbose=args.verbose
    )
    
    sniffer.start_sniffing()

if __name__ == "__main__":
    main()
