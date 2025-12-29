#!/usr/bin/env python3
"""
B01 - Port Scanner Python
Advanced Multi-threaded Port Scanner for Penetration Testing
Author: dinoZ0G1
Full Domain Resolution + Reverse DNS + Multiple A Records
"""

import socket
import threading
import argparse
import sys
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from itertools import product

class PortScanner:
    def __init__(self, targets, ports=None, timeout=1):
        self.original_targets = targets
        self.targets = self._parse_targets(targets)
        self.ports = ports or range(1, 1001)
        self.timeout = timeout
        self.results = []
        self.resolved_targets = {}
        self.lock = threading.Lock()
        
        # Common ports mapping
        self.service_names = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 993: "IMAPS", 995: "POP3S",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }

    def _resolve_domain(self, target):
        """Resolve domain to IP(s) + Reverse DNS"""
        try:
            # Resolve domain to IP(s)
            ips = socket.getaddrinfo(target, None, socket.AF_INET)
            unique_ips = list(set([ip[4][0] for ip in ips]))
            
            resolved = []
            for ip in unique_ips:
                try:
                    # Reverse DNS lookup
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = "Unknown"
                
                resolved.append((ip, hostname))
                self.resolved_targets[target] = resolved
            
            return [ip for ip, _ in resolved]
        except:
            # Fallback to single IP if resolution fails
            try:
                ip = socket.gethostbyname(target)
                self.resolved_targets[target] = [(ip, target)]
                return [ip]
            except:
                return [target]  # Keep original if can't resolve

    def _parse_targets(self, target_input):
        """Parse IP ranges, CIDR, domains, comma-separated targets"""
        targets = []
        
        for target in target_input.split(','):
            target = target.strip()
            
            # Single IP/hostname/domain
            if '/' not in target and '-' not in target:
                print(f"🔍 Resolving {target}...")
                resolved_ips = self._resolve_domain(target)
                targets.extend(resolved_ips)
                print(f"   📍 Found {len(resolved_ips)} IP(s): {', '.join(resolved_ips)}")
            
            # CIDR notation (192.168.1.0/24)
            elif '/' in target:
                network = ipaddress.IPv4Network(target, strict=False)
                targets.extend([str(ip) for ip in network.hosts()])
            
            # IP range (192.168.1.1-254)
            elif '-' in target:
                if target.count('.') == 3:  # 192.168.1.1-254
                    base = '.'.join(target.split('.')[:3]) + '.'
                    start, end = target.split('-')
                    start_num = int(start.split('.')[-1])
                    end_num = int(end)
                    targets.extend([base + str(i) for i in range(start_num, end_num + 1)])
                else:  # Full IP range
                    start_ip, end_ip = target.split('-')
                    start = ipaddress.IPv4Address(start_ip.strip())
                    end = ipaddress.IPv4Address(end_ip.strip())
                    diff = int(end) - int(start)
                    targets.extend([str(ipaddress.IPv4Address(int(start) + i)) for i in range(diff + 1)])
        
        return list(set(targets))  # Remove duplicates

    def scan_port(self, target_port):
        """Scan single port on single target"""
        target, port = target_port
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, port))
            
            if result == 0:
                service = self.service_names.get(port, "Unknown")
                with self.lock:
                    self.results.append((target, port, service))
                print(f"✅ {target}:{port}/{self._get_port_state(port)} ({service})")
            sock.close()
        except:
            pass

    def _get_port_state(self, port):
        """Get port state"""
        return "tcp"

    def scan(self, threads=200):
        """Scan all targets/ports with multi-threading"""
        total_scans = len(self.targets) * len(self.ports)
        print(f"\n🔍 Scanning {len(self.targets)} targets ({total_scans:,} total ports)")
        print(f"⏱️  Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Create all target-port combinations
        scan_tasks = list(product(self.targets, self.ports))
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(self.scan_port, scan_tasks)
        
        print(f"\n📊 Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        return self.results

    def print_results(self):
        """Print formatted results by target with reverse DNS"""
        if not self.results:
            print("❌ No open ports found")
            return
        
        # Group results by target
        results_by_target = {}
        for target, port, service in self.results:
            if target not in results_by_target:
                results_by_target[target] = []
            results_by_target[target].append((port, service))
        
        print(f"\n🎯 {len(self.results)} open ports found across {len(results_by_target)} hosts:")
        print("=" * 80)
        print(f"{'IP Address':<16} {'Hostname':<25} {'Open Ports':<12} {'Services'}")
        print("-" * 80)
        
        for target_ip in sorted(results_by_target.keys()):
            ports = results_by_target[target_ip]
            port_list = ', '.join([f"{p[0]}" for p in ports])
            services = ', '.join([p[1] for p in ports])
            
            # Find hostname from resolution cache
            hostname = "Unknown"
            for orig_target, resolved in self.resolved_targets.items():
                for ip, host in resolved:
                    if ip == target_ip:
                        hostname = host
                        break
            
            print(f"{target_ip:<16} {hostname:<25} {len(ports):2d} ports  {port_list[:30]}{'...' if len(port_list)>30 else ''}")
        
        print("-" * 80)
        print(f"Author: dinoZ0G1")

def main():
    parser = argparse.ArgumentParser(
        description="Advanced IP Range + Domain Port Scanner",
        epilog="Author: dinoZ0G1 | Examples: scanme.nmap.org, google.com, 192.168.1.1-254, 10.0.0.0/24"
    )
    parser.add_argument("targets", help="Target(s): Domain, IP, IP range, CIDR, comma-separated")
    parser.add_argument("-p", "--ports", default="1-1000", 
                       help="Ports to scan (e.g., 1-1000, 80,443,8080)")
    parser.add_argument("-t", "--threads", type=int, default=200,
                       help="Number of threads (default: 200)")
    parser.add_argument("--timeout", type=float, default=1.0,
                       help="Socket timeout in seconds (default: 1)")
    
    args = parser.parse_args()
    
    # Parse ports
    if '-' in args.ports:
        start, end = map(int, args.ports.split('-'))
        ports = range(start, end + 1)
    else:
        ports = [int(p) for p in args.ports.split(',')]
    
    # Run scanner
    print("B01 Port Scanner Python - Full Domain Resolution")
    print("Author: dinoZ0G1")
    print("=" * 50)
    
    scanner = PortScanner(args.targets, ports, args.timeout)
    open_ports = scanner.scan(args.threads)
    scanner.print_results()

if __name__ == "__main__":
    main()