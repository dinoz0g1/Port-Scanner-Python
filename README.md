# Port-Scanner-Python
# B01 - Port Scanner Python

![Author](https://img.shields.io/badge/Author-dinoZ0G1-brightgreen?style=flat-square)
Advanced multi-threaded port scanner for penetration testing.

**Author: dinoZ0G1**

## Usage

```bash
# 1. Single IP (sebelumnya)
python3 port_scanner.py scanme.nmap.org

# 2. IP Range (192.168.1.1-254)
python3 port_scanner.py 192.168.1.1-254 -p 1-1000

# 3. CIDR Notation (10.0.0.0/24 = 256 IPs)
python3 port_scanner.py 10.0.0.0/24

# 4. Multiple targets
python3 port_scanner.py 192.168.1.1-10,scanme.nmap.org,8.8.8.8

# 5. Network scan + common ports
python3 port_scanner.py 192.168.1.0/24 -p 22,80,443,3389 --threads 500

# 6. Full subnet scan
python3 port_scanner.py 10.11.11.0/24 -p 1-1000 --threads 300 --timeout 0.5

# 2. Multiple domains + IP range
python3 port_scanner.py google.com,scanme.nmap.org,192.168.1.1-5
