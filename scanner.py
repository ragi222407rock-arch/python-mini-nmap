import argparse
import socket
import struct
import threading
import time
import json
import csv
import ipaddress
import subprocess
import os
import platform
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Optional, Tuple

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class _Color:
        def __getattr__(self, item): return ""
    Fore = Style = _Color()

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

COMMON_SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 119: "NNTP", 123: "NTP", 135: "MSRPC", 137: "NETBIOS-NS",
    138: "NETBIOS-DGM", 139: "NETBIOS-SSN", 143: "IMAP", 161: "SNMP", 162: "SNMPTRAP",
    389: "LDAP", 443: "HTTPS", 445: "MICROSOFT-DS", 465: "SMTPS", 500: "ISAKMP",
    514: "SYSLOG", 587: "SMTP", 636: "LDAPS", 873: "RSYNC", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1194: "OPENVPN", 1433: "MSSQL", 1434: "MSSQL-M",
    1521: "ORACLE", 1723: "PPTP", 2049: "NFS", 3128: "SQUID", 3306: "MYSQL",
    3389: "RDP", 5432: "POSTGRESQL", 5900: "VNC", 5985: "WINRM", 6379: "REDIS",
    8000: "HTTP-ALT", 8080: "HTTP-PROXY", 8443: "HTTPS-ALT", 9000: "CSLISTENER", 27017: "MONGODB"
}

class PortScanner:
    def __init__(self, targets: List[str], ports: List[int], mode: str, threads: int, timeout: float, verbose: bool, output_file: Optional[str]):
        self.targets = targets
        self.ports = ports
        self.mode = mode.lower()
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.output_file = output_file
        
        self.results = {}  # Format: {ip: [{"port": port, "state": state, "service": service, "banner": banner}]}
        self.scan_start_time = 0
        self.scan_end_time = 0
        self.total_scanned = 0
        self.open_count = 0

    def resolve_service(self, port: int) -> str:
        try:
            return socket.getservbyport(port, 'tcp' if self.mode in ['tcp', 'syn'] else 'udp')
        except OSError:
            return COMMON_SERVICES.get(port, "UNKNOWN")

    def banner_grab(self, ip: str, port: int) -> str:
        if self.mode == 'udp':
            return ""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(max(self.timeout, 1.0))
                s.connect((ip, port))
                # Send a generic payload that triggers responses from many services
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                # If nothing received, try sending just a newline for protocols like SSH/FTP
                if not banner:
                    s.sendall(b"\r\n")
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner.split('\n')[0][:50]
        except Exception:
            return ""

    def ping_host(self, ip: str) -> Tuple[bool, Optional[str]]:
        """Ping sweep and OS fingerprinting via TTL."""
        system = platform.system().lower()
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(int(self.timeout * 1000)), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, int(self.timeout))), ip]
        
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True)
            if "TTL=" in output or "ttl=" in output:
                # Extract TTL for basic OS Fingerprinting
                ttl = None
                for word in output.split():
                    if word.upper().startswith("TTL="):
                        try:
                            ttl = int(word.split("=")[1])
                        except ValueError:
                            pass
                
                os_guess = "Unknown"
                if ttl:
                    if ttl <= 64:
                        os_guess = "Linux/Unix/macOS"
                    elif ttl <= 128:
                        os_guess = "Windows"
                    elif ttl <= 255:
                        os_guess = "Cisco/Network Device"
                return True, os_guess
            return False, None
        except subprocess.CalledProcessError:
            return False, None

    def create_tcp_syn_packet(self, source_ip, dest_ip, dest_port):
        # Simplified TCP SYN packet creation (IP header typically handled by OS for SOCK_RAW with IPPROTO_TCP on some platforms,
        # but full raw sockets might require IP headers depending on the OS like Windows. This is a basic TCP header).
        # Note: Raw sockets in Windows are heavily restricted.
        source_port = 54321
        seq = 0
        ack_seq = 0
        doff = 5
        # Flags
        fin = 0
        syn = 1
        rst = 0
        psh = 0
        ack = 0
        urg = 0
        window = socket.htons(5840)
        check = 0
        urg_ptr = 0

        offset_res = (doff << 4) + 0
        tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)

        tcp_header = struct.pack('!HHLLBBHHH', source_port, dest_port, seq, ack_seq, offset_res, tcp_flags, window, check, urg_ptr)
        
        # Pseudo header for checksum
        source_address = socket.inet_aton(source_ip)
        dest_address = socket.inet_aton(dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)

        psh = struct.pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
        psh = psh + tcp_header

        # Checksum
        def checksum(msg):
            s = 0
            for i in range(0, len(msg), 2):
                if i + 1 < len(msg):
                    w = (msg[i] << 8) + msg[i+1]
                else:
                    w = (msg[i] << 8)
                s = s + w
            s = (s >> 16) + (s & 0xffff)
            s = s + (s >> 16)
            s = ~s & 0xffff
            return s

        tcp_checksum = checksum(psh)
        tcp_header = struct.pack('!HHLLBBH', source_port, dest_port, seq, ack_seq, offset_res, tcp_flags, window) + struct.pack('H', tcp_checksum) + struct.pack('!H', urg_ptr)
        return tcp_header

    def tcp_syn_scan(self, ip: str, port: int) -> str:
        """
        Half-open SYN scan. Requires root/admin.
        WARNING: On Windows, receiving responses natively might not work due to OS blocking.
        """
        try:
            # Create a raw socket
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.settimeout(self.timeout)
            
            # Simple connect check works around some blocks if we just want to see if we can connect 
            # without full custom packet, but it's technically a Connect scan.
            # Building actual SYN scan:
            source_ip = socket.gethostbyname(socket.gethostname())
            packet = self.create_tcp_syn_packet(source_ip, ip, port)
            
            s.sendto(packet, (ip, 0))
            
            try:
                data = s.recvfrom(1024)[0]
                # Assuming the response has TCP header starting at byte 20
                tcp_header_len = (data[32] >> 4) * 4
                flags = data[33]
                
                # Check if SYN-ACK (0x12)
                if flags == 0x12:
                    return "open"
                elif flags == 0x14: # RST-ACK
                    return "closed"
                else:
                    return "filtered"
            except socket.timeout:
                return "filtered"
            finally:
                s.close()
        except PermissionError:
            # Fallback to connect scan or warn
            return "error_permission"
        except OSError as e:
            if e.errno == 10013: # Windows socket permission error
                return "error_permission"
            return "filtered"

    def tcp_connect_scan(self, ip: str, port: int) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((ip, port))
                if result == 0:
                    return "open"
                elif result in (111, 10061): # Connection refused
                    return "closed"
                else:
                    return "filtered"
        except (socket.timeout, OSError):
            return "filtered"

    def udp_scan(self, ip: str, port: int) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout)
                s.sendto(b"\x00", (ip, port))
                try:
                    data, addr = s.recvfrom(1024)
                    return "open"
                except socket.timeout:
                    return "open|filtered"
                except ConnectionResetError:
                    return "closed"
        except Exception:
            return "filtered"

    def scan_port(self, ip: str, port: int) -> Optional[Dict]:
        state = "closed"
        if self.mode == 'tcp':
            state = self.tcp_connect_scan(ip, port)
        elif self.mode == 'syn':
            state = self.tcp_syn_scan(ip, port)
            if state == "error_permission":
                return {"error": "SYN scan requires root/admin privileges."}
        elif self.mode == 'udp':
            state = self.udp_scan(ip, port)

        self.total_scanned += 1

        if state in ['open', 'open|filtered']:
            self.open_count += 1
            service = self.resolve_service(port)
            banner = self.banner_grab(ip, port) if state == 'open' and self.mode != 'udp' else ""
            return {"port": port, "state": state, "service": service, "banner": banner}
        elif self.verbose or state == 'filtered':
            # Even if closed/filtered, return if verbose is on to show progress, but we might drop closed by default
            return {"port": port, "state": state, "service": self.resolve_service(port), "banner": ""}
        return None

    def display_target_result(self, ip: str, results: List[Dict], os_guess: Optional[str]):
        print(f"\n{Style.BRIGHT}{Fore.BLUE}Scan report for {ip}")
        if os_guess:
            print(f"{Style.BRIGHT}OS Fingerprint (TTL): {Fore.YELLOW}{os_guess}")
        
        open_results = [r for r in results if r['state'] in ('open', 'open|filtered')]
        
        if not open_results and not self.verbose:
            print(f"{Fore.RED}No open ports found out of {len(self.ports)} scanned.")
            return

        print(f"{Style.BRIGHT}{'PORT':<10} | {'STATE':<15} | {'SERVICE':<15} | {'BANNER'}")
        print("-" * 65)
        
        # Sort results by port number
        results.sort(key=lambda x: x['port'])
        
        for res in results:
            if not self.verbose and res['state'] not in ('open', 'open|filtered'):
                continue
                
            state_color = Fore.GREEN if 'open' in res['state'] else (Fore.RED if res['state'] == 'closed' else Fore.YELLOW)
            banner_text = f" -> {res['banner']}" if res['banner'] else ""
            
            print(f"{res['port']:<10} | {state_color}{res['state']:<15}{Style.RESET_ALL} | {res['service']:<15} {banner_text}")

    def run(self):
        print(f"{Style.BRIGHT}{Fore.CYAN}Starting Mini Nmap Python Scanner")
        self.scan_start_time = time.time()
        
        syn_warned = False

        for ip in self.targets:
            # Ping sweep before scanning
            print(f"\n{Fore.CYAN}[*] Pinging {ip}...")
            is_up, os_guess = self.ping_host(ip)
            
            if not is_up:
                print(f"{Fore.RED}[-] Host {ip} seems down. Skipping (or use verbose to ignore).")
                continue
                
            print(f"{Fore.GREEN}[+] Host {ip} is UP.")
            
            self.results[ip] = []
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self.scan_port, ip, port): port for port in self.ports}
                
                # Progress bar if tqdm is installed
                iterator = futures
                if tqdm:
                    iterator = tqdm(futures, desc=f"Scanning {ip}", unit="port", leave=False)
                
                try:
                    for future in iterator:
                        res = future.result()
                        if res:
                            if "error" in res:
                                if not syn_warned:
                                    print(f"{Fore.RED}\n[!] Error: {res['error']}")
                                    print(f"{Fore.YELLOW}[!] Falling back to TCP Connect Scan for remaining ports.")
                                    self.mode = 'tcp'
                                    syn_warned = True
                            else:
                                self.results[ip].append(res)
                except KeyboardInterrupt:
                    print(f"\n{Fore.RED}[!] Scan interrupted by user (Ctrl+C). Exiting...")
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

            self.display_target_result(ip, self.results[ip], os_guess)

        self.scan_end_time = time.time()
        self.print_summary()
        
        if self.output_file:
            self.export_results()

    def print_summary(self):
        duration = self.scan_end_time - self.scan_start_time
        print(f"\n{Style.BRIGHT}{Fore.CYAN}--- Scan Summary ---")
        print(f"Total Targets    : {len(self.targets)}")
        print(f"Total Ports      : {self.total_scanned}")
        print(f"Open Ports Found : {Fore.GREEN}{self.open_count}{Style.RESET_ALL}")
        print(f"Scan Duration    : {duration:.2f} seconds")

    def export_results(self):
        ext = os.path.splitext(self.output_file)[1].lower()
        try:
            if ext == '.json':
                with open(self.output_file, 'w') as f:
                    json.dump(self.results, f, indent=4)
                print(f"{Fore.GREEN}[+] Results exported to {self.output_file}")
            elif ext == '.csv':
                with open(self.output_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['IP', 'Port', 'State', 'Service', 'Banner'])
                    for ip, res_list in self.results.items():
                        for res in res_list:
                            writer.writerow([ip, res['port'], res['state'], res['service'], res['banner']])
                print(f"{Fore.GREEN}[+] Results exported to {self.output_file}")
            else:
                print(f"{Fore.RED}[!] Unsupported export format. Use .json or .csv")
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to export results: {e}")

def parse_target(target_str: str) -> List[str]:
    targets = []
    try:
        # Check if CIDR
        if '/' in target_str:
            network = ipaddress.ip_network(target_str, strict=False)
            targets = [str(ip) for ip in network.hosts()]
        else:
            # Attempt to resolve hostname or parse IP
            ip = socket.gethostbyname(target_str)
            targets.append(ip)
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to parse target {target_str}: {e}")
    return targets

def parse_ports(port_str: str) -> List[int]:
    if port_str.lower() == 'common':
        return list(COMMON_SERVICES.keys())
    
    ports = set()
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if 1 <= start <= end <= 65535:
                    ports.update(range(start, end + 1))
            except ValueError:
                print(f"{Fore.RED}[!] Invalid port range: {part}")
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                print(f"{Fore.RED}[!] Invalid port: {part}")
    return sorted(list(ports))

def main():
    parser = argparse.ArgumentParser(description="Python Mini Nmap Port Scanner")
    parser.add_argument('-t', '--target', required=True, help='Target IP, hostname, or CIDR (e.g. 192.168.1.1, example.com, 10.0.0.0/24)')
    parser.add_argument('-p', '--ports', default='common', help='Ports to scan: "1-1024", "22,80,443", or "common" (default: common)')
    parser.add_argument('--threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=float, default=1.0, help='Timeout per port in seconds (default: 1.0)')
    parser.add_argument('--mode', choices=['tcp', 'syn', 'udp'], default='tcp', help='Scan mode (default: tcp)')
    parser.add_argument('-o', '--output', help='Output file to export results (e.g. results.json or results.csv)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output (shows closed/filtered ports)')

    args = parser.parse_args()

    # Parse inputs
    targets = parse_target(args.target)
    if not targets:
        print(f"{Fore.RED}[!] No valid targets found.")
        return

    ports = parse_ports(args.ports)
    if not ports:
        print(f"{Fore.RED}[!] No valid ports to scan.")
        return

    # Initialize and run scanner
    scanner = PortScanner(
        targets=targets,
        ports=ports,
        mode=args.mode,
        threads=args.threads,
        timeout=args.timeout,
        verbose=args.verbose,
        output_file=args.output
    )
    scanner.run()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scanner stopped.")
