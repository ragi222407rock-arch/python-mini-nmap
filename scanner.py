#!/usr/bin/env python3
"""
Python Mini Nmap - A lightweight port scanner inspired by Nmap.
Author: Mini Nmap Project
Usage: python3 scanner.py -t scanme.nmap.org -Pn
"""

import argparse
import socket
import struct
import time
import json
import csv
import ipaddress
import subprocess
import os
import platform
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple

# ─── Color support ───────────────────────────────────────────────────────────
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class _Dummy:
        def __getattr__(self, _): return ""
    Fore = Style = _Dummy()

# ─── Progress bar support ─────────────────────────────────────────────────────
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

# ─── Well-known port → service name mapping ───────────────────────────────────
COMMON_SERVICES: Dict[int, str] = {
    20: "ftp-data",    21: "ftp",          22: "ssh",          23: "telnet",
    25: "smtp",        53: "domain",       67: "dhcps",        68: "dhcpc",
    69: "tftp",        80: "http",         110: "pop3",        111: "rpcbind",
    119: "nntp",       123: "ntp",         135: "msrpc",       137: "netbios-ns",
    138: "netbios-dgm",139: "netbios-ssn", 143: "imap",        161: "snmp",
    162: "snmptrap",   389: "ldap",        443: "https",       445: "microsoft-ds",
    465: "smtps",      500: "isakmp",      514: "syslog",      587: "submission",
    636: "ldaps",      873: "rsync",       993: "imaps",       995: "pop3s",
    1080: "socks",     1194: "openvpn",    1433: "ms-sql-s",   1434: "ms-sql-m",
    1521: "oracle",    1723: "pptp",       2049: "nfs",        3128: "squid-http",
    3306: "mysql",     3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc",
    5985: "wsman",     6379: "redis",      8000: "http-alt",   8080: "http-proxy",
    8443: "https-alt", 8888: "sun-answerbook", 9000: "cslistener", 27017: "mongod",
}

# Top 100 ports to scan by default (like nmap default scan)
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 179, 199, 443, 445,
    465, 514, 515, 587, 631, 636, 646, 873, 993, 995, 1025, 1026, 1027,
    1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
    2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101,
    5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000,
    8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152,
    49153, 49154, 49155, 49156, 49157, 27017, 6379, 5985, 11211, 1521, 1434,
    500, 4500, 1194, 161, 69, 123, 162, 137, 138, 67, 68
]


class PortScanner:
    """Main port scanner class. Handles all scanning modes and result output."""

    def __init__(
        self,
        targets: List[str],
        ports: List[int],
        mode: str,
        threads: int,
        timeout: float,
        verbose: bool,
        output_file: Optional[str],
        no_ping: bool = False,
    ):
        self.targets = targets
        self.ports = ports
        self.mode = mode.lower()
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.output_file = output_file
        self.no_ping = no_ping

        # Thread-safe counters
        self._lock = threading.Lock()
        self.total_scanned = 0
        self.open_count = 0

        # Results store: {ip: [{"port": int, "state": str, "service": str, "banner": str}]}
        self.results: Dict[str, List[Dict]] = {}
        self.scan_start_time = 0.0
        self.scan_end_time = 0.0

    # ── Service resolution ────────────────────────────────────────────────────
    def resolve_service(self, port: int) -> str:
        """Attempt OS service lookup, fall back to our dictionary."""
        proto = "udp" if self.mode == "udp" else "tcp"
        try:
            return socket.getservbyport(port, proto)
        except OSError:
            return COMMON_SERVICES.get(port, "unknown")

    # ── Banner grabbing ───────────────────────────────────────────────────────
    def banner_grab(self, ip: str, port: int) -> str:
        """Try to grab a service banner from an open TCP port."""
        if self.mode == "udp":
            return ""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip, port))
                # HTTP-style probe triggers most services to respond
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                raw = s.recv(2048).decode("utf-8", errors="ignore").strip()
                if not raw:
                    # Fallback: blank line (triggers SSH, FTP, SMTP greetings)
                    s.sendall(b"\r\n")
                    raw = s.recv(1024).decode("utf-8", errors="ignore").strip()
                # Prefer the Server: header if present
                for line in raw.splitlines():
                    if line.lower().startswith("server:"):
                        return line.strip()[:80]
                return raw.splitlines()[0][:80] if raw else ""
        except Exception:
            return ""

    # ── Ping & OS fingerprint ─────────────────────────────────────────────────
    def ping_host(self, ip: str) -> Tuple[bool, str]:
        """
        Ping a host once.  Returns (is_alive, os_guess).
        OS guess is based purely on TTL value (rough heuristic).
        """
        sys_name = platform.system().lower()
        if sys_name == "windows":
            cmd = ["ping", "-n", "1", "-w", str(int(self.timeout * 1000)), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, int(self.timeout))), ip]
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True)
            output_upper = output.upper()
            if "TTL=" in output_upper:
                ttl = None
                for token in output.split():
                    if "TTL=" in token.upper():
                        try:
                            ttl = int(token.split("=")[1].strip().rstrip(")"))
                        except (ValueError, IndexError):
                            pass
                if ttl is not None:
                    if ttl <= 64:
                        return True, "Linux/Unix (TTL≤64)"
                    elif ttl <= 128:
                        return True, "Windows (TTL≤128)"
                    else:
                        return True, "Network/Router (TTL≤255)"
                return True, "Unknown OS"
            return False, ""
        except subprocess.CalledProcessError:
            return False, ""
        except FileNotFoundError:
            # ping not available – treat as alive so scan still runs
            return True, "Unknown OS (ping unavailable)"

    # ── TCP Connect scan ──────────────────────────────────────────────────────
    def tcp_connect_scan(self, ip: str, port: int) -> str:
        """
        Full TCP 3-way handshake.
        Returns: 'open', 'closed', or 'filtered'
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip, port))
                return "open"
        except socket.timeout:
            return "filtered"
        except ConnectionRefusedError:
            return "closed"
        except OSError as e:
            # errno 111 = Connection refused (Linux), errno 10061 = Windows
            if hasattr(e, "errno") and e.errno in (111, 10061):
                return "closed"
            return "filtered"

    # ── TCP SYN (half-open) scan ──────────────────────────────────────────────
    def tcp_syn_scan(self, ip: str, port: int) -> str:
        """
        Half-open SYN scan using raw sockets. Requires root/Administrator.
        Falls back gracefully if permission is denied.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.settimeout(self.timeout)
            source_ip = socket.gethostbyname(socket.gethostname())
            packet = self._build_syn_packet(source_ip, ip, port)
            s.sendto(packet, (ip, 0))
            try:
                data = s.recvfrom(1024)[0]
                # IP header is 20 bytes; TCP flags are at byte 33
                if len(data) > 33:
                    flags = data[33]
                    if flags & 0x12 == 0x12:   # SYN-ACK
                        return "open"
                    elif flags & 0x14 == 0x14: # RST-ACK
                        return "closed"
                return "filtered"
            except socket.timeout:
                return "filtered"
            finally:
                s.close()
        except PermissionError:
            return "error_permission"
        except OSError as e:
            if hasattr(e, "errno") and e.errno == 10013:
                return "error_permission"
            return "filtered"

    def _build_syn_packet(self, src_ip: str, dst_ip: str, dst_port: int) -> bytes:
        """Construct a raw TCP SYN packet with correct checksum."""
        src_port = 54321
        seq = ack = 0
        doff = 5
        flags = 0x02  # SYN
        window = socket.htons(65535)
        urg = check = 0
        offset_res = (doff << 4)

        # Pack without checksum first
        tcp_hdr = struct.pack("!HHLLBBHHH", src_port, dst_port, seq, ack,
                              offset_res, flags, window, check, urg)

        # Pseudo-header for checksum calculation
        src_addr = socket.inet_aton(src_ip)
        dst_addr = socket.inet_aton(dst_ip)
        pseudo = struct.pack("!4s4sBBH", src_addr, dst_addr, 0,
                             socket.IPPROTO_TCP, len(tcp_hdr))

        def chksum(data: bytes) -> int:
            s = 0
            for i in range(0, len(data) - 1, 2):
                s += (data[i] << 8) + data[i + 1]
            if len(data) % 2:
                s += data[-1] << 8
            s = (s >> 16) + (s & 0xFFFF)
            return ~(s + (s >> 16)) & 0xFFFF

        checksum = chksum(pseudo + tcp_hdr)
        return struct.pack("!HHLLBBHHH", src_port, dst_port, seq, ack,
                           offset_res, flags, window, checksum, urg)

    # ── UDP scan ──────────────────────────────────────────────────────────────
    def udp_scan(self, ip: str, port: int) -> str:
        """
        Basic UDP probe.
        Returns 'open', 'open|filtered', or 'closed'.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout)
                s.sendto(b"\x00" * 8, (ip, port))
                try:
                    s.recvfrom(1024)
                    return "open"
                except socket.timeout:
                    return "open|filtered"
                except ConnectionResetError:
                    # ICMP port-unreachable received → port is closed
                    return "closed"
        except Exception:
            return "filtered"

    # ── Per-port dispatcher ───────────────────────────────────────────────────
    def scan_port(self, ip: str, port: int) -> Optional[Dict]:
        """Scan a single port and return a result dict, or None if not reportable."""
        if self.mode == "tcp":
            state = self.tcp_connect_scan(ip, port)
        elif self.mode == "syn":
            state = self.tcp_syn_scan(ip, port)
            if state == "error_permission":
                return {"error": "SYN scan requires root/Administrator privileges."}
        else:  # udp
            state = self.udp_scan(ip, port)

        # Thread-safe counter update
        with self._lock:
            self.total_scanned += 1
            if "open" in state:
                self.open_count += 1

        service = self.resolve_service(port)
        banner = ""
        if state == "open" and self.mode != "udp":
            banner = self.banner_grab(ip, port)

        if "open" in state:
            return {"port": port, "state": state, "service": service, "banner": banner}
        if self.verbose:
            return {"port": port, "state": state, "service": service, "banner": ""}
        return None  # closed/filtered hidden by default

    # ── Result display ────────────────────────────────────────────────────────
    def display_target_result(self, ip: str, results: List[Dict], os_guess: str):
        """Print a well-formatted, Nmap-style table for one target."""
        print(f"\n{Style.BRIGHT}{Fore.BLUE}{'─'*60}")
        print(f"{Style.BRIGHT}{Fore.CYAN}  Nmap-style Scan Report for {ip}")
        if os_guess:
            print(f"{Style.BRIGHT}  OS Fingerprint (TTL): {Fore.YELLOW}{os_guess}")
        print(f"{Fore.BLUE}{'─'*60}{Style.RESET_ALL}")

        open_results = [r for r in results if "open" in r.get("state", "")]
        closed_count = sum(1 for r in results if r.get("state") == "closed")
        filtered_count = sum(1 for r in results if r.get("state") == "filtered")

        if not open_results:
            print(f"{Fore.RED}  All {len(self.ports)} scanned ports are closed/filtered.")
        else:
            # Header
            print(f"{Style.BRIGHT}  {'PORT':<12} {'STATE':<12} {'SERVICE':<18} BANNER{Style.RESET_ALL}")
            print(f"  {'─'*56}")
            for res in sorted(results, key=lambda r: r["port"]):
                state = res["state"]
                if not self.verbose and "open" not in state:
                    continue
                port_label = f"{res['port']}/{self.mode}"
                color = (Fore.GREEN if "open" in state
                         else Fore.YELLOW if state == "filtered"
                         else Fore.RED)
                banner_txt = f"  {res['banner']}" if res["banner"] else ""
                print(
                    f"  {port_label:<12} "
                    f"{color}{state:<12}{Style.RESET_ALL} "
                    f"{res['service']:<18}"
                    f"{banner_txt}"
                )

        if self.verbose:
            print(f"\n  {Fore.YELLOW}Closed: {closed_count}  Filtered: {filtered_count}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}{'─'*60}{Style.RESET_ALL}")

    # ── Main run loop ─────────────────────────────────────────────────────────
    def run(self):
        print(f"\n{Style.BRIGHT}{Fore.CYAN}Starting Mini Nmap Python Scanner")
        print(f"{Fore.CYAN}Scan mode: {self.mode.upper()}  |  Threads: {self.threads}  |  Timeout: {self.timeout}s  |  Ports: {len(self.ports)}")
        self.scan_start_time = time.time()
        syn_warned = False

        for ip in self.targets:
            os_guess = ""

            # ── Host discovery ────────────────────────────────────────────
            if not self.no_ping:
                print(f"\n{Fore.CYAN}[*] Pinging {ip}...")
                is_up, os_guess = self.ping_host(ip)
                if not is_up:
                    print(f"{Fore.RED}[-] {ip} did not respond to ping. Skipping.")
                    print(f"{Fore.YELLOW}    Tip: Add -Pn to skip ping and force-scan anyway.")
                    continue
                print(f"{Fore.GREEN}[+] {ip} is UP  ({os_guess})")
            else:
                print(f"\n{Fore.CYAN}[*] -Pn: Skipping ping, forcing scan on {ip}...")

            self.results[ip] = []

            # ── Port scan ─────────────────────────────────────────────────
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self.scan_port, ip, port): port
                           for port in self.ports}

                try:
                    if TQDM_AVAILABLE:
                        completed = tqdm(as_completed(futures),
                                         total=len(self.ports),
                                         desc=f"  Scanning {ip}",
                                         unit="port",
                                         leave=True,
                                         colour="cyan")
                    else:
                        completed = as_completed(futures)

                    for future in completed:
                        res = future.result()
                        if res is None:
                            continue
                        if "error" in res:
                            if not syn_warned:
                                print(f"\n{Fore.RED}[!] {res['error']}")
                                print(f"{Fore.YELLOW}[!] Falling back to TCP Connect scan.")
                                self.mode = "tcp"
                                syn_warned = True
                        else:
                            with self._lock:
                                self.results[ip].append(res)

                except KeyboardInterrupt:
                    print(f"\n{Fore.RED}[!] Interrupted. Stopping scan...")
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

            self.display_target_result(ip, self.results[ip], os_guess)

        self.scan_end_time = time.time()
        self._print_summary()
        if self.output_file:
            self._export_results()

    # ── Summary ───────────────────────────────────────────────────────────────
    def _print_summary(self):
        duration = self.scan_end_time - self.scan_start_time
        print(f"\n{Style.BRIGHT}{Fore.CYAN}{'─'*60}")
        print(f"  Scan Summary")
        print(f"{'─'*60}{Style.RESET_ALL}")
        print(f"  Hosts Scanned    : {len(self.targets)}")
        print(f"  Total Ports      : {self.total_scanned}")
        print(f"  Open Ports Found : {Fore.GREEN}{self.open_count}{Style.RESET_ALL}")
        print(f"  Scan Duration    : {duration:.2f}s")
        print(f"{Fore.CYAN}{'─'*60}{Style.RESET_ALL}\n")

    # ── Export ────────────────────────────────────────────────────────────────
    def _export_results(self):
        ext = os.path.splitext(self.output_file)[1].lower()
        try:
            if ext == ".json":
                with open(self.output_file, "w") as f:
                    json.dump(self.results, f, indent=4)
            elif ext == ".csv":
                with open(self.output_file, "w", newline="") as f:
                    w = csv.writer(f)
                    w.writerow(["IP", "Port", "Protocol", "State", "Service", "Banner"])
                    for ip, rows in self.results.items():
                        for r in rows:
                            w.writerow([ip, r["port"], self.mode,
                                        r["state"], r["service"], r["banner"]])
            else:
                print(f"{Fore.RED}[!] Unknown extension '{ext}'. Use .json or .csv")
                return
            print(f"{Fore.GREEN}[+] Results saved to {self.output_file}")
        except Exception as exc:
            print(f"{Fore.RED}[!] Export failed: {exc}")


# ─── CLI Helpers ──────────────────────────────────────────────────────────────

def parse_target(target_str: str) -> List[str]:
    """Resolve hostname / CIDR to a list of IP strings."""
    try:
        if "/" in target_str:
            net = ipaddress.ip_network(target_str, strict=False)
            return [str(h) for h in net.hosts()]
        ip = socket.gethostbyname(target_str)
        if target_str != ip:
            print(f"{Fore.CYAN}[*] Resolved {target_str} → {ip}")
        return [ip]
    except Exception as exc:
        print(f"{Fore.RED}[!] Could not resolve target '{target_str}': {exc}")
        return []


def parse_ports(port_str: str) -> List[int]:
    """Parse port expressions like '22,80,443', '1-1024', 'top100', 'common'."""
    if port_str.lower() in ("common", "top50"):
        return sorted(COMMON_SERVICES.keys())
    if port_str.lower() == "top100":
        return sorted(set(TOP_100_PORTS))

    ports: set = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                lo, hi = map(int, part.split("-", 1))
                if 1 <= lo <= hi <= 65535:
                    ports.update(range(lo, hi + 1))
            except ValueError:
                print(f"{Fore.RED}[!] Invalid range: {part}")
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                print(f"{Fore.RED}[!] Invalid port: {part}")
    return sorted(ports)


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Python Mini Nmap – a lightweight port scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scanner.py -t scanme.nmap.org -Pn
  python3 scanner.py -t 192.168.1.1 -p 1-1024 --mode tcp
  python3 scanner.py -t 10.0.0.0/24 -p top100 --threads 200 -Pn
  python3 scanner.py -t example.com -p 22,80,443 -o results.json
        """,
    )
    parser.add_argument("-t", "--target", required=True,
                        help="IP, hostname, or CIDR (e.g. 192.168.1.1, scanme.nmap.org, 10.0.0.0/24)")
    parser.add_argument("-p", "--ports", default="common",
                        help="Ports: '1-1024', '22,80,443', 'common'(top50), 'top100' [default: common]")
    parser.add_argument("--threads", type=int, default=100,
                        help="Worker threads [default: 100]")
    parser.add_argument("--timeout", type=float, default=2.0,
                        help="Per-port timeout in seconds [default: 2.0]")
    parser.add_argument("--mode", choices=["tcp", "syn", "udp"], default="tcp",
                        help="Scan mode [default: tcp]")
    parser.add_argument("-o", "--output",
                        help="Save results to file (e.g. out.json or out.csv)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Also show closed/filtered ports")
    parser.add_argument("-Pn", "--no-ping", action="store_true",
                        help="Skip ping, treat all hosts as up (use for internet targets)")

    args = parser.parse_args()

    targets = parse_target(args.target)
    if not targets:
        return

    ports = parse_ports(args.ports)
    if not ports:
        print(f"{Fore.RED}[!] No valid ports to scan.")
        return

    PortScanner(
        targets=targets,
        ports=ports,
        mode=args.mode,
        threads=args.threads,
        timeout=args.timeout,
        verbose=args.verbose,
        output_file=args.output,
        no_ping=args.no_ping,
    ).run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scanner stopped by user.")
