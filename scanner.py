#!/usr/bin/env python3
"""
Python Mini Nmap - A lightweight port scanner inspired by Nmap.
Usage: python3 scanner.py -t scanme.nmap.org -Pn
       python3 scanner.py -t 192.168.1.1 -p 1-1024 --mode tcp -v
"""

import argparse
import socket
import select
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

# ── Colour support ────────────────────────────────────────────────────────────
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class _D:
        def __getattr__(self, _): return ""
    Fore = Style = _D()

# ── Progress bar ──────────────────────────────────────────────────────────────
try:
    from tqdm import tqdm
    TQDM = True
except ImportError:
    TQDM = False

# ── Service map ───────────────────────────────────────────────────────────────
SERVICES: Dict[int, str] = {
    20:"ftp-data", 21:"ftp", 22:"ssh", 23:"telnet", 25:"smtp",
    53:"dns", 67:"dhcp", 68:"dhcp", 69:"tftp", 80:"http",
    110:"pop3", 111:"rpcbind", 119:"nntp", 123:"ntp", 135:"msrpc",
    137:"netbios-ns", 138:"netbios-dgm", 139:"netbios-ssn", 143:"imap",
    161:"snmp", 162:"snmptrap", 389:"ldap", 443:"https", 445:"smb",
    465:"smtps", 500:"isakmp", 514:"syslog", 587:"submission",
    636:"ldaps", 873:"rsync", 993:"imaps", 995:"pop3s",
    1080:"socks", 1194:"openvpn", 1433:"mssql", 1434:"mssql-m",
    1521:"oracle", 1723:"pptp", 2049:"nfs", 3128:"squid",
    3306:"mysql", 3389:"rdp", 5432:"postgresql", 5900:"vnc",
    5985:"winrm", 6379:"redis", 8000:"http-alt", 8080:"http-proxy",
    8443:"https-alt", 8888:"http-alt2", 9000:"cslistener", 27017:"mongodb",
}

TOP100 = sorted({
    21,22,23,25,53,80,110,111,135,139,143,179,199,443,445,
    465,514,515,587,631,636,873,993,995,1025,1080,1433,1720,
    1723,2049,2121,3000,3128,3306,3389,5000,5432,5900,6379,
    8000,8008,8080,8081,8443,8888,9100,9999,10000,27017,
    137,138,67,69,123,161,162,500,4500,
})


class PortScanner:
    def __init__(self, targets, ports, mode, threads, timeout,
                 verbose, output_file, no_ping=False):
        self.targets     = targets
        self.ports       = ports
        self.mode        = mode.lower()
        self.threads     = threads
        self.timeout     = timeout
        self.verbose     = verbose
        self.output_file = output_file
        self.no_ping     = no_ping

        self._lock        = threading.Lock()
        self.total_scanned = 0
        self.open_count    = 0
        self.results: Dict[str, List[Dict]] = {}
        self.t0 = self.t1 = 0.0

    # ─── Service name ─────────────────────────────────────────────────────────
    def _service(self, port: int) -> str:
        proto = "udp" if self.mode == "udp" else "tcp"
        try:
            return socket.getservbyport(port, proto)
        except OSError:
            return SERVICES.get(port, "unknown")

    # ─── Banner grab ──────────────────────────────────────────────────────────
    def _banner(self, ip: str, port: int) -> str:
        if self.mode == "udp":
            return ""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(max(self.timeout, 2.0))
                s.connect((ip, port))
                # Generic probe (triggers HTTP / SSH / FTP / SMTP greetings)
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                except Exception:
                    pass
                raw = b""
                try:
                    raw = s.recv(2048)
                except Exception:
                    pass
                text = raw.decode("utf-8", errors="ignore").strip()
                for line in text.splitlines():
                    if line.lower().startswith("server:"):
                        return line.strip()[:80]
                return text.splitlines()[0][:80] if text else ""
        except Exception:
            return ""

    # ─── Ping / OS fingerprint ─────────────────────────────────────────────────
    def _ping(self, ip: str) -> Tuple[bool, str]:
        sys = platform.system().lower()
        cmd = (["ping","-n","1","-w",str(int(self.timeout*1000)),ip]
               if sys == "windows"
               else ["ping","-c","1","-W",str(max(1,int(self.timeout))),ip])
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT,
                                          universal_newlines=True)
            if "ttl=" in out.lower():
                ttl = None
                for tok in out.split():
                    if "ttl=" in tok.lower():
                        try: ttl = int(tok.split("=")[1].strip().rstrip(")"))
                        except: pass
                if ttl:
                    if   ttl <= 64:  return True, "Linux/Unix (TTL≤64)"
                    elif ttl <= 128: return True, "Windows (TTL≤128)"
                    else:            return True, "Network device (TTL≤255)"
                return True, "Unknown OS"
            return False, ""
        except subprocess.CalledProcessError:
            return False, ""
        except FileNotFoundError:
            return True, "(ping not available)"

    # ─── TCP Connect via non-blocking socket + select() ────────────────────────
    # This is the most reliable cross-platform method; avoids exception-based
    # false-negatives seen with blocking connect() on some Linux kernels.
    def _tcp_connect(self, ip: str, port: int) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            err = s.connect_ex((ip, port))
            # err == EINPROGRESS (115 Linux / 10035 Windows) means connecting
            # err == 0 means instantly connected (loopback / LAN)
            if err not in (0, 115, 10035):
                s.close()
                return "closed"      # immediate hard refusal

            # Wait up to `timeout` seconds for the socket to become writable
            ready = select.select([], [s], [s], self.timeout)
            if not ready[1] and not ready[2]:
                s.close()
                return "filtered"    # real timeout — firewall dropping packets

            # Read the actual connection result
            err2 = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            s.close()
            if err2 == 0:
                return "open"
            elif err2 in (111, 10061):   # ECONNREFUSED
                return "closed"
            else:
                return "filtered"
        except Exception:
            return "filtered"

    # ─── TCP SYN half-open scan (raw sockets, needs root) ─────────────────────
    def _tcp_syn(self, ip: str, port: int) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.settimeout(self.timeout)
            src = socket.gethostbyname(socket.gethostname())
            pkt = self._build_syn(src, ip, port)
            s.sendto(pkt, (ip, 0))
            try:
                data = s.recvfrom(1024)[0]
                if len(data) > 33:
                    flags = data[33]
                    if flags & 0x12 == 0x12: return "open"
                    if flags & 0x14 == 0x14: return "closed"
                return "filtered"
            except socket.timeout:
                return "filtered"
            finally:
                s.close()
        except PermissionError:
            return "error_permission"
        except OSError as e:
            if getattr(e,"errno",None) == 10013: return "error_permission"
            return "filtered"

    def _build_syn(self, src_ip, dst_ip, dst_port) -> bytes:
        sp, seq, ack = 54321, 0, 0
        doff, flags, win, chk, urg = 5, 0x02, socket.htons(65535), 0, 0
        off = doff << 4
        hdr = struct.pack("!HHLLBBHHH", sp, dst_port, seq, ack, off, flags, win, chk, urg)
        pseudo = (struct.pack("!4s4sBBH",
                  socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
                  0, socket.IPPROTO_TCP, len(hdr)) + hdr)
        def chksum(d):
            s = sum((d[i]<<8)+d[i+1] for i in range(0,len(d)-1,2))
            if len(d)%2: s += d[-1]<<8
            s = (s>>16)+(s&0xFFFF)
            return ~(s+(s>>16))&0xFFFF
        c = chksum(pseudo)
        return struct.pack("!HHLLBBHHH", sp, dst_port, seq, ack, off, flags, win, c, urg)

    # ─── UDP scan ──────────────────────────────────────────────────────────────
    def _udp(self, ip: str, port: int) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout)
                s.sendto(b"\x00"*8, (ip, port))
                try:
                    s.recvfrom(1024); return "open"
                except socket.timeout:
                    return "open|filtered"
                except ConnectionResetError:
                    return "closed"
        except Exception:
            return "filtered"

    # ─── Per-port worker ───────────────────────────────────────────────────────
    def _scan_port(self, ip: str, port: int) -> Optional[Dict]:
        if   self.mode == "tcp": state = self._tcp_connect(ip, port)
        elif self.mode == "syn": state = self._tcp_syn(ip, port)
        else:                    state = self._udp(ip, port)

        if state == "error_permission":
            return {"error": "SYN scan needs root. Run: sudo python3 scanner.py ..."}

        with self._lock:
            self.total_scanned += 1
            if "open" in state:
                self.open_count += 1

        svc = self._service(port)
        banner = self._banner(ip, port) if state == "open" and self.mode != "udp" else ""

        if "open" in state:
            return {"port":port, "state":state, "service":svc, "banner":banner}
        if self.verbose:
            return {"port":port, "state":state, "service":svc, "banner":""}
        return None

    # ─── Display ───────────────────────────────────────────────────────────────
    def _display(self, ip: str, rows: List[Dict], os_hint: str):
        W = 62
        print(f"\n{Style.BRIGHT}{Fore.CYAN}{'─'*W}")
        print(f"  Scan results for: {Fore.WHITE}{ip}{Fore.CYAN}  {os_hint}")
        print(f"{'─'*W}{Style.RESET_ALL}")

        open_rows = [r for r in rows if "open" in r.get("state","")]
        if not open_rows:
            closed = sum(1 for r in rows if r.get("state")=="closed")
            filt   = sum(1 for r in rows if r.get("state")=="filtered")
            print(f"  {Fore.RED}No open ports found.")
            if self.verbose:
                print(f"  {Fore.YELLOW}Closed: {closed}  Filtered: {filt}")
            print(f"{Fore.CYAN}{'─'*W}{Style.RESET_ALL}")
            return

        print(f"{Style.BRIGHT}  {'PORT':<13} {'STATE':<11} {'SERVICE':<16} BANNER{Style.RESET_ALL}")
        print(f"  {'─'*58}")

        for r in sorted(rows, key=lambda x: x["port"]):
            st = r["state"]
            if not self.verbose and "open" not in st:
                continue
            label = f"{r['port']}/{self.mode}"
            col   = (Fore.GREEN if "open" in st else
                     Fore.YELLOW if st=="filtered" else Fore.RED)
            btext = f"  {r['banner']}" if r.get("banner") else ""
            print(f"  {label:<13} {col}{st:<11}{Style.RESET_ALL} {r['service']:<16}{btext}")

        if self.verbose:
            closed = sum(1 for r in rows if r.get("state")=="closed")
            filt   = sum(1 for r in rows if r.get("state")=="filtered")
            print(f"\n  {Fore.YELLOW}Closed: {closed}  Filtered: {filt}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─'*W}{Style.RESET_ALL}")

    # ─── Connectivity self-test ────────────────────────────────────────────────
    def _network_check(self):
        """Quick check to confirm TCP connections work at all from this machine."""
        test_targets = [("8.8.8.8", 53), ("1.1.1.1", 53)]
        for host, port in test_targets:
            result = self._tcp_connect(host, port)
            if result == "open":
                return True
        return False

    # ─── Main run ─────────────────────────────────────────────────────────────
    def run(self):
        print(f"\n{Style.BRIGHT}{Fore.CYAN}Mini Nmap Python Scanner")
        print(f"Mode: {self.mode.upper()}  Threads: {self.threads}  "
              f"Timeout: {self.timeout}s  Ports: {len(self.ports)}{Style.RESET_ALL}")

        # Self-test network connectivity
        print(f"\n{Fore.CYAN}[*] Testing network connectivity...")
        if self._network_check():
            print(f"{Fore.GREEN}[+] Network OK — outbound TCP connections are working.")
        else:
            print(f"{Fore.RED}[!] WARNING: Cannot reach 8.8.8.8:53 — your network may block outbound connections.")
            print(f"{Fore.YELLOW}    If on a VM: switch VMware network adapter to BRIDGED mode.")
            print(f"{Fore.YELLOW}    Continuing scan anyway...\n")

        syn_warned = False
        self.t0 = time.time()

        for ip in self.targets:
            os_hint = ""

            # Host discovery
            if not self.no_ping:
                print(f"\n{Fore.CYAN}[*] Pinging {ip}...")
                alive, os_hint = self._ping(ip)
                if not alive:
                    print(f"{Fore.RED}[-] {ip} did not respond to ping.")
                    print(f"{Fore.YELLOW}    Add -Pn to skip ping and scan anyway.")
                    continue
                print(f"{Fore.GREEN}[+] {ip} is UP — {os_hint}")
            else:
                print(f"\n{Fore.CYAN}[*] -Pn mode: force-scanning {ip} ...")

            self.results[ip] = []
            host_results: List[Dict] = []

            # Thread pool scan
            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                fmap = {ex.submit(self._scan_port, ip, p): p for p in self.ports}
                it = (tqdm(as_completed(fmap), total=len(self.ports),
                           desc=f"  {ip}", unit="port", leave=True, colour="cyan")
                      if TQDM else as_completed(fmap))
                try:
                    for fut in it:
                        res = fut.result()
                        if res is None:
                            continue
                        if "error" in res:
                            if not syn_warned:
                                print(f"\n{Fore.RED}[!] {res['error']}")
                                self.mode = "tcp"
                                syn_warned = True
                        else:
                            with self._lock:
                                host_results.append(res)
                except KeyboardInterrupt:
                    print(f"\n{Fore.RED}[!] Interrupted.")
                    ex.shutdown(wait=False, cancel_futures=True)
                    break

            self.results[ip] = host_results
            self._display(ip, host_results, os_hint)

        self.t1 = time.time()
        self._summary()
        if self.output_file:
            self._export()

    # ─── Summary ──────────────────────────────────────────────────────────────
    def _summary(self):
        dur = self.t1 - self.t0
        print(f"\n{Style.BRIGHT}{Fore.CYAN}{'─'*62}")
        print(f"  Scan Summary")
        print(f"{'─'*62}{Style.RESET_ALL}")
        print(f"  Hosts Scanned    : {len(self.targets)}")
        print(f"  Total Ports      : {self.total_scanned}")
        print(f"  Open Ports Found : {Fore.GREEN}{self.open_count}{Style.RESET_ALL}")
        print(f"  Scan Duration    : {dur:.2f}s")
        print(f"{Fore.CYAN}{'─'*62}{Style.RESET_ALL}\n")

    # ─── Export ───────────────────────────────────────────────────────────────
    def _export(self):
        ext = os.path.splitext(self.output_file)[1].lower()
        try:
            if ext == ".json":
                with open(self.output_file, "w") as f:
                    json.dump(self.results, f, indent=4)
            elif ext == ".csv":
                with open(self.output_file, "w", newline="") as f:
                    w = csv.writer(f)
                    w.writerow(["IP","Port","Protocol","State","Service","Banner"])
                    for ip, rows in self.results.items():
                        for r in rows:
                            w.writerow([ip,r["port"],self.mode,
                                        r["state"],r["service"],r.get("banner","")])
            else:
                print(f"{Fore.RED}[!] Use .json or .csv extension.")
                return
            print(f"{Fore.GREEN}[+] Saved → {self.output_file}")
        except Exception as e:
            print(f"{Fore.RED}[!] Export error: {e}")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def parse_target(s: str) -> List[str]:
    try:
        if "/" in s:
            return [str(h) for h in ipaddress.ip_network(s, strict=False).hosts()]
        ip = socket.gethostbyname(s)
        if ip != s:
            print(f"{Fore.CYAN}[*] Resolved {s} → {ip}")
        return [ip]
    except Exception as e:
        print(f"{Fore.RED}[!] Cannot resolve '{s}': {e}")
        return []


def parse_ports(s: str) -> List[int]:
    if s.lower() in ("common", "top50"):
        return sorted(SERVICES.keys())
    if s.lower() == "top100":
        return sorted(TOP100)
    out: set = set()
    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            try:
                lo, hi = map(int, part.split("-",1))
                if 1<=lo<=hi<=65535: out.update(range(lo, hi+1))
            except ValueError:
                print(f"{Fore.RED}[!] Bad range: {part}")
        else:
            try:
                p = int(part)
                if 1<=p<=65535: out.add(p)
            except ValueError:
                print(f"{Fore.RED}[!] Bad port: {part}")
    return sorted(out)


def main():
    p = argparse.ArgumentParser(
        description="Python Mini Nmap – reliable port scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scanner.py -t scanme.nmap.org -Pn
  python3 scanner.py -t 192.168.1.1 -p 1-1024 -v
  python3 scanner.py -t 10.0.0.0/24 -p top100 --threads 200 -Pn
  python3 scanner.py -t example.com -p 22,80,443 -o out.json
        """)
    p.add_argument("-t","--target", required=True,
                   help="IP, hostname, or CIDR  e.g.  scanme.nmap.org")
    p.add_argument("-p","--ports", default="common",
                   help="'22,80,443'  '1-1024'  'common'(top50)  'top100'")
    p.add_argument("--threads", type=int, default=150)
    p.add_argument("--timeout", type=float, default=2.0,
                   help="Per-port timeout seconds (default 2)")
    p.add_argument("--mode", choices=["tcp","syn","udp"], default="tcp")
    p.add_argument("-o","--output", help="results.json or results.csv")
    p.add_argument("-v","--verbose", action="store_true",
                   help="Show closed/filtered ports too")
    p.add_argument("-Pn","--no-ping", action="store_true",
                   help="Skip ping — treat all hosts as up")
    args = p.parse_args()

    targets = parse_target(args.target)
    if not targets: return
    ports = parse_ports(args.ports)
    if not ports:
        print(f"{Fore.RED}[!] No valid ports."); return

    PortScanner(targets, ports, args.mode, args.threads,
                args.timeout, args.verbose, args.output,
                args.no_ping).run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Stopped.")
