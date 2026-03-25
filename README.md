# 🔍 Python Mini Nmap — Port Scanner

A powerful, lightweight Python-based port scanner inspired by Nmap. Built with raw sockets, multi-threading, banner grabbing, OS fingerprinting, and a clean terminal UI.

---

## ✨ Features

| Feature | Details |
|---|---|
| **TCP Connect Scan** | Full 3-way handshake via non-blocking select() |
| **TCP SYN Scan** | Half-open raw socket scan (needs root) |
| **UDP Scan** | Basic UDP port probing |
| **Banner Grabbing** | Grabs HTTP `Server:` header and service banners |
| **OS Fingerprinting** | TTL-based OS guess (Linux / Windows / Network device) |
| **Ping Sweep** | Checks if host is alive before scanning |
| **CIDR Subnet Scan** | Scan entire subnets (e.g. 192.168.1.0/24) |
| **Multi-threading** | Up to 150+ concurrent threads |
| **Progress Bar** | Live tqdm progress per target |
| **Network Self-Test** | Auto-checks outbound connectivity before scanning |
| **Export Results** | Save output as JSON or CSV |
| **Color Output** | Green=open, Yellow=filtered, Red=closed |

---

## 🛠️ Installation

### On Kali Linux / Ubuntu:

```bash
# 1. Clone the repository
git clone https://github.com/ragi222407rock-arch/python-mini-nmap.git
cd python-mini-nmap

# 2. (Optional but recommended) create a virtual environment
python3 -m venv myenv
source myenv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

### On Windows:
```powershell
git clone https://github.com/ragi222407rock-arch/python-mini-nmap.git
cd "python-mini-nmap"
pip install -r requirements.txt
```

---

## 🚀 Usage

```
python3 scanner.py -t <target> [options]
```

### All Arguments

| Argument | Short | Default | Description |
|---|---|---|---|
| `--target` | `-t` | *(required)* | IP, hostname, or CIDR |
| `--ports` | `-p` | `common` | Port range / list / preset |
| `--mode` | | `tcp` | `tcp`, `syn`, `udp` |
| `--threads` | | `150` | Number of parallel threads |
| `--timeout` | | `2.0` | Seconds to wait per port |
| `--output` | `-o` | *(none)* | Save to `results.json` or `results.csv` |
| `--verbose` | `-v` | off | Show closed & filtered ports too |
| `--no-ping` | `-Pn` | off | Skip ping, force-scan (use for internet targets) |

### Port Presets

| Value | Ports Scanned |
|---|---|
| `common` | Top 50 well-known ports (default) |
| `top100` | Top 100 common ports |
| `1-1024` | Port range |
| `22,80,443` | Specific ports |

---

## 📖 Examples

### ✅ Recommended — Scan Nmap's official test server (always has open ports):
```bash
python3 scanner.py -t scanme.nmap.org -Pn
```

### Basic scan (top 50 ports, auto ping):
```bash
python3 scanner.py -t 192.168.1.1
```

### Scan specific ports:
```bash
python3 scanner.py -t 192.168.1.1 -p 22,80,443,3306,8080
```

### Scan a port range (1–1024):
```bash
python3 scanner.py -t 192.168.1.1 -p 1-1024
```

### Scan top 100 ports with more threads:
```bash
python3 scanner.py -t 192.168.1.1 -p top100 --threads 200
```

### Skip ping (for internet targets / CDN servers):
```bash
python3 scanner.py -t amazon.com -Pn
python3 scanner.py -t tesla.com -Pn
```

### Scan an entire subnet:
```bash
python3 scanner.py -t 192.168.1.0/24 -p 22,80,443
```

### Show ALL ports including closed/filtered (verbose):
```bash
python3 scanner.py -t 192.168.1.1 -p 1-1024 -v
```

### UDP scan:
```bash
python3 scanner.py -t 192.168.1.1 --mode udp -p 53,67,69,123,161
```

### SYN scan (requires root/Administrator):
```bash
sudo python3 scanner.py -t 192.168.1.1 --mode syn -Pn
```

### Export results to JSON:
```bash
python3 scanner.py -t 192.168.1.1 -Pn -o results.json
```

### Export results to CSV:
```bash
python3 scanner.py -t 192.168.1.1 -Pn -o results.csv
```

### Full advanced scan:
```bash
python3 scanner.py -t scanme.nmap.org -p 1-1000 --threads 200 --timeout 2 --mode tcp -Pn -v -o output.json
```

---

## 📊 Sample Output

```
Mini Nmap Python Scanner
Mode: TCP  Threads: 150  Timeout: 2.0s  Ports: 50

[*] Testing network connectivity...
[+] Network OK — outbound TCP connections are working.

[*] -Pn mode: force-scanning 45.33.32.156 ...

──────────────────────────────────────────────────────────────
  Scan results for: 45.33.32.156  Linux/Unix (TTL≤64)
──────────────────────────────────────────────────────────────
  PORT          STATE       SERVICE          BANNER
  ──────────────────────────────────────────────────────────
  22/tcp        open        ssh              SSH-2.0-OpenSSH_6.6.1p1
  80/tcp        open        http             Server: Apache/2.4.7
──────────────────────────────────────────────────────────────

  Scan Summary
──────────────────────────────────────────────────────────────
  Hosts Scanned    : 1
  Total Ports      : 50
  Open Ports Found : 2
  Scan Duration    : 2.01s
──────────────────────────────────────────────────────────────
```

---

## 🐛 Troubleshooting

### ❌ "No open ports found" on internet targets (Samsung, Amazon, Tesla)
These big servers use **enterprise CDN firewalls (Akamai/Cloudflare)** that block most port scanners.

✅ Always use **`-Pn`** for internet targets:
```bash
python3 scanner.py -t target.com -Pn
```

✅ Test with **`scanme.nmap.org`** first (Nmap's official test server — guaranteed open ports):
```bash
python3 scanner.py -t scanme.nmap.org -Pn
```

### ❌ "Network OK" check fails — VM cannot reach internet
If on VMware, your **network adapter might be set to NAT** (which can block outbound probes).

**Fix:**
1. VMware → **VM → Settings → Network Adapter**
2. Change from **NAT** → **Bridged (Autodetect)**
3. Click OK and retry

### ❌ SYN scan permission error
```bash
sudo python3 scanner.py -t 192.168.1.1 --mode syn -Pn
```
SYN scan requires root privileges on Linux / Administrator on Windows.

### ❌ `requirements.txt` not found error
Make sure you `cd` into the cloned folder first:
```bash
cd python-mini-nmap
pip install -r requirements.txt
```

---

## 📁 Project Structure

```
python-mini-nmap/
├── scanner.py        # Main scanner (all logic)
├── requirements.txt  # colorama, tqdm
└── README.md         # This file
```

---

## ⚠️ Disclaimer

This tool is for **educational purposes and authorized security testing only**.  
Do **not** scan hosts you do not own or have explicit permission to test.  
Unauthorized port scanning may be **illegal** in your country.

---

## 📜 License

MIT License — free to use, modify, and distribute.
