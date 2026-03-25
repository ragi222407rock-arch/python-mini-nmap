# Python Mini Nmap

A custom Python-based network port scanner with dynamic features inspired by Nmap. 

## 🚀 Features
- **3-Way TCP Connect Scan**, **TCP SYN Scan (Half Open)**, and **UDP Scan**.
- **Ping Sweep** (determines host liveness before deep scanning).
- **Banner Grabbing** on open active TCP ports.
- **Auto OS Fingerprinting** (Basic matching via Ping TTL limits).
- Multi-threaded execution for massive speed increases.
- Port translation to exact common Service Names.
- Custom beautiful terminal outputs with colored indicators.

## 🛠️ Installation

Make sure you have python installed natively on your machine.
Users on Kali Linux/Ubuntu can easily fetch and run this tool without issues.

1. First, clone the repository to your system:
```bash
git clone https://github.com/ragi222407rock-arch/python-mini-nmap.git
cd python-mini-nmap
```

2. Install the required dependencies (`colorama` and `tqdm` for UI tracking):
```bash
pip install -r requirements.txt
```

## 📖 How to Use

Run the `scanner.py` file through your terminal with Python. 

### 1. Basic Scan Summary (Default Custom Ports)
Scans the Top 50 most common ports of a target immediately using a default TCP connection.
```bash
python scanner.py --target example.com
```

### 2. Scanning a Network Subnet
To scan multiple devices natively on your local network space using CIDR notation.
```bash
python scanner.py --target 192.168.1.0/24
```

### 3. Targeting Specific Ports
Specify an exact singular port (like `80`), numerous split ports (`22,80,443`), or an interconnected range (`1-1024`).
```bash
python scanner.py --target 192.168.1.1 --ports 1-1024
```

### 4. Changing Port Speeds & Toggling Scan Type
Increase threads beyond the default (100) and decrease the response timeout mapping (default is 1s). *Example runs a UDP scan with massive threads.*
```bash
python scanner.py --target 192.168.1.1 --mode udp --threads 200 --timeout 0.5
```

### 5. Exporting Results
Dump the exact live results to a file for later analytical use.
```bash
python scanner.py --target example.com --output results.json
# Or use CSV
python scanner.py --target example.com --output data.csv
```

### 💡 Advanced Full Test:
This will output a robust verbose scan containing a ping sweep, OS fingerprint, 300 threaded scan on every port through 1-1000 without hiding filtered or closed TCP connections, outputting to a JSON.
```bash
python scanner.py -t example.com -p 1-1000 --threads 300 -mode tcp -o results.json -v
```

---
**Disclaimer**: This tool is for educational purposes and authorized auditing only. Standard SYN/RAW sockets require internal Admin/root privileges to execute cleanly!
