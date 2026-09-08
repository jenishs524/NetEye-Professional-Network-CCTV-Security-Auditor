```markdown
# NetEye – Professional Network & CCTV Security Auditor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](https://github.com/yourusername/neteye)

**NetEye** is a state‑of‑the‑art, multi‑threaded network auditing tool designed for security professionals, IT administrators, and ethical hackers. It discovers all live hosts on your network (IPv4/IPv6), identifies CCTV cameras, routers, and other IoT devices, extracts detailed metadata (MAC, hostname, vendor, HTTP titles), and performs brute‑force testing of **default credentials** across a wide range of services.

Whether you are conducting a routine security assessment or responding to an incident, NetEye gives you a complete, real‑time picture of your network’s exposed attack surface – all in one intuitive tool.

---

## ✨ Features

- 🌐 **Dual‑stack scanning** – supports both IPv4 and IPv6 out‑of‑the‑box.
- 📡 **Smart host discovery** – uses ARP (IPv4) / Neighbor Discovery (IPv6) with fallback to ICMP ping. Disable with `--no-ping` for stealth‑mode scanning.
- 🔌 **Comprehensive port scanning** – scans a curated list of 21 common CCTV, router, and management ports (80, 443, 554, 8080, 37777, 8000, 7000, 8554, 81, 88, 8899, 23, 22, 21, 161, 1900, 5000, 5001, 8081, 8443, 9000, 9090).
- 🖥️ **MAC OUI resolution** – instantly identifies device vendors from MAC prefixes (over 150+ entries – Hikvision, Dahua, Cisco, TP‑Link, Huawei, etc.).
- 🔎 **HTTP/HTTPS fingerprinting** – extracts page titles, model numbers, and manufacturer strings from web interfaces.
- 🏷️ **Intelligent classification** – automatically labels each device as **CCTV**, **Router**, **PC/Server**, **Telnet device**, or **Unknown** based on open ports and fingerprint data.
- 🔑 **Default credential brute‑force** – tests hundreds of factory‑default username/password combinations for:
  - HTTP Basic, Digest, and Form‑based authentication
  - SSH (using Paramiko)
  - Telnet
  - FTP
  - SNMP (community strings: `public`, `private`, `admin`, etc.)
- 📊 **Export capabilities** – save results to **CSV** and **JSON** for further analysis or integration.
- 📝 **Detailed logging** – every action is logged to a timestamped file – perfect for audit trails.
- 🎨 **Colourful console output** – professional banner, progress bar, and colour‑coded results for easy reading.

---

## 📸 Screenshots

*(Add your own screenshots here for a polished presentation)*

- **Scanning in progress**  
  ![Scanning](screenshots/scanning.png)

- **Results output**  
  ![Results](screenshots/results.png)

---

## ⚙️ Installation

### Prerequisites

- **Python 3.8 or higher**
- **pip** (Python package manager)
- **root/administrator privileges** (for raw socket operations and ARP/NDP packets)

### Step 1 – Install system dependencies

On **Debian/Ubuntu**:
```bash
sudo apt update
sudo apt install libpcap-dev snmp -y
```

On **macOS** (Homebrew):
```bash
brew install libpcap snmp
```

On **Windows** – install [Npcap](https://npcap.com/) and ensure `snmpget` is in your PATH.

### Step 2 – Clone the repository

```bash
git clone https://github.com/yourusername/neteye.git
cd neteye
```

### Step 3 – Install Python dependencies

```bash
pip install -r requirements.txt
```

**`requirements.txt`** content:
```
netifaces
requests
paramiko
scapy
```

---

## 🚀 Usage

### Basic usage (auto‑detect subnet)
```bash
sudo python3 neteye.py
```

### Recommended advanced usage (skip host discovery, verbose, export)
```bash
sudo python3 neteye.py --no-ping -v -t 100 -o results.csv --json results.json
```

### Specify a custom subnet
```bash
sudo python3 neteye.py -s 192.168.1.0/24
```

### Increase port scan timeout (for slower networks)
```bash
sudo python3 neteye.py --timeout 1.0
```

---

## 🔧 Command‑Line Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message and exit. |
| `-s SUBNET, --subnet SUBNET` | Target subnet (e.g., `192.168.1.0/24` or `2001:db8::/64`). |
| `-t THREADS, --threads THREADS` | Number of concurrent threads (default: 50). |
| `-o OUTPUT, --output OUTPUT` | Save results to CSV file. |
| `--json JSON` | Save results to JSON file. |
| `--no-ping` | **Skip host discovery** – scan every IP in the subnet (essential for networks that block ICMP/ARP). |
| `--timeout TIMEOUT` | Port scan timeout in seconds (default: 0.5). |
| `--ping-timeout PING_TIMEOUT` | Host discovery timeout (default: 1.0). |
| `-v, --verbose` | Enable verbose logging (shows each IP being scanned and open ports). |

---

## 🔄 Workflow (How It Works)

NetEye follows a systematic pipeline. The diagram below illustrates the process:

```mermaid
graph TD
    A[Start] --> B[Auto-detect / parse subnet]
    B --> C[Generate list of IPs (exclude own)]
    C --> D{--no-ping?}
    D -->|No| E[Perform ARP/NDP/ping host discovery]
    D -->|Yes| F[Skip host discovery]
    E --> G[For each alive IP]
    F --> G
    G --> H[Concurrent port scan (21 CCTV + common ports)]
    H --> I{Open ports found?}
    I -->|No| J[Skip this IP]
    I -->|Yes| K[Retrieve MAC address (ARP cache / NDP)]
    K --> L[Resolve MAC vendor via OUI database]
    L --> M[HTTP fingerprinting (if port 80/443 open)]
    M --> N[Classify device type based on ports, vendor, HTTP info]
    N --> O[Brute-force default credentials on open services]
    O --> P[Collect results: IP, MAC, hostname, type, ports, credentials]
    P --> Q[Update progress bar]
    Q --> R{More IPs?}
    R -->|Yes| G
    R -->|No| S[Print results table]
    S --> T[Export to CSV / JSON]
    T --> U[End]
```

---

## 📋 Example Output

```
[1] 192.168.18.1
    MAC      : aa:bb:cc:dd:ee:ff (TP-Link)
    Type     : Router
    Title    : TP-Link Wireless Router
    Open ports: 80, 443, 53, 161
    🔑 HTTP Basic : admin/admin
    🔑 SNMP Community : public
────────────────────────────────────────────────────────────────────────────
[2] 192.168.18.100
    MAC      : 00:0E:8E:12:34:56 (Hikvision)
    Type     : CCTV
    Title    : Hikvision DS-2CD2032
    Open ports: 80, 554, 37777, 8000
    🔑 HTTP Form : admin/12345
────────────────────────────────────────────────────────────────────────────
[3] 192.168.18.200
    MAC      : 00:1A:2B:3C:4D:5E (ZTE)
    Type     : Unknown (likely Router)
    Open ports: 23, 80
    No valid default credentials found.
────────────────────────────────────────────────────────────────────────────
```

---

## 🛡️ Legal Disclaimer

**⚠️ IMPORTANT – READ CAREFULLY**

NetEye is designed **solely for legitimate security auditing of networks you own or have explicit written permission to test**. By using this software, you agree that:

- You are fully responsible for complying with all applicable local, national, and international laws.
- Unauthorised scanning, credential testing, or access to devices constitutes a violation of computer fraud and abuse laws and may result in severe civil and criminal penalties.
- The author(s) of NetEye assume **no liability** for any misuse, damage, or legal consequences arising from the use of this tool.
- You will not use NetEye against any network or system without proper authorisation.

If you do not agree to these terms, you are not permitted to use this software.

---

## 🤝 Contributing

We welcome contributions! Whether it’s fixing bugs, adding new credential databases, supporting additional services, or improving documentation – all help is appreciated.

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a Pull Request.

Please ensure your code is well‑documented and follows the existing style.

---

## 📄 License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgements

- [netifaces](https://pypi.org/project/netifaces/) – for network interface enumeration.
- [scapy](https://scapy.net/) – for ARP/NDP packet crafting.
- [requests](https://docs.python-requests.org/) – for HTTP fingerprinting.
- [paramiko](https://www.paramiko.org/) – for SSH authentication testing.

---

## 📞 Support

For issues, questions, or suggestions, please open an [issue](https://github.com/yourusername/neteye/issues) on GitHub.

---

**Happy Auditing!**  
*Remember – with great power comes great responsibility.*
```
