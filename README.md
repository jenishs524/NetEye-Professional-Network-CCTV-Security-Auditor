```markdown
# 🕵️ NetEye – Advanced Network Intelligence & Security Auditing Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](https://github.com/yourusername/neteye)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

**NetEye** is a **high‑performance, multi‑threaded network auditing framework** designed for security researchers, penetration testers, and IT administrators. It goes beyond simple scanning – it **intelligently discovers**, **fingerprints**, and **actively tests for default credentials** across a wide range of IoT, CCTV, and networking devices. Think of it as your digital reconnaissance Swiss Army knife.

> *“Find, fingerprint, and breach default credentials like a pro.”*

---

## 🎯 Why NetEye?

- **Zero‑configuration intelligence** – automatically detects your subnet and starts scanning.
- **Unmatched speed** – leverages concurrency to scan hundreds of IPs in seconds.
- **Deep device profiling** – combines MAC OUI, HTTP meta‑data, and port behaviour to accurately classify devices.
- **Factory‑credential testing** – includes a massive built‑in database of default credentials for 15+ vendors (Hikvision, Dahua, TP‑Link, Cisco, Huawei, ZTE, Ubiquiti, Axis, Panasonic, Sony, ACTi, Vivotek, and more).
- **Actionable output** – get CSV, JSON, and colour‑coded console reports – ready for your next report or incident response.
- **Stealth‑ready** – disable ICMP/ARP probing with `--no-ping` to avoid detection.

Whether you’re hardening your own network, conducting a penetration test, or responding to a security incident, NetEye gives you the upper hand.

---

## ✨ Feature Set

| Category | Capabilities |
|----------|--------------|
| **Network Discovery** | IPv4 & IPv6, ARP/NDP/ICMP host detection (toggleable) |
| **Port Scanning** | Pre‑tuned list of 21 CCTV, router, and management ports; easily extensible |
| **Fingerprinting** | HTTP title, model string, manufacturer extraction; MAC OUI resolution (160+ vendors) |
| **Device Classification** | Automatically labels as CCTV, Router, PC/Server, Telnet, or Unknown |
| **Credential Testing** | HTTP Basic, Digest, Form‑based; SSH (Paramiko); Telnet; FTP; SNMP communities |
| **Export** | CSV, JSON, and full logging with timestamps |
| **Performance** | Configurable thread count; retry logic for flaky networks |
| **User Experience** | Real‑time progress bar, colour output, professional banner |

---

## 📸 Screenshots

*(Replace these placeholders with your own images)*

![Scan in progress](screenshots/scanning.png)
*Figure 1: Live scan showing progress and discovered devices.*

![Results](screenshots/results.png)
*Figure 2: Detailed results with credentials found.*

---

## ⚙️ Installation

### Prerequisites
- Python 3.8+
- `pip`
- Root/Administrator privileges (for raw sockets and ARP/NDP)

### Step 1 – System Dependencies

**Debian/Ubuntu:**
```bash
sudo apt update && sudo apt install libpcap-dev snmp -y
```
**macOS (Homebrew):**
```bash
brew install libpcap snmp
```
**Windows:** Install [Npcap](https://npcap.com/) and ensure `snmpget` is in your PATH.

### Step 2 – Clone & Install
```bash
git clone https://github.com/yourusername/neteye.git
cd neteye
pip install -r requirements.txt
```

`requirements.txt`:
```
netifaces
requests
paramiko
scapy
```

---

## 🚀 Usage

### Quick Start
```bash
sudo python3 neteye.py
```

### Advanced Scan (Recommended)
```bash
sudo python3 neteye.py --no-ping -v -t 100 -o results.csv --json results.json
```

### Custom Subnet & Timeouts
```bash
sudo python3 neteye.py -s 192.168.1.0/24 --timeout 1.0 --ping-timeout 2.0
```

---

## 🔧 Command‑Line Options

| Option | Description |
|--------|-------------|
| `-s, --subnet` | Target subnet (IPv4/IPv6). |
| `-t, --threads` | Number of concurrent threads (default: 50). |
| `-o, --output` | Save CSV report. |
| `--json` | Save JSON report. |
| `--no-ping` | Skip host discovery – scan every IP (stealth). |
| `--timeout` | Port scan timeout in seconds (default: 0.5). |
| `--ping-timeout` | Host discovery timeout (default: 1.0). |
| `-v, --verbose` | Enable verbose logging. |

---

## 🔄 Workflow

```mermaid
graph TD
    A[Start] --> B[Auto-detect / parse subnet]
    B --> C[Generate IP list (exclude self)]
    C --> D{--no-ping?}
    D -->|No| E[ARP/NDP/ping host discovery]
    D -->|Yes| F[Skip discovery]
    E --> G[For each alive IP]
    F --> G
    G --> H[Concurrent port scan (21 ports)]
    H --> I{Open ports?}
    I -->|No| J[Skip]
    I -->|Yes| K[Get MAC via ARP/NDP]
    K --> L[OUI vendor lookup]
    L --> M[HTTP fingerprint (if web port open)]
    M --> N[Classify device type]
    N --> O[Brute-force default credentials]
    O --> P[Collect results]
    P --> Q[Update progress]
    Q --> R{More IPs?}
    R -->|Yes| G
    R -->|No| S[Print results]
    S --> T[Export CSV / JSON]
    T --> U[End]
```

> *If the diagram does not render on GitHub, view the raw markdown – the Mermaid syntax is correct.*

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
─────────────────────────────────────────────────────────────
[2] 192.168.18.100
    MAC      : 00:0E:8E:12:34:56 (Hikvision)
    Type     : CCTV
    Title    : Hikvision DS-2CD2032
    Open ports: 80, 554, 37777, 8000
    🔑 HTTP Form : admin/12345
─────────────────────────────────────────────────────────────
[3] 192.168.18.200
    MAC      : 00:1A:2B:3C:4D:5E (ZTE)
    Type     : Unknown (likely Router)
    Open ports: 23, 80
    No valid default credentials found.
─────────────────────────────────────────────────────────────
```

---

## 🧠 Under the Hood – How It Works

### 1. Host Discovery
- **IPv4**: Sends ARP requests (scapy) – fast and reliable.
- **IPv6**: Uses Neighbor Discovery (ICMPv6) with fallback to ping6.
- If `--no-ping` is set, all IPs in the subnet are candidates – ideal for networks that block ICMP.

### 2. Port Scanning
- A curated list of 21 ports is scanned concurrently using threaded TCP connects with retries.
- Ports include: `80,443,554,8080,37777,8000,7000,8554,81,88,8899,23,22,21,161,1900,5000,5001,8081,8443,9000,9090`.

### 3. Fingerprinting & Classification
- **MAC OUI**: Matches the first three bytes against a 160+ vendor database.
- **HTTP**: Fetches `/` and parses `<title>`, looks for `model`/`brand` strings, and identifies manufacturer via keyword matching.
- **Classification Rules**:
  - If CCTV ports (`554, 37777, 8000, 7000, 8554, 8899`) are open → **CCTV**.
  - If router ports (`23, 53, 67, 68, 161`) are open and no CCTV ports → **Router**.
  - If HTTP and vendor matches CCTV vendor → **CCTV**; if vendor matches router vendor → **Router**.
  - SSH → **PC/Server**; Telnet alone → **Telnet Device**.

### 4. Credential Testing
- **HTTP**:
  - Basic Auth: sends credentials via `Authorization: Basic`.
  - Digest Auth: uses `requests.auth.HTTPDigestAuth`.
  - Form‑based: POSTs to `/login`, `/ISAPI/Security/login` (Hikvision), `/cgi-bin/login.cgi` (Dahua) with common parameters.
- **SSH**: Uses Paramiko to attempt password authentication.
- **Telnet**: Automates login via `telnetlib`.
- **FTP**: Uses `ftplib` to login.
- **SNMP**: Uses `snmpget` with community strings (`public`, `private`, `admin`, `password`, `123456`).

### 5. Credential Database
- Over **100+ default credential pairs** organised by manufacturer.
- Manufacturers covered: Hikvision, Dahua, TP‑Link, Huawei, ZTE, Cisco, Ubiquiti, Axis, Panasonic, Sony, ACTi, Vivotek, plus a generic fallback list.

---

## 🛡️ Legal Disclaimer

**⚠️ WARNING – READ BEFORE USE**

NetEye is a **professional security auditing tool** intended **exclusively** for:
- Networks you own.
- Networks for which you have **explicit written permission** from the owner.

**Unauthorised scanning, probing, or credential testing is illegal** in most jurisdictions and may lead to severe legal penalties. The author(s) of NetEye assume **no liability** for any misuse, damage, or legal consequences arising from the use of this software.

By downloading, installing, or using NetEye, you agree that you are solely responsible for complying with all applicable laws and that you will not use it for any unlawful purpose.

---

## 🤝 Contributing

We welcome contributions of all kinds – code, documentation, additional credential databases, or new fingerprinting heuristics. Here’s how you can help:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/awesome`).
3. Commit your changes (`git commit -m 'Add awesome feature'`).
4. Push to the branch (`git push origin feature/awesome`).
5. Open a Pull Request.

Please ensure your code is well‑documented and follows PEP8.

---

## 📄 License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgements

- [netifaces](https://pypi.org/project/netifaces/) – cross‑platform network interface enumeration.
- [scapy](https://scapy.net/) – low‑level packet crafting and ARP/NDP.
- [requests](https://docs.python-requests.org/) – elegant HTTP handling.
- [paramiko](https://www.paramiko.org/) – SSH protocol implementation.

---

## 📞 Support & Community

- **Issues**: [GitHub Issues](https://github.com/yourusername/neteye/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/neteye/discussions)
- **Email**: your-email@example.com (replace with yours)

---

**Happy Auditing!**  
*Remember – with great power comes great responsibility.*
```
