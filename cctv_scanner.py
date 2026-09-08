#!/usr/bin/env python3
"""
Ultimate Network Audit Tool - Enhanced Edition
- IPv4 & IPv6 scanning
- Optional host discovery skip
- Configurable timeouts
- Expanded ports
- Verbose mode
- MAC OUI lookup
- Default credential brute-force (HTTP, SSH, Telnet, FTP, SNMP)
- CSV + JSON export
- Full logging
"""

import sys
import os
import socket
import ipaddress
import threading
import time
import csv
import json
import argparse
import subprocess
import re
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional imports
try:
    import netifaces
except ImportError:
    print("[!] netifaces not found. Install: pip install netifaces")
    sys.exit(1)

try:
    import requests
    from requests.auth import HTTPBasicAuth, HTTPDigestAuth
except ImportError:
    requests = None
    HTTPBasicAuth = HTTPDigestAuth = None

try:
    import paramiko
except ImportError:
    paramiko = None

try:
    from scapy.all import ARP, Ether, srp, IPv6, ICMPv6EchoRequest, sr1
    scapy_available = True
except ImportError:
    scapy_available = False

# ============================ COLOR CODES ============================
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
DIM = "\033[2m"

# ============================ BANNER ============================
BANNER = f"""
{BOLD}{CYAN}
   ▄████████  ▄█   ▄█▄    ▄████████ ████████▄     ▄████████ ████████▄   ▄█   ▄█▄ 
  ███    ███ ███ ▄███▀   ███    ███ ███   ▀███   ███    ███ ███   ▀███ ███ ▄███▀ 
  ███    █▀  ███▐██▀     ███    ███ ███    ███   ███    ███ ███    ███ ███▐██▀   
  ███        ▄█████▀     ███    ███ ███    ███  ▄███▄▄▄▄██▀ ███    ███ ▄█████▀    
▀███████████ ▀▀█████▄   ▀███████████ ███    ███ ▀▀███▀▀▀▀▀   ███    ███ ▀▀█████▄  
         ███   ███▐██▄    ███    ███ ███    ███   ███    ███ ███    ███   ███▐██▄ 
   ▄█    ███   ███ ▀███▄  ███    ███ ███   ▄███   ███    ███ ███   ▄███   ███ ▀███▄
 ▄████████▀    ▀█   ▀▀▀  █████   █▀  ████████▀    ██████████ ████████▀    ▀█   ▀▀▀
{RESET}
{BOLD}{GREEN}                 🔒 LEGITIMATE NETWORK AUDIT - FOR YOUR OWN PRIVATE NETWORK ONLY 🔒{RESET}
{BOLD}{DIM}              Version 6.1  |  Enhanced  |  Flexible  |  Full Credential Testing{RESET}
"""

# ============================ CONFIGURATION ============================
DEFAULT_PORTS = [
    80, 443, 554, 8080, 37777, 8000, 7000, 8554, 81, 88, 8899,
    23, 22, 21, 161, 1900, 5000, 5001, 8081, 8443, 9000, 9090
]
TIMEOUT = 0.5
MAX_THREADS = 50
PING_TIMEOUT = 1
RETRY_COUNT = 2

# ============================ MAC OUI DATABASE ============================
OUI_DB = {
    "00:0E:8E": "Hikvision",
    "00:10:4B": "Dahua",
    "00:12:34": "TP-Link",
    "00:14:22": "Huawei",
    "00:1A:2B": "ZTE",
    "00:1C:0A": "Cisco",
    "00:15:6D": "Ubiquiti",
    "00:17:C8": "Axis",
    "00:18:1A": "Panasonic",
    "00:1F:E2": "Sony",
    "00:23:3A": "ACTi",
    "00:25:64": "Vivotek",
    "00:26:4A": "D-Link",
    "00:30:48": "Netgear",
    "00:40:96": "Intel",
    "00:50:8B": "Samsung",
    "00:60:6E": "3Com",
    "00:80:37": "IBM",
    "00:90:A9": "Dell",
    "00:A0:C9": "Apple",
    "00:B0:D0": "HP",
    "00:C0:4F": "Philips",
    "00:D0:59": "Nokia",
    "00:04:20": "MikroTik",
    "00:17:9A": "Asus",
    "00:23:32": "Motorola",
    "00:1A:1E": "Siemens",
    "00:1B:21": "LG",
    "00:1E:0B": "Panasonic",
}
def get_vendor_from_mac(mac):
    if not mac:
        return "Unknown"
    mac_upper = mac.upper().replace("-", ":").replace(".", ":")
    for prefix, vendor in OUI_DB.items():
        if mac_upper.startswith(prefix.upper()):
            return vendor
    return "Unknown"

# ============================ DEFAULT CREDENTIALS ============================
DEFAULT_CREDS = {
    "hikvision": [
        ("admin", "12345"), ("admin", "admin"), ("admin", "123456"),
        ("admin", "hikvision"), ("admin", "888888"),
    ],
    "dahua": [
        ("admin", "admin"), ("admin", "123456"), ("admin", "dahua"),
        ("admin", "888888"),
    ],
    "tplink": [
        ("admin", "admin"), ("admin", "1234"), ("admin", "password"),
        ("user", "user"),
    ],
    "huawei": [
        ("admin", "admin"), ("admin", "123456"), ("admin", "huawei"),
        ("root", "admin"),
    ],
    "zte": [
        ("admin", "admin"), ("admin", "1234"), ("user", "user"),
        ("root", "admin"),
    ],
    "cisco": [
        ("admin", "admin"), ("admin", "cisco"), ("root", "cisco"),
        ("user", "user"),
    ],
    "ubiquiti": [
        ("ubnt", "ubnt"), ("admin", "admin"), ("admin", "ubnt"),
    ],
    "axis": [
        ("root", "pass"), ("admin", "admin"), ("admin", "password"),
    ],
    "panasonic": [
        ("admin", "12345"), ("admin", "admin"), ("admin", "password"),
    ],
    "sony": [
        ("admin", "admin"), ("admin", "1234"), ("root", "admin"),
    ],
    "acti": [
        ("admin", "admin"), ("admin", "123456"), ("admin", "acti"),
    ],
    "vivotek": [
        ("admin", "admin"), ("admin", "123456"), ("admin", "password"),
    ],
    "generic": [
        ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
        ("root", "root"), ("user", "user"), ("admin", "1234"),
        ("admin", "12345"), ("root", "123456"),
    ]
}

# ============================ LOGGING ============================
LOG_FILE = f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# ============================ UTILITY FUNCTIONS ============================
def get_my_ips():
    my_ips = set()
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        for af in [netifaces.AF_INET, netifaces.AF_INET6]:
            if af in addrs:
                for addr in addrs[af]:
                    ip = addr.get('addr')
                    if ip and not ip.startswith('127.'):
                        if '%' in ip:
                            ip = ip.split('%')[0]
                        my_ips.add(ip)
    return my_ips

def get_subnet_from_gateway():
    try:
        gateways = netifaces.gateways()
        for af in [netifaces.AF_INET, netifaces.AF_INET6]:
            if 'default' in gateways and af in gateways['default']:
                default_gw = gateways['default'][af]
                gateway_ip, iface_name = default_gw[0], default_gw[1]
                addrs = netifaces.ifaddresses(iface_name)
                if af in addrs:
                    for addr in addrs[af]:
                        ip = addr.get('addr')
                        netmask = addr.get('netmask')
                        if ip and netmask and not ip.startswith('127.'):
                            if '%' in ip:
                                ip = ip.split('%')[0]
                            if af == netifaces.AF_INET:
                                return ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                            else:
                                if '/' in netmask:
                                    prefix = int(netmask)
                                else:
                                    prefix = sum(bin(int(x,16)).count('1') for x in netmask.split(':'))
                                return ipaddress.IPv6Network(f"{ip}/{prefix}", strict=False)
    except:
        pass
    return None

def get_subnet_manually():
    logger.warning("Could not auto-detect subnet.")
    user_input = input("Enter subnet (e.g., 192.168.1.0/24 or 2001:db8::/64): ").strip()
    try:
        return ipaddress.ip_network(user_input, strict=False)
    except:
        logger.error("Invalid subnet. Exiting.")
        sys.exit(1)

def get_mac(ip):
    if scapy_available and ':' not in ip:
        try:
            arp = ARP(pdst=ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            result = srp(packet, timeout=1, verbose=0)[0]
            if result:
                return result[0][1].hwsrc
        except:
            pass
    try:
        if ':' in ip:
            output = subprocess.check_output(["ndp", "-n", ip], stderr=subprocess.DEVNULL).decode()
        else:
            output = subprocess.check_output(["arp", "-n", ip], stderr=subprocess.DEVNULL).decode()
        match = re.search(r"(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))", output)
        if match:
            return match.group(1)
    except:
        pass
    return None

def is_host_alive(ip):
    if scapy_available:
        try:
            if ':' in ip:
                pkt = IPv6(dst=ip) / ICMPv6EchoRequest()
                ans = sr1(pkt, timeout=PING_TIMEOUT, verbose=0)
                if ans:
                    return True
            else:
                arp = ARP(pdst=ip)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether / arp
                result = srp(packet, timeout=PING_TIMEOUT, verbose=0)[0]
                if result:
                    return True
        except:
            pass
    try:
        if ':' in ip:
            cmd = ["ping6", "-c", "1", "-W", "1", ip] if not sys.platform.startswith('win') else ["ping", "-n", "1", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip] if not sys.platform.startswith('win') else ["ping", "-n", "1", "-w", "1000", ip]
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def scan_port(ip, port, timeout=TIMEOUT, retries=RETRY_COUNT):
    for attempt in range(retries + 1):
        try:
            af = socket.AF_INET6 if ':' in ip else socket.AF_INET
            sock = socket.socket(af, socket.SOCK_STREAM)
            sock.settimeout(timeout * (attempt + 1))
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return True
        except:
            pass
        time.sleep(0.1)
    return False

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ""

def fingerprint_http(ip, port, timeout=2):
    if not requests:
        return {}, ""
    try:
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{ip}:{port}" if ':' not in ip else f"{scheme}://[{ip}]:{port}"
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            title = ""
            match = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE)
            if match:
                title = match.group(1).strip()[:80]
            model = ""
            for line in resp.text.splitlines():
                if "model" in line.lower() or "brand" in line.lower():
                    model = line.strip()[:50]
                    break
            manufacturer = "generic"
            text_lower = resp.text.lower()
            for brand in ["hikvision", "dahua", "tp-link", "huawei", "zte", "cisco", "ubiquiti", "axis", "panasonic", "sony", "acti", "vivotek"]:
                if brand in text_lower:
                    manufacturer = brand
                    break
            return {"manufacturer": manufacturer, "title": title, "model": model}
    except:
        pass
    return {}, ""

def classify_device(ip, open_ports, http_info, mac):
    vendor = get_vendor_from_mac(mac) if mac else ""
    cctv_ports = [554, 37777, 8000, 7000, 8554, 8899]
    router_ports = [23, 53, 67, 68, 161]
    if any(p in open_ports for p in cctv_ports):
        return "CCTV"
    if any(p in open_ports for p in router_ports) and not any(p in open_ports for p in cctv_ports):
        if http_info.get("manufacturer") in ["tplink", "huawei", "zte", "cisco", "ubiquiti"] or vendor in ["TP-Link", "Huawei", "ZTE", "Cisco", "Ubiquiti"]:
            return "Router"
        return "Unknown (likely Router)"
    if 80 in open_ports or 443 in open_ports:
        if http_info.get("manufacturer") in ["tplink", "huawei", "zte", "cisco", "ubiquiti"] or vendor in ["TP-Link", "Huawei", "ZTE", "Cisco", "Ubiquiti"]:
            return "Router"
        elif http_info.get("manufacturer") in ["hikvision", "dahua", "axis", "panasonic", "sony", "acti", "vivotek"] or vendor in ["Hikvision", "Dahua", "Axis", "Panasonic", "Sony", "ACTi", "Vivotek"]:
            return "CCTV"
        else:
            return "Web Device"
    if 22 in open_ports:
        return "SSH Server (PC/Server)"
    if 23 in open_ports and not (80 in open_ports or 443 in open_ports):
        return "Telnet Device (maybe Router)"
    if vendor in ["Hikvision", "Dahua", "Axis", "Panasonic", "Sony", "ACTi", "Vivotek"]:
        return "CCTV"
    if vendor in ["TP-Link", "Huawei", "ZTE", "Cisco", "Ubiquiti", "Netgear", "D-Link"]:
        return "Router"
    return "Unknown"

# ============================ BRUTE-FORCE FUNCTIONS ============================
def try_http_basic(ip, port, username, password):
    if not requests:
        return False
    try:
        url = f"http://{ip}:{port}" if ':' not in ip else f"http://[{ip}]:{port}"
        resp = requests.get(url, auth=HTTPBasicAuth(username, password), timeout=3, allow_redirects=False)
        if resp.status_code == 200 and "login" not in resp.text.lower():
            return True
        return False
    except:
        return False

def try_http_digest(ip, port, username, password):
    if not requests or not HTTPDigestAuth:
        return False
    try:
        url = f"http://{ip}:{port}" if ':' not in ip else f"http://[{ip}]:{port}"
        resp = requests.get(url, auth=HTTPDigestAuth(username, password), timeout=3)
        if resp.status_code == 200 and "login" not in resp.text.lower():
            return True
        return False
    except:
        return False

def try_http_form(ip, port, username, password, manufacturer):
    if not requests:
        return False
    try:
        url = f"http://{ip}:{port}" if ':' not in ip else f"http://[{ip}]:{port}"
        if manufacturer == "hikvision":
            login_url = f"{url}/ISAPI/Security/login"
            data = {"username": username, "password": password}
        elif manufacturer == "dahua":
            login_url = f"{url}/cgi-bin/login.cgi"
            data = {"username": username, "password": password}
        else:
            login_url = f"{url}/login"
            data = {"user": username, "pass": password, "username": username, "password": password}
        resp = requests.post(login_url, data=data, timeout=3, allow_redirects=False)
        if resp.status_code in [200, 302] and "fail" not in resp.text.lower() and "error" not in resp.text.lower():
            return True
        return False
    except:
        return False

def try_ssh(ip, username, password):
    if not paramiko:
        return False
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password, timeout=3)
        client.close()
        return True
    except:
        return False

def try_telnet(ip, username, password):
    import telnetlib
    try:
        tn = telnetlib.Telnet(ip, timeout=3)
        tn.read_until(b"login:", timeout=2)
        tn.write(username.encode('ascii') + b"\n")
        tn.read_until(b"Password:", timeout=2)
        tn.write(password.encode('ascii') + b"\n")
        result = tn.read_some()
        tn.close()
        if b"incorrect" not in result.lower() and b"failed" not in result.lower():
            return True
        return False
    except:
        return False

def try_ftp(ip, username, password):
    try:
        import ftplib
        ftp = ftplib.FTP(ip)
        ftp.login(username, password)
        ftp.quit()
        return True
    except:
        return False

def try_snmp_community(ip, community):
    try:
        oid = "1.3.6.1.2.1.1.1.0"
        cmd = ["snmpget", "-v", "2c", "-c", community, ip, oid, "-t", "2"]
        result = subprocess.run(cmd, capture_output=True, timeout=3, text=True)
        if result.returncode == 0 and "No such object" not in result.stdout:
            return True
        return False
    except:
        return False

def brute_force_device(ip, open_ports, http_info):
    manufacturer = http_info.get("manufacturer", "generic")
    creds_to_try = []
    if manufacturer in DEFAULT_CREDS:
        creds_to_try.extend(DEFAULT_CREDS[manufacturer])
    creds_to_try.extend(DEFAULT_CREDS.get("generic", []))
    seen = set()
    unique_creds = []
    for u, p in creds_to_try:
        if (u, p) not in seen:
            seen.add((u, p))
            unique_creds.append((u, p))
    
    valid_creds = []
    if 80 in open_ports or 443 in open_ports:
        port = 80 if 80 in open_ports else 443
        for u, p in unique_creds:
            if try_http_basic(ip, port, u, p):
                valid_creds.append({"service": "HTTP Basic", "username": u, "password": p})
                break
            if try_http_digest(ip, port, u, p):
                valid_creds.append({"service": "HTTP Digest", "username": u, "password": p})
                break
            if try_http_form(ip, port, u, p, manufacturer):
                valid_creds.append({"service": "HTTP Form", "username": u, "password": p})
                break
    if 22 in open_ports and paramiko:
        for u, p in unique_creds:
            if try_ssh(ip, u, p):
                valid_creds.append({"service": "SSH", "username": u, "password": p})
                break
    if 23 in open_ports:
        for u, p in unique_creds:
            if try_telnet(ip, u, p):
                valid_creds.append({"service": "Telnet", "username": u, "password": p})
                break
    if 21 in open_ports:
        for u, p in unique_creds:
            if try_ftp(ip, u, p):
                valid_creds.append({"service": "FTP", "username": u, "password": p})
                break
    if 161 in open_ports:
        for community in ["public", "private", "admin", "password", "123456"]:
            if try_snmp_community(ip, community):
                valid_creds.append({"service": "SNMP", "community": community})
                break
    return valid_creds

# ============================ MAIN SCAN ============================
def scan_ip(ip_str, my_ips, results, progress_lock, skip_ping=False, verbose=False):
    if ip_str in my_ips:
        return
    if not skip_ping and not is_host_alive(ip_str):
        if verbose:
            logger.debug(f"{ip_str} - not alive")
        return
    if verbose:
        logger.info(f"Scanning {ip_str}")
    open_ports = []
    with ThreadPoolExecutor(max_workers=len(DEFAULT_PORTS)) as executor:
        futures = {executor.submit(scan_port, ip_str, port): port for port in DEFAULT_PORTS}
        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                open_ports.append(port)
    if open_ports:
        open_ports.sort()
        hostname = get_hostname(ip_str)
        mac = get_mac(ip_str)
        http_info = {}
        if 80 in open_ports:
            http_info, _ = fingerprint_http(ip_str, 80)
        elif 443 in open_ports:
            http_info, _ = fingerprint_http(ip_str, 443)
        device_type = classify_device(ip_str, open_ports, http_info, mac)
        valid_creds = brute_force_device(ip_str, open_ports, http_info)
        info = {
            "ip": ip_str,
            "mac": mac,
            "hostname": hostname,
            "device_type": device_type,
            "open_ports": open_ports,
            "http_info": http_info,
            "credentials": valid_creds
        }
        with progress_lock:
            results.append(info)
        if verbose:
            logger.info(f"{ip_str} - open ports: {open_ports}")
    else:
        if verbose:
            logger.debug(f"{ip_str} - no open ports")

def print_results(results, output_csv, output_json):
    if not results:
        print(f"\n{YELLOW}⚠️  No devices found on this subnet.{RESET}")
        return
    print(f"\n{BOLD}{GREEN}✅ Found {len(results)} device(s):{RESET}\n")
    print("=" * 120)
    cred_found = False
    for idx, dev in enumerate(results, 1):
        print(f"{BOLD}{BLUE} [{idx}] {dev['ip']}{RESET}")
        if dev['mac']:
            vendor = get_vendor_from_mac(dev['mac'])
            print(f"     {DIM}MAC      : {dev['mac']} ({vendor}){RESET}")
        if dev['hostname']:
            print(f"     {DIM}Hostname : {dev['hostname']}{RESET}")
        print(f"     {GREEN}Type     : {dev['device_type']}{RESET}")
        if dev['http_info']:
            if dev['http_info'].get('title'):
                print(f"     {DIM}Title    : {dev['http_info']['title']}{RESET}")
            if dev['http_info'].get('model'):
                print(f"     {DIM}Model    : {dev['http_info']['model']}{RESET}")
        ports_str = ", ".join([str(p) for p in dev['open_ports']])
        print(f"     {DIM}Open ports: {ports_str}{RESET}")
        if dev['credentials']:
            for cred in dev['credentials']:
                if 'community' in cred:
                    print(f"     {YELLOW}🔑 SNMP Community : {cred['community']}{RESET}")
                else:
                    print(f"     {YELLOW}🔑 {cred['service']} : {cred['username']} / {cred['password']}{RESET}")
            cred_found = True
        else:
            print(f"     {DIM}No valid default credentials found.{RESET}")
        print("-" * 120)
    
    if output_csv:
        with open(output_csv, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "MAC", "Hostname", "Device Type", "Open Ports", "Credentials", "HTTP Title", "Model"])
            for dev in results:
                creds = "; ".join([f"{c.get('service','SNMP')}:{c.get('username','')}/{c.get('password','')}" if 'password' in c else f"SNMP community:{c['community']}" for c in dev['credentials']])
                writer.writerow([
                    dev['ip'], dev['mac'] or "", dev['hostname'], dev['device_type'],
                    ";".join(map(str, dev['open_ports'])), creds,
                    dev['http_info'].get('title', ''),
                    dev['http_info'].get('model', '')
                ])
        print(f"\n{DIM}📁 CSV results saved to {output_csv}{RESET}")
    if output_json:
        with open(output_json, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"{DIM}📁 JSON results saved to {output_json}{RESET}")
    if not cred_found:
        print(f"\n{YELLOW}⚠️  No default credentials were valid. Manual login might be required.{RESET}")

# ============================ MAIN ============================
def main():
    # Global declarations must be at the very beginning of the function
    global TIMEOUT, PING_TIMEOUT

    parser = argparse.ArgumentParser(description="Ultimate Network Audit Tool")
    parser.add_argument("-s", "--subnet", help="Subnet to scan (e.g., 192.168.1.0/24 or 2001:db8::/64)")
    parser.add_argument("-t", "--threads", type=int, default=MAX_THREADS, help="Concurrent thread count")
    parser.add_argument("-o", "--output", help="Output CSV file")
    parser.add_argument("--json", help="Output JSON file")
    parser.add_argument("--no-ping", action="store_true", help="Skip host discovery (scan all IPs)")
    parser.add_argument("--timeout", type=float, default=TIMEOUT, help="Port scan timeout (seconds)")
    parser.add_argument("--ping-timeout", type=float, default=PING_TIMEOUT, help="Host discovery timeout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    # Update global timeouts from command line
    TIMEOUT = args.timeout
    PING_TIMEOUT = args.ping_timeout
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    print(BANNER)
    logger.info(f"Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 120)

    if args.subnet:
        try:
            network = ipaddress.ip_network(args.subnet, strict=False)
        except:
            logger.error("Invalid subnet.")
            sys.exit(1)
    else:
        network = get_subnet_from_gateway()
        if not network:
            network = get_subnet_manually()

    my_ips = get_my_ips()
    logger.info(f"Scanning subnet: {network}")
    logger.info(f"Skipping your IPs: {', '.join(my_ips)}")
    logger.info(f"Using {args.threads} concurrent threads")
    if args.no_ping:
        logger.info("Skipping host discovery (--no-ping) - scanning all IPs")
    if args.verbose:
        logger.info("Verbose mode enabled")

    ip_list = [str(ip) for ip in network.hosts() if str(ip) not in my_ips]
    total = len(ip_list)
    results = []
    progress_lock = threading.Lock()
    scanned = 0
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_ip, ip, my_ips, results, progress_lock, args.no_ping, args.verbose): ip for ip in ip_list}
        for future in as_completed(futures):
            scanned += 1
            pct = (scanned / total) * 100
            elapsed = time.time() - start_time
            eta = (elapsed / scanned) * (total - scanned) if scanned > 0 else 0
            eta_str = f"ETA {int(eta//60)}m {int(eta%60)}s" if eta < 3600 else f"ETA {int(eta//3600)}h {int((eta%3600)//60)}m"
            bar_len = 40
            filled = int(bar_len * scanned / total)
            bar = '█' * filled + '░' * (bar_len - filled)
            print(f"\r[{GREEN}{bar}{RESET}] {pct:.1f}%  {scanned}/{total}  {eta_str}", end="", flush=True)

    print("\n" + "=" * 120)
    elapsed_total = time.time() - start_time
    logger.info(f"Scan completed in {elapsed_total:.1f} seconds.")
    print_results(results, args.output, args.json)
    logger.info(f"Log saved to {LOG_FILE}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{RED}⚠️  Scan interrupted by user.{RESET}")
        logger.warning("Scan interrupted by user.")
        sys.exit(0)