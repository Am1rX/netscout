#!/usr/bin/env python3
"""
NetScout — Professional Network Scanner
A fast, structured network discovery and analysis tool.

Usage:
    sudo python netscout.py [OPTIONS]

Requirements:
    - Root/Administrator privileges for ARP and SYN scans
    - Nmap installed and available in PATH
"""

import argparse
import ctypes
import csv
import json
import logging
import os
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
import scapy.all as scapy
from colorama import Fore, Style, init
from tqdm import tqdm

# ──────────────────────────────────────────────
# Initialization
# ──────────────────────────────────────────────

init(autoreset=True)

# ──────────────────────────────────────────────
# Logging setup
# ──────────────────────────────────────────────

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("netscout")


# ──────────────────────────────────────────────
# Data Models
# ──────────────────────────────────────────────

@dataclass
class Port:
    """Represents an open port discovered during an Nmap scan."""
    number: str
    service: str
    version: str = ""

    def __str__(self) -> str:
        version_str = f" ({self.version})" if self.version.strip() else ""
        return f"{self.number:<12} {self.service}{version_str}"


@dataclass
class Device:
    """Represents a network device discovered via ARP scan."""
    ip: str
    mac: str
    hostname: str = "Unknown"
    vendor: str = "Unknown"
    vlan: str = "Unknown"
    os_detected: str = "Unknown"
    open_ports: list[Port] = field(default_factory=list)
    network_distance: str = "Unknown"
    scan_time: str = ""
    is_host: bool = False

    def to_dict(self) -> dict:
        """Serialize device to a plain dictionary (JSON-safe)."""
        d = asdict(self)
        d["open_ports"] = [asdict(p) for p in self.open_ports]
        return d


# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

DEFAULT_CONFIG_PATH = Path("config.json")

DEFAULT_CONFIG: dict = {
    "vlan_mapping": {
        "192.168.1": "VLAN 10 - Office",
        "192.168.2": "VLAN 20 - Guests",
        "192.168.3": "VLAN 30 - Servers",
        "10.0.0":    "VLAN 40 - Management",
    },
    "nmap": {
        "scan_type": "-sS",
        "timing": "-T4",
        "max_retries": 1,
        "extra_flags": [],
    },
    "api": {
        "mac_vendor_url": "https://api.macvendors.com/",
        "timeout": 2,
        "rate_limit_seconds": 1.1,
    },
    "arp": {
        "timeout": 2,
    },
    "output": {
        "save_json": False,
        "save_csv": False,
        "save_html": False,
        "output_dir": "reports",
    },
}


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> dict:
    """Load configuration from a JSON file, falling back to defaults.

    Args:
        path: Path to the JSON configuration file.

    Returns:
        Merged configuration dictionary.
    """
    config = DEFAULT_CONFIG.copy()
    if path.exists():
        try:
            with path.open() as f:
                user_config = json.load(f)
            # Deep-merge user config into defaults
            for section, values in user_config.items():
                if isinstance(values, dict) and section in config:
                    config[section].update(values)
                else:
                    config[section] = values
            log.info(f"Loaded configuration from {path}")
        except (json.JSONDecodeError, OSError) as exc:
            log.warning(f"Could not read {path}: {exc}. Using defaults.")
    return config


# ──────────────────────────────────────────────
# Privilege Checks
# ──────────────────────────────────────────────

def is_admin() -> bool:
    """Return True if the process has root/administrator privileges."""
    try:
        return os.getuid() == 0
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]


def require_admin() -> None:
    """Warn the user if the script is not running with elevated privileges."""
    if not is_admin():
        print(
            f"\n{Fore.YELLOW}⚠  Warning: Not running as root/Administrator.\n"
            f"   ARP scan and SYN scan (-sS) may be incomplete or fail.\n"
            f"   Re-run with: sudo python netscout.py{Style.RESET_ALL}\n"
        )


# ──────────────────────────────────────────────
# Network Utilities
# ──────────────────────────────────────────────

def get_local_networks() -> list[str]:
    """Detect all local /24 network ranges from available interfaces.

    Returns:
        List of CIDR strings, e.g. ['192.168.1.0/24', '10.0.0.0/24'].
    """
    networks: set[str] = set()

    # Primary: gethostbyname_ex covers multiple interfaces
    try:
        _, _, ip_list = socket.gethostbyname_ex(socket.gethostname())
        for ip in ip_list:
            if not ip.startswith("127."):
                networks.add(_ip_to_network(ip))
    except socket.gaierror:
        log.debug("gethostbyname_ex failed; trying fallback method.")

    # Fallback: outbound socket trick
    if not networks:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.1)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            if not local_ip.startswith("127."):
                networks.add(_ip_to_network(local_ip))
        except OSError:
            log.error("Could not automatically determine local network.")

    return sorted(networks)


def _ip_to_network(ip: str) -> str:
    """Convert an IP address string to its /24 network CIDR."""
    return ".".join(ip.split(".")[:3]) + ".0/24"


def get_host_ips() -> set[str]:
    """Return the set of IP addresses belonging to the local host."""
    try:
        _, _, ip_list = socket.gethostbyname_ex(socket.gethostname())
        return set(ip_list)
    except socket.gaierror:
        return set()


def validate_ip(ip: str) -> bool:
    """Return True if the string is a valid IPv4 address."""
    parts = ip.strip().split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def validate_cidr(cidr: str) -> bool:
    """Return True if the string looks like a valid IPv4 CIDR block."""
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$"
    return bool(re.match(pattern, cidr))


# ──────────────────────────────────────────────
# ARP Scanner
# ──────────────────────────────────────────────

def scan_network(network_range: str, timeout: int = 2) -> list[dict]:
    """Perform a broadcast ARP scan over the given network range.

    Args:
        network_range: CIDR block to scan, e.g. '192.168.1.0/24'.
        timeout: Seconds to wait for ARP replies.

    Returns:
        List of dicts with 'ip' and 'mac' keys.
    """
    arp = scapy.ARP(pdst=network_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    answered, _ = scapy.srp(broadcast / arp, timeout=timeout, verbose=False)
    return [{"ip": ans[1].psrc, "mac": ans[1].hwsrc} for ans in answered]


# ──────────────────────────────────────────────
# Device Enrichment
# ──────────────────────────────────────────────

def get_vlan(ip: str, vlan_mapping: dict[str, str]) -> str:
    """Map an IP address prefix to a VLAN label.

    Args:
        ip: IPv4 address string.
        vlan_mapping: Dict mapping IP prefixes to VLAN names.

    Returns:
        VLAN name string, or 'Unknown VLAN' if no match.
    """
    prefix = ".".join(ip.split(".")[:3])
    return vlan_mapping.get(prefix, "Unknown VLAN")


def reverse_dns_lookup(ip: str) -> str:
    """Resolve an IP address to its hostname via reverse DNS.

    Args:
        ip: IPv4 address string.

    Returns:
        Hostname string, or 'Unknown' on failure.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "Unknown"


_vendor_cache: dict[str, str] = {}
_last_vendor_request: float = 0.0


def get_mac_vendor(mac: str, api_config: dict) -> str:
    """Look up the hardware vendor for a MAC address via the macvendors.com API.

    Results are cached in-memory to avoid redundant requests.
    A configurable rate-limit delay is applied between API calls.

    Args:
        mac: MAC address string (colon-separated).
        api_config: Dict with keys 'mac_vendor_url', 'timeout', 'rate_limit_seconds'.

    Returns:
        Vendor name string, or 'Unknown' on failure.
    """
    global _last_vendor_request

    if not mac or mac.lower() in ("unknown", "ff:ff:ff:ff:ff:ff"):
        return "N/A"

    mac_upper = mac.upper()
    if mac_upper in _vendor_cache:
        return _vendor_cache[mac_upper]

    # Respect API rate limit
    elapsed = time.time() - _last_vendor_request
    wait = api_config.get("rate_limit_seconds", 1.1) - elapsed
    if wait > 0:
        time.sleep(wait)

    try:
        url = api_config["mac_vendor_url"] + mac
        resp = requests.get(url, timeout=api_config.get("timeout", 2))
        _last_vendor_request = time.time()
        if resp.status_code == 200:
            vendor = resp.text.strip()
            _vendor_cache[mac_upper] = vendor
            return vendor
    except requests.RequestException as exc:
        log.debug(f"MAC vendor lookup failed for {mac}: {exc}")

    _vendor_cache[mac_upper] = "Unknown"
    return "Unknown"


# ──────────────────────────────────────────────
# Nmap Integration
# ──────────────────────────────────────────────

def run_nmap_scan(ip: str, nmap_config: dict, vlan_mapping: dict) -> Optional[Device]:
    """Execute an Nmap scan against a single IP and return a Device object.

    Args:
        ip: Target IPv4 address.
        nmap_config: Dict with keys 'scan_type', 'timing', 'max_retries', 'extra_flags'.
        vlan_mapping: VLAN prefix → name mapping.

    Returns:
        Populated Device on success, None on failure.
    """
    scan_type = nmap_config.get("scan_type", "-sS")
    timing = nmap_config.get("timing", "-T4")
    max_retries = str(nmap_config.get("max_retries", 1))
    extra_flags = nmap_config.get("extra_flags", [])

    cmd = [
        "nmap", scan_type, "-O", "--version-light",
        timing, "-n",
        "--max-retries", max_retries,
        *extra_flags,
        ip,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
        )
        output = result.stdout
    except FileNotFoundError:
        log.error("Nmap not found. Install it and ensure it is in your PATH.")
        return None
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr or ""
        if "requires root" in stderr or "TCP/IP fingerprinting" in stderr:
            log.error(f"Nmap requires root privileges for {ip}.")
        else:
            log.error(f"Nmap error on {ip}: {stderr.strip()}")
        return None

    device = Device(
        ip=ip,
        mac="",
        hostname=reverse_dns_lookup(ip),
        vlan=get_vlan(ip, vlan_mapping),
        scan_time=datetime.now().isoformat(timespec="seconds"),
    )

    # OS detection
    os_match = re.search(r"OS details: (.+)", output)
    device.os_detected = os_match.group(1).strip() if os_match else "Could not be determined"

    # Network distance
    dist_match = re.search(r"Network Distance: (\d+) hop", output)
    device.network_distance = dist_match.group(1) if dist_match else "Unknown"

    # Open ports
    for m in re.finditer(r"(\d+/tcp)\s+open\s+([\w\-\.]+)\s*(.*)", output):
        device.open_ports.append(Port(
            number=m.group(1),
            service=m.group(2),
            version=m.group(3).strip(),
        ))

    return device


# ──────────────────────────────────────────────
# Output / Reporting
# ──────────────────────────────────────────────

def _banner() -> None:
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════╗
║        NetScout  —  Network Scanner      ║
║         github.com/your-handle/netscout  ║
╚══════════════════════════════════════════╝{Style.RESET_ALL}
""")


def print_device_summary(device: Device, index: int) -> None:
    """Print a compact one-device summary row."""
    host_tag = f" {Fore.MAGENTA}(you){Style.RESET_ALL}" if device.is_host else ""
    print(
        f"  {Fore.CYAN}[{index:>3}]{host_tag}  "
        f"{Fore.YELLOW}{device.ip:<17}{Style.RESET_ALL}"
        f"{Fore.WHITE}{device.mac:<20}{Style.RESET_ALL}"
        f"{Fore.GREEN}{device.hostname:<28}{Style.RESET_ALL}"
        f"{Fore.BLUE}{device.vlan}{Style.RESET_ALL}"
    )


def print_device_detail(device: Device) -> None:
    """Print full Nmap scan results for a device."""
    sep = f"{Fore.CYAN}{'─' * 50}{Style.RESET_ALL}"
    print(f"\n{sep}")
    print(f"  {Fore.CYAN}Detailed Report — {device.ip}{Style.RESET_ALL}")
    print(sep)
    print(f"  {'IP Address':<20}: {Fore.YELLOW}{device.ip}{Style.RESET_ALL}")
    print(f"  {'Hostname':<20}: {Fore.YELLOW}{device.hostname}{Style.RESET_ALL}")
    print(f"  {'MAC':<20}: {Fore.YELLOW}{device.mac or 'N/A'}{Style.RESET_ALL}")
    print(f"  {'Vendor':<20}: {Fore.CYAN}{device.vendor or 'N/A'}{Style.RESET_ALL}")
    print(f"  {'VLAN':<20}: {Fore.BLUE}{device.vlan}{Style.RESET_ALL}")
    print(f"  {'OS Detected':<20}: {Fore.YELLOW}{device.os_detected}{Style.RESET_ALL}")
    print(f"  {'Network Distance':<20}: {Fore.YELLOW}{device.network_distance} hops{Style.RESET_ALL}")
    print(f"  {'Scan Time':<20}: {Fore.WHITE}{device.scan_time}{Style.RESET_ALL}")

    if device.open_ports:
        print(f"\n  {Fore.GREEN}Open Ports:{Style.RESET_ALL}")
        for port in device.open_ports:
            print(f"    {Fore.YELLOW}{port}{Style.RESET_ALL}")
    else:
        print(f"\n  {Fore.YELLOW}No open TCP ports found.{Style.RESET_ALL}")
    print(sep)


def save_json(devices: list[Device], output_dir: str) -> Path:
    """Write all devices to a JSON file.

    Args:
        devices: List of scanned Device objects.
        output_dir: Directory to write the report into.

    Returns:
        Path to the written file.
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path(output_dir) / f"netscout_{ts}.json"
    with out.open("w") as f:
        json.dump([d.to_dict() for d in devices], f, indent=2)
    return out


def save_csv(devices: list[Device], output_dir: str) -> Path:
    """Write all devices to a CSV file.

    Args:
        devices: List of scanned Device objects.
        output_dir: Directory to write the report into.

    Returns:
        Path to the written file.
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path(output_dir) / f"netscout_{ts}.csv"
    fields = ["ip", "mac", "hostname", "vendor", "vlan", "os_detected", "network_distance", "scan_time"]
    with out.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for d in devices:
            row = d.to_dict()
            row["open_ports"] = "; ".join(str(p) for p in d.open_ports)
            writer.writerow({k: row.get(k, "") for k in fields})
    return out


def save_html(devices: list[Device], output_dir: str) -> Path:
    """Write all devices to a self-contained HTML report.

    Args:
        devices: List of scanned Device objects.
        output_dir: Directory to write the report into.

    Returns:
        Path to the written file.
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    ts_label = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ts_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path(output_dir) / f"netscout_{ts_file}.html"

    rows = ""
    for d in devices:
        ports_str = ", ".join(str(p) for p in d.open_ports) or "—"
        you_badge = '<span class="badge">you</span>' if d.is_host else ""
        rows += f"""
        <tr>
            <td>{d.ip} {you_badge}</td>
            <td>{d.mac or '—'}</td>
            <td>{d.hostname}</td>
            <td>{d.vendor}</td>
            <td>{d.vlan}</td>
            <td>{d.os_detected}</td>
            <td>{ports_str}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>NetScout Report — {ts_label}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e8f0;padding:2rem}}
  h1{{color:#63b3ed;font-size:1.6rem;margin-bottom:.25rem}}
  .meta{{color:#718096;font-size:.85rem;margin-bottom:1.5rem}}
  table{{width:100%;border-collapse:collapse;font-size:.9rem}}
  th{{background:#1a202c;color:#90cdf4;padding:.6rem 1rem;text-align:left;border-bottom:2px solid #2d3748}}
  td{{padding:.55rem 1rem;border-bottom:1px solid #2d3748;vertical-align:top}}
  tr:hover td{{background:#1a202c}}
  .badge{{background:#553c9a;color:#e9d8fd;font-size:.7rem;padding:.1rem .4rem;border-radius:999px;margin-left:.4rem}}
  @media(max-width:768px){{table{{font-size:.75rem}}td,th{{padding:.4rem .5rem}}}}
</style>
</head>
<body>
<h1>🛰 NetScout — Network Scan Report</h1>
<p class="meta">Generated: {ts_label} &nbsp;|&nbsp; Devices found: {len(devices)}</p>
<table>
  <thead>
    <tr>
      <th>IP Address</th><th>MAC</th><th>Hostname</th>
      <th>Vendor</th><th>VLAN</th><th>OS</th><th>Open Ports</th>
    </tr>
  </thead>
  <tbody>{rows}
  </tbody>
</table>
</body>
</html>"""

    out.write_text(html, encoding="utf-8")
    return out


# ──────────────────────────────────────────────
# CLI / Argument Parsing
# ──────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscout",
        description="NetScout — Professional network discovery and port scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python netscout.py --auto
  sudo python netscout.py --network 192.168.1.0/24
  sudo python netscout.py --ip 192.168.1.100
  sudo python netscout.py --auto --json --csv --html
  sudo python netscout.py --network 10.0.0.0/24 --config myconfig.json
        """,
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--auto", action="store_true", help="Auto-detect and scan all local networks")
    mode.add_argument("--network", metavar="CIDR", help="Scan a specific network range (e.g. 192.168.1.0/24)")
    mode.add_argument("--ip", metavar="IP", help="Scan a single IP address directly with Nmap")

    parser.add_argument("--config", metavar="FILE", default=str(DEFAULT_CONFIG_PATH), help="Path to JSON config file")
    parser.add_argument("--json", action="store_true", help="Save results to JSON")
    parser.add_argument("--csv", action="store_true", help="Save results to CSV")
    parser.add_argument("--html", action="store_true", help="Save results to HTML report")
    parser.add_argument("--output-dir", metavar="DIR", default="reports", help="Output directory for reports (default: reports)")
    parser.add_argument("--workers", type=int, default=10, help="Max parallel threads for enrichment (default: 10)")
    parser.add_argument("--no-vendor", action="store_true", help="Skip MAC vendor API lookup")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    return parser


# ──────────────────────────────────────────────
# Enrichment Pipeline
# ──────────────────────────────────────────────

def enrich_device(
    raw: dict,
    host_ips: set[str],
    config: dict,
    no_vendor: bool,
) -> Device:
    """Build a Device from a raw ARP result dict, adding hostname, VLAN, vendor.

    Args:
        raw: Dict with 'ip' and 'mac' keys from ARP scan.
        host_ips: Set of local host IP addresses.
        config: Full configuration dict.
        no_vendor: If True, skip MAC vendor API call.

    Returns:
        Enriched Device object.
    """
    ip = raw["ip"]
    mac = raw["mac"]
    device = Device(
        ip=ip,
        mac=mac,
        hostname=reverse_dns_lookup(ip),
        vlan=get_vlan(ip, config["vlan_mapping"]),
        vendor="N/A" if no_vendor else get_mac_vendor(mac, config["api"]),
        is_host=ip in host_ips,
    )
    return device


# ──────────────────────────────────────────────
# Main Entrypoint
# ──────────────────────────────────────────────

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    _banner()
    require_admin()

    # Load configuration
    config = load_config(Path(args.config))
    if args.json:
        config["output"]["save_json"] = True
    if args.csv:
        config["output"]["save_csv"] = True
    if args.html:
        config["output"]["save_html"] = True
    output_dir = args.output_dir or config["output"].get("output_dir", "reports")

    # ── Interactive mode if no CLI flags provided ────────────────────────
    if not (args.auto or args.network or args.ip):
        print(f"{Fore.CYAN}Select scan mode:{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}[1]{Style.RESET_ALL} Auto-detect all local networks")
        print(f"  {Fore.YELLOW}[2]{Style.RESET_ALL} Enter network range manually")
        print(f"  {Fore.YELLOW}[3]{Style.RESET_ALL} Scan a single IP with Nmap")
        choice = input("\nOption (1/2/3): ").strip()
        if choice == "1":
            args.auto = True
        elif choice == "2":
            args.network = input("Network range (e.g. 192.168.1.0/24): ").strip()
        elif choice == "3":
            args.ip = input("IP address: ").strip()
        else:
            print(f"{Fore.RED}Invalid choice. Exiting.{Style.RESET_ALL}")
            return 1

    # ── Single IP shortcut ────────────────────────────────────────────────
    if args.ip:
        if not validate_ip(args.ip):
            print(f"{Fore.RED}Invalid IP address: {args.ip}{Style.RESET_ALL}")
            return 1
        device = run_nmap_scan(args.ip, config["nmap"], config["vlan_mapping"])
        if device:
            print_device_detail(device)
            if config["output"]["save_json"]:
                p = save_json([device], output_dir)
                print(f"\n{Fore.GREEN}JSON saved → {p}{Style.RESET_ALL}")
            if config["output"]["save_html"]:
                p = save_html([device], output_dir)
                print(f"{Fore.GREEN}HTML saved → {p}{Style.RESET_ALL}")
        return 0

    # ── Determine networks to scan ────────────────────────────────────────
    if args.auto:
        networks = get_local_networks()
        if not networks:
            print(f"{Fore.RED}Could not detect any local network. Use --network.{Style.RESET_ALL}")
            return 1
        print(f"{Fore.CYAN}Detected networks: {', '.join(networks)}{Style.RESET_ALL}\n")
    else:
        if not validate_cidr(args.network):
            print(f"{Fore.RED}Invalid CIDR: {args.network}{Style.RESET_ALL}")
            return 1
        networks = [args.network]

    host_ips = get_host_ips()
    all_raw: dict[str, dict] = {}

    # ── ARP Discovery ─────────────────────────────────────────────────────
    for net in networks:
        print(f"{Fore.MAGENTA}Scanning {net} …{Style.RESET_ALL}")
        try:
            found = scan_network(net, timeout=config["arp"]["timeout"])
            new = 0
            for dev in found:
                if dev["ip"] not in all_raw:
                    all_raw[dev["ip"]] = dev
                    new += 1
            print(f"  {Fore.GREEN}✓ {new} new device(s) found via ARP{Style.RESET_ALL}")
        except Exception as exc:
            log.warning(f"ARP scan failed on {net}: {exc}")

    if not all_raw:
        print(f"\n{Fore.RED}No active devices found.{Style.RESET_ALL}")
        return 0

    # ── Enrich devices in parallel ────────────────────────────────────────
    raw_list = list(all_raw.values())
    enriched: list[Device] = []

    print(f"\n{Fore.CYAN}Enriching {len(raw_list)} device(s)…{Style.RESET_ALL}")
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(enrich_device, r, host_ips, config, args.no_vendor): r
            for r in raw_list
        }
        for fut in tqdm(as_completed(futures), total=len(futures), unit="device", ncols=70):
            try:
                enriched.append(fut.result())
            except Exception as exc:
                log.debug(f"Enrichment error: {exc}")

    # Sort by IP
    try:
        enriched.sort(key=lambda d: socket.inet_aton(d.ip))
    except socket.error:
        pass

    # ── Print summary table ───────────────────────────────────────────────
    print(f"\n{Fore.GREEN}{'─'*90}{Style.RESET_ALL}")
    print(
        f"  {Fore.CYAN}{'#':>5}  "
        f"{'IP':<17}{'MAC':<20}{'Hostname':<28}{'VLAN'}{Style.RESET_ALL}"
    )
    print(f"{Fore.GREEN}{'─'*90}{Style.RESET_ALL}")
    for idx, dev in enumerate(enriched, 1):
        print_device_summary(dev, idx)
    print(f"{Fore.GREEN}{'─'*90}{Style.RESET_ALL}")
    print(f"  Total: {len(enriched)} device(s)\n")

    # ── Interactive deep-scan loop ────────────────────────────────────────
    while True:
        raw_input = input(
            f"{Fore.CYAN}Enter device number for Nmap deep scan (Enter to exit): {Style.RESET_ALL}"
        ).strip()
        if not raw_input:
            break
        if not raw_input.isdigit():
            print(f"{Fore.RED}Please enter a number.{Style.RESET_ALL}")
            continue
        idx = int(raw_input)
        if not (1 <= idx <= len(enriched)):
            print(f"{Fore.RED}Number must be between 1 and {len(enriched)}.{Style.RESET_ALL}")
            continue

        target = enriched[idx - 1]
        scanned = run_nmap_scan(target.ip, config["nmap"], config["vlan_mapping"])
        if scanned:
            # Preserve enriched data that Nmap doesn't return
            scanned.mac = target.mac
            scanned.vendor = target.vendor
            scanned.is_host = target.is_host
            enriched[idx - 1] = scanned
            print_device_detail(scanned)

    # ── Export reports ────────────────────────────────────────────────────
    saved: list[str] = []
    if config["output"]["save_json"]:
        saved.append(str(save_json(enriched, output_dir)))
    if config["output"]["save_csv"]:
        saved.append(str(save_csv(enriched, output_dir)))
    if config["output"]["save_html"]:
        saved.append(str(save_html(enriched, output_dir)))

    if saved:
        print(f"\n{Fore.GREEN}Reports saved:{Style.RESET_ALL}")
        for path in saved:
            print(f"  → {path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
