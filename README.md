# 🛰 NetScout — Professional Network Scanner

> Fast, structured network discovery and analysis tool built in Python.  
> ARP discovery · Nmap integration · MAC vendor lookup · JSON / CSV / HTML reports

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)

---

## ✨ Features

| Feature | Detail |
|---|---|
| **ARP Discovery** | Finds all active devices on a subnet without touching the internet |
| **OS Detection** | Nmap-powered OS fingerprinting (`-O`) |
| **Port Scanning** | Fast SYN scan (`-sS`) with service version detection |
| **MAC Vendor Lookup** | Resolves hardware manufacturer via `macvendors.com` API (rate-limited, cached) |
| **Reverse DNS** | Resolves hostnames for discovered IPs |
| **VLAN Mapping** | Customizable prefix → VLAN label mapping via `config.json` |
| **Multi-network scan** | Auto-detect all active interfaces and scan them all at once |
| **Parallel enrichment** | Threaded device enrichment with a live progress bar |
| **Export reports** | JSON, CSV, and self-contained HTML reports |
| **CLI & interactive mode** | Full `argparse` CLI — or just run it and answer the prompts |

---

## 📋 Requirements

- Python **3.10+**
- [Nmap](https://nmap.org/download.html) installed and available in `PATH`
- **Root / Administrator privileges** for ARP scans and Nmap SYN scans

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/your-handle/netscout.git
cd netscout

# Install Python dependencies
pip install -r requirements.txt

# (Linux/macOS) Make executable
chmod +x netscout.py
```

---

## ⚡ Usage

### Interactive mode (no arguments)
```bash
sudo python netscout.py
```
You will be prompted to choose a scan mode.

---

### CLI mode

```bash
# Auto-detect and scan all local networks
sudo python netscout.py --auto

# Scan a specific subnet
sudo python netscout.py --network 192.168.1.0/24

# Deep Nmap scan on a single IP (skips ARP discovery)
sudo python netscout.py --ip 192.168.1.105

# Save results as JSON + HTML report
sudo python netscout.py --auto --json --html

# Use a custom config file
sudo python netscout.py --network 10.0.0.0/24 --config /etc/netscout/myconfig.json

# Skip MAC vendor API calls (faster, offline)
sudo python netscout.py --auto --no-vendor

# Enable verbose/debug logging
sudo python netscout.py --auto -v
```

### All Options

```
usage: netscout [-h] [--auto | --network CIDR | --ip IP]
                [--config FILE] [--json] [--csv] [--html]
                [--output-dir DIR] [--workers N] [--no-vendor] [-v]

optional arguments:
  --auto             Auto-detect and scan all local networks
  --network CIDR     Scan a specific range  (e.g. 192.168.1.0/24)
  --ip IP            Nmap deep scan on a single IP address
  --config FILE      Path to JSON config file  (default: config.json)
  --json             Save results to JSON
  --csv              Save results to CSV
  --html             Save results to HTML report
  --output-dir DIR   Output directory for reports  (default: reports/)
  --workers N        Parallel threads for enrichment  (default: 10)
  --no-vendor        Skip MAC vendor API lookup
  -v, --verbose      Enable verbose/debug logging
```

---

## ⚙️ Configuration

Copy and edit `config.json` to customise the tool without touching code.

```json
{
  "vlan_mapping": {
    "192.168.1": "VLAN 10 - Office",
    "192.168.2": "VLAN 20 - Guests",
    "192.168.3": "VLAN 30 - Servers",
    "10.0.0":    "VLAN 40 - Management",
    "172.16.0":  "VLAN 50 - DMZ"
  },
  "nmap": {
    "scan_type": "-sS",
    "timing": "-T4",
    "max_retries": 1,
    "extra_flags": []
  },
  "api": {
    "mac_vendor_url": "https://api.macvendors.com/",
    "timeout": 2,
    "rate_limit_seconds": 1.1
  },
  "arp": {
    "timeout": 2
  },
  "output": {
    "save_json": false,
    "save_csv": false,
    "save_html": true,
    "output_dir": "reports"
  }
}
```

| Key | Description |
|---|---|
| `vlan_mapping` | Map IP prefix (`"x.x.x"`) to a VLAN label |
| `nmap.scan_type` | Default `-sS` (SYN); use `-sT` for unprivileged |
| `nmap.timing` | Nmap timing template (`-T0` … `-T5`) |
| `nmap.extra_flags` | Extra raw Nmap flags, e.g. `["--script=banner"]` |
| `api.rate_limit_seconds` | Delay between MAC vendor API calls (respect free-tier limits) |
| `output.save_html` | Auto-generate HTML report at end of every scan |

---

## 📁 Project Structure

```
netscout/
├── netscout.py        # Main script (single-file tool)
├── config.json        # Default configuration
├── requirements.txt   # Python dependencies
├── reports/           # Auto-created — scan reports land here
└── README.md
```

---

## 🔍 How It Works

```
  1. ARP Broadcast      →  Discover live hosts on the subnet
  2. Parallel Enrichment →  Reverse DNS · VLAN mapping · MAC vendor
  3. Summary Table      →  Print overview of all discovered devices
  4. Interactive Loop   →  Pick any device for a full Nmap deep scan
  5. Export             →  JSON / CSV / HTML based on config or flags
```

---

## 🗂 Sample Output

### Terminal summary
```
  [  1]  192.168.1.1       aa:bb:cc:11:22:33   router.local           VLAN 10 - Office
  [  2]  192.168.1.42  (you) 11:22:33:44:55:66   dev-workstation        VLAN 10 - Office
  [  3]  192.168.1.88      de:ad:be:ef:00:01   Unknown                VLAN 10 - Office
```

### Nmap deep-scan detail
```
──────────────────────────────────────────────────
  Detailed Report — 192.168.1.1
──────────────────────────────────────────────────
  IP Address           : 192.168.1.1
  Hostname             : router.local
  MAC                  : aa:bb:cc:11:22:33
  Vendor               : Cisco Systems
  VLAN                 : VLAN 10 - Office
  OS Detected          : Linux 5.x
  Network Distance     : 1 hops
  Scan Time            : 2025-06-01T14:32:10

  Open Ports:
    22/tcp       ssh OpenSSH 8.9
    80/tcp       http nginx 1.24
    443/tcp      https nginx 1.24
──────────────────────────────────────────────────
```

---

## ⚠️ Privilege Notes

| Operation | Requires root? |
|---|---|
| ARP scan (Scapy) | ✅ Yes |
| Nmap SYN scan (`-sS`) | ✅ Yes |
| Nmap TCP connect (`-sT`) | ❌ No (auto-fallback) |
| Nmap OS detection (`-O`) | ✅ Yes |
| MAC vendor API | ❌ No |
| Reverse DNS | ❌ No |

On **Windows**, run the terminal as Administrator.  
On **Linux / macOS**, prefix with `sudo`.

---

## 🔒 Legal & Ethical Use

> **Only scan networks you own or have explicit written permission to scan.**  
> Unauthorized network scanning may violate local laws (e.g. CFAA in the US, Computer Misuse Act in the UK).  
> The author is not responsible for any misuse.

---

## 📦 Dependencies

| Package | Purpose |
|---|---|
| `scapy` | Low-level ARP packet crafting and sending |
| `requests` | MAC vendor API calls |
| `colorama` | Cross-platform colored terminal output |
| `tqdm` | Progress bar during device enrichment |
| `nmap` (system) | Port scanning and OS detection |

---

## 🛣 Roadmap

- [ ] IPv6 / ICMPv6 neighbor discovery
- [ ] Scheduled scans with delta diffing (alert on new devices)
- [ ] SQLite backend for historical tracking
- [ ] Slack / Webhook notifications
- [ ] Docker image

---

## 📄 License

MIT © 2025 — see [LICENSE](LICENSE) for details.
