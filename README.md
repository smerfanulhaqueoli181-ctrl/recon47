# Recon47
Recon47 is an automated cybersecurity tool that performs reconnaissance, endpoint discovery, technology detection, crawling, and vulnerability scanning for web targets. It integrates tools like Nikto and Nuclei to identify security issues and generate structured reports.

# ⬡ ReconX — Automated Reconnaissance & Vulnerability Scanner

> **For authorized use only.** Only scan targets you own or have explicit written permission to test.

---

## Overview

**ReconX** is a modular, CLI-based automated security assessment tool that performs:

1. **Reconnaissance** — DNS, SSL/TLS, HTTP headers, subdomain enumeration, port scanning, technology detection, JS file discovery, robots.txt/sitemap
2. **Crawling** — Recursive endpoint discovery, parameter extraction, form detection, interesting path probing
3. **Vulnerability Scanning** — Custom checks (SQLi, XSS, open redirect, SSRF, misconfigurations) + optional Nikto & Nuclei integration
4. **Reporting** — Structured text reports, JSON data, and optional HTML dashboard

---

## Architecture

```
recon_scanner/
├── main.py                   # CLI entry point
├── modules/
│   ├── banner.py             # ASCII banner
│   ├── recon.py              # Reconnaissance module
│   ├── crawler.py            # Web crawler & endpoint discovery
│   ├── vuln_scanner.py       # Vulnerability scanner
│   ├── reporter.py           # Report generator (text + HTML)
│   └── utils.py              # Shared utilities
├── reports/                  # Generated reports (auto-created)
├── requirements.txt
├── Dockerfile
└── README.md
```

---

## Requirements

- **Python 3.8+** — No third-party pip packages required (pure stdlib)
- *Optional:* [Nikto](https://cirt.net/Nikto2) — `sudo apt install nikto`
- *Optional:* [Nuclei](https://github.com/projectdiscovery/nuclei) — see their releases page

---

## Installation

```bash
git clone https://github.com/<sakib-011/recon_scanner.git
cd recon_scanner
chmod +x main.py
```

No `pip install` needed — pure Python stdlib.

---

## Usage

```
python main.py -t <target> [OPTIONS]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t`, `--target` | Target domain, subdomain, URL, or IP | **required** |
| `--depth` | Crawler depth | `2` |
| `--threads` | Parallel threads | `5` |
| `--timeout` | Request timeout (seconds) | `10` |
| `--delay` | Delay between requests (seconds) | `0.5` |
| `--output` | Report filename (no extension) | auto timestamp |
| `--html` | Generate HTML report | off |
| `--no-vuln` | Skip vulnerability scanning | off |
| `--no-crawl` | Skip crawling phase | off |
| `--nikto` | Run Nikto scanner (if installed) | off |
| `--nuclei` | Run Nuclei scanner (if installed) | off |
| `--stealth` | Stealth mode (rate-limited) | off |
| `--verbose`, `-v` | Verbose debug output | off |

### Examples

```bash
# Basic scan
python main.py -t example.com

# Full scan with HTML report and external scanners
python main.py -t https://testphp.vulnweb.com --html --nikto --nuclei

# Recon only (no vuln scanning), deeper crawl
python main.py -t example.com --no-vuln --depth 4 --threads 10

# Stealth mode on an IP
python main.py -t 192.168.1.100 --stealth --delay 2

# Custom output filename
python main.py -t example.com --html --output my_assessment
```

---

## What Gets Checked

### Reconnaissance
- A/AAAA DNS records, all resolved IPs
- SSL/TLS version, cipher, certificate details, SAN entries
- HTTP response headers (server, X-Powered-By, etc.)
- Missing security headers (HSTS, CSP, X-Frame-Options, etc.)
- Port scan (21 common ports, concurrent)
- Subdomain brute-force (60-word wordlist, concurrent)
- Technology fingerprinting (WordPress, PHP, React, Nginx, etc.)
- JavaScript file enumeration
- robots.txt and sitemap.xml

### Crawling
- Recursive BFS crawl (configurable depth)
- Link extraction from `href`, `src`, `action`, inline JS
- Form detection (method, action, input names)
- URL parameter extraction
- Interesting path probing (`.git`, `.env`, `/admin`, phpinfo, etc.)

### Vulnerability Checks
| Check | Severity |
|-------|----------|
| Missing HSTS | HIGH |
| CORS misconfiguration | HIGH |
| Exposed .git/HEAD | HIGH |
| Exposed .env file | HIGH |
| PHP Info exposed | HIGH |
| SQL Injection (error-based) | CRITICAL |
| Reflected XSS | HIGH |
| Open Redirect | MEDIUM |
| Missing X-Frame-Options | MEDIUM |
| Missing CSP | MEDIUM |
| Cookie missing HttpOnly/Secure/SameSite | MEDIUM |
| Directory listing | MEDIUM |
| SSRF-prone parameters | MEDIUM |
| Server version disclosure | LOW |
| Missing X-Content-Type-Options | LOW |

---

## Output

Reports are saved to the `reports/` directory:

- `reports/report_YYYYMMDD_HHMMSS.txt` — Human-readable text report
- `reports/report_YYYYMMDD_HHMMSS.json` — Raw JSON data
- `reports/report_YYYYMMDD_HHMMSS.html` — HTML dashboard (with `--html`)

---

## Docker

```bash
# Build
docker build -t reconx .

# Run
docker run --rm -v $(pwd)/reports:/app/reports reconx -t example.com --html
```

---

## Sample Output

```
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
  ...

[*] Starting scan on: https://testphp.vulnweb.com
[*] Scan started at: 2025-01-15 14:32:01

============================================================
  PHASE 1: RECONNAISSANCE
============================================================

[*] Collecting DNS information...
[+] A Record: 44.228.249.3
[*] Collecting HTTP headers...
[+] HTTP Status: 200
[!] Missing security headers: HSTS, CSP, X-Frame-Options
[*] Scanning 21 common ports...
[+] Open port: 80
[+] Open port: 443
[*] Enumerating subdomains...
[*] Detecting technologies...
[+] Detected: PHP
[+] Detected: Apache HTTP Server

============================================================
  PHASE 2: CRAWLING & ENDPOINT DISCOVERY
============================================================
...

============================================================
  SCAN COMPLETE
============================================================
  Duration       : 47.3s
  Subdomains     : 3
  URLs Found     : 128
  Vulnerabilities: 11
============================================================
```

---

## Ethics & Legal

- Only scan systems you own or have **explicit written authorization** to test
- Do not use this tool against production systems without permission
- This tool is intended for educational purposes, authorized penetration testing, and CTF/lab environments
- Follow all applicable laws and responsible disclosure practices

## Report Sample 
<img width="1919" height="926" alt="image" src="https://github.com/user-attachments/assets/3768e7c6-da26-4235-a5c7-f82c35a09ceb" />



---




