"""
modules/recon.py — Reconnaissance Module
Collects: DNS info, HTTP headers, subdomains, open ports, technologies,
          WHOIS-like metadata, robots.txt, sitemap.xml
"""

import socket
import ssl
import concurrent.futures
import time
import re
from datetime import datetime
from urllib.parse import urlparse

import urllib.request
import urllib.error

from .utils import (
    Colors, extract_domain, log_info, log_success, log_warning,
    log_error, log_debug
)


# Common subdomains wordlist
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "admin", "portal",
    "api", "dev", "staging", "test", "beta", "app", "mobile", "secure", "vpn",
    "remote", "intranet", "internal", "login", "auth", "sso", "static",
    "cdn", "media", "images", "img", "assets", "js", "css", "shop", "store",
    "blog", "news", "forum", "support", "help", "docs", "wiki", "git",
    "gitlab", "github", "jenkins", "ci", "dashboard", "monitor", "status",
    "cloud", "office", "outlook", "mx", "ns1", "ns2", "dns", "backup",
    "old", "new", "v2", "v1", "prod", "qa", "uat", "sandbox",
]

# Technology fingerprints: header/body pattern → tech name
TECH_FINGERPRINTS = {
    # Servers
    r"Apache": "Apache HTTP Server",
    r"nginx": "Nginx",
    r"Microsoft-IIS": "Microsoft IIS",
    r"LiteSpeed": "LiteSpeed",
    r"cloudflare": "Cloudflare",
    # Frameworks / CMS
    r"X-Powered-By:\s*PHP": "PHP",
    r"X-Powered-By:\s*Express": "Node.js / Express",
    r"X-Powered-By:\s*ASP\.NET": "ASP.NET",
    r"wp-content|wordpress": "WordPress",
    r"Joomla": "Joomla",
    r"Drupal": "Drupal",
    r"laravel_session|Laravel": "Laravel",
    r"Django|csrfmiddlewaretoken": "Django",
    r"_rails|X-Runtime": "Ruby on Rails",
    r"__cfduid|cf-ray": "Cloudflare",
    r"X-Shopify": "Shopify",
    # JS Frameworks (body)
    r"react": "React",
    r"angular": "Angular",
    r"vue\.js|Vue\.js": "Vue.js",
    r"jquery": "jQuery",
    r"bootstrap": "Bootstrap",
}

# Common ports to scan
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389,
                5432, 6379, 8080, 8443, 8888, 9200, 27017]


class ReconModule:
    def __init__(self, target: str, timeout: int = 10,
                 verbose: bool = False, delay: float = 0):
        self.target = target
        self.timeout = timeout
        self.verbose = verbose
        self.delay = delay
        self.domain = extract_domain(target)

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _get(self, url: str) -> tuple:
        """Return (status_code, headers_dict, body_text) or (None, {}, '')."""
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/124.0.0.0 Safari/537.36"
                    )
                },
            )
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                body = resp.read(1_000_000).decode("utf-8", errors="replace")
                headers = dict(resp.headers)
                return resp.status, headers, body
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), ""
        except Exception as e:
            log_debug(f"GET {url} failed: {e}", self.verbose)
            return None, {}, ""

    # ── DNS ──────────────────────────────────────────────────────────────────

    def _collect_dns(self) -> dict:
        log_info("Collecting DNS information...")
        dns_info = {}
        try:
            ip = socket.gethostbyname(self.domain)
            dns_info["a_record"] = ip
            log_success(f"A Record: {ip}")
        except Exception as e:
            log_warning(f"Could not resolve {self.domain}: {e}")
            dns_info["a_record"] = None

        # MX-like check via raw socket to port 25
        try:
            addrs = socket.getaddrinfo(self.domain, None)
            unique = list({a[4][0] for a in addrs})
            dns_info["all_ips"] = unique
        except Exception:
            dns_info["all_ips"] = []

        return dns_info

    # ── HTTP Headers ─────────────────────────────────────────────────────────

    def _collect_headers(self) -> dict:
        log_info("Collecting HTTP headers...")
        status, headers, _ = self._get(self.target)
        if status is None:
            log_warning("Could not fetch HTTP headers.")
            return {}

        log_success(f"HTTP Status: {status}")
        interesting = {
            "status_code": status,
            "server": headers.get("Server", ""),
            "x_powered_by": headers.get("X-Powered-By", ""),
            "content_type": headers.get("Content-Type", ""),
            "x_frame_options": headers.get("X-Frame-Options", ""),
            "x_xss_protection": headers.get("X-XSS-Protection", ""),
            "strict_transport_security": headers.get("Strict-Transport-Security", ""),
            "content_security_policy": headers.get("Content-Security-Policy", ""),
            "x_content_type_options": headers.get("X-Content-Type-Options", ""),
            "referrer_policy": headers.get("Referrer-Policy", ""),
            "set_cookie": headers.get("Set-Cookie", ""),
            "all": headers,
        }

        # Report missing security headers
        missing_sec = []
        for h in ["X-Frame-Options", "X-XSS-Protection", "Strict-Transport-Security",
                  "Content-Security-Policy", "X-Content-Type-Options"]:
            if not headers.get(h):
                missing_sec.append(h)
        interesting["missing_security_headers"] = missing_sec
        if missing_sec:
            log_warning(f"Missing security headers: {', '.join(missing_sec)}")

        return interesting

    # ── SSL / TLS ─────────────────────────────────────────────────────────────

    def _collect_ssl(self) -> dict:
        log_info("Collecting SSL/TLS information...")
        ssl_info = {}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info["version"] = ssock.version()
                    ssl_info["cipher"]  = ssock.cipher()
                    ssl_info["subject"] = dict(x[0] for x in cert.get("subject", []))
                    ssl_info["issuer"]  = dict(x[0] for x in cert.get("issuer", []))
                    ssl_info["not_before"] = cert.get("notBefore", "")
                    ssl_info["not_after"]  = cert.get("notAfter", "")
                    ssl_info["san"] = [
                        v for _, v in cert.get("subjectAltName", [])
                    ]
                    log_success(f"SSL Version: {ssl_info['version']}")
                    log_success(f"Issued by: {ssl_info['issuer'].get('organizationName','?')}")
        except ssl.SSLError as e:
            log_warning(f"SSL error: {e}")
            ssl_info["error"] = str(e)
        except Exception as e:
            log_debug(f"SSL info failed: {e}", self.verbose)
            ssl_info["error"] = str(e)
        return ssl_info

    # ── Port Scanning ─────────────────────────────────────────────────────────

    def _scan_port(self, port: int) -> tuple:
        try:
            with socket.create_connection(
                (self.domain, port), timeout=max(1, self.timeout // 4)
            ):
                return port, True
        except Exception:
            return port, False

    def _collect_ports(self) -> list:
        log_info(f"Scanning {len(COMMON_PORTS)} common ports...")
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(self._scan_port, p): p for p in COMMON_PORTS}
            for f in concurrent.futures.as_completed(futures):
                port, is_open = f.result()
                if is_open:
                    open_ports.append(port)
                    log_success(f"Open port: {port}")
        if not open_ports:
            log_warning("No common ports found open.")
        return sorted(open_ports)

    # ── Subdomain Enumeration ─────────────────────────────────────────────────

    def _check_subdomain(self, sub: str) -> str | None:
        fqdn = f"{sub}.{self.domain}"
        try:
            socket.gethostbyname(fqdn)
            return fqdn
        except Exception:
            return None

    def _collect_subdomains(self) -> list:
        log_info(f"Enumerating subdomains (wordlist: {len(SUBDOMAIN_WORDLIST)})...")
        found = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
            futures = {ex.submit(self._check_subdomain, s): s for s in SUBDOMAIN_WORDLIST}
            for f in concurrent.futures.as_completed(futures):
                result = f.result()
                if result:
                    found.append(result)
                    log_success(f"Subdomain: {result}")
        log_info(f"Found {len(found)} subdomains.")
        return sorted(found)

    # ── Technology Detection ──────────────────────────────────────────────────

    def _detect_technologies(self, headers: dict, body: str) -> list:
        log_info("Detecting technologies...")
        techs = set()

        combined = body.lower()
        # Add headers as string for matching
        for k, v in headers.get("all", {}).items():
            combined += f"\n{k}: {v}".lower()

        for pattern, tech in TECH_FINGERPRINTS.items():
            if re.search(pattern, combined, re.IGNORECASE):
                techs.add(tech)

        if techs:
            for t in sorted(techs):
                log_success(f"Detected: {t}")
        return sorted(techs)

    # ── Robots / Sitemap ──────────────────────────────────────────────────────

    def _collect_robots(self) -> dict:
        log_info("Fetching robots.txt and sitemap.xml...")
        result = {}
        for path in ["/robots.txt", "/sitemap.xml"]:
            url = self.target.rstrip("/") + path
            status, _, body = self._get(url)
            if status and status < 400:
                result[path] = body[:5000]
                log_success(f"Found: {url}")
            else:
                result[path] = None
        return result

    # ── JavaScript File Discovery ─────────────────────────────────────────────

    def _collect_js_files(self, body: str) -> list:
        log_info("Extracting JavaScript file references...")
        js_files = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', body, re.IGNORECASE)
        absolute = []
        for js in js_files:
            if js.startswith("http"):
                absolute.append(js)
            elif js.startswith("/"):
                absolute.append(self.target.rstrip("/") + js)
            else:
                absolute.append(self.target.rstrip("/") + "/" + js)
        unique = list(dict.fromkeys(absolute))[:50]  # deduplicate, cap at 50
        if unique:
            log_success(f"Found {len(unique)} JS files.")
        return unique

    # ── Main Run ──────────────────────────────────────────────────────────────

    def run(self) -> dict:
        log_info(f"Starting reconnaissance on {Colors.CYAN}{self.domain}{Colors.RESET}")

        dns     = self._collect_dns()
        if self.delay: time.sleep(self.delay)

        headers = self._collect_headers()
        if self.delay: time.sleep(self.delay)

        ssl_    = self._collect_ssl()
        ports   = self._collect_ports()
        subdmns = self._collect_subdomains()

        # Fetch body for tech detection & JS
        _, _, body = self._get(self.target)
        techs   = self._detect_technologies(headers, body)
        js_     = self._collect_js_files(body)
        robots  = self._collect_robots()

        return {
            "domain":                self.domain,
            "dns":                   dns,
            "http_headers":          headers,
            "ssl":                   ssl_,
            "open_ports":            ports,
            "subdomains":            subdmns,
            "technologies":          techs,
            "js_files":              js_,
            "robots_sitemap":        robots,
        }
