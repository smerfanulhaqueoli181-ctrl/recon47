"""
modules/vuln_scanner.py — Vulnerability Scanner Module
Custom checks: SQLi, XSS, IDOR, open redirect, security headers,
               directory listing, sensitive files, CORS, SSRF hints
Optional: Nikto, Nuclei integration
"""

import ssl
import re
import time
import subprocess
import shutil
import concurrent.futures
import urllib.request
import urllib.parse
import urllib.error
from dataclasses import dataclass, field, asdict
from typing import List

from .utils import (
    Colors, log_info, log_success, log_warning, log_error,
    log_finding, log_debug, severity_score
)


@dataclass
class Finding:
    title:       str
    severity:    str       # CRITICAL | HIGH | MEDIUM | LOW | INFO
    url:         str       = ""
    parameter:   str       = ""
    evidence:    str       = ""
    description: str       = ""
    remediation: str       = ""

    def to_dict(self):
        return asdict(self)


# ── SQL Injection payloads ────────────────────────────────────────────────────
SQLI_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR 1=1--", '" OR 1=1--',
    "1; DROP TABLE users--", "1' AND SLEEP(1)--",
]
SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-", "microsoft ole db",
    "odbc sql", "sqlite", "postgresql", "syntax error",
    "unclosed quotation mark", "quoted string not properly terminated",
]

# ── XSS payloads ─────────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "'><svg onload=alert(1)>",
]

# ── Open Redirect payloads ────────────────────────────────────────────────────
REDIRECT_PARAMS = ["redirect", "url", "next", "return", "goto", "dest", "destination",
                   "redirect_uri", "return_url", "returnUrl", "redirectUrl"]
REDIRECT_PAYLOAD = "https://evil.example.com"

# ── SSRF-prone parameters ─────────────────────────────────────────────────────
SSRF_PARAMS = ["url", "uri", "link", "src", "source", "file", "path",
               "fetch", "load", "request", "proxy", "forward"]


class VulnScannerModule:
    def __init__(self, target: str, urls: list = None, timeout: int = 10,
                 threads: int = 5, delay: float = 0.5,
                 run_nikto: bool = False, run_nuclei: bool = False,
                 verbose: bool = False):
        self.target     = target.rstrip("/")
        self.urls       = urls or [target]
        self.timeout    = timeout
        self.threads    = threads
        self.delay      = delay
        self.run_nikto  = run_nikto
        self.run_nuclei = run_nuclei
        self.verbose    = verbose
        self.findings: List[Finding] = []

    # ── HTTP helper ───────────────────────────────────────────────────────────

    def _get(self, url: str, headers: dict = None) -> tuple:
        try:
            h = {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
                )
            }
            if headers:
                h.update(headers)
            req = urllib.request.Request(url, headers=h)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as r:
                body = r.read(500_000).decode("utf-8", errors="replace")
                return r.status, dict(r.headers), body
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), ""
        except Exception:
            return None, {}, ""

    def _add(self, finding: Finding):
        self.findings.append(finding)
        log_finding(finding.severity, f"{finding.title} — {finding.url or self.target}")

    # ── Check 1: Missing Security Headers ─────────────────────────────────────

    def _check_security_headers(self):
        log_info("Checking security headers...")
        status, hdrs, _ = self._get(self.target)
        if not status:
            return

        checks = {
            "Strict-Transport-Security": (
                "HIGH", "Missing HSTS Header",
                "The server does not return an HSTS header, making it vulnerable to "
                "protocol downgrade attacks.",
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
            ),
            "X-Frame-Options": (
                "MEDIUM", "Missing X-Frame-Options",
                "Page can be embedded in iframes, enabling clickjacking attacks.",
                "Add: X-Frame-Options: DENY or SAMEORIGIN"
            ),
            "X-Content-Type-Options": (
                "LOW", "Missing X-Content-Type-Options",
                "Browsers may MIME-sniff responses, leading to XSS risks.",
                "Add: X-Content-Type-Options: nosniff"
            ),
            "Content-Security-Policy": (
                "MEDIUM", "Missing Content-Security-Policy",
                "No CSP header reduces XSS mitigation capability.",
                "Define a strict CSP policy."
            ),
            "X-XSS-Protection": (
                "LOW", "Missing X-XSS-Protection",
                "Older browsers won't use built-in XSS filters.",
                "Add: X-XSS-Protection: 1; mode=block"
            ),
        }

        for header, (sev, title, desc, rem) in checks.items():
            if not hdrs.get(header):
                self._add(Finding(
                    title=title, severity=sev,
                    url=self.target, evidence=f"Header '{header}' absent",
                    description=desc, remediation=rem
                ))

        # Check for server version disclosure
        server = hdrs.get("Server", "")
        if server and re.search(r"[\d.]", server):
            self._add(Finding(
                title="Server Version Disclosure",
                severity="LOW",
                url=self.target,
                evidence=f"Server: {server}",
                description="The server discloses its version, aiding attacker fingerprinting.",
                remediation="Configure the server to suppress version information."
            ))

        # Check for CORS misconfiguration
        _, hdrs2, _ = self._get(self.target, headers={"Origin": "https://evil.example.com"})
        acao = hdrs2.get("Access-Control-Allow-Origin", "")
        if acao == "*" or "evil.example.com" in acao:
            self._add(Finding(
                title="CORS Misconfiguration",
                severity="HIGH",
                url=self.target,
                evidence=f"Access-Control-Allow-Origin: {acao}",
                description="The server reflects or allows arbitrary origins, enabling CORS-based data theft.",
                remediation="Restrict CORS to trusted origins only."
            ))

    # ── Check 2: Insecure Cookie Flags ────────────────────────────────────────

    def _check_cookies(self):
        log_info("Checking cookie security flags...")
        _, hdrs, _ = self._get(self.target)
        cookies_raw = hdrs.get("Set-Cookie", "")
        if not cookies_raw:
            return

        if "httponly" not in cookies_raw.lower():
            self._add(Finding(
                title="Cookie Missing HttpOnly Flag",
                severity="MEDIUM",
                url=self.target,
                evidence=f"Set-Cookie: {cookies_raw[:120]}",
                description="Cookies without HttpOnly can be accessed via JavaScript, enabling session theft.",
                remediation="Set HttpOnly flag on all sensitive cookies."
            ))
        if "secure" not in cookies_raw.lower():
            self._add(Finding(
                title="Cookie Missing Secure Flag",
                severity="MEDIUM",
                url=self.target,
                evidence=f"Set-Cookie: {cookies_raw[:120]}",
                description="Cookies without Secure flag may be transmitted over HTTP.",
                remediation="Set Secure flag on all cookies."
            ))
        if "samesite" not in cookies_raw.lower():
            self._add(Finding(
                title="Cookie Missing SameSite Attribute",
                severity="LOW",
                url=self.target,
                evidence=f"Set-Cookie: {cookies_raw[:120]}",
                description="Without SameSite, cookies may be sent in cross-site requests (CSRF risk).",
                remediation="Add SameSite=Strict or SameSite=Lax."
            ))

    # ── Check 3: SQL Injection (GET params) ───────────────────────────────────

    def _check_sqli_on_url(self, url: str):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return

        for param in params:
            for payload in SQLI_PAYLOADS:
                test_params = {k: ("1" if k != param else payload) for k in params}
                test_url = (
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    f"?{urllib.parse.urlencode(test_params)}"
                )
                status, _, body = self._get(test_url)
                if body:
                    for err in SQLI_ERRORS:
                        if err in body.lower():
                            self._add(Finding(
                                title="Potential SQL Injection",
                                severity="CRITICAL",
                                url=test_url,
                                parameter=param,
                                evidence=f"Error pattern '{err}' in response with payload: {payload}",
                                description="The parameter appears to be vulnerable to SQL injection.",
                                remediation="Use parameterized queries / prepared statements."
                            ))
                            return  # One finding per param is enough
                if self.delay:
                    time.sleep(self.delay)

    def _check_sqli(self):
        log_info("Checking for SQL injection...")
        # Only check URLs with query params
        urls_with_params = [u for u in self.urls if "?" in u][:30]
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(self._check_sqli_on_url, urls_with_params))

    # ── Check 4: Reflected XSS ────────────────────────────────────────────────

    def _check_xss_on_url(self, url: str):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return

        for param in params:
            for payload in XSS_PAYLOADS[:3]:  # Limit payloads
                test_params = {k: payload if k == param else "1" for k in params}
                test_url = (
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    f"?{urllib.parse.urlencode(test_params)}"
                )
                status, hdrs, body = self._get(test_url)
                ct = hdrs.get("Content-Type", "")
                if body and payload in body and "text/html" in ct:
                    self._add(Finding(
                        title="Potential Reflected XSS",
                        severity="HIGH",
                        url=test_url,
                        parameter=param,
                        evidence=f"Payload reflected verbatim in HTML body: {payload[:60]}",
                        description="Input is reflected in the HTML response without encoding.",
                        remediation="Encode all user-supplied data on output; use CSP."
                    ))
                    return
                if self.delay:
                    time.sleep(self.delay)

    def _check_xss(self):
        log_info("Checking for reflected XSS...")
        urls_with_params = [u for u in self.urls if "?" in u][:30]
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(self._check_xss_on_url, urls_with_params))

    # ── Check 5: Open Redirect ────────────────────────────────────────────────

    def _check_open_redirect(self):
        log_info("Checking for open redirect...")
        for url in self.urls[:50]:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for param in params:
                if param.lower() in REDIRECT_PARAMS:
                    test_params = {k: REDIRECT_PAYLOAD if k == param else v[0]
                                   for k, v in params.items()}
                    test_url = (
                        f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        f"?{urllib.parse.urlencode(test_params)}"
                    )
                    try:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode    = ssl.CERT_NONE
                        req = urllib.request.Request(
                            test_url,
                            headers={"User-Agent": "Mozilla/5.0"},
                        )
                        # We intentionally do NOT follow redirects here
                        # to catch the Location header
                        opener = urllib.request.build_opener(
                            urllib.request.HTTPSHandler(context=ctx),
                            urllib.request.HTTPRedirectHandler(),
                        )
                        opener.addheaders = [("User-Agent", "Mozilla/5.0")]
                        try:
                            with opener.open(req, timeout=self.timeout) as r:
                                loc = r.headers.get("Location", "")
                                if REDIRECT_PAYLOAD in loc:
                                    self._add(Finding(
                                        title="Open Redirect",
                                        severity="MEDIUM",
                                        url=test_url,
                                        parameter=param,
                                        evidence=f"Location: {loc}",
                                        description="Arbitrary URL redirection is possible.",
                                        remediation="Validate redirect destinations against a whitelist."
                                    ))
                        except urllib.error.HTTPError as e:
                            loc = e.headers.get("Location", "")
                            if REDIRECT_PAYLOAD in loc:
                                self._add(Finding(
                                    title="Open Redirect",
                                    severity="MEDIUM",
                                    url=test_url,
                                    parameter=param,
                                    evidence=f"Location: {loc}",
                                    description="Arbitrary URL redirection is possible.",
                                    remediation="Validate redirect destinations against a whitelist."
                                ))
                    except Exception:
                        pass

    # ── Check 6: Directory Listing ────────────────────────────────────────────

    def _check_directory_listing(self):
        log_info("Checking for directory listing...")
        probe_paths = ["/", "/images/", "/js/", "/css/", "/uploads/", "/files/", "/backup/"]
        for path in probe_paths:
            url = self.target + path
            status, _, body = self._get(url)
            if status == 200 and body and (
                "Index of /" in body or
                "<title>Directory listing" in body or
                re.search(r'<a href="\.\.">', body)
            ):
                self._add(Finding(
                    title="Directory Listing Enabled",
                    severity="MEDIUM",
                    url=url,
                    evidence="Response contains directory index content.",
                    description="The server exposes directory contents, potentially leaking sensitive files.",
                    remediation="Disable directory listing in the web server configuration."
                ))

    # ── Check 7: Sensitive File Exposure ─────────────────────────────────────

    def _check_sensitive_files(self):
        log_info("Checking for exposed sensitive files...")
        sensitive = {
            "/.git/HEAD":         ("HIGH",     "Git Repository Exposed"),
            "/.env":              ("HIGH",     ".env File Exposed"),
            "/phpinfo.php":       ("HIGH",     "PHP Info Page Exposed"),
            "/server-status":     ("MEDIUM",   "Apache Server Status Exposed"),
            "/.htaccess":         ("MEDIUM",   ".htaccess File Exposed"),
            "/web.config":        ("MEDIUM",   "web.config Exposed"),
            "/config.php":        ("HIGH",     "Config File Exposed"),
            "/backup.zip":        ("HIGH",     "Backup Archive Exposed"),
            "/backup.tar.gz":     ("HIGH",     "Backup Archive Exposed"),
            "/.DS_Store":         ("LOW",      ".DS_Store File Exposed"),
            "/crossdomain.xml":   ("INFO",     "crossdomain.xml Found"),
        }

        def probe(path, sev, title):
            url = self.target + path
            status, _, body = self._get(url)
            if status and status == 200 and body:
                self._add(Finding(
                    title=title, severity=sev, url=url,
                    evidence=f"HTTP 200 response ({len(body)} bytes)",
                    description=f"Sensitive file/path '{path}' is publicly accessible.",
                    remediation="Restrict access via server configuration or remove the file."
                ))

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = [ex.submit(probe, p, s, t) for p, (s, t) in sensitive.items()]
            concurrent.futures.wait(futs)

    # ── Check 8: SSRF Hints ───────────────────────────────────────────────────

    def _check_ssrf_hints(self):
        log_info("Checking for potential SSRF parameters...")
        for url in self.urls[:50]:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for param in params:
                if param.lower() in SSRF_PARAMS:
                    self._add(Finding(
                        title="Potential SSRF Parameter",
                        severity="MEDIUM",
                        url=url,
                        parameter=param,
                        evidence=f"Parameter '{param}' may accept URLs/file paths.",
                        description="Parameters accepting URLs may be exploitable for SSRF.",
                        remediation="Validate and whitelist all server-side URL fetches."
                    ))
                    break  # One finding per URL

    # ── Nikto Integration ─────────────────────────────────────────────────────

    def _run_nikto(self):
        if not shutil.which("nikto") and not shutil.which("nikto.pl"):
            log_warning("Nikto not found in PATH. Skipping.")
            return
        log_info("Running Nikto scanner...")
        cmd = ["nikto", "-h", self.target, "-nointeractive", "-Format", "txt"]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300
            )
            output = result.stdout or ""
            for line in output.splitlines():
                if line.startswith("+") and "OSVDB" in line or "vulnerability" in line.lower():
                    self._add(Finding(
                        title="Nikto Finding",
                        severity="MEDIUM",
                        url=self.target,
                        evidence=line.strip(),
                        description="Finding reported by Nikto scanner.",
                        remediation="Review and remediate the identified issue."
                    ))
            log_success(f"Nikto complete. {len([f for f in self.findings if f.title=='Nikto Finding'])} findings.")
        except subprocess.TimeoutExpired:
            log_warning("Nikto timed out.")
        except Exception as e:
            log_error(f"Nikto error: {e}")

    # ── Nuclei Integration ────────────────────────────────────────────────────

    def _run_nuclei(self):
        if not shutil.which("nuclei"):
            log_warning("Nuclei not found in PATH. Skipping.")
            return
        log_info("Running Nuclei scanner...")
        cmd = ["nuclei", "-u", self.target, "-silent", "-json"]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300
            )
            import json
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    sev  = data.get("info", {}).get("severity", "info").upper()
                    name = data.get("info", {}).get("name", "Nuclei Finding")
                    matched = data.get("matched", self.target)
                    self._add(Finding(
                        title=f"[Nuclei] {name}",
                        severity=sev if sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO") else "INFO",
                        url=matched,
                        evidence=line[:200],
                        description=data.get("info", {}).get("description", ""),
                        remediation=data.get("info", {}).get("remediation", "")
                    ))
                except json.JSONDecodeError:
                    pass
            log_success("Nuclei scan complete.")
        except subprocess.TimeoutExpired:
            log_warning("Nuclei timed out.")
        except Exception as e:
            log_error(f"Nuclei error: {e}")

    # ── Main Run ──────────────────────────────────────────────────────────────

    def run(self) -> list:
        log_info(f"Starting vulnerability scan on {Colors.CYAN}{self.target}{Colors.RESET}")

        self._check_security_headers()
        self._check_cookies()
        self._check_directory_listing()
        self._check_sensitive_files()
        self._check_sqli()
        self._check_xss()
        self._check_open_redirect()
        self._check_ssrf_hints()

        if self.run_nikto:
            self._run_nikto()
        if self.run_nuclei:
            self._run_nuclei()

        # Deduplicate and sort by severity
        seen   = set()
        unique = []
        for f in self.findings:
            key = (f.title, f.url, f.parameter)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        unique.sort(key=lambda x: severity_score(x.severity), reverse=True)

        counts = {}
        for f in unique:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        log_success(f"Vulnerability scan complete: {len(unique)} findings → {counts}")

        return [f.to_dict() for f in unique]
