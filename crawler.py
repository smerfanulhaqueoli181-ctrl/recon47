"""
modules/crawler.py — Recursive Web Crawler & Endpoint Discovery
Collects: URLs, endpoints, parameters, forms, interesting paths
"""

import ssl
import re
import time
import concurrent.futures
from collections import deque
from urllib.parse import urlparse, urljoin, parse_qs, urldefrag
import urllib.request
import urllib.error

from .utils import (
    Colors, is_valid_url, extract_domain, log_info, log_success,
    log_warning, log_debug
)


# Paths to probe for interesting endpoints
INTERESTING_PATHS = [
    "/.git/HEAD", "/.env", "/admin", "/admin/login", "/wp-admin",
    "/phpinfo.php", "/server-status", "/server-info", "/.htaccess",
    "/web.config", "/config.php", "/config.yml", "/config.json",
    "/api", "/api/v1", "/api/v2", "/swagger", "/swagger-ui",
    "/swagger.json", "/openapi.json", "/graphql", "/graphiql",
    "/debug", "/trace", "/actuator", "/actuator/env",
    "/actuator/health", "/.well-known/security.txt",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/backup", "/backup.zip", "/backup.tar.gz",
    "/.DS_Store", "/Thumbs.db",
]


class CrawlerModule:
    def __init__(self, target: str, depth: int = 2, threads: int = 5,
                 timeout: int = 10, delay: float = 0.5, verbose: bool = False):
        self.target    = target.rstrip("/")
        self.depth     = depth
        self.threads   = threads
        self.timeout   = timeout
        self.delay     = delay
        self.verbose   = verbose
        self.domain    = extract_domain(target)
        self.base_domain = self._base_domain(self.domain)

        self.visited   = set()
        self.urls      = set()
        self.params    = set()
        self.forms     = []
        self.endpoints = set()
        self._lock     = __import__("threading").Lock()

    @staticmethod
    def _base_domain(domain: str) -> str:
        """Return eTLD+1 for scope checking."""
        parts = domain.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else domain

    def _in_scope(self, url: str) -> bool:
        """Only crawl URLs within the target domain."""
        parsed = urlparse(url)
        host = parsed.netloc.split(":")[0]
        return host.endswith(self.base_domain)

    def _get(self, url: str) -> tuple:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/124.0.0.0 Safari/537.36"
                    ),
                    "Accept": "text/html,application/xhtml+xml,*/*",
                },
            )
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                ct = resp.headers.get("Content-Type", "")
                if "text" not in ct and "javascript" not in ct:
                    return resp.status, None
                body = resp.read(500_000).decode("utf-8", errors="replace")
                return resp.status, body
        except urllib.error.HTTPError as e:
            return e.code, None
        except Exception as e:
            log_debug(f"Crawl GET {url}: {e}", self.verbose)
            return None, None

    # ── Parsers ──────────────────────────────────────────────────────────────

    def _extract_links(self, base_url: str, body: str) -> list:
        links = []
        # href and src attributes
        for attr in re.findall(r'(?:href|src|action)=["\']([^"\'#?]{3,})', body, re.I):
            url = urljoin(base_url, attr)
            url, _ = urldefrag(url)
            if is_valid_url(url):
                links.append(url)
        # Also catch window.location and fetch() JS patterns
        for js_url in re.findall(r'["\']((https?://[^"\'<>\s]{5,}))["\']', body):
            if is_valid_url(js_url[0]):
                links.append(js_url[0])
        return links

    def _extract_params(self, url: str) -> list:
        parsed  = urlparse(url)
        params  = list(parse_qs(parsed.query).keys())
        return params

    def _extract_forms(self, base_url: str, body: str) -> list:
        forms = []
        for form_html in re.findall(r'<form[^>]*>.*?</form>', body, re.I | re.S):
            action = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
            method = re.search(r'method=["\']([^"\']*)["\']', form_html, re.I)
            inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\']', form_html, re.I)
            forms.append({
                "url":    base_url,
                "action": urljoin(base_url, action.group(1)) if action else base_url,
                "method": (method.group(1) or "GET").upper(),
                "inputs": inputs,
            })
        return forms

    # ── Crawl Worker ─────────────────────────────────────────────────────────

    def _process_url(self, url: str, current_depth: int):
        with self._lock:
            if url in self.visited:
                return []
            self.visited.add(url)

        if self.delay:
            time.sleep(self.delay)

        status, body = self._get(url)
        if status is None:
            return []

        with self._lock:
            self.urls.add(url)
            params = self._extract_params(url)
            for p in params:
                self.params.add(p)

        log_debug(f"[{status}] {url}", self.verbose)
        if status and status < 400:
            log_success(f"[{status}] {url}")

        if body is None or current_depth <= 0:
            return []

        # Parse forms
        forms = self._extract_forms(url, body)
        with self._lock:
            self.forms.extend(forms)

        # Extract new links
        links = self._extract_links(url, body)
        new_links = []
        with self._lock:
            for link in links:
                if link not in self.visited and self._in_scope(link):
                    new_links.append(link)
        return new_links

    def _crawl_bfs(self):
        """Breadth-first crawl up to self.depth."""
        queue = deque([(self.target, self.depth)])

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            while queue:
                batch = []
                while queue and len(batch) < self.threads * 4:
                    batch.append(queue.popleft())

                futures = {
                    ex.submit(self._process_url, url, depth): (url, depth)
                    for url, depth in batch
                }

                for f in concurrent.futures.as_completed(futures):
                    try:
                        _, depth = futures[f]
                        new_links = f.result()
                        if depth > 1:
                            for link in new_links:
                                queue.append((link, depth - 1))
                    except Exception as e:
                        log_debug(f"Crawl thread error: {e}", self.verbose)

    # ── Interesting Path Probe ────────────────────────────────────────────────

    def _probe_interesting_paths(self):
        log_info(f"Probing {len(INTERESTING_PATHS)} interesting paths...")

        def probe(path):
            url = self.target + path
            status, _ = self._get(url)
            if status and status not in (404, 403, 400, 500):
                log_success(f"[{status}] Interesting path: {url}")
                return {"url": url, "status": status}
            return None

        found = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = [ex.submit(probe, p) for p in INTERESTING_PATHS]
            for f in concurrent.futures.as_completed(futures):
                result = f.result()
                if result:
                    found.append(result)
        return found

    # ── Main Run ──────────────────────────────────────────────────────────────

    def run(self) -> dict:
        log_info(
            f"Starting crawl on {Colors.CYAN}{self.target}{Colors.RESET} "
            f"[depth={self.depth}, threads={self.threads}]"
        )

        self._crawl_bfs()
        interesting = self._probe_interesting_paths()

        unique_params = sorted(self.params)
        url_list      = sorted(self.urls)

        log_success(f"Crawl complete: {len(url_list)} URLs, "
                    f"{len(unique_params)} params, {len(self.forms)} forms")

        return {
            "urls":              url_list,
            "parameters":        unique_params,
            "forms":             self.forms,
            "interesting_paths": interesting,
            "total_visited":     len(self.visited),
        }
