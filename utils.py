"""
modules/utils.py — Shared utilities, colors, and logging helpers
"""

import re
import sys
import socket
from urllib.parse import urlparse


class Colors:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    BLUE    = "\033[94m"
    WHITE   = "\033[97m"
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"

    @staticmethod
    def disable():
        """Disable colors (e.g. for file output)."""
        for attr in ["RED","GREEN","YELLOW","CYAN","MAGENTA","BLUE","WHITE","RESET","BOLD","DIM"]:
            setattr(Colors, attr, "")


def _print(prefix: str, color: str, message: str):
    print(f"{color}{prefix}{Colors.RESET} {message}")


def log_info(msg: str):
    _print("[*]", Colors.CYAN, msg)

def log_success(msg: str):
    _print("[+]", Colors.GREEN, msg)

def log_warning(msg: str):
    _print("[!]", Colors.YELLOW, msg)

def log_error(msg: str):
    _print("[-]", Colors.RED, msg)

def log_debug(msg: str, verbose: bool = False):
    if verbose:
        _print("[~]", Colors.DIM, msg)

def log_finding(severity: str, msg: str):
    color_map = {
        "CRITICAL": Colors.RED + Colors.BOLD,
        "HIGH":     Colors.RED,
        "MEDIUM":   Colors.YELLOW,
        "LOW":      Colors.CYAN,
        "INFO":     Colors.WHITE,
    }
    color = color_map.get(severity.upper(), Colors.WHITE)
    _print(f"[{severity.upper()[:3]}]", color, msg)


def sanitize_target(target: str) -> str:
    """
    Normalize target input: strip scheme/path for domain-level ops,
    return clean base URL.
    """
    target = target.strip()

    # If it has a scheme, parse it; otherwise add https temporarily to parse
    if not target.startswith(("http://", "https://")):
        # Check if IP address
        try:
            socket.inet_aton(target.split(":")[0])
            return f"http://{target}"
        except socket.error:
            pass
        target = f"https://{target}"

    parsed = urlparse(target)
    if not parsed.netloc:
        return ""

    # Re-assemble clean URL (scheme + netloc only, no trailing slash weirdness)
    scheme = parsed.scheme or "https"
    return f"{scheme}://{parsed.netloc}"


def extract_domain(target: str) -> str:
    """Return bare domain/IP from a URL."""
    parsed = urlparse(target)
    host = parsed.netloc or parsed.path
    # Strip port
    return host.split(":")[0]


def is_valid_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme in ("http", "https"), result.netloc])
    except Exception:
        return False


def severity_score(severity: str) -> int:
    """Return numeric score for sorting."""
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(
        severity.upper(), 0
    )
