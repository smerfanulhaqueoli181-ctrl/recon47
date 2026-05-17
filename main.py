#!/usr/bin/env python3
"""
ReconX - Automated Reconnaissance & Vulnerability Scanner
CLI Entry Point
"""

import argparse
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.banner import print_banner
from modules.recon import ReconModule
from modules.crawler import CrawlerModule
from modules.vuln_scanner import VulnScannerModule
from modules.reporter import Reporter
from modules.utils import Colors, log_info, log_success, log_warning, log_error, sanitize_target


def interactive_menu():
    """Ask the user for target and options interactively."""
    print(f"{Colors.CYAN}{'─'*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  Quick Scan Setup{Colors.RESET}")
    print(f"{Colors.CYAN}{'─'*60}{Colors.RESET}\n")

    while True:
        target = input(f"  {Colors.GREEN}[?]{Colors.RESET} Enter target (domain / IP / URL): ").strip()
        if target:
            break
        print(f"  {Colors.RED}[-]{Colors.RESET} Target cannot be empty. Try again.")

    html_input = input(f"  {Colors.GREEN}[?]{Colors.RESET} Generate HTML report? (y/n) [y]: ").strip().lower()
    html = html_input != "n"

    vuln_input = input(f"  {Colors.GREEN}[?]{Colors.RESET} Run vulnerability scan? (y/n) [y]: ").strip().lower()
    no_vuln = vuln_input == "n"

    depth_input = input(f"  {Colors.GREEN}[?]{Colors.RESET} Crawl depth (1-5) [2]: ").strip()
    try:
        depth = int(depth_input) if depth_input else 2
        depth = max(1, min(5, depth))
    except ValueError:
        depth = 2

    threads_input = input(f"  {Colors.GREEN}[?]{Colors.RESET} Threads (1-20) [5]: ").strip()
    try:
        threads = int(threads_input) if threads_input else 5
        threads = max(1, min(20, threads))
    except ValueError:
        threads = 5

    print(f"\n  {Colors.CYAN}Target   :{Colors.RESET} {target}")
    print(f"  {Colors.CYAN}HTML     :{Colors.RESET} {'Yes' if html else 'No'}")
    print(f"  {Colors.CYAN}Vuln Scan:{Colors.RESET} {'Yes' if not no_vuln else 'No'}")
    print(f"  {Colors.CYAN}Depth    :{Colors.RESET} {depth}")
    print(f"  {Colors.CYAN}Threads  :{Colors.RESET} {threads}")

    confirm = input(f"\n  {Colors.GREEN}[?]{Colors.RESET} Start scan? (y/n) [y]: ").strip().lower()
    if confirm == "n":
        print(f"\n  {Colors.YELLOW}[!]{Colors.RESET} Scan cancelled.")
        sys.exit(0)
    print()

    class Args:
        pass
    args = Args()
    args.target   = target
    args.html     = html
    args.no_vuln  = no_vuln
    args.no_crawl = False
    args.depth    = depth
    args.threads  = threads
    args.timeout  = 10
    args.delay    = 0.5
    args.output   = None
    args.nikto    = False
    args.nuclei   = False
    args.stealth  = False
    args.verbose  = False
    return args


def parse_args():
    parser = argparse.ArgumentParser(
        description="ReconX - Automated Reconnaissance & Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                          (interactive mode)
  python main.py -t example.com
  python main.py -t 192.168.1.1 --html
  python main.py -t example.com --depth 3 --threads 10 --html
        """
    )
    parser.add_argument("-t", "--target", required=False, default=None,
                        help="Target domain, subdomain, URL, or IP address")
    parser.add_argument("--depth",    type=int,   default=2,   help="Crawl depth (default: 2)")
    parser.add_argument("--threads",  type=int,   default=5,   help="Threads (default: 5)")
    parser.add_argument("--timeout",  type=int,   default=10,  help="Timeout seconds (default: 10)")
    parser.add_argument("--delay",    type=float, default=0.5, help="Delay between requests (default: 0.5)")
    parser.add_argument("--output",   default=None, help="Report filename (no extension)")
    parser.add_argument("--html",     action="store_true", help="Generate HTML report")
    parser.add_argument("--no-vuln",  action="store_true", help="Skip vulnerability scanning")
    parser.add_argument("--no-crawl", action="store_true", help="Skip crawling phase")
    parser.add_argument("--nikto",    action="store_true", help="Run Nikto (if installed)")
    parser.add_argument("--nuclei",   action="store_true", help="Run Nuclei (if installed)")
    parser.add_argument("--stealth",  action="store_true", help="Stealth mode")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    return parser.parse_args()


def main():
    print_banner()
    args = parse_args()

    # No target → interactive mode
    if not args.target:
        args = interactive_menu()

    target = sanitize_target(args.target)
    if not target:
        log_error("Invalid target. Please enter a valid domain, URL, or IP.")
        sys.exit(1)

    scan_start = datetime.now()
    log_info(f"Starting scan on: {Colors.CYAN}{target}{Colors.RESET}")
    log_info(f"Scan started at:  {scan_start.strftime('%Y-%m-%d %H:%M:%S')}")
    log_info(f"Threads: {args.threads} | Depth: {args.depth} | Delay: {args.delay}s")
    if args.stealth:
        log_warning("Stealth mode enabled — scan will be slower.")

    results = {
        "target": target,
        "scan_start": scan_start.isoformat(),
        "args": vars(args),
        "recon": {},
        "crawl": {},
        "vulnerabilities": [],
    }

    # ── Phase 1: Reconnaissance ─────────────────────────────────────────────
    print(f"\n{Colors.BOLD}{Colors.YELLOW}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.YELLOW}  PHASE 1: RECONNAISSANCE{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.YELLOW}{'='*60}{Colors.RESET}\n")

    recon = ReconModule(target=target, timeout=args.timeout, verbose=args.verbose,
                        delay=args.delay if args.stealth else 0)
    results["recon"] = recon.run()

    # ── Phase 2: Crawling ───────────────────────────────────────────────────
    if not args.no_crawl:
        print(f"\n{Colors.BOLD}{Colors.YELLOW}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.YELLOW}  PHASE 2: CRAWLING & ENDPOINT DISCOVERY{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.YELLOW}{'='*60}{Colors.RESET}\n")

        crawler = CrawlerModule(target=target, depth=args.depth, threads=args.threads,
                                timeout=args.timeout, delay=args.delay, verbose=args.verbose)
        results["crawl"] = crawler.run()

    # ── Phase 3: Vulnerability Scanning ────────────────────────────────────
    if not args.no_vuln:
        print(f"\n{Colors.BOLD}{Colors.YELLOW}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.YELLOW}  PHASE 3: VULNERABILITY SCANNING{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.YELLOW}{'='*60}{Colors.RESET}\n")

        vuln_scanner = VulnScannerModule(
            target=target,
            urls=results.get("crawl", {}).get("urls", []),
            timeout=args.timeout, threads=args.threads, delay=args.delay,
            run_nikto=args.nikto, run_nuclei=args.nuclei, verbose=args.verbose,
        )
        results["vulnerabilities"] = vuln_scanner.run()

    # ── Phase 4: Reporting ──────────────────────────────────────────────────
    print(f"\n{Colors.BOLD}{Colors.YELLOW}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.YELLOW}  PHASE 4: REPORT GENERATION{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.YELLOW}{'='*60}{Colors.RESET}\n")

    scan_end = datetime.now()
    results["scan_end"] = scan_end.isoformat()
    results["duration_seconds"] = (scan_end - scan_start).total_seconds()

    reporter = Reporter(results=results, output_name=args.output)
    text_report = reporter.generate_text_report()
    log_success(f"Text report saved: {text_report}")

    if args.html:
        html_report = reporter.generate_html_report()
        log_success(f"HTML report saved: {html_report}")

    vuln_count      = len(results.get("vulnerabilities", []))
    url_count       = len(results.get("crawl", {}).get("urls", []))
    subdomain_count = len(results.get("recon", {}).get("subdomains", []))

    print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.GREEN}  SCAN COMPLETE{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.GREEN}{'='*60}{Colors.RESET}")
    print(f"  {Colors.CYAN}Duration       :{Colors.RESET} {results['duration_seconds']:.1f}s")
    print(f"  {Colors.CYAN}Subdomains     :{Colors.RESET} {subdomain_count}")
    print(f"  {Colors.CYAN}URLs Found     :{Colors.RESET} {url_count}")
    print(f"  {Colors.CYAN}Vulnerabilities:{Colors.RESET} {Colors.RED if vuln_count > 0 else Colors.GREEN}{vuln_count}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.GREEN}{'='*60}{Colors.RESET}\n")


if __name__ == "__main__":
    main()