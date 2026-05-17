"""
modules/reporter.py — Report Generator
Outputs: structured text report + optional HTML report
"""

import os
import json
from datetime import datetime

from .utils import Colors, log_info, log_error

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")


def _ensure_dir():
    os.makedirs(REPORTS_DIR, exist_ok=True)


class Reporter:
    def __init__(self, results: dict, output_name: str = None):
        self.results     = results
        self.target      = results.get("target", "unknown")
        self.scan_start  = results.get("scan_start", "")
        self.scan_end    = results.get("scan_end", "")
        self.duration    = results.get("duration_seconds", 0)
        self.recon       = results.get("recon", {})
        self.crawl       = results.get("crawl", {})
        self.vulns       = results.get("vulnerabilities", [])
        _ensure_dir()

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = output_name or f"report_{ts}"
        self.base_name   = os.path.join(REPORTS_DIR, name)

    # ── Text Report ───────────────────────────────────────────────────────────

    def generate_text_report(self) -> str:
        lines = []
        sep  = "=" * 70
        sep2 = "-" * 70

        lines.append(sep)
        lines.append("  RECONX — SECURITY ASSESSMENT REPORT")
        lines.append(sep)
        lines.append(f"  Target         : {self.target}")
        lines.append(f"  Scan Started   : {self.scan_start}")
        lines.append(f"  Scan Ended     : {self.scan_end}")
        lines.append(f"  Duration       : {self.duration:.1f} seconds")
        lines.append(f"  Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(sep)

        # ── Recon section
        lines.append("\n[1] RECONNAISSANCE FINDINGS")
        lines.append(sep2)

        dns = self.recon.get("dns", {})
        lines.append(f"\n  Domain         : {self.recon.get('domain','')}")
        lines.append(f"  IP (A Record)  : {dns.get('a_record','N/A')}")
        if dns.get("all_ips"):
            lines.append(f"  All IPs        : {', '.join(dns.get('all_ips',[]))}")

        ssl_ = self.recon.get("ssl", {})
        if ssl_.get("version"):
            lines.append(f"\n  SSL/TLS Version: {ssl_['version']}")
            lines.append(f"  Cipher         : {ssl_.get('cipher','')}")
            lines.append(f"  Cert Issuer    : {ssl_.get('issuer',{}).get('organizationName','')}")
            lines.append(f"  Valid Until    : {ssl_.get('not_after','')}")
            if ssl_.get("san"):
                lines.append(f"  SAN Entries    : {', '.join(ssl_['san'][:8])}")

        hdrs = self.recon.get("http_headers", {})
        if hdrs:
            lines.append(f"\n  HTTP Status    : {hdrs.get('status_code','')}")
            lines.append(f"  Server         : {hdrs.get('server','')}")
            lines.append(f"  X-Powered-By   : {hdrs.get('x_powered_by','')}")
            missing = hdrs.get("missing_security_headers", [])
            if missing:
                lines.append(f"  Missing Headers: {', '.join(missing)}")

        ports = self.recon.get("open_ports", [])
        lines.append(f"\n  Open Ports     : {', '.join(str(p) for p in ports) or 'None found'}")

        subs = self.recon.get("subdomains", [])
        lines.append(f"\n  Subdomains ({len(subs)}):")
        for s in subs:
            lines.append(f"    - {s}")

        techs = self.recon.get("technologies", [])
        lines.append(f"\n  Technologies ({len(techs)}):")
        for t in techs:
            lines.append(f"    - {t}")

        js_files = self.recon.get("js_files", [])
        lines.append(f"\n  JavaScript Files ({len(js_files)}):")
        for js in js_files[:20]:
            lines.append(f"    - {js}")
        if len(js_files) > 20:
            lines.append(f"    ... and {len(js_files)-20} more")

        # ── Crawl section
        lines.append("\n\n[2] CRAWL & ENDPOINT DISCOVERY")
        lines.append(sep2)

        urls = self.crawl.get("urls", [])
        lines.append(f"\n  Total URLs Found : {len(urls)}")
        for u in urls[:50]:
            lines.append(f"    {u}")
        if len(urls) > 50:
            lines.append(f"    ... and {len(urls)-50} more")

        params = self.crawl.get("parameters", [])
        lines.append(f"\n  Parameters Discovered ({len(params)}): {', '.join(params)}")

        forms = self.crawl.get("forms", [])
        lines.append(f"\n  Forms ({len(forms)}):")
        for f in forms[:10]:
            lines.append(
                f"    [{f.get('method','?')}] {f.get('action','')} "
                f"— inputs: {', '.join(f.get('inputs',[]))}"
            )

        interesting = self.crawl.get("interesting_paths", [])
        lines.append(f"\n  Interesting Paths ({len(interesting)}):")
        for ip in interesting:
            lines.append(f"    [{ip.get('status','')}] {ip.get('url','')}")

        # ── Vulnerability section
        lines.append("\n\n[3] VULNERABILITY FINDINGS")
        lines.append(sep2)

        if not self.vulns:
            lines.append("\n  No vulnerabilities found.")
        else:
            sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            for sev in sev_order:
                group = [v for v in self.vulns if v.get("severity","").upper() == sev]
                if not group:
                    continue
                lines.append(f"\n  ── {sev} ({len(group)}) ──")
                for i, vuln in enumerate(group, 1):
                    lines.append(f"\n  [{i}] {vuln.get('title','')}")
                    if vuln.get("url"):
                        lines.append(f"      URL        : {vuln['url']}")
                    if vuln.get("parameter"):
                        lines.append(f"      Parameter  : {vuln['parameter']}")
                    if vuln.get("evidence"):
                        lines.append(f"      Evidence   : {vuln['evidence'][:150]}")
                    if vuln.get("description"):
                        lines.append(f"      Description: {vuln['description']}")
                    if vuln.get("remediation"):
                        lines.append(f"      Remediation: {vuln['remediation']}")

        # ── Summary
        lines.append("\n\n[4] SUMMARY")
        lines.append(sep2)
        lines.append(f"\n  Target         : {self.target}")
        lines.append(f"  Subdomains     : {len(self.recon.get('subdomains',[]))}")
        lines.append(f"  Open Ports     : {len(self.recon.get('open_ports',[]))}")
        lines.append(f"  Technologies   : {len(self.recon.get('technologies',[]))}")
        lines.append(f"  URLs Crawled   : {len(self.crawl.get('urls',[]))}")
        total_vulns = len(self.vulns)
        counts = {}
        for v in self.vulns:
            s = v.get("severity","INFO")
            counts[s] = counts.get(s, 0) + 1
        lines.append(f"  Vulnerabilities: {total_vulns}")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if counts.get(sev):
                lines.append(f"    {sev:10}: {counts[sev]}")

        lines.append(f"\n{sep}")
        lines.append("  END OF REPORT — ReconX v1.0.0")
        lines.append(sep)

        text = "\n".join(lines)
        path = self.base_name + ".txt"
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

        # Also save raw JSON
        json_path = self.base_name + ".json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, default=str)

        return path

    # ── HTML Report ───────────────────────────────────────────────────────────

    def generate_html_report(self) -> str:
        vulns       = self.vulns
        subs        = self.recon.get("subdomains", [])
        techs       = self.recon.get("technologies", [])
        open_ports  = self.recon.get("open_ports", [])
        urls        = self.crawl.get("urls", [])
        params      = self.crawl.get("parameters", [])
        interesting = self.crawl.get("interesting_paths", [])

        sev_color = {
            "CRITICAL": "#e74c3c",
            "HIGH":     "#e67e22",
            "MEDIUM":   "#f1c40f",
            "LOW":      "#3498db",
            "INFO":     "#95a5a6",
        }

        def vuln_rows():
            if not vulns:
                return '<tr><td colspan="5" style="text-align:center;color:#999">No vulnerabilities found</td></tr>'
            rows = []
            for v in vulns:
                sev  = v.get("severity","INFO")
                col  = sev_color.get(sev, "#999")
                rows.append(f"""
                <tr>
                  <td><span style="background:{col};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{sev}</span></td>
                  <td><strong>{v.get('title','')}</strong></td>
                  <td><code style="font-size:11px">{v.get('url','')[:60]}</code></td>
                  <td style="font-size:12px">{v.get('evidence','')[:80]}</td>
                  <td style="font-size:12px;color:#27ae60">{v.get('remediation','')[:80]}</td>
                </tr>""")
            return "\n".join(rows)

        sev_counts = {s: sum(1 for v in vulns if v.get("severity") == s)
                      for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReconX Report — {self.target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f1117; color: #e0e0e0; }}
  header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            border-bottom: 2px solid #e74c3c; padding: 24px 40px; }}
  header h1 {{ color: #e74c3c; font-size: 28px; letter-spacing: 4px; }}
  header p  {{ color: #888; margin-top: 4px; font-size: 13px; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 30px 24px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(180px,1fr)); gap: 16px; margin-bottom: 30px; }}
  .card {{ background: #1e2130; border-radius: 8px; padding: 20px; border-left: 4px solid #e74c3c; }}
  .card .num {{ font-size: 32px; font-weight: 700; color: #e74c3c; }}
  .card .lbl {{ font-size: 12px; color: #888; margin-top: 4px; text-transform: uppercase; letter-spacing: 1px; }}
  .sev-grid {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 30px; }}
  .sev-badge {{ padding: 8px 16px; border-radius: 6px; font-size: 13px; font-weight: 600; }}
  section {{ margin-bottom: 32px; }}
  section h2 {{ font-size: 16px; color: #e74c3c; border-bottom: 1px solid #2a2d3e;
                padding-bottom: 8px; margin-bottom: 16px; text-transform: uppercase;
                letter-spacing: 2px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ background: #1e2130; color: #888; padding: 10px 12px; text-align: left;
        font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }}
  td {{ padding: 9px 12px; border-bottom: 1px solid #1e2130; vertical-align: top; }}
  tr:hover td {{ background: #1a1d2b; }}
  .tag {{ display:inline-block; background:#2a2d3e; border-radius:4px;
          padding:2px 8px; font-size:11px; margin:2px; color:#aaa; }}
  pre {{ background:#1e2130; padding:14px; border-radius:6px; font-size:12px;
         overflow-x:auto; max-height:240px; color:#a0c4ff; }}
  ul li {{ margin: 4px 0; font-size: 13px; color: #ccc; }}
  footer {{ text-align: center; color: #444; font-size: 12px; padding: 20px; }}
</style>
</head>
<body>
<header>
  <h1>⬡ RECONX SECURITY REPORT</h1>
  <p>Target: {self.target} &nbsp;|&nbsp; {self.scan_start} &nbsp;|&nbsp; Duration: {self.duration:.1f}s</p>
</header>

<div class="container">

  <!-- Summary cards -->
  <div class="grid">
    <div class="card"><div class="num">{len(subs)}</div><div class="lbl">Subdomains</div></div>
    <div class="card"><div class="num">{len(open_ports)}</div><div class="lbl">Open Ports</div></div>
    <div class="card"><div class="num">{len(techs)}</div><div class="lbl">Technologies</div></div>
    <div class="card"><div class="num">{len(urls)}</div><div class="lbl">URLs Found</div></div>
    <div class="card"><div class="num" style="color:{'#e74c3c' if len(vulns)>0 else '#27ae60'}">{len(vulns)}</div><div class="lbl">Vulnerabilities</div></div>
  </div>

  <!-- Severity breakdown -->
  <div class="sev-grid">
    {"".join(f'<div class="sev-badge" style="background:{sev_color[s]};color:#fff">{s}: {sev_counts[s]}</div>' for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] if sev_counts[s])}
  </div>

  <!-- Vulnerabilities -->
  <section>
    <h2>Vulnerability Findings</h2>
    <table>
      <thead><tr><th>Severity</th><th>Title</th><th>URL</th><th>Evidence</th><th>Remediation</th></tr></thead>
      <tbody>{vuln_rows()}</tbody>
    </table>
  </section>

  <!-- Recon -->
  <section>
    <h2>Reconnaissance</h2>
    <table>
      <tbody>
        <tr><td><strong>Domain</strong></td><td>{self.recon.get('domain','')}</td></tr>
        <tr><td><strong>IP Address</strong></td><td>{self.recon.get('dns',{}).get('a_record','')}</td></tr>
        <tr><td><strong>Open Ports</strong></td><td>{', '.join(str(p) for p in open_ports) or '—'}</td></tr>
        <tr><td><strong>SSL Version</strong></td><td>{self.recon.get('ssl',{}).get('version','—')}</td></tr>
        <tr><td><strong>Cert Valid Until</strong></td><td>{self.recon.get('ssl',{}).get('not_after','—')}</td></tr>
        <tr><td><strong>Server</strong></td><td>{self.recon.get('http_headers',{}).get('server','—')}</td></tr>
        <tr><td><strong>Subdomains</strong></td><td>{"<br>".join(subs) or "—"}</td></tr>
        <tr><td><strong>Technologies</strong></td><td>{"".join(f'<span class="tag">{t}</span>' for t in techs) or "—"}</td></tr>
      </tbody>
    </table>
  </section>

  <!-- Endpoints -->
  <section>
    <h2>Discovered Endpoints ({len(urls)})</h2>
    <pre>{"&#10;".join(urls[:100])}</pre>
    {"<p style='color:#888;font-size:12px'>... truncated to first 100</p>" if len(urls)>100 else ""}
  </section>

  <!-- Parameters -->
  <section>
    <h2>Parameters ({len(params)})</h2>
    <p>{"".join(f'<span class="tag">{p}</span>' for p in params) or "None found"}</p>
  </section>

  <!-- Interesting Paths -->
  <section>
    <h2>Interesting Paths ({len(interesting)})</h2>
    <table>
      <thead><tr><th>Status</th><th>URL</th></tr></thead>
      <tbody>
        {"".join(f"<tr><td>{ip.get('status','')}</td><td><code>{ip.get('url','')}</code></td></tr>" for ip in interesting) or '<tr><td colspan="2" style="color:#888">None found</td></tr>'}
      </tbody>
    </table>
  </section>

</div>
<footer>ReconX v1.0.0 &mdash; For authorized use only</footer>
</body>
</html>"""

        path = self.base_name + ".html"
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path
