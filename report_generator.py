"""
report_generator.py — Unified HTML Report Generator
Handles output from: domain_recon, email_recon, shodan_wrapper, port_scanner, web_scraper
"""

import json
import os
import argparse
from datetime import datetime
from jinja2 import Template


REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Recon Report — {{ target }}</title>
  <style>
    :root {
      --bg: #0d1117; --surface: #161b22; --border: #30363d;
      --text: #c9d1d9; --muted: #8b949e;
      --blue: #58a6ff; --green: #3fb950; --red: #f85149;
      --yellow: #d29922; --purple: #bc8cff;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', system-ui, monospace; background: var(--bg);
           color: var(--text); padding: 2rem; line-height: 1.6; }
    h1 { color: var(--blue); font-size: 1.8rem; margin-bottom: 0.25rem; }
    h2 { color: var(--blue); font-size: 1.2rem; margin: 2rem 0 0.75rem;
         padding-bottom: 0.4rem; border-bottom: 1px solid var(--border); }
    h3 { color: var(--purple); font-size: 1rem; margin: 1rem 0 0.5rem; }
    .meta { color: var(--muted); font-size: 0.85rem; margin-bottom: 2rem; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 12px;
             font-size: 0.75rem; font-weight: 600; margin: 2px; }
    .badge-blue   { background: #1f6feb33; color: var(--blue);   border: 1px solid #1f6feb; }
    .badge-green  { background: #3fb95033; color: var(--green);  border: 1px solid #3fb950; }
    .badge-red    { background: #f8514933; color: var(--red);    border: 1px solid #f85149; }
    .badge-yellow { background: #d2992233; color: var(--yellow); border: 1px solid #d29922; }
    .card { background: var(--surface); border: 1px solid var(--border);
            border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem; }
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
    .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1rem; }
    .stat { text-align: center; }
    .stat .num   { font-size: 2rem; font-weight: 700; color: var(--blue); }
    .stat .label { font-size: 0.8rem; color: var(--muted); }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    th { background: #1f2937; color: var(--muted); text-align: left;
         padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border); }
    td { padding: 0.4rem 0.75rem; border-bottom: 1px solid #21262d; vertical-align: top; }
    tr:hover td { background: #1c2128; }
    .open   { color: var(--green); font-weight: 600; }
    .closed { color: var(--muted); }
    .warn   { color: var(--yellow); }
    .danger { color: var(--red); font-weight: 600; }
    pre { background: #0a0d11; border: 1px solid var(--border); border-radius: 6px;
          padding: 1rem; overflow-x: auto; font-size: 0.8rem; white-space: pre-wrap;
          word-break: break-all; max-height: 300px; }
    .tag-list { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 4px; }
    details { margin: 0.5rem 0; }
    summary { cursor: pointer; color: var(--blue); padding: 0.25rem 0; }
    summary:hover { color: var(--purple); }
    .section-icon { margin-right: 0.4rem; }
    ul { padding-left: 1.25rem; }
    li { margin: 2px 0; font-size: 0.85rem; }
    a  { color: var(--blue); text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>

<h1>🔍 Recon Report</h1>
<div class="meta">
  <strong>Target:</strong> {{ target }} &nbsp;|&nbsp;
  <strong>Generated:</strong> {{ timestamp }} &nbsp;|&nbsp;
  <strong>Modules:</strong> {{ modules | join(', ') }}
</div>

<!-- Summary Dashboard -->
<h2><span class="section-icon">📊</span>Executive Summary</h2>
<div class="grid-3">
  {% if summary.open_ports is defined %}
  <div class="card stat">
    <div class="num">{{ summary.open_ports }}</div>
    <div class="label">Open Ports</div>
  </div>
  {% endif %}
  {% if summary.emails_found is defined %}
  <div class="card stat">
    <div class="num">{{ summary.emails_found }}</div>
    <div class="label">Emails Found</div>
  </div>
  {% endif %}
  {% if summary.subdomains is defined %}
  <div class="card stat">
    <div class="num">{{ summary.subdomains }}</div>
    <div class="label">Subdomains</div>
  </div>
  {% endif %}
  {% if summary.technologies %}
  <div class="card stat">
    <div class="num">{{ summary.technologies | length }}</div>
    <div class="label">Technologies</div>
  </div>
  {% endif %}
  {% if summary.cves %}
  <div class="card stat">
    <div class="num danger">{{ summary.cves | length }}</div>
    <div class="label">CVEs Detected</div>
  </div>
  {% endif %}
  {% if summary.missing_sec_headers %}
  <div class="card stat">
    <div class="num warn">{{ summary.missing_sec_headers | length }}</div>
    <div class="label">Missing Sec Headers</div>
  </div>
  {% endif %}
</div>

<!-- Domain Recon -->
{% if domain %}
<h2><span class="section-icon">🌐</span>Domain Reconnaissance</h2>

{% if domain.whois %}
<div class="card">
  <h3>WHOIS</h3>
  <table><tbody>
  {% for k, v in domain.whois.items() %}
    {% if v %}<tr><th style="width:180px">{{ k }}</th><td>{{ v }}</td></tr>{% endif %}
  {% endfor %}
  </tbody></table>
</div>
{% endif %}

{% if domain.dns %}
<div class="card">
  <h3>DNS Records</h3>
  <table><thead><tr><th>Type</th><th>Values</th></tr></thead><tbody>
  {% for rtype, vals in domain.dns.items() %}
    {% if vals %}
    <tr>
      <td><span class="badge badge-blue">{{ rtype }}</span></td>
      <td>{% for v in vals %}<code>{{ v }}</code><br>{% endfor %}</td>
    </tr>
    {% endif %}
  {% endfor %}
  </tbody></table>
</div>
{% endif %}

{% if domain.subdomains %}
<div class="card">
  <h3>Subdomains ({{ domain.subdomains | length }})</h3>
  <div class="tag-list">
    {% for sub in domain.subdomains %}
    <span class="badge badge-green">{{ sub }}</span>
    {% endfor %}
  </div>
</div>
{% endif %}
{% endif %}

<!-- Email Recon -->
{% if email %}
<h2><span class="section-icon">📧</span>Email Reconnaissance</h2>
<div class="grid-2">
  <div class="card">
    <h3>Breach Data</h3>
    {% if email.breaches %}
      {% for b in email.breaches %}
        <span class="badge badge-red">{{ b }}</span>
      {% endfor %}
    {% else %}
      <span class="badge badge-green">No known breaches</span>
    {% endif %}
  </div>
  <div class="card">
    <h3>Reputation</h3>
    {% if email.reputation %}
    <table><tbody>
      <tr>
        <th>Reputation</th>
        <td class="{{ 'danger' if email.reputation.reputation == 'low' else 'open' }}">
          {{ email.reputation.reputation }}
        </td>
      </tr>
      <tr>
        <th>Suspicious</th>
        <td class="{{ 'danger' if email.reputation.suspicious else 'open' }}">
          {{ email.reputation.suspicious }}
        </td>
      </tr>
    </tbody></table>
    {% endif %}
  </div>
</div>
{% if email.associated_emails %}
<div class="card">
  <h3>Associated Emails ({{ email.associated_emails | length }})</h3>
  <table><thead><tr><th>Email</th><th>Type</th><th>Confidence</th></tr></thead><tbody>
  {% for e in email.associated_emails %}
  <tr>
    <td>{{ e.value }}</td>
    <td>{{ e.type }}</td>
    <td>{{ e.confidence }}%</td>
  </tr>
  {% endfor %}
  </tbody></table>
</div>
{% endif %}
{% endif %}

<!-- Shodan -->
{% if shodan_data %}
<h2><span class="section-icon">📡</span>Shodan Intelligence</h2>
{% if shodan_data.host %}
<div class="card">
  <h3>Host Info — {{ shodan_data.host.ip }}</h3>
  <div class="grid-2">
    <div>
      <table><tbody>
        <tr><th>Organisation</th><td>{{ shodan_data.host.org }}</td></tr>
        <tr><th>ISP</th>         <td>{{ shodan_data.host.isp }}</td></tr>
        <tr><th>ASN</th>         <td>{{ shodan_data.host.asn }}</td></tr>
        <tr><th>Location</th>    <td>{{ shodan_data.host.city }}, {{ shodan_data.host.country }}</td></tr>
        <tr><th>Open Ports</th>  <td>{{ shodan_data.host.ports | join(', ') }}</td></tr>
      </tbody></table>
    </div>
    <div>
      {% if shodan_data.host.vulns %}
      <h3 class="danger">⚠ CVEs Detected</h3>
      {% for cve in shodan_data.host.vulns %}
        <span class="badge badge-red">{{ cve }}</span>
      {% endfor %}
      {% else %}
        <span class="badge badge-green">No CVEs detected</span>
      {% endif %}
    </div>
  </div>
</div>

{% if shodan_data.host.services %}
<div class="card">
  <h3>Services</h3>
  <table>
    <thead><tr><th>Port</th><th>Protocol</th><th>Product</th><th>Version</th><th>Banner</th></tr></thead>
    <tbody>
    {% for svc in shodan_data.host.services %}
    <tr>
      <td class="open">{{ svc.port }}</td>
      <td>{{ svc.transport }}</td>
      <td>{{ svc.product }}</td>
      <td>{{ svc.version }}</td>
      <td><code>{{ (svc.banner or '')[:100] }}</code></td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
{% endif %}
{% endif %}

{% if shodan_data.exploits %}
<div class="card">
  <h3>Exploits Found ({{ shodan_data.exploits.total }})</h3>
  <table>
    <thead><tr><th>Type</th><th>Description</th><th>CVEs</th><th>Date</th></tr></thead>
    <tbody>
    {% for e in shodan_data.exploits.exploits %}
    <tr>
      <td><span class="badge badge-red">{{ e.type }}</span></td>
      <td>{{ e.description[:120] }}</td>
      <td>{% for cve in e.cve %}<span class="badge badge-yellow">{{ cve }}</span>{% endfor %}</td>
      <td>{{ e.date }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
{% endif %}
{% endif %}

<!-- Port Scanner -->
{% if ports %}
<h2><span class="section-icon">🔌</span>Port Scan Results — {{ ports.target }}</h2>
<div class="card">
  <div class="grid-3" style="margin-bottom:1rem">
    <div class="stat">
      <div class="num">{{ ports.summary.total_scanned }}</div>
      <div class="label">Ports Scanned</div>
    </div>
    <div class="stat">
      <div class="num open">{{ ports.summary.open_tcp }}</div>
      <div class="label">Open TCP</div>
    </div>
    <div class="stat">
      <div class="num">{{ ports.summary.open_udp }}</div>
      <div class="label">Open/Filtered UDP</div>
    </div>
  </div>
  <h3>Open TCP Ports</h3>
  <table>
    <thead><tr><th>Port</th><th>State</th><th>Service</th><th>Product</th><th>Version</th><th>Banner</th></tr></thead>
    <tbody>
    {% for p in ports.tcp %}
      {% if p.state == 'open' %}
      <tr>
        <td class="open">{{ p.port }}</td>
        <td><span class="badge badge-green">{{ p.state }}</span></td>
        <td>{{ p.service }}</td>
        <td>{{ p.get('product', '') }}</td>
        <td>{{ p.get('version', '') }}</td>
        <td><code>{{ ((p.get('banner') or ''))[:80] }}</code></td>
      </tr>
      {% endif %}
    {% endfor %}
    </tbody>
  </table>
</div>

{% if ports.udp %}
<div class="card">
  <h3>UDP Scan Results</h3>
  <table>
    <thead><tr><th>Port</th><th>Protocol</th><th>State</th></tr></thead>
    <tbody>
    {% for p in ports.udp %}
    <tr>
      <td>{{ p.port }}</td>
      <td>udp</td>
      <td>
        <span class="badge {{ 'badge-green' if 'open' in p.state else 'badge-yellow' }}">
          {{ p.state }}
        </span>
      </td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
{% endif %}
{% endif %}

<!-- Web Scraper -->
{% if web %}
<h2><span class="section-icon">🕸</span>Web Scraping & Metadata — {{ web.target }}</h2>

<div class="grid-2">
  <div class="card">
    <h3>Page Info</h3>
    <table><tbody>
      <tr><th>Status</th>      <td>{{ web.status_code }}</td></tr>
      <tr><th>Title</th>       <td>{{ web.metadata.title }}</td></tr>
      <tr><th>Server</th>      <td>{{ web.headers.server }}</td></tr>
      <tr><th>X-Powered-By</th><td>{{ web.headers.x_powered_by }}</td></tr>
      {% if web.metadata.generator %}
      <tr><th>Generator</th>   <td>{{ web.metadata.generator }}</td></tr>
      {% endif %}
      {% if web.metadata.description %}
      <tr><th>Description</th> <td>{{ web.metadata.description[:200] }}</td></tr>
      {% endif %}
    </tbody></table>
  </div>
  <div class="card">
    <h3>Technologies Detected</h3>
    <div class="tag-list">
      {% for tech in web.technologies.detected %}
        <span class="badge badge-blue">{{ tech }}</span>
      {% endfor %}
    </div>
    <h3 style="margin-top:1rem">Security Headers</h3>
    {% for header, value in web.headers.security_headers.items() %}
    <div style="display:flex; justify-content:space-between; font-size:0.8rem; padding:2px 0">
      <span>{{ header }}</span>
      <span class="{{ 'open' if value else 'danger' }}">{{ '✓' if value else '✗ Missing' }}</span>
    </div>
    {% endfor %}
  </div>
</div>

{% if web.emails_and_ips.emails %}
<div class="card">
  <h3>Emails Discovered</h3>
  {% for email_addr in web.emails_and_ips.emails %}
    <span class="badge badge-green">{{ email_addr }}</span>
  {% endfor %}
</div>
{% endif %}

{% if web.forms %}
<div class="card">
  <h3>Forms Discovered ({{ web.forms | length }})</h3>
  <table>
    <thead><tr><th>Action</th><th>Method</th><th>Fields</th></tr></thead>
    <tbody>
    {% for form in web.forms %}
    <tr>
      <td><a href="{{ form.action }}">{{ form.action }}</a></td>
      <td><span class="badge badge-blue">{{ form.method }}</span></td>
      <td>{{ form.fields | map(attribute='name') | join(', ') }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
{% endif %}

{% if web.html_comments %}
<div class="card">
  <h3>⚠ HTML Comments ({{ web.html_comments | length }})</h3>
  {% for comment in web.html_comments[:10] %}
    <pre>{{ comment[:300] }}</pre>
  {% endfor %}
</div>
{% endif %}

<div class="grid-2">
  {% if web.robots_txt.disallowed %}
  <div class="card">
    <h3>robots.txt — Disallowed Paths</h3>
    <ul>
      {% for path in web.robots_txt.disallowed %}
      <li>{{ path }}</li>
      {% endfor %}
    </ul>
  </div>
  {% endif %}

  {% if web.sitemap.urls %}
  <div class="card">
    <h3>Sitemap ({{ web.sitemap.url_count }} URLs)</h3>
    <ul>
      {% for u in web.sitemap.urls[:15] %}
      <li><a href="{{ u }}">{{ u }}</a></li>
      {% endfor %}
    </ul>
    {% if web.sitemap.url_count > 15 %}
    <p style="color:var(--muted);font-size:.8rem">...and {{ web.sitemap.url_count - 15 }} more</p>
    {% endif %}
  </div>
  {% endif %}
</div>

<details>
  <summary>All Links ({{ web.links.internal | length }} internal,
           {{ web.links.external | length }} external)</summary>
  <div class="grid-2" style="margin-top:0.5rem">
    <div class="card">
      <h3>Internal ({{ web.links.internal | length }})</h3>
      <ul>
        {% for l in web.links.internal[:30] %}
        <li><a href="{{ l }}">{{ l }}</a></li>
        {% endfor %}
      </ul>
    </div>
    <div class="card">
      <h3>External ({{ web.links.external | length }})</h3>
      <ul>
        {% for l in web.links.external[:30] %}
        <li><a href="{{ l }}">{{ l }}</a></li>
        {% endfor %}
      </ul>
    </div>
  </div>
</details>
{% endif %}

<div class="meta" style="margin-top:3rem; text-align:center;">
  Generated by recon-toolkit · For authorized penetration testing only
</div>
</body>
</html>
"""


# ─── Context builder ──────────────────────────────────────────────────────────

def load_json(path):
    with open(path) as f:
        return json.load(f)


def build_context(input_dir):
    ctx = {
        "target":    "Unknown",
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "modules":   [],
        "summary":   {},
    }

    files = [f for f in os.listdir(input_dir) if f.endswith(".json")
             and "ERROR" not in f and f != "run_metadata.json"]

    for fname in files:
        try:
            data = load_json(os.path.join(input_dir, fname))
        except Exception:
            continue

        module = data.get("module", "")
        target = data.get("target", "")
        if target:
            ctx["target"] = target

        if module == "domain_recon" or fname.startswith("domain_"):
            ctx["domain"] = data
            ctx["modules"].append("Domain Recon")
            ctx["summary"]["subdomains"] = len(data.get("subdomains", []))

        elif module == "email_recon" or fname.startswith("email_"):
            ctx["email"] = data
            ctx["modules"].append("Email Recon")
            ctx["summary"]["emails_found"]  = len(data.get("associated_emails", []))
            ctx["summary"]["breaches"]      = len(data.get("breaches", []))

        elif module == "shodan_wrapper" or fname.startswith("shodan_"):
            ctx["shodan_data"] = data
            ctx["modules"].append("Shodan")
            host = data.get("host", {})
            ctx["summary"]["cves"] = host.get("vulns", [])

        elif module == "port_scanner" or fname.startswith("portscan_"):
            ctx["ports"] = data
            ctx["modules"].append("Port Scanner")
            ctx["summary"]["open_ports"] = data.get("summary", {}).get("open_tcp", 0)

        elif module == "web_scraper" or fname.startswith("web_"):
            ctx["web"] = data
            ctx["modules"].append("Web Scraper")
            s = data.get("summary", {})
            ctx["summary"]["emails_found"]       = s.get("emails_found", 0)
            ctx["summary"]["technologies"]       = s.get("technologies", [])
            ctx["summary"]["missing_sec_headers"] = s.get("missing_security_headers", [])

    return ctx


# ─── Report generator ─────────────────────────────────────────────────────────

def generate_report(input_dir, output_path=None):
    ctx = build_context(input_dir)
    html = Template(REPORT_TEMPLATE).render(**ctx)

    if not output_path:
        safe = ctx["target"].replace("https://","").replace("http://","").replace("/","_")
        output_path = os.path.join(
            input_dir,
            f"REPORT_{safe}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
        )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[✓] Report generated: {output_path}")
    return output_path


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate unified recon HTML report")
    parser.add_argument("--input",  default="results/", help="Directory with JSON result files")
    parser.add_argument("--output", default=None,       help="Output HTML path (optional)")
    args = parser.parse_args()
    generate_report(args.input, args.output)
