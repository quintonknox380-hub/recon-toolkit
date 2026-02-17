#!/usr/bin/env python3
"""
run_all.py — Full Recon Pipeline Runner
Supports: fresh run | --resume | --compare

Usage:
  python run_all.py --domain example.com
  python run_all.py --domain example.com --email admin@example.com --ip 1.2.3.4
  python run_all.py --resume  results/example.com/20260217_120000/
  python run_all.py --compare results/example.com/run_A/ results/example.com/run_B/
  python run_all.py --domain example.com --only domain_recon port_scanner
  python run_all.py --domain example.com --skip shodan_host shodan_search

For authorized penetration testing only.
"""

import argparse
import json
import os
import sys
import time
import traceback
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "modules"))

import domain_recon
import email_recon
import shodan_wrapper
import port_scanner
import web_scraper
import report_generator

# ─── Cosmetics ────────────────────────────────────────────────────────────────

BANNER = f"""
{Fore.CYAN}
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
          RECON TOOLKIT — FULL PIPELINE
{Fore.YELLOW}  ⚠  Authorized penetration testing only  ⚠
{Style.RESET_ALL}"""

SEP       = f"{Fore.CYAN}{'─'*60}{Style.RESET_ALL}"
SEP_GREEN = f"{Fore.GREEN}{'─'*60}{Style.RESET_ALL}"
SEP_YEL   = f"{Fore.YELLOW}{'─'*60}{Style.RESET_ALL}"

ALL_MODULES = [
    "domain_recon", "email_recon", "shodan_host",
    "shodan_search", "port_scanner", "web_scraper",
]

MODULE_PREFIX = {
    "domain_recon":  "domain_",
    "email_recon":   "email_",
    "shodan_host":   "shodan_host_",
    "shodan_search": "shodan_search_",
    "port_scanner":  "portscan_",
    "web_scraper":   "web_",
}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def ts():
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")

def load_config(path="config/config.yaml"):
    import yaml
    with open(path) as f:
        return yaml.safe_load(f)

def save_json(data, directory, filename):
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, filename)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path

def load_json(path):
    with open(path) as f:
        return json.load(f)

def hdr(title, n, total):
    print(f"\n{SEP}\n{Fore.CYAN}[{n}/{total}] {title}{Style.RESET_ALL}\n{SEP}")

def done_line(label, result, elapsed):
    ok = "error" not in (result or {})
    icon = f"{Fore.GREEN}✓" if ok else f"{Fore.RED}✗"
    print(f"\n{icon} {Style.RESET_ALL}{label} ({elapsed:.1f}s)")

def skip_line(name, reason=""):
    r = f" ({reason})" if reason else ""
    print(f"\n{Fore.YELLOW}[--] Skipping {name}{r}{Style.RESET_ALL}")

def confirm(domain, ip, email, url):
    print(f"\n{Fore.YELLOW}╔══════════════════════════════════════╗")
    print(  "║       TARGET CONFIRMATION            ║")
    print(f"╚══════════════════════════════════════╝{Style.RESET_ALL}")
    for label, val in [("Domain", domain), ("IP", ip), ("Email", email), ("URL", url)]:
        print(f"  {label:<8}: {val or 'N/A'}")
    print(f"\n{Fore.RED}  Only proceed with written authorization.{Style.RESET_ALL}\n")
    if input("  Confirm [yes/no]: ").strip().lower() not in ("yes","y"):
        print(f"{Fore.YELLOW}Aborted.{Style.RESET_ALL}")
        sys.exit(0)

# ─── Resume helpers ───────────────────────────────────────────────────────────

def detect_completed(output_dir):
    """Return set of module keys that already have valid JSON output."""
    completed = set()
    files = os.listdir(output_dir)
    for key, prefix in MODULE_PREFIX.items():
        candidates = [f for f in files
                      if f.startswith(prefix) and f.endswith(".json") and "ERROR" not in f]
        for fname in candidates:
            try:
                data = load_json(os.path.join(output_dir, fname))
                if "error" not in data:
                    completed.add(key)
                    break
            except Exception:
                pass
    return completed

def load_meta(output_dir):
    path = os.path.join(output_dir, "run_metadata.json")
    if not os.path.exists(path):
        print(f"{Fore.RED}[-] run_metadata.json not found in {output_dir}{Style.RESET_ALL}")
        sys.exit(1)
    return load_json(path)

def print_resume_table(completed, output_dir):
    print(f"\n{SEP_YEL}")
    print(f"{Fore.YELLOW}  RESUMING FROM: {output_dir}{Style.RESET_ALL}")
    print(SEP_YEL)
    print(f"\n  {'Module':<22} Status")
    print(f"  {'─'*22} {'─'*20}")
    for m in ALL_MODULES:
        if m in completed:
            print(f"  {m:<22} {Fore.GREEN}✓ done — will skip{Style.RESET_ALL}")
        else:
            print(f"  {m:<22} {Fore.YELLOW}✗ pending — will run{Style.RESET_ALL}")
    print()

# ─── Module runners ───────────────────────────────────────────────────────────

def _run_module(key, fn, skip, *fn_args, num=0, total=6, title="", save_as="", out_dir=""):
    if key in skip:
        skip_line(key)
        return None
    hdr(title, num, total)
    t = time.time()
    try:
        result = fn(*fn_args)
        if result is None:
            result = {}
        result["module"] = key
        path = save_json(result, out_dir, save_as)
        done_line(key, result, time.time() - t)
        print(f"  {Fore.BLUE}→ {path}{Style.RESET_ALL}")
        return result
    except Exception as e:
        err = {"module": key, "error": str(e), "trace": traceback.format_exc()}
        print(f"{Fore.RED}[-] {key} failed: {e}{Style.RESET_ALL}")
        save_json(err, out_dir, save_as.replace(".json", "_ERROR.json"))
        return err

def do_domain(domain, config, out, skip):
    if "domain_recon" in skip:
        skip_line("domain_recon"); return None
    hdr("DOMAIN RECONNAISSANCE", 1, 6)
    t = time.time()
    try:
        r = domain_recon.run(domain, config)
        r["module"] = "domain_recon"
        p = save_json(r, out, f"domain_{domain}_{ts()}.json")
        done_line("domain_recon", r, time.time()-t)
        print(f"  {Fore.BLUE}→ {p}{Style.RESET_ALL}")
        return r
    except Exception as e:
        err = {"module":"domain_recon","error":str(e),"trace":traceback.format_exc()}
        print(f"{Fore.RED}[-] domain_recon: {e}{Style.RESET_ALL}")
        save_json(err, out, f"domain_ERROR_{ts()}.json")
        return err

def do_email(email_addr, config, out, skip):
    if "email_recon" in skip:
        skip_line("email_recon"); return None
    if not email_addr:
        skip_line("email_recon","no --email"); return None
    hdr("EMAIL RECONNAISSANCE", 2, 6)
    t = time.time()
    try:
        r = email_recon.run(email_addr, config)
        r["module"] = "email_recon"
        safe = email_addr.replace("@","_at_")
        p = save_json(r, out, f"email_{safe}_{ts()}.json")
        done_line("email_recon", r, time.time()-t)
        print(f"  {Fore.BLUE}→ {p}{Style.RESET_ALL}")
        return r
    except Exception as e:
        err = {"module":"email_recon","error":str(e)}
        print(f"{Fore.RED}[-] email_recon: {e}{Style.RESET_ALL}")
        return err

def do_shodan_host(ip, config, out, skip):
    if "shodan_host" in skip:
        skip_line("shodan_host"); return None
    if not ip:
        skip_line("shodan_host","no --ip"); return None
    hdr("SHODAN HOST LOOKUP", 3, 6)
    t = time.time()
    class A: command="host"
    a=A(); a.ip=ip; a.history=False
    try:
        r = shodan_wrapper.run(a, config)
        r["module"] = "shodan_wrapper"
        p = save_json(r, out, f"shodan_host_{ip}_{ts()}.json")
        done_line("shodan_host", r, time.time()-t)
        print(f"  {Fore.BLUE}→ {p}{Style.RESET_ALL}")
        return r
    except Exception as e:
        err = {"module":"shodan_wrapper","error":str(e)}
        print(f"{Fore.RED}[-] shodan_host: {e}{Style.RESET_ALL}")
        return err

def do_shodan_search(query, config, out, skip):
    if "shodan_search" in skip:
        skip_line("shodan_search"); return None
    if not query:
        skip_line("shodan_search","no --shodan-query"); return None
    hdr("SHODAN SEARCH", 4, 6)
    t = time.time()
    class A: command="search"
    a=A(); a.query=query; a.limit=20
    try:
        r = shodan_wrapper.run(a, config)
        r["module"] = "shodan_wrapper"
        sq = query.replace(" ","_").replace('"',"")[:40]
        p = save_json(r, out, f"shodan_search_{sq}_{ts()}.json")
        done_line("shodan_search", r, time.time()-t)
        print(f"  {Fore.BLUE}→ {p}{Style.RESET_ALL}")
        return r
    except Exception as e:
        err = {"module":"shodan_wrapper","error":str(e)}
        print(f"{Fore.RED}[-] shodan_search: {e}{Style.RESET_ALL}")
        return err

def do_ports(target, ports_arg, config, out, skip, use_nmap, udp, threads, timeout):
    if "port_scanner" in skip:
        skip_line("port_scanner"); return None
    hdr("PORT SCANNER", 5, 6)
    t = time.time()
    try:
        ports = port_scanner.parse_ports(ports_arg)
        r = port_scanner.run(target, ports, config, use_nmap=use_nmap,
                             udp=udp, threads=threads, timeout=timeout)
        r["module"] = "port_scanner"
        safe = target.replace("/","_")
        p = save_json(r, out, f"portscan_{safe}_{ts()}.json")
        done_line("port_scanner", r, time.time()-t)
        print(f"  {Fore.BLUE}→ {p}{Style.RESET_ALL}")
        return r
    except Exception as e:
        err = {"module":"port_scanner","error":str(e)}
        print(f"{Fore.RED}[-] port_scanner: {e}{Style.RESET_ALL}")
        save_json(err, out, f"portscan_ERROR_{ts()}.json")
        return err

def do_web(url, config, out, skip, timeout):
    if "web_scraper" in skip:
        skip_line("web_scraper"); return None
    hdr("WEB SCRAPER & METADATA", 6, 6)
    t = time.time()
    try:
        r = web_scraper.run(url, config, timeout=timeout)
        r["module"] = "web_scraper"
        safe = url.replace("https://","").replace("http://","").replace("/","_")
        p = save_json(r, out, f"web_{safe}_{ts()}.json")
        done_line("web_scraper", r, time.time()-t)
        print(f"  {Fore.BLUE}→ {p}{Style.RESET_ALL}")
        return r
    except Exception as e:
        err = {"module":"web_scraper","error":str(e)}
        print(f"{Fore.RED}[-] web_scraper: {e}{Style.RESET_ALL}")
        save_json(err, out, f"web_ERROR_{ts()}.json")
        return err

# ─── Pipeline summary ─────────────────────────────────────────────────────────

def pipeline_summary(results, report_path, total_time):
    print(f"\n{SEP_GREEN}\n{Fore.GREEN}  PIPELINE COMPLETE{Style.RESET_ALL}\n{SEP_GREEN}")
    print(f"  Total time : {total_time:.1f}s")
    print(f"  Report     : {Fore.GREEN}{report_path}{Style.RESET_ALL}\n")
    print(f"  {'Module':<22} {'Status':<24} Key Finding")
    print(f"  {'─'*22} {'─'*12} {'─'*34}")
    rows = [
        ("domain_recon",  "Domain Recon"),
        ("email_recon",   "Email Recon"),
        ("shodan_host",   "Shodan Host"),
        ("shodan_search", "Shodan Search"),
        ("port_scanner",  "Port Scanner"),
        ("web_scraper",   "Web Scraper"),
    ]
    for key, label in rows:
        r = results.get(key)
        if r is None:
            st = f"{Fore.YELLOW}skipped{Style.RESET_ALL}"; finding=""
        elif "error" in r:
            st = f"{Fore.RED}failed{Style.RESET_ALL}"; finding=str(r["error"])[:40]
        else:
            st = f"{Fore.GREEN}done{Style.RESET_ALL}"
            if key=="domain_recon":    finding=f"{len(r.get('subdomains',[]))} subdomain(s)"
            elif key=="email_recon":   finding=f"{len(r.get('breaches',[]))} breach(es)"
            elif key=="shodan_host":
                h=r.get("host",{}); finding=f"{len(h.get('ports',[]))} ports, {len(h.get('vulns',[]))} CVE(s)"
            elif key=="shodan_search": finding=f"{r.get('search',{}).get('total',0)} match(es)"
            elif key=="port_scanner":
                s=r.get("summary",{}); finding=f"{s.get('open_tcp',0)} TCP, {s.get('open_udp',0)} UDP open"
            elif key=="web_scraper":
                s=r.get("summary",{})
                finding=(f"{s.get('emails_found',0)} emails, "
                         f"{len(s.get('technologies',[]))} techs, "
                         f"{len(s.get('missing_security_headers',[]))} sec issues")
            else: finding=""
        print(f"  {label:<22} {st:<32} {finding}")
    print(f"\n{SEP_GREEN}\n")

# ══════════════════════════════════════════════════════════════════════════════
#  COMPARE MODE
# ══════════════════════════════════════════════════════════════════════════════

def load_run(run_dir):
    """Load all module JSON results + metadata from a run directory."""
    data = {}
    if not os.path.isdir(run_dir):
        print(f"{Fore.RED}[-] Not a directory: {run_dir}{Style.RESET_ALL}"); sys.exit(1)
    for key, prefix in MODULE_PREFIX.items():
        candidates = sorted([
            f for f in os.listdir(run_dir)
            if f.startswith(prefix) and f.endswith(".json") and "ERROR" not in f
        ])
        if candidates:
            try:
                data[key] = load_json(os.path.join(run_dir, candidates[-1]))
            except Exception:
                pass
    meta = os.path.join(run_dir, "run_metadata.json")
    if os.path.exists(meta):
        data["_meta"] = load_json(meta)
    return data

def diff_lists(label, la, lb):
    sa, sb = set(str(x) for x in la), set(str(x) for x in lb)
    return {
        "label": label,
        "added":   sorted(sb - sa),
        "removed": sorted(sa - sb),
        "count_a": len(sa),
        "count_b": len(sb),
    }

def cmp_domain(a, b):
    diffs = [diff_lists("Subdomains", a.get("subdomains",[]), b.get("subdomains",[]))]
    for rt in ["A","MX","NS","TXT"]:
        diffs.append(diff_lists(f"DNS {rt}",
            a.get("dns",{}).get(rt,[]), b.get("dns",{}).get(rt,[])))
    whois_ch = {}
    for fld in ["registrar","expiration_date","org","emails"]:
        va = str(a.get("whois",{}).get(fld,""))
        vb = str(b.get("whois",{}).get(fld,""))
        if va != vb:
            whois_ch[fld] = {"before":va,"after":vb}
    return {"diffs":diffs,"whois_changes":whois_ch}

def cmp_ports(a, b):
    def pmap(d):
        return {p["port"]:p for p in d.get("tcp",[]) if p.get("state")=="open"}
    pa, pb = pmap(a), pmap(b)
    ver_ch = {}
    for p in pa:
        if p in pb:
            va = f"{pa[p].get('product','')} {pa[p].get('version','')}".strip()
            vb = f"{pb[p].get('product','')} {pb[p].get('version','')}".strip()
            if va != vb and (va or vb):
                ver_ch[p] = {"before":va or "unknown","after":vb or "unknown"}
    return {
        "new_open":      sorted(set(pb)-set(pa)),
        "newly_closed":  sorted(set(pa)-set(pb)),
        "version_changes": ver_ch,
        "total_before":  len(pa),
        "total_after":   len(pb),
    }

def cmp_web(a, b):
    diffs = [
        diff_lists("Technologies",
            a.get("technologies",{}).get("detected",[]),
            b.get("technologies",{}).get("detected",[])),
        diff_lists("Emails Found",
            a.get("emails_and_ips",{}).get("emails",[]),
            b.get("emails_and_ips",{}).get("emails",[])),
        diff_lists("Missing Security Headers",
            a.get("headers",{}).get("missing_security_headers",[]),
            b.get("headers",{}).get("missing_security_headers",[])),
        diff_lists("Internal Links",
            a.get("links",{}).get("internal",[]),
            b.get("links",{}).get("internal",[])),
        diff_lists("Forms",
            [f.get("action","") for f in a.get("forms",[])],
            [f.get("action","") for f in b.get("forms",[])]),
    ]
    scalar_ch = {}
    checks = [
        (["metadata","title"],      "Page Title"),
        (["headers","server"],      "Server Header"),
        (["headers","x_powered_by"],"X-Powered-By"),
        (["metadata","generator"],  "Generator"),
    ]
    for path_keys, lbl in checks:
        va, vb = a, b
        for k in path_keys:
            va = va.get(k,{}) if isinstance(va,dict) else ""
            vb = vb.get(k,{}) if isinstance(vb,dict) else ""
        if str(va) != str(vb):
            scalar_ch[lbl] = {"before":str(va),"after":str(vb)}
    return {"diffs":diffs,"scalar_changes":scalar_ch}

def cmp_shodan(a, b):
    ha, hb = a.get("host",{}), b.get("host",{})
    cva, cvb = set(ha.get("vulns",[])), set(hb.get("vulns",[]))
    poa, pob = set(ha.get("ports",[])), set(hb.get("ports",[]))
    return {
        "new_cves":     sorted(cvb-cva),
        "fixed_cves":   sorted(cva-cvb),
        "new_ports":    sorted(pob-poa),
        "closed_ports": sorted(poa-pob),
        "org_change":   ha.get("org") != hb.get("org"),
        "org_before":   ha.get("org",""),
        "org_after":    hb.get("org",""),
    }

def cmp_email(a, b):
    return {
        "breach_diff": diff_lists("Breaches",
            a.get("breaches",[]), b.get("breaches",[])),
        "email_diff":  diff_lists("Associated Emails",
            [e.get("value","") for e in a.get("associated_emails",[])],
            [e.get("value","") for e in b.get("associated_emails",[])]),
    }

def run_compare(dir_a, dir_b, out_dir):
    print(f"\n{SEP}")
    print(f"{Fore.CYAN}  COMPARE MODE{Style.RESET_ALL}")
    print(f"  Run A: {dir_a}")
    print(f"  Run B: {dir_b}")
    print(SEP)

    da = load_run(dir_a)
    db = load_run(dir_b)

    meta_a = da.get("_meta",{})
    meta_b = db.get("_meta",{})
    target = meta_a.get("target_domain") or meta_b.get("target_domain") or "unknown"

    compare = {
        "target":    target,
        "generated": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "run_a":     {"dir":dir_a, "timestamp": meta_a.get("started_at", dir_a)},
        "run_b":     {"dir":dir_b, "timestamp": meta_b.get("started_at", dir_b)},
        "domain":    None,
        "email":     None,
        "shodan":    None,
        "ports":     None,
        "web":       None,
    }

    checks = [
        ("domain_recon",  "domain",  cmp_domain),
        ("email_recon",   "email",   cmp_email),
        ("shodan_host",   "shodan",  cmp_shodan),
        ("port_scanner",  "ports",   cmp_ports),
        ("web_scraper",   "web",     cmp_web),
    ]
    for key, field, fn in checks:
        if key in da and key in db:
            compare[field] = fn(da[key], db[key])
            print(f"{Fore.GREEN}[+] {key} diff complete{Style.RESET_ALL}")
        else:
            missing = []
            if key not in da: missing.append("Run A")
            if key not in db: missing.append("Run B")
            print(f"{Fore.YELLOW}[!] {key} missing in: {', '.join(missing)} — skipping{Style.RESET_ALL}")

    os.makedirs(out_dir, exist_ok=True)
    safe_t = target.replace("/","_")
    stamp  = ts()

    # Save diff JSON
    json_path = os.path.join(out_dir, f"COMPARE_{safe_t}_{stamp}.json")
    with open(json_path,"w") as f:
        json.dump(compare, f, indent=2)
    print(f"{Fore.BLUE}[+] Diff JSON: {json_path}{Style.RESET_ALL}")

    # Render HTML
    html_path = os.path.join(out_dir, f"COMPARE_{safe_t}_{stamp}.html")
    from jinja2 import Template
    html = Template(COMPARE_HTML).render(**compare)
    with open(html_path,"w",encoding="utf-8") as f:
        f.write(html)
    print(f"{Fore.GREEN}[✓] Compare report: {html_path}{Style.RESET_ALL}\n")
    return html_path

# ─── Compare HTML template ────────────────────────────────────────────────────

COMPARE_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Recon Diff — {{ target }}</title>
<style>
:root{--bg:#0d1117;--sur:#161b22;--bdr:#30363d;--tx:#c9d1d9;--mu:#8b949e;
      --bl:#58a6ff;--gr:#3fb950;--re:#f85149;--ye:#d29922;--pu:#bc8cff;--or:#f0883e;}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Segoe UI',system-ui,monospace;background:var(--bg);color:var(--tx);padding:2rem;line-height:1.6;}
h1{color:var(--bl);font-size:1.8rem;margin-bottom:.2rem;}
h2{color:var(--bl);font-size:1.15rem;margin:2rem 0 .7rem;padding-bottom:.4rem;border-bottom:1px solid var(--bdr);}
h3{color:var(--pu);font-size:.95rem;margin:.7rem 0 .4rem;}
.meta{color:var(--mu);font-size:.83rem;margin-bottom:2rem;}
.card{background:var(--sur);border:1px solid var(--bdr);border-radius:8px;padding:1.2rem;margin-bottom:.9rem;}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:1rem;}
.g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:1rem;}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.73rem;font-weight:600;margin:2px;}
.add{background:#3fb95033;color:var(--gr);border:1px solid var(--gr);}
.rem{background:#f8514933;color:var(--re);border:1px solid var(--re);}
.chg{background:#d2992233;color:var(--ye);border:1px solid var(--ye);}
.neu{background:#58a6ff22;color:var(--bl);border:1px solid var(--bl);}
.nc{color:var(--mu);font-style:italic;font-size:.83rem;}
table{width:100%;border-collapse:collapse;font-size:.83rem;}
th{background:#1f2937;color:var(--mu);text-align:left;padding:.45rem .7rem;border-bottom:1px solid var(--bdr);}
td{padding:.38rem .7rem;border-bottom:1px solid #21262d;vertical-align:top;}
tr:hover td{background:#1c2128;}
.ra{color:var(--or);}.rb{color:var(--bl);}
.stat{text-align:center;}
.stat .num{font-size:1.9rem;font-weight:700;}
.stat .lbl{font-size:.78rem;color:var(--mu);}
.dp{color:var(--gr);}.dn{color:var(--re);}.dm{color:var(--mu);}
.timeline{display:flex;align-items:center;gap:1rem;margin:.7rem 0;font-size:.83rem;flex-wrap:wrap;}
.tlbox{background:var(--sur);border:1px solid var(--bdr);border-radius:6px;padding:.5rem 1rem;flex:1;min-width:200px;}
.arr{color:var(--mu);font-size:1.3rem;}
code{background:#0a0d11;padding:1px 5px;border-radius:3px;font-size:.8rem;}
details{margin:.4rem 0;}summary{cursor:pointer;color:var(--bl);padding:.2rem 0;}
.sec{margin-right:.35rem;}
</style>
</head>
<body>

<h1>🔀 Recon Diff Report</h1>
<div class="meta">
  <strong>Target:</strong> {{ target }} &nbsp;|&nbsp;
  <strong>Generated:</strong> {{ generated }}
</div>

<div class="timeline">
  <div class="tlbox"><span class="ra">▶ Run A</span><br>
    <code>{{ run_a.dir }}</code><br>
    <small class="mu">{{ run_a.timestamp }}</small></div>
  <span class="arr">→</span>
  <div class="tlbox"><span class="rb">▶ Run B</span><br>
    <code>{{ run_b.dir }}</code><br>
    <small class="mu">{{ run_b.timestamp }}</small></div>
</div>

{% macro diff_block(diff) %}
<div class="card">
  <h3>{{ diff.label }}
    <small style="color:var(--mu)"> — {{ diff.count_a }} → {{ diff.count_b }}</small>
    {% if diff.count_b > diff.count_a %}<span class="badge add">+{{ diff.count_b - diff.count_a }}</span>
    {% elif diff.count_b < diff.count_a %}<span class="badge rem">-{{ diff.count_a - diff.count_b }}</span>
    {% else %}<span class="badge neu">no change</span>{% endif %}
  </h3>
  {% if diff.added %}
  <div style="margin:.35rem 0"><strong class="dp">New:</strong>
    {% for i in diff.added %}<span class="badge add" title="{{ i }}">{{ i[:70] }}</span>{% endfor %}
  </div>{% endif %}
  {% if diff.removed %}
  <div style="margin:.35rem 0"><strong class="dn">Removed:</strong>
    {% for i in diff.removed %}<span class="badge rem" title="{{ i }}">{{ i[:70] }}</span>{% endfor %}
  </div>{% endif %}
  {% if not diff.added and not diff.removed %}<span class="nc">No changes detected</span>{% endif %}
</div>
{% endmacro %}

{# ── Domain ── #}
{% if domain %}
<h2><span class="sec">🌐</span>Domain Recon Changes</h2>
{% for d in domain.diffs %}{{ diff_block(d) }}{% endfor %}
{% if domain.whois_changes %}
<div class="card"><h3>WHOIS Changes</h3>
<table><thead><tr><th>Field</th><th class="ra">Run A</th><th class="rb">Run B</th></tr></thead><tbody>
{% for fld,ch in domain.whois_changes.items() %}
<tr><td><strong>{{ fld }}</strong></td><td class="ra">{{ ch.before }}</td>
    <td class="rb"><span class="badge chg">{{ ch.after }}</span></td></tr>
{% endfor %}</tbody></table></div>{% endif %}
{% endif %}

{# ── Email ── #}
{% if email %}
<h2><span class="sec">📧</span>Email Recon Changes</h2>
<div class="g2">
  <div class="card"><h3>Breaches</h3>
    {% if email.breach_diff.added %}<strong class="dn">New:</strong><br>
      {% for b in email.breach_diff.added %}<span class="badge rem">{{ b }}</span>{% endfor %}
    {% endif %}
    {% if email.breach_diff.removed %}<strong class="dp">Resolved:</strong><br>
      {% for b in email.breach_diff.removed %}<span class="badge add">{{ b }}</span>{% endfor %}
    {% endif %}
    {% if not email.breach_diff.added and not email.breach_diff.removed %}
      <span class="nc">No breach changes</span>{% endif %}
  </div>
  <div class="card"><h3>Associated Emails</h3>
    {% if email.email_diff.added %}<strong class="dp">New:</strong><br>
      {% for e in email.email_diff.added %}<span class="badge add">{{ e }}</span>{% endfor %}
    {% endif %}
    {% if email.email_diff.removed %}<strong class="dn">Gone:</strong><br>
      {% for e in email.email_diff.removed %}<span class="badge rem">{{ e }}</span>{% endfor %}
    {% endif %}
    {% if not email.email_diff.added and not email.email_diff.removed %}
      <span class="nc">No changes</span>{% endif %}
  </div>
</div>
{% endif %}

{# ── Shodan ── #}
{% if shodan %}
<h2><span class="sec">📡</span>Shodan Changes</h2>
<div class="g2">
  <div class="card"><h3>CVE Changes</h3>
    {% if shodan.new_cves %}<strong class="dn">⚠ New CVEs:</strong><br>
      {% for c in shodan.new_cves %}<span class="badge rem">{{ c }}</span>{% endfor %}{% endif %}
    {% if shodan.fixed_cves %}<strong class="dp">✓ Resolved:</strong><br>
      {% for c in shodan.fixed_cves %}<span class="badge add">{{ c }}</span>{% endfor %}{% endif %}
    {% if not shodan.new_cves and not shodan.fixed_cves %}<span class="nc">No CVE changes</span>{% endif %}
  </div>
  <div class="card"><h3>Port Changes</h3>
    {% if shodan.new_ports %}<strong class="dn">Newly open:</strong><br>
      {% for p in shodan.new_ports %}<span class="badge rem">{{ p }}</span>{% endfor %}{% endif %}
    {% if shodan.closed_ports %}<strong class="dp">Closed:</strong><br>
      {% for p in shodan.closed_ports %}<span class="badge add">{{ p }}</span>{% endfor %}{% endif %}
    {% if not shodan.new_ports and not shodan.closed_ports %}<span class="nc">No port changes</span>{% endif %}
  </div>
</div>
{% if shodan.org_change %}
<div class="card"><h3>Organisation Change <span class="badge chg">changed</span></h3>
<table><thead><tr><th>Run A</th><th>Run B</th></tr></thead>
<tbody><tr><td class="ra">{{ shodan.org_before }}</td>
           <td class="rb">{{ shodan.org_after }}</td></tr></tbody></table></div>{% endif %}
{% endif %}

{# ── Ports ── #}
{% if ports %}
<h2><span class="sec">🔌</span>Port Scan Changes</h2>
<div class="g3">
  <div class="card stat">
    <div class="num dn">{{ ports.new_open | length }}</div>
    <div class="lbl">Newly Open Ports</div>
  </div>
  <div class="card stat">
    <div class="num dp">{{ ports.newly_closed | length }}</div>
    <div class="lbl">Newly Closed Ports</div>
  </div>
  <div class="card stat">
    <div class="num" style="color:var(--ye)">{{ ports.version_changes | length }}</div>
    <div class="lbl">Version Changes</div>
  </div>
</div>
{% if ports.new_open %}
<div class="card"><h3>⚠ Newly Open Ports <span class="badge rem">attention</span></h3>
{% for p in ports.new_open %}<span class="badge rem">{{ p }}/tcp</span>{% endfor %}</div>{% endif %}
{% if ports.newly_closed %}
<div class="card"><h3>✓ Newly Closed Ports</h3>
{% for p in ports.newly_closed %}<span class="badge add">{{ p }}/tcp</span>{% endfor %}</div>{% endif %}
{% if ports.version_changes %}
<div class="card"><h3>Service Version Changes</h3>
<table><thead><tr><th>Port</th><th class="ra">Run A</th><th class="rb">Run B</th></tr></thead><tbody>
{% for port, ch in ports.version_changes.items() %}
<tr><td><strong>{{ port }}/tcp</strong></td>
    <td class="ra">{{ ch.before }}</td>
    <td class="rb"><span class="badge chg">{{ ch.after }}</span></td></tr>
{% endfor %}</tbody></table></div>{% endif %}
{% endif %}

{# ── Web ── #}
{% if web %}
<h2><span class="sec">🕸</span>Web Scraper Changes</h2>
{% if web.scalar_changes %}
<div class="card"><h3>Page / Server Changes</h3>
<table><thead><tr><th>Field</th><th class="ra">Run A</th><th class="rb">Run B</th></tr></thead><tbody>
{% for fld, ch in web.scalar_changes.items() %}
<tr><td><strong>{{ fld }}</strong></td>
    <td class="ra">{{ ch.before }}</td>
    <td class="rb"><span class="badge chg">{{ ch.after }}</span></td></tr>
{% endfor %}</tbody></table></div>{% endif %}
{% for d in web.diffs %}{{ diff_block(d) }}{% endfor %}
{% endif %}

<div class="meta" style="margin-top:3rem;text-align:center">
  recon-toolkit · For authorized penetration testing only
</div>
</body></html>
"""

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="run_all.py — Recon Pipeline | Authorized testing only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  Fresh run:  python run_all.py --domain example.com [options]
  Resume:     python run_all.py --resume  results/example.com/20260217_120000/
  Compare:    python run_all.py --compare results/example.com/run_A/ results/example.com/run_B/

Port presets: web | remote | mail | database | dns | ftp | smb | top100
        """
    )

    m = parser.add_argument_group("Mode")
    m.add_argument("--resume",  metavar="RUN_DIR",
                   help="Resume an incomplete run from its results directory")
    m.add_argument("--compare", metavar="RUN_DIR", nargs=2,
                   help="Diff two run dirs: --compare <run_A> <run_B>")

    t = parser.add_argument_group("Target (required for fresh run)")
    t.add_argument("--domain",       default=None)
    t.add_argument("--ip",           default=None)
    t.add_argument("--email",        default=None)
    t.add_argument("--url",          default=None)
    t.add_argument("--shodan-query", default=None, dest="shodan_query")

    mod = parser.add_argument_group("Module control")
    mod.add_argument("--skip", nargs="+", default=[], choices=ALL_MODULES, metavar="MODULE",
                     help=f"Modules to skip. Options: {', '.join(ALL_MODULES)}")
    mod.add_argument("--only", nargs="+", default=[], choices=ALL_MODULES, metavar="MODULE",
                     help="Run only these modules (overrides --skip)")

    sc = parser.add_argument_group("Scanner options")
    sc.add_argument("--ports",   default="top100")
    sc.add_argument("--threads", type=int,   default=100)
    sc.add_argument("--timeout", type=float, default=2.0)
    sc.add_argument("--udp",     action="store_true")
    sc.add_argument("--no-nmap", action="store_true", dest="no_nmap")

    o = parser.add_argument_group("Output")
    o.add_argument("--output", default=None,
                   help="Output dir (default: results/<domain>/<timestamp>/)")
    o.add_argument("--config", default="config/config.yaml")
    o.add_argument("--yes",    action="store_true", help="Skip confirmation prompt")

    args = parser.parse_args()

    # ── COMPARE ───────────────────────────────────────────────────────────────
    if args.compare:
        dir_a, dir_b = args.compare
        # Infer a sensible output location beside run B
        out_dir = args.output or os.path.dirname(os.path.abspath(dir_b))
        run_compare(dir_a, dir_b, out_dir)
        sys.exit(0)

    # ── RESUME ────────────────────────────────────────────────────────────────
    if args.resume:
        resume_dir = args.resume.rstrip("/\\")
        if not os.path.isdir(resume_dir):
            print(f"{Fore.RED}[-] Directory not found: {resume_dir}{Style.RESET_ALL}")
            sys.exit(1)
        meta = load_meta(resume_dir)
        completed = detect_completed(resume_dir)
        print_resume_table(completed, resume_dir)

        # Restore original target params from saved metadata
        args.domain       = meta.get("target_domain",  args.domain)
        args.ip           = meta.get("target_ip",      args.ip)
        args.email        = meta.get("target_email",   args.email)
        args.url          = meta.get("target_url",     args.url)
        args.shodan_query = meta.get("shodan_query",   args.shodan_query)
        args.ports        = meta.get("ports",          args.ports)
        output_dir        = resume_dir
        skip = list(set(list(args.skip) + list(completed)))
        print(f"{Fore.CYAN}[*] Picking up from where we left off...\n"
              f"    Completed already: {', '.join(completed) or 'none'}{Style.RESET_ALL}")
    else:
        # ── FRESH RUN ─────────────────────────────────────────────────────────
        if not args.domain:
            parser.error("--domain is required for a fresh run "
                         "(or use --resume / --compare)")
        skip = ([m for m in ALL_MODULES if m not in args.only]
                if args.only else list(args.skip))
        output_dir = args.output or os.path.join(
            "results", args.domain, datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        )
        os.makedirs(output_dir, exist_ok=True)

    target_url = args.url or f"https://{args.domain}"

    # ── Config ────────────────────────────────────────────────────────────────
    try:
        config = load_config(args.config)
    except FileNotFoundError:
        print(f"{Fore.RED}[-] Config not found: {args.config}\n"
              f"    Copy config/config.yaml.example → config/config.yaml{Style.RESET_ALL}")
        sys.exit(1)

    # ── Confirm ───────────────────────────────────────────────────────────────
    if not args.yes:
        confirm(args.domain, args.ip, args.email, target_url)

    # ── Save run metadata ─────────────────────────────────────────────────────
    meta_data = {
        "run_id":        ts(),
        "target_domain": args.domain,
        "target_ip":     args.ip,
        "target_email":  args.email,
        "target_url":    target_url,
        "shodan_query":  args.shodan_query,
        "ports":         args.ports,
        "skip":          skip,
        "output_dir":    output_dir,
        "started_at":    datetime.utcnow().isoformat(),
        "resumed":       bool(args.resume),
    }
    save_json(meta_data, output_dir, "run_metadata.json")

    # ── Pipeline ──────────────────────────────────────────────────────────────
    t0 = time.time()
    results = {}

    results["domain_recon"]  = do_domain(args.domain, config, output_dir, skip)
    results["email_recon"]   = do_email(args.email, config, output_dir, skip)
    results["shodan_host"]   = do_shodan_host(args.ip, config, output_dir, skip)
    results["shodan_search"] = do_shodan_search(args.shodan_query, config, output_dir, skip)
    results["port_scanner"]  = do_ports(
        args.domain, args.ports, config, output_dir, skip,
        use_nmap=not args.no_nmap, udp=args.udp,
        threads=args.threads, timeout=args.timeout,
    )
    results["web_scraper"]   = do_web(target_url, config, output_dir, skip, timeout=10)

    # ── Generate report ───────────────────────────────────────────────────────
    print(f"\n{SEP}\n{Fore.CYAN}  GENERATING HTML REPORT{Style.RESET_ALL}\n{SEP}")
    safe_d = args.domain.replace("/","_")
    report_path = os.path.join(output_dir, f"REPORT_{safe_d}_{ts()}.html")
    try:
        report_generator.generate_report(output_dir, report_path)
    except Exception as e:
        print(f"{Fore.RED}[-] Report failed: {e}{Style.RESET_ALL}")
        report_path = "N/A"

    meta_data["completed_at"] = datetime.utcnow().isoformat()
    meta_data["report"]       = report_path
    save_json(meta_data, output_dir, "run_metadata.json")

    pipeline_summary(results, report_path, time.time()-t0)


if __name__ == "__main__":
    main()
