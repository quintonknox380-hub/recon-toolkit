"""
shodan_wrapper.py — Shodan CLI Wrapper Module
Commands: host | search | dns | exploits | info
For authorized penetration testing only.
"""

import shodan
import json, argparse, yaml, os
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

def load_config(config_path="config/config.yaml"):
    with open(config_path) as f:
        return yaml.safe_load(f)

def get_api(api_key):
    if not api_key or api_key == "YOUR_SHODAN_API_KEY":
        raise ValueError("Shodan API key not configured.")
    return shodan.Shodan(api_key)


# ── Host Lookup ────────────────────────────────────────────────────────────────
def host_lookup(ip, api_key, history=False):
    """Full host info: ports, services, CVEs, location."""
    print(f"{Fore.CYAN}[*] Host lookup: {ip}")
    try:
        api = get_api(api_key)
        host = api.host(ip, history=history)
        result = {
            "ip": host["ip_str"],
            "org": host.get("org", "N/A"),
            "isp": host.get("isp", "N/A"),
            "asn": host.get("asn", "N/A"),
            "country": host.get("country_name", "N/A"),
            "city": host.get("city", "N/A"),
            "hostnames": host.get("hostnames", []),
            "tags": host.get("tags", []),
            "vulns": list(host.get("vulns", {}).keys()),
            "ports": host.get("ports", []),
            "services": [],
        }
        for item in host.get("data", []):
            svc = {
                "port": item["port"],
                "transport": item.get("transport", "tcp"),
                "product": item.get("product", ""),
                "version": item.get("version", ""),
                "banner": item.get("data", "")[:300],
                "cpe": item.get("cpe", []),
            }
            result["services"].append(svc)
            print(f"{Fore.GREEN}  [+] {svc['port']}/{svc['transport']} — "
                  f"{svc['product']} {svc['version']}")
        if result["vulns"]:
            print(f"{Fore.RED}  [!] CVEs: {result['vulns']}")
        return result
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {e}")
        return {"error": str(e)}


# ── DNS Resolution ─────────────────────────────────────────────────────────────
def dns_resolve(hostnames, api_key):
    print(f"{Fore.CYAN}[*] Resolving hostnames via Shodan...")
    try:
        api = get_api(api_key)
        resolved = api.dns.resolve(hostnames)
        for h, ip in resolved.items():
            print(f"{Fore.GREEN}  [+] {h} → {ip}")
        return resolved
    except Exception as e:
        print(f"{Fore.RED}[-] {e}")
        return {}

def reverse_dns(ips, api_key):
    print(f"{Fore.CYAN}[*] Reverse DNS via Shodan...")
    try:
        api = get_api(api_key)
        results = api.dns.reverse(ips)
        for ip, names in results.items():
            print(f"{Fore.GREEN}  [+] {ip} → {names}")
        return results
    except Exception as e:
        print(f"{Fore.RED}[-] {e}")
        return {}


# ── Search ─────────────────────────────────────────────────────────────────────
def search(query, api_key, max_results=20):
    """Search Shodan with a dork query. e.g. 'hostname:example.com port:22'"""
    print(f"{Fore.CYAN}[*] Shodan search: \"{query}\"")
    try:
        api = get_api(api_key)
        results = api.search(query, limit=max_results)
        matches = []
        for m in results["matches"]:
            entry = {
                "ip": m["ip_str"], "port": m["port"],
                "org": m.get("org", "N/A"),
                "hostnames": m.get("hostnames", []),
                "country": m.get("location", {}).get("country_name", "N/A"),
                "product": m.get("product", ""),
                "version": m.get("version", ""),
                "banner": m.get("data", "")[:200],
            }
            matches.append(entry)
            print(f"  {Fore.GREEN}→ {entry['ip']}:{entry['port']} "
                  f"[{entry['org']}] {entry['product']} {entry['version']}")
        return {"query": query, "total": results["total"], "matches": matches}
    except Exception as e:
        print(f"{Fore.RED}[-] {e}")
        return {"error": str(e)}


# ── Exploit Search ─────────────────────────────────────────────────────────────
def exploit_search(query, api_key, max_results=10):
    """Search Shodan Exploits DB. e.g. 'CVE-2021-44228' or 'apache 2.4'"""
    print(f"{Fore.CYAN}[*] Exploit search: \"{query}\"")
    try:
        api = get_api(api_key)
        results = api.exploits.search(query)
        exploits = []
        for m in results.get("matches", [])[:max_results]:
            entry = {
                "id": m.get("id", ""), "type": m.get("type", ""),
                "description": m.get("description", "")[:300],
                "platform": m.get("platform", ""),
                "cve": m.get("cve", []),
                "source": m.get("source", ""),
                "date": m.get("date", ""),
            }
            exploits.append(entry)
            print(f"  {Fore.RED}→ [{entry['type']}] {entry['description'][:80]}...")
        return {"query": query, "total": results.get("total", 0), "exploits": exploits}
    except Exception as e:
        print(f"{Fore.RED}[-] {e}")
        return {"error": str(e)}


# ── Account Info ───────────────────────────────────────────────────────────────
def account_info(api_key):
    print(f"{Fore.CYAN}[*] Fetching account info...")
    try:
        api = get_api(api_key)
        info = api.info()
        print(f"{Fore.GREEN}[+] Plan: {info.get('plan')} | "
              f"Query credits: {info.get('query_credits')} | "
              f"Scan credits: {info.get('scan_credits')}")
        return info
    except Exception as e:
        print(f"{Fore.RED}[-] {e}")
        return {}


# ── Run ────────────────────────────────────────────────────────────────────────
def run(args, config):
    api_key = config["api_keys"]["shodan"]
    results = {"module": "shodan_wrapper", "timestamp": datetime.utcnow().isoformat()}

    if args.command == "host":
        results["target"] = args.ip
        results["host"] = host_lookup(args.ip, api_key, getattr(args, "history", False))
    elif args.command == "search":
        results["target"] = args.query
        results["search"] = search(args.query, api_key, getattr(args, "limit", 20))
    elif args.command == "dns":
        results["target"] = args.hostname
        resolved = dns_resolve([args.hostname], api_key)
        results["resolved"] = resolved
        ips = list(resolved.values())
        if ips:
            results["reverse"] = reverse_dns(ips, api_key)
    elif args.command == "exploits":
        results["target"] = args.query
        results["exploits"] = exploit_search(args.query, api_key, getattr(args, "limit", 10))
    elif args.command == "info":
        results["account"] = account_info(api_key)

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Shodan CLI Wrapper — Authorized testing only")
    parser.add_argument("--config", default="config/config.yaml")
    parser.add_argument("--output", default="results/")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("host");    p.add_argument("ip");          p.add_argument("--history", action="store_true")
    p = sub.add_parser("search");  p.add_argument("query");       p.add_argument("--limit", type=int, default=20)
    p = sub.add_parser("dns");     p.add_argument("hostname")
    p = sub.add_parser("exploits"); p.add_argument("query");      p.add_argument("--limit", type=int, default=10)
    sub.add_parser("info")

    args = parser.parse_args()
    config = load_config(args.config)
    results = run(args, config)

    os.makedirs(args.output, exist_ok=True)
    safe = str(results.get("target", "output")).replace("/", "_").replace(" ", "_")
    out = os.path.join(args.output, f"shodan_{args.command}_{safe}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json")
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n{Fore.GREEN}[✓] Saved to {out}")
