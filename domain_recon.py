"""
domain_recon.py — Domain & DNS Reconnaissance Module
For authorized penetration testing only.
"""

import whois
import dns.resolver
import requests
import shodan
import json
import argparse
import yaml
import os
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

def load_config(config_path="config/config.yaml"):
    with open(config_path) as f:
        return yaml.safe_load(f)

def whois_lookup(domain):
    """Perform WHOIS lookup on a domain."""
    print(f"{Fore.CYAN}[*] Running WHOIS lookup for {domain}...")
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "emails": w.emails,
            "org": w.org,
        }
    except Exception as e:
        print(f"{Fore.RED}[-] WHOIS failed: {e}")
        return {}

def dns_enum(domain):
    """Enumerate DNS records."""
    print(f"{Fore.CYAN}[*] Enumerating DNS records for {domain}...")
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]
    results = {}
    resolver = dns.resolver.Resolver()

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            results[rtype] = [str(r) for r in answers]
            print(f"{Fore.GREEN}[+] {rtype}: {results[rtype]}")
        except Exception:
            results[rtype] = []

    return results

def subdomain_enum(domain, wordlist="wordlists/subdomains.txt"):
    """Brute-force subdomains from a wordlist."""
    print(f"{Fore.CYAN}[*] Enumerating subdomains for {domain}...")
    found = []

    if not os.path.exists(wordlist):
        print(f"{Fore.YELLOW}[!] Wordlist not found at {wordlist}, skipping.")
        return found

    with open(wordlist) as f:
        subdomains = [line.strip() for line in f if line.strip()]

    resolver = dns.resolver.Resolver()
    for sub in subdomains:
        fqdn = f"{sub}.{domain}"
        try:
            resolver.resolve(fqdn, "A")
            print(f"{Fore.GREEN}[+] Found: {fqdn}")
            found.append(fqdn)
        except Exception:
            pass

    return found

def shodan_lookup(domain, api_key):
    """Query Shodan for hosts related to domain."""
    print(f"{Fore.CYAN}[*] Querying Shodan for {domain}...")
    if not api_key or api_key == "YOUR_SHODAN_API_KEY":
        print(f"{Fore.YELLOW}[!] Shodan API key not configured, skipping.")
        return []

    try:
        api = shodan.Shodan(api_key)
        results = api.search(f"hostname:{domain}")
        hosts = []
        for match in results["matches"]:
            hosts.append({
                "ip": match["ip_str"],
                "port": match["port"],
                "org": match.get("org", "N/A"),
                "os": match.get("os", "N/A"),
            })
            print(f"{Fore.GREEN}[+] {match['ip_str']}:{match['port']} — {match.get('org','N/A')}")
        return hosts
    except Exception as e:
        print(f"{Fore.RED}[-] Shodan error: {e}")
        return []

def run(domain, config):
    results = {
        "target": domain,
        "timestamp": datetime.utcnow().isoformat(),
        "whois": whois_lookup(domain),
        "dns": dns_enum(domain),
        "subdomains": subdomain_enum(domain),
        "shodan": shodan_lookup(domain, config["api_keys"]["shodan"]),
    }
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Domain Recon Module")
    parser.add_argument("--domain", required=True, help="Target domain (authorized targets only)")
    parser.add_argument("--output", default="results/", help="Output directory")
    parser.add_argument("--config", default="config/config.yaml")
    args = parser.parse_args()

    config = load_config(args.config)
    results = run(args.domain, config)

    os.makedirs(args.output, exist_ok=True)
    out_file = os.path.join(args.output, f"domain_{args.domain}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json")
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n{Fore.GREEN}[✓] Results saved to {out_file}")
