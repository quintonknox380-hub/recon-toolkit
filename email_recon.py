"""
email_recon.py — Email Reconnaissance Module
For authorized penetration testing only.
"""

import requests
import json
import argparse
import yaml
import os
import time
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

def load_config(config_path="config/config.yaml"):
    with open(config_path) as f:
        return yaml.safe_load(f)

def validate_email_format(email):
    """Basic format check."""
    return "@" in email and "." in email.split("@")[-1]

def hibp_check(email, api_key, delay=1.5):
    """Check email against HaveIBeenPwned breach database."""
    print(f"{Fore.CYAN}[*] Checking breaches for {email}...")
    if not api_key or api_key == "YOUR_HIBP_API_KEY":
        print(f"{Fore.YELLOW}[!] HIBP API key not set, skipping.")
        return []

    headers = {
        "hibp-api-key": api_key,
        "user-agent": "ReconToolkit-EthicalHacking"
    }
    time.sleep(delay)
    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            breaches = [b["Name"] for b in r.json()]
            print(f"{Fore.RED}[!] Found in {len(breaches)} breach(es): {breaches}")
            return breaches
        elif r.status_code == 404:
            print(f"{Fore.GREEN}[+] Not found in any known breaches.")
            return []
        else:
            print(f"{Fore.YELLOW}[!] HIBP returned status {r.status_code}")
            return []
    except Exception as e:
        print(f"{Fore.RED}[-] HIBP error: {e}")
        return []

def emailrep_check(email, api_key, delay=1.5):
    """Check email reputation via EmailRep.io."""
    print(f"{Fore.CYAN}[*] Checking email reputation for {email}...")
    time.sleep(delay)
    try:
        headers = {"Key": api_key} if api_key and api_key != "YOUR_EMAILREP_API_KEY" else {}
        r = requests.get(f"https://emailrep.io/{email}", headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            print(f"{Fore.GREEN}[+] Reputation: {data.get('reputation','unknown')} | Suspicious: {data.get('suspicious')}")
            return data
        else:
            print(f"{Fore.YELLOW}[!] EmailRep returned {r.status_code}")
            return {}
    except Exception as e:
        print(f"{Fore.RED}[-] EmailRep error: {e}")
        return {}

def hunter_domain_search(domain, api_key, delay=1.5):
    """Search for emails associated with a domain via Hunter.io."""
    print(f"{Fore.CYAN}[*] Searching Hunter.io for emails at {domain}...")
    if not api_key or api_key == "YOUR_HUNTER_IO_API_KEY":
        print(f"{Fore.YELLOW}[!] Hunter.io API key not set, skipping.")
        return []

    time.sleep(delay)
    try:
        url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            emails = r.json().get("data", {}).get("emails", [])
            print(f"{Fore.GREEN}[+] Found {len(emails)} email(s) via Hunter.io")
            for e in emails:
                print(f"    {Fore.GREEN}→ {e['value']} ({e.get('type','unknown')})")
            return emails
        else:
            print(f"{Fore.YELLOW}[!] Hunter.io returned {r.status_code}")
            return []
    except Exception as e:
        print(f"{Fore.RED}[-] Hunter.io error: {e}")
        return []

def run(email, config):
    if not validate_email_format(email):
        print(f"{Fore.RED}[-] Invalid email format.")
        return {}

    delay = config["settings"].get("rate_limit_delay", 1.5)
    domain = email.split("@")[1]

    results = {
        "target": email,
        "domain": domain,
        "timestamp": datetime.utcnow().isoformat(),
        "breaches": hibp_check(email, config["api_keys"]["hibp"], delay),
        "reputation": emailrep_check(email, config["api_keys"]["emailrep"], delay),
        "associated_emails": hunter_domain_search(domain, config["api_keys"]["hunter"], delay),
    }
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Email Recon Module")
    parser.add_argument("--email", required=True, help="Target email (authorized targets only)")
    parser.add_argument("--output", default="results/", help="Output directory")
    parser.add_argument("--config", default="config/config.yaml")
    args = parser.parse_args()

    config = load_config(args.config)
    results = run(args.email, config)

    os.makedirs(args.output, exist_ok=True)
    safe_email = args.email.replace("@", "_at_")
    out_file = os.path.join(args.output, f"email_{safe_email}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json")
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n{Fore.GREEN}[✓] Results saved to {out_file}")
