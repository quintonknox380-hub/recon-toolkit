"""
web_scraper.py — Web Scraping & Metadata Extraction Module
Extracts: headers, tech stack, links, emails, metadata, comments, robots.txt,
          sitemap, JS files, forms, cookies, and EXIF from images.
For authorized penetration testing only.
"""

import requests
import json
import argparse
import yaml
import os
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style, init

init(autoreset=True)

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    print(f"{Fore.YELLOW}[!] beautifulsoup4 not installed. Run: pip install beautifulsoup4 lxml")

try:
    import builtwith
    BUILTWITH_AVAILABLE = True
except ImportError:
    BUILTWITH_AVAILABLE = False

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; ReconBot/1.0; +https://github.com/YOUR_USERNAME/recon-toolkit)",
}

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
COMMENT_REGEX = re.compile(r"<!--(.*?)-->", re.DOTALL)
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def load_config(config_path="config/config.yaml"):
    with open(config_path) as f:
        return yaml.safe_load(f)


def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


# ── HTTP Headers ──────────────────────────────────────────────────────────────
def get_headers(url, timeout=10):
    """Fetch and analyse HTTP response headers for security posture."""
    print(f"{Fore.CYAN}[*] Fetching headers: {url}")
    try:
        r = requests.head(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
        headers = dict(r.headers)

        security_headers = {
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
            "Referrer-Policy": headers.get("Referrer-Policy"),
            "Permissions-Policy": headers.get("Permissions-Policy"),
        }
        missing = [k for k, v in security_headers.items() if not v]
        if missing:
            print(f"  {Fore.YELLOW}[!] Missing security headers: {missing}")

        server = headers.get("Server", "")
        x_powered_by = headers.get("X-Powered-By", "")
        if server:
            print(f"  {Fore.GREEN}[+] Server: {server}")
        if x_powered_by:
            print(f"  {Fore.GREEN}[+] X-Powered-By: {x_powered_by}")

        return {
            "status_code": r.status_code,
            "final_url": r.url,
            "all_headers": headers,
            "security_headers": security_headers,
            "missing_security_headers": missing,
            "server": server,
            "x_powered_by": x_powered_by,
        }
    except Exception as e:
        print(f"{Fore.RED}[-] Header fetch failed: {e}")
        return {"error": str(e)}


# ── Technology Detection ───────────────────────────────────────────────────────
def detect_technologies(url, html_content="", headers=None):
    """Detect CMS, frameworks, analytics, CDN, etc."""
    print(f"{Fore.CYAN}[*] Detecting technologies...")
    tech = {}

    if BUILTWITH_AVAILABLE:
        try:
            tech["builtwith"] = builtwith.parse(url)
        except Exception:
            pass

    # Heuristic detection from HTML + headers
    signatures = {
        "WordPress": ["/wp-content/", "/wp-includes/", 'name="generator" content="WordPress'],
        "Drupal": ["/sites/default/files/", "Drupal.settings", "X-Generator: Drupal"],
        "Joomla": ["/components/com_", "Joomla!"],
        "Django": ["csrfmiddlewaretoken", "__django"],
        "Laravel": ["laravel_session", "XSRF-TOKEN"],
        "React": ["__NEXT_DATA__", "react-dom", "_reactFiber"],
        "Angular": ["ng-version", "ng-app", "__ng_app"],
        "Vue.js": ["__vue__", "data-v-"],
        "jQuery": ["jquery.min.js", "jquery-"],
        "Bootstrap": ["bootstrap.min.css", "bootstrap.min.js"],
        "Cloudflare": ["__cfduid", "CF-RAY", "cloudflare"],
        "Google Analytics": ["google-analytics.com/analytics.js", "gtag/js"],
        "nginx": ["nginx"],
        "Apache": ["Apache"],
    }

    combined = html_content + json.dumps(headers or {})
    detected = []
    for tech_name, patterns in signatures.items():
        if any(p.lower() in combined.lower() for p in patterns):
            detected.append(tech_name)
            print(f"  {Fore.GREEN}[+] Detected: {tech_name}")

    tech["detected"] = detected
    return tech


# ── Page Metadata ──────────────────────────────────────────────────────────────
def extract_metadata(soup, url):
    """Extract meta tags, title, description, OG tags, schema.org, etc."""
    print(f"{Fore.CYAN}[*] Extracting page metadata...")
    meta = {
        "title": "",
        "description": "",
        "keywords": "",
        "og_tags": {},
        "twitter_tags": {},
        "generator": "",
        "author": "",
        "canonical": "",
    }

    if not soup:
        return meta

    title = soup.find("title")
    meta["title"] = title.get_text(strip=True) if title else ""

    for tag in soup.find_all("meta"):
        name = (tag.get("name") or tag.get("property") or "").lower()
        content = tag.get("content", "")
        if name == "description":
            meta["description"] = content
        elif name == "keywords":
            meta["keywords"] = content
        elif name == "generator":
            meta["generator"] = content
        elif name == "author":
            meta["author"] = content
        elif name.startswith("og:"):
            meta["og_tags"][name] = content
        elif name.startswith("twitter:"):
            meta["twitter_tags"][name] = content

    canonical = soup.find("link", rel="canonical")
    meta["canonical"] = canonical.get("href", "") if canonical else ""

    print(f"  {Fore.GREEN}[+] Title: {meta['title'][:60]}")
    if meta["generator"]:
        print(f"  {Fore.GREEN}[+] Generator: {meta['generator']}")
    return meta


# ── Link & Asset Extraction ────────────────────────────────────────────────────
def extract_links(soup, base_url):
    """Extract all internal and external links."""
    print(f"{Fore.CYAN}[*] Extracting links...")
    base_domain = urlparse(base_url).netloc
    internal, external, resources = [], [], {}

    if not soup:
        return {"internal": [], "external": [], "resources": {}}

    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if href.startswith(("mailto:", "javascript:", "#", "tel:")):
            continue
        full = urljoin(base_url, href)
        domain = urlparse(full).netloc
        if base_domain in domain:
            internal.append(full)
        else:
            external.append(full)

    # JS, CSS, images
    resources["js"] = list(set(
        urljoin(base_url, tag["src"]) for tag in soup.find_all("script", src=True)
    ))
    resources["css"] = list(set(
        urljoin(base_url, tag["href"]) for tag in soup.find_all("link", rel="stylesheet")
    ))
    resources["images"] = list(set(
        urljoin(base_url, tag["src"]) for tag in soup.find_all("img", src=True)
    ))

    print(f"  {Fore.GREEN}[+] Internal: {len(internal)} | External: {len(external)} | "
          f"JS: {len(resources['js'])} | CSS: {len(resources['css'])}")

    return {
        "internal": list(set(internal))[:100],
        "external": list(set(external))[:100],
        "resources": resources,
    }


# ── Email & IP Extraction ─────────────────────────────────────────────────────
def extract_emails_and_ips(html):
    """Regex extraction of email addresses and IPs from page source."""
    emails = list(set(EMAIL_REGEX.findall(html)))
    ips = list(set(IP_REGEX.findall(html)))
    # Filter out version numbers that look like IPs
    ips = [ip for ip in ips if not ip.startswith(("0.", "255.", "127."))]
    if emails:
        print(f"  {Fore.GREEN}[+] Emails found: {emails}")
    if ips:
        print(f"  {Fore.GREEN}[+] IPs found: {ips}")
    return {"emails": emails, "ips": ips}


# ── HTML Comments ─────────────────────────────────────────────────────────────
def extract_comments(html):
    """Extract HTML comments — often contain debug info, credentials, TODOs."""
    comments = [c.strip() for c in COMMENT_REGEX.findall(html) if c.strip()]
    if comments:
        print(f"  {Fore.YELLOW}[!] {len(comments)} HTML comment(s) found:")
        for c in comments[:5]:
            print(f"      {c[:100]}")
    return comments[:50]


# ── Forms ─────────────────────────────────────────────────────────────────────
def extract_forms(soup, base_url):
    """Extract forms, input fields, and actions — useful for auth/login discovery."""
    print(f"{Fore.CYAN}[*] Extracting forms...")
    forms = []
    if not soup:
        return forms

    for form in soup.find_all("form"):
        fields = []
        for inp in form.find_all(["input", "textarea", "select"]):
            fields.append({
                "name": inp.get("name", ""),
                "type": inp.get("type", "text"),
                "id": inp.get("id", ""),
                "placeholder": inp.get("placeholder", ""),
            })
        action = form.get("action", "")
        forms.append({
            "action": urljoin(base_url, action) if action else base_url,
            "method": form.get("method", "GET").upper(),
            "fields": fields,
            "field_count": len(fields),
        })
        print(f"  {Fore.GREEN}[+] Form → {forms[-1]['action']} [{forms[-1]['method']}] "
              f"({len(fields)} fields)")
    return forms


# ── Cookies ───────────────────────────────────────────────────────────────────
def analyse_cookies(response):
    """Analyse cookies for security flags (HttpOnly, Secure, SameSite)."""
    print(f"{Fore.CYAN}[*] Analysing cookies...")
    cookies = []
    for name, value in response.cookies.items():
        c = response.cookies.get_dict()
        cookie_obj = response.cookies._cookies
        flags = {}
        try:
            for domain in cookie_obj.values():
                for path in domain.values():
                    if name in path:
                        morsel = path[name]
                        flags = {
                            "httponly": morsel.has_nonstandard_attr("httponly"),
                            "secure": bool(morsel["secure"]),
                            "samesite": morsel.get("samesite", ""),
                            "expires": morsel["expires"],
                        }
        except Exception:
            pass
        cookies.append({"name": name, "value": value[:50], "flags": flags})
        issue = []
        if not flags.get("httponly"):
            issue.append("missing HttpOnly")
        if not flags.get("secure"):
            issue.append("missing Secure flag")
        if issue:
            print(f"  {Fore.YELLOW}[!] Cookie '{name}': {', '.join(issue)}")
        else:
            print(f"  {Fore.GREEN}[+] Cookie '{name}': properly secured")
    return cookies


# ── robots.txt & Sitemap ──────────────────────────────────────────────────────
def fetch_robots(base_url, timeout=10):
    """Fetch and parse robots.txt for disallowed paths (useful recon intel)."""
    url = base_url + "/robots.txt"
    print(f"{Fore.CYAN}[*] Fetching robots.txt...")
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout)
        if r.status_code == 200:
            lines = r.text.splitlines()
            disallowed = [l.split(":", 1)[1].strip() for l in lines if l.lower().startswith("disallow")]
            sitemaps = [l.split(":", 1)[1].strip() for l in lines if l.lower().startswith("sitemap")]
            if disallowed:
                print(f"  {Fore.GREEN}[+] Disallowed paths ({len(disallowed)}): {disallowed[:10]}")
            return {"raw": r.text[:2000], "disallowed": disallowed, "sitemaps": sitemaps}
        else:
            return {"status": r.status_code}
    except Exception as e:
        return {"error": str(e)}


def fetch_sitemap(base_url, timeout=10):
    """Fetch sitemap.xml and extract URLs."""
    url = base_url + "/sitemap.xml"
    print(f"{Fore.CYAN}[*] Fetching sitemap.xml...")
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout)
        if r.status_code == 200:
            urls = re.findall(r"<loc>(.*?)</loc>", r.text)
            print(f"  {Fore.GREEN}[+] Sitemap: {len(urls)} URL(s) found")
            return {"url_count": len(urls), "urls": urls[:100]}
        return {"status": r.status_code}
    except Exception as e:
        return {"error": str(e)}


# ── Run ────────────────────────────────────────────────────────────────────────
def run(target_url, config, timeout=10, depth=1):
    url = normalize_url(target_url)
    print(f"\n{Fore.CYAN}[*] Web scraping: {url}\n")

    results = {
        "module": "web_scraper",
        "target": url,
        "timestamp": datetime.utcnow().isoformat(),
    }

    # ── Fetch page ──────────────────────────────────────────────────────────
    try:
        response = requests.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
        html = response.text
        results["status_code"] = response.status_code
        results["final_url"] = response.url
    except Exception as e:
        print(f"{Fore.RED}[-] Could not fetch {url}: {e}")
        results["error"] = str(e)
        return results

    soup = BeautifulSoup(html, "lxml") if BS4_AVAILABLE else None

    # ── Run all extraction modules ──────────────────────────────────────────
    results["headers"] = get_headers(url, timeout)
    results["technologies"] = detect_technologies(url, html, results["headers"].get("all_headers"))
    results["metadata"] = extract_metadata(soup, url)
    results["links"] = extract_links(soup, url)
    results["emails_and_ips"] = extract_emails_and_ips(html)
    results["html_comments"] = extract_comments(html)
    results["forms"] = extract_forms(soup, url)
    results["cookies"] = analyse_cookies(response)
    results["robots_txt"] = fetch_robots(url, timeout)
    results["sitemap"] = fetch_sitemap(url, timeout)

    # ── Summary ─────────────────────────────────────────────────────────────
    results["summary"] = {
        "emails_found": len(results["emails_and_ips"]["emails"]),
        "ips_found": len(results["emails_and_ips"]["ips"]),
        "internal_links": len(results["links"]["internal"]),
        "external_links": len(results["links"]["external"]),
        "js_files": len(results["links"]["resources"].get("js", [])),
        "forms": len(results["forms"]),
        "cookies": len(results["cookies"]),
        "html_comments": len(results["html_comments"]),
        "missing_security_headers": results["headers"].get("missing_security_headers", []),
        "technologies": results["technologies"].get("detected", []),
    }

    print(f"\n{Fore.GREEN}[✓] Web scraping complete for {url}")
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web Scraper/Metadata Module — Authorized testing only")
    parser.add_argument("--url", required=True, help="Target URL (authorized targets only)")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--output", default="results/")
    parser.add_argument("--config", default="config/config.yaml")

    args = parser.parse_args()
    config = load_config(args.config)
    results = run(args.url, config, args.timeout)

    os.makedirs(args.output, exist_ok=True)
    safe = args.url.replace("https://", "").replace("http://", "").replace("/", "_")
    out = os.path.join(args.output, f"web_{safe}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json")
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n{Fore.GREEN}[✓] Saved to {out}")
