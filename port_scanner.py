"""
port_scanner.py — TCP/UDP Port Scanner Module
Supports: SYN scan (via nmap), connect scan, banner grabbing, service detection.
For authorized penetration testing only.
"""

import socket
import json
import argparse
import yaml
import os
import concurrent.futures
import subprocess
import shutil
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# Common ports grouped by category
COMMON_PORTS = {
    "web":      [80, 443, 8080, 8443, 8000, 8888],
    "remote":   [22, 23, 3389, 5900],
    "mail":     [25, 465, 587, 110, 995, 143, 993],
    "database": [3306, 5432, 1433, 1521, 27017, 6379, 5984],
    "dns":      [53],
    "ftp":      [20, 21],
    "smb":      [137, 138, 139, 445],
    "voip":     [5060, 5061],
    "top100":   [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888,
        27017, 6379, 5432, 1433, 5060
    ],
}


def load_config(config_path="config/config.yaml"):
    with open(config_path) as f:
        return yaml.safe_load(f)


def parse_ports(port_arg):
    """
    Parse port argument into a list of ints.
    Accepts: '80', '80,443', '1-1024', 'web', 'top100'
    """
    if port_arg in COMMON_PORTS:
        return COMMON_PORTS[port_arg]
    ports = []
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


# ── Banner Grabbing ────────────────────────────────────────────────────────────
def grab_banner(ip, port, timeout=3):
    """Attempt to grab service banner from open port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            # Send common probes depending on port
            if port in [80, 8080, 8000, 8888]:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner on connect
            elif port == 22:
                pass  # SSH sends banner on connect
            else:
                s.send(b"\r\n")
            banner = s.recv(1024).decode("utf-8", errors="replace").strip()
            return banner[:500]
    except Exception:
        return ""


# ── Connect Scan ──────────────────────────────────────────────────────────────
def connect_scan_port(ip, port, timeout=2, grab=True):
    """Attempt TCP connect to a single port. Returns result dict."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                banner = grab_banner(ip, port, timeout) if grab else ""
                service = get_service_name(port)
                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner,
                }
    except Exception:
        pass
    return {"port": port, "state": "closed"}


def get_service_name(port):
    """Try to identify service by port number."""
    try:
        return socket.getservbyport(port)
    except Exception:
        return "unknown"


def connect_scan(ip, ports, timeout=2, threads=100, grab_banners=True):
    """
    Multi-threaded TCP connect scan.
    """
    print(f"{Fore.CYAN}[*] TCP connect scan on {ip} ({len(ports)} ports, {threads} threads)...")
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(connect_scan_port, ip, port, timeout, grab_banners): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result["state"] == "open":
                open_ports.append(result)
                banner_preview = result["banner"][:60].replace("\n", " ") if result["banner"] else ""
                print(f"  {Fore.GREEN}[+] {result['port']}/tcp  OPEN  "
                      f"[{result['service']}]  {banner_preview}")

    open_ports.sort(key=lambda x: x["port"])
    print(f"\n{Fore.GREEN}[✓] {len(open_ports)} open port(s) found on {ip}")
    return open_ports


# ── Nmap Integration ──────────────────────────────────────────────────────────
def nmap_scan(ip, ports, flags="-sV -O --script=banner"):
    """
    Run nmap if available. Falls back to connect_scan if not installed.
    Requires nmap to be installed: apt install nmap / brew install nmap
    """
    if not shutil.which("nmap"):
        print(f"{Fore.YELLOW}[!] nmap not found — falling back to connect scan.")
        return None

    port_str = ",".join(str(p) for p in ports)
    cmd = ["nmap", flags, "-p", port_str, "--open", "-oJ", "-", ip]
    # Flatten flags properly
    cmd = ["nmap"] + flags.split() + ["-p", port_str, "--open", "-oX", "-", ip]

    print(f"{Fore.CYAN}[*] Running nmap: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            # Parse nmap XML output
            return parse_nmap_xml(result.stdout, ip)
        else:
            print(f"{Fore.RED}[-] nmap error: {result.stderr[:200]}")
            return None
    except subprocess.TimeoutExpired:
        print(f"{Fore.RED}[-] nmap timed out.")
        return None
    except Exception as e:
        print(f"{Fore.RED}[-] nmap failed: {e}")
        return None


def parse_nmap_xml(xml_output, ip):
    """Parse nmap XML output into a clean list of port dicts."""
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_output)
        ports_found = []
        for host in root.findall("host"):
            for port_elem in host.findall(".//port"):
                state = port_elem.find("state")
                if state is not None and state.get("state") == "open":
                    service = port_elem.find("service")
                    script_outputs = {}
                    for script in port_elem.findall("script"):
                        script_outputs[script.get("id")] = script.get("output", "")[:300]
                    ports_found.append({
                        "port": int(port_elem.get("portid")),
                        "protocol": port_elem.get("protocol", "tcp"),
                        "state": "open",
                        "service": service.get("name", "") if service is not None else "",
                        "product": service.get("product", "") if service is not None else "",
                        "version": service.get("version", "") if service is not None else "",
                        "scripts": script_outputs,
                    })
        return ports_found
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Could not parse nmap XML: {e}")
        return []


# ── UDP Scan ───────────────────────────────────────────────────────────────────
def udp_scan(ip, ports, timeout=2):
    """
    Basic UDP scan. Note: UDP scanning is inherently less reliable than TCP.
    Many firewalls block ICMP port unreachable, causing false open|filtered results.
    """
    print(f"{Fore.CYAN}[*] UDP scan on {ip} ({len(ports)} ports)...")
    results = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(b"\x00\x00\x00\x00", (ip, port))
                data, _ = s.recvfrom(1024)
                results.append({"port": port, "protocol": "udp", "state": "open", "data": data[:100].hex()})
                print(f"  {Fore.GREEN}[+] {port}/udp OPEN")
        except socket.timeout:
            results.append({"port": port, "protocol": "udp", "state": "open|filtered"})
        except ConnectionRefusedError:
            pass  # ICMP port unreachable = closed
        except Exception:
            pass
    return results


# ── Run ────────────────────────────────────────────────────────────────────────
def run(target, ports, config, use_nmap=True, udp=False, threads=100, grab=True, timeout=2):
    results = {
        "module": "port_scanner",
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "tcp": [],
        "udp": [],
        "scan_type": "nmap" if (use_nmap and shutil.which("nmap")) else "connect",
    }

    # Resolve hostname if needed
    try:
        ip = socket.gethostbyname(target)
        results["resolved_ip"] = ip
        if ip != target:
            print(f"{Fore.CYAN}[*] {target} → {ip}")
    except Exception as e:
        print(f"{Fore.RED}[-] Could not resolve {target}: {e}")
        results["error"] = str(e)
        return results

    # TCP Scan
    if use_nmap and shutil.which("nmap"):
        nmap_results = nmap_scan(ip, ports)
        if nmap_results is not None:
            results["tcp"] = nmap_results
            results["scan_type"] = "nmap"
        else:
            results["tcp"] = connect_scan(ip, ports, timeout, threads, grab)
            results["scan_type"] = "connect"
    else:
        results["tcp"] = connect_scan(ip, ports, timeout, threads, grab)

    # UDP Scan (optional)
    if udp:
        common_udp = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1194, 5060]
        results["udp"] = udp_scan(ip, common_udp, timeout)

    results["summary"] = {
        "total_scanned": len(ports),
        "open_tcp": len([p for p in results["tcp"] if p.get("state") == "open"]),
        "open_udp": len([p for p in results["udp"] if "open" in p.get("state", "")]),
    }

    print(f"\n{Fore.GREEN}[✓] Scan complete: "
          f"{results['summary']['open_tcp']} open TCP, "
          f"{results['summary']['open_udp']} open/filtered UDP")
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Port Scanner Module — Authorized testing only",
        epilog="Port formats: '80', '80,443', '1-1024', 'web', 'top100', 'database'"
    )
    parser.add_argument("--target", required=True, help="IP or hostname (authorized targets only)")
    parser.add_argument("--ports", default="top100", help="Ports to scan (default: top100)")
    parser.add_argument("--threads", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--no-nmap", action="store_true", help="Force connect scan (skip nmap)")
    parser.add_argument("--udp", action="store_true", help="Also run UDP scan on common ports")
    parser.add_argument("--no-banners", action="store_true", help="Skip banner grabbing")
    parser.add_argument("--output", default="results/")
    parser.add_argument("--config", default="config/config.yaml")

    args = parser.parse_args()
    config = load_config(args.config)
    ports = parse_ports(args.ports)

    results = run(
        args.target, ports, config,
        use_nmap=not args.no_nmap,
        udp=args.udp,
        threads=args.threads,
        grab=not args.no_banners,
        timeout=args.timeout,
    )

    os.makedirs(args.output, exist_ok=True)
    safe = args.target.replace("/", "_")
    out = os.path.join(args.output, f"portscan_{safe}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json")
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n{Fore.GREEN}[✓] Saved to {out}")
