#!/usr/bin/env python3
"""
DNS Inspector

Given a website URL (e.g. https://test.com) this script extracts the domain,
resolves its A/AAAA addresses, queries the domain's authoritative NS records,
resolves those names to IPs, checks basic reachability of each DNS server,
and retrieves WHOIS registration information when available.

Designed to run on Linux with Python 3 and required packages installed.
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
from typing import List, Dict, Tuple, Optional
from urllib.parse import urlparse

try:
    import dns.resolver
    import dns.exception
except Exception:
    dns = None  # type: ignore

try:
    import whois
except ImportError:
    whois = None


def extract_domain(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    p = urlparse(url)
    domain = p.hostname
    if not domain:
        raise ValueError("Could not parse domain from input")
    return domain


def resolve_records(domain: str) -> Dict[str, List[str]]:
    """Return A and AAAA records for the domain."""
    result = {"A": [], "AAAA": []}
    # Prefer dnspython if available for control; otherwise fallback to socket
    if dns:
        resolver = dns.resolver.Resolver()
        for rtype in ("A", "AAAA"):
            try:
                answers = resolver.resolve(domain, rtype, lifetime=5)
                for r in answers:
                    result[rtype].append(r.to_text())
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout, dns.exception.DNSException):
                # No records of this type or query failed
                pass
    else:
        # Fallback using socket.getaddrinfo
        try:
            infos = socket.getaddrinfo(domain, None)
            for fam, *_ in infos:
                try:
                    if fam == socket.AF_INET:
                        # use gethostbyname
                        ip = socket.gethostbyname(domain)
                        if ip not in result["A"]:
                            result["A"].append(ip)
                    elif fam == socket.AF_INET6:
                        # socket doesn't give us a direct gethostbyname for IPv6 easily
                        # we'll include the address from getaddrinfo
                        pass
                except Exception:
                    pass
        except Exception:
            pass
    return result


def get_ns_records(domain: str) -> List[str]:
    """Return list of NS hostnames for the domain."""
    if not dns:
        # Without dnspython, attempt to use system resolver via socket to query NS is hard.
        raise RuntimeError("dnspython is required to query NS records. Install with 'pip install dnspython'.")
    resolver = dns.resolver.Resolver()
    try:
        answers = resolver.resolve(domain, "NS", lifetime=5)
        return [r.to_text().rstrip('.') for r in answers]
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []
    except dns.exception.DNSException as e:
        raise RuntimeError(f"DNS query failed: {e}")


def resolve_name_to_ips(name: str) -> Dict[str, List[str]]:
    return resolve_records(name)


def check_tcp_port(ip: str, port: int = 53, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def get_whois_info(domain: str) -> Optional[Dict]:
    """Fetch WHOIS information for the domain if possible."""
    if whois is None:
        return None
    
    try:
        w = whois.whois(domain)
        if not w:
            return None
            
        # Convert datetime objects to strings if present
        clean_data = {}
        for k, v in w.items():
            if isinstance(v, (list, tuple)):
                clean_data[k] = [str(x) if hasattr(x, 'strftime') else x for x in v]
            else:
                clean_data[k] = str(v) if hasattr(v, 'strftime') else v
                
        return clean_data
    except Exception as e:
        print(f"WHOIS lookup failed: {e}", file=sys.stderr)
        return None

def inspect(domain: str) -> Dict:
    out = {
        "domain": domain,
        "addresses": {},
        "nameservers": [],
        "registration": None
    }

    # Resolve domain A/AAAA
    addr = resolve_records(domain)
    out["addresses"] = addr

    # Get NS records
    try:
        ns_list = get_ns_records(domain)
    except RuntimeError as e:
        ns_list = []
        out["ns_error"] = str(e)

    for ns in ns_list:
        ns_entry = {"name": ns, "addresses": {}, "reachable": []}
        ips = resolve_name_to_ips(ns)
        ns_entry["addresses"] = ips
        # Check reachability for each IP (TCP 53)
        reachable = []
        for t in ("A", "AAAA"):
            for ip in ips.get(t, []):
                ok = check_tcp_port(ip, 53, timeout=3.0)
                reachable.append({"ip": ip, "type": t, "tcp53": ok})
        ns_entry["reachable"] = reachable
        out["nameservers"].append(ns_entry)
    
    # Get WHOIS information if available
    whois_data = get_whois_info(domain)
    if whois_data:
        out["registration"] = whois_data

    return out


def pretty_print(report: Dict) -> None:
    print("\nDNS Inspector Report")
    print("====================\n")
    print(f"Domain: {report.get('domain')}")

    # Print registration information if available
    reg = report.get("registration")
    if reg:
        print("\nDomain Registration Information:")
        print("------------------------------")
        
        # Basic domain info
        fields = [
            ("Registrar", "registrar"),
            ("Organization", "org"),
            ("Name", "name"),
            ("Email", "emails"),
            ("Phone", "phone"),
            ("Address", "address"),
            ("City", "city"),
            ("State", "state"),
            ("Country", "country"),
            ("Creation Date", "creation_date"),
            ("Expiration Date", "expiration_date"),
            ("Updated Date", "updated_date"),
            ("WHOIS Server", "whois_server"),
            ("Status", "status")
        ]
        
        for label, key in fields:
            value = reg.get(key)
            if value:
                if isinstance(value, (list, tuple)):
                    print(f"  {label}:")
                    for item in value:
                        print(f"    - {item}")
                else:
                    print(f"  {label}: {value}")

    # DNS Records
    addrs = report.get("addresses", {})
    a = addrs.get("A", [])
    aaaa = addrs.get("AAAA", [])
    print("\nResolved addresses:")
    if a:
        for ip in a:
            print(f"  A  : {ip}")
    else:
        print("  (no A records found)")
    if aaaa:
        for ip in aaaa:
            print(f"  AAAA: {ip}")

    if report.get("ns_error"):
        print("\nNS lookup error:")
        print(f"  {report['ns_error']}")

    print("\nName servers:")
    if not report.get("nameservers"):
        print("  (no NS records found or lookup failed)")
        return

    for i, ns in enumerate(report["nameservers"], start=1):
        print(f"\n {i}. {ns['name']}")
        ips = ns.get("addresses", {})
        a = ips.get("A", [])
        aaaa = ips.get("AAAA", [])
        if a:
            for ip in a:
                print(f"      A  : {ip}")
        if aaaa:
            for ip in aaaa:
                print(f"      AAAA: {ip}")
        if not a and not aaaa:
            print("      (no A/AAAA records for this NS)")

        # Reachability
        reach = ns.get("reachable", [])
        if reach:
            for r in reach:
                status = "open" if r.get("tcp53") else "closed/unreachable"
                print(f"      -> {r.get('ip')} ({r.get('type')}) TCP/53: {status}")
        else:
            print("      (no reachability checks performed)")


def main(argv: List[str] = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect DNS for a given website URL")
    parser.add_argument("url", nargs="?", help="Website URL or hostname (e.g. https://example.com)")
    args = parser.parse_args(argv)

    if not args.url:
        try:
            args.url = input("Enter website URL or hostname: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("No input provided, exiting.")
            return 1

    try:
        domain = extract_domain(args.url)
    except Exception as e:
        print(f"Error parsing URL: {e}")
        return 2

    try:
        report = inspect(domain)
    except Exception as e:
        print(f"Error during inspection: {e}")
        return 3

    pretty_print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
