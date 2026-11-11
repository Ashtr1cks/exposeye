"""DNS record collection, wildcard detection and host resolution."""

from __future__ import annotations

import secrets
from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.resolver

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")

_EMPTY = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers)


def make_resolver(nameservers: list[str] | None = None, timeout: float = 5.0):
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = min(timeout, 3.0)
    if nameservers:
        resolver.nameservers = nameservers
    return resolver


def _fmt(rdata, rtype: str) -> str:
    if rtype == "TXT":
        return b"".join(rdata.strings).decode("utf-8", errors="replace")
    if rtype == "MX":
        return f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}"
    if rtype in ("NS", "CNAME"):
        return rdata.target.to_text().rstrip(".")
    return rdata.to_text()


def query(resolver, name: str, rtype: str) -> list[str]:
    try:
        answer = resolver.resolve(name, rtype)
    except (*_EMPTY, dns.exception.Timeout):
        return []
    return [_fmt(r, rtype) for r in answer]


def collect_records(domain: str, resolver) -> dict:
    records = {rtype: query(resolver, domain, rtype) for rtype in RECORD_TYPES}
    return {
        "records": records,
        "dnssec": bool(query(resolver, domain, "DNSKEY")),
        "wildcard_ips": detect_wildcard(domain, resolver),
    }


def detect_wildcard(domain: str, resolver) -> list[str]:
    """Resolve a random label; any answer means *.domain is a wildcard."""
    probe = f"ds-{secrets.token_hex(6)}.{domain}"
    return sorted(query(resolver, probe, "A"))


def resolve_host(name: str, resolver) -> dict:
    """Resolve A records and spot CNAMEs that point at names that no longer exist."""
    result = {"name": name, "ips": [], "cname": None, "dangling": False}
    try:
        answer = resolver.resolve(name, "A")
        result["ips"] = sorted(r.to_text() for r in answer)
        canonical = answer.canonical_name.to_text().rstrip(".")
        if canonical != name:
            result["cname"] = canonical
    except dns.resolver.NXDOMAIN:
        # The name may still exist as a CNAME whose *target* is NXDOMAIN.
        cnames = query(resolver, name, "CNAME")
        if cnames:
            result["cname"] = cnames[0]
            result["dangling"] = True
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        cnames = query(resolver, name, "CNAME")
        if cnames:
            result["cname"] = cnames[0]
    return result


def resolve_hosts(names: list[str], resolver, workers: int = 20) -> list[dict]:
    if not names:
        return []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        return list(pool.map(lambda n: resolve_host(n, resolver), names))
