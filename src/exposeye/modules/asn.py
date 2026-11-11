"""IP -> ASN / network owner using Team Cymru's DNS interface (no API key)."""

from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor

from exposeye.modules.dns_records import query


def origin_query_name(ip: str) -> str | None:
    addr = ipaddress.ip_address(ip)
    if not addr.is_global:
        return None
    rp = addr.reverse_pointer
    if addr.version == 4:
        return rp.removesuffix(".in-addr.arpa") + ".origin.asn.cymru.com"
    return rp.removesuffix(".ip6.arpa") + ".origin6.asn.cymru.com"


def parse_origin(txt: str) -> dict:
    # "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
    parts = [p.strip() for p in txt.split("|")]
    asn = parts[0].split()[0] if parts and parts[0] else None
    return {
        "asn": asn,
        "prefix": parts[1] if len(parts) > 1 else None,
        "country": parts[2] if len(parts) > 2 else None,
        "registry": parts[3] if len(parts) > 3 else None,
    }


def parse_as_name(txt: str) -> str | None:
    # "15169 | US | arin | 2000-03-30 | GOOGLE, US"
    parts = [p.strip() for p in txt.split("|")]
    return parts[4] if len(parts) > 4 else None


def lookup_many(ips: list[str], resolver, workers: int = 20) -> dict[str, dict]:
    def origin(ip):
        name = origin_query_name(ip)
        if not name:
            return ip, None
        txt = query(resolver, name, "TXT")
        return ip, parse_origin(txt[0]) if txt else None

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        results = {ip: info for ip, info in pool.map(origin, ips) if info}

    asns = sorted({info["asn"] for info in results.values() if info.get("asn")})
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        names = dict(
            pool.map(
                lambda a: (a, (query(resolver, f"AS{a}.asn.cymru.com", "TXT") or [""])[0]),
                asns,
            )
        )
    for info in results.values():
        info["as_name"] = parse_as_name(names.get(info.get("asn"), ""))
    return results
