"""Open ports and known vulnerabilities per IP - passively, from public data.

- Shodan InternetDB: open ports, detected software (CPEs), tags and CVE IDs for an IP,
  from Shodan's own weekly internet-wide scans. Free for non-commercial use, no key.
  domainscope never connects to the target for this.
- CISA KEV: vulnerabilities known to be exploited in the wild (cached for 24 h).
- FIRST EPSS: probability that a CVE gets exploited in the next 30 days.

Caveat: InternetDB infers CVEs from software versions. Vendors often backport fixes
without changing the version string, so CVEs are leads to verify, not proof.
"""

from __future__ import annotations

import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

from domainscope.storage import read_json, write_json
from domainscope.utils import short_error

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MAX_AGE = 24 * 3600

# port -> (service, severity if exposed to the internet, why it matters)
RISKY_PORTS: dict[int, tuple[str, str, str]] = {
    21: ("FTP", "medium", "sends credentials in clear text"),
    23: ("Telnet", "high", "unencrypted remote shell"),
    135: ("Microsoft RPC", "medium", "Windows internals that shouldn't face the internet"),
    139: ("NetBIOS", "high", "Windows file sharing"),
    445: ("SMB", "high", "Windows file sharing; WannaCry/EternalBlue target"),
    161: ("SNMP", "medium", "device management; often leaks configuration"),
    389: ("LDAP", "medium", "directory service; can leak users and structure"),
    1433: ("Microsoft SQL Server", "high", "database"),
    1521: ("Oracle DB", "high", "database"),
    2375: ("Docker API (no TLS)", "high", "gives full control of the host"),
    3306: ("MySQL", "high", "database"),
    3389: ("RDP", "high", "remote desktop; a top ransomware entry point"),
    5432: ("PostgreSQL", "high", "database"),
    5601: ("Kibana", "medium", "log dashboard; often unauthenticated"),
    5900: ("VNC", "high", "remote desktop, often weakly protected"),
    5985: ("WinRM", "medium", "Windows remote management"),
    5986: ("WinRM (TLS)", "medium", "Windows remote management"),
    6379: ("Redis", "high", "database, frequently no password"),
    9200: ("Elasticsearch", "high", "database, frequently no password"),
    11211: ("Memcached", "high", "cache; abused for DDoS amplification"),
    27017: ("MongoDB", "high", "database, frequently no password"),
}

COMMON_SERVICES = {
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP submission",
    993: "IMAPS",
    995: "POP3S",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    2082: "cPanel",
    2083: "cPanel",
    2086: "WHM",
    2087: "WHM",
    10000: "Webmin",
}

_kev_memory: tuple[float, dict] | None = None


def service_name(port: int) -> str:
    if port in RISKY_PORTS:
        return RISKY_PORTS[port][0]
    return COMMON_SERVICES.get(port, f"port {port}")


def is_lookupable(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def parse_internetdb(data: dict) -> dict | None:
    if not isinstance(data, dict) or "detail" in data:  # {"detail": "No information available"}
        return None
    return {
        "ports": sorted(int(p) for p in data.get("ports") or []),
        "cpes": list(data.get("cpes") or []),
        "hostnames": list(data.get("hostnames") or []),
        "tags": list(data.get("tags") or []),
        "vulns": sorted(data.get("vulns") or []),
    }


def lookup_ip(ip: str, session: requests.Session, timeout: float = 15) -> dict | None:
    for attempt in range(3):
        resp = session.get(INTERNETDB_URL.format(ip=ip), timeout=timeout)
        if resp.status_code == 404:
            return None
        if resp.status_code == 429 and attempt < 2:
            time.sleep(2 * (attempt + 1))
            continue
        resp.raise_for_status()
        return parse_internetdb(resp.json())
    return None


def kev_catalog(session: requests.Session, cache_dir: Path | None, timeout: float = 30) -> dict:
    """CVE -> KEV entry. Cached in memory and on disk for 24 hours."""
    global _kev_memory
    now = time.time()
    if _kev_memory and now - _kev_memory[0] < KEV_MAX_AGE:
        return _kev_memory[1]
    cache = Path(cache_dir) / "kev.json" if cache_dir else None
    if cache and cache.exists() and now - cache.stat().st_mtime < KEV_MAX_AGE:
        data = read_json(cache, None)
        if isinstance(data, dict) and data:
            _kev_memory = (now, data)
            return data
    resp = session.get(KEV_URL, timeout=timeout)
    resp.raise_for_status()
    data = {
        v["cveID"]: {
            "name": v.get("vulnerabilityName"),
            "vendor": v.get("vendorProject"),
            "product": v.get("product"),
            "added": v.get("dateAdded"),
            "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
        }
        for v in resp.json().get("vulnerabilities", [])
        if v.get("cveID")
    }
    if cache:
        write_json(cache, data)
    _kev_memory = (now, data)
    return data


def epss_scores(cves: list[str], session: requests.Session, timeout: float = 30) -> dict:
    scores: dict[str, dict] = {}
    for i in range(0, len(cves), 100):
        batch = cves[i : i + 100]
        resp = session.get(EPSS_URL, params={"cve": ",".join(batch)}, timeout=timeout)
        resp.raise_for_status()
        for row in resp.json().get("data", []):
            try:
                scores[row["cve"]] = {
                    "epss": float(row["epss"]),
                    "percentile": float(row["percentile"]),
                }
            except (KeyError, ValueError):
                continue
    return scores


def cve_priority(info: dict) -> str:
    """high / medium / low, from known exploitation and exploit probability."""
    if info.get("kev"):
        return "high"
    epss = info.get("epss") or 0
    if epss >= 0.5:
        return "high"
    if epss >= 0.1:
        return "medium"
    return "low"


def collect(
    ips: list[str],
    session: requests.Session,
    cache_dir: Path | None = None,
    workers: int = 5,
) -> dict:
    targets = [ip for ip in dict.fromkeys(ips) if is_lookupable(ip)]
    errors: dict[str, str] = {}

    def one(ip):
        try:
            return ip, lookup_ip(ip, session), None
        except Exception as exc:  # noqa: BLE001
            return ip, None, short_error(exc)

    per_ip: dict[str, dict] = {}
    failures = 0
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for ip, info, err in pool.map(one, targets):
            if err:
                failures += 1
                errors.setdefault("internetdb", err)
            elif info:
                per_ip[ip] = info

    all_cves = sorted({c for info in per_ip.values() for c in info["vulns"]})
    cves: dict[str, dict] = {c: {"kev": False} for c in all_cves}
    if all_cves:
        try:
            kev = kev_catalog(session, cache_dir)
            for c in all_cves:
                if c in kev:
                    cves[c].update(
                        kev=True,
                        kev_name=kev[c]["name"],
                        ransomware=kev[c]["ransomware"],
                        kev_added=kev[c]["added"],
                    )
        except Exception as exc:  # noqa: BLE001
            errors["kev"] = short_error(exc)
        try:
            for c, score in epss_scores(all_cves, session).items():
                cves[c].update(score)
        except Exception as exc:  # noqa: BLE001
            errors["epss"] = short_error(exc)
        for info in cves.values():
            info["priority"] = cve_priority(info)

    return {
        "checked": len(targets),
        "failed": failures,
        "ok": failures < len(targets) or not targets,
        "ips": per_ip,
        "cves": cves,
        "errors": errors,
    }


def findings(exposure: dict, ip_hosts: dict[str, list[str]]) -> list[tuple[str, str, str]]:
    """Group findings by port / CVE so a big domain doesn't produce hundreds of rows."""
    out = []

    def where(ips):
        labels = []
        for ip in sorted(ips):
            names = ip_hosts.get(ip) or []
            labels.append(f"{names[0]} ({ip})" if names else ip)
        return ", ".join(labels[:8]) + (f" (+{len(labels) - 8} more)" if len(labels) > 8 else "")

    by_port: dict[int, set[str]] = {}
    for ip, info in exposure["ips"].items():
        for port in info["ports"]:
            if port in RISKY_PORTS:
                by_port.setdefault(port, set()).add(ip)
    for port, ips in sorted(by_port.items()):
        name, sev, why = RISKY_PORTS[port]
        out.append((sev, f"{name} (port {port}) exposed to the internet", f"{why} · {where(ips)}"))

    cve_ips: dict[str, set[str]] = {}
    for ip, info in exposure["ips"].items():
        for c in info["vulns"]:
            cve_ips.setdefault(c, set()).add(ip)
    groups = {"kev": [], "high": [], "medium": [], "low": []}
    for c in cve_ips:
        meta = exposure["cves"].get(c, {})
        if meta.get("kev"):
            groups["kev"].append(c)
        else:
            groups[meta.get("priority", "low")].append(c)

    def cve_list(items):
        items = sorted(items, key=lambda c: -(exposure["cves"].get(c, {}).get("epss") or 0))
        return ", ".join(items[:10]) + (f" (+{len(items) - 10} more)" if len(items) > 10 else "")

    def ips_for(items):
        return where({ip for c in items for ip in cve_ips[c]})

    if groups["kev"]:
        ransomware = [c for c in groups["kev"] if exposure["cves"][c].get("ransomware")]
        out.append(
            (
                "high",
                f"Known-exploited vulnerabilities (CISA KEV): {len(groups['kev'])}",
                f"{cve_list(groups['kev'])} · on {ips_for(groups['kev'])}"
                + (f" · used by ransomware: {', '.join(ransomware[:5])}" if ransomware else ""),
            )
        )
    if groups["high"]:
        out.append(
            (
                "high",
                f"Vulnerabilities likely to be exploited: {len(groups['high'])}",
                f"{cve_list(groups['high'])} · on {ips_for(groups['high'])}",
            )
        )
    if groups["medium"]:
        out.append(
            (
                "medium",
                f"Vulnerabilities with elevated exploit risk: {len(groups['medium'])}",
                f"{cve_list(groups['medium'])} · on {ips_for(groups['medium'])}",
            )
        )
    if groups["low"]:
        out.append(
            (
                "low",
                f"Other reported vulnerabilities: {len(groups['low'])}",
                f"{cve_list(groups['low'])} · on {ips_for(groups['low'])}",
            )
        )

    eol = sorted(
        ip for ip, info in exposure["ips"].items() if any(t.startswith("eol") for t in info["tags"])
    )
    if eol:
        out.append(
            (
                "medium",
                "End-of-life software detected",
                f"No longer receives security updates · {where(eol)}",
            )
        )
    return out
