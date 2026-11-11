"""Runs the recon modules in order and assembles one JSON-serialisable result."""

from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from domainscope import __version__
from domainscope.modules import (
    asn,
    dns_records,
    email_security,
    http_probe,
    rdap,
    subdomains,
    tls_info,
)
from domainscope.utils import SEVERITIES, finding, make_session, short_error

INTERESTING_WORDS = (
    "admin",
    "dev",
    "staging",
    "stage",
    "test",
    "uat",
    "qa",
    "vpn",
    "remote",
    "jenkins",
    "gitlab",
    "git",
    "jira",
    "confluence",
    "internal",
    "intranet",
    "backup",
    "old",
    "legacy",
    "beta",
    "sso",
    "auth",
    "login",
    "portal",
    "grafana",
    "kibana",
    "db",
    "sql",
    "ftp",
    "mail",
)

Progress = Callable[[str, str, bool], None]


@dataclass
class ScanOptions:
    passive: bool = False
    subdomains: bool = True
    probe_limit: int = 25
    max_hosts: int = 1000
    workers: int = 20
    timeout: float = 10.0
    resolvers: list[str] = field(default_factory=list)


def _noop(step: str, message: str, ok: bool = True) -> None:
    pass


def _interesting(name: str, domain: str) -> bool:
    prefix = name[: -len(domain)].rstrip(".")
    tokens = set(prefix.replace("-", ".").replace("_", ".").split("."))
    return any(word in tokens for word in INTERESTING_WORDS)


def scan(domain: str, opts: ScanOptions | None = None, progress: Progress = _noop) -> dict:
    opts = opts or ScanOptions()
    t0 = time.monotonic()
    started = datetime.now(timezone.utc)
    session = make_session()
    resolver = dns_records.make_resolver(opts.resolvers or None, timeout=min(opts.timeout, 8))

    findings: list[dict] = []
    errors: dict[str, str] = {}

    def add(module: str, items) -> None:
        for severity, title, detail in items:
            findings.append(finding(severity, title, detail, module))

    result: dict = {
        "meta": {
            "tool": "domainscope",
            "version": __version__,
            "domain": domain,
            "started": started.isoformat(timespec="seconds"),
            "options": asdict(opts),
        }
    }

    # 1. Registration data ------------------------------------------------
    try:
        reg = rdap.lookup(domain, session, opts.timeout)
        result["rdap"] = reg
        add("whois", rdap.findings(reg))
        created = (reg.get("created") or "?")[:10]
        progress("WHOIS", f"{reg.get('registrar') or 'unknown registrar'}, created {created}", True)
    except Exception as exc:  # noqa: BLE001
        result["rdap"] = None
        errors["whois"] = short_error(exc)
        progress("WHOIS", f"failed ({errors['whois']})", False)

    # 2. DNS records --------------------------------------------------------
    dns_info = dns_records.collect_records(domain, resolver)
    result["dns"] = dns_info
    recs = dns_info["records"]
    present = [t for t, v in recs.items() if v]
    progress(
        "DNS", ", ".join(f"{t}:{len(recs[t])}" for t in present) or "no records", bool(present)
    )
    if not dns_info["dnssec"]:
        add("dns", [("info", "DNSSEC not enabled", "No DNSKEY records at the zone apex.")])
    if not recs["CAA"]:
        add("dns", [("info", "No CAA record", "Any public CA may issue certificates.")])
    if dns_info["wildcard_ips"]:
        add("dns", [("info", "Wildcard DNS in use", ", ".join(dns_info["wildcard_ips"]))])

    # 3. Email security -----------------------------------------------------
    real_mx = [m for m in recs["MX"] if m.split(" ", 1)[-1].strip()]
    email = email_security.analyze(domain, resolver, recs["TXT"], has_mx=bool(real_mx))
    result["email"] = email
    add("email", email_security.findings(email))
    spf_state = f"SPF {email['spf']['all'] or '?'}all" if email["spf"] else "SPF missing"
    dmarc_state = f"DMARC p={email['dmarc']['policy']}" if email["dmarc"] else "DMARC missing"
    progress("Email sec", f"{spf_state}, {dmarc_state}", bool(email["spf"] and email["dmarc"]))

    # 4. Subdomain discovery (passive, CT logs) ------------------------------
    names = {domain, f"www.{domain}"}
    ct_names: set[str] = set()
    if opts.subdomains:
        disc = subdomains.discover(domain, session)
        ct_names = set(disc["names"])
        names |= ct_names
        for source, err in disc["errors"].items():
            errors[f"subdomains:{source}"] = err
        counts = ", ".join(f"{s} {n}" for s, n in disc["counts"].items()) or "all sources failed"
        progress("CT logs", f"{len(ct_names)} unique names ({counts})", bool(disc["counts"]))
        result["subdomain_sources"] = {"counts": disc["counts"], "errors": disc["errors"]}

    ordered = sorted(names, key=lambda n: (n != domain, n != f"www.{domain}", n))
    truncated = len(ordered) > opts.max_hosts
    ordered = ordered[: opts.max_hosts]

    # 5. Resolve ------------------------------------------------------------
    hosts = dns_records.resolve_hosts(ordered, resolver, opts.workers)
    wildcard = set(dns_info["wildcard_ips"])
    for h in hosts:
        h["wildcard"] = bool(wildcard) and bool(h["ips"]) and set(h["ips"]) <= wildcard
        h["from_ct"] = h["name"] in ct_names
        h["interesting"] = _interesting(h["name"], domain) if h["name"] != domain else False
    # Drop guessed names (apex/www) that do not exist; keep CT names as historical evidence.
    hosts = [h for h in hosts if h["ips"] or h["cname"] or h["from_ct"]]
    live = [h for h in hosts if h["ips"]]
    progress(
        "Resolve",
        f"{len(live)}/{len(hosts)} hosts resolve" + (" (truncated)" if truncated else ""),
        True,
    )

    for h in hosts:
        if h["dangling"]:
            risky = subdomains.is_takeover_candidate(h["cname"])
            add(
                "subdomains",
                [
                    (
                        "high" if risky else "medium",
                        f"Dangling CNAME: {h['name']}",
                        f"Points to {h['cname']} which does not resolve"
                        + (" - known takeover-prone provider." if risky else "."),
                    )
                ],
            )
    interesting = [h["name"] for h in live if h["interesting"]]
    if interesting:
        add(
            "subdomains",
            [
                (
                    "info",
                    f"{len(interesting)} potentially sensitive subdomain(s)",
                    ", ".join(interesting[:25]) + (" ..." if len(interesting) > 25 else ""),
                )
            ],
        )

    # 6. ASN / hosting ---------------------------------------------------------
    ips = sorted({ip for h in live for ip in h["ips"]} | set(recs["A"]) | set(recs["AAAA"]))[:300]
    try:
        asn_map = asn.lookup_many(ips, resolver, opts.workers)
    except Exception as exc:  # noqa: BLE001
        asn_map = {}
        errors["asn"] = short_error(exc)
    result["asn"] = asn_map
    for h in hosts:
        h["asn"] = sorted(
            {
                f"AS{asn_map[ip]['asn']} {asn_map[ip].get('as_name') or ''}".strip()
                for ip in h["ips"]
                if ip in asn_map
            }
        )
    networks = {(i["asn"], i.get("as_name")) for i in asn_map.values()}
    progress("ASN", f"{len(ips)} IPs across {len(networks)} networks", True)

    result["hosts"] = hosts

    # 7. Active: HTTP + TLS ----------------------------------------------------
    result["http"], result["tls"] = [], []
    if opts.passive:
        progress("HTTP/TLS", "skipped (--passive)", True)
    else:
        targets = [h["name"] for h in live if not h["wildcard"]][: opts.probe_limit]

        def check(host: str):
            probe = http_probe.probe(host, session, opts.timeout)
            tls = None
            if probe.get("url", "").startswith("https://"):
                tls = tls_info.inspect(host, timeout=opts.timeout)
            return probe, tls

        with ThreadPoolExecutor(max_workers=max(1, min(opts.workers, 10))) as pool:
            for probe, tls in pool.map(check, targets):
                result["http"].append(probe)
                if tls:
                    result["tls"].append(tls)
                    add("tls", tls_info.findings(tls))

        _http_findings(result["http"], add)
        up = sum(1 for p in result["http"] if p["reachable"])
        progress("HTTP", f"{up}/{len(targets)} probed hosts responded", True)
        bad_tls = sum(1 for t in result["tls"] if not t["valid"])
        progress("TLS", f"{len(result['tls'])} certificates, {bad_tls} problems", bad_tls == 0)

    # 8. Wrap up -----------------------------------------------------------------
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (order[f["severity"]], f["module"], f["title"]))
    result["findings"] = findings
    result["errors"] = errors
    result["summary"] = {
        "findings": {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES},
        "hosts_total": len(hosts),
        "hosts_live": len(live),
        "unique_ips": len(ips),
        "networks": len(networks),
        "hosts_probed": len(result["http"]),
        "truncated": truncated,
    }
    result["meta"]["finished"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    result["meta"]["duration_s"] = round(time.monotonic() - t0, 1)
    return result


def _http_findings(probes: list[dict], add) -> None:
    missing_by_header: dict[str, list[str]] = defaultdict(list)
    meta: dict[str, tuple[str, str]] = {}
    for p in probes:
        if not p.get("reachable"):
            continue
        hdr = p["headers"]
        for m in hdr["missing"]:
            missing_by_header[m["header"]].append(p["host"])
            meta[m["header"]] = (m["severity"], m["label"])
        if hdr["leaks"]:
            add("http", [("low", f"Version disclosure on {p['host']}", "; ".join(hdr["leaks"]))])
        if p.get("http_redirects_to_https") is False:
            detail = f"http://{p['host']}/ serves content without upgrading to HTTPS"
            add("http", [("low", f"HTTP not redirected to HTTPS on {p['host']}", detail)])

    for header, hosts in missing_by_header.items():
        severity, label = meta[header]
        detail = ", ".join(hosts[:10]) + (f" (+{len(hosts) - 10} more)" if len(hosts) > 10 else "")
        add("http", [(severity, f"{label} missing on {len(hosts)} host(s)", detail)])
