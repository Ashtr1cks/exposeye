"""Compare two scans of the same target and describe what changed.

Design rule: only report a change when both scans actually measured it. If a data
source failed or a module was switched off in either scan, that area is skipped
rather than reported as "everything disappeared".
"""

from __future__ import annotations

import re

from domainscope.utils import SEVERITIES

SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
SPF_RANK = {"-": 3, "~": 2, "?": 1, None: 1, "+": 0}
DMARC_RANK = {None: 0, "none": 1, "quarantine": 2, "reject": 3}
BAD_STATUS = ("hold", "redemption", "pending delete")


def change(category: str, severity: str, title: str, detail: str = "", good: bool = False) -> dict:
    return {
        "category": category,
        "severity": severity,
        "title": title,
        "detail": detail,
        "improvement": good,
    }


def _names(items, limit: int = 10) -> str:
    items = list(items)
    more = f" (+{len(items) - limit} more)" if len(items) > limit else ""
    return ", ".join(items[:limit]) + more


def _delta(old: set, new: set) -> str:
    parts = []
    if new - old:
        parts.append("added: " + _names(sorted(new - old)))
    if old - new:
        parts.append("removed: " + _names(sorted(old - new)))
    return "; ".join(parts)


def kind_of(result: dict) -> str:
    return (result.get("meta") or {}).get("kind", "domain")


def diff(old: dict, new: dict) -> list[dict]:
    if kind_of(old) != kind_of(new):
        raise ValueError("cannot compare a domain scan with an email check")
    out = diff_email(old, new) if kind_of(new) == "email" else diff_domain(old, new)
    out.sort(key=lambda c: (c["improvement"], SEV_ORDER[c["severity"]], c["category"]))
    return out


def is_alert(c: dict) -> bool:
    """Worth notifying about: a regression that is more than informational."""
    return not c["improvement"] and c["severity"] in ("high", "medium", "low")


# ------------------------------------------------------------------ domain scans


def diff_domain(old: dict, new: dict) -> list[dict]:
    out: list[dict] = []
    oo = (old.get("meta") or {}).get("options") or {}
    no = (new.get("meta") or {}).get("options") or {}
    domain = (new.get("meta") or {}).get("domain", "")

    _hosts(old, new, domain, out)
    if old.get("dns") and new.get("dns"):
        _dns(
            old["dns"], new["dns"], both_email=bool(old.get("email") and new.get("email")), out=out
        )
    if old.get("email") and new.get("email"):
        _email_security(old["email"], new["email"], out)
    if old.get("rdap") and new.get("rdap"):
        _registration(old["rdap"], new["rdap"], out)
    if not oo.get("passive") and not no.get("passive"):
        _tls(old.get("tls") or [], new.get("tls") or [], out)
        _web(old.get("http") or [], new.get("http") or [], out)
    _exposure(old.get("exposure"), new.get("exposure"), out)
    _findings(old.get("findings") or [], new.get("findings") or [], out)
    return out


def _exposure(old: dict | None, new: dict | None, out: list) -> None:
    """New open ports / CVEs per IP. Only IPs that both scans looked up are compared."""
    if not (old and new and old.get("ok") and new.get("ok")):
        return
    from domainscope.modules.exposure import RISKY_PORTS, service_name

    oi, ni = old.get("ips") or {}, new.get("ips") or {}
    opened_risky, opened, closed = [], [], []
    for ip in sorted(set(oi) & set(ni)):
        before, after = set(oi[ip]["ports"]), set(ni[ip]["ports"])
        for port in sorted(after - before):
            label = f"{service_name(port)} ({port}) on {ip}"
            (opened_risky if port in RISKY_PORTS else opened).append(label)
        closed += [f"{service_name(p)} ({p}) on {ip}" for p in sorted(before - after)]
    if opened_risky:
        out.append(
            change(
                "exposure",
                "high",
                f"Risky port(s) newly opened: {len(opened_risky)}",
                _names(opened_risky),
            )
        )
    if opened:
        out.append(change("exposure", "low", f"New open port(s): {len(opened)}", _names(opened)))
    if closed:
        out.append(
            change("exposure", "info", f"Port(s) closed: {len(closed)}", _names(closed), good=True)
        )

    old_cves = {c for ip in set(oi) & set(ni) for c in oi[ip]["vulns"]}
    new_cves = {c for ip in set(oi) & set(ni) for c in ni[ip]["vulns"]}
    meta = new.get("cves") or {}
    fresh = sorted(new_cves - old_cves)
    kev = [c for c in fresh if meta.get(c, {}).get("kev")]
    rest = [c for c in fresh if c not in kev]
    if kev:
        out.append(
            change(
                "exposure", "high", f"New known-exploited vulnerabilities: {len(kev)}", _names(kev)
            )
        )
    if rest:
        worst = (
            "medium"
            if any(meta.get(c, {}).get("priority") in ("high", "medium") for c in rest)
            else "low"
        )
        out.append(
            change("exposure", worst, f"New reported vulnerabilities: {len(rest)}", _names(rest))
        )
    gone = sorted(old_cves - new_cves)
    if gone:
        out.append(
            change(
                "exposure",
                "info",
                f"Vulnerabilities no longer reported: {len(gone)}",
                _names(gone),
                good=True,
            )
        )


def _ct_ok(result: dict) -> bool:
    src = result.get("subdomain_sources")
    return bool(src and src.get("counts"))


def _hosts(old: dict, new: dict, domain: str, out: list) -> None:
    old_h = {h["name"]: h for h in old.get("hosts") or []}
    new_h = {h["name"]: h for h in new.get("hosts") or []}
    comparable = _ct_ok(old) and _ct_ok(new)

    def live(h):
        return bool(h and h.get("ips"))

    appeared = sorted(
        n
        for n, h in new_h.items()
        if live(h)
        and not h.get("wildcard")
        and not live(old_h.get(n))
        and (comparable or n in old_h)  # without CT data both times, only trust known names
    )
    if appeared:
        interesting = [n for n in appeared if new_h[n].get("interesting")]
        out.append(
            change(
                "subdomains",
                "medium" if interesting else "low",
                f"{len(appeared)} new live host(s)",
                _names(appeared)
                + (f" · worth a look: {_names(interesting, 5)}" if interesting else ""),
            )
        )

    # Gone = present in the new scan's list but no longer resolving. Names missing from the
    # new list entirely are "unknown" (a CT source probably failed), so they're not reported.
    gone = sorted(n for n, h in old_h.items() if live(h) and n in new_h and not live(new_h[n]))
    if gone:
        out.append(
            change("subdomains", "info", f"{len(gone)} host(s) stopped resolving", _names(gone))
        )

    for n, h in sorted(new_h.items()):
        if h.get("dangling") and not (old_h.get(n) or {}).get("dangling"):
            out.append(
                change(
                    "subdomains",
                    "high",
                    f"New dangling CNAME: {n}",
                    f"Points to {h.get('cname')}, which no longer exists. "
                    "Possible subdomain takeover.",
                )
            )
        elif (old_h.get(n) or {}).get("dangling") and not h.get("dangling"):
            out.append(change("subdomains", "info", f"Dangling CNAME fixed: {n}", "", good=True))

    moved = []
    for n, h in new_h.items():
        o = old_h.get(n)
        if n != domain and live(h) and live(o) and set(h["ips"]) != set(o["ips"]):
            moved.append(n)
    if moved:
        sev = "low" if f"www.{domain}" in moved else "info"
        out.append(
            change(
                "subdomains",
                sev,
                f"IP address changed on {len(moved)} host(s)",
                _names(sorted(moved)),
            )
        )

    old_nets = {i.get("as_name") or i.get("asn") for i in (old.get("asn") or {}).values()}
    new_nets = {i.get("as_name") or i.get("asn") for i in (new.get("asn") or {}).values()}
    if old_nets and new_nets - old_nets:
        out.append(
            change(
                "subdomains",
                "info",
                "New hosting network(s)",
                _names(sorted(str(x) for x in new_nets - old_nets)),
            )
        )


DNS_RULES = {
    "NS": (
        "medium",
        "Name servers changed",
        "Whoever controls the name servers controls the whole domain. Confirm this was planned.",
    ),
    "MX": ("medium", "Mail servers (MX) changed", "Email for the domain now goes elsewhere."),
    "A": ("low", "Main website IPv4 address changed", ""),
    "AAAA": ("low", "Main website IPv6 address changed", ""),
    "CAA": ("low", "CAA record changed", ""),
}


def _dns(old: dict, new: dict, both_email: bool, out: list) -> None:
    ro, rn = old.get("records") or {}, new.get("records") or {}
    for rtype, (sev, title, why) in DNS_RULES.items():
        a, b = set(ro.get(rtype) or []), set(rn.get(rtype) or [])
        if a != b:
            out.append(change("dns", sev, title, _delta(a, b) + (f". {why}" if why else "")))

    def txt(records):
        values = set(records.get("TXT") or [])
        # SPF is compared separately (with meaning) when both scans checked email security
        return {v for v in values if not v.lower().startswith("v=spf1")} if both_email else values

    a, b = txt(ro), txt(rn)
    if a != b:
        out.append(change("dns", "info", "TXT records changed", _delta(a, b)))

    if old.get("dnssec") and not new.get("dnssec"):
        out.append(
            change("dns", "medium", "DNSSEC was turned off", "DNS answers are no longer signed.")
        )
    elif new.get("dnssec") and not old.get("dnssec"):
        out.append(change("dns", "info", "DNSSEC was turned on", "", good=True))
    if new.get("wildcard_ips") and not old.get("wildcard_ips"):
        out.append(change("dns", "low", "Wildcard DNS appeared", _names(new["wildcard_ips"])))


def _email_security(old: dict, new: dict, out: list) -> None:
    o, n = old.get("spf"), new.get("spf")
    if o and not n:
        out.append(change("email", "medium", "SPF record removed", o["record"]))
    elif n and not o:
        out.append(change("email", "info", "SPF record added", n["record"], good=True))
    elif o and n and o["record"] != n["record"]:
        before, after = SPF_RANK.get(o.get("all"), 1), SPF_RANK.get(n.get("all"), 1)
        detail = f"{o['record']}  →  {n['record']}"
        if after < before:
            out.append(change("email", "medium", "SPF became less strict", detail))
        elif after > before:
            out.append(change("email", "info", "SPF became stricter", detail, good=True))
        else:
            out.append(change("email", "info", "SPF record changed", detail))

    o, n = old.get("dmarc"), new.get("dmarc")
    if o and not n:
        out.append(change("email", "medium", "DMARC record removed", o["record"]))
    elif n and not o:
        out.append(change("email", "info", "DMARC record added", n["record"], good=True))
    elif o and n:
        before, after = DMARC_RANK.get(o.get("policy"), 0), DMARC_RANK.get(n.get("policy"), 0)
        detail = f"p={o.get('policy')}  →  p={n.get('policy')}"
        if after < before:
            out.append(change("email", "medium", "DMARC policy weakened", detail))
        elif after > before:
            out.append(change("email", "info", "DMARC policy strengthened", detail, good=True))
        elif o["record"] != n["record"]:
            out.append(
                change("email", "info", "DMARC record changed", f"{o['record']}  →  {n['record']}")
            )

    if old.get("mta_sts") and not new.get("mta_sts"):
        out.append(change("email", "low", "MTA-STS policy removed"))
    elif new.get("mta_sts") and not old.get("mta_sts"):
        out.append(change("email", "info", "MTA-STS policy added", "", good=True))


def _registration(old: dict, new: dict, out: list) -> None:
    if old.get("registrar") and new.get("registrar") and old["registrar"] != new["registrar"]:
        out.append(
            change(
                "registration",
                "medium",
                "Registrar changed",
                f"{old['registrar']}  →  {new['registrar']}",
            )
        )
    added = set(new.get("status") or []) - set(old.get("status") or [])
    removed = set(old.get("status") or []) - set(new.get("status") or [])
    bad = sorted(s for s in added if any(b in s.lower() for b in BAD_STATUS))
    if bad:
        out.append(
            change("registration", "high", "Domain put on hold / pending deletion", _names(bad))
        )
    elif added or removed:
        out.append(
            change(
                "registration",
                "info",
                "Registration status changed",
                _delta(set(old.get("status") or []), set(new.get("status") or [])),
            )
        )

    od, nd = old.get("days_to_expiry"), new.get("days_to_expiry")
    if nd is not None and nd < 30 and (od is None or od >= 30):
        out.append(
            change(
                "registration",
                "medium",
                f"Domain registration expires in {nd} days",
                new.get("expires") or "",
            )
        )
    if old.get("expires") and new.get("expires") and new["expires"] > old["expires"]:
        out.append(
            change(
                "registration",
                "info",
                "Domain registration renewed",
                f"Now expires {new['expires'][:10]}",
                good=True,
            )
        )


def _tls(old: list, new: list, out: list) -> None:
    old_t = {t["host"]: t for t in old}
    renewed = []
    for t in new:
        o = old_t.get(t["host"])
        if not o:
            continue
        host = t["host"]
        if o.get("valid") and not t.get("valid"):
            out.append(
                change(
                    "tls", "high", f"TLS certificate is now invalid on {host}", t.get("error") or ""
                )
            )
        elif t.get("valid") and not o.get("valid"):
            out.append(change("tls", "info", f"TLS certificate fixed on {host}", "", good=True))
        elif t.get("valid") and o.get("valid"):
            nd, od = t.get("days_left"), o.get("days_left")
            if nd is not None and od is not None:
                for threshold, sev in ((7, "high"), (30, "medium")):
                    if nd < threshold <= od:
                        out.append(
                            change(
                                "tls",
                                sev,
                                f"Certificate on {host} expires in {nd} days",
                                t.get("not_after", "")[:10],
                            )
                        )
                        break
            if (t.get("not_after") or "") > (o.get("not_after") or ""):
                renewed.append(host)
            if o.get("issuer") and t.get("issuer") and o["issuer"] != t["issuer"]:
                out.append(
                    change(
                        "tls",
                        "info",
                        f"Certificate issuer changed on {host}",
                        f"{o['issuer']}  →  {t['issuer']}",
                    )
                )
    if renewed:
        out.append(
            change(
                "tls",
                "info",
                f"Certificates renewed on {len(renewed)} host(s)",
                _names(renewed),
                good=True,
            )
        )


def _web(old: list, new: list, out: list) -> None:
    old_p = {p["host"]: p for p in old}
    fixed: list[str] = []
    for p in new:
        o = old_p.get(p["host"])
        if not o:
            continue
        host = p["host"]
        if o.get("reachable") and not p.get("reachable"):
            out.append(
                change("web", "low", f"{host} stopped responding", "; ".join(p.get("errors") or []))
            )
            continue
        if not (o.get("reachable") and p.get("reachable")):
            continue
        if str(o.get("status"))[:1] != str(p.get("status"))[:1]:
            out.append(
                change(
                    "web",
                    "info",
                    f"{host} now returns HTTP {p.get('status')}",
                    f"was {o.get('status')}",
                )
            )
        om = {m["header"] for m in (o.get("headers") or {}).get("missing", [])}
        nm = {m["header"] for m in (p.get("headers") or {}).get("missing", [])}
        if nm - om:
            out.append(
                change("web", "low", f"Security header removed on {host}", _names(sorted(nm - om)))
            )
        if om - nm:
            fixed.append(f"{host} ({', '.join(sorted(om - nm))})")
        new_leaks = set((p.get("headers") or {}).get("leaks", [])) - set(
            (o.get("headers") or {}).get("leaks", [])
        )
        if new_leaks:
            out.append(
                change("web", "low", f"New version disclosure on {host}", _names(sorted(new_leaks)))
            )
        tech = set(p.get("tech") or []) ^ set(o.get("tech") or [])
        if tech:
            out.append(
                change(
                    "web",
                    "info",
                    f"Technology changed on {host}",
                    _delta(set(o.get("tech") or []), set(p.get("tech") or [])),
                )
            )
    if fixed:
        out.append(change("web", "info", "Security headers added", _names(fixed, 6), good=True))


# Findings already covered by the specific comparisons above.
_SKIP_FINDING_EXPOSURE = "exposure"  # covered by _exposure(), which compares per IP
_SKIP_FINDING = re.compile(
    r"^(Dangling CNAME|TLS certificate|Domain registration expires|Recently registered)"
)


def _finding_key(f: dict) -> tuple[str, str]:
    return f.get("module", ""), re.sub(r"\d+", "#", f.get("title", ""))


def _findings(old: list, new: list, out: list) -> None:
    def important(items):
        return {
            _finding_key(f): f
            for f in items
            if f.get("severity") in ("high", "medium")
            and not _SKIP_FINDING.match(f.get("title", ""))
            and f.get("module") != _SKIP_FINDING_EXPOSURE
        }

    o, n = important(old), important(new)
    for key in sorted(n.keys() - o.keys()):
        f = n[key]
        out.append(
            change("findings", f["severity"], f"New finding: {f['title']}", f.get("detail", ""))
        )
    for key in sorted(o.keys() - n.keys()):
        out.append(change("findings", "info", f"Resolved: {o[key]['title']}", "", good=True))


# ------------------------------------------------------------------ email checks


def diff_email(old: dict, new: dict) -> list[dict]:
    out: list[dict] = []
    ob, nb = old.get("breaches") or {}, new.get("breaches") or {}
    if ob.get("checked") and nb.get("checked"):
        before = {b["name"] for b in ob.get("items", [])}
        fresh = [b for b in nb.get("items", []) if b["name"] not in before]
        with_pw = [b for b in fresh if b.get("password_exposed")]
        without = [b for b in fresh if not b.get("password_exposed")]
        if with_pw:
            out.append(
                change(
                    "breaches",
                    "high",
                    f"Password exposed in {len(with_pw)} new breach(es)",
                    _names(f"{b['title']} ({b['date'][:4]})" for b in with_pw)
                    + ". Change these passwords now.",
                )
            )
        if without:
            out.append(
                change(
                    "breaches",
                    "medium",
                    f"Email found in {len(without)} new breach(es)",
                    _names(f"{b['title']} ({b['date'][:4]})" for b in without),
                )
            )

    og, ng = old.get("gravatar") or {}, new.get("gravatar") or {}
    if ng.get("profile") and not og.get("profile"):
        out.append(
            change(
                "profile",
                "low",
                "A public Gravatar profile appeared for this email",
                ng["profile"].get("display_name") or "",
            )
        )

    om = (old.get("domain_info") or {}).get("mx")
    nm = (new.get("domain_info") or {}).get("mx")
    if om and not nm:
        out.append(
            change("domain", "low", "Email domain stopped accepting mail", "MX records removed.")
        )
    return out
