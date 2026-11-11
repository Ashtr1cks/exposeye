"""SPF, DMARC, MTA-STS and TLS-RPT checks (email spoofing posture)."""

from __future__ import annotations

from exposeye.modules.dns_records import query

# Mechanisms/modifiers that cost a DNS lookup under RFC 7208 section 4.6.4
_LOOKUP_BARE = ("a", "mx", "ptr")
_LOOKUP_PREFIXES = ("include:", "a:", "a/", "mx:", "mx/", "ptr:", "exists:", "redirect=")


def parse_spf(record: str) -> dict:
    terms = record.split()[1:]
    all_qualifier = None
    includes = []
    lookups = 0
    for term in terms:
        t = term.lower()
        bare = t.lstrip("+-~?")
        if bare == "all":
            all_qualifier = t[0] if t[0] in "+-~?" else "+"
        if bare.startswith("include:"):
            includes.append(bare.split(":", 1)[1])
        if bare in _LOOKUP_BARE or bare.startswith(_LOOKUP_PREFIXES):
            lookups += 1
    return {
        "record": record,
        "all": all_qualifier,
        "includes": includes,
        "lookup_count": lookups,
    }


def parse_dmarc(record: str) -> dict:
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    pct = tags.get("pct", "100")
    return {
        "record": record,
        "policy": tags.get("p", "").lower() or None,
        "subdomain_policy": tags.get("sp", "").lower() or None,
        "pct": int(pct) if pct.isdigit() else None,
        "rua": tags.get("rua"),
        "ruf": tags.get("ruf"),
    }


def analyze(domain: str, resolver, txt_records: list[str], has_mx: bool) -> dict:
    spf_records = [t for t in txt_records if t.lower().startswith("v=spf1")]
    dmarc_records = [
        t for t in query(resolver, f"_dmarc.{domain}", "TXT") if t.lower().startswith("v=dmarc1")
    ]
    mta_sts = [
        t for t in query(resolver, f"_mta-sts.{domain}", "TXT") if t.lower().startswith("v=stsv1")
    ]
    tls_rpt = [
        t
        for t in query(resolver, f"_smtp._tls.{domain}", "TXT")
        if t.lower().startswith("v=tlsrptv1")
    ]
    return {
        "has_mx": has_mx,
        "spf": parse_spf(spf_records[0]) if spf_records else None,
        "spf_record_count": len(spf_records),
        "dmarc": parse_dmarc(dmarc_records[0]) if dmarc_records else None,
        "mta_sts": bool(mta_sts),
        "tls_rpt": bool(tls_rpt),
    }


def findings(email: dict) -> list[tuple[str, str, str]]:
    out = []
    spf, dmarc = email.get("spf"), email.get("dmarc")
    sends_mail = email.get("has_mx")

    if email.get("spf_record_count", 0) > 1:
        out.append(("medium", "Multiple SPF records", "RFC 7208 treats this as a permerror."))
    if spf is None:
        sev = "medium" if sends_mail else "low"
        out.append((sev, "No SPF record", "Anyone can claim to send mail from this domain."))
    else:
        qualifier = spf["all"]
        if qualifier == "+":
            out.append(("high", "SPF allows all senders (+all)", spf["record"]))
        elif qualifier == "?":
            out.append(("medium", "SPF is neutral (?all)", spf["record"]))
        elif qualifier is None and "redirect=" not in spf["record"].lower():
            out.append(("low", "SPF has no 'all' mechanism", spf["record"]))
        elif qualifier == "~":
            out.append(("info", "SPF uses softfail (~all)", "Common, but -all is stricter."))
        if spf["lookup_count"] > 10:
            out.append(
                (
                    "medium",
                    "SPF exceeds 10 DNS lookups",
                    f"{spf['lookup_count']} top-level lookup terms (nested includes not counted).",
                )
            )

    if dmarc is None:
        sev = "medium" if sends_mail else "low"
        out.append((sev, "No DMARC record", "Spoofed mail is not rejected or reported."))
    else:
        if dmarc["policy"] == "none":
            out.append(
                ("low", "DMARC policy is p=none", "Monitoring only; spoofed mail still delivered.")
            )
        if dmarc["pct"] is not None and dmarc["pct"] < 100:
            out.append(("info", "DMARC applies to a subset of mail", f"pct={dmarc['pct']}"))
        if not dmarc["rua"]:
            out.append(("info", "DMARC has no aggregate reporting (rua)", dmarc["record"]))

    if sends_mail and not email.get("mta_sts"):
        out.append(("info", "No MTA-STS policy", "Inbound SMTP TLS is opportunistic."))
    return out
