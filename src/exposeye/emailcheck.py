"""Email exposure check: breaches, password exposure, email-domain health, public profile."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime, timezone

from exposeye import __version__
from exposeye.modules import breaches, dns_records, email_identity, email_security
from exposeye.utils import SEVERITIES, finding, make_session, short_error

Progress = Callable[[str, str, bool], None]

SENSITIVE_DATA = {
    "credit card details",
    "partial credit card data",
    "social security numbers",
    "government ids",
    "government issued ids",
    "partial government issued ids",
    "bank account numbers",
    "passport numbers",
    "auth tokens",
    "security questions and answers",
}


def _noop(step: str, message: str, ok: bool = True) -> None:
    pass


def check_email(
    email: str,
    hibp_key: str | None = None,
    progress: Progress = _noop,
    timeout: float = 30,
) -> dict:
    t0 = time.monotonic()
    session = make_session()
    resolver = dns_records.make_resolver(timeout=8)
    domain = email.rsplit("@", 1)[1]
    findings: list[dict] = []
    errors: dict[str, str] = {}

    def add(module: str, severity: str, title: str, detail: str = "") -> None:
        findings.append(finding(severity, title, detail, module))

    result: dict = {
        "meta": {
            "kind": "email",
            "tool": "exposeye",
            "version": __version__,
            "email": email,
            "domain": domain,
            "started": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "options": {"hibp": bool(hibp_key)},
        }
    }

    # 1. Breaches --------------------------------------------------------------
    provider = "Have I Been Pwned" if hibp_key else "XposedOrNot"
    found: list[dict] = []
    try:
        provider, found = breaches.lookup(email, session, hibp_key, timeout)
        pw = [b for b in found if b["password_exposed"]]
        progress(
            "Breaches", f"{len(found)} found via {provider}, {len(pw)} exposed passwords", True
        )
    except Exception as exc:  # noqa: BLE001
        errors["breaches"] = short_error(exc, 300)
        progress("Breaches", f"failed ({errors['breaches']})", False)
    result["breaches"] = {"provider": provider, "items": found, "checked": "breaches" not in errors}
    _breach_findings(found, add)

    # 2. Email domain ----------------------------------------------------------
    disposable = email_identity.disposable_domains(session)
    mx = [m for m in dns_records.query(resolver, domain, "MX") if m.split(" ", 1)[-1].strip()]
    txt = dns_records.query(resolver, domain, "TXT")
    mail = email_security.analyze(domain, resolver, txt, has_mx=bool(mx))
    ptype = email_identity.provider_type(domain, disposable)
    result["domain_info"] = {"provider_type": ptype, "mx": mx, "email_security": mail}
    if not mx:
        add(
            "domain",
            "medium",
            "Email domain can't receive mail",
            f"{domain} has no MX records, so this address probably doesn't work.",
        )
    if ptype == "disposable":
        add("domain", "info", "Disposable email address", f"{domain} is a throwaway inbox service.")
    if ptype == "custom":
        for sev, title, detail in email_security.findings(mail):
            if sev in ("high", "medium"):
                add("domain", sev, f"{title} on {domain}", detail)
    progress(
        "Email domain", f"{ptype} provider, {'accepts mail' if mx else 'no MX records'}", bool(mx)
    )

    # 3. Public profile ------------------------------------------------------------
    try:
        grav = email_identity.gravatar(email, session)
    except Exception as exc:  # noqa: BLE001
        grav = None
        errors["gravatar"] = short_error(exc)
    result["gravatar"] = grav
    if grav and grav["profile"]:
        accounts = ", ".join(a["service"] or "?" for a in grav["profile"]["verified_accounts"])
        add(
            "profile",
            "low",
            "Public Gravatar profile linked to this email",
            (grav["profile"].get("display_name") or "")
            + (f" · links: {accounts}" if accounts else ""),
        )
    elif grav and grav["has_avatar"]:
        add(
            "profile",
            "info",
            "Public Gravatar avatar linked to this email",
            "Anyone who knows the address can see this picture.",
        )
    progress(
        "Public profile",
        "Gravatar profile found"
        if grav and grav["profile"]
        else "avatar only"
        if grav and grav["has_avatar"]
        else "nothing public",
        True,
    )

    # Wrap up ------------------------------------------------------------------------
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (order[f["severity"]], f["module"], f["title"]))
    pw = [b for b in found if b["password_exposed"]]
    years = sorted(b["date"][:4] for b in found if b["date"][:4].isdigit())
    result["findings"] = findings
    result["errors"] = errors
    result["advice"] = advice(found, ptype)
    result["summary"] = {
        "findings": {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES},
        "breaches": len(found),
        "password_breaches": len(pw),
        "plaintext_breaches": sum(
            1 for b in pw if b["password_risk"] in ("plaintext", "easytocrack")
        ),
        "first_year": years[0] if years else None,
        "latest_year": years[-1] if years else None,
    }
    result["meta"]["finished"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    result["meta"]["duration_s"] = round(time.monotonic() - t0, 1)
    return result


def _list(names: list[str], limit: int = 12) -> str:
    return ", ".join(names[:limit]) + (
        f" (+{len(names) - limit} more)" if len(names) > limit else ""
    )


def _breach_findings(found: list[dict], add) -> None:
    if not found:
        return
    pw = [b for b in found if b["password_exposed"]]
    weak = [b for b in pw if b["password_risk"] in ("plaintext", "easytocrack")]
    if weak:
        add(
            "breaches",
            "high",
            f"Password exposed in readable or easy-to-crack form ({len(weak)})",
            _list([f"{b['title']} ({b['date'][:4]})" for b in weak]),
        )
    rest = [b for b in pw if b not in weak]
    if rest:
        add(
            "breaches",
            "medium",
            f"Password hash exposed in {len(rest)} breach(es)",
            _list([f"{b['title']} ({b['date'][:4]})" for b in rest]),
        )
    sensitive = sorted({d for b in found for d in b["data"] if d.lower() in SENSITIVE_DATA})
    if sensitive:
        add(
            "breaches", "high", "Sensitive personal or financial data exposed", ", ".join(sensitive)
        )
    add(
        "breaches",
        "medium" if not pw else "info",
        f"Email found in {len(found)} data breach(es)",
        _list([b["title"] for b in found]),
    )


def advice(found: list[dict], provider_type: str) -> list[dict]:
    tips = []
    pw = [b for b in found if b["password_exposed"]]
    if pw:
        tips.append(
            {
                "priority": "high",
                "title": "Change these passwords now",
                "detail": "Change your password on: "
                + _list([b["title"] for b in pw], 20)
                + ". If you used the same password anywhere else, change it there too.",
            }
        )
        tips.append(
            {
                "priority": "high",
                "title": "Use a password manager",
                "detail": "Unique random passwords per site mean one breach can't unlock your "
                "other accounts. Bitwarden (free), 1Password and KeePassXC are good options.",
            }
        )
    if found:
        tips.append(
            {
                "priority": "medium",
                "title": "Turn on two-factor authentication (2FA)",
                "detail": "Prefer an authenticator app or passkey over SMS, starting with email, "
                "banking and social media accounts.",
            }
        )
        tips.append(
            {
                "priority": "medium",
                "title": "Watch for targeted phishing",
                "detail": "Leaked names, phone numbers and addresses make scam emails and texts "
                "more convincing. Be suspicious of messages that reference these breaches.",
            }
        )
    if any(d.lower() in SENSITIVE_DATA for b in found for d in b["data"]):
        tips.append(
            {
                "priority": "high",
                "title": "Protect your identity and finances",
                "detail": "Financial or ID data leaked. Watch bank statements, and consider a "
                "credit ban or alerts with a credit bureau (e.g. Equifax, Experian, "
                "illion in Australia).",
            }
        )
    if provider_type == "custom":
        tips.append(
            {
                "priority": "low",
                "title": "Check the domain's own security",
                "detail": "Run a domain scan on this email's domain to check SPF/DMARC, subdomains "
                "and website security.",
            }
        )
    if not found:
        tips.append(
            {
                "priority": "low",
                "title": "No known breaches, but stay careful",
                "detail": "Not every breach is public. Keep using unique passwords and 2FA, and "
                "re-check from time to time.",
            }
        )
    return tips
