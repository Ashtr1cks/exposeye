"""Registration data via RDAP (the JSON successor to WHOIS)."""

from __future__ import annotations

from datetime import datetime, timezone

import requests

RDAP_URL = "https://rdap.org/domain/{domain}"


def _vcard_field(entity: dict, field: str) -> str | None:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return None
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == field:
            value = item[3]
            return value if isinstance(value, str) else str(value)
    return None


def _find_entities(entities: list, role: str) -> list[dict]:
    found = []
    for ent in entities or []:
        if role in (ent.get("roles") or []):
            found.append(ent)
        found.extend(_find_entities(ent.get("entities") or [], role))
    return found


def parse_rdap(data: dict) -> dict:
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events") or []}
    entities = data.get("entities") or []

    registrar = None
    for ent in _find_entities(entities, "registrar"):
        registrar = _vcard_field(ent, "fn") or ent.get("handle")
        if registrar:
            break

    abuse_email = None
    for ent in _find_entities(entities, "abuse"):
        abuse_email = _vcard_field(ent, "email")
        if abuse_email:
            break

    registrant = None
    for ent in _find_entities(entities, "registrant"):
        registrant = _vcard_field(ent, "org") or _vcard_field(ent, "fn")
        if registrant:
            break

    nameservers = sorted(
        ns.get("ldhName", "").lower().rstrip(".")
        for ns in data.get("nameservers") or []
        if ns.get("ldhName")
    )

    created = events.get("registration")
    expires = events.get("expiration")
    return {
        "domain": (data.get("ldhName") or "").lower() or None,
        "registrar": registrar,
        "registrant": registrant,
        "abuse_email": abuse_email,
        "created": created,
        "updated": events.get("last changed"),
        "expires": expires,
        "age_days": _days_since(created),
        "days_to_expiry": -_days_since(expires) if expires else None,
        "status": data.get("status") or [],
        "nameservers": nameservers,
        "dnssec_signed": (data.get("secureDNS") or {}).get("delegationSigned"),
    }


def _days_since(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).days


def lookup(domain: str, session: requests.Session, timeout: float = 15) -> dict:
    """Look up the registered domain, walking up labels if a subdomain was given."""
    labels = domain.split(".")
    last_error = "not found"
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        resp = session.get(
            RDAP_URL.format(domain=candidate),
            headers={"Accept": "application/rdap+json"},
            timeout=timeout,
        )
        if resp.status_code == 404:
            last_error = f"no RDAP record for {candidate}"
            continue
        resp.raise_for_status()
        return parse_rdap(resp.json())
    raise LookupError(last_error)


def findings(rdap: dict) -> list[tuple[str, str, str]]:
    out = []
    age = rdap.get("age_days")
    if age is not None and age < 90:
        out.append(("medium", "Recently registered domain", f"Registered {age} days ago."))
    left = rdap.get("days_to_expiry")
    if left is not None and left < 30:
        out.append(("medium", "Domain registration expires soon", f"{left} days left."))
    return out
