"""Breach lookups for an email address.

Two providers, normalised to the same shape:
- XposedOrNot (free, no key, ~25 lookups/hour per IP)
- Have I Been Pwned (needs a paid API key)

Only breach *metadata* is returned (site, date, what kinds of data leaked).
Leaked passwords themselves are never fetched or shown.
"""

from __future__ import annotations

import html
import re
import time
from urllib.parse import quote

import requests

XON_URL = "https://api.xposedornot.com/v1/breach-analytics"
HIBP_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"

PASSWORD_RISK_LABELS = {
    "plaintext": "stored in plain text",
    "easytocrack": "weakly hashed (easy to crack)",
    "hardtocrack": "strongly hashed",
    "unknown": "storage method unknown",
    "none": "not exposed",
}

_TAG_RE = re.compile(r"<[^>]+>")


class BreachLookupError(RuntimeError):
    pass


def _plain(text: str | None) -> str:
    return html.unescape(_TAG_RE.sub("", text or "")).strip()


def _password_exposed(data: list[str]) -> bool:
    return any(d.lower() == "passwords" for d in data)


def normalise_xon(item: dict) -> dict:
    data = [d.strip() for d in (item.get("xposed_data") or "").split(";") if d.strip()]
    exposed = _password_exposed(data)
    risk = (item.get("password_risk") or "unknown").lower() if exposed else "none"
    return {
        "name": item.get("breach") or "Unknown",
        "title": item.get("breach") or "Unknown",
        "domain": item.get("domain") or "",
        "date": str(item.get("xposed_date") or ""),
        "records": item.get("xposed_records"),
        "data": data,
        "password_exposed": exposed,
        "password_risk": risk if risk in PASSWORD_RISK_LABELS else "unknown",
        "verified": str(item.get("verified", "")).lower() in ("yes", "true", "1"),
        "industry": item.get("industry") or "",
        "description": _plain(item.get("details")),
        "source": "xposedornot",
    }


def normalise_hibp(item: dict) -> dict:
    data = list(item.get("DataClasses") or [])
    exposed = _password_exposed(data)
    return {
        "name": item.get("Name") or "Unknown",
        "title": item.get("Title") or item.get("Name") or "Unknown",
        "domain": item.get("Domain") or "",
        "date": item.get("BreachDate") or "",
        "records": item.get("PwnCount"),
        "data": data,
        "password_exposed": exposed,
        "password_risk": "unknown" if exposed else "none",
        "verified": bool(item.get("IsVerified")),
        "industry": "",
        "description": _plain(item.get("Description")),
        "source": "hibp",
        "sensitive": bool(item.get("IsSensitive")),
    }


def _sort(breaches: list[dict]) -> list[dict]:
    return sorted(breaches, key=lambda b: (b["date"] or "0000", b["name"]), reverse=True)


def lookup_xposedornot(email: str, session: requests.Session, timeout: float = 30) -> list[dict]:
    resp = session.get(XON_URL, params={"email": email}, timeout=timeout)
    if resp.status_code == 429:
        raise BreachLookupError(
            "XposedOrNot free limit reached (about 25 checks per hour). "
            "Try again later, or add a Have I Been Pwned API key in Settings."
        )
    if resp.status_code == 404:
        return []
    resp.raise_for_status()
    data = resp.json()
    details = (data.get("ExposedBreaches") or {}).get("breaches_details") or []
    return _sort([normalise_xon(item) for item in details])


def lookup_hibp(
    email: str, api_key: str, session: requests.Session, timeout: float = 30
) -> list[dict]:
    url = HIBP_URL.format(account=quote(email, safe=""))
    headers = {"hibp-api-key": api_key}
    for attempt in range(2):
        resp = session.get(
            url, params={"truncateResponse": "false"}, headers=headers, timeout=timeout
        )
        if resp.status_code == 404:
            return []
        if resp.status_code == 401:
            raise BreachLookupError("Have I Been Pwned rejected the API key (401). Check it.")
        if resp.status_code == 429:
            wait = int(resp.headers.get("retry-after", "0") or 0)
            if attempt == 0 and wait <= 10:
                time.sleep(wait or 2)
                continue
            raise BreachLookupError("Have I Been Pwned rate limit hit. Wait a moment and retry.")
        resp.raise_for_status()
        return _sort([normalise_hibp(item) for item in resp.json()])
    return []


def lookup(
    email: str, session: requests.Session, hibp_key: str | None = None, timeout: float = 30
) -> tuple[str, list[dict]]:
    """Returns (provider name, breaches)."""
    if hibp_key:
        return "Have I Been Pwned", lookup_hibp(email, hibp_key, session, timeout)
    return "XposedOrNot", lookup_xposedornot(email, session, timeout)
