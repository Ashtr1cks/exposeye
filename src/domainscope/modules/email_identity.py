"""Facts about an email address that need no breach data: provider type,
disposable-domain detection and public Gravatar profile."""

from __future__ import annotations

import hashlib

import requests

DISPOSABLE_LIST_URL = (
    "https://raw.githubusercontent.com/disposable-email-domains/"
    "disposable-email-domains/main/disposable_email_blocklist.conf"
)

# Fallback when the community list can't be downloaded.
BUILTIN_DISPOSABLE = {
    "10minutemail.com",
    "guerrillamail.com",
    "guerrillamail.net",
    "sharklasers.com",
    "mailinator.com",
    "maildrop.cc",
    "temp-mail.org",
    "tempmail.com",
    "throwawaymail.com",
    "yopmail.com",
    "trashmail.com",
    "getnada.com",
    "dispostable.com",
    "fakeinbox.com",
    "mintemail.com",
    "mohmal.com",
    "emailondeck.com",
    "tempail.com",
    "moakt.com",
    "mailnesia.com",
}

FREE_PROVIDERS = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "yahoo.com",
    "ymail.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "aol.com",
    "proton.me",
    "protonmail.com",
    "pm.me",
    "gmx.com",
    "gmx.net",
    "mail.com",
    "zoho.com",
    "yandex.com",
    "yandex.ru",
    "qq.com",
    "163.com",
    "tutanota.com",
    "tuta.io",
    "fastmail.com",
    "bigpond.com",
    "optusnet.com.au",
}

_disposable_cache: set[str] | None = None


def disposable_domains(session: requests.Session, timeout: float = 10) -> set[str]:
    global _disposable_cache
    if _disposable_cache is None:
        try:
            resp = session.get(DISPOSABLE_LIST_URL, timeout=timeout)
            resp.raise_for_status()
            remote = {
                line.strip().lower()
                for line in resp.text.splitlines()
                if line.strip() and not line.startswith("#")
            }
            _disposable_cache = remote | BUILTIN_DISPOSABLE
        except requests.RequestException:
            return set(BUILTIN_DISPOSABLE)  # don't cache the fallback; retry next time
    return _disposable_cache


def provider_type(domain: str, disposable: set[str]) -> str:
    if domain in disposable:
        return "disposable"
    if domain in FREE_PROVIDERS:
        return "free"
    return "custom"


def gravatar_hash(email: str) -> str:
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()


def gravatar(email: str, session: requests.Session, timeout: float = 10) -> dict:
    """Public Gravatar profile/avatar linked to the email, if any."""
    digest = gravatar_hash(email)
    result = {
        "hash": digest,
        "has_avatar": False,
        "avatar_url": None,
        "profile": None,
    }
    resp = session.get(f"https://api.gravatar.com/v3/profiles/{digest}", timeout=timeout)
    if resp.status_code == 200:
        data = resp.json()
        result["profile"] = {
            "display_name": data.get("display_name"),
            "profile_url": data.get("profile_url"),
            "location": data.get("location"),
            "description": data.get("description"),
            "job_title": data.get("job_title"),
            "company": data.get("company"),
            "pronouns": data.get("pronouns"),
            "verified_accounts": [
                {"service": a.get("service_label") or a.get("service_type"), "url": a.get("url")}
                for a in data.get("verified_accounts") or []
            ],
        }
    avatar = session.get(
        f"https://gravatar.com/avatar/{digest}", params={"d": "404", "s": "160"}, timeout=timeout
    )
    if avatar.status_code == 200:
        result["has_avatar"] = True
        result["avatar_url"] = f"https://gravatar.com/avatar/{digest}?s=160"
    return result
