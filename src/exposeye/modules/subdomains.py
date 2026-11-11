"""Passive subdomain discovery from Certificate Transparency logs."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor

import requests

from exposeye.utils import short_error

# Hosting providers where a dangling CNAME is a known takeover risk.
TAKEOVER_SUFFIXES = (
    "github.io",
    "herokuapp.com",
    "herokudns.com",
    "azurewebsites.net",
    "cloudapp.net",
    "cloudapp.azure.com",
    "trafficmanager.net",
    "blob.core.windows.net",
    "s3.amazonaws.com",
    "elasticbeanstalk.com",
    "netlify.app",
    "vercel.app",
    "surge.sh",
    "pantheonsite.io",
    "ghost.io",
    "myshopify.com",
    "readthedocs.io",
    "fly.dev",
)


def clean_names(names: Iterable[str], domain: str) -> list[str]:
    """Normalise CT-log names and keep only those inside `domain`."""
    out = set()
    suffix = "." + domain
    for raw in names:
        for part in str(raw).split():
            name = part.strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            if not name or "*" in name or "@" in name or " " in name:
                continue
            if name == domain or name.endswith(suffix):
                out.add(name)
    return sorted(out)


def from_crtsh(domain: str, session: requests.Session, timeout: float = 45) -> list[str]:
    last = "unknown error"
    for attempt in range(3):
        try:
            resp = session.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                timeout=timeout,
            )
            if resp.status_code == 200:
                rows = resp.json()
                return [row.get("name_value", "") for row in rows]
            last = f"HTTP {resp.status_code}"
        except (requests.RequestException, ValueError) as exc:
            last = short_error(exc)
        time.sleep(2 * (attempt + 1))  # crt.sh is often overloaded; back off
    raise RuntimeError(f"crt.sh: {last}")


def from_certspotter(domain: str, session: requests.Session, timeout: float = 30) -> list[str]:
    resp = session.get(
        "https://api.certspotter.com/v1/issuances",
        params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
        timeout=timeout,
    )
    if resp.status_code == 429:
        raise RuntimeError("certspotter: rate limited (free tier)")
    resp.raise_for_status()
    names = []
    for issuance in resp.json():
        names.extend(issuance.get("dns_names") or [])
    return names


SOURCES: dict[str, Callable[[str, requests.Session], list[str]]] = {
    "crt.sh": from_crtsh,
    "certspotter": from_certspotter,
}


def discover(domain: str, session: requests.Session) -> dict:
    """Query all sources in parallel. Returns names plus per-source counts/errors."""
    counts, errors, names = {}, {}, set()

    def run(item):
        source, fn = item
        try:
            return source, clean_names(fn(domain, session), domain), None
        except Exception as exc:  # noqa: BLE001 - one bad source must not kill the scan
            return source, [], short_error(exc)

    with ThreadPoolExecutor(max_workers=len(SOURCES)) as pool:
        for source, found, error in pool.map(run, SOURCES.items()):
            if error:
                errors[source] = error
            else:
                counts[source] = len(found)
                names.update(found)
    return {"names": sorted(names), "counts": counts, "errors": errors}


def is_takeover_candidate(cname: str | None) -> bool:
    if not cname:
        return False
    cname = cname.lower().rstrip(".")
    return any(cname == s or cname.endswith("." + s) for s in TAKEOVER_SUFFIXES)
