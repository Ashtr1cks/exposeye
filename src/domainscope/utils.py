"""Shared helpers: domain normalisation, HTTP session, findings."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

import requests

from domainscope import __version__

USER_AGENT = f"domainscope/{__version__} (OSINT recon tool)"

SEVERITIES = ("high", "medium", "low", "info")

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def normalize_domain(raw: str) -> str:
    """Turn user input (URL, host, host:port, wildcard) into a bare ASCII domain.

    Raises ValueError if the result is not a plausible domain name.
    """
    s = (raw or "").strip().lower()
    if not s:
        raise ValueError("empty domain")
    if "://" not in s:
        s = "http://" + s
    host = urlsplit(s).hostname or ""
    host = host.rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid domain: {raw!r}") from exc

    labels = host.split(".")
    if len(labels) < 2 or not all(_LABEL_RE.match(label) for label in labels):
        raise ValueError(f"invalid domain: {raw!r}")
    if labels[-1].isdigit():
        raise ValueError(f"expected a domain name, got an IP address: {raw!r}")
    return host


_LOCAL_PART_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}$")


def normalize_email(raw: str) -> str:
    """Validate and normalise an email address (lower-cased, IDNA domain)."""
    s = (raw or "").strip()
    if s.lower().startswith("mailto:"):
        s = s[7:]
    local, sep, domain = s.rpartition("@")
    if not sep or not local or not _LOCAL_PART_RE.match(local) or ".." in local:
        raise ValueError(f"invalid email address: {raw!r}")
    if local.startswith(".") or local.endswith("."):
        raise ValueError(f"invalid email address: {raw!r}")
    try:
        domain = normalize_domain(domain)
    except ValueError as exc:
        raise ValueError(f"invalid email address: {raw!r}") from exc
    return f"{local.lower()}@{domain}"


def make_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    return session


def finding(severity: str, title: str, detail: str = "", module: str = "") -> dict:
    if severity not in SEVERITIES:
        raise ValueError(f"unknown severity {severity}")
    return {"severity": severity, "title": title, "detail": detail, "module": module}


def short_error(exc: BaseException, limit: int = 160) -> str:
    text = str(exc) or exc.__class__.__name__
    # requests errors are very verbose; keep the most useful tail
    text = text.replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 3] + "..."
