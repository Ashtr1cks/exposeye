"""Pwned Passwords check using k-anonymity.

The password is SHA-1 hashed locally. Only the first 5 hex characters of the hash
are sent to HIBP, which returns every leaked hash starting with that prefix
(padded with decoys); the match is done here. Neither the password nor its full
hash leaves the machine. Free, no API key.
"""

from __future__ import annotations

import hashlib

import requests

RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"


def split_hash(password: str) -> tuple[str, str]:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324 - API format
    return digest[:5], digest[5:]


def count_in_range(range_body: str, suffix: str) -> int:
    suffix = suffix.upper()
    for line in range_body.splitlines():
        candidate, _, count = line.strip().partition(":")
        if candidate.upper() == suffix:
            try:
                return int(count)
            except ValueError:
                return 0
    return 0


def times_pwned(password: str, session: requests.Session, timeout: float = 15) -> int:
    """How many times this password appears in known breaches (0 = not found)."""
    if not password:
        raise ValueError("empty password")
    prefix, suffix = split_hash(password)
    resp = session.get(
        RANGE_URL.format(prefix=prefix), headers={"Add-Padding": "true"}, timeout=timeout
    )
    resp.raise_for_status()
    return count_in_range(resp.text, suffix)
