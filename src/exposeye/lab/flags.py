"""Flag hunter: find CTF flags in any text the Lab produces.

Formats are written the way CTFs announce them, e.g. ``picoCTF{...}``. ``...`` marks the
secret part. Prefix a line with ``re:`` to use a raw regular expression instead.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

DEFAULT_FORMATS = ["flag{...}", "CTF{...}", "picoCTF{...}", "HTB{...}", "THM{...}", "DUCTF{...}"]

# Anything shaped like PREFIX{secret}: catches unknown competitions, ranked as "possible".
GENERIC = re.compile(r"\b[A-Za-z][A-Za-z0-9_]{1,24}\{[^{}\s]{3,200}\}")


@dataclass(frozen=True)
class FlagPattern:
    label: str
    regex: re.Pattern


def compile_formats(formats: list[str]) -> list[FlagPattern]:
    patterns = []
    for raw in formats:
        fmt = raw.strip()
        if not fmt:
            continue
        if fmt.lower().startswith("re:"):
            try:
                patterns.append(FlagPattern(fmt, re.compile(fmt[3:].strip())))
            except re.error as exc:
                raise ValueError(f"invalid regular expression {fmt[3:].strip()!r}: {exc}") from exc
            continue
        if "..." in fmt:
            prefix, suffix = fmt.split("...", 1)
        elif fmt.endswith("{}"):
            prefix, suffix = fmt[:-1], "}"
        else:
            prefix, suffix = fmt + "{", "}"
        body = r"[^\s{}]{1,300}?" if suffix else r"[^\s{}]{1,300}"
        patterns.append(
            FlagPattern(fmt, re.compile(re.escape(prefix) + body + re.escape(suffix), re.I))
        )
    return patterns


def find_flags(text: str, patterns: list[FlagPattern], generic: bool = True) -> list[dict]:
    """Return unique flags, configured formats first, then generic 'possible' ones."""
    if not text:
        return []
    found: dict[str, dict] = {}
    for p in patterns:
        for m in p.regex.finditer(text):
            found.setdefault(
                m.group(0), {"value": m.group(0), "format": p.label, "confidence": "high"}
            )
    if generic:
        for m in GENERIC.finditer(text):
            found.setdefault(
                m.group(0), {"value": m.group(0), "format": "generic", "confidence": "possible"}
            )
    # "CTF{x}" inside "picoCTF{x}" is the same flag: keep the longest match of the same confidence.
    # A confirmed match is never dropped because of a generic guess around it (e.g. "txtflag{x}").
    high = [v for v, f in found.items() if f["confidence"] == "high"]
    keep = []
    for v, f in found.items():
        if f["confidence"] == "high":
            if not any(v != o and v in o for o in high):
                keep.append(f)
        elif not any(v in o or o in v for o in high) and not any(
            v != o and v in o for o, g in found.items() if g["confidence"] == "possible"
        ):
            keep.append(f)
    return keep


class FlagHunter:
    """Bundles the configured formats so every Lab tool can call `hunter.scan(text)`."""

    def __init__(self, formats: list[str] | None = None, generic: bool = True):
        self.formats = list(formats) if formats is not None else list(DEFAULT_FORMATS)
        self.generic = generic
        self.patterns = compile_formats(self.formats)

    def scan(self, text: str) -> list[dict]:
        return find_flags(text, self.patterns, self.generic)

    def scan_bytes(self, data: bytes) -> list[dict]:
        return self.scan(data.decode("latin-1"))
