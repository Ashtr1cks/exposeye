"""JSON Web Token (JWT) decoding and weakness checks for CTF challenges.

Decodes the header and payload (they are only base64url, not encryption), flags the
well-known vulnerabilities, and tries to recover a weak HMAC signing secret from a
wordlist. This is the standard jwt_tool workflow, used on tokens from challenges or
your own test applications.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from collections.abc import Iterable
from datetime import datetime, timezone

from exposeye.lab.hashes import BUILTIN_WORDS

HS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
TIME_CLAIMS = {"exp": "expires", "nbf": "not valid before", "iat": "issued at"}


def b64url_decode(part: str) -> bytes:
    pad = "=" * (-len(part) % 4)
    return base64.urlsafe_b64decode(part + pad)


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _as_json(raw: bytes):
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def decode(token: str) -> dict:
    token = token.strip()
    parts = token.split(".")
    if len(parts) not in (2, 3):
        return {"valid": False, "error": "Not a JWT (expected 2 or 3 dot-separated parts)."}
    try:
        header = _as_json(b64url_decode(parts[0]))
        payload = _as_json(b64url_decode(parts[1]))
    except (binascii.Error, ValueError):
        return {"valid": False, "error": "The header or payload is not valid base64url."}
    if header is None or payload is None:
        return {"valid": False, "error": "The header or payload is not valid JSON."}
    sig = parts[2] if len(parts) == 3 else ""
    result = {
        "valid": True,
        "header": header,
        "payload": payload,
        "signature_b64": sig,
        "signing_input": f"{parts[0]}.{parts[1]}",
        "alg": str(header.get("alg", "")),
        "claims": _claims(payload),
        "findings": [],
    }
    result["findings"] = _findings(result)
    return result


def _claims(payload: dict) -> list[dict]:
    out = []
    now = datetime.now(timezone.utc).timestamp()
    for key, label in TIME_CLAIMS.items():
        if isinstance(payload.get(key), (int, float)):
            ts = payload[key]
            when = datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")
            note = ""
            if key == "exp":
                note = "expired" if ts < now else "still valid"
            out.append({"claim": key, "label": label, "value": when, "note": note})
    return out


def _findings(r: dict) -> list[dict]:
    out = []
    alg = r["alg"].lower()
    header, payload = r["header"], r["payload"]
    if alg == "none":
        out.append(
            {
                "severity": "high",
                "title": "alg: none",
                "detail": "The server may accept this token with no signature at all. Edit the "
                "payload and send it with an empty signature to forge any claims.",
            }
        )
    if not r["signature_b64"] and alg != "none":
        out.append(
            {
                "severity": "medium",
                "title": "No signature present",
                "detail": "The token has no signature segment.",
            }
        )
    if alg.startswith("hs"):
        out.append(
            {
                "severity": "info",
                "title": f"Symmetric signature ({r['alg']})",
                "detail": "Signed with a shared secret. If the secret is weak you can forge "
                "tokens - try the secret finder below.",
            }
        )
    if alg.startswith("rs") or alg.startswith("es"):
        out.append(
            {
                "severity": "info",
                "title": f"Asymmetric signature ({r['alg']})",
                "detail": "If the server also accepts HS256, an attacker can re-sign the token "
                "with the public key as an HMAC secret (alg-confusion attack).",
            }
        )
    if "jku" in header or "x5u" in header:
        out.append(
            {
                "severity": "medium",
                "title": f"External key URL in header ({'jku' if 'jku' in header else 'x5u'})",
                "detail": "The server fetches the verification key from a URL in the token. If it "
                "isn't locked down, point it at a key you control.",
            }
        )
    if header.get("kid"):
        out.append(
            {
                "severity": "info",
                "title": "kid header present",
                "detail": f"kid = {header['kid']!r}. Sometimes injectable (path traversal / SQL).",
            }
        )
    for role_key in ("role", "admin", "is_admin", "isAdmin", "user", "sub"):
        if role_key in payload:
            out.append(
                {
                    "severity": "info",
                    "title": f"Interesting claim: {role_key}",
                    "detail": f"{role_key} = {payload[role_key]!r}. Try changing it (needs a valid signature).",
                }
            )
            break
    return out


def forge_none(payload: dict) -> str:
    """Build an alg:none token for a given payload (to paste into a challenge)."""
    header = b64url_encode(
        json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode()
    )
    body = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header}.{body}."


def find_secret(token: str, words: Iterable[str], max_words: int = 5_000_000) -> dict:
    """Recover a weak HS256/384/512 signing secret from a wordlist."""
    info = decode(token)
    if not info["valid"]:
        return {"error": info["error"]}
    alg = info["alg"]
    if alg not in HS:
        return {"error": f"Secret search only applies to HS256/384/512, not {alg or 'this token'}."}
    signing_input = info["signing_input"].encode()
    try:
        want = b64url_decode(info["signature_b64"])
    except (binascii.Error, ValueError):
        return {"error": "The signature is not valid base64url."}
    digest = HS[alg]
    tried = 0
    for word in words:
        tried += 1
        if tried > max_words:
            return {"secret": None, "tried": tried - 1, "exhausted": False, "alg": alg}
        got = hmac.new(word.encode("utf-8", "replace"), signing_input, digest).digest()
        if hmac.compare_digest(got, want):
            return {"secret": word, "tried": tried, "exhausted": True, "alg": alg}
    return {"secret": None, "tried": tried, "exhausted": True, "alg": alg}


def find_secret_builtin(token: str) -> dict:
    result = find_secret(
        token, BUILTIN_WORDS + ["secret", "jwt", "key", "s3cr3t", "your-256-bit-secret"]
    )
    result["wordlist"] = "built-in common secrets"
    return result


def resign(token: str, secret: str) -> str | None:
    """Re-sign the token's current header+payload with a known HMAC secret."""
    info = decode(token)
    if not info["valid"] or info["alg"] not in HS:
        return None
    sig = hmac.new(secret.encode(), info["signing_input"].encode(), HS[info["alg"]]).digest()
    return f"{info['signing_input']}.{b64url_encode(sig)}"
