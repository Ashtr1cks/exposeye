"""TLS certificate inspection using only the standard library."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

import certifi


def _name_dict(name_tuple) -> dict:
    out = {}
    for rdn in name_tuple or ():
        for key, value in rdn:
            out[key] = value
    return out


def inspect(host: str, port: int = 443, timeout: float = 10) -> dict:
    # Use Mozilla's CA bundle (same as requests) so results don't depend on the OS trust store,
    # which on Windows is often missing roots until something else triggers a fetch.
    ctx = ssl.create_default_context(cafile=certifi.where())
    result = {"host": host, "port": port, "valid": False}
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                result["protocol"] = tls.version()
                result["cipher"] = (tls.cipher() or (None,))[0]
    except ssl.SSLCertVerificationError as exc:
        result["error"] = exc.verify_message or str(exc)
        return result
    except (OSError, ssl.SSLError) as exc:
        result["error"] = str(exc) or exc.__class__.__name__
        return result

    not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    not_before = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), timezone.utc)
    subject = _name_dict(cert.get("subject"))
    issuer = _name_dict(cert.get("issuer"))
    result.update(
        {
            "valid": True,
            "subject_cn": subject.get("commonName"),
            "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_left": (not_after - datetime.now(timezone.utc)).days,
            "san": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"],
        }
    )
    return result


def findings(tls: dict) -> list[tuple[str, str, str]]:
    host = tls["host"]
    if tls.get("error"):
        if "refused" in tls["error"].lower() or "timed out" in tls["error"].lower():
            return []
        return [("high", f"TLS certificate problem on {host}", tls["error"])]
    days = tls.get("days_left")
    if days is not None and days < 14:
        return [("medium", f"TLS certificate on {host} expires in {days} days", tls["not_after"])]
    if tls.get("protocol") in ("TLSv1", "TLSv1.1", "SSLv3"):
        return [("medium", f"Legacy TLS negotiated on {host}", tls["protocol"])]
    return []
