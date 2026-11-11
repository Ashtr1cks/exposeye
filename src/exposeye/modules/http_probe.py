"""HTTP probing: reachability, titles, security headers and tech fingerprinting.

This module *does* send requests to the target, so it is skipped in --passive mode.
"""

from __future__ import annotations

import html
import re
import warnings
from collections.abc import Mapping

import requests
from urllib3.exceptions import InsecureRequestWarning

from exposeye.utils import short_error

MAX_BODY = 256_000
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
VERSION_RE = re.compile(r"\d+(\.\d+)+")

# header name -> (severity if missing, human label)
SECURITY_HEADERS = {
    "strict-transport-security": ("low", "Strict-Transport-Security (HSTS)"),
    "content-security-policy": ("low", "Content-Security-Policy"),
    "x-content-type-options": ("info", "X-Content-Type-Options"),
    "x-frame-options": ("info", "X-Frame-Options"),
    "referrer-policy": ("info", "Referrer-Policy"),
    "permissions-policy": ("info", "Permissions-Policy"),
}

# (technology, where, pattern) - where is "header:<name>" or "body"
SIGNATURES = [
    ("Cloudflare", "header:cf-ray", r"."),
    ("Cloudflare", "header:server", r"cloudflare"),
    ("Amazon CloudFront", "header:x-amz-cf-id", r"."),
    ("Amazon S3", "header:server", r"AmazonS3"),
    ("Akamai", "header:server", r"AkamaiGHost"),
    ("Fastly", "header:x-served-by", r"cache-"),
    ("Vercel", "header:x-vercel-id", r"."),
    ("Netlify", "header:server", r"Netlify"),
    ("GitHub Pages", "header:x-github-request-id", r"."),
    ("Microsoft Azure", "header:x-azure-ref", r"."),
    ("Google Cloud", "header:via", r"google"),
    ("nginx", "header:server", r"nginx"),
    ("Apache", "header:server", r"apache"),
    ("Microsoft IIS", "header:server", r"IIS"),
    ("LiteSpeed", "header:server", r"LiteSpeed"),
    ("Caddy", "header:server", r"Caddy"),
    ("PHP", "header:x-powered-by", r"PHP"),
    ("ASP.NET", "header:x-powered-by", r"ASP\.NET"),
    ("ASP.NET", "header:x-aspnet-version", r"."),
    ("Express", "header:x-powered-by", r"Express"),
    ("Next.js", "header:x-powered-by", r"Next\.js"),
    ("Next.js", "body", r"__NEXT_DATA__|/_next/static/"),
    ("Nuxt", "body", r"__NUXT__|/_nuxt/"),
    ("React", "body", r"data-reactroot|react-dom"),
    ("Angular", "body", r"ng-version="),
    ("Vue.js", "body", r"data-v-[0-9a-f]{8}"),
    ("WordPress", "body", r"wp-content/|wp-includes/"),
    ("Drupal", "header:x-drupal-cache", r"."),
    ("Drupal", "body", r"Drupal\.settings|/sites/default/files"),
    ("Joomla", "body", r"/media/jui/|Joomla!"),
    ("Shopify", "header:x-shopid", r"."),
    ("Shopify", "body", r"cdn\.shopify\.com"),
    ("Squarespace", "body", r"static\.squarespace\.com"),
    ("Wix", "header:x-wix-request-id", r"."),
    ("Google Analytics", "body", r"googletagmanager\.com|google-analytics\.com"),
    ("jQuery", "body", r"jquery[.-]"),
    ("Bootstrap", "body", r"bootstrap(\.min)?\.(css|js)"),
]


def _lower_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


def analyze_headers(headers: Mapping[str, str], is_https: bool) -> dict:
    h = _lower_headers(headers)
    missing = []
    for name, (severity, label) in SECURITY_HEADERS.items():
        if name in h:
            continue
        if name == "strict-transport-security" and not is_https:
            continue
        if name == "x-frame-options" and "frame-ancestors" in h.get("content-security-policy", ""):
            continue
        missing.append({"header": name, "label": label, "severity": severity})

    leaks = []
    server = h.get("server", "")
    if VERSION_RE.search(server):
        leaks.append(f"Server: {server}")
    for name in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        if name in h:
            leaks.append(f"{name}: {h[name]}")

    return {
        "present": sorted(n for n in SECURITY_HEADERS if n in h),
        "missing": missing,
        "leaks": leaks,
    }


def fingerprint(headers: Mapping[str, str], body: str) -> list[str]:
    h = _lower_headers(headers)
    found = set()
    for tech, where, pattern in SIGNATURES:
        if where == "body":
            target = body
        else:
            target = h.get(where.split(":", 1)[1], "")
        if target and re.search(pattern, target, re.IGNORECASE):
            found.add(tech)
    return sorted(found)


def extract_title(body: str) -> str | None:
    match = TITLE_RE.search(body)
    if not match:
        return None
    title = html.unescape(" ".join(match.group(1).split()))
    return title[:200] or None


def _fetch(session: requests.Session, url: str, timeout: float, verify: bool = True):
    resp = session.get(url, timeout=timeout, allow_redirects=True, stream=True, verify=verify)
    try:
        raw = resp.raw.read(MAX_BODY, decode_content=True) or b""
    finally:
        resp.close()
    body = raw.decode(resp.encoding or "utf-8", errors="replace")
    return resp, body


def probe(host: str, session: requests.Session, timeout: float = 10) -> dict:
    result = {"host": host, "reachable": False, "errors": []}
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            resp, body = _fetch(session, url, timeout)
        except requests.exceptions.SSLError as exc:
            result["tls_error"] = short_error(exc)
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", InsecureRequestWarning)
                    resp, body = _fetch(session, url, timeout, verify=False)
            except requests.RequestException as exc2:
                result["errors"].append(f"{scheme}: {short_error(exc2)}")
                continue
        except requests.RequestException as exc:
            result["errors"].append(f"{scheme}: {short_error(exc)}")
            continue

        final_https = resp.url.startswith("https://")
        result.update(
            {
                "reachable": True,
                "url": url,
                "final_url": resp.url,
                "status": resp.status_code,
                "redirects": [r.url for r in resp.history],
                "title": extract_title(body),
                "server": resp.headers.get("Server"),
                "content_type": resp.headers.get("Content-Type"),
                "tech": fingerprint(resp.headers, body),
                "headers": analyze_headers(resp.headers, final_https),
            }
        )
        if scheme == "https":
            result["http_redirects_to_https"] = _http_upgrades(host, session, timeout)
        return result
    return result


def _http_upgrades(host: str, session: requests.Session, timeout: float) -> bool | None:
    try:
        resp = session.get(f"http://{host}/", timeout=timeout, allow_redirects=True, stream=True)
        resp.close()
    except requests.RequestException:
        return None  # port 80 closed is fine
    return resp.url.startswith("https://")
