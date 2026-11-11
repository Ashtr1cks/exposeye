from exposeye.modules.http_probe import analyze_headers, extract_title, fingerprint
from exposeye.report import to_html, to_json, to_markdown


def test_analyze_headers_missing_and_leaks():
    headers = {"Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/7.4.3"}
    out = analyze_headers(headers, is_https=True)
    missing = {m["header"] for m in out["missing"]}
    assert "strict-transport-security" in missing
    assert "content-security-policy" in missing
    assert "Server: Apache/2.4.41 (Ubuntu)" in out["leaks"]
    assert any(leak.startswith("x-powered-by") for leak in out["leaks"])


def test_analyze_headers_hsts_only_matters_on_https():
    out = analyze_headers({}, is_https=False)
    assert "strict-transport-security" not in {m["header"] for m in out["missing"]}


def test_csp_frame_ancestors_covers_xfo():
    out = analyze_headers({"Content-Security-Policy": "frame-ancestors 'none'"}, is_https=True)
    assert "x-frame-options" not in {m["header"] for m in out["missing"]}


def test_fingerprint():
    headers = {"Server": "cloudflare", "CF-RAY": "abc", "X-Powered-By": "PHP/8.2"}
    body = '<link href="/wp-content/themes/x/style.css"><script src="jquery.min.js">'
    assert fingerprint(headers, body) == ["Cloudflare", "PHP", "WordPress", "jQuery"]


def test_extract_title():
    assert extract_title("<html><TITLE>\n Hello &amp; welcome </TITLE>") == "Hello & welcome"
    assert extract_title("<html></html>") is None


SAMPLE = {
    "meta": {
        "tool": "exposeye",
        "version": "0.1.0",
        "domain": "example.com",
        "started": "2026-01-01T00:00:00+00:00",
        "duration_s": 1.2,
        "options": {"passive": False},
    },
    "rdap": None,
    "dns": {
        "records": {"A": ["93.184.215.14"], "TXT": ["<script>alert(1)</script>"]},
        "dnssec": True,
        "wildcard_ips": [],
    },
    "email": {"has_mx": False, "spf": None, "dmarc": None, "mta_sts": False, "tls_rpt": False},
    "hosts": [
        {
            "name": "example.com",
            "ips": ["93.184.215.14"],
            "cname": None,
            "dangling": False,
            "wildcard": False,
            "interesting": False,
            "from_ct": True,
            "asn": ["AS15133 EDGECAST"],
        }
    ],
    "http": [],
    "tls": [],
    "findings": [{"severity": "low", "module": "email", "title": "No SPF record", "detail": "a|b"}],
    "errors": {},
    "summary": {
        "findings": {"high": 0, "medium": 0, "low": 1, "info": 0},
        "hosts_total": 1,
        "hosts_live": 1,
        "unique_ips": 1,
        "networks": 1,
        "hosts_probed": 0,
        "truncated": False,
    },
}


def test_html_report_escapes_untrusted_data():
    html = to_html(SAMPLE)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "AS15133 EDGECAST" in html


def test_markdown_and_json_render():
    md = to_markdown(SAMPLE)
    assert "# exposeye report: example.com" in md
    assert "a\\|b" in md  # pipes escaped inside tables
    assert '"domain": "example.com"' in to_json(SAMPLE)
