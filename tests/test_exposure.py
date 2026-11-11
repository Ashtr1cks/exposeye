import copy

from domainscope.modules import exposure
from domainscope.monitor.diff import diff
from domainscope.report import to_html, to_markdown


class FakeResp:
    def __init__(self, status, data):
        self.status_code = status
        self._data = data

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    """Answers InternetDB, KEV and EPSS URLs from canned data."""

    def __init__(self, internetdb, kev=None, epss=None):
        self.internetdb, self.kev, self.epss = internetdb, kev or [], epss or {}
        self.calls = []

    def get(self, url, params=None, timeout=None, **kw):
        self.calls.append(url)
        if "internetdb" in url:
            ip = url.rsplit("/", 1)[1]
            if ip in self.internetdb:
                return FakeResp(200, self.internetdb[ip])
            return FakeResp(404, {"detail": "No information available"})
        if "known_exploited" in url:
            return FakeResp(200, {"vulnerabilities": self.kev})
        if "epss" in url:
            cves = params["cve"].split(",")
            return FakeResp(
                200,
                {
                    "data": [
                        {"cve": c, "epss": str(self.epss[c]), "percentile": "0.9"}
                        for c in cves
                        if c in self.epss
                    ]
                },
            )
        raise AssertionError(url)


IDB = {
    "93.184.215.14": {
        "ip": "93.184.215.14",
        "ports": [443, 3389, 80],
        "cpes": [],
        "hostnames": [],
        "tags": ["eol-os"],
        "vulns": ["CVE-2021-40438", "CVE-2017-9798", "CVE-2012-0001"],
    },
    "93.184.215.15": {
        "ip": "93.184.215.15",
        "ports": [443],
        "cpes": [],
        "hostnames": [],
        "tags": [],
        "vulns": [],
    },
}
KEV = [
    {
        "cveID": "CVE-2021-40438",
        "vulnerabilityName": "Apache SSRF",
        "vendorProject": "Apache",
        "product": "HTTP Server",
        "dateAdded": "2021-12-01",
        "knownRansomwareCampaignUse": "Known",
    }
]
EPSS = {"CVE-2021-40438": 0.97, "CVE-2017-9798": 0.2, "CVE-2012-0001": 0.001}


def test_parse_internetdb_handles_no_data():
    assert exposure.parse_internetdb({"detail": "No information available"}) is None
    parsed = exposure.parse_internetdb(IDB["93.184.215.14"])
    assert parsed["ports"] == [80, 443, 3389]  # sorted


def test_cve_priority():
    assert exposure.cve_priority({"kev": True, "epss": 0.0}) == "high"
    assert exposure.cve_priority({"epss": 0.6}) == "high"
    assert exposure.cve_priority({"epss": 0.15}) == "medium"
    assert exposure.cve_priority({"epss": 0.01}) == "low"
    assert exposure.cve_priority({}) == "low"


def test_collect_enriches_and_skips_private_ips(tmp_path, monkeypatch):
    monkeypatch.setattr(exposure, "_kev_memory", None)
    s = FakeSession(IDB, KEV, EPSS)
    exp = exposure.collect(
        ["93.184.215.14", "93.184.215.15", "10.0.0.5", "8.8.4.4"], s, cache_dir=tmp_path
    )
    assert not any("10.0.0.5" in c for c in s.calls)  # private IPs never sent
    assert exp["checked"] == 3 and exp["ok"]
    assert set(exp["ips"]) == {"93.184.215.14", "93.184.215.15"}  # 8.8.4.4 had no data
    cve = exp["cves"]["CVE-2021-40438"]
    assert cve["kev"] and cve["ransomware"] and cve["priority"] == "high"
    assert exp["cves"]["CVE-2017-9798"]["priority"] == "medium"
    assert (tmp_path / "kev.json").exists()  # cached for next time


def test_findings_group_by_port_and_priority(tmp_path, monkeypatch):
    monkeypatch.setattr(exposure, "_kev_memory", None)
    exp = exposure.collect(list(IDB), FakeSession(IDB, KEV, EPSS), cache_dir=tmp_path)
    out = exposure.findings(exp, {"93.184.215.14": ["example.com"]})
    titles = {(sev, title) for sev, title, _ in out}
    assert ("high", "RDP (port 3389) exposed to the internet") in titles
    assert ("high", "Known-exploited vulnerabilities (CISA KEV): 1") in titles
    assert ("medium", "Vulnerabilities with elevated exploit risk: 1") in titles
    assert ("low", "Other reported vulnerabilities: 1") in titles
    assert ("medium", "End-of-life software detected") in titles
    rdp = next(d for _, t, d in out if t.startswith("RDP"))
    assert "example.com (93.184.215.14)" in rdp
    kev = next(d for _, t, d in out if t.startswith("Known-exploited"))
    assert "used by ransomware: CVE-2021-40438" in kev


def test_lookup_failures_are_reported_not_fatal(tmp_path):
    class Broken(FakeSession):
        def get(self, url, **kw):
            raise ConnectionError("network down")

    exp = exposure.collect(["93.184.215.14"], Broken({}), cache_dir=tmp_path)
    assert exp["ok"] is False and exp["failed"] == 1
    assert "network down" in exp["errors"]["internetdb"]


def _scan(exp):
    return {
        "meta": {"kind": "domain", "domain": "example.com", "options": {"passive": True}},
        "hosts": [],
        "findings": [],
        "exposure": exp,
    }


def _exp(ports, vulns, cves=None):
    return {
        "ok": True,
        "ips": {"93.184.215.14": {"ports": ports, "vulns": vulns, "tags": []}},
        "cves": cves or {},
    }


def test_diff_new_ports_and_cves():
    old = _scan(_exp([443], ["CVE-1"]))
    new = _scan(
        _exp(
            [443, 3389, 8080],
            ["CVE-1", "CVE-2", "CVE-3"],
            {"CVE-2": {"kev": True, "priority": "high"}, "CVE-3": {"priority": "low"}},
        )
    )
    changes = {c["title"]: c for c in diff(old, new)}
    assert changes["Risky port(s) newly opened: 1"]["severity"] == "high"
    assert "RDP (3389)" in changes["Risky port(s) newly opened: 1"]["detail"]
    assert changes["New open port(s): 1"]["severity"] == "low"
    assert changes["New known-exploited vulnerabilities: 1"]["severity"] == "high"
    assert changes["New reported vulnerabilities: 1"]["severity"] == "low"

    back = {c["title"]: c for c in diff(new, old)}
    assert back["Port(s) closed: 2"]["improvement"] is True
    assert back["Vulnerabilities no longer reported: 2"]["improvement"] is True


def test_diff_skips_failed_exposure_lookups():
    old = _scan(_exp([443], []))
    new = _scan({**_exp([443, 3389], []), "ok": False})
    assert diff(old, new) == []
    assert diff(_scan(None), _scan(_exp([3389], []))) == []


def test_reports_include_exposure():
    exp = _exp([3389], ["CVE-2021-40438"], {"CVE-2021-40438": {"kev": True, "epss": 0.97}})
    result = {
        "meta": {
            "tool": "domainscope",
            "version": "t",
            "domain": "example.com",
            "started": "2026-01-01T00:00:00+00:00",
            "duration_s": 1,
            "options": {"passive": True},
        },
        "rdap": None,
        "dns": {"records": {}, "dnssec": False, "wildcard_ips": []},
        "email": None,
        "hosts": [],
        "http": [],
        "tls": [],
        "findings": [],
        "errors": {},
        "exposure": exp,
        "summary": {
            "findings": {"high": 0, "medium": 0, "low": 0, "info": 0},
            "hosts_total": 0,
            "hosts_live": 0,
            "unique_ips": 1,
            "networks": 0,
        },
    }
    html = to_html(copy.deepcopy(result))
    assert "Open ports &amp; vulnerabilities" in html and "CVE-2021-40438 (KEV) 97%" in html
    md = to_markdown(result)
    assert "| 93.184.215.14 | 3389 | CVE-2021-40438 (KEV) |" in md
