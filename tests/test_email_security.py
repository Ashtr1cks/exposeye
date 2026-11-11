from exposeye.modules.email_security import findings, parse_dmarc, parse_spf


def titles(email):
    return {title for _, title, _ in findings(email)}


def test_parse_spf_basic():
    spf = parse_spf("v=spf1 include:_spf.google.com mx -all")
    assert spf["all"] == "-"
    assert spf["includes"] == ["_spf.google.com"]
    assert spf["lookup_count"] == 2  # include + mx; 'all' must not count


def test_parse_spf_implicit_plus_all():
    assert parse_spf("v=spf1 ip4:1.2.3.4 all")["all"] == "+"


def test_parse_spf_counts_lookup_terms():
    spf = parse_spf("v=spf1 a a:x.com mx/24 ptr exists:%{i}.x.com ip4:1.1.1.1 redirect=x.com")
    assert spf["lookup_count"] == 6


def test_parse_dmarc():
    d = parse_dmarc("v=DMARC1; p=Reject; sp=none; pct=50; rua=mailto:a@b.com")
    assert d["policy"] == "reject"
    assert d["subdomain_policy"] == "none"
    assert d["pct"] == 50
    assert d["rua"] == "mailto:a@b.com"


def test_findings_missing_everything_with_mx():
    email = {"has_mx": True, "spf": None, "spf_record_count": 0, "dmarc": None, "mta_sts": False}
    sev = {title: s for s, title, _ in findings(email)}
    assert sev["No SPF record"] == "medium"
    assert sev["No DMARC record"] == "medium"
    assert "No MTA-STS policy" in sev


def test_findings_plus_all_is_high():
    email = {
        "has_mx": True,
        "spf": parse_spf("v=spf1 +all"),
        "spf_record_count": 1,
        "dmarc": parse_dmarc("v=DMARC1; p=reject; rua=mailto:x@y.z"),
        "mta_sts": True,
    }
    out = findings(email)
    assert ("high", "SPF allows all senders (+all)", "v=spf1 +all") in out


def test_findings_strict_config_is_clean():
    email = {
        "has_mx": True,
        "spf": parse_spf("v=spf1 mx -all"),
        "spf_record_count": 1,
        "dmarc": parse_dmarc("v=DMARC1; p=reject; rua=mailto:x@y.z"),
        "mta_sts": True,
    }
    assert findings(email) == []
