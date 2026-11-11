from domainscope.modules.asn import origin_query_name, parse_as_name, parse_origin
from domainscope.modules.rdap import parse_rdap
from domainscope.modules.subdomains import clean_names, is_takeover_candidate


def test_clean_names_filters_and_dedupes():
    raw = [
        "*.example.com\nwww.example.com",
        "API.example.com.",
        "user@example.com",
        "evil-example.com",
        "example.com.attacker.net",
        "deep.sub.example.com",
    ]
    assert clean_names(raw, "example.com") == [
        "api.example.com",
        "deep.sub.example.com",
        "example.com",
        "www.example.com",
    ]


def test_takeover_candidates():
    assert is_takeover_candidate("myorg.github.io")
    assert is_takeover_candidate("app.herokuapp.com.")
    assert not is_takeover_candidate("github.io.evil.com")
    assert not is_takeover_candidate(None)


def test_cymru_query_names():
    assert origin_query_name("8.8.4.4") == "4.4.8.8.origin.asn.cymru.com"
    assert origin_query_name("10.0.0.1") is None
    v6 = origin_query_name("2001:4860:4860::8888")
    assert v6.endswith(".origin6.asn.cymru.com") and v6.startswith("8.8.8.8.0.0.0.0")


def test_cymru_parsers():
    origin = parse_origin("15169 | 8.8.8.0/24 | US | arin | 2023-12-28")
    assert origin == {"asn": "15169", "prefix": "8.8.8.0/24", "country": "US", "registry": "arin"}
    assert parse_as_name("15169 | US | arin | 2000-03-30 | GOOGLE, US") == "GOOGLE, US"


def test_parse_rdap():
    data = {
        "ldhName": "EXAMPLE.COM",
        "status": ["client transfer prohibited"],
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2099-08-13T04:00:00Z"},
        ],
        "nameservers": [{"ldhName": "B.IANA-SERVERS.NET"}, {"ldhName": "A.IANA-SERVERS.NET"}],
        "secureDNS": {"delegationSigned": True},
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [["version", {}, "text", "4.0"], ["fn", {}, "text", "RESERVED-IANA"]],
                ],
                "entities": [
                    {
                        "roles": ["abuse"],
                        "vcardArray": ["vcard", [["email", {}, "text", "abuse@iana.org"]]],
                    }
                ],
            }
        ],
    }
    r = parse_rdap(data)
    assert r["domain"] == "example.com"
    assert r["registrar"] == "RESERVED-IANA"
    assert r["abuse_email"] == "abuse@iana.org"
    assert r["nameservers"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert r["dnssec_signed"] is True
    assert r["age_days"] > 10000
    assert r["days_to_expiry"] > 0
