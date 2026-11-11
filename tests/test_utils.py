import pytest

from exposeye.utils import normalize_domain


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("example.com", "example.com"),
        ("  Example.COM.  ", "example.com"),
        ("https://www.example.com/path?q=1", "www.example.com"),
        ("example.com:8443/login", "example.com"),
        ("*.example.com", "example.com"),
        ("bücher.de", "xn--bcher-kva.de"),
    ],
)
def test_normalize_domain(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "localhost", "-bad-.com", "1.2.3.4", "exa mple.com"])
def test_normalize_domain_rejects(raw):
    with pytest.raises(ValueError):
        normalize_domain(raw)
