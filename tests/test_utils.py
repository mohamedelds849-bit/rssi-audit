import subprocess
import types

import pytest

import utils


@pytest.mark.parametrize("raw,clean", [
    ("example.com", "example.com"),
    ("https://Example.COM/blog/?x=1#top", "example.com"),
    ("http://www.example.com:8080/", "www.example.com"),
    ("  example.com.  ", "example.com"),
])
def test_normalize(raw, clean):
    d, base = utils.normalize(raw)
    assert d == clean
    assert base == "https://" + clean


@pytest.mark.parametrize("domain,ok", [
    ("example.com", True), ("sub.example.co.uk", True), ("xn--bcher-kva.example", True),
    ("localhost", False), ("192.168.1.1", False), ("", False), ("-bad.com", False),
    ("bad-.com", False), ("not a domain", False), ("a" * 64 + ".com", False),
])
def test_is_valid_domain(domain, ok):
    assert utils.is_valid_domain(domain) is ok


NSLOOKUP_OUTPUT = """Server:  dns.example
Address:  10.0.0.1

example.com\ttext =

\t"v=spf1 include:_spf.example.net ~all"
example.com\ttext = "google-site-verification=abc"
example.com descriptive text "part1" "part2"
"""


def test_parse_nslookup_txt_windows_and_unix_formats():
    recs = utils._parse_nslookup_txt(NSLOOKUP_OUTPUT)
    assert "v=spf1 include:_spf.example.net ~all" in recs
    assert "google-site-verification=abc" in recs
    assert "part1part2" in recs  # split TXT strings are concatenated
    assert not any(r.lower().startswith(("server", "address")) for r in recs)


def test_dns_txt_uses_dnspython(monkeypatch):
    import dns.resolver
    rdata = types.SimpleNamespace(strings=[b"v=DMARC1; ", b"p=reject"])
    monkeypatch.setattr(dns.resolver, "resolve", lambda d, t: [rdata])
    assert utils.dns_txt("_dmarc.example.com") == ["v=DMARC1; p=reject"]


def test_dns_txt_falls_back_to_nslookup(monkeypatch):
    import dns.resolver

    def boom(*a, **k):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns.resolver, "resolve", boom)
    fake = types.SimpleNamespace(stdout='example.com text = "v=spf1 -all"\n', stderr="")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: fake)
    assert utils.dns_txt("example.com") == ["v=spf1 -all"]


def test_dns_txt_empty_domain():
    assert utils.dns_txt("") == []


def test_fetch_url_never_raises(monkeypatch):
    def boom(*a, **k):
        raise utils.requests.ConnectionError("down")

    monkeypatch.setattr(utils.requests, "get", boom)
    assert utils.fetch_url("https://example.com") is None


def test_fetch_url_retries_without_tls_verification(monkeypatch):
    calls = []

    def get(url, **kw):
        calls.append(kw["verify"])
        if kw["verify"]:
            raise utils.requests.exceptions.SSLError("bad cert")
        return "RESP"

    monkeypatch.setattr(utils.requests, "get", get)
    assert utils.fetch_url("https://example.com") == "RESP"
    assert calls == [True, False]
