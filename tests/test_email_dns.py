import pytest

import utils
from modules import email_dns
from conftest import assert_valid_finding, by_id


@pytest.fixture
def fake_dns(monkeypatch):
    """Install a fake DNS zone: {name: [TXT...]} plus an MX list."""
    zone = {"txt": {}, "mx": []}
    monkeypatch.setattr(utils, "dns_txt", lambda name: list(zone["txt"].get(name, [])))
    monkeypatch.setattr(email_dns, "_dns_records",
                        lambda name, rtype: list(zone["mx"]) if rtype == "MX" else [])
    return zone


# --- pure parsing helpers ---------------------------------------------------

@pytest.mark.parametrize("spf,qual", [
    ("v=spf1 include:_spf.google.com -all", "-all"),
    ("v=spf1 mx ~all", "~all"),
    ("v=spf1 ?all", "?all"),
    ("v=spf1 +all", "+all"),
    ("v=spf1 a all", "all"),
    ("v=spf1 include:x.example", None),
    (None, None),
])
def test_spf_qualifier(spf, qual):
    assert email_dns._spf_qualifier(spf) == qual


def test_find_spf_ignores_other_txt():
    recs = ["google-site-verification=abc", "V=SPF1 -all"]
    assert email_dns._find_spf(recs) == "V=SPF1 -all"
    assert email_dns._find_spf(["hello"]) is None


@pytest.mark.parametrize("rec,policy", [
    ("v=DMARC1; p=reject; rua=mailto:a@example.com", "reject"),
    ("v=DMARC1;p=Quarantine", "quarantine"),
    ("v=DMARC1; p=none", "none"),
    ("v=DMARC1; rua=mailto:a@example.com", None),
])
def test_dmarc_policy(rec, policy):
    assert email_dns._find_dmarc([rec]) == rec
    assert email_dns._dmarc_policy(rec) == policy


def test_parse_nslookup_mx():
    out = ("example.com  MX preference = 10, mail exchanger = mx1.example.net\n"
           "example.com  mail exchanger = mx2.example.net\n"
           "Server: 1.1.1.1\n")
    assert email_dns._parse_nslookup_generic(out, "MX") == ["10 mx1.example.net", "mx2.example.net"]


# --- full scan with mocked DNS ---------------------------------------------

def test_well_protected_domain(fake_dns):
    fake_dns["txt"]["example.com"] = ["v=spf1 include:_spf.example.net -all"]
    fake_dns["txt"]["_dmarc.example.com"] = ["v=DMARC1; p=reject"]
    fake_dns["txt"]["google._domainkey.example.com"] = ["v=DKIM1; k=rsa; p=MIIB..."]
    fake_dns["mx"] = ["10 mx.example.net."]

    findings = email_dns.scan("example.com", "https://example.com")
    for f in findings:
        assert_valid_finding(f)
    assert by_id(findings, "email_spf")["status"] == "pass"
    assert by_id(findings, "email_dmarc")["status"] == "pass"
    dkim = by_id(findings, "email_dkim")
    assert dkim["status"] == "pass" and "google" in dkim["title"]
    assert by_id(findings, "email_mx")["status"] == "info"


def test_unprotected_domain(fake_dns):
    findings = email_dns.scan("example.com", "https://example.com")
    spf = by_id(findings, "email_spf")
    dmarc = by_id(findings, "email_dmarc")
    assert (spf["status"], spf["severity"]) == ("fail", "eleve")
    assert (dmarc["status"], dmarc["severity"]) == ("fail", "eleve")
    # Unknown DKIM selector must NOT be reported as a failure (could be a false positive).
    assert by_id(findings, "email_dkim")["status"] == "info"
    assert by_id(findings, "email_mx")["status"] == "warn"


def test_softfail_spf_and_monitoring_dmarc(fake_dns):
    fake_dns["txt"]["example.com"] = ["v=spf1 include:_spf.example.net ~all"]
    fake_dns["txt"]["_dmarc.example.com"] = ["v=DMARC1; p=none"]
    findings = email_dns.scan("example.com", "https://example.com")
    assert (by_id(findings, "email_spf")["status"], by_id(findings, "email_spf")["severity"]) == ("warn", "moyen")
    assert (by_id(findings, "email_dmarc")["status"], by_id(findings, "email_dmarc")["severity"]) == ("warn", "eleve")


def test_dns_errors_never_crash(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("resolver exploded")

    monkeypatch.setattr(utils, "dns_txt", boom)
    monkeypatch.setattr(email_dns, "_dns_records", boom)
    findings = email_dns.scan("example.com", "https://example.com")
    assert len(findings) == 4
    for f in findings:
        assert_valid_finding(f)
