import datetime

import pytest

import utils
from modules import ssl_headers
from conftest import FakeResponse, assert_valid_finding, by_id


def cert_expiring_in(days, names=("example.com", "www.example.com"), issuer="Let's Encrypt"):
    exp = ssl_headers._utcnow() + datetime.timedelta(days=days, hours=1)
    return {
        "notAfter": exp.strftime("%b %d %H:%M:%S %Y GMT"),
        "subject": ((("commonName", names[0]),),),
        "subjectAltName": tuple(("DNS", n) for n in names),
        "issuer": ((("countryName", "US"),), (("organizationName", issuer),)),
    }


ALL_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "SAMEORIGIN",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
    "Server": "nginx",
}


@pytest.fixture
def site(monkeypatch):
    """Configurable fake site: TLS handshake result + HTTP(S) responses."""
    state = {
        "cert": cert_expiring_in(80), "version": "TLSv1.3", "err": None,
        "novalidate": (None, None, None, None),
        "https": FakeResponse(headers=dict(ALL_HEADERS), url="https://example.com/"),
        "http": FakeResponse(url="https://example.com/"),
    }
    monkeypatch.setattr(ssl_headers, "_get_certificate",
                        lambda d: (state["cert"], state["version"], None, state["err"]))
    monkeypatch.setattr(ssl_headers, "_get_certificate_novalidate", lambda d: state["novalidate"])
    monkeypatch.setattr(utils, "fetch_url",
                        lambda url, timeout=8: state["http"] if url.startswith("http://") else state["https"])
    return state


# --- helpers ---------------------------------------------------------------------

@pytest.mark.parametrize("domain,names,ok", [
    ("example.com", ["example.com"], True),
    ("www.example.com", ["*.example.com"], True),
    ("example.com", ["*.example.com"], False),        # wildcard does not cover apex
    ("a.b.example.com", ["*.example.com"], False),    # wildcard covers one label only
    ("evil.com", ["example.com"], False),
])
def test_name_matches(domain, names, ok):
    assert ssl_headers._name_matches(domain, names) is ok


def test_cert_names_and_issuer():
    c = cert_expiring_in(10)
    assert ssl_headers._cert_names(c) == ["example.com", "example.com", "www.example.com"]
    assert ssl_headers._issuer_org(c) == "Let's Encrypt"
    assert ssl_headers._issuer_org({}) == "inconnu"


def test_parse_cert_datetime():
    assert ssl_headers._parse_cert_datetime("Jun  1 12:00:00 2026 GMT") == datetime.datetime(2026, 6, 1, 12)


# --- full scan -------------------------------------------------------------------

def test_healthy_site_has_no_penalties(site):
    findings = ssl_headers.scan("example.com", "https://example.com")
    for f in findings:
        assert_valid_finding(f)
    bad = [f for f in findings if f["status"] in ("fail", "warn")]
    assert bad == []
    assert by_id(findings, "ssl_protocol")["title"].endswith("TLSv1.3")


@pytest.mark.parametrize("days,status,severity", [
    (-3, "fail", "critique"), (10, "warn", "eleve"), (20, "warn", "moyen"), (60, "pass", "ok"),
])
def test_certificate_expiry_thresholds(site, days, status, severity):
    site["cert"] = cert_expiring_in(days)
    f = by_id(ssl_headers.scan("example.com", ""), "ssl_expiry")
    assert (f["status"], f["severity"]) == (status, severity)


def test_obsolete_tls_version_fails(site):
    site["version"] = "TLSv1"
    f = by_id(ssl_headers.scan("example.com", ""), "ssl_protocol")
    assert (f["status"], f["severity"]) == ("fail", "eleve")


def test_name_mismatch_fails(site):
    site["cert"] = cert_expiring_in(80, names=("other.org",))
    assert by_id(ssl_headers.scan("example.com", ""), "ssl_name_match")["status"] == "fail"


def test_no_https_at_all(site):
    site["cert"], site["version"], site["err"] = None, None, "Connection refused"
    findings = ssl_headers.scan("example.com", "")
    f = by_id(findings, "ssl_https_absent")
    assert (f["status"], f["severity"]) == ("fail", "critique")


def test_broken_chain_with_valid_leaf(site):
    site["cert"], site["version"] = None, None
    site["err"] = "certificate verify failed: certificate has expired"
    site["novalidate"] = (cert_expiring_in(80), "TLSv1.3", None, b"der")
    f = by_id(ssl_headers.scan("example.com", ""), "ssl_cert_invalide")
    assert (f["severity"], f["status"]) == ("eleve", "fail")
    assert "incomplete" in f["title"]


def test_self_signed_is_critical(site):
    site["cert"], site["version"] = None, None
    site["err"] = "certificate verify failed: self-signed certificate"
    site["novalidate"] = (cert_expiring_in(80), "TLSv1.2", None, b"der")
    f = by_id(ssl_headers.scan("example.com", ""), "ssl_cert_invalide")
    assert f["severity"] == "critique"


def test_missing_headers_and_version_disclosure(site):
    site["https"] = FakeResponse(headers={"Server": "Apache/2.4.41", "X-Powered-By": "PHP/7.4"})
    findings = ssl_headers.scan("example.com", "https://example.com")
    for hid, sev in [("hdr_hsts", "moyen"), ("hdr_csp", "moyen"), ("hdr_xfo", "faible"),
                     ("hdr_xcto", "faible"), ("hdr_referrer", "faible"), ("hdr_permissions", "faible")]:
        f = by_id(findings, hid)
        assert (f["status"], f["severity"]) == ("fail", sev)
    assert by_id(findings, "hdr_server_version")["status"] == "warn"


def test_no_http_to_https_redirect(site):
    site["http"] = FakeResponse(url="http://example.com/")
    assert by_id(ssl_headers.scan("example.com", ""), "hdr_http_redirect")["status"] == "fail"


def test_site_unreachable_for_headers(site):
    site["https"] = None
    assert by_id(ssl_headers.scan("example.com", ""), "hdr_unreachable")["status"] == "warn"


def test_real_tls_helper_fails_gracefully_without_network():
    # The autouse fixture blocks sockets: the helper must report an error, not raise.
    cert, version, cipher, err = ssl_headers._get_certificate("example.com")
    assert cert is None and err
