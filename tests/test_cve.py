import pytest

import utils
from modules import cve
from conftest import FakeResponse, assert_valid_finding, by_id


def nvd_item(cve_id, score, version="31"):
    key = {"31": "cvssMetricV31", "30": "cvssMetricV30"}.get(version)
    metrics = {}
    if key:
        metrics[key] = [{"cvssData": {"baseScore": score, "baseSeverity": "HIGH"}}]
    elif version == "2":
        metrics["cvssMetricV2"] = [{"cvssData": {"baseScore": score}, "baseSeverity": "HIGH"}]
    return {"cve": {"id": cve_id, "metrics": metrics,
                    "descriptions": [{"lang": "es", "value": "x"},
                                     {"lang": "en", "value": "  A   bug\n here "}]}}


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(cve.time, "sleep", lambda s: None)


# --- detection / parsing -----------------------------------------------------

def test_extract_server_version():
    assert cve._extract_server_version("Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f") == [
        ("Apache 2.4.41", "apache 2.4.41", "2.4.41"),
        ("OpenSSL 1.1.1", "openssl 1.1.1", "1.1.1"),
    ]
    assert cve._extract_server_version("LiteSpeed") == []
    assert cve._extract_server_version("") == []


def test_extract_powered_by():
    assert cve._extract_powered_by("PHP/8.3.33") == [("PHP 8.3.33", "php 8.3.33", "8.3.33")]


def test_extract_generator():
    html = '<head><meta name="generator" content="WordPress 6.8.1" />' \
           "<meta name='generator' content='Site Kit by Google'></head>"
    techs = cve._extract_generator(html)
    assert ("WordPress 6.8.1", "wordpress 6.8.1", "6.8.1") in techs
    assert ("Site Kit by Google", "site kit by google", "") in techs


def test_detect_technologies_deduplicates():
    headers = {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.3"}
    html = '<meta name="generator" content="WordPress 5.8">'
    detected = cve._detect_technologies(headers, html)
    assert [d[3] for d in detected] == ["Server", "X-Powered-By", "generator"]
    assert cve._detect_technologies({"Server": "nginx/1.18.0 nginx/1.18.0"}, "") == [
        ("nginx 1.18.0", "nginx 1.18.0", "1.18.0", "Server")]


@pytest.mark.parametrize("score,sev", [
    (9.8, "critique"), (9.0, "critique"), (7.5, "eleve"), (4.0, "moyen"),
    (3.9, "faible"), ("n/a", "faible"),
])
def test_severity_from_cvss(score, sev):
    assert cve._severity_from_cvss(score) == sev


def test_extract_cvss_prefers_v31_then_falls_back():
    assert cve._extract_cvss(nvd_item("A", 9.8, "31")["cve"]) == (9.8, "HIGH")
    assert cve._extract_cvss(nvd_item("B", 5.0, "2")["cve"])[0] == 5.0
    assert cve._extract_cvss({"metrics": {}}) == (None, "")


def test_english_summary_is_normalized():
    assert cve._english_summary(nvd_item("A", 1)["cve"]) == "A bug here"


def test_cpe_for_known_and_unknown():
    assert cve._cpe_for("PHP") == "php:php"
    assert cve._cpe_for("elementor") is None


# --- NVD query building --------------------------------------------------------

def test_query_nvd_uses_precise_cpe_for_known_products(monkeypatch):
    captured = {}

    def fake_get(url, params=None, headers=None, timeout=None):
        captured.update(params)
        return FakeResponse(json_data={"vulnerabilities": [nvd_item("CVE-1", 7.5)]})

    monkeypatch.setattr(utils.requests, "get", fake_get)
    cves, err, precise = cve._query_nvd("php", "7.4.3", True)
    assert err is None and precise is True
    assert captured["virtualMatchString"] == "cpe:2.3:a:php:php:7.4.3:*:*:*:*:*:*:*"
    assert cves[0]["id"] == "CVE-1"


def test_query_nvd_keyword_fallback_and_rate_limit_retry(monkeypatch):
    calls = []

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append(dict(params))
        if len(calls) == 1:
            return FakeResponse(status_code=429)
        return FakeResponse(json_data={"vulnerabilities": []})

    monkeypatch.setattr(utils.requests, "get", fake_get)
    cves, err, precise = cve._query_nvd("elementor", "3.0", False)
    assert precise is False and err is None and cves == []
    assert calls[0]["keywordSearch"] == "elementor 3.0"
    assert len(calls) == 2


def test_query_nvd_http_error(monkeypatch):
    monkeypatch.setattr(utils.requests, "get", lambda *a, **k: FakeResponse(status_code=500))
    assert cve._query_nvd("php", "8.0", True)[1] == "NVD HTTP 500"


# --- full scan -------------------------------------------------------------------

def test_scan_no_version_exposed_is_a_pass(monkeypatch):
    resp = FakeResponse(headers={"Server": "cloudflare"}, text='<link href="/wp-content/x.css">')
    monkeypatch.setattr(utils, "fetch_url", lambda url, timeout=8: resp)
    findings = cve.scan("example.com", "https://example.com")
    assert [f["id"] for f in findings] == ["cve_no_version"]
    assert findings[0]["status"] == "pass"
    assert "wp-content" in findings[0]["evidence"]


def test_scan_unreachable_site(monkeypatch):
    monkeypatch.setattr(utils, "fetch_url", lambda url, timeout=8: None)
    assert cve.scan("example.com", "https://example.com")[0]["id"] == "cve_fetch"


def test_scan_precise_match_keeps_cvss_severity(monkeypatch):
    resp = FakeResponse(headers={"X-Powered-By": "PHP/7.4.3"})
    monkeypatch.setattr(utils, "fetch_url", lambda url, timeout=8: resp)
    monkeypatch.setattr(utils.requests, "get", lambda *a, **k: FakeResponse(
        json_data={"vulnerabilities": [nvd_item("CVE-LOW", 5.3), nvd_item("CVE-CRIT", 9.8)]}))
    findings = cve.scan("example.com", "https://example.com")
    for f in findings:
        assert_valid_finding(f)
    assert by_id(findings, "cve_versions_exposees")["status"] == "warn"
    hit = by_id(findings, "cve_php_7_4_3")
    assert hit["severity"] == "critique"
    assert "9.8" in hit["title"]
    assert hit["evidence"].startswith("CVE-CRIT")  # worst CVE listed first


def test_scan_keyword_match_is_downgraded(monkeypatch):
    """Approximate keyword matches are capped at 'moyen' to limit false positives."""
    resp = FakeResponse(text='<meta name="generator" content="Elementor 3.0.1">')
    monkeypatch.setattr(utils, "fetch_url", lambda url, timeout=8: resp)
    monkeypatch.setattr(utils.requests, "get", lambda *a, **k: FakeResponse(
        json_data={"vulnerabilities": [nvd_item("CVE-X", 9.8)]}))
    hit = by_id(cve.scan("example.com", "https://example.com"), "cve_elementor_3_0_1")
    assert hit["severity"] == "moyen"
    assert "A VERIFIER" in hit["title"]


def test_scan_nvd_unavailable_is_info(monkeypatch):
    resp = FakeResponse(headers={"Server": "nginx/1.18.0"})
    monkeypatch.setattr(utils, "fetch_url", lambda url, timeout=8: resp)

    def boom(*a, **k):
        raise utils.requests.ConnectionError("down")

    monkeypatch.setattr(utils.requests, "get", boom)
    hit = by_id(cve.scan("example.com", "https://example.com"), "cve_nvd_error_nginx_1_18_0")
    assert hit["status"] == "info"
