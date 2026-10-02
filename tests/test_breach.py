import utils
from modules import breach
from conftest import FakeResponse, assert_valid_finding, by_id

BREACHES = [
    {"Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com", "BreachDate": "2013-10-04",
     "PwnCount": 152445165, "DataClasses": ["Email addresses", "Passwords"]},
    {"Name": "ExampleShop", "Title": "Example Shop", "Domain": "shop.example.com",
     "BreachDate": "2020-01-01", "PwnCount": 1234, "DataClasses": ["Email addresses"]},
    {"Name": "NoDomain", "Title": "Combo list", "Domain": "", "PwnCount": 5},
    "not-a-dict",
]


def _patch(monkeypatch, resp):
    seen = {}

    def fake_fetch(url, timeout=8):
        seen["url"] = url
        return resp

    monkeypatch.setattr(utils, "fetch_url", fake_fetch)
    return seen


def test_root_label():
    assert breach._root_label("www.example.co") == "example"
    assert breach._root_label("example") == "example"
    assert breach._root_label("") == ""


def test_domain_found_via_subdomain(monkeypatch):
    seen = _patch(monkeypatch, FakeResponse(json_data=BREACHES))
    findings = breach.scan("example.com", "https://example.com")
    for f in findings:
        assert_valid_finding(f)
    # Only the free public endpoint is ever called (never the paid per-account one).
    assert seen["url"] == breach.HIBP_BREACHES_URL
    hit = by_id(findings, "breach_domain_found")
    assert hit["status"] == "fail" and hit["severity"] == "eleve"
    assert "Example Shop" in hit["evidence"] and "Adobe" not in hit["evidence"]
    assert by_id(findings, "breach_world_total")["title"].endswith("4 piratages recenses")


def test_domain_clean(monkeypatch):
    _patch(monkeypatch, FakeResponse(json_data=BREACHES))
    findings = breach.scan("othersite.org", "https://othersite.org")
    assert by_id(findings, "breach_domain_clean")["status"] == "pass"
    assert not [f for f in findings if f["id"] == "breach_domain_found"]


def test_label_alone_is_not_a_match(monkeypatch):
    # "adobe.net" shares the label "adobe" but is a different domain.
    _patch(monkeypatch, FakeResponse(json_data=BREACHES))
    findings = breach.scan("adobe.net", "https://adobe.net")
    assert by_id(findings, "breach_domain_clean")


def test_api_unreachable(monkeypatch):
    _patch(monkeypatch, None)
    findings = breach.scan("example.com", "https://example.com")
    assert [f["id"] for f in findings] == ["breach_api_unavailable"]
    assert findings[0]["status"] == "info"


def test_api_http_error(monkeypatch):
    _patch(monkeypatch, FakeResponse(status_code=503))
    findings = breach.scan("example.com", "https://example.com")
    assert findings[0]["id"] == "breach_api_unavailable"
    assert "503" in findings[0]["evidence"]


def test_api_unexpected_format(monkeypatch):
    _patch(monkeypatch, FakeResponse(json_data={"error": "nope"}))
    assert breach.scan("example.com", "")[0]["id"] == "breach_api_unavailable"
