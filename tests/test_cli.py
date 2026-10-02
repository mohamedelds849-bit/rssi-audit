import json
import os

import rssi
import report
import scoring


def test_discover_scanners_finds_all_modules():
    names = [n for n, _ in rssi.discover_scanners()]
    assert names == ["breach", "cve", "email_dns", "ssl_headers"]


def test_discover_scanners_only_and_skip():
    assert [n for n, _ in rssi.discover_scanners(only=["cve"])] == ["cve"]
    assert "cve" not in [n for n, _ in rssi.discover_scanners(skip=["cve"])]


def test_plugin_auto_discovery(tmp_path):
    (tmp_path / "hello.py").write_text(
        "def scan(domain, base_url):\n    return [{'id': 'x', 'status': 'pass'}]\n")
    (tmp_path / "_private.py").write_text("def scan(d, b):\n    return []\n")
    (tmp_path / "noscan.py").write_text("X = 1\n")
    names = [n for n, _ in rssi.discover_scanners(str(tmp_path))]
    assert names == ["hello"]


def test_crashing_scanner_does_not_stop_audit():
    def boom(d, b):
        raise RuntimeError("bug")

    def good(d, b):
        return [{"id": "ok"}, "ignored-non-dict"]

    out = rssi.run_all_scanners([("boom", boom), ("good", good)], "example.com", "https://example.com")
    assert out == [{"id": "ok"}]


def test_compute_evolution():
    assert rssi.compute_evolution([], 50) == (None, None)
    assert rssi.compute_evolution([{"score": 40}, {"score": "bad"}], 55) == (15, 40)


def test_top_problems_order():
    findings = [
        {"severity": "moyen", "status": "fail", "title": "m"},
        {"severity": "eleve", "status": "warn", "title": "ew"},
        {"severity": "eleve", "status": "fail", "title": "ef"},
        {"severity": "critique", "status": "pass", "title": "ignored"},
    ]
    assert [f["title"] for f in rssi.top_problems(findings)] == ["ef", "ew", "m"]


def test_history_roundtrip(tmp_path):
    hist, path = rssi.load_history("example.com", str(tmp_path))
    assert hist == []
    assert rssi.save_history([{"score": 70}], path)
    assert rssi.load_history("example.com", str(tmp_path))[0] == [{"score": 70}]


def test_invalid_domain_exit_code(capsys):
    assert rssi.main(["not a domain"]) == rssi.EXIT_INVALID_DOMAIN
    assert rssi.main([]) == rssi.EXIT_INVALID_DOMAIN


def test_full_audit_offline(tmp_path, monkeypatch):
    """End-to-end pipeline with a stub scanner: report + JSON + history are written."""
    from base import make_finding

    def stub(domain, base_url):
        return [make_finding("t", "Headers", "HSTS absent", "moyen", "fail", "d", "p", "r")]

    monkeypatch.setattr(rssi, "discover_scanners", lambda only=None, skip=None: [("stub", stub)])
    out_json = tmp_path / "out.json"
    code = rssi.audit("https://Example.com/", output_dir=str(tmp_path / "rep"),
                      data_dir=str(tmp_path / "data"), json_path=str(out_json))
    assert code == 0
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["domain"] == "example.com" and data["score"]["score"] == 88
    assert os.path.isfile(tmp_path / "rep" / "rapport_example.com.html")
    assert os.path.isfile(tmp_path / "data" / "history_example.com.json")


def test_report_escapes_html(tmp_path):
    findings = [{"id": "x", "category": "Headers", "title": "<script>alert(1)</script>",
                 "severity": "moyen", "status": "fail", "detail": "d", "patron": "p",
                 "reco": "r", "evidence": "e"}]
    path = report.generate_report("example.com", findings, scoring.compute_score(findings),
                                  [{"score": 50, "date": "2026-01-01"}], str(tmp_path))
    html = open(path, encoding="utf-8").read()
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "88" in html and "Score :" in html  # evolution line rendered
