import pytest

import scoring
from base import SEVERITY_WEIGHTS


def f(severity, status):
    return {"severity": severity, "status": status}


def test_empty_is_perfect():
    r = scoring.compute_score([])
    assert r["score"] == 100 and r["grade"] == "A"
    assert r["counts"]["critique"] == 0


def test_none_is_tolerated():
    assert scoring.compute_score(None)["score"] == 100


@pytest.mark.parametrize("sev", ["critique", "eleve", "moyen", "faible"])
def test_fail_costs_full_weight(sev):
    assert scoring.compute_score([f(sev, "fail")])["score"] == 100 - SEVERITY_WEIGHTS[sev]


@pytest.mark.parametrize("sev,expected", [
    ("critique", 80),   # 40 / 2
    ("eleve", 88),      # round(12.5) == 12 (banker's rounding)
    ("moyen", 94),
    ("faible", 98),     # round(2.5) == 2
])
def test_warn_costs_half_weight(sev, expected):
    assert scoring.compute_score([f(sev, "warn")])["score"] == expected


@pytest.mark.parametrize("status", ["pass", "info"])
def test_pass_and_info_never_penalize(status):
    r = scoring.compute_score([f("critique", status)] * 5)
    assert r["score"] == 100
    assert r["counts"]["critique"] == 5  # still counted


def test_score_is_clamped_at_zero():
    r = scoring.compute_score([f("critique", "fail")] * 10)
    assert r["score"] == 0 and r["grade"] == "F"


@pytest.mark.parametrize("score,grade,emoji", [
    (100, "A", "🟢"), (90, "A", "🟢"), (89, "B", "🟢"), (75, "B", "🟢"),
    (74, "C", "🟠"), (60, "C", "🟠"), (59, "D", "🟠"), (40, "D", "🟠"),
    (39, "E", "🔴"), (20, "E", "🔴"), (19, "F", "🔴"), (0, "F", "🔴"),
])
def test_grade_boundaries(score, grade, emoji):
    assert scoring._grade_for(score) == (grade, emoji)


def test_malformed_entries_are_ignored():
    r = scoring.compute_score(["oops", None, 42, {"severity": "moyen", "status": "fail"}])
    assert r["score"] == 88


def test_unknown_severity_is_counted_but_not_penalized():
    r = scoring.compute_score([{"severity": "bizarre", "status": "fail"}])
    assert r["score"] == 100
    assert r["counts"]["bizarre"] == 1


def test_mixed_scenario():
    findings = [f("eleve", "fail"), f("moyen", "warn"), f("faible", "fail"), f("ok", "pass")]
    # 100 - 25 - 6 - 5 = 64
    r = scoring.compute_score(findings)
    assert r["score"] == 64 and r["grade"] == "C"
