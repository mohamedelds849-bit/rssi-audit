import pytest

from base import FINDING_KEYS, make_finding


def _ok(**over):
    args = dict(id="x", category="SSL", title="t", severity="faible", status="warn",
                detail="d", patron="p", reco="r", evidence="e")
    args.update(over)
    return make_finding(**args)


def test_valid_finding_has_exact_contract_keys():
    assert tuple(_ok().keys()) == FINDING_KEYS


def test_evidence_defaults_to_empty_string():
    assert _ok(evidence=None)["evidence"] == ""


@pytest.mark.parametrize("field,value", [
    ("category", "NOPE"), ("severity", "gravissime"), ("status", "maybe"),
    ("title", ""), ("patron", "   "), ("reco", None), ("detail", 3),
])
def test_invalid_values_raise(field, value):
    with pytest.raises(ValueError):
        _ok(**{field: value})
