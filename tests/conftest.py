"""Shared pytest fixtures.

Every test runs with outbound networking disabled: any attempt to open a
socket or resolve a name raises immediately, so a test can never reach a
live host by accident. Network-dependent code is exercised through mocks.
"""
import os
import socket
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


class NetworkBlocked(RuntimeError):
    pass


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def guard(*args, **kwargs):
        raise NetworkBlocked("network access is disabled in tests")

    monkeypatch.setattr(socket, "create_connection", guard)
    monkeypatch.setattr(socket.socket, "connect", guard)
    monkeypatch.setattr(socket.socket, "connect_ex", guard)
    monkeypatch.setattr(socket, "getaddrinfo", guard)


class FakeResponse:
    """Minimal stand-in for requests.Response."""

    def __init__(self, status_code=200, headers=None, text="", json_data=None, url=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self._json = json_data
        self.url = url

    def json(self):
        if self._json is None:
            raise ValueError("no JSON body")
        return self._json


def assert_valid_finding(f):
    from base import FINDING_KEYS, VALID_CATEGORIES, VALID_SEVERITIES, VALID_STATUSES
    assert set(f) == set(FINDING_KEYS)
    assert f["category"] in VALID_CATEGORIES
    assert f["severity"] in VALID_SEVERITIES
    assert f["status"] in VALID_STATUSES


def by_id(findings, fid):
    matches = [f for f in findings if f["id"] == fid]
    assert matches, "finding %r not found in %s" % (fid, [f["id"] for f in findings])
    return matches[0]
