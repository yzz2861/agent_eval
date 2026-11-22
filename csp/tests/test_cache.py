from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from django.core.cache import cache, caches
from django.http import HttpResponse
from django.test import RequestFactory
from django.test.utils import override_settings

from csp.constants import (
    CACHE_FINGERPRINT_CACHE_ALIAS,
    HEADER,
    HEADER_REPORT_ONLY,
    NONCE,
    SELF,
)
from csp.exceptions import CSPNonceError
from csp.middleware import CSPMiddleware
from csp.tests.utils import response

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponseBase

mw = CSPMiddleware(response())
rf = RequestFactory()

ENFORCED_POLICY = {"DIRECTIVES": {"default-src": [SELF, NONCE]}}
REPORT_ONLY_POLICY = {"DIRECTIVES": {"default-src": [SELF, NONCE]}}
REUSABLE_POLICY = {"DIRECTIVES": {"default-src": [SELF]}}


class FakeCache:
    """A minimal stand-in for Django's shared page cache."""

    def __init__(self) -> None:
        self.store: dict[str, Any] = {}
        self.deleted: list[str] = []

    def get(self, key: str, default: Any = None) -> Any:
        return self.store.get(key, default)

    def set(self, key: str, value: Any, timeout: Any = None) -> None:
        self.store[key] = value

    def delete(self, key: str) -> None:
        self.deleted.append(key)
        self.store.pop(key, None)

    def clear(self) -> None:
        self.store.clear()
        self.deleted.clear()


def _seed_old_policy_entry(
    middleware: CSPMiddleware,
    request: HttpRequest,
    stale_response: HttpResponseBase,
) -> tuple[str, str]:
    """Simulate an entry left in the shared cache by an older CSP policy."""
    key = middleware._fingerprint_cache_key(request)
    stale_fingerprint = "old-policy-fingerprint"
    cache.set(key, (stale_response, stale_fingerprint))
    return key, stale_fingerprint


def _nonce_value(nonce: str) -> str:
    return "'nonce-" + nonce + "'"


@override_settings(CONTENT_SECURITY_POLICY=ENFORCED_POLICY)
def test_nonce_response_is_never_cached_and_each_request_gets_own_nonce() -> None:
    cache.clear()
    nonces: list[str] = []
    cache_controls: list[str] = []

    for _ in range(2):
        request = rf.get("/nonced/")
        assert mw.process_request(request) is None

        # The view renders a nonced body, which generates the lazy nonce.
        nonce = str(request.csp_nonce)
        nonces.append(nonce)

        http_response = HttpResponse('<script nonce="' + nonce + '"></script>')
        processed = mw.process_response(request, http_response)

        assert _nonce_value(nonce) in processed[HEADER]
        assert "no-store" in processed["Cache-Control"]
        cache_controls.append(processed["Cache-Control"])

    # The two isolated requests must see two distinct, per-request nonces.
    assert nonces[0] != nonces[1]
    # A nonced response is never written to the shared cache.
    assert not cache._cache
    assert all("no-store" in value for value in cache_controls)


@override_settings(CONTENT_SECURITY_POLICY=REUSABLE_POLICY)
def test_reusable_response_is_cached_and_served_from_cache() -> None:
    cache.clear()

    first_request = rf.get("/reusable/")
    assert mw.process_request(first_request) is None
    # The body never reads the nonce, so the response can be shared.
    first_response = HttpResponse("shared body")
    processed_first = mw.process_response(first_request, first_response)
    assert "nonce-" not in processed_first[HEADER]
    assert not processed_first.has_header("Cache-Control")

    key = mw._fingerprint_cache_key(first_request)
    cached = cache.get(key)
    assert cached is not None
    cached_response, cached_fingerprint = cached
    assert cached_response.content == processed_first.content
    assert cached_response[HEADER] == processed_first[HEADER]

    # A second, isolated request gets the cached response back.
    second_request = rf.get("/reusable/")
    hit = mw.process_request(second_request)
    assert hit is not None
    assert hit.content == processed_first.content
    assert hit[HEADER] == processed_first[HEADER]
    assert second_request._csp_cached_response is hit
    # The fingerprint stored alongside the response matches the current policy.
    assert cached_fingerprint == mw.get_policy_fingerprint(second_request)


@override_settings(CONTENT_SECURITY_POLICY=REUSABLE_POLICY)
def test_policy_change_invalidates_stale_cache_entry() -> None:
    cache.clear()
    request = rf.get("/reusable/")
    mw.process_request(request)
    stale_response = HttpResponse("stale body")
    key, stale_fingerprint = _seed_old_policy_entry(mw, request, stale_response)
    assert stale_fingerprint != mw.get_policy_fingerprint(request)

    # The stale entry must not be reused; the request is rebuilt instead.
    lookup_request = rf.get("/reusable/")
    assert mw.process_request(lookup_request) is None
    assert cache.get(key) is None


@override_settings(CONTENT_SECURITY_POLICY=REUSABLE_POLICY)
def test_stale_entry_handling_through_fake_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_cache = FakeCache()
    request = rf.get("/reusable/")
    stale_response = HttpResponse("stale body")
    key = mw._fingerprint_cache_key(request)
    fake_cache.set(key, (stale_response, "old-policy-fingerprint"))

    # Point the middleware at the fake cache for this lookup.
    monkeypatch.setattr(caches._connections, CACHE_FINGERPRINT_CACHE_ALIAS, fake_cache)

    lookup_request = rf.get("/reusable/")
    assert mw.process_request(lookup_request) is None
    assert fake_cache.deleted == [key]
    assert key not in fake_cache.store


@override_settings(CONTENT_SECURITY_POLICY=ENFORCED_POLICY)
def test_report_only_nonce_is_handled_independently_from_enforced() -> None:
    cache.clear()
    request = rf.get("/report-only/")
    mw.process_request(request)
    nonce = str(request.csp_nonce)

    http_response = HttpResponse()
    processed = mw.process_response(request, http_response)
    # The enforced header embeds the per-request nonce and the response is no-store.
    assert _nonce_value(nonce) in processed[HEADER]
    assert "no-store" in processed["Cache-Control"]
    assert not cache._cache


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF]}},
    CONTENT_SECURITY_POLICY_REPORT_ONLY=REPORT_ONLY_POLICY,
)
def test_report_only_nonce_alone_blocks_caching() -> None:
    cache.clear()
    request = rf.get("/ro-only/")
    mw.process_request(request)
    # The nonce is read even though the enforced policy does not use one.
    nonce = str(request.csp_nonce)

    http_response = HttpResponse()
    processed = mw.process_response(request, http_response)
    assert "nonce-" not in processed[HEADER]
    assert _nonce_value(nonce) in processed[HEADER_REPORT_ONLY]
    assert "no-store" in processed["Cache-Control"]
    assert not cache._cache


@override_settings(CONTENT_SECURITY_POLICY=ENFORCED_POLICY)
def test_existing_csp_exempt_decorator_path_is_not_cached() -> None:
    cache.clear()
    request = rf.get("/exempt/")
    mw.process_request(request)
    http_response = HttpResponse()
    setattr(http_response, "_csp_exempt", True)

    processed = mw.process_response(request, http_response)
    assert HEADER not in processed
    # Exempted responses are not stored by the CSP cache.
    assert not cache._cache


@override_settings(CONTENT_SECURITY_POLICY=ENFORCED_POLICY)
def test_header_decided_first_nonce_accessed_afterwards_raises() -> None:
    request = rf.get("/late-nonce/")
    mw.process_request(request)
    # The view never reads the nonce, so the header is decided without one.
    processed = mw.process_response(request, HttpResponse())
    assert "nonce-" not in processed[HEADER]
    with pytest.raises(CSPNonceError):
        str(request.csp_nonce)
