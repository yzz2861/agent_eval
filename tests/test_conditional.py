import io
from datetime import datetime

import pytest

from webob.conditional import evaluate_preconditions, precondition_response
from webob.datetime_utils import UTC, serialize_date
from webob.request import Request

LAST_MODIFIED = datetime(2024, 6, 1, 12, 0, 0, tzinfo=UTC)
LAST_MODIFIED_HTTP = serialize_date(LAST_MODIFIED)
EARLIER_HTTP = serialize_date(datetime(2024, 5, 1, 12, 0, 0, tzinfo=UTC))
LATER_HTTP = serialize_date(datetime(2024, 7, 1, 12, 0, 0, tzinfo=UTC))
ETAG = '"abc"'
WEAK_ETAG = 'W/"abc"'

WRITE_METHODS = ["PUT", "POST", "DELETE", "PATCH"]


class GuardedStream(io.BytesIO):
    """A wsgi.input stand-in that records any attempt to read the body."""

    def __init__(self, data):
        super().__init__(data)
        self.read_called = False

    def read(self, *args, **kwargs):
        self.read_called = True
        return super().read(*args, **kwargs)

    def readline(self, *args, **kwargs):
        self.read_called = True
        return super().readline(*args, **kwargs)


def make_request(method="GET", headers=None, body=None):
    kw = {"method": method}

    if headers:
        kw["headers"] = headers

    if body is not None:
        kw["body"] = body

    return Request.blank("/resource", **kw)


def guard_body(req):
    stream = GuardedStream(req.body)
    req.environ["wsgi.input"] = stream
    return stream


class TestIfMatch:
    @pytest.mark.parametrize("method", ["GET", "HEAD"] + WRITE_METHODS)
    def test_match_passes(self, method):
        req = make_request(method, {"If-Match": ETAG})
        assert evaluate_preconditions(req, True, etag=ETAG) is None

    def test_match_in_list_passes(self):
        req = make_request("PUT", {"If-Match": '"xyz", "abc"'})
        assert evaluate_preconditions(req, True, etag=ETAG) is None

    @pytest.mark.parametrize("method", ["GET", "HEAD"] + WRITE_METHODS)
    def test_mismatch_fails_with_412(self, method):
        req = make_request(method, {"If-Match": '"other"'})
        assert evaluate_preconditions(req, True, etag=ETAG) == 412

    def test_weak_etag_in_header_never_matches(self):
        req = make_request("PUT", {"If-Match": WEAK_ETAG})
        assert evaluate_preconditions(req, True, etag=ETAG) == 412

    def test_weak_current_etag_never_strong_matches(self):
        req = make_request("PUT", {"If-Match": ETAG})
        assert evaluate_preconditions(req, True, etag=WEAK_ETAG) == 412

    def test_star_matches_existing_resource(self):
        req = make_request("PUT", {"If-Match": "*"})
        assert evaluate_preconditions(req, True, etag=ETAG) is None

    def test_star_fails_for_missing_resource(self):
        req = make_request("PUT", {"If-Match": "*"})
        assert evaluate_preconditions(req, False) == 412

    def test_missing_resource_fails(self):
        req = make_request("PUT", {"If-Match": ETAG})
        assert evaluate_preconditions(req, False) == 412

    def test_no_current_etag_fails(self):
        req = make_request("PUT", {"If-Match": ETAG})
        assert evaluate_preconditions(req, True, etag=None) == 412


class TestIfUnmodifiedSince:
    def test_unmodified_passes(self):
        req = make_request("PUT", {"If-Unmodified-Since": LAST_MODIFIED_HTTP})
        assert (
            evaluate_preconditions(req, True, last_modified=LAST_MODIFIED) is None
        )

    def test_modified_after_fails_with_412(self):
        req = make_request("PUT", {"If-Unmodified-Since": EARLIER_HTTP})
        assert evaluate_preconditions(req, True, last_modified=LAST_MODIFIED) == 412

    def test_invalid_date_is_ignored(self):
        req = make_request("PUT", {"If-Unmodified-Since": "not-a-date"})
        assert (
            evaluate_preconditions(req, True, last_modified=LAST_MODIFIED) is None
        )

    def test_subsecond_precision_is_truncated(self):
        req = make_request("PUT", {"If-Unmodified-Since": LAST_MODIFIED_HTTP})
        almost = LAST_MODIFIED.replace(microsecond=900000)
        assert evaluate_preconditions(req, True, last_modified=almost) is None

    def test_ignored_when_if_match_present(self):
        req = make_request(
            "PUT", {"If-Match": ETAG, "If-Unmodified-Since": EARLIER_HTTP}
        )
        assert (
            evaluate_preconditions(req, True, etag=ETAG, last_modified=LAST_MODIFIED)
            is None
        )


class TestIfNoneMatch:
    @pytest.mark.parametrize("method", ["GET", "HEAD"])
    def test_match_on_safe_method_is_304(self, method):
        req = make_request(method, {"If-None-Match": ETAG})
        assert evaluate_preconditions(req, True, etag=ETAG) == 304

    @pytest.mark.parametrize("method", WRITE_METHODS)
    def test_match_on_write_method_is_412_not_304(self, method):
        req = make_request(method, {"If-None-Match": ETAG})
        assert evaluate_preconditions(req, True, etag=ETAG) == 412

    def test_weak_comparison_current_weak(self):
        req = make_request("GET", {"If-None-Match": ETAG})
        assert evaluate_preconditions(req, True, etag=WEAK_ETAG) == 304

    def test_weak_comparison_header_weak(self):
        req = make_request("GET", {"If-None-Match": WEAK_ETAG})
        assert evaluate_preconditions(req, True, etag=ETAG) == 304

    def test_no_match_passes(self):
        req = make_request("GET", {"If-None-Match": '"other"'})
        assert evaluate_preconditions(req, True, etag=ETAG) is None

    def test_star_matches_existing_resource(self):
        req = make_request("GET", {"If-None-Match": "*"})
        assert evaluate_preconditions(req, True, etag=ETAG) == 304

    def test_star_on_write_method_is_412(self):
        req = make_request("PUT", {"If-None-Match": "*"})
        assert evaluate_preconditions(req, True, etag=ETAG) == 412

    def test_star_passes_for_missing_resource(self):
        req = make_request("PUT", {"If-None-Match": "*"})
        assert evaluate_preconditions(req, False) is None

    def test_missing_resource_never_matches(self):
        req = make_request("GET", {"If-None-Match": ETAG})
        assert evaluate_preconditions(req, False) is None


class TestIfModifiedSince:
    @pytest.mark.parametrize("method", ["GET", "HEAD"])
    def test_not_modified_is_304(self, method):
        req = make_request(method, {"If-Modified-Since": LAST_MODIFIED_HTTP})
        assert evaluate_preconditions(req, True, last_modified=LAST_MODIFIED) == 304

    def test_modified_since_passes(self):
        req = make_request("GET", {"If-Modified-Since": EARLIER_HTTP})
        assert (
            evaluate_preconditions(req, True, last_modified=LAST_MODIFIED) is None
        )

    @pytest.mark.parametrize("method", WRITE_METHODS)
    def test_write_methods_ignore_if_modified_since(self, method):
        # A failed/conflicting write must never be disguised as a 304.
        req = make_request(method, {"If-Modified-Since": LATER_HTTP})
        assert (
            evaluate_preconditions(req, True, last_modified=LAST_MODIFIED) is None
        )

    def test_invalid_date_is_ignored(self):
        req = make_request("GET", {"If-Modified-Since": "not-a-date"})
        assert (
            evaluate_preconditions(req, True, last_modified=LAST_MODIFIED) is None
        )

    def test_subsecond_precision_is_truncated(self):
        req = make_request("GET", {"If-Modified-Since": LAST_MODIFIED_HTTP})
        almost = LAST_MODIFIED.replace(microsecond=400000)
        assert evaluate_preconditions(req, True, last_modified=almost) == 304

    def test_naive_datetime_is_assumed_utc(self):
        req = make_request("GET", {"If-Modified-Since": LAST_MODIFIED_HTTP})
        naive = datetime(2024, 6, 1, 12, 0, 0)
        assert evaluate_preconditions(req, True, last_modified=naive) == 304

    def test_ignored_when_if_none_match_present(self):
        req = make_request(
            "GET", {"If-None-Match": '"other"', "If-Modified-Since": LATER_HTTP}
        )
        assert (
            evaluate_preconditions(req, True, etag=ETAG, last_modified=LAST_MODIFIED)
            is None
        )


class TestPrecedence:
    def test_if_match_failure_beats_if_none_match(self):
        req = make_request(
            "GET", {"If-Match": '"other"', "If-None-Match": ETAG}
        )
        assert evaluate_preconditions(req, True, etag=ETAG) == 412

    def test_if_match_passes_then_if_none_match_applies(self):
        req = make_request(
            "GET", {"If-Match": ETAG, "If-None-Match": ETAG}
        )
        assert evaluate_preconditions(req, True, etag=ETAG) == 304

    def test_if_unmodified_since_beats_if_none_match(self):
        req = make_request(
            "GET",
            {
                "If-Unmodified-Since": EARLIER_HTTP,
                "If-None-Match": ETAG,
            },
        )
        assert (
            evaluate_preconditions(req, True, etag=ETAG, last_modified=LAST_MODIFIED)
            == 412
        )

    def test_no_conditional_headers_passes(self):
        req = make_request("PUT")
        assert (
            evaluate_preconditions(req, True, etag=ETAG, last_modified=LAST_MODIFIED)
            is None
        )


class TestPreconditionResponse:
    def test_passes_returns_none(self):
        req = make_request("PUT", {"If-Match": ETAG})
        assert req.check_preconditions(True, etag=ETAG) is None

    def test_304_response_status_and_headers(self):
        req = make_request("GET", {"If-None-Match": ETAG})
        resp = req.check_preconditions(
            True, etag=ETAG, last_modified=LAST_MODIFIED
        )
        assert resp.status_code == 304
        assert resp.headers["ETag"] == ETAG
        assert resp.headers["Last-Modified"] == LAST_MODIFIED_HTTP

    def test_304_response_has_no_body(self):
        req = make_request("GET", {"If-None-Match": ETAG})
        resp = req.check_preconditions(True, etag=ETAG)
        assert resp.status_code == 304
        assert b"".join(resp(req.environ, lambda *a: None)) == b""

    def test_412_response_status_and_body(self):
        req = make_request("PUT", {"If-Match": '"other"'})
        resp = req.check_preconditions(True, etag=ETAG)
        assert resp.status_code == 412
        body = b"".join(resp(req.environ, lambda *a: None))
        assert b"412" in body

    def test_write_method_never_returns_304(self):
        req = make_request("PUT", {"If-None-Match": ETAG})
        resp = precondition_response(req, True, etag=ETAG)
        assert resp.status_code == 412

    def test_modification_is_not_performed_on_failure(self):
        # The convenience interface only produces a response; it is up to
        # the caller to skip the modification, which a ``None`` result
        # gates.
        performed = []
        req = make_request("PUT", {"If-Match": '"other"'}, body=b"payload")
        resp = req.check_preconditions(True, etag=ETAG)

        if resp is None:
            performed.append(True)

        assert resp.status_code == 412
        assert performed == []


class TestBodyIsNotConsumed:
    @pytest.mark.parametrize(
        "headers,expected",
        [
            ({"If-Match": '"other"'}, 412),
            ({"If-Match": ETAG}, None),
            ({"If-None-Match": ETAG}, 412),
            ({"If-Unmodified-Since": EARLIER_HTTP}, 412),
        ],
    )
    def test_evaluation_does_not_read_body(self, headers, expected):
        req = make_request("PUT", headers, body=b"payload")
        stream = guard_body(req)
        result = evaluate_preconditions(
            req, True, etag=ETAG, last_modified=LAST_MODIFIED
        )
        assert result == expected
        assert not stream.read_called

    def test_check_preconditions_does_not_read_body(self):
        req = make_request(
            "PUT", {"If-Match": '"other"'}, body=b"payload"
        )
        stream = guard_body(req)
        resp = req.check_preconditions(True, etag=ETAG)
        assert resp.status_code == 412
        assert not stream.read_called
        # The body is still fully available for error handling etc.
        assert req.body == b"payload"
