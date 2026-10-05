from datetime import datetime, timedelta, timezone
from io import BytesIO

import pytest

from webob import Request, Response
from webob.preconditions import check_if_preconditions


ETAG = '"v1"'
WEAK_ETAG = 'W/"v1"'
MODIFIED = datetime(2024, 1, 1, 12, 0, 0)
BEFORE = MODIFIED - timedelta(seconds=1)
AFTER = MODIFIED + timedelta(seconds=1)


@pytest.mark.parametrize(
    ("method", "headers", "exists", "expected"),
    [
        ("GET", {}, True, None),
        ("GET", {"If-Match": ETAG}, True, None),
        ("GET", {"If-Match": '"v2"'}, True, 412),
        ("GET", {"If-Match": "*"}, True, None),
        ("GET", {"If-Match": "*"}, False, 412),
        ("GET", {"If-Match": WEAK_ETAG}, True, None),
        ("GET", {"If-Match": ETAG}, False, 412),
        ("GET", {"If-Unmodified-Since": "Mon, 01 Jan 2024 12:00:00 GMT"}, True, None),
        ("GET", {"If-Unmodified-Since": "Mon, 01 Jan 2024 11:59:59 GMT"}, True, 412),
        ("GET", {"If-Unmodified-Since": "not a date"}, True, None),
        ("GET", {"If-None-Match": ETAG}, True, 304),
        ("GET", {"If-None-Match": WEAK_ETAG}, True, 304),
        ("GET", {"If-None-Match": "v1"}, True, 304),
        ("HEAD", {"If-None-Match": ETAG}, True, 304),
        ("PUT", {"If-None-Match": ETAG}, True, 412),
        ("POST", {"If-None-Match": "*"}, True, 412),
        ("GET", {"If-None-Match": '"v2"'}, True, None),
        ("GET", {"If-None-Match": "*"}, False, None),
        ("GET", {"If-Modified-Since": "Mon, 01 Jan 2024 12:00:00 GMT"}, True, 304),
        ("GET", {"If-Modified-Since": "Mon, 01 Jan 2024 11:59:59 GMT"}, True, None),
        ("GET", {"If-Modified-Since": "Mon, 01 Jan 2024 12:00:00 GMT"}, False, None),
        ("GET", {"If-Modified-Since": "not a date"}, True, None),
        ("PUT", {"If-Modified-Since": "Mon, 01 Jan 2024 12:00:00 GMT"}, True, None),
    ],
)
def test_precondition_matrix(method, headers, exists, expected):
    if_match = headers.get("If-Match")
    if_none_match = headers.get("If-None-Match")
    if_unmodified_since = headers.get("If-Unmodified-Since")
    if_modified_since = headers.get("If-Modified-Since")

    assert (
        check_if_preconditions(
            method,
            exists,
            etag=ETAG,
            last_modified=MODIFIED,
            if_match=if_match,
            if_none_match=if_none_match,
            if_modified_since=if_modified_since,
            if_unmodified_since=if_unmodified_since,
        )
        == expected
    )


def test_weak_resource_etag_uses_strong_comparison_for_if_match():
    assert (
        check_if_preconditions(
            "PUT",
            True,
            etag=WEAK_ETAG,
            if_match=ETAG,
        )
        == 412
    )
    assert (
        check_if_preconditions(
            "GET",
            True,
            etag=WEAK_ETAG,
            if_none_match=ETAG,
        )
        == 304
    )


def test_invalid_if_match_is_ignored_and_date_precondition_is_used():
    assert (
        check_if_preconditions(
            "PUT",
            True,
            etag=ETAG,
            last_modified=AFTER,
            if_match='"v1" malformed',
            if_unmodified_since=BEFORE,
        )
        == 412
    )


def test_request_dates_use_second_precision():
    modified = datetime(2024, 1, 1, 12, 0, 0, 500000)

    assert (
        check_if_preconditions(
            "PUT",
            True,
            last_modified=modified,
            if_unmodified_since="Mon, 01 Jan 2024 12:00:00 GMT",
        )
        == 412
    )


def test_if_match_takes_precedence_over_date_conditions():
    assert (
        check_if_preconditions(
            "GET",
            True,
            etag=ETAG,
            last_modified=MODIFIED,
            if_match='"v2"',
            if_none_match=ETAG,
            if_modified_since=AFTER,
            if_unmodified_since=BEFORE,
        )
        == 412
    )


def test_if_none_match_takes_precedence_over_if_modified_since():
    assert (
        check_if_preconditions(
            "GET",
            True,
            etag=ETAG,
            last_modified=AFTER,
            if_none_match=ETAG,
            if_modified_since=BEFORE,
        )
        == 304
    )


def test_request_check_does_not_consume_body_and_returns_response():
    body = b"updated resource"
    input = BytesIO(body)
    req = Request.blank(
        "/",
        method="PUT",
        environ={"wsgi.input": input, "CONTENT_LENGTH": str(len(body))},
        headers={"If-Match": '"v2"'},
    )

    response = req.check_if_preconditions(
        resource_exists=True,
        etag=ETAG,
        last_modified=MODIFIED,
    )

    assert response.status_code == 412
    assert response.headers["ETag"] == ETAG
    assert response.headers["Last-Modified"] == "Mon, 01 Jan 2024 12:00:00 GMT"
    assert input.tell() == 0
    assert req.body == body


def test_request_check_304_preserves_weak_etag_and_aware_modification_time():
    modified = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    req = Request.blank("/", headers={"If-None-Match": WEAK_ETAG})

    response = req.check_if_preconditions(True, WEAK_ETAG, modified)

    assert response.status_code == 304
    assert response.headers["ETag"] == WEAK_ETAG
    assert response.headers["Last-Modified"] == "Mon, 01 Jan 2024 12:00:00 GMT"


def test_request_check_returns_none_before_update():
    req = Request.blank("/", method="PUT", headers={"If-Match": ETAG})
    mutated = []

    response = req.check_if_preconditions(True, ETAG, MODIFIED)

    assert response is None
    assert mutated == []


def test_request_check_put_if_none_match_returns_412_not_304():
    req = Request.blank("/", method="PUT", headers={"If-None-Match": ETAG})

    response = req.check_if_preconditions(True, ETAG, MODIFIED)

    assert response.status_code == 412


def test_response_conditional_put_failure_does_not_consume_app_iter():
    class ClosingIterator:
        def __init__(self):
            self.closed = False

        def __iter__(self):
            if self.closed:
                raise RuntimeError("body was consumed after close")
            yield b"resource body"

        def close(self):
            self.closed = True

    app_iter = ClosingIterator()
    response = Response(
        app_iter=app_iter,
        conditional_response=True,
        etag="v1",
        last_modified=MODIFIED,
    )
    req = Request.blank("/", method="PUT", headers={"If-Match": '"v2"'})

    result = req.get_response(response)

    assert result.status_code == 412
    assert result.headers["ETag"] == ETAG
    assert app_iter.closed


def test_response_conditional_get_uses_304_headers():
    response = Response(
        "resource body",
        conditional_response=True,
        etag="v1",
        last_modified=MODIFIED,
    )
    req = Request.blank("/", headers={"If-None-Match": ETAG})

    result = req.get_response(response)

    assert result.status_code == 304
    assert result.body == b""
    assert result.headers["ETag"] == ETAG
    assert "Content-Length" not in result.headers
    assert "Content-Type" not in result.headers
