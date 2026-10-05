"""
Precondition evaluation for conditional requests.
"""

from datetime import date, datetime
import re

from webob.datetime_utils import UTC, parse_date
from webob.descriptors import (
    parse_etag_response,
    serialize_date,
    serialize_etag_response,
)

__all__ = ["check_if_preconditions", "precondition_response_headers"]

_safe_methods = frozenset(("GET", "HEAD"))
_rx_if_header_etag = re.compile(r'^(?:W/)?"(?:\\.|[^"\\])*"$')
_rx_opaque_etag = re.compile(r"^[!#$%&'*+.^_\`|~0-9A-Za-z-]+$")


def _parse_datetime(value):
    if value is None:
        return None

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, date):
        parsed = datetime(value.year, value.month, value.day)
    elif isinstance(value, (int, float)):
        parsed = datetime.fromtimestamp(value, UTC)
    elif isinstance(value, bytes):
        parsed = parse_date(value)
    else:
        parsed = parse_date(str(value))

    if parsed is None:
        return None

    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(UTC).replace(tzinfo=None)

    return parsed


def _parse_request_date(value):
    parsed = _parse_datetime(value)

    if parsed is None:
        return None

    return parsed.replace(microsecond=0)


def _parse_if_match(value):
    if value is None:
        return False, False, None

    if value.strip() == "*":
        return True, True, ()

    etags, _ = _parse_etag_list(value, strong=True)
    return etags is not None, False, etags or []


def _parse_if_none_match(value):
    if value is None:
        return False, False, None

    if value.strip() == "*":
        return True, True, ()

    etags, _ = _parse_etag_list(value, strong=False)
    return etags is not None, False, etags or []


def _parse_etag_list(value, strong=False):
    etags = []

    for item in value.split(","):
        item = item.strip()

        if not item:
            return None, False

        if _rx_if_header_etag.match(item):
            weak = item.startswith("W/")
            etag_value = item

            if weak:
                if strong:
                    return None, False
                etag_value = etag_value[2:]

            etags.append(
                (
                    etag_value[1:-1].replace('\\"', '"').replace("\\\\", "\\"),
                    weak,
                )
            )
        elif _rx_opaque_etag.match(item):
            etags.append((item, False))
        else:
            return None, False

    return etags, False


def _resource_etags(etag):
    if etag is None:
        return None, None

    return (
        parse_etag_response(etag, strong=False),
        parse_etag_response(etag, strong=True),
    )


def _etag_matches(etags, resource_etag):
    return resource_etag is not None and any(
        resource_etag == etag for etag, weak in etags
    )


def check_if_preconditions(
    method,
    resource_exists,
    etag=None,
    last_modified=None,
    if_match=None,
    if_none_match=None,
    if_modified_since=None,
    if_unmodified_since=None,
):
    """
    Return ``304``, ``412``, or ``None`` for the request's preconditions.
    """

    resource_weak_etag, resource_strong_etag = _resource_etags(etag)
    resource_last_modified = _parse_datetime(last_modified)

    if_match_valid = False
    if if_match is not None:
        if_match_valid, wildcard, etags = _parse_if_match(if_match)

        if if_match_valid and wildcard:
            matched = resource_exists
        elif if_match_valid:
            matched = resource_exists and _etag_matches(etags, resource_strong_etag)

        if if_match_valid and not matched:
            return 412

    if not if_match_valid and if_unmodified_since is not None:
        unmodified_since = _parse_request_date(if_unmodified_since)

        if unmodified_since is not None and (
            not resource_exists
            or resource_last_modified is None
            or resource_last_modified > unmodified_since
        ):
            return 412

    if_none_match_valid = False
    if if_none_match is not None:
        if_none_match_valid, wildcard, etags = _parse_if_none_match(if_none_match)

        if if_none_match_valid and wildcard:
            matched = resource_exists
        elif if_none_match_valid:
            matched = resource_exists and _etag_matches(etags, resource_weak_etag)

        if if_none_match_valid and matched:
            return 304 if method in _safe_methods else 412

    if (
        not if_none_match_valid
        and method in _safe_methods
        and if_modified_since is not None
    ):
        modified_since = _parse_request_date(if_modified_since)

        if (
            modified_since is not None
            and resource_exists
            and resource_last_modified is not None
            and resource_last_modified <= modified_since
        ):
            return 304

    return None


def precondition_response_headers(etag=None, last_modified=None):
    headers = {}

    if etag is not None:
        headers["ETag"] = serialize_etag_response(etag)

    if last_modified is not None:
        if isinstance(last_modified, datetime) and last_modified.tzinfo is not None:
            last_modified = _parse_datetime(last_modified)

        headers["Last-Modified"] = serialize_date(last_modified)

    return headers
