"""Tests for unified header name/value validation and WSGI/ASGI parity."""

from __future__ import annotations

import asyncio
import re

import pytest

from secure import CustomHeader, Secure
from secure._internal.emit import HeaderSetError, set_headers_async, set_headers_sync
from secure.headers._validation import (
    RULE_HEADER_ENCODING,
    RULE_HEADER_NAME,
    RULE_HEADER_SET,
    RULE_HEADER_VALUE,
    normalize_header_value,
    validate_header_name,
    validate_wire_header,
)
from secure.middleware import SecureASGIMiddleware, SecureWSGIMiddleware

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_STRICT_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def _strict_parse(fields):
    """Re-read a final header list with a strict parser (mirrors acceptance)."""
    parsed = []
    for raw_name, raw_value in fields:
        name = raw_name.decode("ascii") if isinstance(raw_name, bytes) else raw_name
        value = raw_value.decode("latin-1") if isinstance(raw_value, bytes) else raw_value
        assert _STRICT_NAME_RE.fullmatch(name), f"invalid field name {name!r}"
        for char in value:
            codepoint = ord(char)
            assert codepoint == 0x09 or 0x20 <= codepoint <= 0x7E or 0xA0 <= codepoint <= 0xFF, (
                f"forbidden character U+{codepoint:04X} in value of {name!r}"
            )
        parsed.append((name, value))
    return parsed


def _run_wsgi(secure, app_headers=()):
    def app(environ, start_response):
        start_response("200 OK", list(app_headers))
        return [b"ok"]

    middleware = SecureWSGIMiddleware(app, secure=secure)
    captured = {}

    def start_response(status, headers, exc_info=None):
        captured["status"] = status
        captured["headers"] = headers
        return lambda _: None

    list(middleware({}, start_response))
    return captured["headers"]


def _run_asgi(secure, app_headers=()):
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": list(app_headers)})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    middleware = SecureASGIMiddleware(app, secure=secure)
    messages = []

    async def send(message):
        messages.append(message)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    asyncio.run(middleware({"type": "http"}, receive, send))
    start = next(message for message in messages if message["type"] == "http.response.start")
    return start["headers"]


def _wsgi_error(secure):
    try:
        _run_wsgi(secure)
    except ValueError as error:
        return error
    return None


def _asgi_error(secure):
    try:
        _run_asgi(secure)
    except ValueError as error:
        return error
    return None


# ---------------------------------------------------------------------------
# Value syntax: CRLF, obs-fold, NUL, and other control characters
# ---------------------------------------------------------------------------

INJECTION_VALUES = [
    pytest.param("ok\r\nSet-Cookie: session=evil", id="crlf"),
    pytest.param("ok\nSet-Cookie: session=evil", id="lf"),
    pytest.param("ok\rSet-Cookie: session=evil", id="cr"),
    pytest.param("ok\r\n folded", id="obs-fold"),
    pytest.param("ok\x00admin", id="nul"),
    pytest.param("ok\x0bvalue", id="vertical-tab"),
    pytest.param("ok\x1fvalue", id="unit-separator"),
    pytest.param("ok\x7fvalue", id="del"),
    pytest.param("ok\x85value", id="c1-control"),
]


@pytest.mark.parametrize("value", INJECTION_VALUES)
def test_normalize_header_value_rejects_control_characters(value):
    with pytest.raises(ValueError, match=RULE_HEADER_VALUE) as excinfo:
        normalize_header_value(value, what="X-Test")
    # The exception must not echo the attacker-controlled value.
    assert "Set-Cookie" not in str(excinfo.value)
    assert "folded" not in str(excinfo.value)
    assert "admin" not in str(excinfo.value)


def test_normalize_header_value_allows_latin1_visible_and_internal_space():
    assert normalize_header_value("café au lait") == "café au lait"
    assert normalize_header_value("alpha  beta\tgamma") == "alpha  beta\tgamma"
    assert normalize_header_value("«naïve»") == "«naïve»"
    # Leading/trailing whitespace is trimmed, internal spacing preserved.
    assert normalize_header_value("  padded value  ") == "padded value"


def test_normalize_header_value_allows_chinese_display_value():
    assert normalize_header_value("张三") == "张三"


# ---------------------------------------------------------------------------
# Name syntax: RFC 9110 token
# ---------------------------------------------------------------------------


def test_validate_header_name_accepts_rfc_token():
    assert validate_header_name("X-Custom-Header") == "X-Custom-Header"
    assert validate_header_name("!#$%&'*+-.^_`|~09azAZ") == "!#$%&'*+-.^_`|~09azAZ"
    # Surrounding whitespace is trimmed before the token check.
    assert validate_header_name("  X-Test  ") == "X-Test"


@pytest.mark.parametrize(
    "name",
    [
        pytest.param("Bad Name", id="space"),
        pytest.param("Bad:Name", id="colon"),
        pytest.param("Bad(Name)", id="separator"),
        pytest.param("Bad\r\nName", id="crlf"),
        pytest.param("", id="empty"),
        pytest.param("名字", id="non-ascii"),
    ],
)
def test_validate_header_name_rejects_non_token(name):
    with pytest.raises(ValueError, match=RULE_HEADER_NAME) as excinfo:
        validate_header_name(name)
    # Control characters from a malicious name must not reach logs raw.
    assert "\r" not in str(excinfo.value)
    assert "\n" not in str(excinfo.value)


# ---------------------------------------------------------------------------
# Custom headers
# ---------------------------------------------------------------------------


def test_custom_header_rejects_invalid_name():
    with pytest.raises(ValueError, match=RULE_HEADER_NAME):
        CustomHeader("Bad Name", "value")


def test_custom_header_accepts_chinese_display_value():
    header = CustomHeader("X-Display-Name", "张三")
    assert header.header_name == "X-Display-Name"
    assert header.header_value == "张三"


def test_custom_header_set_rejects_crlf_without_echoing_value():
    header = CustomHeader("X-Test", "initial")
    with pytest.raises(ValueError, match=RULE_HEADER_VALUE) as excinfo:
        header.set("ok\r\nSet-Cookie: session=evil")
    assert "Set-Cookie" not in str(excinfo.value)


# ---------------------------------------------------------------------------
# WSGI/ASGI parity: same accept/reject conclusion for the same header list
# ---------------------------------------------------------------------------

PARITY_CASES = [
    pytest.param("custom-value", None, id="clean"),
    pytest.param("café au lait «naïve»", None, id="latin1-visible"),
    pytest.param("alpha beta", None, id="internal-space"),
    pytest.param("ok\r\nSet-Cookie: session=evil", RULE_HEADER_VALUE, id="crlf"),
    pytest.param("ok\r\n folded", RULE_HEADER_VALUE, id="obs-fold"),
    pytest.param("ok\x00admin", RULE_HEADER_VALUE, id="nul"),
    pytest.param("ok\x7fvalue", RULE_HEADER_VALUE, id="del"),
    pytest.param("ok\x85value", RULE_HEADER_VALUE, id="c1-control"),
    pytest.param("张三", RULE_HEADER_ENCODING, id="non-latin1-cjk"),
    pytest.param("ok \U0001f600", RULE_HEADER_ENCODING, id="non-latin1-emoji"),
]


@pytest.mark.parametrize("value,expected_rule", PARITY_CASES)
def test_wsgi_asgi_same_accept_reject_conclusion(value, expected_rule):
    secure = Secure(custom=[CustomHeader("X-Test", value)])

    wsgi_error = _wsgi_error(secure)
    asgi_error = _asgi_error(secure)

    if expected_rule is None:
        assert wsgi_error is None, f"WSGI unexpectedly rejected: {wsgi_error}"
        assert asgi_error is None, f"ASGI unexpectedly rejected: {asgi_error}"
        return

    assert wsgi_error is not None, "WSGI accepted a value ASGI rejects"
    assert asgi_error is not None, "ASGI accepted a value WSGI rejects"
    assert expected_rule in str(wsgi_error)
    assert expected_rule in str(asgi_error)
    # Errors contain the header name and rule id only, never the value.
    for error in (wsgi_error, asgi_error):
        message = str(error)
        assert "X-Test" in message
        assert "Set-Cookie" not in message
        assert "folded" not in message
        assert "admin" not in message
        assert "张三" not in message
        assert "\U0001f600" not in message


def test_wsgi_asgi_emit_identical_logical_headers():
    secure = Secure(custom=[CustomHeader("X-Test", "café au lait")])

    wsgi_headers = dict(_run_wsgi(secure))
    asgi_headers = {name.decode("ascii"): value.decode("latin-1") for name, value in _run_asgi(secure)}

    assert wsgi_headers["X-Test"] == "café au lait"
    assert asgi_headers["X-Test"] == wsgi_headers["X-Test"]


# ---------------------------------------------------------------------------
# Final header lists re-read by a strict parser
# ---------------------------------------------------------------------------


def test_default_headers_survive_strict_reparse_wsgi_and_asgi():
    secure = Secure.with_default_headers()

    wsgi_parsed = _strict_parse(_run_wsgi(secure, app_headers=[("X-App", "keep")]))
    asgi_parsed = _strict_parse(_run_asgi(secure, app_headers=[(b"x-app", b"keep")]))

    for parsed in (wsgi_parsed, asgi_parsed):
        names = [name.lower() for name, _ in parsed]
        # No extra fields appeared beyond the app header and Secure's defaults.
        assert len(parsed) == len(secure.headers) + 1
        assert "x-app" in names
        assert "x-frame-options" in names
        assert "strict-transport-security" in names
        # Single-valued defaults are not duplicated.
        assert names.count("x-frame-options") == 1


def test_duplicate_existing_headers_collapse_to_single_field():
    secure = Secure.with_default_headers()
    app_headers = [("X-Frame-Options", "DENY"), ("x-frame-options", "SAMEORIGIN")]

    wsgi_parsed = _strict_parse(_run_wsgi(secure, app_headers=app_headers))
    asgi_parsed = _strict_parse(_run_asgi(secure, app_headers=[(n.encode(), v.encode()) for n, v in app_headers]))

    for parsed in (wsgi_parsed, asgi_parsed):
        xfo = [value for name, value in parsed if name.lower() == "x-frame-options"]
        assert xfo == [secure.headers["X-Frame-Options"]]


def test_multi_ok_merge_still_appends():
    secure = Secure.with_default_headers()

    wsgi_headers = _run_wsgi(secure, app_headers=[("Content-Security-Policy", "app-csp")])
    asgi_headers = _run_asgi(secure, app_headers=[(b"content-security-policy", b"app-csp")])

    wsgi_csp = [value for name, value in wsgi_headers if name.lower() == "content-security-policy"]
    asgi_csp = [value.decode("latin-1") for name, value in asgi_headers if name.lower() == b"content-security-policy"]
    assert wsgi_csp == ["app-csp", secure.headers["Content-Security-Policy"]]
    assert asgi_csp == wsgi_csp


# ---------------------------------------------------------------------------
# Sync/async emit
# ---------------------------------------------------------------------------


class _MappingResponse:
    def __init__(self) -> None:
        self.headers = {}


class _EchoingRaiseResponse:
    """Setter that leaks the offending value in its error, like some frameworks."""

    def set_header(self, name, value):
        raise ValueError(f"framework rejected value {value!r}")


class _AsyncEchoingRaiseResponse:
    async def set_header(self, name, value):
        raise ValueError(f"framework rejected value {value!r}")


def test_emit_sync_applies_valid_headers():
    response = _MappingResponse()
    set_headers_sync(response, (("X-Test", "café au lait"),))
    assert response.headers == {"X-Test": "café au lait"}


def test_emit_async_applies_valid_headers():
    response = _MappingResponse()
    asyncio.run(set_headers_async(response, (("X-Test", "value"),)))
    assert response.headers == {"X-Test": "value"}


def test_emit_sync_rejects_injection_with_sanitized_error():
    response = _MappingResponse()
    with pytest.raises(HeaderSetError, match=RULE_HEADER_VALUE) as excinfo:
        set_headers_sync(response, (("X-Test", "ok\r\nSet-Cookie: session=evil"),))
    assert "X-Test" in str(excinfo.value)
    assert "Set-Cookie" not in str(excinfo.value)
    assert response.headers == {}


def test_emit_async_rejects_injection_with_sanitized_error():
    response = _MappingResponse()
    with pytest.raises(HeaderSetError, match=RULE_HEADER_VALUE) as excinfo:
        asyncio.run(set_headers_async(response, (("X-Test", "ok\x00admin"),)))
    assert "X-Test" in str(excinfo.value)
    assert "admin" not in str(excinfo.value)


def test_emit_rejects_invalid_name():
    response = _MappingResponse()
    with pytest.raises(HeaderSetError, match=RULE_HEADER_NAME):
        set_headers_sync(response, (("Bad Name", "value"),))


def test_emit_sync_wraps_setter_errors_without_echoing_value():
    with pytest.raises(HeaderSetError, match=RULE_HEADER_SET) as excinfo:
        set_headers_sync(_EchoingRaiseResponse(), (("X-Test", "secret-value"),))
    assert "X-Test" in str(excinfo.value)
    assert "secret-value" not in str(excinfo.value)


def test_emit_async_wraps_setter_errors_without_echoing_value():
    with pytest.raises(HeaderSetError, match=RULE_HEADER_SET) as excinfo:
        asyncio.run(set_headers_async(_AsyncEchoingRaiseResponse(), (("X-Test", "secret-value"),)))
    assert "X-Test" in str(excinfo.value)
    assert "secret-value" not in str(excinfo.value)


def test_secure_set_headers_roundtrip_unchanged():
    secure = Secure.with_default_headers()
    response = _MappingResponse()
    secure.set_headers(response)
    assert response.headers["X-Frame-Options"] == secure.headers["X-Frame-Options"]


# ---------------------------------------------------------------------------
# Wire-level validator
# ---------------------------------------------------------------------------


def test_validate_wire_header_checks_name_then_value():
    with pytest.raises(ValueError, match=RULE_HEADER_NAME):
        validate_wire_header("Bad Name", "value")
    with pytest.raises(ValueError, match=RULE_HEADER_VALUE):
        validate_wire_header("X-Test", "ok\r\nSet-Cookie: x")
    with pytest.raises(ValueError, match=RULE_HEADER_ENCODING):
        validate_wire_header("X-Test", "张三")
    assert validate_wire_header("X-Test", "café") == ("X-Test", "café")
