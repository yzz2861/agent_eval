import linecache
import re
import sys
from unittest import mock

import pytest
from conftest import mark_dev_server
from werkzeug.debug import console
from werkzeug.debug import DebuggedApplication
from werkzeug.debug import DebugTraceback
from werkzeug.debug import get_machine_id
from werkzeug.debug.console import HTMLStringO
from werkzeug.debug.repr import debug_repr
from werkzeug.debug.repr import DebugReprGenerator
from werkzeug.debug.repr import dump
from werkzeug.debug.repr import helper
from werkzeug.test import Client
from werkzeug.wrappers import Request


class TestDebugRepr:
    def test_basic_repr(self):
        assert debug_repr([]) == "[]"
        assert debug_repr([1, 2]) == (
            '[<span class="number">1</span>, <span class="number">2</span>]'
        )
        assert debug_repr([1, "test"]) == (
            '[<span class="number">1</span>,'
            ' <span class="string">&#39;test&#39;</span>]'
        )
        assert debug_repr([None]) == '[<span class="object">None</span>]'

    def test_string_repr(self):
        assert debug_repr("") == '<span class="string">&#39;&#39;</span>'
        assert debug_repr("foo") == '<span class="string">&#39;foo&#39;</span>'
        assert debug_repr("s" * 80) == (
            f'<span class="string">&#39;{"s" * 69}'
            f'<span class="extended">{"s" * 11}&#39;</span></span>'
        )
        assert debug_repr("<" * 80) == (
            f'<span class="string">&#39;{"&lt;" * 69}'
            f'<span class="extended">{"&lt;" * 11}&#39;</span></span>'
        )

    def test_string_subclass_repr(self):
        class Test(str):
            pass

        assert debug_repr(Test("foo")) == (
            '<span class="module">test_debug.</span>'
            'Test(<span class="string">&#39;foo&#39;</span>)'
        )

    def test_sequence_repr(self):
        assert debug_repr(list(range(20))) == (
            '[<span class="number">0</span>, <span class="number">1</span>, '
            '<span class="number">2</span>, <span class="number">3</span>, '
            '<span class="number">4</span>, <span class="number">5</span>, '
            '<span class="number">6</span>, <span class="number">7</span>, '
            '<span class="extended"><span class="number">8</span>, '
            '<span class="number">9</span>, <span class="number">10</span>, '
            '<span class="number">11</span>, <span class="number">12</span>, '
            '<span class="number">13</span>, <span class="number">14</span>, '
            '<span class="number">15</span>, <span class="number">16</span>, '
            '<span class="number">17</span>, <span class="number">18</span>, '
            '<span class="number">19</span></span>]'
        )

    def test_mapping_repr(self):
        assert debug_repr({}) == "{}"
        assert debug_repr({"foo": 42}) == (
            '{<span class="pair"><span class="key"><span class="string">&#39;foo&#39;'
            '</span></span>: <span class="value"><span class="number">42'
            "</span></span></span>}"
        )
        assert debug_repr(dict(zip(range(10), [None] * 10, strict=True))) == (
            '{<span class="pair"><span class="key"><span class="number">0'
            '</span></span>: <span class="value"><span class="object">None'
            "</span></span></span>, "
            '<span class="pair"><span class="key"><span class="number">1'
            '</span></span>: <span class="value"><span class="object">None'
            "</span></span></span>, "
            '<span class="pair"><span class="key"><span class="number">2'
            '</span></span>: <span class="value"><span class="object">None'
            "</span></span></span>, "
            '<span class="pair"><span class="key"><span class="number">3'
            '</span></span>: <span class="value"><span class="object">None'
            "</span></span></span>, "
            '<span class="extended">'
            '<span class="pair"><span class="key"><span class="number">4'
            '</span></span>: <span class="value"><span class="object">None'
            "</span></span></span>, "
            '<span class="pair"><span class="key"><span class="number">5'
            '</span></span>: <span class="value"><span class="object">None'
            "</span></span></span>, "
            '<span class="pair"><span class="key"><span class="number">6'
            '</span></span>: <span class="value"><span class="object">None'
            "</span></span></span>, "
            '<span class="pair"><span class="key"><span class="number">7'
            '</span></span>: <span class="value"><span class="object">None'
            "</span></span></span>, "
            '<span class="pair"><span class="key"><span class="number">8'
            '</span></span>: <span class="value"><span class="object">None'
            "</span></span></span>, "
            '<span class="pair"><span class="key"><span class="number">9'
            '</span></span>: <span class="value"><span class="object">None'
            "</span></span></span></span>}"
        )
        assert debug_repr((1, "zwei", "drei")) == (
            '(<span class="number">1</span>, <span class="string">&#39;'
            'zwei&#39;</span>, <span class="string">&#39;drei&#39;</span>)'
        )

    def test_custom_repr(self):
        class Foo:
            def __repr__(self):
                return "<Foo 42>"

        assert debug_repr(Foo()) == '<span class="object">&lt;Foo 42&gt;</span>'

    def test_list_subclass_repr(self):
        class MyList(list):
            pass

        assert debug_repr(MyList([1, 2])) == (
            '<span class="module">test_debug.</span>MyList(['
            '<span class="number">1</span>, <span class="number">2</span>])'
        )

    def test_regex_repr(self):
        assert (
            debug_repr(re.compile(r"foo\d"))
            == "re.compile(<span class=\"string regex\">r'foo\\d'</span>)"
        )

    def test_set_repr(self):
        assert (
            debug_repr(frozenset("x"))
            == 'frozenset([<span class="string">&#39;x&#39;</span>])'
        )
        assert debug_repr(set("x")) == (
            'set([<span class="string">&#39;x&#39;</span>])'
        )

    def test_recursive_repr(self):
        a = [1]
        a.append(a)
        assert debug_repr(a) == '[<span class="number">1</span>, [...]]'

    def test_broken_repr(self):
        class Foo:
            def __repr__(self):
                raise Exception("broken!")

        assert debug_repr(Foo()) == (
            '<span class="brokenrepr">&lt;broken repr (Exception: broken!)&gt;</span>'
        )


class Foo:
    x = 42
    y = 23

    def __init__(self):
        self.z = 15


class TestDebugHelpers:
    def test_object_dumping(self):
        drg = DebugReprGenerator()
        out = drg.dump_object(Foo())
        assert re.search("Details for test_debug.Foo object at", out)
        assert re.search('<th>x.*<span class="number">42</span>', out, flags=re.DOTALL)
        assert re.search('<th>y.*<span class="number">23</span>', out, flags=re.DOTALL)
        assert re.search('<th>z.*<span class="number">15</span>', out, flags=re.DOTALL)

        out = drg.dump_object({"x": 42, "y": 23})
        assert re.search("Contents of", out)
        assert re.search('<th>x.*<span class="number">42</span>', out, flags=re.DOTALL)
        assert re.search('<th>y.*<span class="number">23</span>', out, flags=re.DOTALL)

        out = drg.dump_object({"x": 42, "y": 23, 23: 11})
        assert not re.search("Contents of", out)

        out = drg.dump_locals({"x": 42, "y": 23})
        assert re.search("Local variables in frame", out)
        assert re.search('<th>x.*<span class="number">42</span>', out, flags=re.DOTALL)
        assert re.search('<th>y.*<span class="number">23</span>', out, flags=re.DOTALL)

    def test_debug_dump(self):
        old = sys.stdout
        sys.stdout = HTMLStringO()
        try:
            dump([1, 2, 3])
            x = sys.stdout.reset()
            dump()
            y = sys.stdout.reset()
        finally:
            sys.stdout = old

        assert "Details for list object at" in x
        assert '<span class="number">1</span>' in x
        assert "Local variables in frame" in y
        assert "<th>x" in y
        assert "<th>old" in y

    def test_debug_help(self):
        old = sys.stdout
        sys.stdout = HTMLStringO()
        try:
            helper([1, 2, 3])
            x = sys.stdout.reset()
        finally:
            sys.stdout = old

        assert "Help on list object" in x
        assert "__delitem__" in x

    def test_exc_divider_found_on_chained_exception(self):
        @Request.application
        def app(request):
            def do_something():
                raise ValueError("inner")

            try:
                do_something()
            except ValueError:
                raise KeyError("outer")  # noqa: B904

        debugged = DebuggedApplication(app)
        client = Client(debugged)
        response = client.get("/")
        data = response.text
        assert 'raise ValueError("inner")' in data
        assert '<div class="exc-divider">' in data
        assert 'raise KeyError("outer")' in data


def test_get_machine_id():
    rv = get_machine_id()
    assert isinstance(rv, bytes)


@pytest.mark.parametrize("crash", (True, False))
@mark_dev_server
def test_basic(dev_server, crash):
    c = dev_server(use_debugger=True)
    r = c.request("/crash" if crash else "")
    assert r.status == (500 if crash else 200)

    if crash:
        assert b"The debugger caught an exception in your WSGI application" in r.data
    else:
        assert r.json["PATH_INFO"] == "/"


def test_console_closure_variables(monkeypatch):
    # restore the original display hook
    monkeypatch.setattr(sys, "displayhook", console._displayhook)
    c = console.Console()
    c.eval("y = 5")
    c.eval("x = lambda: y")
    ret = c.eval("x()")
    assert ret == ">>> x()\n5\n"


@pytest.mark.timeout(2)
def test_chained_exception_cycle():
    try:
        try:
            raise ValueError()
        except ValueError:
            raise TypeError()  # noqa: B904
    except TypeError as e:
        # create a cycle and make it available outside the except block
        e.__context__.__context__ = error = e

    # if cycles aren't broken, this will time out
    tb = DebugTraceback(error)
    assert len(tb.all_tracebacks) == 2


def test_exception_without_traceback():
    try:
        raise Exception("msg1")
    except Exception as e:
        # filter_hidden_frames should skip this since it has no traceback
        e.__context__ = Exception("msg2")
        DebugTraceback(e)


@mock.patch.object(linecache, "getlines", autospec=True)
def test_missing_source_lines(mock_getlines: mock.Mock) -> None:
    """Rendering doesn't fail when the line number is beyond the available
    source lines.
    """
    mock_getlines.return_value = ["truncated"]

    try:
        raise ValueError()
    except ValueError as e:
        tb = DebugTraceback(e)

    html = tb.render_traceback_html()
    assert "test_debug.py" in html
    assert "truncated" not in html


def test_debugged_application_pin_security_false():
    """Test that DebuggedApplication can be initialized with pin_security=False."""

    @Request.application
    def app(request):
        return "OK"

    # This should not raise AttributeError
    debugged = DebuggedApplication(app, evalex=True, pin_security=False)
    assert debugged.pin is None


def _debug_app(monkeypatch=None, pin="123-456-789", **kwargs):
    if monkeypatch is not None:
        monkeypatch.setenv("WERKZEUG_DEBUG_PIN", pin.replace("-", ""))

    @Request.application
    def app(request):
        return "OK"

    debugged = DebuggedApplication(app, evalex=True, pin_logging=False, **kwargs)
    return debugged, app


PIN = "123-456-789"


def _environ(path="/", host="a.localhost", cookie=None, query=None):
    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": path,
        "QUERY_STRING": query or "",
        "SERVER_NAME": host,
        "SERVER_PORT": "80",
        "HTTP_HOST": host,
        "wsgi.url_scheme": "http",
    }
    if cookie is not None:
        environ["HTTP_COOKIE"] = cookie
    return environ


def _cookie_header(debugged, value):
    return f"{debugged.pin_cookie_name}={value}"


def _auth_url(debugged, pin=PIN, extra=""):
    suffix = f"&{extra}" if extra else ""
    return (
        "/?__debugger__=yes&cmd=pinauth"
        f"&pin={pin.replace('-', '')}&s={debugged.secret}{suffix}"
    )


def _authenticate(client, debugged, host="a.localhost", pin=PIN):
    return client.get(_auth_url(debugged, pin), headers={"Host": host})


def _set_cookie(response, debugged):
    return response.headers["Set-Cookie"].split(";", 1)[0]


class TestStrictPinTrust:
    def test_strict_cookie_format_and_same_host(self, monkeypatch):
        monkeypatch.setattr("werkzeug.debug.time.sleep", lambda *_: None)
        debugged, _ = _debug_app(monkeypatch, strict_pin=True)
        client = Client(debugged)

        response = _authenticate(client, debugged)
        assert response.json == {"auth": True, "exhausted": False}

        value = response.headers["Set-Cookie"].split(";", 1)[0].split("=", 1)[1]
        parts = value.split("|")
        assert len(parts) == 5
        assert parts[0] == "1"
        # The PIN itself and its legacy digest must not appear in the cookie.
        assert PIN.replace("-", "") not in value
        from werkzeug.debug import hash_pin

        assert hash_pin(PIN) not in value

        result = debugged.check_pin_trust_detail(
            _environ(cookie=_cookie_header(debugged, value))
        )
        assert result.trusted is True
        assert result.reason == "ok"

    def test_cross_host_cookie_is_rejected(self, monkeypatch):
        monkeypatch.setattr("werkzeug.debug.time.sleep", lambda *_: None)
        debugged, _ = _debug_app(monkeypatch, strict_pin=True)
        client = Client(debugged)
        cookie = _set_cookie(_authenticate(client, debugged), debugged)

        result = debugged.check_pin_trust_detail(
            _environ(host="b.localhost", cookie=cookie)
        )
        assert result.trusted is False
        assert result.reason == "host-mismatch"
        assert (
            debugged.check_pin_trust(_environ(host="b.localhost", cookie=cookie))
            is False
        )

        # The same cookie still works on the host it was issued to.
        assert debugged.check_pin_trust(_environ(cookie=cookie)) is True

    def test_cross_host_console_has_no_executable_prompt(self, monkeypatch):
        monkeypatch.setattr("werkzeug.debug.time.sleep", lambda *_: None)
        debugged, _ = _debug_app(monkeypatch, strict_pin=True)
        client = Client(debugged)
        cookie = _set_cookie(_authenticate(client, debugged), debugged)

        trusted_page = client.get(
            "/console", headers={"Host": "a.localhost", "Cookie": cookie}
        )
        assert "EVALEX_TRUSTED = true" in trusted_page.text

        other_page = client.get(
            "/console", headers={"Host": "b.localhost", "Cookie": cookie}
        )
        assert "EVALEX_TRUSTED = false" in other_page.text

    def test_unknown_and_malformed_cookie_versions(self, monkeypatch):
        debugged, _ = _debug_app(monkeypatch, strict_pin=True)
        pin_version = debugged.pin_version
        key = debugged._get_pin_key()
        from werkzeug.debug import _sign_strict_pin_cookie

        good = _sign_strict_pin_cookie(key, pin_version, "a.localhost", 1000)

        # Unknown layout version is treated as a bad cookie to discard.
        unknown = good.replace("1|", "99|", 1)
        result = debugged.check_pin_trust_detail(
            _environ(cookie=_cookie_header(debugged, unknown))
        )
        assert result.trusted is None
        assert result.reason == "unknown-cookie-version"

        for bad in ("1|only-two", "1||||x", "1|v|host|not-an-int|mac"):
            result = debugged.check_pin_trust_detail(
                _environ(cookie=_cookie_header(debugged, bad))
            )
            assert result.reason == "malformed-cookie"

    def test_pin_rotation_invalidates_old_cookies(self, monkeypatch):
        debugged, _ = _debug_app(monkeypatch, strict_pin=True)
        debugged.time_func = lambda: 1000.0
        old_cookie = debugged._issue_strict_cookie(Request(_environ()))
        assert (
            debugged.check_pin_trust_detail(
                _environ(cookie=_cookie_header(debugged, old_cookie))
            ).reason
            == "ok"
        )

        debugged.pin = "987-654-321"

        result = debugged.check_pin_trust_detail(
            _environ(cookie=_cookie_header(debugged, old_cookie))
        )
        assert result.trusted is None
        assert result.reason == "pin-version-mismatch"

        # A freshly issued cookie for the new PIN works.
        new_cookie = debugged._issue_strict_cookie(Request(_environ()))
        assert (
            debugged.check_pin_trust_detail(
                _environ(cookie=_cookie_header(debugged, new_cookie))
            ).reason
            == "ok"
        )

    def test_clock_future_and_expiry(self, monkeypatch):
        debugged, _ = _debug_app(monkeypatch, strict_pin=True)
        debugged.time_func = lambda: 10_000.0
        cookie = debugged._issue_strict_cookie(Request(_environ()))
        header = _cookie_header(debugged, cookie)

        # Cookie issued "in the future" relative to the injected clock.
        debugged.time_func = lambda: 9_000.0
        result = debugged.check_pin_trust_detail(_environ(cookie=header))
        assert result.trusted is False
        assert result.reason == "future-timestamp"

        # Move the clock beyond the validity window.
        from werkzeug.debug import PIN_TIME

        debugged.time_func = lambda: 10_000.0 + PIN_TIME + 1
        result = debugged.check_pin_trust_detail(_environ(cookie=header))
        assert result.trusted is False
        assert result.reason == "expired"

    def test_tampered_signature(self, monkeypatch):
        debugged, _ = _debug_app(monkeypatch, strict_pin=True)
        debugged.time_func = lambda: 1000.0
        cookie = debugged._issue_strict_cookie(Request(_environ()))
        tampered = cookie[:-1] + ("0" if cookie[-1] != "0" else "1")
        result = debugged.check_pin_trust_detail(
            _environ(cookie=_cookie_header(debugged, tampered))
        )
        assert result.trusted is None
        assert result.reason == "invalid-signature"

    def test_failures_are_isolated_per_host_and_lock_out(self, monkeypatch):
        monkeypatch.setattr("werkzeug.debug.time.sleep", lambda *_: None)
        debugged, _ = _debug_app(monkeypatch, strict_pin=True)
        client = Client(debugged)

        response = None
        for _ in range(10):
            response = client.get(
                _auth_url(debugged, pin="000-000-000"),
                headers={"Host": "a.localhost"},
            )
        assert response.json == {"auth": False, "exhausted": True}

        # Locked out on host A, even with a valid cookie presented afterwards.
        cookie = debugged._issue_strict_cookie(Request(_environ()))
        result = debugged.check_pin_trust_detail(
            _environ(cookie=_cookie_header(debugged, cookie))
        )
        assert result.reason == "too-many-failures"

        # Host B has its own independent counter and still authenticates.
        fresh = _authenticate(client, debugged, host="b.localhost")
        assert fresh.json["auth"] is True
        assert fresh.json["exhausted"] is False

    def test_locked_out_blocks_console_and_execute(self, monkeypatch):
        monkeypatch.setattr("werkzeug.debug.time.sleep", lambda *_: None)
        debugged, _ = _debug_app(monkeypatch, strict_pin=True)
        debugged._strict_set_failure_count("a.localhost", 10)
        client = Client(debugged)

        response = client.get(_auth_url(debugged), headers={"Host": "a.localhost"})
        assert response.json == {"auth": False, "exhausted": True}

        # The standalone console renders in its locked state.
        console_page = client.get("/console", headers={"Host": "a.localhost"})
        assert "EVALEX_TRUSTED = false" in console_page.text

        # The command execution dispatch entry must stay inaccessible.
        environ = _environ(
            query=(f"__debugger__=yes&cmd=1%2B1&frm=0&s={debugged.secret}")
        )
        assert debugged.check_pin_trust(environ) is False

    def test_pin_is_never_echoed(self, monkeypatch):
        monkeypatch.setattr("werkzeug.debug.time.sleep", lambda *_: None)
        debugged, _ = _debug_app(monkeypatch, strict_pin=True)
        client = Client(debugged)

        bad = client.get(
            _auth_url(debugged, pin="000-000-000"),
            headers={"Host": "a.localhost"},
        )
        assert "123" not in bad.text
        assert "456" not in bad.text

        result = debugged.check_pin_trust_detail(
            _environ(cookie=_cookie_header(debugged, "garbage|value|here"))
        )
        assert "123" not in result.reason

    def test_normalized_host_ignores_case_and_port(self, monkeypatch):
        from werkzeug.debug import _normalize_host

        assert _normalize_host("A.LocalHost:5000") == "a.localhost"
        assert _normalize_host("[::1]:8080") == "::1"
        assert _normalize_host(None) == ""

        debugged, _ = _debug_app(monkeypatch, strict_pin=True)
        debugged.time_func = lambda: 1000.0
        cookie = debugged._issue_strict_cookie(
            Request(_environ(host="a.localhost:5000"))
        )
        result = debugged.check_pin_trust_detail(
            _environ(
                host="A.LOCALHOST:9999",
                cookie=_cookie_header(debugged, cookie),
            )
        )
        assert result.reason == "ok"


class TestLegacyPinTrustCompatibility:
    def test_default_keeps_legacy_cookie_format(self, monkeypatch):
        monkeypatch.setattr("werkzeug.debug.time.sleep", lambda *_: None)
        debugged, _ = _debug_app(monkeypatch)
        assert debugged.strict_pin is False
        client = Client(debugged)

        response = _authenticate(client, debugged)
        assert response.json["auth"] is True
        cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        value = cookie.split("=", 1)[1]

        # Legacy layout: timestamp|pin-hash, no version prefix.
        ts_str, _, pin_hash = value.partition("|")
        assert ts_str.isdecimal()
        from werkzeug.debug import hash_pin

        assert pin_hash == hash_pin(PIN)

        # Legacy cookies are not host-bound and remain accepted cross-host.
        assert (
            debugged.check_pin_trust(_environ(host="b.localhost", cookie=cookie))
            is True
        )

    def test_legacy_bad_cookie_returns_none(self, monkeypatch):
        debugged, _ = _debug_app(monkeypatch)
        result = debugged.check_pin_trust_detail(
            _environ(cookie=_cookie_header(debugged, "1234|deadbeefdead"))
        )
        assert result.trusted is None
        assert result.reason == "pin-version-mismatch"

    def test_legacy_global_failure_counter(self, monkeypatch):
        monkeypatch.setattr("werkzeug.debug.time.sleep", lambda *_: None)
        debugged, _ = _debug_app(monkeypatch)
        client = Client(debugged)

        for _ in range(10):
            client.get(
                _auth_url(debugged, pin="000-000-000"),
                headers={"Host": "a.localhost"},
            )

        # Legacy behavior: one global counter, so host B is locked out too.
        response = client.get(_auth_url(debugged), headers={"Host": "b.localhost"})
        assert response.json["exhausted"] is True

    def test_default_is_opt_in_only(self, monkeypatch):
        debugged, _ = _debug_app(monkeypatch)
        assert debugged._strict_failures == {}
        assert debugged.check_pin_trust_detail(_environ()).reason == "missing-cookie"
