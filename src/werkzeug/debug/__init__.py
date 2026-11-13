from __future__ import annotations

import collections.abc as cabc
import getpass
import hashlib
import hmac
import json
import os
import pkgutil
import re
import secrets
import subprocess
import sys
import threading
import time
import typing as t
import uuid
import wsgiref.types as wt
from contextlib import ExitStack
from io import BytesIO
from itertools import chain
from multiprocessing import Value
from os.path import basename
from os.path import join
from zlib import adler32

from .._internal import _log
from .._internal import _plain_int
from ..exceptions import NotFound
from ..exceptions import SecurityError
from ..http import parse_cookie
from ..sansio.utils import host_is_trusted
from ..utils import send_file
from ..wrappers.request import Request
from ..wrappers.response import Response
from .console import Console
from .tbtools import DebugFrameSummary
from .tbtools import DebugTraceback
from .tbtools import render_console_html

# A week
PIN_TIME = 60 * 60 * 24 * 7

# Strict PIN trust cookie format version. This only identifies the cookie
# layout, it never contains the PIN itself.
_STRICT_PIN_COOKIE_VERSION = "1"

# How many failed PIN attempts are allowed per verification boundary before
# the debugger locks it out.
_PIN_MAX_ATTEMPTS = 10

# Reasons returned by :meth:`DebuggedApplication.check_pin_trust_detail`. The
# values are intentionally generic and never include the PIN or cookie data.
PIN_TRUST_OK = "ok"
PIN_TRUST_DISABLED = "pin-disabled"
PIN_TRUST_LOCKED = "too-many-failures"
PIN_TRUST_NO_COOKIE = "missing-cookie"
PIN_TRUST_MALFORMED = "malformed-cookie"
PIN_TRUST_UNKNOWN_VERSION = "unknown-cookie-version"
PIN_TRUST_VERSION_MISMATCH = "pin-version-mismatch"
PIN_TRUST_HOST_MISMATCH = "host-mismatch"
PIN_TRUST_FUTURE = "future-timestamp"
PIN_TRUST_EXPIRED = "expired"
PIN_TRUST_INVALID_SIGNATURE = "invalid-signature"


def hash_pin(pin: str) -> str:
    return hashlib.sha3_256(f"{pin} added salt".encode("utf-8", "replace")).hexdigest()[
        :12
    ]


def _pin_version(pin: str) -> str:
    """Derive a stable version identifier for a PIN.

    Rotating the PIN changes this value, which invalidates every trust cookie
    issued for the previous PIN. The output is a digest, not the PIN.
    """
    return hashlib.sha3_256(f"pin-version:{pin}".encode("utf-8", "replace")).hexdigest()


def _normalize_host(host: str | None) -> str:
    """Return a canonical, case-insensitive host without a port.

    The reverse proxy may expose the same app on several internal domains, so
    the normalized host is the verification boundary a trust cookie is bound
    to. An absent or malformed host normalizes to the empty string instead of
    raising, which keeps cookie parsing free of data-dependent failures.
    """
    if not host:
        return ""

    host = host.strip().lower()

    if host.startswith("["):
        # IPv6 literal, optionally followed by a port: ``[::1]:5000``.
        end = host.find("]")
        if end == -1:
            return ""
        return host[1:end]

    # Strip a single trailing ``:port``. Bare IPv6 literals without brackets
    # are treated as opaque names rather than guessed at.
    if host.count(":") == 1:
        host = host.partition(":")[0]

    return host


def _strict_pin_key(pin: str, cookie_name: str) -> bytes:
    """Derive the HMAC key used to sign and verify strict trust cookies."""
    return hmac.new(
        cookie_name.encode("utf-8"),
        f"strict-pin:{pin}".encode("utf-8", "replace"),
        hashlib.sha256,
    ).digest()


def _sign_strict_pin_cookie(
    key: bytes, pin_version: str, host: str, timestamp: int
) -> str:
    """Build a versioned trust cookie value.

    The value carries the cookie layout version, PIN derivation version,
    normalized host and issue time, plus an HMAC over those fields. The PIN is
    never written into the cookie.
    """
    message = f"{_STRICT_PIN_COOKIE_VERSION}|{pin_version}|{host}|{int(timestamp)}"
    digest = hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{message}|{digest}"


class PinTrustResult:
    """Outcome of a PIN trust check.

    ``trusted`` mirrors the legacy tri-state: ``True`` when the request is
    trusted, ``False`` when it is not, and ``None`` when a cookie was present
    but could not be associated with the current PIN and should be discarded.
    ``reason`` is a generic, non-sensitive classification of the outcome.
    """

    __slots__ = ("trusted", "reason")

    def __init__(self, trusted: bool | None, reason: str) -> None:
        self.trusted = trusted
        self.reason = reason

    def __bool__(self) -> bool:
        return bool(self.trusted)

    def __repr__(self) -> str:
        return f"PinTrustResult(trusted={self.trusted!r}, reason={self.reason!r})"


_machine_id: str | bytes | None = None


def get_machine_id() -> str | bytes | None:
    global _machine_id

    if _machine_id is not None:
        return _machine_id

    def _generate() -> str | bytes | None:
        linux = b""

        # machine-id is stable across boots, boot_id is not.
        for filename in "/etc/machine-id", "/proc/sys/kernel/random/boot_id":
            try:
                with open(filename, "rb") as f:
                    value = f.readline().strip()
            except OSError:
                continue

            if value:
                linux += value
                break

        # Containers share the same machine id, add some cgroup
        # information. This is used outside containers too but should be
        # relatively stable across boots.
        try:
            with open("/proc/self/cgroup", "rb") as f:
                linux += f.readline().strip()
        except OSError:
            pass

        if linux:
            return linux

        # On OS X, use ioreg to get the computer's serial number.
        try:
            dump = subprocess.Popen(
                ["ioreg", "-c", "IOPlatformExpertDevice", "-d", "2"],
                stdout=subprocess.PIPE,
            ).communicate()[0]
            match = re.search(b'"serial-number" = <([^>]+)', dump)

            if match is not None:
                return match.group(1)
        except OSError:
            pass

        # On Windows, use winreg to get the machine guid.
        if sys.platform == "win32":
            import winreg

            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    "SOFTWARE\\Microsoft\\Cryptography",
                    0,
                    winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
                ) as rk:
                    guid: str | bytes
                    guid_type: int
                    guid, guid_type = winreg.QueryValueEx(rk, "MachineGuid")

                    if guid_type == winreg.REG_SZ:
                        return guid.encode()

                    return guid
            except OSError:
                pass

        return None

    _machine_id = _generate()
    return _machine_id


class _ConsoleFrame:
    """Helper class so that we can reuse the frame console code for the
    standalone console.
    """

    def __init__(self, namespace: dict[str, t.Any]):
        self.console = Console(namespace)
        self.id = 0

    def eval(self, code: str) -> t.Any:
        return self.console.eval(code)


def get_pin_and_cookie_name(
    app: wt.WSGIApplication,
) -> tuple[str, str] | tuple[None, None]:
    """Given an application object this returns a semi-stable 9 digit pin
    code and a random key.  The hope is that this is stable between
    restarts to not make debugging particularly frustrating.  If the pin
    was forcefully disabled this returns `None`.

    Second item in the resulting tuple is the cookie name for remembering.
    """
    pin = os.environ.get("WERKZEUG_DEBUG_PIN")
    rv = None
    num = None

    # Pin was explicitly disabled
    if pin == "off":
        return None, None

    # Pin was provided explicitly
    if pin is not None and pin.replace("-", "").isdecimal():
        # If there are separators in the pin, return it directly
        if "-" in pin:
            rv = pin
        else:
            num = pin

    modname = getattr(app, "__module__", t.cast(object, app).__class__.__module__)
    username: str | None

    try:
        # Python < 3.13 may raise a KeyError if the UID does not have a
        # username, such as in Docker.
        username = getpass.getuser()
    except (KeyError, OSError):
        username = None

    mod = sys.modules.get(modname)

    # This information only exists to make the cookie unique on the
    # computer, not as a security feature.
    probably_public_bits = [
        username,
        modname,
        getattr(app, "__name__", type(app).__name__),
        getattr(mod, "__file__", None),
    ]

    # This information is here to make it harder for an attacker to
    # guess the cookie name.  They are unlikely to be contained anywhere
    # within the unauthenticated debug page.
    private_bits = [str(uuid.getnode()), get_machine_id()]

    h = hashlib.sha3_256()
    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode()
        h.update(bit)
    h.update(b"cookiesalt")

    cookie_name = f"__wzd{h.hexdigest()[:20]}"

    # If we need to generate a pin we salt it a bit more so that we don't
    # end up with the same value and generate out 9 digits
    if num is None:
        h.update(b"pinsalt")
        num = f"{int(h.hexdigest(), 16):09d}"[:9]

    # Format the pincode in groups of digits for easier remembering if
    # we don't have a result yet.
    if rv is None:
        for group_size in 5, 4, 3:
            if len(num) % group_size == 0:
                rv = "-".join(
                    num[x : x + group_size].rjust(group_size, "0")
                    for x in range(0, len(num), group_size)
                )
                break
        else:
            rv = num

    return rv, cookie_name


class DebuggedApplication:
    """Enables debugging support for a given application::

        from werkzeug.debug import DebuggedApplication
        from myapp import app
        app = DebuggedApplication(app, evalex=True)

    The ``evalex`` argument allows evaluating expressions in any frame
    of a traceback. This works by preserving each frame with its local
    state. Some state, such as context globals, cannot be restored with
    the frame by default. When ``evalex`` is enabled,
    ``environ["werkzeug.debug.preserve_context"]`` will be a callable
    that takes a context manager, and can be called multiple times.
    Each context manager will be entered before evaluating code in the
    frame, then exited again, so they can perform setup and cleanup for
    each call.

    :param app: the WSGI application to run debugged.
    :param evalex: enable exception evaluation feature (interactive
                   debugging).  This requires a non-forking server.
    :param console_path: the URL for a general purpose console.
    :param console_init_func: the function that is executed before starting
                              the general purpose console.  The return value
                              is used as initial namespace.
    :param show_hidden_frames: by default hidden traceback frames are skipped.
                               You can show them by setting this parameter
                               to `True`.
    :param pin_security: can be used to disable the pin based security system.
    :param pin_logging: enables the logging of the pin system.
    :param strict_pin: enable strict PIN trust cookies. Cookies are bound to
                       the normalized request host, PIN derivation version and
                       issue time, fail closed on unknown versions and clock
                       skew, and track failures per host. Defaults to
                       ``False`` to preserve the legacy cookie behavior.

    .. versionchanged:: 3.2
        The ``reqeust_key`` parameter was removed.

    .. versionchanged:: 2.2
        Added the ``werkzeug.debug.preserve_context`` environ key.
    """

    _pin: str | None
    _pin_cookie: str

    def __init__(
        self,
        app: wt.WSGIApplication,
        evalex: bool = False,
        console_path: str = "/console",
        console_init_func: t.Callable[[], dict[str, t.Any]] | None = None,
        show_hidden_frames: bool = False,
        pin_security: bool = True,
        pin_logging: bool = True,
        strict_pin: bool = False,
    ) -> None:
        if not console_init_func:
            console_init_func = None
        self.app = app
        self.evalex = evalex
        self.frames: dict[int, DebugFrameSummary | _ConsoleFrame] = {}
        self.frame_contexts: dict[int, list[t.ContextManager[None]]] = {}
        self.console_path = console_path
        self.console_init_func = console_init_func
        self.show_hidden_frames = show_hidden_frames
        self.secret = secrets.token_urlsafe(20)
        self._failed_pin_auth = Value("B")
        self.strict_pin = strict_pin
        # Strict mode isolates failed attempts per normalized host, which is
        # the verification boundary the cookie is bound to.
        self._strict_failures: dict[str, int] = {}
        self._strict_failures_lock = threading.Lock()
        # Injectable time source; defaults to the wall clock.
        self.time_func: t.Callable[[], float] = time.time

        self.pin_logging = pin_logging
        if pin_security:
            # Print out the pin for the debugger on standard out.
            if os.environ.get("WERKZEUG_RUN_MAIN") == "true" and pin_logging:
                _log("warning", " * Debugger is active!")
                if self.pin is None:
                    _log("warning", " * Debugger PIN disabled. DEBUGGER UNSECURED!")
                else:
                    _log("info", " * Debugger PIN: %s", self.pin)
        else:
            self.pin = None

        self.trusted_hosts: list[str] = [".localhost", "127.0.0.1"]
        """List of domains to allow requests to the debugger from. A leading dot
        allows all subdomains. This only allows ``".localhost"`` domains by
        default.

        .. versionadded:: 3.0.3
        """

    @property
    def pin(self) -> str | None:
        if not hasattr(self, "_pin"):
            pin_cookie = get_pin_and_cookie_name(self.app)
            self._pin, self._pin_cookie = pin_cookie  # type: ignore[assignment]
        return self._pin

    @pin.setter
    def pin(self, value: str | None) -> None:
        if value is None:
            # Set _pin to None explicitly to prevent regeneration by the getter
            self._pin = None
        else:
            self._pin = value
        # Rotating the PIN must invalidate cached derived material so that any
        # cookie issued for the old PIN fails the version check immediately.
        self.__dict__.pop("_pin_version", None)
        self.__dict__.pop("_pin_key", None)

    @property
    def pin_cookie_name(self) -> str:
        """The name of the pin cookie."""
        if not hasattr(self, "_pin_cookie"):
            pin_cookie = get_pin_and_cookie_name(self.app)
            self._pin, self._pin_cookie = pin_cookie  # type: ignore[assignment]
        return self._pin_cookie

    @property
    def pin_version(self) -> str | None:
        """Stable identifier derived from the current PIN.

        Rotating the PIN changes this value, which makes strict cookies issued
        previously fail verification immediately.
        """
        if self.pin is None:
            return None

        if "_pin_version" not in self.__dict__:
            self._pin_version = _pin_version(self.pin)

        return self._pin_version

    def _get_pin_key(self) -> bytes:
        if "_pin_key" not in self.__dict__:
            self._pin_key = _strict_pin_key(t.cast(str, self.pin), self.pin_cookie_name)

        return self._pin_key

    def debug_application(
        self, environ: wt.WSGIEnvironment, start_response: wt.StartResponse
    ) -> t.Iterator[bytes]:
        """Run the application and conserve the traceback frames."""
        contexts: list[t.ContextManager[t.Any]] = []

        if self.evalex:
            environ["werkzeug.debug.preserve_context"] = contexts.append

        app_iter: cabc.Iterator[bytes] | None = None

        try:
            app_iter = self.app(environ, start_response)  # type: ignore[assignment]
            yield from app_iter  # type: ignore[misc]
            if app_iter is not None and hasattr(app_iter, "close"):
                app_iter.close()
        except Exception as e:
            if app_iter is not None and hasattr(app_iter, "close"):
                app_iter.close()

            tb = DebugTraceback(e, skip=1, hide=not self.show_hidden_frames)

            for frame in tb.all_frames:
                self.frames[id(frame)] = frame
                self.frame_contexts[id(frame)] = contexts

            is_trusted = bool(self.check_pin_trust(environ))
            html = tb.render_debugger_html(
                evalex=self.evalex and self.check_host_trust(environ),
                secret=self.secret,
                evalex_trusted=is_trusted,
            )
            response = Response(html, status=500, mimetype="text/html")

            try:
                yield from response(environ, start_response)
            except Exception:
                # if we end up here there has been output but an error
                # occurred.  in that situation we can do nothing fancy any
                # more, better log something into the error log and fall
                # back gracefully.
                environ["wsgi.errors"].write(
                    "Debugging middleware caught exception in streamed "
                    "response at a point where response headers were already "
                    "sent.\n"
                )

            environ["wsgi.errors"].write("".join(tb.render_traceback_text()))

    def execute_command(
        self,
        request: Request,
        command: str,
        frame: DebugFrameSummary | _ConsoleFrame,
    ) -> Response:
        """Execute a command in a console."""
        if not self.check_host_trust(request.environ):
            return SecurityError()  # type: ignore[return-value]

        contexts = self.frame_contexts.get(id(frame), [])

        with ExitStack() as exit_stack:
            for cm in contexts:
                exit_stack.enter_context(cm)

            return Response(frame.eval(command), mimetype="text/html")

    def display_console(self, request: Request) -> Response:
        """Display a standalone shell."""
        if not self.check_host_trust(request.environ):
            return SecurityError()  # type: ignore[return-value]

        if 0 not in self.frames:
            if self.console_init_func is None:
                ns = {}
            else:
                ns = dict(self.console_init_func())
            ns.setdefault("app", self.app)
            self.frames[0] = _ConsoleFrame(ns)
        is_trusted = bool(self.check_pin_trust(request.environ))
        return Response(
            render_console_html(secret=self.secret, evalex_trusted=is_trusted),
            mimetype="text/html",
        )

    def get_resource(self, request: Request, filename: str) -> Response:
        """Return a static resource from the shared folder."""
        path = join("shared", basename(filename))

        try:
            data = pkgutil.get_data(__package__, path)
        except OSError:
            return NotFound()  # type: ignore[return-value]
        else:
            if data is None:
                return NotFound()  # type: ignore[return-value]

            etag = str(adler32(data) & 0xFFFFFFFF)
            return send_file(
                BytesIO(data), request.environ, download_name=filename, etag=etag
            )

    def _pin_boundary(self, environ: wt.WSGIEnvironment) -> str:
        """The verification boundary used to isolate failures in strict mode."""
        return _normalize_host(environ.get("HTTP_HOST"))

    def _strict_failure_count(self, boundary: str) -> int:
        with self._strict_failures_lock:
            return self._strict_failures.get(boundary, 0)

    def _strict_set_failure_count(self, boundary: str, value: int) -> None:
        with self._strict_failures_lock:
            self._strict_failures[boundary] = value

    def _is_locked_out(self, environ: wt.WSGIEnvironment) -> bool:
        if self.strict_pin:
            return self._strict_failure_count(self._pin_boundary(environ)) >= (
                _PIN_MAX_ATTEMPTS
            )

        return self._failed_pin_auth.value >= _PIN_MAX_ATTEMPTS

    def check_pin_trust_detail(self, environ: wt.WSGIEnvironment) -> PinTrustResult:
        """Check whether the request passed PIN authentication.

        Unlike :meth:`check_pin_trust`, this always returns a
        :class:`PinTrustResult` whose ``reason`` classifies the outcome. In
        strict mode every distinct failure (unknown cookie version, cross-host
        reuse, clock skew, bad signature, ...) gets its own reason. The reason
        never contains the PIN or any cookie material.
        """
        if self.pin is None:
            return PinTrustResult(True, PIN_TRUST_DISABLED)

        # If we failed too many times, then we're locked out.
        if self._is_locked_out(environ):
            return PinTrustResult(False, PIN_TRUST_LOCKED)

        val = parse_cookie(environ.get("HTTP_COOKIE")).get(self.pin_cookie_name)

        if not val:
            return PinTrustResult(False, PIN_TRUST_NO_COOKIE)

        if self.strict_pin:
            return self._check_strict_cookie(environ, val)

        if "|" not in val:
            return PinTrustResult(False, PIN_TRUST_MALFORMED)

        ts_str, _, pin_hash = val.partition("|")

        try:
            ts = _plain_int(ts_str)
        except ValueError:
            return PinTrustResult(False, PIN_TRUST_MALFORMED)

        if not hmac.compare_digest(pin_hash, hash_pin(self.pin)):
            return PinTrustResult(None, PIN_TRUST_VERSION_MISMATCH)

        if (time.time() - PIN_TIME) < ts:
            return PinTrustResult(True, PIN_TRUST_OK)

        return PinTrustResult(False, PIN_TRUST_EXPIRED)

    def _check_strict_cookie(
        self, environ: wt.WSGIEnvironment, val: str
    ) -> PinTrustResult:
        parts = val.split("|")

        if len(parts) != 5 or not all(parts):
            return PinTrustResult(False, PIN_TRUST_MALFORMED)

        cookie_version, cookie_pin_version, cookie_host, ts_str, _mac = parts

        if not hmac.compare_digest(cookie_version, _STRICT_PIN_COOKIE_VERSION):
            return PinTrustResult(None, PIN_TRUST_UNKNOWN_VERSION)

        try:
            ts = _plain_int(ts_str)
        except ValueError:
            return PinTrustResult(False, PIN_TRUST_MALFORMED)

        expected_host = self._pin_boundary(environ)

        if not hmac.compare_digest(cookie_host, expected_host):
            return PinTrustResult(False, PIN_TRUST_HOST_MISMATCH)

        if not hmac.compare_digest(cookie_pin_version, t.cast(str, self.pin_version)):
            return PinTrustResult(None, PIN_TRUST_VERSION_MISMATCH)

        now = self.time_func()

        if ts > now:
            return PinTrustResult(False, PIN_TRUST_FUTURE)

        if ts < now - PIN_TIME:
            return PinTrustResult(False, PIN_TRUST_EXPIRED)

        expected = _sign_strict_pin_cookie(
            self._get_pin_key(),
            t.cast(str, self.pin_version),
            expected_host,
            ts,
        )

        if not hmac.compare_digest(val, expected):
            return PinTrustResult(None, PIN_TRUST_INVALID_SIGNATURE)

        return PinTrustResult(True, PIN_TRUST_OK)

    def check_pin_trust(self, environ: wt.WSGIEnvironment) -> bool | None:
        """Checks if the request passed the pin test. This returns `True` if
        the request is trusted on a pin/cookie basis and returns `False` if
        not. Additionally if the cookie cannot be associated with the current
        PIN it will return `None` so that the cookie is discarded.

        Use :meth:`check_pin_trust_detail` for the classified failure reason.
        The legacy behavior is unchanged unless ``strict_pin`` is enabled.
        """
        return self.check_pin_trust_detail(environ).trusted

    def check_host_trust(self, environ: wt.WSGIEnvironment) -> bool:
        return host_is_trusted(environ.get("HTTP_HOST"), self.trusted_hosts)

    def _fail_pin_auth(self, environ: wt.WSGIEnvironment | None = None) -> None:
        if self.strict_pin and environ is not None:
            boundary = self._pin_boundary(environ)

            with self._strict_failures_lock:
                count = self._strict_failures.get(boundary, 0) + 1
                self._strict_failures[boundary] = count

            time.sleep(5.0 if count > 5 else 0.5)
            return

        with self._failed_pin_auth.get_lock():
            count = self._failed_pin_auth.value
            self._failed_pin_auth.value = count + 1

        time.sleep(5.0 if count > 5 else 0.5)

    def _issue_strict_cookie(self, request: Request) -> str:
        return _sign_strict_pin_cookie(
            self._get_pin_key(),
            t.cast(str, self.pin_version),
            self._pin_boundary(request.environ),
            int(self.time_func()),
        )

    def pin_auth(self, request: Request) -> Response:
        """Authenticates with the pin."""
        if not self.check_host_trust(request.environ):
            return SecurityError()  # type: ignore[return-value]

        if self.strict_pin:
            return self._pin_auth_strict(request)

        return self._pin_auth_legacy(request)

    def _pin_auth_strict(self, request: Request) -> Response:
        """Strict PIN authentication with host-bound, versioned cookies."""
        exhausted = False
        auth = False
        result = self.check_pin_trust_detail(request.environ)
        pin = t.cast(str, self.pin)

        # A cookie that cannot be associated with the current PIN counts as a
        # bad auth and is unset, so guessing the cookie name is not easier
        # than guessing the PIN. The generic reason is logged without any
        # cookie or PIN material.
        bad_cookie = result.trusted is None
        if bad_cookie:
            self._fail_pin_auth(request.environ)
            if self.pin_logging:
                _log(
                    "warning",
                    " * Debugger PIN trust rejected, reason: %s",
                    result.reason,
                )
        elif result.trusted:
            auth = True
        elif self._is_locked_out(request.environ):
            exhausted = True
        else:
            entered_pin = request.args["pin"]

            if hmac.compare_digest(
                entered_pin.strip().replace("-", ""), pin.replace("-", "")
            ):
                self._strict_set_failure_count(self._pin_boundary(request.environ), 0)
                auth = True
            else:
                self._fail_pin_auth(request.environ)
                exhausted = self._is_locked_out(request.environ)

        rv = Response(
            json.dumps({"auth": auth, "exhausted": exhausted}),
            mimetype="application/json",
        )
        if auth:
            rv.set_cookie(
                self.pin_cookie_name,
                self._issue_strict_cookie(request),
                httponly=True,
                samesite="Strict",
                secure=request.is_secure,
            )
        elif bad_cookie:
            rv.delete_cookie(self.pin_cookie_name)
        return rv

    def _pin_auth_legacy(self, request: Request) -> Response:
        """Legacy PIN authentication, kept byte-for-byte in behavior."""
        exhausted = False
        auth = False
        trust = self.check_pin_trust(request.environ)
        pin = t.cast(str, self.pin)

        # If the trust return value is `None` it means that the cookie is
        # set but the stored pin hash value is bad.  This means that the
        # pin was changed.  In this case we count a bad auth and unset the
        # cookie.  This way it becomes harder to guess the cookie name
        # instead of the pin as we still count up failures.
        bad_cookie = False
        if trust is None:
            self._fail_pin_auth()
            bad_cookie = True

        # If we're trusted, we're authenticated.
        elif trust:
            auth = True

        # If we failed too many times, then we're locked out.
        elif self._failed_pin_auth.value >= _PIN_MAX_ATTEMPTS:
            exhausted = True

        # Otherwise go through pin based authentication
        else:
            entered_pin = request.args["pin"]

            if entered_pin.strip().replace("-", "") == pin.replace("-", ""):
                self._failed_pin_auth.value = 0
                auth = True
            else:
                self._fail_pin_auth()

        rv = Response(
            json.dumps({"auth": auth, "exhausted": exhausted}),
            mimetype="application/json",
        )
        if auth:
            rv.set_cookie(
                self.pin_cookie_name,
                f"{int(time.time())}|{hash_pin(pin)}",
                httponly=True,
                samesite="Strict",
                secure=request.is_secure,
            )
        elif bad_cookie:
            rv.delete_cookie(self.pin_cookie_name)
        return rv

    def log_pin_request(self, request: Request) -> Response:
        """Log the pin if needed."""
        if not self.check_host_trust(request.environ):
            return SecurityError()  # type: ignore[return-value]

        if self.pin_logging and self.pin is not None:
            _log(
                "info", " * To enable the debugger you need to enter the security pin:"
            )
            _log("info", " * Debugger pin code: %s", self.pin)
        return Response("")

    def __call__(
        self, environ: wt.WSGIEnvironment, start_response: wt.StartResponse
    ) -> t.Iterable[bytes]:
        """Dispatch the requests."""
        # important: don't ever access a function here that reads the incoming
        # form data!  Otherwise the application won't have access to that data
        # any more!
        request = Request(environ)
        response: wt.WSGIApplication = self.debug_application
        if request.args.get("__debugger__") == "yes":
            cmd = request.args.get("cmd")
            arg = request.args.get("f")
            secret = request.args.get("s")
            frame = self.frames.get(request.args.get("frm", type=int))  # type: ignore[arg-type]
            if cmd == "resource" and arg:
                response = self.get_resource(request, arg)
            elif cmd == "pinauth" and secret == self.secret:
                response = self.pin_auth(request)
            elif cmd == "printpin" and secret == self.secret:
                response = self.log_pin_request(request)
            elif (
                self.evalex
                and cmd is not None
                and frame is not None
                and self.secret == secret
                and self.check_pin_trust(environ)
            ):
                response = self.execute_command(request, cmd, frame)
        elif (
            self.evalex
            and self.console_path is not None
            and request.path == self.console_path
        ):
            response = self.display_console(request)
        return response(environ, start_response)
