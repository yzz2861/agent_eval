"""
requests.cookies
~~~~~~~~~~~~~~~~

Compatibility code to be able to use `http.cookiejar.CookieJar` with requests.

requests.utils imports from here, so be careful with imports.
"""

from __future__ import annotations

import calendar
import copy
import time
from collections.abc import Iterator, MutableMapping
from http.cookiejar import Cookie, CookieJar, CookiePolicy, DefaultCookiePolicy
from typing import TYPE_CHECKING, Any, TypeVar, overload

from ._internal_utils import to_native_string
from ._types import is_prepared as _is_prepared
from .compat import Morsel, cookielib, urlparse, urlunparse

if TYPE_CHECKING:
    from _typeshed import SupportsKeysAndGetItem

    from .models import PreparedRequest

import threading


def normalize_cookie_host(host: str | None) -> str:
    """Return the canonical form of a host used for all cookie scoping.

    The exact same normalization is applied on the extract (set) path, the
    send (return) path, and for redirect/proxy/IDNA edge cases, so that
    same-origin checks always compare like with like: the host is
    lowercased, any trailing dot is removed, IPv6 literals keep their
    brackets, and internationalized names are IDNA-encoded.
    """
    if not host:
        return ""
    normalized = host.strip().lower().rstrip(".")
    if normalized.startswith("[") and normalized.endswith("]"):
        # IPv6 literal: unambiguous once lowercased.
        return normalized
    try:
        return normalized.encode("idna").decode("ascii")
    except UnicodeError:
        return normalized


# Minimal built-in public suffix list. Cookies must never be scoped to one
# of these (e.g. Domain=.com or Domain=co.uk), because that would share
# them across unrelated tenants of the same suffix. Deployments can supply
# their own list via SessionCookiePolicy(public_suffixes=...).
_DEFAULT_PUBLIC_SUFFIXES = frozenset(
    {
        "ac.uk",
        "aero",
        "ai",
        "app",
        "biz",
        "cc",
        "club",
        "co",
        "co.il",
        "co.in",
        "co.jp",
        "co.kr",
        "co.nz",
        "co.uk",
        "co.za",
        "com",
        "com.au",
        "com.br",
        "com.cn",
        "com.hk",
        "com.mx",
        "com.tw",
        "coop",
        "dev",
        "edu",
        "eu",
        "gov",
        "gov.cn",
        "gov.uk",
        "info",
        "int",
        "io",
        "me",
        "mil",
        "museum",
        "name",
        "net",
        "net.au",
        "net.cn",
        "online",
        "org",
        "org.au",
        "org.cn",
        "org.uk",
        "pro",
        "shop",
        "site",
        "su",
        "tech",
        "top",
        "tv",
        "xyz",
        # Single-label TLDs and well-known public-suffix second levels.
        "ac.jp",
        "ae",
        "ar",
        "at",
        "au",
        "be",
        "br",
        "ca",
        "ch",
        "cl",
        "cn",
        "de",
        "dk",
        "eg",
        "es",
        "fi",
        "fr",
        "hk",
        "id",
        "ie",
        "il",
        "in",
        "it",
        "jp",
        "ke",
        "kr",
        "mx",
        "my",
        "ne.jp",
        "ng",
        "nl",
        "no",
        "nz",
        "or.jp",
        "ph",
        "pl",
        "ru",
        "sa",
        "se",
        "sg",
        "th",
        "tr",
        "tw",
        "uk",
        "us",
        "vn",
        "za",
    }
)


def _normalized_request_host(request: Any) -> str:
    """Canonical host of an outgoing request (URL or Host-header override)."""
    url = request.get_full_url()
    return normalize_cookie_host(urlparse(url).hostname)


def _effective_request_port(request: Any) -> int | None:
    """Port the request will be sent to, defaulting from the URL scheme."""
    parsed = urlparse(request.get_full_url())
    try:
        if parsed.port is not None:
            return parsed.port
    except ValueError:
        return None
    scheme = (parsed.scheme or "").lower()
    if scheme in ("https", "wss"):
        return 443
    if scheme in ("http", "ws"):
        return 80
    return None


def _is_insecure_samesite_none(cookie: Cookie) -> bool:
    """True for SameSite=None cookies missing the Secure attribute."""
    if cookie.secure:
        return False
    rest = getattr(cookie, "_rest", None) or {}
    for key, value in rest.items():
        if (
            key.lower() == "samesite"
            and isinstance(value, str)
            and value.lower() == "none"
        ):
            return True
    return False


def _cookie_sort_key(cookie: Cookie) -> tuple[int, str, str, str]:
    """Deterministic send order: longest (most specific) path first."""
    path = cookie.path or ""
    return (-len(path), cookie.domain or "", path, cookie.name or "")


def _iter_jar_cookies_sorted(jar: CookieJar) -> list[Cookie]:
    """Iterate a jar in a deterministic (domain, path, name) order."""
    return sorted(jar, key=lambda c: (c.domain or "", c.path or "", c.name or ""))


class SessionCookiePolicy(DefaultCookiePolicy):
    """Scoping and attribute policy for session-level cookie jars.

    This policy tightens http.cookiejar.DefaultCookiePolicy so that a jar
    shared across tenants cannot leak cookies:

    * Cookies are matched against the request host, path, secure flag and
      port. Host comparison always goes through normalize_cookie_host,
      giving one canonical form for direct requests, redirects, proxies
      and IDNA names.
    * A Domain attribute naming a public suffix (e.g. .com or co.uk) is
      rejected when the cookie is set.
    * A cookie scoped to a parent domain (e.g. Domain=.example.com) is
      only returned to that exact host. Sending it to subdomains (sibling
      tenants such as evil.example.com) requires the domain to be listed
      in allowed_shared_domains.
    * Host-only cookies (no Domain attribute) are only returned to the
      exact host that set them, never to subdomains.
    * secure cookies are only sent over HTTPS (inherited from
      DefaultCookiePolicy.secure_protocols).
    * SameSite=None cookies without Secure are rejected when set, unless
      reject_insecure_samesite_none is disabled.
    * HttpOnly is preserved as cookie metadata (cookie._rest) only;
      requests is not a browser and does not emulate script-access rules.

    Cookies created from the dict API (cookiejar_from_dict) have no
    domain and keep their historical supercookie behavior of being sent
    to every host.
    """

    def __init__(
        self,
        allowed_shared_domains: Any = (),
        *,
        public_suffixes: Any = None,
        reject_insecure_samesite_none: bool = True,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.allowed_shared_domains = frozenset(
            normalized
            for d in allowed_shared_domains
            if (normalized := normalize_cookie_host(str(d)).lstrip("."))
        )
        self.public_suffixes = (
            _DEFAULT_PUBLIC_SUFFIXES
            if public_suffixes is None
            else frozenset(
                normalize_cookie_host(str(s)).lstrip(".") for s in public_suffixes
            )
        )
        self.reject_insecure_samesite_none = reject_insecure_samesite_none

    # -- extract (set) path ------------------------------------------------

    def set_ok(self, cookie: Cookie, request: Any) -> bool:
        self._normalize_cookie_domain(cookie)
        if not super().set_ok(cookie, request):
            return False
        if cookie.domain_specified and self._is_public_suffix(cookie.domain):
            return False
        if self.reject_insecure_samesite_none and _is_insecure_samesite_none(cookie):
            return False
        return True

    @staticmethod
    def _normalize_cookie_domain(cookie: Cookie) -> None:
        domain = cookie.domain or ""
        initial_dot = domain.startswith(".")
        normalized = normalize_cookie_host(domain.lstrip("."))
        if initial_dot and normalized:
            normalized = f".{normalized}"
        cookie.domain = normalized

    def _is_public_suffix(self, domain: str) -> bool:
        candidate = normalize_cookie_host(domain).lstrip(".")
        if not candidate or "." not in candidate:
            # Single-label domains are treated as public suffixes.
            return True
        return candidate in self.public_suffixes

    # -- send (return) path ------------------------------------------------

    def _is_sharing_authorized(self, domain: str) -> bool:
        return any(
            domain == allowed or domain.endswith(f".{allowed}")
            for allowed in self.allowed_shared_domains
        )

    def domain_return_ok(self, domain: str, request: Any) -> bool:
        normalized = normalize_cookie_host(domain).lstrip(".")
        if not normalized:
            # Domain-less supercookie from the dict API: legacy behavior.
            return True
        req_host = _normalized_request_host(request)
        if not req_host:
            return False
        if not (req_host == normalized or req_host.endswith(f".{normalized}")):
            return False
        if self.is_blocked(domain):
            return False
        if self.is_not_allowed(domain):
            return False
        return True

    def return_ok_domain(self, cookie: Cookie, request: Any) -> bool:
        domain = normalize_cookie_host(cookie.domain).lstrip(".")
        if not domain:
            # Domain-less supercookie from the dict API: legacy behavior.
            return True
        req_host = _normalized_request_host(request)
        if not req_host:
            return False
        if req_host == domain:
            return True
        if cookie.domain_specified and self._is_sharing_authorized(domain):
            return req_host.endswith(f".{domain}")
        # Host-only cookies, and domain cookies whose sharing across
        # subdomains was not explicitly authorized, stay with their host.
        return False

    def return_ok_port(self, cookie: Cookie, request: Any) -> bool:
        if not cookie.port_specified or not cookie.port:
            return True
        req_port = _effective_request_port(request)
        if req_port is None:
            return False
        allowed_ports = [p.strip() for p in cookie.port.split(",")]
        return str(req_port) in allowed_ports


class MockRequest:
    """Wraps a `requests.PreparedRequest` to mimic a `urllib2.Request`.

    The code in `http.cookiejar.CookieJar` expects this interface in order to correctly
    manage cookie policies, i.e., determine whether a cookie can be set, given the
    domains of the request and the cookie.

    The original request object is read-only. The client is responsible for collecting
    the new headers via `get_new_headers()` and interpreting them appropriately. You
    probably want `get_cookie_header`, defined below.
    """

    type: str

    def __init__(self, request: PreparedRequest) -> None:
        assert _is_prepared(request)
        self._r = request
        self._new_headers: dict[str, str] = {}
        self.type = urlparse(self._r.url).scheme

    def get_type(self) -> str:
        return self.type

    def get_host(self) -> str:
        return urlparse(self._r.url).netloc

    def get_origin_req_host(self) -> str:
        return self.get_host()

    def get_full_url(self) -> str:
        # Only return the response's URL if the user hadn't set the Host
        # header
        if not self._r.headers.get("Host"):
            return self._r.url
        # If they did set it, retrieve it and reconstruct the expected domain
        host = to_native_string(self._r.headers["Host"], encoding="utf-8")
        parsed = urlparse(self._r.url)
        # Reconstruct the URL as we expect it
        return urlunparse(
            [
                parsed.scheme,
                host,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            ]
        )

    def is_unverifiable(self) -> bool:
        return True

    def has_header(self, name: str) -> bool:
        return name in self._r.headers or name in self._new_headers

    def get_header(self, name: str, default: str | None = None) -> str | None:
        return self._r.headers.get(name, self._new_headers.get(name, default))  # type: ignore[return-value]

    def add_header(self, key: str, val: str) -> None:
        """cookiejar has no legitimate use for this method; add it back if you find one."""
        raise NotImplementedError(
            "Cookie headers should be added with add_unredirected_header()"
        )

    def add_unredirected_header(self, name: str, value: str) -> None:
        self._new_headers[name] = value

    def get_new_headers(self) -> dict[str, str]:
        return self._new_headers

    @property
    def unverifiable(self) -> bool:
        return self.is_unverifiable()

    @property
    def origin_req_host(self) -> str:
        return self.get_origin_req_host()

    @property
    def host(self) -> str:
        return self.get_host()


class MockResponse:
    """Wraps a `httplib.HTTPMessage` to mimic a `urllib.addinfourl`.

    ...what? Basically, expose the parsed HTTP headers from the server response
    the way `http.cookiejar` expects to see them.
    """

    def __init__(self, headers: Any) -> None:
        """Make a MockResponse for `cookiejar` to read.

        :param headers: a httplib.HTTPMessage or analogous carrying the headers
        """
        self._headers = headers

    def info(self) -> Any:
        return self._headers

    def getheaders(self, name: str) -> Any:
        self._headers.getheaders(name)


def extract_cookies_to_jar(
    jar: CookieJar, request: PreparedRequest, response: Any
) -> None:
    """Extract the cookies from the response into a CookieJar.

    :param jar: http.cookiejar.CookieJar (not necessarily a RequestsCookieJar)
    :param request: our own requests.Request object
    :param response: urllib3.HTTPResponse object
    """
    if not (hasattr(response, "_original_response") and response._original_response):
        return
    # the _original_response field is the wrapped httplib.HTTPResponse object,
    req = MockRequest(request)
    # pull out the HTTPMessage with the headers and put it in the mock:
    res = MockResponse(response._original_response.msg)
    jar.extract_cookies(res, req)  # type: ignore[arg-type]


def get_cookie_header(jar: CookieJar, request: PreparedRequest) -> str | None:
    """
    Produce an appropriate Cookie header string to be sent with `request`, or None.

    :rtype: str
    """
    r = MockRequest(request)
    jar.add_cookie_header(r)  # type: ignore[arg-type]
    return r.get_new_headers().get("Cookie")


def remove_cookie_by_name(
    cookiejar: CookieJar, name: str, domain: str | None = None, path: str | None = None
) -> None:
    """Unsets a cookie by name, by default over all domains and paths.

    Wraps CookieJar.clear(), is O(n).
    """
    clearables: list[tuple[str, str, str]] = []
    for cookie in cookiejar:
        if cookie.name != name:
            continue
        if domain is not None and domain != cookie.domain:
            continue
        if path is not None and path != cookie.path:
            continue
        clearables.append((cookie.domain, cookie.path, cookie.name))

    for domain, path, name in clearables:
        cookiejar.clear(domain, path, name)


class CookieConflictError(RuntimeError):
    """There are two cookies that meet the criteria specified in the cookie jar.
    Use .get and .set and include domain and path args in order to be more specific.
    """


class RequestsCookieJar(CookieJar, MutableMapping[str, str | None]):  # type: ignore[misc]
    """Compatibility class; is a http.cookiejar.CookieJar, but exposes a dict
    interface.

    This is the CookieJar we create by default for requests and sessions that
    don't specify one, since some clients may expect response.cookies and
    session.cookies to support dict operations.

    Requests does not use the dict interface internally; it's just for
    compatibility with external client code. All requests code should work
    out of the box with externally provided instances of ``CookieJar``, e.g.
    ``LWPCookieJar`` and ``FileCookieJar``.

    Unlike a regular CookieJar, this class is pickleable.

    .. warning:: dictionary operations that are normally O(1) may be O(n).
    """

    _policy: CookiePolicy

    def __init__(self, policy: CookiePolicy | None = None) -> None:
        # Session jars default to the scoped SessionCookiePolicy; callers
        # may still pass any cookielib-compatible policy explicitly.
        super().__init__(policy if policy is not None else SessionCookiePolicy())

    def _cookies_for_request(self, request: Any) -> list[Cookie]:
        """Return the cookies for a request in a deterministic order.

        Expired cookies are purged first; the survivors are ordered by
        longest (most specific) path first, then domain, path and name,
        so that same-name cookies from different scopes always serialize
        into the Cookie header in a stable, predictable order.
        """
        self.clear_expired_cookies()
        cookies = super()._cookies_for_request(request)
        cookies.sort(key=_cookie_sort_key)
        return cookies

    def get(  # type: ignore[override]
        self,
        name: str,
        default: str | None = None,
        domain: str | None = None,
        path: str | None = None,
    ) -> str | None:
        """Dict-like get() that also supports optional domain and path args in
        order to resolve naming collisions from using one cookie jar over
        multiple domains.

        .. warning:: operation is O(n), not O(1).
        """
        try:
            return self._find_no_duplicates(name, domain, path)
        except KeyError:
            return default

    def set(
        self, name: str, value: str | Morsel[dict[str, str]] | None, **kwargs: Any
    ) -> Cookie | None:
        """Dict-like set() that also supports optional domain and path args in
        order to resolve naming collisions from using one cookie jar over
        multiple domains.
        """
        # support client code that unsets cookies by assignment of a None value:
        if value is None:
            remove_cookie_by_name(
                self, name, domain=kwargs.get("domain"), path=kwargs.get("path")
            )
            return

        if isinstance(value, Morsel):
            c = morsel_to_cookie(value)
        else:
            c = create_cookie(name, value, **kwargs)
        self.set_cookie(c)
        return c

    def iterkeys(self) -> Iterator[str]:
        """Dict-like iterkeys() that returns an iterator of names of cookies
        from the jar.

        .. seealso:: itervalues() and iteritems().
        """
        for cookie in iter(self):
            yield cookie.name

    def keys(self) -> list[str]:  # type: ignore[override]
        """Dict-like keys() that returns a list of names of cookies from the
        jar.

        .. seealso:: values() and items().
        """
        return list(self.iterkeys())

    def itervalues(self) -> Iterator[str | None]:
        """Dict-like itervalues() that returns an iterator of values of cookies
        from the jar.

        .. seealso:: iterkeys() and iteritems().
        """
        for cookie in iter(self):
            yield cookie.value

    def values(self) -> list[str | None]:  # type: ignore[override]
        """Dict-like values() that returns a list of values of cookies from the
        jar.

        .. seealso:: keys() and items().
        """
        return list(self.itervalues())

    def iteritems(self) -> Iterator[tuple[str, str | None]]:
        """Dict-like iteritems() that returns an iterator of name-value tuples
        from the jar.

        .. seealso:: iterkeys() and itervalues().
        """
        for cookie in iter(self):
            yield cookie.name, cookie.value

    def items(self) -> list[tuple[str, str | None]]:  # type: ignore[override]
        """Dict-like items() that returns a list of name-value tuples from the
        jar. Allows client-code to call ``dict(RequestsCookieJar)`` and get a
        vanilla python dict of key value pairs.

        .. seealso:: keys() and values().
        """
        return list(self.iteritems())

    def list_domains(self) -> list[str]:
        """Utility method to list all the domains in the jar."""
        domains: list[str] = []
        for cookie in iter(self):
            if cookie.domain not in domains:
                domains.append(cookie.domain)
        return domains

    def list_paths(self) -> list[str]:
        """Utility method to list all the paths in the jar."""
        paths: list[str] = []
        for cookie in iter(self):
            if cookie.path not in paths:
                paths.append(cookie.path)
        return paths

    def multiple_domains(self) -> bool:
        """Returns True if there are multiple domains in the jar.
        Returns False otherwise.

        :rtype: bool
        """
        domains: list[str] = []
        for cookie in iter(self):
            if cookie.domain is not None and cookie.domain in domains:  # type: ignore[reportUnnecessaryComparison]  # defensive check
                return True
            domains.append(cookie.domain)
        return False  # there is only one domain in jar

    def get_dict(
        self, domain: str | None = None, path: str | None = None
    ) -> dict[str, str | None]:
        """Takes as an argument an optional domain and path and returns a plain
        old Python dict of name-value pairs of cookies that meet the
        requirements.

        :rtype: dict
        """
        dictionary: dict[str, str | None] = {}
        for cookie in iter(self):
            if (domain is None or cookie.domain == domain) and (
                path is None or cookie.path == path
            ):
                dictionary[cookie.name] = cookie.value
        return dictionary

    def __iter__(self) -> Iterator[Cookie]:  # type: ignore[override]
        """RequestCookieJar's __iter__ comes from CookieJar not MutableMapping."""
        return super().__iter__()

    def __contains__(self, name: object) -> bool:
        try:
            return super().__contains__(name)
        except CookieConflictError:
            return True

    def __getitem__(self, name: str) -> str | None:
        """Dict-like __getitem__() for compatibility with client code. Throws
        exception if there are more than one cookie with name. In that case,
        use the more explicit get() method instead.

        .. warning:: operation is O(n), not O(1).
        """
        return self._find_no_duplicates(name)

    def __setitem__(
        self, name: str, value: str | Morsel[dict[str, str]] | None
    ) -> None:
        """Dict-like __setitem__ for compatibility with client code. Throws
        exception if there is already a cookie of that name in the jar. In that
        case, use the more explicit set() method instead.
        """
        self.set(name, value)

    def __delitem__(self, name: str) -> None:
        """Deletes a cookie given a name. Wraps ``http.cookiejar.CookieJar``'s
        ``remove_cookie_by_name()``.
        """
        remove_cookie_by_name(self, name)

    def set_cookie(self, cookie: Cookie, *args: Any, **kwargs: Any) -> None:
        if (
            (value := cookie.value) is not None
            and value.startswith('"')
            and value.endswith('"')
        ):
            cookie.value = value.replace('\\"', "")
        return super().set_cookie(cookie, *args, **kwargs)

    def update(  # type: ignore[override]
        self, other: CookieJar | SupportsKeysAndGetItem[str, str]
    ) -> None:
        """Updates this jar with cookies from another CookieJar or dict-like.

        Cookies coming from another jar are merged in a deterministic
        (domain, path, name) order, and expired cookies are skipped.
        """
        if isinstance(other, cookielib.CookieJar):
            for cookie in _iter_jar_cookies_sorted(other):
                if not cookie.is_expired():
                    self.set_cookie(copy.copy(cookie))
        else:
            super().update(other)

    def _find(
        self, name: str, domain: str | None = None, path: str | None = None
    ) -> str | None:
        """Requests uses this method internally to get cookie values.

        If there are conflicting cookies, _find arbitrarily chooses one.
        See _find_no_duplicates if you want an exception thrown if there are
        conflicting cookies.

        :param name: a string containing name of cookie
        :param domain: (optional) string containing domain of cookie
        :param path: (optional) string containing path of cookie
        :return: cookie.value
        """
        for cookie in iter(self):
            if cookie.name == name:
                if domain is None or cookie.domain == domain:
                    if path is None or cookie.path == path:
                        return cookie.value

        raise KeyError(f"name={name!r}, domain={domain!r}, path={path!r}")

    def _find_no_duplicates(
        self, name: str, domain: str | None = None, path: str | None = None
    ) -> str:
        """Both ``__get_item__`` and ``get`` call this function: it's never
        used elsewhere in Requests.

        :param name: a string containing name of cookie
        :param domain: (optional) string containing domain of cookie
        :param path: (optional) string containing path of cookie
        :raises KeyError: if cookie is not found
        :raises CookieConflictError: if there are multiple cookies
            that match name and optionally domain and path
        :return: cookie.value
        """
        toReturn = None
        for cookie in iter(self):
            if cookie.name == name:
                if domain is None or cookie.domain == domain:
                    if path is None or cookie.path == path:
                        if toReturn is not None:
                            # if there are multiple cookies that meet passed in criteria
                            raise CookieConflictError(
                                f"There are multiple cookies with name, {name!r}"
                            )
                        # we will eventually return this as long as no cookie conflict
                        toReturn = cookie.value

        if toReturn is not None:
            return toReturn
        raise KeyError(f"name={name!r}, domain={domain!r}, path={path!r}")

    def __getstate__(self) -> dict[str, Any]:
        """Unlike a normal CookieJar, this class is pickleable."""
        state = self.__dict__.copy()
        # remove the unpickleable RLock object
        state.pop("_cookies_lock")
        return state

    def __setstate__(self, state: dict[str, Any]) -> None:
        """Unlike a normal CookieJar, this class is pickleable."""
        self.__dict__.update(state)
        if "_cookies_lock" not in self.__dict__:
            self._cookies_lock = threading.RLock()

    def copy(self) -> RequestsCookieJar:
        """Return a copy of this RequestsCookieJar."""
        new_cj = RequestsCookieJar()
        new_cj.set_policy(self.get_policy())
        new_cj.update(self)
        return new_cj

    def get_policy(self) -> CookiePolicy:
        """Return the CookiePolicy instance used."""
        return self._policy


def _copy_cookie_jar(jar: CookieJar | None) -> CookieJar | None:  # type: ignore[reportUnusedFunction]  # cross-module usage in models.py
    if jar is None:
        return None

    if copy_method := getattr(jar, "copy", None):
        # We're dealing with an instance of RequestsCookieJar
        return copy_method()
    # We're dealing with a generic CookieJar instance
    new_jar = copy.copy(jar)
    new_jar.clear()
    for cookie in jar:
        new_jar.set_cookie(copy.copy(cookie))
    return new_jar


def create_cookie(name: str, value: str, **kwargs: Any) -> Cookie:
    """Make a cookie from underspecified parameters.

    By default, the pair of `name` and `value` will be set for the domain ''
    and sent on every request (this is sometimes called a "supercookie").
    """
    result: dict[str, Any] = {
        "version": 0,
        "name": name,
        "value": value,
        "port": None,
        "domain": "",
        "path": "/",
        "secure": False,
        "expires": None,
        "discard": True,
        "comment": None,
        "comment_url": None,
        "rest": {"HttpOnly": None},
        "rfc2109": False,
    }

    badargs = set(kwargs) - set(result)
    if badargs:
        raise TypeError(
            f"create_cookie() got unexpected keyword arguments: {list(badargs)}"
        )

    result.update(kwargs)
    result["port_specified"] = bool(result["port"])
    result["domain_specified"] = bool(result["domain"])
    result["domain_initial_dot"] = result["domain"].startswith(".")
    result["path_specified"] = bool(result["path"])

    return cookielib.Cookie(**result)


def morsel_to_cookie(morsel: Morsel[Any]) -> Cookie:
    """Convert a Morsel object into a Cookie containing the one k/v pair."""

    expires: int | None = None
    if morsel["max-age"]:
        try:
            expires = int(time.time() + int(morsel["max-age"]))
        except ValueError:
            raise TypeError(f"max-age: {morsel['max-age']} must be integer")
    elif morsel["expires"]:
        time_template = "%a, %d-%b-%Y %H:%M:%S GMT"
        expires = calendar.timegm(time.strptime(morsel["expires"], time_template))
    return create_cookie(
        comment=morsel["comment"],
        comment_url=bool(morsel["comment"]),
        discard=False,
        domain=morsel["domain"],
        expires=expires,
        name=morsel.key,
        path=morsel["path"],
        port=None,
        rest={"HttpOnly": morsel["httponly"]},
        rfc2109=False,
        secure=bool(morsel["secure"]),
        value=morsel.value,
        version=morsel["version"] or 0,
    )


_CookieJarT = TypeVar("_CookieJarT", bound=CookieJar)


@overload
def cookiejar_from_dict(
    cookie_dict: dict[str, str] | None,
    cookiejar: None = None,
    overwrite: bool = True,
) -> RequestsCookieJar: ...


@overload
def cookiejar_from_dict(
    cookie_dict: dict[str, str] | None,
    cookiejar: _CookieJarT,
    overwrite: bool = True,
) -> _CookieJarT: ...


def cookiejar_from_dict(
    cookie_dict: dict[str, str] | None,
    cookiejar: CookieJar | None = None,
    overwrite: bool = True,
) -> CookieJar:
    """Returns a CookieJar from a key/value dictionary.

    :param cookie_dict: Dict of key/values to insert into CookieJar.
    :param cookiejar: (optional) A cookiejar to add the cookies to.
    :param overwrite: (optional) If False, will not replace cookies
        already in the jar with new ones.
    :rtype: CookieJar
    """
    if cookiejar is None:
        cookiejar = RequestsCookieJar()

    if cookie_dict is not None:
        names_from_jar = [cookie.name for cookie in cookiejar]
        for name in cookie_dict:
            if overwrite or (name not in names_from_jar):
                cookiejar.set_cookie(create_cookie(name, cookie_dict[name]))

    return cookiejar


def merge_cookies(
    cookiejar: CookieJar, cookies: dict[str, str] | CookieJar | None
) -> CookieJar:
    """Add cookies to cookiejar and returns a merged CookieJar.

    :param cookiejar: CookieJar object to add the cookies to.
    :param cookies: Dictionary or CookieJar object to be added.
    :rtype: CookieJar
    """
    if not isinstance(cookiejar, cookielib.CookieJar):  # runtime guard
        raise ValueError("You can only merge into CookieJar")

    if isinstance(cookies, dict):
        cookiejar = cookiejar_from_dict(cookies, cookiejar=cookiejar, overwrite=False)
    elif isinstance(cookies, cookielib.CookieJar):
        if update_method := getattr(cookiejar, "update", None):
            update_method(cookies)
        else:
            for cookie_in_jar in _iter_jar_cookies_sorted(cookies):
                if not cookie_in_jar.is_expired():
                    cookiejar.set_cookie(cookie_in_jar)

    # Deterministic expiry cleanup: merging never resurrects or keeps
    # cookies whose lifetime has already ended.
    cookiejar.clear_expired_cookies()

    return cookiejar
