from __future__ import annotations

import collections.abc as c
import hashlib
import inspect
import typing as t
import weakref
from collections.abc import MutableMapping
from datetime import datetime
from datetime import timezone

from itsdangerous import BadSignature
from itsdangerous import URLSafeTimedSerializer
from werkzeug.datastructures import CallbackDict

from .json.tag import TaggedJSONSerializer

_missing = object()

if t.TYPE_CHECKING:  # pragma: no cover
    import typing_extensions as te

    from .app import Flask
    from .wrappers import Request
    from .wrappers import Response


class _TrackedMutation:
    _session_roots: _RootRegistry

    def _tracked_modified(self) -> None:
        on_update = getattr(self, "on_update", None)

        if on_update is not None:
            on_update(self)
            return

        for root in tuple(self._session_roots):
            root.modified = True

    def _detach_values(self, values: c.Iterable[t.Any]) -> None:
        roots = self._session_roots
        seen: set[int] = set()

        def detach(value: t.Any) -> None:
            if isinstance(value, _TrackedMutation):
                value_id = id(value)

                if value_id in seen:
                    return

                seen.add(value_id)

                for root in tuple(value._session_roots):
                    if root in roots and not _is_reachable(root, value, self):
                        value._session_roots.discard(root)

                items = value.values() if isinstance(value, _TrackedDict) else value
            elif isinstance(value, tuple):
                items = value
            else:
                return

            for item in items:
                detach(item)

        for value in values:
            detach(value)


class _RootRegistry:
    def __init__(self, roots: c.Iterable[SecureCookieSession] = ()) -> None:
        self._refs: dict[int, weakref.ReferenceType[SecureCookieSession]] = {}

        for root in roots:
            self.add(root)

    def add(self, root: SecureCookieSession) -> None:
        root_id = id(root)

        def remove(ref: weakref.ReferenceType[SecureCookieSession]) -> None:
            self._refs.pop(root_id, None)

        self._refs[root_id] = weakref.ref(root, remove)

    def update(self, roots: c.Iterable[SecureCookieSession]) -> None:
        for root in roots:
            self.add(root)

    def __contains__(self, item: object) -> bool:
        ref = self._refs.get(id(item))
        return ref is not None and ref() is item

    def discard(self, item: object) -> None:
        ref = self._refs.get(id(item))

        if ref is not None and ref() is item:
            self._refs.pop(id(item), None)

    def __iter__(self) -> c.Iterator[SecureCookieSession]:
        for ref in list(self._refs.values()):
            root = ref()

            if root is not None:
                yield root


class _TrackedDict(_TrackedMutation, dict[str, t.Any]):
    def _wrap_value(self, value: t.Any) -> t.Any:
        return _wrap_tracked_value(value, self._session_roots)

    def __setitem__(self, key: str, value: t.Any) -> None:
        old = dict.get(self, key, _missing)
        dict.__setitem__(self, key, self._wrap_value(value))

        if old is not _missing:
            self._detach_values([old])

        self._tracked_modified()

    def __delitem__(self, key: str) -> None:
        old = dict.__getitem__(self, key)
        dict.__delitem__(self, key)
        self._detach_values([old])
        self._tracked_modified()

    def clear(self) -> None:
        old_values = list(dict.values(self))
        dict.clear(self)
        self._detach_values(old_values)
        self._tracked_modified()

    def popitem(self) -> tuple[str, t.Any]:
        item = dict.popitem(self)
        self._detach_values([item[1]])
        self._tracked_modified()
        return item

    def setdefault(self, key: str, default: t.Any = None) -> t.Any:
        if key not in self:
            dict.__setitem__(self, key, self._wrap_value(default))
            self._tracked_modified()

        return dict.__getitem__(self, key)

    def pop(
        self,
        key: str,
        default: t.Any = _missing,
    ) -> t.Any:
        if key in self:
            value = dict.pop(self, key)
            self._detach_values([value])
            self._tracked_modified()
            return value

        if default is _missing:
            return dict.pop(self, key)

        return dict.pop(self, key, default)

    def update(
        self,
        arg: c.Mapping[str, t.Any] | c.Iterable[tuple[str, t.Any]] | None = None,
        /,
        **kwargs: t.Any,
    ) -> None:
        items = list(arg.items()) if isinstance(arg, c.Mapping) else list(arg or ())
        items.extend(kwargs.items())

        old_values = [dict.get(self, key, _missing) for key, _ in items]

        for key, value in items:
            dict.__setitem__(self, key, self._wrap_value(value))

        if items:
            self._detach_values(value for value in old_values if value is not _missing)
            self._tracked_modified()

    def __ior__(  # type: ignore[override]
        self,
        other: c.Mapping[str, t.Any] | c.Iterable[tuple[str, t.Any]],
    ) -> t.Self:
        self.update(other)
        return self


class _TrackedList(_TrackedMutation, list[t.Any]):
    def _wrap_value(self, value: t.Any) -> t.Any:
        return _wrap_tracked_value(value, self._session_roots)

    def __setitem__(self, index: int | slice, value: t.Any) -> None:
        old = list.__getitem__(self, index)

        if isinstance(index, slice):
            value = [self._wrap_value(item) for item in value]
            modified = bool(old or value)
        else:
            value = self._wrap_value(value)
            modified = True

        list.__setitem__(self, index, value)
        self._detach_values(old if isinstance(index, slice) else [old])

        if modified:
            self._tracked_modified()

    def __delitem__(self, index: int | slice) -> None:
        old = list.__getitem__(self, index)
        list.__delitem__(self, index)
        self._detach_values(old if isinstance(index, slice) else [old])

        if not isinstance(index, slice) or old:
            self._tracked_modified()

    def append(self, value: t.Any) -> None:
        list.append(self, self._wrap_value(value))
        self._tracked_modified()

    def insert(self, index: int, value: t.Any) -> None:
        list.insert(self, index, self._wrap_value(value))
        self._tracked_modified()

    def extend(self, values: c.Iterable[t.Any]) -> None:
        list.extend(self, [self._wrap_value(value) for value in values])
        self._tracked_modified()

    def remove(self, value: t.Any) -> None:
        index = list.index(self, value)
        old = list.__getitem__(self, index)
        list.remove(self, value)
        self._detach_values([old])
        self._tracked_modified()

    def pop(self, index: int = -1) -> t.Any:
        value = list.pop(self, index)
        self._detach_values([value])
        self._tracked_modified()
        return value

    def clear(self) -> None:
        old_values = list.copy(self)
        list.clear(self)
        self._detach_values(old_values)
        self._tracked_modified()

    def sort(self, **kwargs: t.Any) -> None:
        list.sort(self, **kwargs)
        self._tracked_modified()

    def reverse(self) -> None:
        list.reverse(self)
        self._tracked_modified()

    def __iadd__(self, values: c.Iterable[t.Any]) -> t.Self:
        self.extend(values)
        return self

    def __imul__(self, value: int) -> t.Self:
        old_values = list.copy(self)
        list.__imul__(self, value)

        if value <= 0:
            self._detach_values(old_values)

        self._tracked_modified()
        return self


def _attach_roots(
    value: t.Any,
    roots: _RootRegistry,
    seen: set[int] | None = None,
) -> None:
    if seen is None:
        seen = set()

    if isinstance(value, _TrackedMutation):
        value_id = id(value)

        if value_id in seen:
            return

        seen.add(value_id)
        value._session_roots.update(roots)
        values = value.values() if isinstance(value, _TrackedDict) else value
    elif isinstance(value, tuple):
        values = value
    else:
        return

    for item in values:
        _attach_roots(item, roots, seen)


def _wrap_tracked_value(value: t.Any, roots: _RootRegistry) -> t.Any:
    memo: dict[int, _TrackedMutation] = {}
    return _wrap_new_tracked_value(value, roots, memo)


def _wrap_new_tracked_value(
    value: t.Any,
    roots: _RootRegistry,
    memo: dict[int, _TrackedMutation],
) -> t.Any:
    if isinstance(value, _TrackedMutation):
        _attach_roots(value, roots)
        return value

    if type(value) is dict or type(value) is list:
        value_id = id(value)

        if value_id in memo:
            return memo[value_id]

        if type(value) is dict:
            wrapped: _TrackedMutation = _TrackedDict()
            wrapped._session_roots = _RootRegistry(roots)
            memo[value_id] = wrapped

            for key, item in value.items():
                dict.__setitem__(
                    wrapped, key, _wrap_new_tracked_value(item, roots, memo)
                )
        else:
            wrapped = _TrackedList()
            wrapped._session_roots = _RootRegistry(roots)
            memo[value_id] = wrapped
            list.extend(
                wrapped,
                [_wrap_new_tracked_value(item, roots, memo) for item in value],
            )

        return wrapped

    if isinstance(value, tuple):
        return tuple(_wrap_new_tracked_value(item, roots, memo) for item in value)

    return value


def _is_reachable(
    root: object,
    target: _TrackedMutation,
    start: object | None = None,
) -> bool:
    pending = [root if start is None else start]
    seen: set[int] = set()

    while pending:
        value = pending.pop()

        if value is target:
            return True

        value_id = id(value)

        if value_id in seen:
            continue

        seen.add(value_id)

        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, (list, tuple)):
            pending.extend(value)

    return False


class SessionMixin(MutableMapping[str, t.Any]):
    """Expands a basic dictionary with session attributes."""

    @property
    def permanent(self) -> bool:
        """This reflects the ``'_permanent'`` key in the dict."""
        return self.get("_permanent", False)  # type: ignore[no-any-return]

    @permanent.setter
    def permanent(self, value: bool) -> None:
        self["_permanent"] = bool(value)

    #: Some implementations can detect whether a session is newly
    #: created, but that is not guaranteed. Use with caution. The mixin
    # default is hard-coded ``False``.
    new = False

    #: Some implementations can detect changes to the session and set
    #: this when that happens. The mixin default is hard coded to
    #: ``True``.
    modified = True

    accessed = False
    """Indicates if the session was accessed, even if it was not modified. This
    is set when the session object is accessed through the request context,
    including the global :data:`.session` proxy. A ``Vary: cookie`` header will
    be added if this is ``True``.

    .. versionchanged:: 3.1.3
        This is tracked by the request context.
    """


class SecureCookieSession(_TrackedDict, CallbackDict[str, t.Any], SessionMixin):
    """Base class for sessions based on signed cookies.

    This session backend will set the :attr:`modified` and
    :attr:`accessed` attributes. It cannot reliably track whether a
    session is new (vs. empty), so :attr:`new` remains hard coded to
    ``False``.
    """

    #: When data is changed, this is set to true. By default, only the session
    #: dictionary itself is tracked. Pass track_modifications=True to track
    #: in-place changes to nested dictionaries and lists. Otherwise, modified
    #: must be set manually when changing mutable data.
    modified = False

    def __init__(
        self,
        initial: c.Mapping[str, t.Any] | None = None,
        track_modifications: bool = False,
    ) -> None:
        """Create a signed cookie session.

        :param initial: Initial session data.
        :param track_modifications: Track in-place changes to nested
            dictionaries and lists.
        """

        def on_update(self: te.Self) -> None:
            self.modified = True

        self._session_roots = _RootRegistry()
        CallbackDict.__init__(self, None, on_update)

        if track_modifications:
            self._session_roots.add(self)

            if initial is not None:
                for key, value in initial.items():
                    dict.__setitem__(
                        self, key, _wrap_tracked_value(value, self._session_roots)
                    )
        elif initial is not None:
            dict.update(self, initial)


class NullSession(SecureCookieSession):
    """Class used to generate nicer error messages if sessions are not
    available.  Will still allow read-only access to the empty session
    but fail on setting.
    """

    def _fail(self, *args: t.Any, **kwargs: t.Any) -> t.NoReturn:
        raise RuntimeError(
            "The session is unavailable because no secret "
            "key was set.  Set the secret_key on the "
            "application to something unique and secret."
        )

    __setitem__ = __delitem__ = clear = pop = popitem = update = setdefault = _fail
    del _fail


class SessionInterface:
    """The basic interface you have to implement in order to replace the
    default session interface which uses werkzeug's securecookie
    implementation.  The only methods you have to implement are
    :meth:`open_session` and :meth:`save_session`, the others have
    useful defaults which you don't need to change.

    The session object returned by the :meth:`open_session` method has to
    provide a dictionary like interface plus the properties and methods
    from the :class:`SessionMixin`.  We recommend just subclassing a dict
    and adding that mixin::

        class Session(dict, SessionMixin):
            pass

    If :meth:`open_session` returns ``None`` Flask will call into
    :meth:`make_null_session` to create a session that acts as replacement
    if the session support cannot work because some requirement is not
    fulfilled.  The default :class:`NullSession` class that is created
    will complain that the secret key was not set.

    To replace the session interface on an application all you have to do
    is to assign :attr:`flask.Flask.session_interface`::

        app = Flask(__name__)
        app.session_interface = MySessionInterface()

    Multiple requests with the same session may be sent and handled
    concurrently. When implementing a new session interface, consider
    whether reads or writes to the backing store must be synchronized.
    There is no guarantee on the order in which the session for each
    request is opened or saved, it will occur in the order that requests
    begin and end processing.

    .. versionadded:: 0.8
    """

    #: :meth:`make_null_session` will look here for the class that should
    #: be created when a null session is requested.  Likewise the
    #: :meth:`is_null_session` method will perform a typecheck against
    #: this type.
    null_session_class = NullSession

    #: A flag that indicates if the session interface is pickle based.
    #: This can be used by Flask extensions to make a decision in regards
    #: to how to deal with the session object.
    #:
    #: .. versionadded:: 0.10
    pickle_based = False

    def make_null_session(self, app: Flask) -> NullSession:
        """Creates a null session which acts as a replacement object if the
        real session support could not be loaded due to a configuration
        error.  This mainly aids the user experience because the job of the
        null session is to still support lookup without complaining but
        modifications are answered with a helpful error message of what
        failed.

        This creates an instance of :attr:`null_session_class` by default.
        """
        return self.null_session_class()

    def is_null_session(self, obj: object) -> bool:
        """Checks if a given object is a null session.  Null sessions are
        not asked to be saved.

        This checks if the object is an instance of :attr:`null_session_class`
        by default.
        """
        return isinstance(obj, self.null_session_class)

    def get_cookie_name(self, app: Flask) -> str:
        """The name of the session cookie. Uses``app.config["SESSION_COOKIE_NAME"]``."""
        return app.config["SESSION_COOKIE_NAME"]  # type: ignore[no-any-return]

    def get_cookie_domain(self, app: Flask) -> str | None:
        """The value of the ``Domain`` parameter on the session cookie. If not set,
        browsers will only send the cookie to the exact domain it was set from.
        Otherwise, they will send it to any subdomain of the given value as well.

        Uses the :data:`SESSION_COOKIE_DOMAIN` config.

        .. versionchanged:: 2.3
            Not set by default, does not fall back to ``SERVER_NAME``.
        """
        return app.config["SESSION_COOKIE_DOMAIN"]  # type: ignore[no-any-return]

    def get_cookie_path(self, app: Flask) -> str:
        """Returns the path for which the cookie should be valid.  The
        default implementation uses the value from the ``SESSION_COOKIE_PATH``
        config var if it's set, and falls back to ``APPLICATION_ROOT`` or
        uses ``/`` if it's ``None``.
        """
        return app.config["SESSION_COOKIE_PATH"] or app.config["APPLICATION_ROOT"]  # type: ignore[no-any-return]

    def get_cookie_httponly(self, app: Flask) -> bool:
        """Returns True if the session cookie should be httponly.  This
        currently just returns the value of the ``SESSION_COOKIE_HTTPONLY``
        config var.
        """
        return app.config["SESSION_COOKIE_HTTPONLY"]  # type: ignore[no-any-return]

    def get_cookie_secure(self, app: Flask) -> bool:
        """Returns True if the cookie should be secure.  This currently
        just returns the value of the ``SESSION_COOKIE_SECURE`` setting.
        """
        return app.config["SESSION_COOKIE_SECURE"]  # type: ignore[no-any-return]

    def get_cookie_samesite(self, app: Flask) -> str | None:
        """Return ``'Strict'`` or ``'Lax'`` if the cookie should use the
        ``SameSite`` attribute. This currently just returns the value of
        the :data:`SESSION_COOKIE_SAMESITE` setting.
        """
        return app.config["SESSION_COOKIE_SAMESITE"]  # type: ignore[no-any-return]

    def get_cookie_partitioned(self, app: Flask) -> bool:
        """Returns True if the cookie should be partitioned. By default, uses
        the value of :data:`SESSION_COOKIE_PARTITIONED`.

        .. versionadded:: 3.1
        """
        return app.config["SESSION_COOKIE_PARTITIONED"]  # type: ignore[no-any-return]

    def get_expiration_time(self, app: Flask, session: SessionMixin) -> datetime | None:
        """A helper method that returns an expiration date for the session
        or ``None`` if the session is linked to the browser session.  The
        default implementation returns now + the permanent session
        lifetime configured on the application.
        """
        if session.permanent:
            return datetime.now(timezone.utc) + app.permanent_session_lifetime
        return None

    def should_set_cookie(self, app: Flask, session: SessionMixin) -> bool:
        """Used by session backends to determine if a ``Set-Cookie`` header
        should be set for this session cookie for this response. If the session
        has been modified, the cookie is set. If the session is permanent and
        the ``SESSION_REFRESH_EACH_REQUEST`` config is true, the cookie is
        always set.

        This check is usually skipped if the session was deleted.

        .. versionadded:: 0.11
        """

        return session.modified or (
            session.permanent and app.config["SESSION_REFRESH_EACH_REQUEST"]
        )

    def open_session(self, app: Flask, request: Request) -> SessionMixin | None:
        """This is called at the beginning of each request, after
        pushing the request context, before matching the URL.

        This must return an object which implements a dictionary-like
        interface as well as the :class:`SessionMixin` interface.

        This will return ``None`` to indicate that loading failed in
        some way that is not immediately an error. The request
        context will fall back to using :meth:`make_null_session`
        in this case.
        """
        raise NotImplementedError()

    def save_session(
        self, app: Flask, session: SessionMixin, response: Response
    ) -> None:
        """This is called at the end of each request, after generating
        a response, before removing the request context. It is skipped
        if :meth:`is_null_session` returns ``True``.
        """
        raise NotImplementedError()


session_json_serializer = TaggedJSONSerializer()


def _lazy_sha1(string: bytes = b"") -> t.Any:
    """Don't access ``hashlib.sha1`` until runtime. FIPS builds may not include
    SHA-1, in which case the import and use as a default would fail before the
    developer can configure something else.
    """
    return hashlib.sha1(string)


class SecureCookieSessionInterface(SessionInterface):
    """The default session interface that stores sessions in signed cookies
    through the :mod:`itsdangerous` module.
    """

    #: the salt that should be applied on top of the secret key for the
    #: signing of cookie based sessions.
    salt = "cookie-session"
    #: the hash function to use for the signature.  The default is sha1
    digest_method = staticmethod(_lazy_sha1)
    #: the name of the itsdangerous supported key derivation.  The default
    #: is hmac.
    key_derivation = "hmac"
    #: A python serializer for the payload.  The default is a compact
    #: JSON derived serializer with support for some extra Python types
    #: such as datetime objects or tuples.
    serializer = session_json_serializer
    session_class = SecureCookieSession

    #: Track in-place changes to nested dictionaries and lists.
    track_modifications = False

    def _make_session(self, data: c.Mapping[str, t.Any] | None = None) -> SessionMixin:
        parameters = inspect.signature(self.session_class.__init__).parameters
        supports_tracking = "track_modifications" in parameters or any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in parameters.values()
        )

        if self.track_modifications and not supports_tracking:
            raise TypeError("session_class must accept a track_modifications argument")

        kwargs = (
            {"track_modifications": self.track_modifications}
            if supports_tracking
            else {}
        )

        if data is None:
            return self.session_class(**kwargs)

        return self.session_class(data, **kwargs)

    def get_signing_serializer(self, app: Flask) -> URLSafeTimedSerializer | None:
        if not app.secret_key:
            return None

        keys: list[str | bytes] = []

        if fallbacks := app.config["SECRET_KEY_FALLBACKS"]:
            keys.extend(fallbacks)

        keys.append(app.secret_key)  # itsdangerous expects current key at top
        return URLSafeTimedSerializer(
            keys,  # type: ignore[arg-type]
            salt=self.salt,
            serializer=self.serializer,
            signer_kwargs={
                "key_derivation": self.key_derivation,
                "digest_method": self.digest_method,
            },
        )

    def open_session(self, app: Flask, request: Request) -> SecureCookieSession | None:
        s = self.get_signing_serializer(app)
        if s is None:
            return None
        val = request.cookies.get(self.get_cookie_name(app))
        if not val:
            return self._make_session()
        max_age = int(app.permanent_session_lifetime.total_seconds())
        try:
            data = s.loads(val, max_age=max_age)
            return self._make_session(data)
        except BadSignature:
            return self._make_session()

    def save_session(
        self, app: Flask, session: SessionMixin, response: Response
    ) -> None:
        name = self.get_cookie_name(app)
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        secure = self.get_cookie_secure(app)
        partitioned = self.get_cookie_partitioned(app)
        samesite = self.get_cookie_samesite(app)
        httponly = self.get_cookie_httponly(app)

        # Add a "Vary: Cookie" header if the session was accessed at all.
        if session.accessed:
            response.vary.add("Cookie")

        # If the session is modified to be empty, remove the cookie.
        # If the session is empty, return without setting the cookie.
        if not session:
            if session.modified:
                response.delete_cookie(
                    name,
                    domain=domain,
                    path=path,
                    secure=secure,
                    partitioned=partitioned,
                    samesite=samesite,
                    httponly=httponly,
                )
                response.vary.add("Cookie")

            return

        if not self.should_set_cookie(app, session):
            return

        expires = self.get_expiration_time(app, session)
        val = self.get_signing_serializer(app).dumps(dict(session))  # type: ignore[union-attr]
        response.set_cookie(
            name,
            val,
            expires=expires,
            httponly=httponly,
            domain=domain,
            path=path,
            secure=secure,
            partitioned=partitioned,
            samesite=samesite,
        )
        response.vary.add("Cookie")
