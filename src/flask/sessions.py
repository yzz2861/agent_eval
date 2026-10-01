from __future__ import annotations

import collections.abc as c
import hashlib
import typing as t
import weakref
from collections.abc import MutableMapping
from datetime import datetime
from datetime import timezone

from itsdangerous import BadSignature
from itsdangerous import URLSafeTimedSerializer
from werkzeug.datastructures import CallbackDict

from .json.tag import TaggedJSONSerializer

if t.TYPE_CHECKING:  # pragma: no cover
    import typing_extensions as te

    from .app import Flask
    from .wrappers import Request
    from .wrappers import Response


class _SessionTracker:
    __slots__ = ("root",)

    def __init__(self, session: SecureCookieSession) -> None:
        self.root = weakref.ref(session)

    def modified(self, container: object) -> None:
        root = self.root()

        if root is not None and _is_reachable(root, container):
            root.modified = True


class _TrackedMapping(dict[str, t.Any]):
    _tracker: _SessionTracker

    def __setitem__(self, key: str, value: t.Any) -> None:
        assert self._tracker is not None
        super().__setitem__(key, _track_value(value, self._tracker, {}))

    def setdefault(self, key: str, default: t.Any = None) -> t.Any:
        assert self._tracker is not None
        if key in self:
            return dict.__getitem__(self, key)

        value = super().setdefault(key, _track_value(default, self._tracker, {}))
        return value

    def update(
        self,
        other: c.Mapping[str, t.Any] | c.Iterable[tuple[str, t.Any]] = (),
        /,
        **kwargs: t.Any,
    ) -> None:
        assert self._tracker is not None
        converted: dict[str, t.Any] = {}
        seen: dict[int, t.Any] = {}

        if isinstance(other, c.Mapping):
            items = other.items()
        else:
            items = other

        for key, value in items:
            converted[key] = _track_value(value, self._tracker, seen)

        for key, value in kwargs.items():
            converted[key] = _track_value(value, self._tracker, seen)

        super().update(converted)

    def __ior__(
        self, other: c.Mapping[str, t.Any] | c.Iterable[tuple[str, t.Any]]
    ) -> _TrackedMapping:
        self.update(other)
        return self


class _TrackedDict(_TrackedMapping, CallbackDict[str, t.Any]):
    @classmethod
    def _wrap(
        cls,
        value: c.Mapping[str, t.Any] | c.Iterable[tuple[str, t.Any]],
        tracker: _SessionTracker,
        seen: dict[int, t.Any],
    ) -> _TrackedDict:
        def on_update(self: _TrackedDict) -> None:
            assert self._tracker is not None
            self._tracker.modified(self)

        wrapped = cls.__new__(cls)
        CallbackDict.__init__(wrapped, None, on_update)
        wrapped._tracker = tracker
        seen[id(value)] = wrapped

        if isinstance(value, c.Mapping):
            items: c.Iterable[tuple[t.Any, t.Any]] = value.items()
        else:
            items = value

        for key, item in items:
            dict.__setitem__(wrapped, key, _track_value(item, tracker, seen))

        return wrapped


class _TrackedList(list[t.Any]):
    __slots__ = ("_tracker",)
    _tracker: _SessionTracker

    def __init__(self, tracker: _SessionTracker) -> None:
        super().__init__()
        self._tracker = tracker

    @classmethod
    def _wrap(
        cls, value: c.Iterable[t.Any], tracker: _SessionTracker, seen: dict[int, t.Any]
    ) -> _TrackedList:
        wrapped = cls(tracker)
        seen[id(value)] = wrapped
        list.extend(wrapped, (_track_value(item, tracker, seen) for item in value))
        return wrapped

    def _modified(self) -> None:
        assert self._tracker is not None
        self._tracker.modified(self)

    def append(self, value: t.Any) -> None:
        assert self._tracker is not None
        list.append(self, _track_value(value, self._tracker, {}))
        self._modified()

    def extend(self, values: c.Iterable[t.Any]) -> None:
        assert self._tracker is not None
        values = tuple(values)
        seen: dict[int, t.Any] = {}
        list.extend(
            self, (_track_value(value, self._tracker, seen) for value in values)
        )
        self._modified()

    def insert(self, index: int, value: t.Any) -> None:
        assert self._tracker is not None
        list.insert(self, index, _track_value(value, self._tracker, {}))
        self._modified()

    def remove(self, value: t.Any) -> None:
        list.remove(self, value)
        self._modified()

    def pop(self, index: int = -1) -> t.Any:
        value = list.pop(self, index)
        self._modified()
        return value

    def clear(self) -> None:
        list.clear(self)
        self._modified()

    def __setitem__(self, index: int | slice, value: t.Any) -> None:
        assert self._tracker is not None
        if isinstance(index, slice):
            seen: dict[int, t.Any] = {}
            value = [_track_value(item, self._tracker, seen) for item in value]
        else:
            value = _track_value(value, self._tracker, {})

        list.__setitem__(self, index, value)
        self._modified()

    def __delitem__(self, index: int | slice) -> None:
        list.__delitem__(self, index)
        self._modified()

    def sort(self, *args: t.Any, **kwargs: t.Any) -> None:
        list.sort(self, *args, **kwargs)
        self._modified()

    def reverse(self) -> None:
        list.reverse(self)
        self._modified()

    def __iadd__(self, values: c.Iterable[t.Any]) -> _TrackedList:
        self.extend(values)
        return self

    def __imul__(self, count: int) -> _TrackedList:
        if count <= 0:
            list.clear(self)
            self._modified()
            return self

        list.__imul__(self, count)
        self._modified()
        return self


def _track_value(
    value: t.Any, tracker: _SessionTracker | None, seen: dict[int, t.Any] | None = None
) -> t.Any:
    if tracker is None:
        return value

    if seen is not None and id(value) in seen:
        return seen[id(value)]

    if isinstance(value, (_TrackedMapping, _TrackedList)) and value._tracker is tracker:
        return value

    if isinstance(value, c.Mapping):
        return _TrackedDict._wrap(value, tracker, seen if seen is not None else {})

    if isinstance(value, list):
        return _TrackedList._wrap(value, tracker, seen if seen is not None else {})

    if isinstance(value, tuple):
        if seen is None:
            seen = {}

        return tuple(_track_value(item, tracker, seen) for item in value)

    return value


def _is_reachable(root: object, target: object) -> bool:
    pending = [root]
    visited: set[int] = set()

    while pending:
        value = pending.pop()
        value_id = id(value)

        if value_id in visited:
            continue

        visited.add(value_id)

        if value is target:
            return True

        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, (list, tuple)):
            pending.extend(value)

    return False


def _check_circular(value: t.Any) -> None:
    active: set[int] = set()
    finished: set[int] = set()

    def children(item: t.Any) -> c.Iterable[t.Any]:
        if isinstance(item, dict):
            return item.values()

        if isinstance(item, (list, tuple)):
            return item

        return ()

    active.add(id(value))
    pending: list[tuple[t.Any, c.Iterator[t.Any]]] = [(value, iter(children(value)))]

    while pending:
        current, iterator = pending[-1]

        try:
            child = next(iterator)
        except StopIteration:
            active.remove(id(current))
            finished.add(id(current))
            pending.pop()
            continue

        child_id = id(child)

        if child_id in active:
            raise ValueError("Circular reference detected in session data.")

        if child_id in finished or not isinstance(child, (dict, list, tuple)):
            continue

        active.add(child_id)
        pending.append((child, iter(children(child))))


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


class SecureCookieSession(CallbackDict[str, t.Any], SessionMixin):
    """Base class for sessions based on signed cookies.

    This session backend will set the :attr:`modified` and
    :attr:`accessed` attributes. It cannot reliably track whether a
    session is new (vs. empty), so :attr:`new` remains hard coded to
    ``False``.

    Pass ``track_nested_modifications=True``, or use
    :class:`TrackedSecureCookieSession`, to track modifications to nested
    dictionaries and lists as well.
    """

    #: When data is changed, this is set to ``True``. Only the session
    #: dictionary itself is tracked by default. Nested data is tracked by
    #: :class:`TrackedSecureCookieSession`, or ``modified`` can be set to
    #: ``True`` manually. The session cookie is only written if this is
    #: ``True``.
    modified = False

    def __new__(
        cls,
        initial: c.Mapping[str, t.Any] | None = None,
        track_nested_modifications: bool = False,
    ) -> SecureCookieSession:
        if track_nested_modifications and cls is SecureCookieSession:
            return TrackedSecureCookieSession(initial)

        return super().__new__(cls)

    def __init__(
        self,
        initial: c.Mapping[str, t.Any] | None = None,
        track_nested_modifications: bool = False,
    ) -> None:
        def on_update(self: te.Self) -> None:
            self.modified = True

        super().__init__(initial, on_update)


class TrackedSecureCookieSession(_TrackedMapping, SecureCookieSession):
    """A secure cookie session that tracks nested dictionary and list changes."""

    _tracker: _SessionTracker

    def __init__(
        self,
        initial: c.Mapping[str, t.Any] | None = None,
        track_nested_modifications: bool = True,
    ) -> None:
        if getattr(self, "_tracker", None) is not None:
            return

        def on_update(self: SecureCookieSession) -> None:
            self.modified = True

        CallbackDict.__init__(self, None, on_update)
        self._tracker = _SessionTracker(self)

        if initial is not None:
            converted: dict[str, t.Any] = {}
            seen: dict[int, t.Any] = {}

            for key, value in initial.items():
                converted[key] = _track_value(value, self._tracker, seen)

            dict.update(self, converted)


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
    tracked_session_class = TrackedSecureCookieSession
    track_nested_modifications = False

    def _make_session(
        self, data: c.Mapping[str, t.Any] | None = None
    ) -> SecureCookieSession:
        if self.track_nested_modifications:
            return self.tracked_session_class(data)

        return self.session_class(data)

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
        data = dict(session)
        if isinstance(session, TrackedSecureCookieSession):
            _check_circular(data)
        val = self.get_signing_serializer(app).dumps(data)  # type: ignore[union-attr]
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


class TrackedSecureCookieSessionInterface(SecureCookieSessionInterface):
    """Secure cookie session interface that tracks nested data changes."""

    track_nested_modifications = True
