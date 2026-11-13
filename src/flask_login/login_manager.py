from datetime import datetime
from datetime import timedelta
from datetime import timezone
from inspect import signature
from secrets import token_urlsafe
from threading import RLock

from flask import abort
from flask import current_app
from flask import flash
from flask import g
from flask import redirect
from flask import request
from flask import session

from .config import COOKIE_DURATION
from .config import COOKIE_HTTPONLY
from .config import COOKIE_NAME
from .config import COOKIE_SAMESITE
from .config import COOKIE_SECURE
from .config import ID_ATTRIBUTE
from .config import LOGIN_MESSAGE
from .config import LOGIN_MESSAGE_CATEGORY
from .config import REFRESH_MESSAGE
from .config import REFRESH_MESSAGE_CATEGORY
from .config import SESSION_KEYS
from .config import USE_SESSION_FOR_NEXT
from .mixins import AnonymousUserMixin
from .signals import session_protected
from .signals import user_accessed
from .signals import user_loaded_from_cookie
from .signals import user_loaded_from_request
from .signals import user_needs_refresh
from .signals import user_unauthorized
from .utils import _create_identifier
from .utils import _user_context_processor
from .utils import decode_cookie
from .utils import encode_cookie
from .utils import expand_login_view
from .utils import login_url as make_login_url
from .utils import make_next_param


class SessionRekeyError(RuntimeError):
    """Raised by applications that require a backend capable of rekeying."""


class LoginManager:
    """This object is used to hold the settings used for logging in. Instances
    of :class:`LoginManager` are *not* bound to specific apps, so you can
    create one in the main body of your code and then bind it to your
    app in a factory function.
    """

    def __init__(self, app=None, add_context_processor=True):
        #: A class or factory function that produces an anonymous user, which
        #: is used when no one is logged in.
        self.anonymous_user = AnonymousUserMixin

        #: The name of the view to redirect to when the user needs to log in.
        #: (This can be an absolute URL as well, if your authentication
        #: machinery is external to your application.)
        self.login_view = None

        #: Names of views to redirect to when the user needs to log in,
        #: per blueprint. If the key value is set to None the value of
        #: :attr:`login_view` will be used instead.
        self.blueprint_login_views = {}

        #: The message to flash when a user is redirected to the login page.
        self.login_message = LOGIN_MESSAGE

        #: The message category to flash when a user is redirected to the login
        #: page.
        self.login_message_category = LOGIN_MESSAGE_CATEGORY

        #: The name of the view to redirect to when the user needs to
        #: reauthenticate.
        self.refresh_view = None

        #: The message to flash when a user is redirected to the 'needs
        #: refresh' page.
        self.needs_refresh_message = REFRESH_MESSAGE

        #: The message category to flash when a user is redirected to the
        #: 'needs refresh' page.
        self.needs_refresh_message_category = REFRESH_MESSAGE_CATEGORY

        #: The mode to use session protection in. This can be either
        #: ``'basic'`` (the default) or ``'strong'``, or ``None`` to disable
        #: it.
        self.session_protection = "basic"

        #: If present, used to translate flash messages ``self.login_message``
        #: and ``self.needs_refresh_message``
        self.localize_callback = None

        self.unauthorized_callback = None

        self.needs_refresh_callback = None

        self.id_attribute = ID_ATTRIBUTE

        self._user_callback = None

        self._request_callback = None

        self._session_identifier_generator = _create_identifier

        #: Opt-in strict session rekeying. When enabled, identity changes get
        #: a new server-recognised session id before any user data is written.
        self.strict_session_rekey = False
        self.session_rekey_mode = None
        self.require_session_rekey = False

        #: Require a real session backend rekey hook. Without one, strict
        #: mode fails instead of using the process-local fallback.
        self.session_rekey_require_backend = False

        #: Optional callback implementing a session backend rekey. It may
        #: accept ``(session, new_id)`` or just ``(session)``.
        self._session_rekey_handler = None

        self._session_rekey_lock = RLock()
        self._session_rekey_store = {}
        self._remember_rekey_store = {}
        self._rekey_fallback_warned = False
        self.last_session_rekey_degraded = False

        if app is not None:
            self.init_app(app, add_context_processor)

    def init_app(self, app, add_context_processor=True):
        """
        Configures an application. This registers an `after_request` call, and
        attaches this `LoginManager` to it as `app.login_manager`.

        :param app: The :class:`flask.Flask` object to configure.
        :type app: :class:`flask.Flask`
        :param add_context_processor: Whether to add a context processor to
            the app that adds a `current_user` variable to the template.
            Defaults to ``True``.
        :type add_context_processor: bool
        """
        app.login_manager = self
        app.after_request(self._update_remember_cookie)

        if add_context_processor:
            app.context_processor(_user_context_processor)

    def unauthorized(self):
        """
        This is called when the user is required to log in. If you register a
        callback with :meth:`LoginManager.unauthorized_handler`, then it will
        be called. Otherwise, it will take the following actions:

            - Flash :attr:`LoginManager.login_message` to the user.

            - If the app is using blueprints find the login view for
              the current blueprint using `blueprint_login_views`. If the app
              is not using blueprints or the login view for the current
              blueprint is not specified use the value of `login_view`.

            - Redirect the user to the login view. (The page they were
              attempting to access will be passed in the ``next`` query
              string variable, so you can redirect there if present instead
              of the homepage. Alternatively, it will be added to the session
              as ``next`` if USE_SESSION_FOR_NEXT is set.)

        If :attr:`LoginManager.login_view` is not defined, then it will simply
        raise a HTTP 401 (Unauthorized) error instead.

        This should be returned from a view or before/after_request function,
        otherwise the redirect will have no effect.
        """
        user_unauthorized.send(current_app._get_current_object())

        if self.unauthorized_callback:
            return self.unauthorized_callback()

        if request.blueprint in self.blueprint_login_views:
            login_view = self.blueprint_login_views[request.blueprint]
        else:
            login_view = self.login_view

        if not login_view:
            abort(401)

        if self.login_message:
            if self.localize_callback is not None:
                flash(
                    self.localize_callback(self.login_message),
                    category=self.login_message_category,
                )
            else:
                flash(self.login_message, category=self.login_message_category)

        config = current_app.config
        if config.get("USE_SESSION_FOR_NEXT", USE_SESSION_FOR_NEXT):
            login_url = expand_login_view(login_view)
            session["_id"] = self._session_identifier_generator()
            session["next"] = make_next_param(login_url, request.url)
            redirect_url = make_login_url(login_view)
        else:
            redirect_url = make_login_url(login_view, next_url=request.url)

        return redirect(redirect_url)

    def user_loader(self, callback):
        """
        This sets the callback for reloading a user from the session. The
        function you set should take a user ID (a ``str``) and return a
        user object, or ``None`` if the user does not exist.

        :param callback: The callback for retrieving a user object.
        :type callback: callable
        """
        self._user_callback = callback
        return self.user_callback

    @property
    def user_callback(self):
        """Gets the user_loader callback set by user_loader decorator."""
        return self._user_callback

    def request_loader(self, callback):
        """
        This sets the callback for loading a user from a Flask request.
        The function you set should take Flask request object and
        return a user object, or `None` if the user does not exist.

        :param callback: The callback for retrieving a user object.
        :type callback: callable
        """
        self._request_callback = callback
        return self.request_callback

    @property
    def request_callback(self):
        """Gets the request_loader callback set by request_loader decorator."""
        return self._request_callback

    def unauthorized_handler(self, callback):
        """
        This will set the callback for the `unauthorized` method, which among
        other things is used by `login_required`. It takes no arguments, and
        should return a response to be sent to the user instead of their
        normal view.

        :param callback: The callback for unauthorized users.
        :type callback: callable
        """
        self.unauthorized_callback = callback
        return callback

    def needs_refresh_handler(self, callback):
        """
        This will set the callback for the `needs_refresh` method, which among
        other things is used by `fresh_login_required`. It takes no arguments,
        and should return a response to be sent to the user instead of their
        normal view.

        :param callback: The callback for unauthorized users.
        :type callback: callable
        """
        self.needs_refresh_callback = callback
        return callback

    def needs_refresh(self):
        """
        This is called when the user is logged in, but they need to be
        reauthenticated because their session is stale. If you register a
        callback with `needs_refresh_handler`, then it will be called.
        Otherwise, it will take the following actions:

            - Flash :attr:`LoginManager.needs_refresh_message` to the user.

            - Redirect the user to :attr:`LoginManager.refresh_view`. (The page
              they were attempting to access will be passed in the ``next``
              query string variable, so you can redirect there if present
              instead of the homepage.)

        If :attr:`LoginManager.refresh_view` is not defined, then it will
        simply raise a HTTP 401 (Unauthorized) error instead.

        This should be returned from a view or before/after_request function,
        otherwise the redirect will have no effect.
        """
        user_needs_refresh.send(current_app._get_current_object())

        if self.needs_refresh_callback:
            return self.needs_refresh_callback()

        if not self.refresh_view:
            abort(401)

        if self.needs_refresh_message:
            if self.localize_callback is not None:
                flash(
                    self.localize_callback(self.needs_refresh_message),
                    category=self.needs_refresh_message_category,
                )
            else:
                flash(
                    self.needs_refresh_message,
                    category=self.needs_refresh_message_category,
                )

        config = current_app.config
        if config.get("USE_SESSION_FOR_NEXT", USE_SESSION_FOR_NEXT):
            login_url = expand_login_view(self.refresh_view)
            session["_id"] = self._session_identifier_generator()
            session["next"] = make_next_param(login_url, request.url)
            redirect_url = make_login_url(self.refresh_view)
        else:
            login_url = self.refresh_view
            redirect_url = make_login_url(login_url, next_url=request.url)

        return redirect(redirect_url)

    def _update_request_context_with_user(self, user=None):
        """Store the given user as ctx.user."""

        if user is None:
            user = self.anonymous_user()

        g._login_user = user
        g._login_user_object = user
        g._login_user_session_key = self._session_cache_key()

    def session_rekey_handler(self, callback):
        """Set the callback used to rekey the current session backend."""

        self._session_rekey_handler = callback
        return callback

    def session_rekey(self, user_id=None, new_session_id=None):
        """Explicitly replace the current session identity.

        The backend hook is preferred. If it is unavailable, the built-in
        process-local identity store is used unless strict mode requires a
        backend. Returns ``True`` only when the old identity can no longer
        authorise requests.
        """

        return self._rekey_session(user_id=user_id, new_session_id=new_session_id)

    def _strict_rekey_enabled(self, override=None):
        if override is True:
            return True

        app = current_app._get_current_object()
        config = app.config
        strict = bool(getattr(self, "strict_session_rekey", False))
        strict = strict or bool(getattr(self, "require_session_rekey", False))

        manager_mode = getattr(self, "session_rekey_mode", None)
        if isinstance(manager_mode, str) and manager_mode.lower() in {
            "strict",
            "strong",
            "true",
            "1",
            "require",
            "required",
        }:
            strict = True

        for key in (
            "SESSION_REKEY_STRICT",
            "SESSION_REKEY_ENABLED",
            "LOGIN_SESSION_REKEY_STRICT",
            "LOGIN_STRICT_SESSION_REKEY",
            "STRICT_SESSION_REKEY",
        ):
            if config.get(key):
                strict = True

        mode = config.get("SESSION_REKEY_MODE")
        if mode is None:
            mode = config.get("SESSION_REKEY")

        if isinstance(mode, bool):
            strict = strict or mode
        elif isinstance(mode, str) and mode.lower() in {
            "strict",
            "strong",
            "true",
            "1",
            "require",
            "required",
        }:
            strict = True

        return strict

    def _session_cache_key(self):
        return (
            session.get("_user_id"),
            session.get("_id"),
            session.get("_fresh"),
            session.get("_strict_rekey"),
        )

    def _request_user_cache_stale(self):
        cached_user = getattr(g, "_login_user_object", None)
        if cached_user is not None and g._login_user is not cached_user:
            return True

        cached = getattr(g, "_login_user_session_key", None)
        if cached is None:
            return False

        if cached != self._session_cache_key():
            return True

        user_id = session.get("_user_id")
        if user_id is None:
            return False

        user = getattr(g, "_login_user", None)
        if user is not None and getattr(user, "is_authenticated", False):
            if str(user.get_id()) != str(user_id):
                return True

        rekeyed = bool(session.get("_strict_rekey"))
        strict = self._strict_rekey_enabled()
        if not rekeyed and not strict:
            return False

        return not self._session_identity_is_current(user_id)

    def _session_identity_is_current(self, user_id=None):
        if not session.get("_strict_rekey"):
            return False

        session_id = session.get("_id")
        if session_id is None:
            return False

        with self._session_rekey_lock:
            registered_user = self._session_rekey_store.get(session_id)

        if registered_user is None:
            return False

        return user_id is None or str(registered_user) == str(user_id)

    def _revoke_session_identity(self, session_id):
        if session_id is None:
            return

        with self._session_rekey_lock:
            self._session_rekey_store.pop(session_id, None)

    def _clear_session_authentication(self):
        old_id = session.pop("_id", None)
        self._revoke_session_identity(old_id)
        session.pop("_fresh", None)
        session.pop("_user_id", None)
        session.pop("_fingerprint", None)
        session.pop("_strict_rekey", None)
        session.pop("_remember_nonce", None)

    def _requires_backend_rekey(self):
        app = current_app._get_current_object()
        config = app.config
        required = bool(getattr(self, "session_rekey_require_backend", False))
        required = required or bool(config.get("SESSION_REKEY_REQUIRE_BACKEND"))
        required = required or bool(config.get("SESSION_REKEY_BACKEND_REQUIRED"))

        fallback = config.get("SESSION_REKEY_FALLBACK")
        if isinstance(fallback, str) and fallback.lower() in {
            "reject",
            "fail",
            "error",
            "required",
        }:
            required = True

        return required

    def _session_rekey_failed(self, message):
        failure_mode = current_app.config.get("SESSION_REKEY_FAILURE", "return")
        if isinstance(failure_mode, str) and failure_mode.lower() == "raise":
            raise SessionRekeyError(message)

        return False

    def _invoke_rekey_hook(self, hook, session_obj, new_id, old_id):
        try:
            parameters = signature(hook).parameters
        except (TypeError, ValueError):
            parameters = {}

        names = list(parameters)
        has_varargs = any(
            p.kind == p.VAR_POSITIONAL for p in parameters.values()
        )

        if has_varargs:
            args = (session_obj, new_id)
        elif len(parameters) >= 3:
            app = current_app._get_current_object()
            if names and names[0] in {"app", "application"}:
                args = (app, session_obj, new_id)
            else:
                args = (session_obj, old_id, new_id)
        elif len(parameters) >= 2:
            second = names[1].lower() if len(names) > 1 else ""
            if "old" in second:
                args = (session_obj, old_id)
            else:
                args = (session_obj, new_id)
        elif len(parameters) == 1:
            args = (session_obj,)
        else:
            args = ()

        return hook(*args)

    def _backend_rekey(self, session_obj, new_id, old_id):
        app = current_app._get_current_object()
        hooks = []

        if self._session_rekey_handler is not None:
            hooks.append(("session_rekey_handler", self._session_rekey_handler))

        for key in (
            "SESSION_REKEY_HANDLER",
            "SESSION_REKEY_CALLBACK",
            "SESSION_REKEY_BACKEND",
        ):
            hook = app.config.get(key)
            if callable(hook):
                hooks.append((key, hook))

        session_interface = app.session_interface
        for name in (
            "rekey_session",
            "regenerate_session",
            "regenerate",
            "rotate_session",
            "rekey",
        ):
            hook = getattr(session_interface, name, None)
            if callable(hook):
                hooks.append((f"session_interface.{name}", hook))

        supported = False
        for name, hook in hooks:
            try:
                result = self._invoke_rekey_hook(
                    hook, session_obj, new_id, old_id
                )
            except NotImplementedError:
                continue
            except Exception:
                current_app.logger.exception("Session rekey hook %s failed", name)
                return True, False, None

            if result is False:
                current_app.logger.error("Session rekey hook %s rejected the rekey", name)
                return True, False, None

            supported = True
            if isinstance(result, str):
                new_id = result
            break

        return supported, supported, new_id

    def _rekey_session(self, user_id=None, new_session_id=None):
        session_obj = session._get_current_object()
        old_id = session_obj.get("_id")
        new_id = new_session_id or token_urlsafe(32)
        self.last_session_rekey_degraded = False

        supported, success, backend_id = self._backend_rekey(
            session_obj, new_id, old_id
        )

        if not success:
            if supported or self._requires_backend_rekey():
                if supported:
                    return self._session_rekey_failed(
                        "Session rekey hook failed or rejected the rekey"
                    )

                current_app.logger.error(
                    "Session rekey failed: the session backend does not "
                    "implement a rekey hook"
                )
                return self._session_rekey_failed(
                    "Session backend does not implement a rekey hook"
                )

            if not self._rekey_fallback_warned:
                current_app.logger.warning(
                    "Session backend cannot rekey; using process-local identity "
                    "revocation. Configure a server-side session backend for "
                    "multi-process deployments."
                )
                self._rekey_fallback_warned = True

            backend_id = new_id
            self.last_session_rekey_degraded = True

        session_obj["_id"] = backend_id
        session_obj["_fingerprint"] = self._session_identifier_generator()
        session_obj["_strict_rekey"] = True

        with self._session_rekey_lock:
            if old_id is not None:
                self._session_rekey_store.pop(old_id, None)
            if user_id is not None:
                self._session_rekey_store[backend_id] = str(user_id)
            else:
                self._session_rekey_store.pop(backend_id, None)

        return True

    def _new_remember_nonce(self, user_id):
        nonce = f"rk_{token_urlsafe(24)}"
        with self._session_rekey_lock:
            self._remember_rekey_store[nonce] = str(user_id)
        return nonce

    def _revoke_remember_nonce(self, nonce):
        if nonce is None:
            return

        with self._session_rekey_lock:
            self._remember_rekey_store.pop(nonce, None)

    def _remember_nonce_is_current(self, nonce, user_id):
        if nonce is None:
            return False

        with self._session_rekey_lock:
            registered_user = self._remember_rekey_store.get(nonce)

        return registered_user is not None and str(registered_user) == str(user_id)

    def _consume_remember_nonce(self, nonce, user_id):
        if nonce is None:
            return False

        with self._session_rekey_lock:
            registered_user = self._remember_rekey_store.pop(nonce, None)

        return registered_user is not None and str(registered_user) == str(user_id)

    @staticmethod
    def _parse_remember_payload(payload):
        if payload is None:
            return None, None

        if "|rk_" in payload:
            user_id, nonce = payload.rsplit("|", 1)
            return user_id, nonce

        return payload, None

    def _remember_cookie_is_current(self, cookie):
        user_id = session.get("_user_id")
        pending = getattr(g, "_flask_login_remember_nonce", None)
        if pending is not None and self._remember_nonce_is_current(pending, user_id):
            return True

        payload = decode_cookie(cookie)
        user_id, nonce = self._parse_remember_payload(payload)
        if user_id is None:
            return False

        if nonce is None:
            return not self._strict_rekey_enabled()

        return self._remember_nonce_is_current(nonce, user_id)

    def _load_user(self):
        """Loads user from session or remember_me cookie as applicable"""

        if self._user_callback is None and self._request_callback is None:
            raise Exception(
                "Missing user_loader or request_loader. Refer to "
                "http://flask-login.readthedocs.io/#how-it-works "
                "for more info."
            )

        user_accessed.send(current_app._get_current_object())

        # Check SESSION_PROTECTION
        if self._session_protection_failed():
            return self._update_request_context_with_user()

        strict = self._strict_rekey_enabled()
        rekeyed = bool(session.get("_strict_rekey"))
        enforce_identity = strict or rekeyed
        user = None

        # Load user from Flask Session
        user_id = session.get("_user_id")
        if user_id is not None:
            if enforce_identity and not self._session_identity_is_current(user_id):
                self._clear_session_authentication()
                if request.cookies.get(
                    current_app.config.get("REMEMBER_COOKIE_NAME", COOKIE_NAME)
                ):
                    session["_remember"] = "clear"
                return self._update_request_context_with_user()

            if self._user_callback is not None:
                user = self._user_callback(user_id)
                if enforce_identity and user is not None and not user.is_active:
                    user = None

            if enforce_identity and self._user_callback is None:
                self._clear_session_authentication()
                if request.cookies.get(
                    current_app.config.get("REMEMBER_COOKIE_NAME", COOKIE_NAME)
                ):
                    session["_remember"] = "clear"
                return self._update_request_context_with_user()

            if self._user_callback is not None and user is None:
                self._clear_session_authentication()
                if request.cookies.get(
                    current_app.config.get("REMEMBER_COOKIE_NAME", COOKIE_NAME)
                ):
                    session["_remember"] = "clear"
                return self._update_request_context_with_user()

        # Load user from Remember Me Cookie or Request Loader
        if user is None:
            config = current_app.config
            cookie_name = config.get("REMEMBER_COOKIE_NAME", COOKIE_NAME)
            has_cookie = cookie_name in request.cookies and session.get("_remember") != "clear"
            if has_cookie:
                cookie = request.cookies[cookie_name]
                user = self._load_user_from_remember_cookie(cookie)
            elif self._request_callback:
                user = self._load_user_from_request(request)
                if enforce_identity and user is not None and not user.is_active:
                    user = None

        return self._update_request_context_with_user(user)

    def _session_protection_failed(self):
        sess = session._get_current_object()
        ident = self._session_identifier_generator()

        app = current_app._get_current_object()
        mode = app.config.get("SESSION_PROTECTION", self.session_protection)

        if not mode or mode not in ["basic", "strong"]:
            return False

        # if the sess is empty, it's an anonymous user or just logged out
        # so we can skip this
        if sess.get("_strict_rekey"):
            stored_ident = sess.get("_fingerprint")
        else:
            stored_ident = sess.get("_id")

        if sess and ident != stored_ident:
            if mode == "basic" or sess.permanent:
                if sess.get("_fresh") is not False:
                    sess["_fresh"] = False
                session_protected.send(app)
                return False
            elif mode == "strong":
                self._revoke_session_identity(sess.get("_id"))
                for k in SESSION_KEYS:
                    sess.pop(k, None)
                sess.pop("_fingerprint", None)
                sess.pop("_strict_rekey", None)
                sess.pop("_remember_nonce", None)

                sess["_remember"] = "clear"
                session_protected.send(app)
                return True

        return False

    def _load_user_from_remember_cookie(self, cookie):
        payload = decode_cookie(cookie)
        user_id, nonce = self._parse_remember_payload(payload)
        strict = self._strict_rekey_enabled()

        if strict and nonce is None:
            return None

        if strict and not self._consume_remember_nonce(nonce, user_id):
            return None

        if user_id is not None:
            user = None
            if self._user_callback:
                user = self._user_callback(user_id)
            if user is not None:
                if strict and not user.is_active:
                    self._revoke_remember_nonce(nonce)
                    session["_remember"] = "clear"
                    return None

                if strict:
                    if not self._rekey_session(user_id=user_id):
                        return None

                    new_nonce = self._new_remember_nonce(user_id)
                    g._flask_login_remember_nonce = new_nonce

                session["_user_id"] = user_id
                session["_fresh"] = False
                if strict:
                    session["_remember"] = "set"

                app = current_app._get_current_object()
                user_loaded_from_cookie.send(app, user=user)
                return user

            if strict:
                session["_remember"] = "clear"
        return None

    def _load_user_from_request(self, request):
        if self._request_callback:
            user = self._request_callback(request)
            if user is not None:
                app = current_app._get_current_object()
                user_loaded_from_request.send(app, user=user)
                return user
        return None

    def _update_remember_cookie(self, response):
        config = current_app.config
        cookie_name = config.get("REMEMBER_COOKIE_NAME", COOKIE_NAME)
        has_cookie = cookie_name in request.cookies and session.get("_remember") != "clear"
        refresh = current_app.config.get("REMEMBER_COOKIE_REFRESH_EACH_REQUEST") and has_cookie

        operation = session.pop("_remember", None)

        if (
            operation != "set"
            and has_cookie
            and self._strict_rekey_enabled()
            and not self._remember_cookie_is_current(request.cookies[cookie_name])
        ):
            operation = "clear"
            refresh = False

        if not operation and not refresh:
            return response

        if operation == "clear":
            self._clear_cookie(response)

        if operation == "set" or refresh:
            self._set_cookie(response, rotate=operation == "set")

        return response

    def _set_cookie(self, response, rotate=False):
        if "_user_id" not in session:
            return

        # cookie settings
        config = current_app.config
        cookie_name = config.get("REMEMBER_COOKIE_NAME", COOKIE_NAME)
        domain = config.get("REMEMBER_COOKIE_DOMAIN")
        path = config.get("REMEMBER_COOKIE_PATH", "/")

        secure = config.get("REMEMBER_COOKIE_SECURE", COOKIE_SECURE)
        httponly = config.get("REMEMBER_COOKIE_HTTPONLY", COOKIE_HTTPONLY)
        samesite = config.get("REMEMBER_COOKIE_SAMESITE", COOKIE_SAMESITE)

        if "_remember_seconds" in session:
            duration = timedelta(seconds=session["_remember_seconds"])
        else:
            duration = config.get("REMEMBER_COOKIE_DURATION", COOKIE_DURATION)

        # prepare data
        user_id = str(session["_user_id"])
        strict = self._strict_rekey_enabled()
        nonce = None

        if strict:
            nonce = getattr(g, "_flask_login_remember_nonce", None)
            old_cookie = request.cookies.get(cookie_name)
            if rotate and old_cookie is not None:
                old_payload = decode_cookie(old_cookie)
                _old_user_id, old_nonce = self._parse_remember_payload(old_payload)
                self._revoke_remember_nonce(old_nonce)

            if nonce is None:
                current_payload = decode_cookie(old_cookie) if old_cookie else None
                current_user_id, current_nonce = self._parse_remember_payload(
                    current_payload
                )
                if not rotate and self._remember_nonce_is_current(
                    current_nonce, user_id
                ):
                    nonce = current_nonce

            if nonce is None or not self._remember_nonce_is_current(nonce, user_id):
                nonce = self._new_remember_nonce(user_id)

            data = encode_cookie(f"{user_id}|{nonce}")
        else:
            data = encode_cookie(user_id)

        if isinstance(duration, int):
            duration = timedelta(seconds=duration)

        try:
            expires = datetime.now(timezone.utc) + duration
        except TypeError as e:
            raise Exception(
                f"REMEMBER_COOKIE_DURATION must be a datetime.timedelta, instead got: {duration}"
            ) from e

        # actually set it
        response.set_cookie(
            cookie_name,
            value=data,
            expires=expires,
            domain=domain,
            path=path,
            secure=secure,
            httponly=httponly,
            samesite=samesite,
        )

    def _clear_cookie(self, response):
        config = current_app.config
        cookie_name = config.get("REMEMBER_COOKIE_NAME", COOKIE_NAME)
        domain = config.get("REMEMBER_COOKIE_DOMAIN")
        path = config.get("REMEMBER_COOKIE_PATH", "/")
        cookie = request.cookies.get(cookie_name)
        if cookie is not None:
            payload = decode_cookie(cookie)
            _user_id, nonce = self._parse_remember_payload(payload)
            self._revoke_remember_nonce(nonce)
        response.delete_cookie(cookie_name, domain=domain, path=path)
