from datetime import datetime
from datetime import timedelta
from datetime import timezone

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
from .remember_token import InMemoryRememberTokenStore
from .remember_token import RememberToken
from .remember_token import TokenConsumeResult
from .signals import remember_token_replayed
from .signals import session_protected
from .signals import user_accessed
from .signals import user_loaded_from_cookie
from .signals import user_loaded_from_request
from .signals import user_needs_refresh
from .signals import user_unauthorized
from .utils import _create_identifier
from .utils import _user_context_processor
from .utils import decode_cookie
from .utils import decode_rotating_cookie
from .utils import encode_cookie
from .utils import encode_rotating_cookie
from .utils import expand_login_view
from .utils import generate_remember_token_id
from .utils import login_url as make_login_url
from .utils import make_next_param


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

        #: The store used by rotating "remember me" tokens when
        #: ``REMEMBER_COOKIE_ROTATION`` is enabled. Defaults to an in-memory
        #: store so the feature works out of the box; replace it via the
        #: ``REMEMBER_TOKEN_STORE`` configuration with a shared backend.
        self.remember_token_store = InMemoryRememberTokenStore()

        #: Whether rotating remember-me tokens are enabled. The
        #: ``REMEMBER_COOKIE_ROTATION`` application config takes precedence
        #: over this attribute. Defaults to ``False``.
        self.remember_cookie_rotation = False

        #: The replay grace window. The ``REMEMBER_COOKIE_REPLAY_GRACE``
        #: application config takes precedence over this attribute.
        self.remember_cookie_replay_grace = None

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

        user = None

        # Load user from Flask Session
        user_id = session.get("_user_id")
        if user_id is not None and self._user_callback is not None:
            user = self._user_callback(user_id)

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
        if sess and ident != sess.get("_id", None):
            if mode == "basic" or sess.permanent:
                if sess.get("_fresh") is not False:
                    sess["_fresh"] = False
                session_protected.send(app)
                return False
            elif mode == "strong":
                for k in SESSION_KEYS:
                    sess.pop(k, None)

                sess["_remember"] = "clear"
                session_protected.send(app)
                return True

        return False

    def _load_user_from_remember_cookie(self, cookie):
        if self._rotation_enabled():
            return self._load_user_from_rotating_cookie(cookie)

        user_id = decode_cookie(cookie)
        if user_id is not None:
            session["_user_id"] = user_id
            session["_fresh"] = False
            user = None
            if self._user_callback:
                user = self._user_callback(user_id)
            if user is not None:
                app = current_app._get_current_object()
                user_loaded_from_cookie.send(app, user=user)
                return user
        return None

    def _get_remember_token_store(self):
        """Return the configured :class:`RememberTokenStore` instance."""
        store = current_app.config.get("REMEMBER_TOKEN_STORE")
        if store is None:
            store = self.remember_token_store
        return store

    def _rotation_enabled(self):
        enabled = current_app.config.get(
            "REMEMBER_COOKIE_ROTATION", self.remember_cookie_rotation
        )
        return bool(enabled)

    def _remember_grace_window(self):
        """Return the replay grace window as a timedelta, or ``None``."""
        window = current_app.config.get(
            "REMEMBER_COOKIE_REPLAY_GRACE", self.remember_cookie_replay_grace
        )
        if window is None:
            return None
        if isinstance(window, (int, float)):
            return timedelta(seconds=window)
        return window

    def _clear_login_session(self):
        """Clear the session and schedule the remember cookie for deletion."""
        for key in list(session.keys()):
            session.pop(key, None)
        session["_remember"] = "clear"

    def _handle_remember_replay(self, payload):
        """React to a replayed rotating token.

        Outside the grace window the whole token family is revoked, the
        session and cookie are cleared, and the
        :data:`~flask_login.signals.remember_token_replayed` signal is sent.
        Inside the grace window the request is rejected and the signal is
        still sent, but the family is not revoked.
        """
        family_id = payload.get("family_id")
        token_id = payload.get("token_id")
        user_id = payload.get("user_id")

        store = self._get_remember_token_store()
        grace = self._remember_grace_window()
        within_grace = False
        if grace is not None:
            stored = store.get_token(family_id, token_id)
            if stored is not None and stored.consumed_at is not None:
                consumed_at = stored.consumed_at
                if consumed_at.tzinfo is None:
                    consumed_at = consumed_at.replace(tzinfo=timezone.utc)
                within_grace = datetime.now(timezone.utc) - consumed_at <= grace

        if not within_grace:
            store.revoke_family(family_id)
            self._clear_login_session()
        remember_token_replayed.send(
            current_app._get_current_object(),
            user_id=user_id,
            family_id=family_id,
            token_id=token_id,
        )

    def _load_user_from_rotating_cookie(self, cookie):
        payload = decode_rotating_cookie(cookie)
        if payload is None:
            return None

        try:
            now = datetime.now(timezone.utc)
            expires_at = datetime.fromtimestamp(payload["expires_at"], timezone.utc)
            if now >= expires_at:
                return None

            if payload["version"] != 1:
                return None
            user_id = str(payload["user_id"])
            identifier = payload["identifier"]
            family_id = payload["family_id"]
            token_id = payload["token_id"]

            if identifier != self._session_identifier_generator():
                return None

            user = None
            if self._user_callback:
                user = self._user_callback(user_id)
            if user is None:
                return None
        except Exception:
            # Malformed payloads or a failing user loader are treated as an
            # unauthenticated request; the token has not been consumed yet.
            return None

        store = self._get_remember_token_store()
        try:
            result = store.consume_token(family_id, token_id)
        except Exception:
            # We cannot prove the token is unused: invalidate the family when
            # possible and treat the request as unauthenticated.
            self._best_effort_revoke(store, family_id)
            self._clear_login_session()
            return None

        if result == TokenConsumeResult.ALREADY_USED:
            try:
                self._handle_remember_replay(payload)
            except Exception:
                self._best_effort_revoke(store, family_id)
                self._clear_login_session()
            return None
        if result != TokenConsumeResult.CONSUMED:
            return None

        # Rotate within the same family and schedule the cookie rewrite.
        try:
            next_payload = self._issue_rotating_token(
                user_id=user_id,
                identifier=identifier,
                family_id=family_id,
                expires_at=expires_at,
            )
        except Exception:
            self._best_effort_revoke(store, family_id)
            self._clear_login_session()
            return None

        session["_user_id"] = user_id
        session["_fresh"] = False
        session["_id"] = identifier
        session["_remember"] = "rotate"
        g._login_remember_cookie_rotated = True
        g._login_remember_cookie_payload = next_payload
        app = current_app._get_current_object()
        user_loaded_from_cookie.send(app, user=user)
        return user

    def _best_effort_revoke(self, store, family_id):
        try:
            store.revoke_family(family_id)
        except Exception:
            return

    def _issue_rotating_token(self, user_id, identifier, family_id=None, expires_at=None):
        """Create and persist a single-use rotating remember token.

        Returns the payload mapping that should be signed into the cookie.
        Store failures are propagated to the caller.
        """
        config = current_app.config
        now = datetime.now(timezone.utc)
        if "_remember_seconds" in session:
            duration = timedelta(seconds=session["_remember_seconds"])
        else:
            duration = config.get("REMEMBER_COOKIE_DURATION", COOKIE_DURATION)
        if isinstance(duration, int):
            duration = timedelta(seconds=duration)
        if expires_at is None:
            expires_at = now + duration
        if family_id is None:
            family_id = generate_remember_token_id()
        token_id = generate_remember_token_id()

        token = RememberToken(
            user_id=str(user_id),
            family_id=family_id,
            token_id=token_id,
            identifier=identifier,
            created_at=now,
            expires_at=expires_at,
        )
        store = self._get_remember_token_store()
        store.save_token(token)
        return {
            "version": 1,
            "user_id": str(user_id),
            "identifier": identifier,
            "family_id": family_id,
            "token_id": token_id,
            "issued_at": now.timestamp(),
            "expires_at": expires_at.timestamp(),
        }

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
        # With rotation enabled every refresh would mint a new single-use
        # token on every request. Rotation is driven only by an actual
        # remember-me restore instead.
        refresh = (
            config.get("REMEMBER_COOKIE_REFRESH_EACH_REQUEST")
            and has_cookie
            and not self._rotation_enabled()
        )

        operation = session.pop("_remember", None)
        rotated = g.pop("_login_remember_cookie_rotated", False)
        if not operation and not refresh and not rotated:
            return response

        if operation == "clear":
            self._clear_cookie(response)

        if operation == "set" or refresh or rotated:
            self._set_cookie(response)

        return response

    def _set_cookie(self, response):
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

        if isinstance(duration, int):
            duration = timedelta(seconds=duration)

        try:
            expires = datetime.now(timezone.utc) + duration
        except TypeError as e:
            raise Exception(
                f"REMEMBER_COOKIE_DURATION must be a datetime.timedelta, instead got: {duration}"
            ) from e

        # prepare data
        if self._rotation_enabled():
            payload = g.pop("_login_remember_cookie_payload", None)
            if payload is None:
                identifier = self._session_identifier_generator()
                try:
                    payload = self._issue_rotating_token(
                        user_id=session["_user_id"],
                        identifier=identifier,
                        expires_at=expires,
                    )
                except Exception:
                    # Storage failures must not produce a 500 or a usable cookie.
                    session.pop("_remember_seconds", None)
                    self._clear_cookie(response)
                    return
            expires = datetime.fromtimestamp(payload["expires_at"], timezone.utc)
            data = encode_rotating_cookie(payload)
        else:
            data = encode_cookie(str(session["_user_id"]))

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
        response.delete_cookie(cookie_name, domain=domain, path=path)

    def _revoke_current_remember_family(self):
        """Revoke the token family carried by the current request's cookie.

        Used by :func:`flask_login.logout_user`. Failures are swallowed so a
        broken store cannot turn a logout into a server error; the cookie is
        still cleared.
        """
        if not self._rotation_enabled():
            return
        config = current_app.config
        cookie_name = config.get("REMEMBER_COOKIE_NAME", COOKIE_NAME)
        cookie = request.cookies.get(cookie_name)
        if cookie is None:
            return
        payload = decode_rotating_cookie(cookie)
        if payload is None:
            return
        try:
            self._get_remember_token_store().revoke_family(payload["family_id"])
        except Exception:
            return
