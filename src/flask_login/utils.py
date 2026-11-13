from collections import namedtuple
from datetime import timedelta
from enum import Enum
import hmac
from functools import wraps
from hashlib import sha512
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

from flask import current_app
from flask import g
from flask import has_request_context
from flask import request
from flask import session
from flask import url_for
from werkzeug.local import LocalProxy

from .config import COOKIE_NAME
from .config import EXEMPT_METHODS
from .signals import user_logged_in
from .signals import user_logged_out
from .signals import user_login_confirmed

#: A proxy for the current user. If no user is logged in, this will be an
#: anonymous user
current_user = LocalProxy(lambda: _get_user())

#: The session key holding the signed, tamper-evident timestamp of the most
#: recent interactive authentication (a plain login or ``confirm_login``).
AUTH_TIME_SESSION_KEY = "_auth_time"

#: Marker embedded in the signed claim payload so a remember-me cookie value
#: (which has the same ``payload|digest`` shape) can never be replayed as an
#: authentication-time claim.
_AUTH_TIME_PREFIX = "stepup"


class StepUpStatus(str, Enum):
    """Outcome of a step-up authentication check."""

    #: The most recent interactive authentication is fresh enough.
    ALLOWED = "allowed"
    #: The user is authenticated, but must reauthenticate first.
    REAUTH_REQUIRED = "reauth_required"
    #: The step-up policy itself is misconfigured, so no decision is possible.
    CONFIG_ERROR = "config_error"


class StepUpResult(
    namedtuple("StepUpResult", ["status", "reason", "max_age", "auth_time", "age"])
):
    """
    The structured result of :func:`step_up_status` /
    :meth:`LoginManager.step_up_check`.

    :param status: A :class:`StepUpStatus` describing what the caller should do.
    :param reason: A stable, machine-readable code explaining the decision.
    :param max_age: The configured maximum age in seconds, or ``None`` on a
        configuration error.
    :param auth_time: The verified authentication time (epoch seconds), or
        ``None`` when no valid claim was available.
    :param age: The age of the verified authentication time in seconds, or
        ``None`` when no valid claim was available.
    """

    __slots__ = ()

    @property
    def allowed(self):
        """``True`` when the sensitive operation may proceed."""
        return self.status is StepUpStatus.ALLOWED

    @property
    def reauth_required(self):
        """``True`` when the user must reauthenticate before proceeding."""
        return self.status is StepUpStatus.REAUTH_REQUIRED

    @property
    def config_error(self):
        """``True`` when the step-up policy is misconfigured."""
        return self.status is StepUpStatus.CONFIG_ERROR


#: Stable reason codes returned on :class:`StepUpResult`.
STEPUP_REASON_FRESH = "fresh"
STEPUP_REASON_UNAUTHENTICATED = "unauthenticated"
STEPUP_REASON_REMEMBERED = "remembered"
STEPUP_REASON_MISSING_CLAIM = "missing_claim"
STEPUP_REASON_FORGED_CLAIM = "forged_claim"
STEPUP_REASON_CLOCK_ROLLED_BACK = "clock_rolled_back"
STEPUP_REASON_EXPIRED = "expired"
STEPUP_REASON_MISSING_MAX_AGE = "missing_max_age"
STEPUP_REASON_INVALID_MAX_AGE = "invalid_max_age"
STEPUP_REASON_MISSING_SECRET_KEY = "missing_secret_key"


def encode_cookie(payload, key=None):
    """
    This will encode a ``str`` value into a cookie, and sign that cookie
    with the app's secret key.

    :param payload: The value to encode, as `str`.
    :type payload: str

    :param key: The key to use when creating the cookie digest. If not
                specified, the SECRET_KEY value from app config will be used.
    :type key: str
    """
    return f"{payload}|{_cookie_digest(payload, key=key)}"


def decode_cookie(cookie, key=None):
    """
    This decodes a cookie given by `encode_cookie`. If verification of the
    cookie fails, ``None`` will be implicitly returned.

    :param cookie: An encoded cookie.
    :type cookie: str

    :param key: The key to use when creating the cookie digest. If not
                specified, the SECRET_KEY value from app config will be used.
    :type key: str
    """
    try:
        payload, digest = cookie.rsplit("|", 1)
        if hasattr(digest, "decode"):
            digest = digest.decode("ascii")  # pragma: no cover
    except ValueError:
        return

    if hmac.compare_digest(_cookie_digest(payload, key=key), digest):
        return payload


def encode_auth_time(auth_time, user_id, key=None):
    """
    Build a tamper-evident claim of an authentication time. The claim binds
    the timestamp to the user id and is signed with the app's secret key, so a
    client cannot forge one or make an old timestamp look newer.

    :param auth_time: The authentication time as epoch seconds.
    :type auth_time: int or float
    :param user_id: The id of the user that authenticated.
    :type user_id: str
    :param key: The key to sign with. Defaults to the app ``SECRET_KEY``.
    :type key: str
    """
    payload = f"{_AUTH_TIME_PREFIX}|{user_id}|{repr(float(auth_time))}"
    return encode_cookie(payload, key=key)


def decode_auth_time(claim, user_id, key=None):
    """
    Verify an authentication-time claim produced by
    :func:`encode_auth_time`. Returns the authentication time as epoch
    seconds, or ``None`` if the claim is missing, malformed, signed with a
    different key, or belongs to another user.

    :param claim: The signed claim stored in the session.
    :type claim: str
    :param user_id: The id of the current user.
    :type user_id: str
    :param key: The key to verify with. Defaults to the app ``SECRET_KEY``.
    :type key: str
    """
    if not isinstance(claim, str):
        return None

    payload = decode_cookie(claim, key=key)

    if payload is None:
        return None

    try:
        prefix, claim_user_id, timestamp = payload.split("|", 2)
    except ValueError:
        return None

    if prefix != _AUTH_TIME_PREFIX or claim_user_id != str(user_id):
        return None

    try:
        return float(timestamp)
    except ValueError:
        return None


def make_next_param(login_url, current_url):
    """
    Reduces the scheme and host from a given URL so it can be passed to
    the given `login` URL more efficiently.

    :param login_url: The login URL being redirected to.
    :type login_url: str
    :param current_url: The URL to reduce.
    :type current_url: str
    """
    l_url = urlsplit(login_url)
    c_url = urlsplit(current_url)

    if (not l_url.scheme or l_url.scheme == c_url.scheme) and (
        not l_url.netloc or l_url.netloc == c_url.netloc
    ):
        return urlunsplit(("", "", c_url.path, c_url.query, ""))
    return current_url


def expand_login_view(login_view):
    """
    Returns the url for the login view, expanding the view name to a url if
    needed.

    :param login_view: The name of the login view or a URL for the login view.
    :type login_view: str
    """
    if login_view.startswith(("https://", "http://", "/")):
        return login_view

    return url_for(login_view)


def login_url(login_view, next_url=None, next_field="next"):
    """
    Creates a URL for redirecting to a login page. If only `login_view` is
    provided, this will just return the URL for it. If `next_url` is provided,
    however, this will append a ``next=URL`` parameter to the query string
    so that the login view can redirect back to that URL. Flask-Login's default
    unauthorized handler uses this function when redirecting to your login url.

    To force the host name used, set `FORCE_HOST_FOR_REDIRECTS` to a host. This
    prevents from redirecting to external sites if `SERVER_NAME` is not configured.

    :param login_view: The name of the login view. (Alternately, the actual
                       URL to the login view.)
    :type login_view: str
    :param next_url: The URL to give the login view for redirection.
    :type next_url: str
    :param next_field: What field to store the next URL in. (It defaults to
                       ``next``.)
    :type next_field: str
    """
    base = expand_login_view(login_view)

    if next_url is None:
        return base

    parsed_result = urlsplit(base)
    md = parse_qs(parsed_result.query, keep_blank_values=True)
    md[next_field] = make_next_param(base, next_url)
    netloc = current_app.config.get("FORCE_HOST_FOR_REDIRECTS") or parsed_result.netloc
    parsed_result = parsed_result._replace(netloc=netloc, query=urlencode(md, doseq=True))
    return urlunsplit(parsed_result)


def login_fresh():
    """
    This returns ``True`` if the current login is fresh.
    """
    return session.get("_fresh", False)


def login_remembered():
    """
    This returns ``True`` if the current login is remembered across sessions.
    """
    config = current_app.config
    cookie_name = config.get("REMEMBER_COOKIE_NAME", COOKIE_NAME)
    has_cookie = cookie_name in request.cookies and session.get("_remember") != "clear"
    if has_cookie:
        cookie = request.cookies[cookie_name]
        user_id = decode_cookie(cookie)
        return user_id is not None
    return False


def login_user(user, remember=False, duration=None, force=False, fresh=True):
    """
    Logs a user in. You should pass the actual user object to this. If the
    user's `is_active` property is ``False``, they will not be logged in
    unless `force` is ``True``.

    This will return ``True`` if the log in attempt succeeds, and ``False`` if
    it fails (i.e. because the user is inactive).

    :param user: The user object to log in.
    :type user: object
    :param remember: Whether to remember the user after their session expires.
        Defaults to ``False``.
    :type remember: bool
    :param duration: The amount of time before the remember cookie expires. If
        ``None`` the value set in the settings is used. Defaults to ``None``.
    :type duration: :class:`datetime.timedelta`
    :param force: If the user is inactive, setting this to ``True`` will log
        them in regardless. Defaults to ``False``.
    :type force: bool
    :param fresh: setting this to ``False`` will log in the user with a session
        marked as not "fresh". Defaults to ``True``.
    :type fresh: bool
    """
    if not force and not user.is_active:
        return False

    user_id = getattr(user, current_app.login_manager.id_attribute)()
    session["_user_id"] = user_id
    session["_fresh"] = fresh
    session["_id"] = current_app.login_manager._session_identifier_generator()

    # Only an interactive (fresh) login establishes a recent authentication
    # time. Non-fresh logins must not be able to pass a step-up check.
    if fresh:
        _set_auth_time(user_id)
    else:
        _clear_auth_time()

    if remember:
        session["_remember"] = "set"
        if duration is not None:
            try:
                # equal to timedelta.total_seconds() but works with Python 2.6
                session["_remember_seconds"] = (
                    duration.microseconds + (duration.seconds + duration.days * 24 * 3600) * 10**6
                ) / 10.0**6
            except AttributeError as e:
                raise Exception(
                    f"duration must be a datetime.timedelta, instead got: {duration}"
                ) from e

    current_app.login_manager._update_request_context_with_user(user)
    user_logged_in.send(current_app._get_current_object(), user=_get_user())
    return True


def logout_user():
    """
    Logs a user out. (You do not need to pass the actual user.) This will
    also clean up the remember me cookie if it exists.
    """

    user = _get_user()

    if "_user_id" in session:
        session.pop("_user_id")

    if "_fresh" in session:
        session.pop("_fresh")

    if "_id" in session:
        session.pop("_id")

    _clear_auth_time()

    cookie_name = current_app.config.get("REMEMBER_COOKIE_NAME", COOKIE_NAME)
    if cookie_name in request.cookies:
        session["_remember"] = "clear"
        if "_remember_seconds" in session:
            session.pop("_remember_seconds")

    user_logged_out.send(current_app._get_current_object(), user=user)

    current_app.login_manager._update_request_context_with_user()
    return True


def confirm_login():
    """
    This sets the current session as fresh. Sessions become stale when they
    are reloaded from a cookie.
    """
    session["_fresh"] = True
    session["_id"] = current_app.login_manager._session_identifier_generator()

    # The reauthentication itself is a fresh proof of identity, so the
    # authentication-time claim must be (re)issued, not merely toggled.
    user_id = session.get("_user_id")
    if user_id is not None:
        _set_auth_time(user_id)

    user_login_confirmed.send(current_app._get_current_object())


def _set_auth_time(user_id):
    """Store a signed claim of the current authentication time."""
    manager = current_app.login_manager
    session[AUTH_TIME_SESSION_KEY] = encode_auth_time(
        manager.clock(), user_id
    )


def _clear_auth_time():
    """Remove any authentication-time claim from the session."""
    if AUTH_TIME_SESSION_KEY in session:
        session.pop(AUTH_TIME_SESSION_KEY)


def _coerce_max_age(max_age):
    """Normalize a step-up ``max_age`` argument to seconds."""
    if isinstance(max_age, timedelta):
        return max_age.total_seconds()
    if isinstance(max_age, bool) or not isinstance(max_age, (int, float)):
        return None
    return float(max_age)


def step_up_status(max_age=None):
    """
    Evaluate the explicit step-up authentication policy for the current
    request without raising or redirecting. The decision is always returned
    as a structured :class:`StepUpResult`; callers branch on
    :attr:`StepUpResult.status` (or its ``allowed`` / ``reauth_required`` /
    ``config_error`` properties) rather than parsing exception text.

    A reauthentication is required when the most recent interactive
    authentication is older than ``max_age``, its signed claim is missing or
    forged, the timestamp lies in the future (for example after a clock
    rollback), or the session was restored from a "remember me" cookie
    without a fresh confirmation.

    :param max_age: Maximum accepted age of the authentication. Accepts a
        :class:`datetime.timedelta` or a number of seconds. When ``None``,
        the ``STEPUP_MAX_AGE`` app config or the
        :attr:`LoginManager.step_up_max_age` attribute is used.
    :type max_age: datetime.timedelta or int or float or None
    """
    return current_app.login_manager.step_up_check(max_age)


def login_required(func):
    """
    If you decorate a view with this, it will ensure that the current user is
    logged in and authenticated before calling the actual view. (If they are
    not, it calls the :attr:`LoginManager.unauthorized` callback.) For
    example::

        @app.route('/post')
        @login_required
        def post():
            pass

    If there are only certain times you need to require that your user is
    logged in, you can do so with::

        if not current_user.is_authenticated:
            return current_app.login_manager.unauthorized()

    ...which is essentially the code that this function adds to your views.

    .. Note ::

        Per `W3 guidelines for CORS preflight requests
        <http://www.w3.org/TR/cors/#cross-origin-request-with-preflight-0>`_,
        HTTP ``OPTIONS`` requests are exempt from login checks.

    :param func: The view function to decorate.
    :type func: function
    """

    @wraps(func)
    def decorated_view(*args, **kwargs):
        if request.method in EXEMPT_METHODS:
            pass
        elif not current_user.is_authenticated:
            return current_app.login_manager.unauthorized()

        # flask 1.x compatibility
        # current_app.ensure_sync is only available in Flask >= 2.0
        if callable(getattr(current_app, "ensure_sync", None)):
            return current_app.ensure_sync(func)(*args, **kwargs)
        return func(*args, **kwargs)

    return decorated_view


def fresh_login_required(func):
    """
    If you decorate a view with this, it will ensure that the current user's
    login is fresh - i.e. their session was not restored from a 'remember me'
    cookie. Sensitive operations, like changing a password or e-mail, should
    be protected with this, to impede the efforts of cookie thieves.

    If the user is not authenticated, :meth:`LoginManager.unauthorized` is
    called as normal. If they are authenticated, but their session is not
    fresh, it will call :meth:`LoginManager.needs_refresh` instead. (In that
    case, you will need to provide a :attr:`LoginManager.refresh_view`.)

    Behaves identically to the :func:`login_required` decorator with respect
    to configuration variables.

    .. Note ::

        Per `W3 guidelines for CORS preflight requests
        <http://www.w3.org/TR/cors/#cross-origin-request-with-preflight-0>`_,
        HTTP ``OPTIONS`` requests are exempt from login checks.

    :param func: The view function to decorate.
    :type func: function
    """

    @wraps(func)
    def decorated_view(*args, **kwargs):
        if request.method in EXEMPT_METHODS:
            pass
        elif not current_user.is_authenticated:
            return current_app.login_manager.unauthorized()
        elif not login_fresh():
            return current_app.login_manager.needs_refresh()
        try:
            # current_app.ensure_sync available in Flask >= 2.0
            return current_app.ensure_sync(func)(*args, **kwargs)
        except AttributeError:  # pragma: no cover
            return func(*args, **kwargs)

    return decorated_view


def step_up_required(func=None, max_age=None):
    """
    Protect a view with an explicit step-up authentication policy. Unlike
    :func:`fresh_login_required`, which only checks a boolean flag, this
    enforces a maximum age on the most recent interactive authentication,
    backed by a signed timestamp that a client cannot forge or extend.

    It can be applied bare (``@step_up_required``, using the configured
    default maximum age) or parameterized::

        @app.route("/payment-account")
        @step_up_required(max_age=timedelta(minutes=10))
        def change_payout_account():
            ...

    Unauthenticated users are handled by
    :meth:`LoginManager.unauthorized`; authenticated users with a stale,
    missing, forged or remembered authentication are handled by
    :meth:`LoginManager.needs_refresh`. A policy misconfiguration (no
    maximum age configured, an invalid age, or no secret key) is reported
    separately through :meth:`LoginManager.step_up_config_error` instead of
    being mistaken for a missing login.

    HTTP ``OPTIONS`` requests are exempt, matching the other decorators.

    :param func: The view function to decorate.
    :type func: function
    :param max_age: Maximum accepted age of the authentication, as a
        :class:`datetime.timedelta` or a number of seconds. When ``None``,
        the ``STEPUP_MAX_AGE`` app config or
        :attr:`LoginManager.step_up_max_age` is used.
    :type max_age: datetime.timedelta or int or float or None
    """

    def decorator(view_func):
        @wraps(view_func)
        def decorated_view(*args, **kwargs):
            if request.method in EXEMPT_METHODS:
                pass
            elif not current_user.is_authenticated:
                return current_app.login_manager.unauthorized()
            else:
                result = step_up_status(max_age)
                if result.config_error:
                    return current_app.login_manager.step_up_config_error(result)
                if result.reauth_required:
                    return current_app.login_manager.needs_refresh()

            if callable(getattr(current_app, "ensure_sync", None)):
                return current_app.ensure_sync(view_func)(*args, **kwargs)
            return view_func(*args, **kwargs)

        return decorated_view

    if func is not None:
        return decorator(func)
    return decorator


def set_login_view(login_view, blueprint=None):
    """
    Sets the login view for the app or blueprint. If a blueprint is passed,
    the login view is set for this blueprint on ``blueprint_login_views``.

    :param login_view: The user object to log in.
    :type login_view: str
    :param blueprint: The blueprint which this login view should be set on.
        Defaults to ``None``.
    :type blueprint: object
    """

    num_login_views = len(current_app.login_manager.blueprint_login_views)
    if blueprint is not None or num_login_views != 0:
        (current_app.login_manager.blueprint_login_views[blueprint.name]) = login_view

        if (
            current_app.login_manager.login_view is not None
            and None not in current_app.login_manager.blueprint_login_views
        ):
            (
                current_app.login_manager.blueprint_login_views[None]
            ) = current_app.login_manager.login_view

        current_app.login_manager.login_view = None
    else:
        current_app.login_manager.login_view = login_view


def _get_user():
    if has_request_context():
        if "_login_user" not in g:
            current_app.login_manager._load_user()

        return g._login_user

    return None


def _cookie_digest(payload, key=None):
    key = _secret_key(key)

    return hmac.new(key, payload.encode("utf-8"), sha512).hexdigest()


def _create_identifier():
    h = sha512()
    h.update(f"{request.remote_addr}|{request.user_agent.string}".encode())
    return h.hexdigest()


def _user_context_processor():
    return dict(current_user=_get_user())


def _secret_key(key=None):
    if key is None:
        key = current_app.config["SECRET_KEY"]

    if isinstance(key, str):  # pragma: no cover
        key = key.encode("latin1")  # ensure bytes

    return key
