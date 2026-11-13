"""
oauthlib.oauth2.rfc6749.client_assertion
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pluggable lifecycle for ``private_key_jwt`` client assertions (RFC 7523).

The JWTClientAssertionValidator performs the full client assertion lifetime
check:

1. parse the (untrusted) JOSE header and locate the registered public key;
2. verify the signature chain;
3. bind ``iss``/``sub`` to the authenticated client;
4. require an exact ``aud`` match against the token endpoint;
5. validate the ``exp``/``nbf``/``iat`` time windows against one clock;
6. atomically reserve the one-time ``jti`` so replays and concurrent
   exchanges are rejected, and roll the reservation back on any failure.

Two deployment shapes are supported:

* Host-managed (production): the host RequestValidator only verifies
  signatures (or resolves keys) and supplies the clock and an atomic, durable
  jti store through the ``*_client_assertion_*`` hooks.
* In-memory (tests / single process): InMemoryJtiStore and a key registry
  are wired directly into the validator without any host storage.

Error responses never contain the assertion text, the claims or public key
material; only generic, distinct error codes are returned.
"""
import logging
import threading
import time

from . import errors
from .request_validator import RequestValidator, call_validator_hook

log = logging.getLogger(__name__)

# RFC 7523 only allows asymmetric keys for client assertions: a shared secret
# would not constitute a private-key proof of possession.
DEFAULT_ALLOWED_ALGS = (
    'RS256', 'RS384', 'RS512',
    'PS256', 'PS384', 'PS512',
    'ES256', 'ES384', 'ES512',
    'EdDSA',
)

# RFC 7523 section 3 requires assertions to be short lived. Ten minutes is the
# conventional upper bound and also caps the replay window for valid jtis.
DEFAULT_MAX_ASSERTION_LIFETIME = 600
DEFAULT_CLOCK_SKEW_LEEWAY = 0

_JTI_STATUS_ERRORS = {
    RequestValidator.JTI_REPLAYED: errors.ReplayedClientAssertionError,
    RequestValidator.JTI_CONCURRENT: errors.ConcurrentClientAssertionError,
    RequestValidator.JTI_CLOCK_ROLLBACK:
        errors.ClockRollbackClientAssertionError,
}


class InMemoryJtiStore:
    """Thread-safe, in-process one-time jti store.

    Reservations and consumptions are performed while holding a single lock,
    which makes the check-and-insert atomic within one process. It is intended
    for tests and single-process deployments; multi-process deployments must
    provide a durable atomic store through the RequestValidator hooks.
    """

    def __init__(self, clock=None, clock_rollback_tolerance=0):
        self._lock = threading.Lock()
        # jti key -> expiry timestamp; separate maps keep "in flight" and
        # "consumed" states distinguishable for concurrent requests.
        self._reserved = {}
        self._consumed = {}
        self._clock = clock or time.time
        self._last_now = None
        self._clock_rollback_tolerance = clock_rollback_tolerance

    def _now(self):
        now = self._clock()
        if (self._last_now is not None
                and now < self._last_now - self._clock_rollback_tolerance):
            log.warning('Client assertion clock rollback detected: %r -> %r.',
                        self._last_now, now)
            raise errors.ClockRollbackClientAssertionError()
        self._last_now = now
        return now

    def _prune(self, now):
        for mapping in (self._reserved, self._consumed):
            expired = [key for key, expires_at in mapping.items()
                       if expires_at <= now]
            for key in expired:
                del mapping[key]

    def reserve(self, client_id, jti, expires_at):
        """Atomically reserve ``(client_id, jti)`` and return a status."""
        with self._lock:
            now = self._now()
            self._prune(now)
            key = (client_id, jti)
            if key in self._consumed:
                return RequestValidator.JTI_REPLAYED
            if key in self._reserved:
                return RequestValidator.JTI_CONCURRENT
            self._reserved[key] = expires_at
            return RequestValidator.JTI_ACCEPTED

    def commit(self, client_id, jti):
        with self._lock:
            key = (client_id, jti)
            expires_at = self._reserved.pop(key, None)
            if expires_at is not None:
                self._consumed[key] = expires_at

    def release(self, client_id, jti):
        with self._lock:
            self._reserved.pop((client_id, jti), None)

    def is_consumed(self, client_id, jti):
        with self._lock:
            return (client_id, jti) in self._consumed

    def is_reserved(self, client_id, jti):
        with self._lock:
            return (client_id, jti) in self._reserved


class JWTClientAssertionValidator:
    """RFC 7523 client assertion lifecycle bound to a RequestValidator."""

    def __init__(self, request_validator, expected_audience=None,
                 signing_keys=None, jti_store=None, clock=None,
                 allowed_algs=None, leeway=DEFAULT_CLOCK_SKEW_LEEWAY,
                 max_assertion_lifetime=DEFAULT_MAX_ASSERTION_LIFETIME):
        """
        :param request_validator: Host RequestValidator providing the hooks.
        :param expected_audience: Exact token endpoint URI string, or a
            callable taking the request and returning it. Defaults to the
            request URI.
        :param signing_keys: Optional ``{kid: public_key}`` registry for the
            built-in in-memory deployment.
        :param jti_store: Optional InMemoryJtiStore for the built-in in-memory
            deployment. When omitted, jti and clock are delegated to the
            request validator hooks (host-managed deployment).
        :param clock: Optional zero-argument callable returning the current
            UNIX timestamp used for time-window and rollback checks.
        """
        self.request_validator = request_validator
        self.expected_audience = expected_audience
        self.signing_keys = dict(signing_keys or {})
        self.jti_store = jti_store
        self._clock = clock
        self.allowed_algs = tuple(allowed_algs or DEFAULT_ALLOWED_ALGS)
        self.leeway = leeway
        self.max_assertion_lifetime = max_assertion_lifetime

    def now(self, request):
        if self._clock is not None:
            return self._clock()
        return call_validator_hook(
            self.request_validator,
            'get_client_assertion_time',
            {'request': request},
        )

    def validate(self, assertion, request):
        """Validate an assertion and atomically reserve its jti.

        On success the request is bound to the authenticated client and the
        tuple ``(client_id, jti)`` is returned. Every failure raises a
        distinct OAuth2Error and leaves no consumed-jti side effect.
        """
        import jwt  # noqa: PLC0415

        headers = self._parse_header(assertion, jwt)
        client_id = self._resolve_client_id(assertion, headers, request, jwt)
        now = self.now(request)

        signing_key = self._resolve_signing_key(client_id, headers, request)
        claims = self._verify_signature(
            client_id, assertion, headers, request, signing_key, jwt)

        self._validate_client_binding(client_id, claims)
        self._validate_audience(claims, request)
        self._validate_time_windows(claims, now)
        jti = self._validate_jti(claims)

        expires_at = self._expires_at(claims, now)
        self._reserve_jti(client_id, jti, expires_at, request)

        if not call_validator_hook(
                self.request_validator,
                'authenticate_client_assertion',
                {'client_id': client_id, 'request': request,
                 'claims': claims}):
            self.release_reservation(client_id, jti, request)
            raise errors.InvalidClientAssertionError(request=request)

        request.client_assertion_jti = jti
        request.client_assertion_client_id = client_id
        request.client_id = client_id
        return client_id, jti

    def release_reservation(self, client_id, jti, request):
        """Roll back a reservation; never raises and never marks consumed."""
        if self.jti_store is not None:
            self.jti_store.release(client_id, jti)
            return
        try:
            call_validator_hook(
                self.request_validator,
                'release_client_assertion_jti',
                {'client_id': client_id, 'jti': jti, 'request': request},
            )
        except Exception:
            log.exception('Failed to release client assertion jti reservation.')

    def commit_reservation(self, client_id, jti, request):
        """Permanently consume a reservation after token issuance succeeds."""
        if self.jti_store is not None:
            self.jti_store.commit(client_id, jti)
            return
        call_validator_hook(
            self.request_validator,
            'commit_client_assertion_jti',
            {'client_id': client_id, 'jti': jti, 'request': request},
        )

    def _parse_header(self, assertion, jwt_module):
        try:
            headers = jwt_module.get_unverified_header(assertion)
        except jwt_module.PyJWTError:
            log.debug('Malformed client assertion JOSE header.')
            raise errors.InvalidClientAssertionError()
        alg = headers.get('alg')
        if not alg or alg not in self.allowed_algs:
            log.debug('Disallowed client assertion alg %r.', alg)
            raise errors.InvalidClientAssertionError()
        return headers

    def _resolve_client_id(self, assertion, headers, request, jwt_module):
        client_id = getattr(request, 'client_id', None)
        if client_id:
            return client_id
        try:
            unverified = jwt_module.decode(assertion, options={
                'verify_signature': False,
                'verify_aud': False,
                'verify_exp': False,
            })
        except jwt_module.PyJWTError:
            raise errors.InvalidClientAssertionError()
        client_id = unverified.get('iss')
        if not isinstance(client_id, str) or not client_id:
            raise errors.MissingClientIdError()
        request.client_id = client_id
        return client_id

    def _resolve_signing_key(self, client_id, headers, request):
        kid = headers.get('kid')
        if kid in self.signing_keys:
            return self.signing_keys[kid]
        try:
            return call_validator_hook(
                self.request_validator,
                'get_client_assertion_signing_key',
                {'client_id': client_id, 'kid': kid, 'headers': headers,
                 'request': request},
            )
        except NotImplementedError:
            raise errors.UnknownClientAssertionKeyError()
        except KeyError:
            raise errors.UnknownClientAssertionKeyError()

    def _verify_signature(self, client_id, assertion, headers, request,
                          signing_key, jwt_module):
        try:
            return call_validator_hook(
                self.request_validator,
                'verify_client_assertion_signature',
                {'client_id': client_id, 'assertion': assertion,
                 'headers': headers, 'request': request,
                 'signing_key': signing_key},
            )
        except errors.OAuth2Error:
            raise
        except jwt_module.PyJWTError:
            log.debug('Client assertion signature verification failed.')
            raise errors.InvalidClientAssertionError()

    def _validate_client_binding(self, client_id, claims):
        iss = claims.get('iss')
        sub = claims.get('sub')
        if not isinstance(iss, str) or not isinstance(sub, str):
            raise errors.InvalidClientAssertionError()
        if iss != client_id or sub != client_id:
            log.debug('Client assertion iss/sub not bound to client %s.',
                      client_id)
            raise errors.InvalidClientAssertionError()

    def _expected_audience(self, request):
        if callable(self.expected_audience):
            return self.expected_audience(request)
        if isinstance(self.expected_audience, str):
            return self.expected_audience
        return request.uri

    def _validate_audience(self, claims, request):
        audience = claims.get('aud')
        if isinstance(audience, str):
            audiences = [audience]
        elif isinstance(audience, list) and audience:
            audiences = audience
        else:
            raise errors.InvalidClientAssertionAudienceError()
        expected = self._expected_audience(request)
        # Exact, whole-string match only: a matching host with a different
        # port or path must never be accepted.
        if not any(isinstance(item, str) and item == expected
                   for item in audiences):
            raise errors.InvalidClientAssertionAudienceError()

    def _validate_time_windows(self, claims, now):
        exp = claims.get('exp')
        if not isinstance(exp, (int, float)) or isinstance(exp, bool):
            raise errors.InvalidClientAssertionError()
        if now >= exp - self.leeway:
            raise errors.ExpiredClientAssertionError()

        nbf = claims.get('nbf')
        if (nbf is not None and (
                not isinstance(nbf, (int, float)) or isinstance(nbf, bool)
                or now < nbf - self.leeway)):
            raise errors.InvalidClientAssertionError()

        iat = claims.get('iat')
        if iat is not None:
            if not isinstance(iat, (int, float)) or isinstance(iat, bool):
                raise errors.InvalidClientAssertionError()
            if iat - self.leeway > now:
                raise errors.InvalidClientAssertionError()
            if now - iat > self.max_assertion_lifetime + self.leeway:
                raise errors.InvalidClientAssertionError()

    def _validate_jti(self, claims):
        jti = claims.get('jti')
        if not isinstance(jti, str) or not jti:
            log.debug('Client assertion is missing a usable jti.')
            raise errors.InvalidClientAssertionError()
        return jti

    def _expires_at(self, claims, now):
        exp = claims.get('exp')
        if isinstance(exp, (int, float)) and not isinstance(exp, bool):
            return exp
        return now + self.max_assertion_lifetime

    def _reserve_jti(self, client_id, jti, expires_at, request):
        if self.jti_store is not None:
            status = self.jti_store.reserve(client_id, jti, expires_at)
        else:
            status = call_validator_hook(
                self.request_validator,
                'reserve_client_assertion_jti',
                {'client_id': client_id, 'jti': jti,
                 'expires_at': expires_at, 'request': request},
            )
        error_cls = _JTI_STATUS_ERRORS.get(status)
        if error_cls is not None:
            raise error_cls()
        if status != RequestValidator.JTI_ACCEPTED:
            log.error('Unexpected jti reservation status %r.', status)
            raise errors.ServerError()
