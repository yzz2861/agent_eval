# -*- coding: utf-8 -*-
import threading

import jwt

from cryptography.hazmat.primitives.asymmetric import rsa

from oauthlib.common import Request
from oauthlib.oauth2.rfc6749.client_assertion import (
    InMemoryJtiStore,
    JWTClientAssertionValidator,
)
from oauthlib.oauth2.rfc6749.errors import (
    ClockRollbackClientAssertionError,
    ConcurrentClientAssertionError,
    ExpiredClientAssertionError,
    InvalidClientAssertionAudienceError,
    ReplayedClientAssertionError,
    UnknownClientAssertionKeyError,
)
from oauthlib.oauth2 import RequestValidator
from oauthlib.oauth2.rfc6749.request_validator import call_validator_hook

from tests.unittest import TestCase


TOKEN_URI = 'https://as.example.com/token'
ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'


class RequestValidatorTest(TestCase):

    def test_method_contracts(self):
        v = RequestValidator()
        self.assertRaises(NotImplementedError, v.authenticate_client, 'r')
        self.assertRaises(NotImplementedError, v.authenticate_client_id,
                'client_id', 'r')
        self.assertRaises(NotImplementedError, v.confirm_redirect_uri,
                'client_id', 'code', 'redirect_uri', 'client', 'request')
        self.assertRaises(NotImplementedError, v.get_default_redirect_uri,
                'client_id', 'request')
        self.assertRaises(NotImplementedError, v.get_default_scopes,
                'client_id', 'request')
        self.assertRaises(NotImplementedError, v.get_original_scopes,
                'refresh_token', 'request')
        self.assertFalse(v.is_within_original_scope(
                ['scope'], 'refresh_token', 'request'))
        self.assertRaises(NotImplementedError, v.invalidate_authorization_code,
                'client_id', 'code', 'request')
        self.assertRaises(NotImplementedError, v.save_authorization_code,
                'client_id', 'code', 'request')
        self.assertRaises(NotImplementedError, v.save_bearer_token,
                'token', 'request')
        self.assertRaises(NotImplementedError, v.validate_bearer_token,
                'token', 'scopes', 'request')
        self.assertRaises(NotImplementedError, v.validate_client_id,
                'client_id', 'request')
        self.assertRaises(NotImplementedError, v.validate_code,
                'client_id', 'code', 'client', 'request')
        self.assertRaises(NotImplementedError, v.validate_grant_type,
                'client_id', 'grant_type', 'client', 'request')
        self.assertRaises(NotImplementedError, v.validate_redirect_uri,
                'client_id', 'redirect_uri', 'request')
        self.assertRaises(NotImplementedError, v.validate_refresh_token,
                'refresh_token', 'client', 'request')
        self.assertRaises(NotImplementedError, v.validate_response_type,
                'client_id', 'response_type', 'client', 'request')
        self.assertRaises(NotImplementedError, v.validate_scopes,
                'client_id', 'scopes', 'client', 'request')
        self.assertRaises(NotImplementedError, v.validate_user,
                'username', 'password', 'client', 'request')
        self.assertTrue(v.client_authentication_required('r'))
        self.assertFalse(
            v.is_origin_allowed('client_id', 'https://foo.bar', 'r')
        )


class LegacySignatureValidator(RequestValidator):
    """Host validator using older positional hook signatures."""

    def __init__(self, public_key, now):
        self.public_key = public_key
        self._now = now
        self.reserved = {}
        self.released = []
        self.committed = []

    # Legacy signature: only (client_id, request) - extra kwargs must be
    # filtered out by the compatibility layer.
    def get_client_assertion_time(self, request):
        return self._now()

    def get_client_assertion_signing_key(self, client_id, kid, request):
        if kid != 'key-1':
            raise KeyError(kid)
        return self.public_key

    def reserve_client_assertion_jti(self, client_id, jti, request):
        key = (client_id, jti)
        if key in self.reserved or key in self.committed:
            return self.JTI_REPLAYED
        self.reserved[key] = True
        return self.JTI_ACCEPTED

    def commit_client_assertion_jti(self, client_id, jti, request):
        self.reserved.pop((client_id, jti), None)
        self.committed.append((client_id, jti))

    def release_client_assertion_jti(self, client_id, jti, request):
        self.reserved.pop((client_id, jti), None)
        self.released.append((client_id, jti))


class HostManagedAssertionTest(TestCase):
    """Deployment A: host supplies signature key, clock and jti store."""

    def setUp(self):
        self.now = 1_700_000_000
        self.private_key = rsa.generate_private_key(public_exponent=65537,
                                                    key_size=2048)
        self.validator = LegacySignatureValidator(
            self.private_key.public_key(), lambda: self.now)

    def make_request(self, **claims_overrides):
        payload = {
            'iss': 'client-1',
            'sub': 'client-1',
            'aud': TOKEN_URI,
            'iat': self.now - 10,
            'exp': self.now + 300,
            'jti': 'jti-host-1',
        }
        payload.update(claims_overrides)
        assertion = jwt.encode(payload, self.private_key,
                               algorithm='RS256', headers={'kid': 'key-1'})
        body = ('grant_type=client_credentials&client_id=client-1'
                '&client_assertion_type=' + ASSERTION_TYPE +
                '&client_assertion=' + assertion)
        return Request(TOKEN_URI, body=body)

    def test_host_managed_lifecycle_with_legacy_positional_hooks(self):
        lifecycle = JWTClientAssertionValidator(self.validator)
        request = self.make_request()
        client_id, jti = lifecycle.validate(
            request.client_assertion, request)
        self.assertEqual(client_id, 'client-1')
        self.assertEqual(jti, 'jti-host-1')
        self.assertIn(('client-1', 'jti-host-1'), self.validator.reserved)

        lifecycle.commit_reservation(client_id, jti, request)
        self.assertIn(('client-1', 'jti-host-1'), self.validator.committed)

    def test_host_managed_replay_and_rollback_failure_paths(self):
        lifecycle = JWTClientAssertionValidator(self.validator)
        request = self.make_request()
        lifecycle.validate(request.client_assertion, request)

        replay_request = self.make_request()
        with self.assertRaises(ReplayedClientAssertionError):
            lifecycle.validate(replay_request.client_assertion, replay_request)

        # A failed check before reservation leaves no consumed side effect.
        bad_aud = self.make_request(aud='https://evil.example.com/token')
        with self.assertRaises(InvalidClientAssertionAudienceError):
            lifecycle.validate(bad_aud.client_assertion, bad_aud)
        self.assertEqual(self.validator.released, [])

        expired = self.make_request(exp=self.now - 1, jti='jti-exp')
        with self.assertRaises(ExpiredClientAssertionError):
            lifecycle.validate(expired.client_assertion, expired)

        unknown = self.make_request(jti='jti-kid')
        payload = jwt.decode(unknown.client_assertion,
                             options={'verify_signature': False})
        resigned = jwt.encode(payload, self.private_key, algorithm='RS256',
                              headers={'kid': 'nope'})
        unknown.client_assertion = resigned
        with self.assertRaises(UnknownClientAssertionKeyError):
            lifecycle.validate(unknown.client_assertion, unknown)

    def test_compatibility_shim_drops_unsupported_kwargs(self):
        class VarArgs:
            def hook(self, **kwargs):
                return kwargs

        self.assertEqual(
            call_validator_hook(VarArgs(), 'hook',
                                {'a': 1, 'request': None}),
            {'a': 1, 'request': None},
        )

        class FixedArgs:
            def hook(self, request):
                return request

        self.assertIsNone(call_validator_hook(
            FixedArgs(), 'hook', {'request': None, 'jti': 'x'}))


class InMemoryJtiStoreTest(TestCase):

    def test_atomic_states_and_clock_rollback(self):
        current = [1000]
        store = InMemoryJtiStore(clock=lambda: current[0])
        self.assertEqual(store.reserve('c', 'j', 1300),
                         RequestValidator.JTI_ACCEPTED)
        self.assertTrue(store.is_reserved('c', 'j'))

        self.assertEqual(store.reserve('c', 'j', 1300),
                         RequestValidator.JTI_CONCURRENT)
        store.commit('c', 'j')
        self.assertTrue(store.is_consumed('c', 'j'))
        self.assertFalse(store.is_reserved('c', 'j'))
        self.assertEqual(store.reserve('c', 'j', 1300),
                         RequestValidator.JTI_REPLAYED)

        store.release('c', 'other')  # must be a safe no-op

        current[0] = 900
        with self.assertRaises(ClockRollbackClientAssertionError):
            store.reserve('c', 'j2', 1300)

    def test_reservation_release_allows_retry(self):
        store = InMemoryJtiStore()
        self.assertEqual(store.reserve('c', 'j', 4_000_000_000),
                         RequestValidator.JTI_ACCEPTED)
        store.release('c', 'j')
        self.assertEqual(store.reserve('c', 'j', 4_000_000_000),
                         RequestValidator.JTI_ACCEPTED)

    def test_concurrent_reservations_under_threads(self):
        store = InMemoryJtiStore()
        barrier = threading.Barrier(8)
        outcomes = []

        def reserve():
            barrier.wait()
            outcomes.append(store.reserve('c', 'shared', 4_000_000_000))

        threads = [threading.Thread(target=reserve) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(outcomes.count(RequestValidator.JTI_ACCEPTED), 1)
        self.assertEqual(outcomes.count(RequestValidator.JTI_CONCURRENT), 7)


class RequestValidatorDefaultsTest(TestCase):

    def test_jti_status_constants_are_distinct(self):
        values = {
            RequestValidator.JTI_ACCEPTED,
            RequestValidator.JTI_REPLAYED,
            RequestValidator.JTI_CONCURRENT,
            RequestValidator.JTI_CLOCK_ROLLBACK,
        }
        self.assertEqual(len(values), 4)

    def test_consume_default_composes_reserve_and_commit(self):
        class ComposingValidator(RequestValidator):
            def __init__(self):
                self.events = []

            def reserve_client_assertion_jti(self, client_id, jti,
                                             expires_at, request):
                self.events.append(('reserve', client_id, jti))
                return self.JTI_ACCEPTED

            def commit_client_assertion_jti(self, client_id, jti, request):
                self.events.append(('commit', client_id, jti))

        validator = ComposingValidator()
        status = validator.consume_client_assertion_jti(
            'c', 'j', 1234, None)
        self.assertEqual(status, RequestValidator.JTI_ACCEPTED)
        self.assertEqual(validator.events,
                         [('reserve', 'c', 'j'), ('commit', 'c', 'j')])

    def test_failed_release_is_swallowed_by_lifecycle(self):
        class FailingRelease(LegacySignatureValidator):
            def release_client_assertion_jti(self, client_id, jti, request):
                raise RuntimeError('storage unavailable')

        validator = FailingRelease(object(), lambda: 1)
        lifecycle = JWTClientAssertionValidator(validator)
        # Must not raise: cleanup errors cannot mask the original failure.
        lifecycle.release_reservation('c', 'j', Request('http://x'))

    def test_default_authenticate_client_assertion_binds_client(self):
        validator = RequestValidator()
        request = Request('http://x')
        self.assertTrue(validator.authenticate_client_assertion(
            'client-9', request, claims={}))
        self.assertEqual(request.client_id, 'client-9')
        self.assertEqual(request.client.client_id, 'client-9')
