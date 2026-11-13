#coding: utf-8
import unittest
import json
import os
import subprocess
import sys
import tempfile
import time
import importlib.util

import bottle
from bottle import tob, touni
from .tools import api


TOOLS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROTATION_SCRIPT = os.path.join(TOOLS_DIR, 'tools', 'cookie_key_rotation.py')


def load_rotation_module():
    spec = importlib.util.spec_from_file_location(
        'cookie_key_rotation', ROTATION_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class KeyringTestBase(unittest.TestCase):
    def setUp(self):
        bottle.app.push()
        bottle.response.bind()

    def tearDown(self):
        bottle.app.pop()

    def get_pairs(self):
        for k, v in bottle.response.headerlist:
            if k == 'Set-Cookie':
                key, value = v.split(';')[0].split('=', 1)
                yield key.lower().strip(), value.strip()

    def set_pairs(self, pairs):
        header = ','.join(['%s=%s' % (k, v) for k, v in pairs])
        bottle.request.bind({'HTTP_COOKIE': header})

    def make_keyring(self, keys=None, **kwargs):
        keys = keys or {'1': 'first-secret', '2': 'second-secret'}
        options = dict(current_generation='2',
                       allowed_generations=set(keys),
                       purpose='session', max_age=3600)
        options.update(kwargs)
        return bottle.CookieKeyring(keys, **options)


class TestSignedCookies(unittest.TestCase):
    def setUp(self):
        self.data = touni('υηι¢σ∂є')
        self.secret = tob('secret')
        bottle.app.push()
        bottle.response.bind()

    def tear_down(self):
        bottle.app.pop()

    def get_pairs(self):
        for k, v in bottle.response.headerlist:
            if k == 'Set-Cookie':
                key, value = v.split(';')[0].split('=', 1)
                yield key.lower().strip(), value.strip()

    def set_pairs(self, pairs):
        header = ','.join(['%s=%s' % (k, v) for k, v in pairs])
        bottle.request.bind({'HTTP_COOKIE': header})

    def testValid(self):
        bottle.response.set_cookie('key', self.data, secret=self.secret)
        pairs = self.get_pairs()
        self.set_pairs(pairs)
        result = bottle.request.get_cookie('key', secret=self.secret)
        self.assertEqual(self.data, result)

    def testWrongKey(self):
        bottle.response.set_cookie('key', self.data, secret=self.secret)
        pairs = self.get_pairs()
        self.set_pairs([(k + 'xxx', v) for (k, v) in pairs])
        result = bottle.request.get_cookie('key', secret=self.secret)
        self.assertEqual(None, result)


class TestSignedCookiesWithPickle(TestSignedCookies):
    def setUp(self):
        super(TestSignedCookiesWithPickle, self).setUp()
        self.data = dict(a=5, b=touni('υηι¢σ∂є'), c=[1,2,3,4,tob('bytestring')])

    @api("0.9", "0.13")
    def testValid(self):
        super(TestSignedCookiesWithPickle, self).testValid()

    @api("0.9", "0.13")
    def testWrongKey(self):
        super(TestSignedCookiesWithPickle, self).testWrongKey()


class TestKeyringRoundtrip(KeyringTestBase):
    def test_legal_string_roundtrip(self):
        keyring = self.make_keyring()
        data = touni('υηι¢σ∂є-值')
        bottle.response.set_cookie('account', data, keyring=keyring)
        pairs = list(self.get_pairs())
        self.set_pairs(pairs)
        result = bottle.request.get_cookie('account', keyring=keyring)
        self.assertEqual(data, result)

    def test_token_carries_generation_iat_and_purpose(self):
        keyring = self.make_keyring()
        token = keyring.sign('account', 'alice', now=1000)
        import base64 as b64
        raw = b64.b64decode(token[2:token.rfind('.')]).decode()
        version, gen, purpose, name, iat, max_age, payload = raw.split('|')
        self.assertEqual(version, '1')
        self.assertEqual(gen, '2')
        self.assertEqual(purpose, 'session')
        self.assertEqual(name, 'account')
        self.assertEqual(iat, '1000')
        self.assertEqual(max_age, '3600')

    def test_no_pickle_for_keyring_values(self):
        keyring = self.make_keyring()
        with self.assertRaises(TypeError):
            bottle.response.set_cookie('account', {'user': 'alice'},
                                       keyring=keyring)
        with self.assertRaises(TypeError):
            keyring.sign('account', ['not', 'a', 'string'])

    def test_secret_and_keyring_are_mutually_exclusive(self):
        keyring = self.make_keyring()
        with self.assertRaises(ValueError):
            bottle.response.set_cookie('account', 'x', secret='s',
                                       keyring=keyring)
        bottle.response.set_cookie('account', 'x', keyring=keyring)
        self.set_pairs(list(self.get_pairs()))
        with self.assertRaises(ValueError):
            bottle.request.get_cookie('account', secret='s', keyring=keyring)

    def test_missing_cookie_returns_default(self):
        keyring = self.make_keyring()
        self.assertEqual('fallback',
                         bottle.request.get_cookie('nope', default='fallback',
                                                   keyring=keyring))

    def test_oversized_name_and_value_rejected(self):
        keyring = self.make_keyring()
        with self.assertRaises(ValueError):
            bottle.response.set_cookie('x' * 3900, 'v', keyring=keyring)
        with self.assertRaises(ValueError):
            bottle.response.set_cookie('x', 'v' * 3900, keyring=keyring)


class TestLegacySingleSecretCompatibility(KeyringTestBase):
    def test_legacy_format_still_verified(self):
        data = touni('υηι¢σ∂є')
        bottle.response.set_cookie('key', data, secret=LEGACY_SECRET)
        pairs = list(self.get_pairs())
        token = dict(pairs)['key'].strip('"')
        # Legacy format marker must be unchanged.
        self.assertTrue(token.startswith('!') and not token.startswith('!!'))
        self.set_pairs(pairs)
        self.assertEqual(
            data, bottle.request.get_cookie('key', secret=LEGACY_SECRET))

    def test_legacy_token_rejected_by_keyring(self):
        keyring = self.make_keyring()
        bottle.response.set_cookie('key', 'legacy', secret=LEGACY_SECRET)
        self.set_pairs(list(self.get_pairs()))
        self.assertIsNone(bottle.request.get_cookie('key', keyring=keyring))
        with self.assertRaises(bottle.CookieFormatError):
            bottle.request.get_cookie('key', keyring=keyring, strict=True)

LEGACY_SECRET = tob('legacy-secret')


class TestKeyringMigration(KeyringTestBase):
    def test_two_generation_rotation_window(self):
        keyring = self.make_keyring()
        old = bottle.CookieKeyring(
            {'1': 'first-secret'}, current_generation='1',
            purpose='session', max_age=3600)
        old_token = old.sign('account', 'old-session')
        new_token = keyring.sign('account', 'new-session')

        self.set_pairs([('account', old_token)])
        self.assertEqual('old-session',
                         bottle.request.get_cookie('account', keyring=keyring))
        self.set_pairs([('account', new_token)])
        self.assertEqual('new-session',
                         bottle.request.get_cookie('account', keyring=keyring))

        # New tokens are always minted with the current generation.
        self.assertEqual('2', _token_generation(new_token))

    def test_rotation_helper_opens_and_closes_window(self):
        keyring = self.make_keyring()
        old_token = bottle.CookieKeyring(
            {'1': 'first-secret'}, current_generation='1',
            purpose='session', max_age=3600).sign('account', 'old-session')

        previous = keyring.rotate('3', 'third-secret')
        self.assertEqual('2', previous)
        self.assertEqual('3', keyring.current_generation)
        self.set_pairs([('account', old_token)])
        self.assertEqual('old-session',
                         bottle.request.get_cookie('account', keyring=keyring))

        retired = keyring.finish_rotation()
        self.assertEqual({'1', '2'}, retired)
        self.assertEqual(('1', '2', '3'), keyring.generations)
        self.assertEqual({'3'}, keyring.allowed_generations)
        self.assertEqual({'1', '2'}, keyring.revoked_generations)
        with self.assertRaises(bottle.RevokedKeyGenerationError):
            bottle.request.get_cookie('account', keyring=keyring, strict=True)
        # Non-strict mode keeps the historical API contract.
        self.assertIsNone(bottle.request.get_cookie('account', keyring=keyring))

    def test_revoked_generation_rejected(self):
        keyring = self.make_keyring()
        token = bottle.CookieKeyring(
            {'1': 'first-secret'}, current_generation='1',
            purpose='session', max_age=3600).sign('account', 'alice')
        keyring.revoke('1')
        self.set_pairs([('account', token)])
        with self.assertRaises(bottle.RevokedKeyGenerationError) as ctx:
            bottle.request.get_cookie('account', keyring=keyring, strict=True)
        self.assertIn('1', str(ctx.exception))


class TestKeyringRejections(KeyringTestBase):
    def _bind(self, token, name='account'):
        self.set_pairs([(name, token)])

    def test_unknown_generation_rejected(self):
        keyring = self.make_keyring()
        foreign = bottle.CookieKeyring(
            {'9': 'unknown-secret'}, current_generation='9',
            purpose='session', max_age=3600)
        token = foreign.sign('account', 'alice')
        self._bind(token)
        with self.assertRaises(bottle.UnknownKeyGenerationError):
            bottle.request.get_cookie('account', keyring=keyring, strict=True)

    def test_cross_purpose_rejected(self):
        keyring = self.make_keyring(purpose='session')
        other = self.make_keyring(purpose='csrf')
        token = other.sign('account', 'alice')
        self._bind(token)
        with self.assertRaises(bottle.CookiePurposeError):
            bottle.request.get_cookie('account', keyring=keyring, strict=True)

    def test_cross_cookie_name_rejected(self):
        keyring = self.make_keyring()
        token = keyring.sign('other-cookie', 'alice')
        self._bind(token)
        with self.assertRaises(bottle.CookiePurposeError):
            bottle.request.get_cookie('account', keyring=keyring, strict=True)

    def test_expired_token_rejected(self):
        keyring = self.make_keyring(max_age=10, clock_skew=0)
        token = keyring.sign('account', 'alice', now=time.time() - 11)
        self._bind(token)
        with self.assertRaises(bottle.CookieExpiredError):
            bottle.request.get_cookie('account', keyring=keyring,
                                      strict=True)

    def test_expiry_accepts_clock_skew(self):
        keyring = self.make_keyring(max_age=10, clock_skew=5)
        token = keyring.sign('account', 'alice', now=time.time() - 13)
        self._bind(token)
        self.assertEqual('alice',
                         bottle.request.get_cookie('account', keyring=keyring))

    def test_replay_stops_after_validity_window(self):
        keyring = self.make_keyring(max_age=5, clock_skew=0)
        token = keyring.sign('account', 'alice', now=time.time())
        self._bind(token)
        self.assertEqual('alice',
                         bottle.request.get_cookie('account', keyring=keyring))
        stale = keyring.sign('account', 'alice', now=time.time() - 6)
        self._bind(stale)
        with self.assertRaises(bottle.CookieExpiredError):
            bottle.request.get_cookie('account', keyring=keyring, strict=True)

    def test_future_token_rejected_but_skew_tolerated(self):
        now = time.time()
        strict = self.make_keyring(clock_skew=0)
        future_token = strict.sign('account', 'alice', now=now + 60)
        self._bind(future_token)
        with self.assertRaises(bottle.CookieFutureError):
            bottle.request.get_cookie('account', keyring=strict, strict=True)

        tolerant = self.make_keyring(clock_skew=120)
        self.assertEqual(
            'alice',
            bottle.request.get_cookie('account', keyring=tolerant))

    def test_tampered_signature_rejected(self):
        keyring = self.make_keyring()
        token = keyring.sign('account', 'alice')
        head, sig = token.rsplit('.', 1)
        flipped = sig[:-1] + ('A' if sig[-1] != 'A' else 'B')
        self._bind(head + '.' + flipped)
        with self.assertRaises(bottle.CookieSignatureError):
            bottle.request.get_cookie('account', keyring=keyring, strict=True)

    def test_tampered_payload_rejected(self):
        import base64 as b64
        keyring = self.make_keyring()
        token = keyring.sign('account', 'alice')
        prefix = bottle.COOKIE_KEYRING_PREFIX
        raw = b64.b64decode(token[len(prefix):token.rfind('.')]).decode()
        fields = raw.split('|')
        fields[1] = '1'  # rewrite generation without the matching key
        rewritten = b64.b64encode('|'.join(fields).encode()).decode()
        self._bind(prefix + rewritten + token[token.rfind('.'):])
        with self.assertRaises(bottle.CookieSignatureError):
            bottle.request.get_cookie('account', keyring=keyring, strict=True)

    def test_garbage_token_rejected(self):
        keyring = self.make_keyring()
        for garbage in ('!!not-base64.sig', '!!|', 'plain-value'):
            self._bind(garbage)
            with self.assertRaises(bottle.CookieVerificationError):
                bottle.request.get_cookie(
                    'account', keyring=keyring, strict=True)
        # A missing/empty cookie is an ordinary default, not an error.
        self._bind('')
        self.assertIsNone(bottle.request.get_cookie('account', keyring=keyring))


class TestRotationScript(KeyringTestBase):
    def setUp(self):
        super(TestRotationScript, self).setUp()
        self.rotation = load_rotation_module()
        self.tmpdir = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmpdir, 'keyring.json')
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_full_rotation_lifecycle_invalidates_unsigned_old_session(self):
        self.rotation.init_state(self.state_path, generation='1',
                                 secret='first-secret', purpose='session',
                                 max_age=3600)
        keyring_v1 = self.rotation.load_keyring(self.state_path)
        token = keyring_v1.sign('account', 'session-before-rotation')

        self.rotation.rotate_state(self.state_path, new_generation='2',
                                   secret='second-secret')
        keyring_window = self.rotation.load_keyring(self.state_path)
        self.assertEqual('session-before-rotation',
                         keyring_window.verify('account', token))
        self.assertEqual('2', keyring_window.current_generation)

        self.rotation.finish_state(self.state_path)
        keyring_final = self.rotation.load_keyring(self.state_path)
        with self.assertRaises(bottle.RevokedKeyGenerationError) as ctx:
            keyring_final.verify('account', token)
        self.assertIn('1', str(ctx.exception))

        # Re-signed sessions on the current generation still work.
        fresh = keyring_final.sign('account', 'session-after-rotation')
        self.assertEqual('session-after-rotation',
                         keyring_final.verify('account', fresh))

    def test_cli_status_and_finish(self):
        self.rotation.init_state(self.state_path, secret='s1')
        env = dict(os.environ)
        run = lambda *args: subprocess.run(
            [sys.executable, ROTATION_SCRIPT, self.state_path] + list(args),
            capture_output=True, text=True, env=env, check=True)
        run('rotate', '--generation', '2', '--secret', 's2')
        run('finish')
        with open(self.state_path, encoding='utf-8') as handle:
            state = json.load(handle)
        self.assertEqual(state['current_generation'], '2')
        self.assertEqual(state['allowed_generations'], ['2'])
        self.assertIn('1', state['revoked_generations'])
        output = run('status').stdout
        self.assertIn('"current_generation": "2"', output)

    def test_rotate_can_reject_previous_generation_immediately(self):
        self.rotation.init_state(self.state_path, generation='1', secret='s1')
        old = self.rotation.load_keyring(self.state_path)
        token = old.sign('account', 'old')

        self.rotation.rotate_state(self.state_path, new_generation='2',
                                   secret='s2', accept_previous=False)
        keyring = self.rotation.load_keyring(self.state_path)
        with self.assertRaises(bottle.RevokedKeyGenerationError):
            keyring.verify('account', token)
        self.assertEqual({'2'}, keyring.allowed_generations)

    def test_state_file_round_trip_through_cli(self):
        env = dict(os.environ)
        subprocess.run([sys.executable, ROTATION_SCRIPT, self.state_path,
                        'init', '--generation', '1', '--secret', 's1',
                        '--purpose', 'session', '--max-age', '60'],
                       capture_output=True, text=True, env=env, check=True)
        keyring = self.rotation.load_keyring(self.state_path)
        self.assertEqual('session', keyring.purpose)
        self.assertEqual(60, keyring.max_age)
        self.assertEqual('1', keyring.current_generation)


def _token_generation(token):
    import base64 as b64
    prefix = bottle.COOKIE_KEYRING_PREFIX
    raw = b64.b64decode(token[len(prefix):token.rfind('.')]).decode()
    return raw.split('|')[1]
