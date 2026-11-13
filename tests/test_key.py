"""
Some tests for the rsa/key.py file.
"""

import unittest
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

import rsa
import rsa.key
import rsa.core


class BlindingTest(unittest.TestCase):
    def test_blinding(self):
        """Test blinding and unblinding.

        This is basically the doctest of the PrivateKey.blind method, but then
        implemented as unittest to allow running on different Python versions.
        """

        pk = rsa.key.PrivateKey(3727264081, 65537, 3349121513, 65063, 57287)

        message = 12345
        encrypted = rsa.core.encrypt_int(message, pk.e, pk.n)

        blinded_1, unblind_1 = pk.blind(encrypted)  # blind before decrypting
        decrypted = rsa.core.decrypt_int(blinded_1, pk.d, pk.n)
        unblinded_1 = pk.unblind(decrypted, unblind_1)

        self.assertEqual(unblinded_1, message)

        # Re-blinding should use a different blinding factor.
        blinded_2, unblind_2 = pk.blind(encrypted)  # blind before decrypting
        self.assertNotEqual(blinded_1, blinded_2)

        # The unblinding should still work, though.
        decrypted = rsa.core.decrypt_int(blinded_2, pk.d, pk.n)
        unblinded_2 = pk.unblind(decrypted, unblind_2)
        self.assertEqual(unblinded_2, message)


class KeyGenTest(unittest.TestCase):
    def test_custom_exponent(self):
        pub, priv = rsa.key.newkeys(16, exponent=3)

        self.assertEqual(3, priv.e)
        self.assertEqual(3, pub.e)

    def test_default_exponent(self):
        pub, priv = rsa.key.newkeys(16)

        self.assertEqual(0x10001, priv.e)
        self.assertEqual(0x10001, pub.e)

    def test_exponents_coefficient_calculation(self):
        pk = rsa.key.PrivateKey(3727264081, 65537, 3349121513, 65063, 57287)

        self.assertEqual(pk.exp1, 55063)
        self.assertEqual(pk.exp2, 10095)
        self.assertEqual(pk.coef, 50797)

    def test_custom_getprime_func(self):
        # List of primes to test with, in order [p, q, p, q, ....]
        # By starting with two of the same primes, we test that this is
        # properly rejected.
        primes = [64123, 64123, 64123, 50957, 39317, 33107]

        def getprime(_):
            return primes.pop(0)

        # This exponent will cause two other primes to be generated.
        exponent = 136407

        (p, q, e, d) = rsa.key.gen_keys(
            64, accurate=False, getprime_func=getprime, exponent=exponent
        )
        self.assertEqual(39317, p)
        self.assertEqual(33107, q)

    def test_multiprime(self):
        primes = [64123, 50957, 39317, 33107]
        exponent = 2**2**4 + 1

        def getprime(_):
            return primes.pop(0)
        (p, q, e, d, rs) = rsa.key.gen_keys(
            128, accurate=False, getprime_func=getprime, exponent=exponent, nprimes=4
        )
        self.assertEqual(64123, p)
        self.assertEqual(50957, q)
        self.assertEqual(rs, [39317, 33107])


class HashTest(unittest.TestCase):
    """Test hashing of keys"""

    def test_hash_possible(self):
        pub, priv = rsa.key.newkeys(16)

        # This raises a TypeError when hashing isn't possible.
        hash(priv)
        hash(pub)


class UnifiedPrivateOperationTest(unittest.TestCase):
    def setUp(self):
        (self.pub, self.priv) = rsa.newkeys(256)
        self.encrypted = rsa.core.encrypt_int(123456789, self.pub.e, self.pub.n)

    def test_raw_crt_helper_rejects_unblinded_call(self):
        with self.assertRaises(rsa.core.UnblindedOperationError):
            rsa.core.decrypt_int_fast(
                self.encrypted,
                [self.priv.p, self.priv.q],
                [self.priv.exp1, self.priv.exp2],
                [self.priv.coef],
            )

    def test_blinded_helper_rejects_token_reuse(self):
        token = rsa.core._new_blinding_token(
            self.priv.n, self.priv.blindfac, self.priv.blindfac_inverse
        )
        first = rsa.core.decrypt_int_fast(
            self.encrypted,
            [self.priv.p, self.priv.q],
            [self.priv.exp1, self.priv.exp2],
            [self.priv.coef],
            blinding_token=token,
        )
        self.assertIsInstance(first, int)

        with self.assertRaises(rsa.core.BlindingError):
            rsa.core.decrypt_int_fast(
                self.encrypted,
                [self.priv.p, self.priv.q],
                [self.priv.exp1, self.priv.exp2],
                [self.priv.coef],
                blinding_token=token,
            )

    def test_unified_entry_blinds_before_private_operation(self):
        factors = []
        original = rsa.core.decrypt_int_fast

        def recording_helper(*args, **kwargs):
            token = kwargs.get("blinding_token") or rsa.core.current_blinding_token()
            self.assertIsNotNone(token)
            self.assertTrue(token.blinded)
            self.assertIn(token.factor, self.priv._active_blindfacs)
            factors.append(token.factor)
            return original(*args, **kwargs)

        with mock.patch.object(rsa.core, "decrypt_int_fast", recording_helper):
            self.assertEqual(123456789, self.priv.decrypt_int(self.encrypted))

        self.assertEqual(1, len(factors))
        self.assertNotIn(factors[0], self.priv._active_blindfacs)

    def test_private_helper_keeps_historical_call_signature(self):
        original = rsa.core.decrypt_int_fast
        observed = []

        def four_argument_spy(cyphertext, rs, ds, ts):
            token = rsa.core.current_blinding_token()
            self.assertIsNotNone(token)
            observed.append(token.factor)
            return original(cyphertext, rs, ds, ts)

        with mock.patch.object(rsa.core, "decrypt_int_fast", four_argument_spy):
            self.assertEqual(123456789, self.priv.decrypt_int(self.encrypted))

        self.assertEqual(1, len(observed))

    def test_consecutive_operations_use_different_factors(self):
        factors = []
        original = rsa.core.decrypt_int_fast

        def recording_helper(*args, **kwargs):
            token = kwargs.get("blinding_token") or rsa.core.current_blinding_token()
            factors.append(token.factor)
            return original(*args, **kwargs)

        with mock.patch.object(rsa.core, "decrypt_int_fast", recording_helper):
            for _ in range(5):
                self.assertEqual(123456789, self.priv.decrypt_int(self.encrypted))

        self.assertEqual(5, len(set(factors)))

    def test_constant_random_source_still_advances_factors(self):
        constant_source = lambda maxvalue: self.priv.n // 2
        priv = rsa.key.PrivateKey(
            self.priv.n,
            self.priv.e,
            self.priv.d,
            self.priv.p,
            self.priv.q,
            randfunc=constant_source,
        )
        factors = []
        original = rsa.core.decrypt_int_fast

        def recording_helper(*args, **kwargs):
            token = kwargs.get("blinding_token") or rsa.core.current_blinding_token()
            factors.append(token.factor)
            return original(*args, **kwargs)

        with mock.patch.object(rsa.core, "decrypt_int_fast", recording_helper):
            for _ in range(4):
                self.assertEqual(123456789, priv.decrypt_int(self.encrypted))

        self.assertEqual(4, len(set(factors)))

    def test_results_match_unblinded_baseline(self):
        expected = pow(self.encrypted, self.priv.d, self.priv.n)
        self.assertEqual(expected, self.priv.decrypt_int(self.encrypted))

    def test_random_source_failure_is_explicit(self):
        def failing_source(maxvalue):
            raise OSError("random source unavailable")

        priv = rsa.key.PrivateKey(
            self.priv.n,
            self.priv.e,
            self.priv.d,
            self.priv.p,
            self.priv.q,
            randfunc=failing_source,
        )

        with self.assertRaises(rsa.key.BlindingError) as raised:
            priv.decrypt_int(self.encrypted)

        self.assertIsInstance(raised.exception.__cause__, OSError)

    def test_concurrent_operations_do_not_share_unfinished_factors(self):
        thread_count = 4
        barrier = threading.Barrier(thread_count)
        factors = []
        factors_lock = threading.Lock()
        original = rsa.core.decrypt_int_fast

        def recording_helper(*args, **kwargs):
            token = kwargs.get("blinding_token") or rsa.core.current_blinding_token()
            with factors_lock:
                factors.append(token.factor)
            self.assertTrue(token.blinded)
            barrier.wait(timeout=10)
            return original(*args, **kwargs)

        with mock.patch.object(rsa.core, "decrypt_int_fast", recording_helper):
            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                results = list(
                    executor.map(
                        lambda _: self.priv.decrypt_int(self.encrypted),
                        range(thread_count),
                    )
                )

        self.assertEqual([123456789] * thread_count, results)
        self.assertEqual(thread_count, len(set(factors)))
        self.assertFalse(self.priv._active_blindfacs)
