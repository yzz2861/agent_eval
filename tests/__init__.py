"""
Tests for ``onetimepass`` module
"""
import base64
import time
from datetime import datetime
from unittest import TestCase

from freezegun import freeze_time

from onetimepass import (
    MAX_COUNTER,
    SUPPORTED_ALGORITHMS,
    _is_possible_token,
    get_hotp,
    get_totp,
    valid_hotp,
    valid_totp,
)


class PreliminaryChecksTestCase(TestCase):
    """
    Test for assessing potential validity of tokens, aimed at limiting data
    processing to validating only non-malformed tokens.
    """
    def test_is_possible_token_helper(self):
        """
        Checks ``_is_possible_token`` helper method for valid behaviour
        """
        # Properly formatted tokens:
        # integer
        self.assertTrue(_is_possible_token(123456))
        # bytes
        self.assertTrue(_is_possible_token(b'123456'))
        # unicode
        self.assertTrue(_is_possible_token('123456'))

        # token with invalid characters
        self.assertFalse(_is_possible_token(b'abcdef'))
        # token being too long
        self.assertFalse(_is_possible_token(b'12345678'))

        # similar cases as above, but for unicode
        self.assertFalse(_is_possible_token('abcdef'))
        self.assertFalse(_is_possible_token('12345678'))

    def test_variable_length_in_possible_tokens(self):
        """
        Check if length is respected when verifying tokens
        """
        # When default is length of 6:
        self.assertFalse(_is_possible_token(1234567))
        # Longer version:
        self.assertTrue(_is_possible_token(1234567, token_length=7))
        # Shorter version, when longer is allowed:
        self.assertTrue(_is_possible_token(123456, token_length=7))
        # Invalid token with correct length:
        self.assertFalse(_is_possible_token('abcdefg', token_length=7))


class HotpGenerationTestCase(TestCase):
    """
    Test generating HOTP tokens.
    """
    def test_hotp_generation_from_bytes_secret(self):
        """
        Test simple generation of HOTP token
        """
        # Simple generation from bytes
        secret = b'MFRGGZDFMZTWQ2LK'
        self.assertEqual(get_hotp(secret, 1), 765705)

    def test_hotp_generation_from_unicode_secret(self):
        """
        Check if HOTP is properly generated for unicode secrets
        """
        # Simple generation from unicode
        secret = 'MFRGGZDFMZTWQ2LK'
        self.assertEqual(get_hotp(secret, 1), 765705)

    def test_returning_hotp_as_string(self):
        """
        Check if properly returns string when asked
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        self.assertEqual(get_hotp(secret, 1, as_string=True), b'765705')

    def test_generation_for_different_intervals(self):
        """
        Check if the HOTP changes with different intervals properly
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        self.assertEqual(get_hotp(secret, intervals_no=1), 765705)
        self.assertEqual(get_hotp(secret, intervals_no=2), 816065)

        self.assertEqual(
            get_hotp(secret, intervals_no=2, as_string=True),
            b'816065',
        )

    def test_ignoring_spaces_in_secret(self):
        """
        Check if spaces are skipped during generation of the token
        """
        def chunks(original, size):
            """
            Split original string into chunks sized as requested in ``size``
            parameter. Returns iterator yielding single chunks.
            Similar to: http://stackoverflow.com/a/312464/548696
            :param original: original string (almost any iterable really)
            :type original: str or unicode
            :param size: requested size of chunks
            :type size: int
            """
            for i in range(0, len(original), size):
                yield original[i:i+size]

        # Simple generation without spaces:
        secret = 'MFRGGZDFMZTWQ2LK'
        # Simple generation with spaces:
        secret_with_spaces = ' '.join(chunks(secret, 3))
        # Check if was properly sliced:
        self.assertEqual(5, secret_with_spaces.count(' '))

        # Both spaceless secret and secret with spaces should give the same
        self.assertEqual(
            get_hotp(secret, 1),
            get_hotp(secret_with_spaces, 1),
        )


class HotpValidityTestCase(TestCase):
    """
    Check valid_hotp() function
    """
    def test_checking_hotp_validity_without_range(self):
        """
        Check if validating HOTP without giving any interval works properly
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        self.assertTrue(valid_hotp(get_hotp(secret, 123), secret))

    def test_checking_hotp_validity_for_unicode_secret(self):
        """
        Validity check should also work if secret passed to valid_hotp is
        unicode.
        """
        secret = 'MFRGGZDFMZTWQ2LK'
        self.assertTrue(valid_hotp(get_hotp(secret, 123), secret))

    def test_validating_correct_hotp_after_exhaustion(self):
        """
        Validating token created for old interval number should fail
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        # Act as if the given token was created for previous interval
        self.assertFalse(valid_hotp(get_hotp(secret, 123), secret, last=123))

    def test_validating_correct_totp_as_hotp(self):
        """
        Check if valid TOTP will work as HOTP - should not work, unless for
        very big interval number (matching Unix epoch timestamp)
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        self.assertFalse(valid_hotp(get_totp(secret), secret))

    def test_retrieving_proper_interval_from_validator(self):
        """
        Check, if returns valid interval when checking the valid HOTP
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        totp = 713385
        result = valid_hotp(totp, secret, last=1, trials=5)
        # Should be 4, as HOTP is valid for 4th interval
        self.assertEqual(result, 4)
        # Re-generate HOTP for this specific interval and check again
        self.assertEqual(get_hotp(secret, intervals_no=4), totp)

    def test_hotp_for_range_preceding_match(self):
        """
        Check behaviour of validation of values that precede the proper
        interval value
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        self.assertFalse(valid_hotp(713385, secret, last=1, trials=2))


class TotpGenerationTestCase(TestCase):
    """
    TOTP generation test
    """
    def test_generating_current_totp_and_validating(self):
        """
        Check if TOTP generated for current time is the same as manually
        created HOTP for proper interval
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        with freeze_time(datetime.now()):
            hotp = get_hotp(secret=secret, intervals_no=int(time.time())//30,)
            totp = get_totp(secret=secret)
            self.assertEqual(hotp, totp)

    def test_generating_current_totp_as_string(self):
        """
        Check if the TOTP also works seamlessly when generated as string
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        with freeze_time(datetime.now()):
            hotp = get_hotp(
                secret=secret,
                intervals_no=int(time.time())//30,
                as_string=True,
            )
            totp = get_totp(secret=secret, as_string=True)
            self.assertEqual(hotp, totp)

    def test_generating_totp_at_specific_clock(self):
        """
        check if the totp can be generated for a specific clock
        which is basically the same as hotp
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        with freeze_time(datetime.now()):
            hotp = get_hotp(secret=secret, intervals_no=int(time.time())//30,)
            totp = get_totp(secret=secret, clock=None)
            self.assertEqual(hotp, totp)

            # hotp intervals minus 1
            hotp = get_hotp(
                secret=secret,
                intervals_no=int(time.time())//30-1,
            )
            # totp 30 seconds in the past
            totp = get_totp(secret=secret, clock=(int(time.time())-30))
            self.assertEqual(hotp, totp)

    def test_validating_totp_with_a_window(self):
        """
        validate if a totp token falls within a certain window
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        with freeze_time(datetime.now()):
            totp = get_totp(secret=secret, clock=(int(time.time()-30)))
            self.assertFalse(valid_totp(totp, secret))
            self.assertTrue(valid_totp(totp, secret, window=1))

            totp = get_totp(secret=secret, clock=(int(time.time()+30)))
            self.assertFalse(valid_totp(totp, secret))
            self.assertTrue(valid_totp(totp, secret, window=1))

            totp = get_totp(secret=secret, clock=(int(time.time()-60)))
            self.assertFalse(valid_totp(totp, secret))
            self.assertFalse(valid_totp(totp, secret, window=1))
            self.assertTrue(valid_totp(totp, secret, window=2))


class TotpValidityTestCase(TestCase):
    """
    TOTP token validation checks
    """
    def test_validating_totp_for_same_secret(self):
        """
        Check if validating TOTP generated for the same secret works
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        with freeze_time(datetime.now()):
            self.assertTrue(valid_totp(get_totp(secret), secret))

    def test_validating_invalid_totp_for_same_secret(self):
        """
        Test case when the same secret is used, but the token differs
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        with freeze_time(datetime.now()):
            self.assertFalse(valid_totp(get_totp(secret)+1, secret))

    def test_validating_correct_hotp_as_totp(self):
        """
        Check if valid TOTP will work as HOTP - should not work, unless for
        very big interval number (matching Unix epoch timestamp)
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        with freeze_time(datetime.now()):
            self.assertFalse(valid_totp(get_hotp(secret, 1), secret))

SECRET = b"MFRGGZDFMZTWQ2LK"


class AlgorithmSupportTestCase(TestCase):
    """HOTP/TOTP generation and validation for all supported algorithms."""

    def test_supported_algorithms_constant(self):
        self.assertEqual(SUPPORTED_ALGORITHMS, ('SHA1', 'SHA256', 'SHA512'))

    def test_hotp_for_each_algorithm_returns_distinct_integer_tokens(self):
        tokens = {
            algo: get_hotp(SECRET, 1, algorithm=algo)
            for algo in SUPPORTED_ALGORITHMS
        }
        for token in tokens.values():
            self.assertIsInstance(token, int)
            self.assertLessEqual(len(str(token)), 6)
            self.assertLess(token, 10 ** 6)
        self.assertEqual(len(set(tokens.values())), 3)

    def test_totp_for_each_algorithm_returns_integer_tokens(self):
        clock = 1700000000
        tokens = {
            algo: get_totp(SECRET, clock=clock, algorithm=algo)
            for algo in SUPPORTED_ALGORITHMS
        }
        for token in tokens.values():
            self.assertIsInstance(token, int)
        self.assertEqual(len(set(tokens.values())), 3)

    def test_algorithm_name_is_case_insensitive_and_hyphen_optional(self):
        expected = get_hotp(SECRET, 1, algorithm='SHA256')
        for name in ('sha256', 'Sha256', 'SHA-256', ' sha256 '):
            self.assertEqual(get_hotp(SECRET, 1, algorithm=name), expected)

    def test_default_algorithm_remains_sha1(self):
        default_token = get_hotp(SECRET, 7)
        sha1_token = get_hotp(SECRET, 7, algorithm='SHA1')
        self.assertEqual(default_token, sha1_token)
        self.assertEqual(
            get_totp(SECRET, clock=1700000000),
            get_totp(SECRET, clock=1700000000, algorithm='SHA1'),
        )

    def test_validators_accept_the_algorithm_parameter(self):
        token = get_hotp(SECRET, 9, algorithm='SHA512')
        self.assertEqual(
            valid_hotp(token, SECRET, last=8, trials=2, algorithm='SHA512'),
            9,
        )
        totp_token = get_totp(SECRET, clock=1700000000, algorithm='SHA256')
        self.assertTrue(
            valid_totp(totp_token, SECRET, clock=1700000000,
                       algorithm='SHA256')
        )

    def test_legacy_digest_method_still_overrides_algorithm(self):
        import hashlib
        token = get_hotp(
            SECRET, 1, digest_method=hashlib.sha256, algorithm='SHA1',
        )
        self.assertEqual(token, get_hotp(SECRET, 1, algorithm='SHA256'))


class AlgorithmValidationTestCase(TestCase):
    """Error handling for unsupported algorithms and bad parameters."""

    def test_unsupported_algorithm_raises_value_error_with_name(self):
        for bad_name in ('md5', 'sha-3', 'nonsense', ''):
            with self.assertRaises(ValueError) as ctx:
                get_hotp(SECRET, 1, algorithm=bad_name)
            message = str(ctx.exception)
            self.assertIn('Unsupported algorithm', message)
            for supported in SUPPORTED_ALGORITHMS:
                self.assertIn(supported, message)

    def test_unsupported_algorithm_reported_by_totp_and_validators(self):
        with self.assertRaises(ValueError):
            get_totp(SECRET, algorithm='md5')
        with self.assertRaises(ValueError):
            valid_hotp(123456, SECRET, algorithm='md5')
        with self.assertRaises(ValueError):
            valid_totp(123456, SECRET, algorithm='md5')

    def test_non_string_algorithm_raises_type_error(self):
        for bad_value in (123, None, b'SHA1', object()):
            with self.assertRaises(TypeError):
                get_hotp(SECRET, 1, algorithm=bad_value)

    def test_counter_type_validation(self):
        for bad_counter in (1.5, True, False, '1', None):
            with self.assertRaises(TypeError):
                get_hotp(SECRET, bad_counter)

    def test_counter_range_validation(self):
        with self.assertRaises(ValueError):
            get_hotp(SECRET, -1)
        with self.assertRaises(ValueError):
            get_hotp(SECRET, MAX_COUNTER + 1)

    def test_counter_boundaries_are_accepted(self):
        self.assertIsInstance(get_hotp(SECRET, 0), int)
        self.assertIsInstance(get_hotp(SECRET, MAX_COUNTER), int)

    def test_empty_secret_is_rejected(self):
        for empty_secret in (b'', '', b'        '):
            with self.assertRaises(ValueError):
                get_hotp(empty_secret, 1)

    def test_non_positive_interval_length_is_rejected(self):
        with self.assertRaises(ValueError):
            get_totp(SECRET, interval_length=0)
        with self.assertRaises(ValueError):
            get_totp(SECRET, interval_length=-30)
        with self.assertRaises(TypeError):
            get_totp(SECRET, interval_length=30.0)


class CrossAlgorithmIsolationTestCase(TestCase):
    """Tokens, time steps and validation state must not be shared."""

    def test_hotp_token_does_not_validate_under_another_algorithm(self):
        token = get_hotp(SECRET, 5, algorithm='SHA256')
        self.assertFalse(
            valid_hotp(token, SECRET, last=4, trials=2, algorithm='SHA1')
        )
        self.assertFalse(
            valid_hotp(token, SECRET, last=4, trials=2, algorithm='SHA512')
        )
        self.assertEqual(
            valid_hotp(token, SECRET, last=4, trials=2, algorithm='SHA256'),
            5,
        )

    def test_totp_token_does_not_validate_under_another_algorithm(self):
        clock = 1700000000
        for algorithm in SUPPORTED_ALGORITHMS:
            token = get_totp(SECRET, clock=clock, algorithm=algorithm)
            for other in SUPPORTED_ALGORITHMS:
                result = valid_totp(
                    token, SECRET, clock=clock, algorithm=other,
                )
                self.assertIs(result, algorithm == other)

    def test_default_validator_keeps_using_sha1(self):
        clock = 1700000000
        sha1_token = get_totp(SECRET, clock=clock, algorithm='SHA1')
        sha256_token = get_totp(SECRET, clock=clock, algorithm='SHA256')
        self.assertTrue(valid_totp(sha1_token, SECRET, clock=clock))
        self.assertFalse(valid_totp(sha256_token, SECRET, clock=clock))

    def test_time_steps_are_not_shared_between_algorithms(self):
        clock = 1700000000
        for interval_length in (30, 60):
            for algorithm in SUPPORTED_ALGORITHMS:
                expected_counter = clock // interval_length
                expected = get_hotp(
                    SECRET, expected_counter, algorithm=algorithm,
                )
                self.assertEqual(
                    get_totp(
                        SECRET,
                        clock=clock,
                        interval_length=interval_length,
                        algorithm=algorithm,
                    ),
                    expected,
                )


class RfcHotpVectorsTestCase(TestCase):
    """RFC 4226 Appendix D HOTP test vectors (6-digit, HMAC-SHA1)."""

    SECRET_B32 = base64.b32encode(b'12345678901234567890')
    EXPECTED = (755224, 287082, 359152, 969429, 338314, 254676)

    def test_rfc_4226_hotp_vectors(self):
        for counter, expected in enumerate(self.EXPECTED):
            token = get_hotp(self.SECRET_B32, counter, algorithm='SHA1')
            self.assertEqual(token, expected)
            self.assertIsInstance(token, int)

    def test_rfc_4226_vectors_match_default_behavior(self):
        for counter, expected in enumerate(self.EXPECTED):
            self.assertEqual(get_hotp(self.SECRET_B32, counter), expected)


class RfcTotpVectorsTestCase(TestCase):
    """RFC 6238 Appendix B TOTP test vectors (8-digit, 30s time step)."""

    RAW_KEYS = {
        'SHA1': b'12345678901234567890',
        'SHA256': b'12345678901234567890123456789012',
        'SHA512': (
            b'1234567890123456789012345678901234567890123456789012345678901234'
        ),
    }
    TIMES = (59, 1111111109, 1111111111, 1234567890, 20000000000)
    EXPECTED = {
        'SHA1': (94287082, 7081804, 14050471, 89005924, 65353130),
        'SHA256': (46119246, 68084774, 67062674, 91819424, 77737706),
        'SHA512': (90693936, 25091201, 99943326, 93441116, 47863826),
    }

    def test_rfc_6238_totp_vectors_for_each_algorithm(self):
        for algorithm in SUPPORTED_ALGORITHMS:
            secret = base64.b32encode(self.RAW_KEYS[algorithm])
            for clock, expected in zip(self.TIMES, self.EXPECTED[algorithm]):
                token = get_totp(
                    secret,
                    clock=clock,
                    token_length=8,
                    algorithm=algorithm,
                )
                self.assertEqual(
                    token, expected, msg='%s at %s' % (algorithm, clock),
                )
                self.assertIsInstance(token, int)

    def test_rfc_6238_vectors_validate_with_window_zero(self):
        for algorithm in SUPPORTED_ALGORITHMS:
            secret = base64.b32encode(self.RAW_KEYS[algorithm])
            for clock, expected in zip(self.TIMES, self.EXPECTED[algorithm]):
                self.assertTrue(
                    valid_totp(
                        expected,
                        secret,
                        clock=clock,
                        token_length=8,
                        algorithm=algorithm,
                    )
                )
