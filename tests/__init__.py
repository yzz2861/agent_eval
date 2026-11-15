"""
Tests for ``onetimepass`` module
"""
import time
from datetime import datetime
from unittest import TestCase

from freezegun import freeze_time

from onetimepass import (
    InvalidLengthError, InvalidSecretError, InvalidTokenError,
    _decode_secret, _is_possible_token, _normalize_token,
    get_hotp, get_totp, valid_hotp, valid_totp,
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


class SecretDecodingTestCase(TestCase):
    """
    Checks for unified Base32 secret decoding shared by generation and
    validation paths.
    """
    def test_mixed_case_secret_decodes_like_uppercase(self):
        """
        Base32 secrets are case-insensitive, mixed case must decode the same
        """
        expected = _decode_secret(b'MFRGGZDFMZTWQ2LK')
        self.assertEqual(_decode_secret(b'mfrggzdfmztwq2lk'), expected)
        self.assertEqual(_decode_secret(b'MfrGgZdFmZtWq2Lk'), expected)
        self.assertEqual(get_hotp('mfrggzdfmztwq2lk', 1), 765705)
        self.assertEqual(get_hotp('MfrGgZdFmZtWq2Lk', 1), 765705)

    def test_whitespace_is_ignored(self):
        """
        Spaces, tabs and newlines in the secret must not change the result
        """
        expected = _decode_secret(b'MFRGGZDFMZTWQ2LK')
        self.assertEqual(_decode_secret(b'MFRG GZDF MZTW Q2LK'), expected)
        self.assertEqual(_decode_secret(b'MFRG\tGZDF\nMZTW\r\nQ2LK'), expected)
        self.assertEqual(get_hotp('MFRG GZDF\nMZTWQ2LK', 1), 765705)

    def test_explicit_correct_padding_is_accepted(self):
        """
        Explicitly declared, correct padding must be accepted
        """
        self.assertEqual(_decode_secret(b'MY======'), _decode_secret(b'MY'))
        self.assertEqual(
            _decode_secret(b'MFRGGZDFMZTWQ2LK'),
            _decode_secret(b'MFRGGZDFMZTWQ2LK'),
        )
        self.assertEqual(
            get_hotp(b'MY======', 1),
            get_hotp(b'MY', 1),
        )

    def test_missing_padding_is_derived(self):
        """
        Missing padding is derived from the length, like at import time
        """
        self.assertEqual(_decode_secret(b'MY'), _decode_secret(b'MY======'))
        self.assertEqual(_decode_secret('mfrggzdfmztwq2lk'),
                         _decode_secret('MFRGGZDFMZTWQ2LK'))

    def test_incorrect_padding_is_rejected(self):
        """
        Declared padding that does not match the body length is a length error
        """
        with self.assertRaises(InvalidLengthError):
            _decode_secret(b'MY=')
        with self.assertRaises(InvalidLengthError):
            _decode_secret(b'MY=====')
        with self.assertRaises(InvalidLengthError):
            _decode_secret(b'MFRGGZDFMZTWQ2LK=')

    def test_illegal_length_is_rejected(self):
        """
        Lengths that cannot be Base32 bodies are reported as length errors
        """
        for secret in (b'M', b'MFR', b'MFRGGZ', b''):
            with self.assertRaises(InvalidLengthError):
                _decode_secret(secret)

    def test_characters_outside_alphabet_are_rejected(self):
        """
        Characters outside of the Base32 alphabet are secret errors
        """
        for secret in (b'MFRGGZDFMZTWQ2L!', b'MFRGGZDF1ZTWQ2LK',
                       b'MFRGGZDF=TWQ2LK'):
            with self.assertRaises(InvalidSecretError):
                _decode_secret(secret)

    def test_control_characters_are_rejected(self):
        """
        Control characters (other than stripped whitespace) are rejected
        """
        for secret in (b'MFRGGZDF\x01MZTWQ2LK', b'MFRGGZDF\x7fMZTWQ2LK',
                       b'\x00MFRGGZDFMZTWQ2LK'):
            with self.assertRaises(InvalidSecretError):
                _decode_secret(secret)

    def test_non_ascii_secret_is_rejected(self):
        """
        Non-ASCII characters in the secret are secret errors
        """
        with self.assertRaises(InvalidSecretError):
            _decode_secret('MFRGGZDFMZTÖQ2LK')

    def test_invalid_secret_type_is_rejected(self):
        """
        Secrets that are neither bytes nor strings are secret errors
        """
        with self.assertRaises(InvalidSecretError):
            _decode_secret(123456)

    def test_generation_and_validation_share_decoding(self):
        """
        A secret imported with spaces, lowercase and missing padding must
        validate tokens generated for the canonical form
        """
        canonical = b'MFRGGZDFMZTWQ2LK'
        imported = 'mfrggzdf mztwq2lk'
        with freeze_time(datetime.now()):
            token = get_totp(canonical)
            self.assertTrue(valid_totp(token, imported))
            self.assertTrue(valid_totp(token, canonical))


class TokenNormalizationTestCase(TestCase):
    """
    Checks for token normalization and the distinct error types used to
    report token and length problems.
    """
    def test_non_numeric_token_is_token_error(self):
        """
        Non-numeric tokens are reported as token errors
        """
        with self.assertRaises(InvalidTokenError):
            _normalize_token('abcdef')
        with self.assertRaises(InvalidTokenError):
            _normalize_token(b'12345a')
        with self.assertRaises(InvalidTokenError):
            _normalize_token(None)

    def test_too_long_token_is_length_error(self):
        """
        Tokens longer than allowed are reported as length errors
        """
        with self.assertRaises(InvalidLengthError):
            _normalize_token('1234567')
        with self.assertRaises(InvalidLengthError):
            _normalize_token(b'123456789', token_length=8)

    def test_token_is_zero_padded(self):
        """
        Shorter numeric tokens are zero-padded to the expected length
        """
        self.assertEqual(_normalize_token(123), b'000123')
        self.assertEqual(_normalize_token('123', token_length=8), b'00000123')

    def test_malformed_tokens_fail_validation_without_raising(self):
        """
        Malformed tokens make validation return False, not raise
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        self.assertFalse(valid_totp('abcdef', secret))
        self.assertFalse(valid_totp('1234567', secret))
        self.assertFalse(valid_hotp('abcdef', secret))


class TokenLengthCompatibilityTestCase(TestCase):
    """
    Checks that valid 6- and 8-digit tokens keep working with the existing
    get_totp()/valid_totp() behaviour.
    """
    def test_six_digit_totp_roundtrip(self):
        """
        6-digit tokens generated by get_totp validate with valid_totp
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        with freeze_time(datetime.now()):
            token = get_totp(secret, token_length=6)
            self.assertTrue(valid_totp(token, secret, token_length=6))
            self.assertFalse(valid_totp(token + 1, secret, token_length=6))

    def test_eight_digit_totp_roundtrip(self):
        """
        8-digit tokens generated by get_totp validate with valid_totp
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        with freeze_time(datetime.now()):
            token = get_totp(secret, token_length=8)
            self.assertTrue(valid_totp(token, secret, token_length=8))
            self.assertFalse(valid_totp(token + 1, secret, token_length=8))

    def test_eight_digit_hotp_roundtrip(self):
        """
        8-digit HOTP tokens validate with valid_hotp
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        token = get_hotp(secret, 123, token_length=8)
        self.assertEqual(
            valid_hotp(token, secret, token_length=8),
            123,
        )
