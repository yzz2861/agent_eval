"""
Tests for ``onetimepass`` module
"""
import math
import time
from datetime import datetime
from unittest import TestCase
from unittest.mock import patch

from freezegun import freeze_time

from onetimepass import (
    EXPIRED, FUTURE, INVALID, MAX_COUNTER, MAX_INTERVAL_LENGTH, MAX_TOKEN_LENGTH,
    MAX_TRIALS, MAX_WINDOW, REPLAY, VALID, ValidationReason, _is_possible_token,
    get_hotp, get_totp, valid_hotp, valid_totp, validate_hotp, validate_totp,
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


class CounterBoundaryTestCase(TestCase):
    """
    HOTP counters are unsigned 64-bit values and must never wrap.
    """
    secret = b'MFRGGZDFMZTWQ2LK'

    def test_hotp_counter_boundaries(self):
        self.assertGreaterEqual(get_hotp(self.secret, 0), 0)
        self.assertGreaterEqual(get_hotp(self.secret, MAX_COUNTER), 0)

        for invalid in (-1, MAX_COUNTER + 1, -MAX_COUNTER):
            with self.assertRaises(ValueError):
                get_hotp(self.secret, invalid)

    def test_hotp_counter_requires_an_integer(self):
        for invalid in (1.0, '1', None, True):
            with self.assertRaises(TypeError):
                get_hotp(self.secret, invalid)

    def test_valid_hotp_does_not_wrap_at_max_counter(self):
        token_for_zero = get_hotp(self.secret, 0)
        self.assertFalse(
            valid_hotp(token_for_zero, self.secret, last=MAX_COUNTER, trials=5),
        )

        token_for_max = get_hotp(self.secret, MAX_COUNTER)
        self.assertEqual(
            valid_hotp(token_for_max, self.secret, last=MAX_COUNTER - 1,
                       trials=5),
            MAX_COUNTER,
        )
        self.assertFalse(
            valid_hotp(token_for_max, self.secret, last=MAX_COUNTER, trials=5),
        )

    def test_valid_hotp_bounds(self):
        token = get_hotp(self.secret, 5)
        for kwargs in (
                {'last': -1},
                {'last': MAX_COUNTER + 1},
                {'last': 1, 'trials': -1},
                {'last': 1, 'trials': MAX_TRIALS + 1},
                {'last': 1, 'trials': 1.5},
                {'last': 1, 'token_length': 0},
                {'last': 1, 'token_length': MAX_TOKEN_LENGTH + 1},
        ):
            with self.assertRaises((TypeError, ValueError)):
                valid_hotp(token, self.secret, **kwargs)

    def test_totp_time_step_boundaries(self):
        self.assertEqual(
            get_totp(self.secret, interval_length=1, clock=MAX_COUNTER),
            get_hotp(self.secret, MAX_COUNTER),
        )
        self.assertEqual(
            get_totp(
                self.secret,
                clock=MAX_COUNTER * 30 + 29,
            ),
            get_hotp(self.secret, MAX_COUNTER),
        )

        with self.assertRaises(ValueError):
            get_totp(self.secret, clock=MAX_COUNTER * 30 + 30)
        with self.assertRaises(ValueError):
            get_totp(self.secret, interval_length=1,
                     clock=MAX_COUNTER + 1)

    def test_totp_parameter_bounds(self):
        for interval_length in (0, -1, MAX_INTERVAL_LENGTH + 1):
            with self.assertRaises(ValueError):
                get_totp(self.secret, interval_length=interval_length)
        with self.assertRaises(TypeError):
            get_totp(self.secret, interval_length=1.5)

        for clock in (-1, -0.1, math.inf, -math.inf, math.nan):
            with self.assertRaises(ValueError):
                get_totp(self.secret, clock=clock)
        for clock in ('0', True):
            with self.assertRaises(TypeError):
                get_totp(self.secret, clock=clock)
        # ``None`` keeps its documented meaning: use the current time.
        self.assertIsInstance(get_totp(self.secret, clock=None), int)

    def test_totp_window_bounds(self):
        token = get_totp(self.secret, clock=300)
        for window in (-1, MAX_WINDOW + 1):
            with self.assertRaises(ValueError):
                valid_totp(token, self.secret, clock=300, window=window)
        with self.assertRaises(TypeError):
            valid_totp(token, self.secret, clock=300, window=1.5)
        with self.assertRaises(TypeError):
            valid_totp(token, self.secret, clock=300, window=True)


class TotpWindowBoundaryTestCase(TestCase):
    """
    Both ends of the acceptance window are covered, including clock zero and
    the maximum representable time step.
    """
    secret = b'MFRGGZDFMZTWQ2LK'

    def test_window_accepts_both_edges(self):
        current = 600
        for offset in (-2, -1, 0, 1, 2):
            token = get_totp(self.secret, clock=current + offset * 30)
            self.assertTrue(
                valid_totp(token, self.secret, clock=current, window=2),
            )

        token = get_totp(self.secret, clock=current + 90)
        self.assertFalse(
            valid_totp(token, self.secret, clock=current, window=2),
        )
        self.assertEqual(
            validate_totp(token, self.secret, clock=current, window=2).reason,
            FUTURE,
        )

        token = get_totp(self.secret, clock=current - 90)
        self.assertFalse(
            valid_totp(token, self.secret, clock=current, window=2),
        )
        self.assertEqual(
            validate_totp(token, self.secret, clock=current, window=2).reason,
            EXPIRED,
        )

    def test_window_edges_at_clock_zero(self):
        token = get_totp(self.secret, clock=0)
        self.assertTrue(valid_totp(token, self.secret, clock=0, window=2))
        self.assertTrue(valid_totp(token, self.secret, clock=60, window=2))

        future = get_totp(self.secret, clock=90)
        self.assertFalse(valid_totp(future, self.secret, clock=0, window=2))
        self.assertEqual(
            validate_totp(future, self.secret, clock=0, window=2).reason,
            FUTURE,
        )

    def test_window_edges_at_max_counter(self):
        token = get_totp(self.secret, interval_length=1, clock=MAX_COUNTER)
        self.assertTrue(
            valid_totp(token, self.secret, interval_length=1,
                       clock=MAX_COUNTER, window=2),
        )

        older = get_totp(
            self.secret, interval_length=1, clock=MAX_COUNTER - 2,
        )
        self.assertTrue(
            valid_totp(older, self.secret, interval_length=1,
                       clock=MAX_COUNTER, window=2),
        )

        expired = get_totp(
            self.secret, interval_length=1, clock=MAX_COUNTER - 3,
        )
        self.assertFalse(
            valid_totp(expired, self.secret, interval_length=1,
                       clock=MAX_COUNTER, window=2),
        )
        self.assertEqual(
            validate_totp(
                expired, self.secret, interval_length=1,
                clock=MAX_COUNTER, window=2,
            ).reason,
            EXPIRED,
        )

    def test_window_validation_is_not_short_circuited(self):
        token = get_totp(self.secret, clock=540)
        with patch('onetimepass.get_hotp', wraps=get_hotp) as mocked:
            self.assertTrue(
                valid_totp(token, self.secret, clock=600, window=2),
            )
        self.assertEqual(mocked.call_count, 5)

    def test_hotp_validation_is_not_short_circuited(self):
        token = get_hotp(self.secret, 2)
        with patch('onetimepass.get_hotp', wraps=get_hotp) as mocked:
            self.assertEqual(
                valid_hotp(token, self.secret, last=1, trials=5),
                2,
            )
        self.assertEqual(mocked.call_count, 5)


class TotpClockRollbackTestCase(TestCase):
    """
    Clock rollback must not turn an already-used token into a fresh one.
    """
    secret = b'MFRGGZDFMZTWQ2LK'

    def test_rollback_is_replay_when_last_counter_is_known(self):
        token = get_totp(self.secret, clock=1000)
        last_counter = 1000 // 30
        result = validate_totp(
            token, self.secret, clock=940, window=1, last=last_counter,
        )
        self.assertFalse(result)
        self.assertEqual(result.reason, REPLAY)
        self.assertEqual(result.counter, last_counter)

    def test_rollback_is_future_without_replay_state(self):
        token = get_totp(self.secret, clock=1000)
        result = validate_totp(token, self.secret, clock=940, window=1)
        self.assertFalse(result)
        self.assertEqual(result.reason, FUTURE)

    def test_legal_clock_skew_is_still_accepted(self):
        token = get_totp(self.secret, clock=1000)
        self.assertTrue(
            valid_totp(token, self.secret, clock=970, window=1),
        )

    def test_hotp_replay_and_future_reasons(self):
        replay = validate_hotp(
            get_hotp(self.secret, 4), self.secret, last=4, trials=5,
        )
        self.assertEqual(replay.reason, REPLAY)

        future = validate_hotp(
            get_hotp(self.secret, 10), self.secret, last=4, trials=5,
        )
        self.assertEqual(future.reason, FUTURE)

        invalid = validate_hotp(
            get_hotp(self.secret, 30), self.secret, last=4, trials=5,
        )
        self.assertEqual(invalid.reason, INVALID)


class TokenLengthTestCase(TestCase):
    """
    Both six- and eight-digit tokens remain supported.
    """
    secret = b'MFRGGZDFMZTWQ2LK'

    def test_six_digit_tokens(self):
        token = get_hotp(self.secret, 123)
        self.assertEqual(len(str(token).zfill(6)), 6)
        self.assertEqual(valid_hotp(token, self.secret), 123)

    def test_eight_digit_tokens(self):
        token = get_hotp(self.secret, 5, token_length=8)
        token_str = get_hotp(
            self.secret, 5, as_string=True, token_length=8,
        )
        self.assertEqual(len(token_str), 8)
        self.assertEqual(
            valid_hotp(token_str, self.secret, last=4, trials=2,
                       token_length=8),
            5,
        )
        self.assertEqual(
            valid_hotp(token, self.secret, last=4, trials=2,
                       token_length=8),
            5,
        )

        totp = get_totp(self.secret, clock=300, token_length=8)
        self.assertTrue(
            valid_totp(totp, self.secret, clock=300, token_length=8),
        )

    def test_wrong_token_length_does_not_validate(self):
        token = get_hotp(self.secret, 5, token_length=8)
        self.assertFalse(
            valid_hotp(token, self.secret, last=4, trials=2, token_length=6),
        )


class ValidationResultTestCase(TestCase):
    """
    The detailed validation API exposes reasons without changing the legacy
    return types of ``valid_hotp`` and ``valid_totp``.
    """
    secret = b'MFRGGZDFMZTWQ2LK'

    def test_reason_constants(self):
        self.assertEqual(VALID, ValidationReason.VALID)
        self.assertEqual(EXPIRED, ValidationReason.EXPIRED)
        self.assertEqual(FUTURE, ValidationReason.FUTURE)
        self.assertEqual(REPLAY, ValidationReason.REPLAY)
        self.assertEqual(INVALID, ValidationReason.INVALID)

    def test_legacy_return_types_are_preserved(self):
        self.assertEqual(valid_hotp(get_hotp(self.secret, 5), self.secret,
                                    last=4, trials=2), 5)
        self.assertIs(valid_hotp(get_hotp(self.secret, 5), self.secret,
                                 last=5, trials=2), False)
        self.assertIs(valid_totp(get_totp(self.secret, clock=300),
                                 self.secret, clock=300), True)
        self.assertIs(valid_totp(get_totp(self.secret, clock=270),
                                 self.secret, clock=300), False)

    def test_optional_reason_result(self):
        result = valid_hotp(
            get_hotp(self.secret, 5), self.secret, last=4, trials=2,
            return_reason=True,
        )
        self.assertTrue(result)
        self.assertEqual(result.reason, VALID)
        self.assertEqual(result.counter, 5)
        self.assertEqual(result, VALID)
        self.assertEqual(result, 5)

        result = valid_totp(
            get_totp(self.secret, clock=270), self.secret, clock=300,
            return_reason=True,
        )
        self.assertFalse(result)
        self.assertEqual(result.reason, EXPIRED)
        self.assertEqual(result, EXPIRED)


class SecretErrorTestCase(TestCase):
    """
    Secret decoding errors must be generic and must not echo the secret.
    """
    secret = b'SUPER-SECRET-MATERIAL-!@#'

    def test_generation_errors_do_not_leak_secret(self):
        with self.assertRaises(TypeError) as caught:
            get_hotp(self.secret, 1)
        self.assertEqual(str(caught.exception), 'Incorrect secret')
        self.assertNotIn('SUPER-SECRET', repr(caught.exception))
        if caught.exception.__context__ is not None:
            self.assertNotIn(
                'SUPER-SECRET', repr(caught.exception.__context__),
            )

    def test_validation_errors_do_not_leak_secret(self):
        with self.assertRaises(TypeError) as caught:
            valid_hotp(123456, self.secret)
        self.assertEqual(str(caught.exception), 'Incorrect secret')
        self.assertNotIn('SUPER-SECRET', repr(caught.exception))

    def test_invalid_secret_type_does_not_leak_object_repr(self):
        secret = object()
        with self.assertRaises(TypeError) as caught:
            get_hotp(secret, 1)
        self.assertEqual(str(caught.exception), 'Incorrect secret')
        self.assertNotIn(repr(secret), str(caught.exception))
