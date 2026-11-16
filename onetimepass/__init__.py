"""
onetimepass module is designed to work for one-time passwords - HMAC-based and
time-based. It is compatible with Google Authenticator application and
applications based on it.

@version: 2.0.0
@author: Tomasz Jaskowski
@contact: http://github.com/tadeck
@license: MIT

>>> secret = b'MFRGGZDFMZTWQ2LK'
>>> get_hotp(secret, 1) == 765705
True
>>> get_hotp(secret, 1, as_string=True) == b'765705'
True
>>> valid_hotp(get_hotp(secret, 123), secret)
123
>>> valid_hotp(get_hotp(secret, 123), secret, last=123)
False
>>> valid_totp(get_totp(secret), secret)
True
>>> valid_totp(get_totp(secret)+1, secret)
False
>>> valid_hotp(get_totp(secret), secret)
False
>>> valid_totp(get_hotp(secret, 1), secret)
False
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import math
import struct
import time
from dataclasses import dataclass
from typing import Any, Callable

__author__ = 'Tomasz Jaskowski <tadeck@gmail.com>'
__date__ = '21 June 2026'
__version_info__ = (2, 0, 0)
__version__ = '%s.%s.%s' % __version_info__
__license__ = 'MIT'

# RFC 4226 defines the moving factor as an unsigned 64-bit integer.  Keeping
# that bound explicit prevents ``struct.pack`` from silently accepting values
# that would otherwise need to be wrapped or truncated.
COUNTER_BITS = 64
MAX_COUNTER = (1 << COUNTER_BITS) - 1

# Time-step counts use the same 64-bit space as HOTP counters.  The remaining
# limits protect validation from unbounded work requested by an attacker.
MAX_INTERVAL_LENGTH = MAX_COUNTER
MAX_WINDOW = 1000
MAX_TRIALS = 1_000_000
MAX_TOKEN_LENGTH = 8


class ValidationReason:
    """Values returned in :attr:`OTPValidationResult.reason`."""

    VALID = 'valid'
    EXPIRED = 'expired'
    FUTURE = 'future'
    REPLAY = 'replay'
    INVALID = 'invalid'


VALID = ValidationReason.VALID
EXPIRED = ValidationReason.EXPIRED
FUTURE = ValidationReason.FUTURE
REPLAY = ValidationReason.REPLAY
INVALID = ValidationReason.INVALID


@dataclass(frozen=True, eq=False)
class OTPValidationResult:
    """Result of validating a HOTP or TOTP token.

    ``counter`` is the counter matching the supplied token, if one was found.
    ``expected_counter`` is the counter the validator considered current (TOTP)
    or the next counter after ``last`` (HOTP).

    The object is truthy only when the token is valid, compares equal to its
    ``reason`` string or to a matching counter, and can be used directly with
    :func:`bool`.
    """

    valid: bool
    reason: str
    counter: int | None = None
    expected_counter: int | None = None

    def __bool__(self) -> bool:
        return self.valid

    def __eq__(self, other: object) -> bool:
        if isinstance(other, OTPValidationResult):
            return (
                self.valid,
                self.reason,
                self.counter,
                self.expected_counter,
            ) == (
                other.valid,
                other.reason,
                other.counter,
                other.expected_counter,
            )
        if isinstance(other, bool):
            return self.valid is other
        if isinstance(other, str):
            return self.reason == other
        if isinstance(other, int):
            return self.valid and self.counter == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.valid, self.reason, self.counter, self.expected_counter))

    @property
    def status(self) -> str:
        """Alias for :attr:`reason`."""
        return self.reason

    @property
    def interval_no(self) -> int | None:
        """Alias for :attr:`counter`."""
        return self.counter


def _require_int(name: str, value: object, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError('%s must be an integer' % name)
    if value < minimum or value > maximum:
        raise ValueError('%s must be between %d and %d' % (name, minimum, maximum))
    return value


def _validate_counter(value: object, name: str = 'intervals_no') -> int:
    return _require_int(name, value, 0, MAX_COUNTER)


def _validate_token_length(token_length: object) -> int:
    return _require_int('token_length', token_length, 1, MAX_TOKEN_LENGTH)


def _validate_interval_length(interval_length: object) -> int:
    return _require_int(
        'interval_length', interval_length, 1, MAX_INTERVAL_LENGTH,
    )


def _validate_window(window: object) -> int:
    return _require_int('window', window, 0, MAX_WINDOW)


def _validate_trials(trials: object) -> int:
    return _require_int('trials', trials, 0, MAX_TRIALS)


def _validate_last(last: object) -> int:
    return _require_int('last', last, 0, MAX_COUNTER)


def _clock_to_counter(clock: object, interval_length: int) -> int:
    if isinstance(clock, bool) or not isinstance(clock, (int, float)):
        raise TypeError('clock must be a number')
    if isinstance(clock, float):
        if not math.isfinite(clock):
            raise ValueError('clock must be finite')
        clock_value = clock
    else:
        # Keep integer arithmetic exact at the 2**64 boundary; converting a
        # large int to float would round MAX_COUNTER up to 2**64.
        clock_value = clock
    if clock_value < 0:
        raise ValueError('clock must be non-negative')

    counter = int(clock_value) // interval_length
    if counter > MAX_COUNTER:
        raise ValueError('clock is out of range')
    return counter


def _decode_secret(secret: bytes | str, casefold: bool) -> bytes:
    if isinstance(secret, str):
        try:
            secret_bytes = secret.encode('utf-8')
        except UnicodeError:
            raise TypeError('Incorrect secret') from None
    elif isinstance(secret, (bytes, bytearray, memoryview)):
        try:
            secret_bytes = bytes(secret)
        except (TypeError, ValueError):
            raise TypeError('Incorrect secret') from None
    else:
        raise TypeError('Incorrect secret')

    secret_bytes = secret_bytes.replace(b' ', b'')
    try:
        return base64.b32decode(secret_bytes, casefold=casefold)
    except (TypeError, ValueError):
        # Never include the supplied value or the decoder's message: it could
        # contain fragments of a secret supplied by a caller.
        raise TypeError('Incorrect secret') from None


def _normalized_token(token: int | bytes | str, token_length: int) -> str | None:
    if not _is_possible_token(token, token_length=token_length):
        return None
    try:
        token_value = int(token)
    except (TypeError, ValueError, OverflowError):
        return None
    if token_value < 0:
        return None
    return '{:0{}d}'.format(token_value, token_length)


def _token_matches(
        candidate: int | bytes,
        token_str: str,
        token_length: int,
) -> bool:
    candidate_str = '{:0{}d}'.format(candidate, token_length)
    return hmac.compare_digest(candidate_str, token_str)


def _is_possible_token(token: int | bytes | str, token_length: int = 6) -> bool:
    """Determines if given value is acceptable as a token. Used when validating
    tokens.

    Currently allows only numeric tokens no longer than ``token_length``.

    :param token: token value to be checked
    :type token: int or str
    :param token_length: allowed length of token
    :type token_length: int
    :return: True if can be a candidate for token, False otherwise
    :rtype: bool

    >>> _is_possible_token(123456)
    True
    >>> _is_possible_token(b'123456')
    True
    >>> _is_possible_token(b'abcdef')
    False
    >>> _is_possible_token(b'12345678')
    False
    """
    if not isinstance(token, bytes):
        token = str(token).encode('utf-8')
    return token.isdigit() and len(token) <= token_length


def get_hotp(
        secret: bytes | str,
        intervals_no: int,
        as_string: bool = False,
        casefold: bool = True,
        digest_method: Callable[..., Any] = hashlib.sha1,
        token_length: int = 6,
) -> int | bytes:
    """
    Get HMAC-based one-time password on the basis of given secret and
    interval number.

    :param secret: the base32-encoded string acting as secret key
    :type secret: str or unicode
    :param intervals_no: interval number used for getting different tokens, it
        is incremented with each use
    :type intervals_no: int
    :param as_string: True if result should be padded string, False otherwise
    :type as_string: bool
    :param casefold: True (default), if should accept also lowercase alphabet
    :type casefold: bool
    :param digest_method: method of generating digest (hashlib.sha1 by default)
    :type digest_method: callable
    :param token_length: length of the token (6 by default)
    :type token_length: int
    :return: generated HOTP token
    :rtype: int or str

    >>> get_hotp(b'MFRGGZDFMZTWQ2LK', intervals_no=1)
    765705
    >>> get_hotp(b'MFRGGZDFMZTWQ2LK', intervals_no=2)
    816065
    >>> result = get_hotp(b'MFRGGZDFMZTWQ2LK', intervals_no=2, as_string=True)
    >>> result == b'816065'
    True
    >>> get_hotp(b'MFRGGZDFMZTWQ2LK', intervals_no=MAX_COUNTER) >= 0
    True
    >>> get_hotp(b'MFRGGZDFMZTWQ2LK', intervals_no=-1)
    Traceback (most recent call last):
    ...
    ValueError: intervals_no must be between 0 and 18446744073709551615
    """
    intervals_no = _validate_counter(intervals_no)
    token_length = _validate_token_length(token_length)
    key = _decode_secret(secret, casefold)
    msg = struct.pack('>Q', intervals_no)
    hmac_digest = hmac.new(key, msg, digest_method).digest()
    ob = hmac_digest[19]
    o = ob & 15
    token_base = struct.unpack('>I', hmac_digest[o:o + 4])[0] & 0x7fffffff
    token = token_base % (10 ** token_length)
    if as_string:
        # TODO: should as_string=True return unicode, not bytes?
        return '{:0{}d}'.format(token, token_length).encode('utf-8')
    else:
        return token


def get_totp(
        secret: bytes | str,
        as_string: bool = False,
        digest_method: Callable[..., Any] = hashlib.sha1,
        token_length: int = 6,
        interval_length: int = 30,
        clock: float | None = None,
) -> int | bytes:
    """Get time-based one-time password on the basis of given secret and time.

    :param secret: the base32-encoded string acting as secret key
    :type secret: str
    :param as_string: True if result should be padded string, False otherwise
    :type as_string: bool
    :param digest_method: method of generating digest (hashlib.sha1 by default)
    :type digest_method: callable
    :param token_length: length of the token (6 by default)
    :type token_length: int
    :param interval_length: length of TOTP interval (30 seconds by default)
    :type interval_length: int
    :param clock: time in epoch seconds to generate totp for, default is now
    :type clock: int
    :return: generated TOTP token
    :rtype: int or str

    >>> get_hotp(b'MFRGGZDFMZTWQ2LK', int(time.time())//30) == \
        get_totp(b'MFRGGZDFMZTWQ2LK')
    True
    >>> get_hotp(b'MFRGGZDFMZTWQ2LK', int(time.time())//30) == \
        get_totp(b'MFRGGZDFMZTWQ2LK', as_string=True)
    False
    >>> get_totp(b'MFRGGZDFMZTWQ2LK', interval_length=1,
    ...          clock=MAX_COUNTER) == \
        get_hotp(b'MFRGGZDFMZTWQ2LK', intervals_no=MAX_COUNTER)
    True
    """
    token_length = _validate_token_length(token_length)
    interval_length = _validate_interval_length(interval_length)
    if clock is None:
        clock = time.time()
    interv_no = _clock_to_counter(clock, interval_length)
    return get_hotp(
        secret,
        intervals_no=interv_no,
        as_string=as_string,
        digest_method=digest_method,
        token_length=token_length,
    )


def valid_hotp(
        token: int | bytes | str,
        secret: bytes | str,
        last: int = 1,
        trials: int = 1000,
        digest_method: Callable[..., Any] = hashlib.sha1,
        token_length: int = 6,
        return_reason: bool = False,
) -> int | bool | OTPValidationResult:
    """Check if given token is valid for given secret. Return interval number
    that was successful, or False if not found.

    :param token: token being checked
    :type token: int or str
    :param secret: secret for which token is checked
    :type secret: str
    :param last: last used interval (start checking with next one)
    :type last: int
    :param trials: number of intervals to check after 'last'
    :type trials: int
    :param digest_method: method of generating digest (hashlib.sha1 by default)
    :type digest_method: callable
    :param token_length: length of the token (6 by default)
    :type token_length: int
    :param return_reason: return ``OTPValidationResult`` instead of an
        interval number, allowing ``expired``, ``future`` and ``replay`` to be
        distinguished (False by default)
    :type return_reason: bool
    :return: interval number, or False if check unsuccessful
    :rtype: int or bool

    >>> secret = b'MFRGGZDFMZTWQ2LK'
    >>> valid_hotp(713385, secret, last=1, trials=5)
    4
    >>> valid_hotp(865438, secret, last=1, trials=5)
    False
    >>> valid_hotp(713385, secret, last=4, trials=5)
    False
    >>> result = valid_hotp(713385, secret, last=4, trials=5,
    ...                     return_reason=True)
    >>> result.reason
    'replay'
    """
    result = _validate_hotp(
        token=token,
        secret=secret,
        last=last,
        trials=trials,
        digest_method=digest_method,
        token_length=token_length,
        classify=return_reason,
    )
    if return_reason:
        return result
    return result.counter if result.valid else False


def valid_totp(
        token: int | bytes | str,
        secret: bytes | str,
        digest_method: Callable[..., Any] = hashlib.sha1,
        token_length: int = 6,
        interval_length: int = 30,
        clock: float | None = None,
        window: int = 0,
        last: int | None = None,
        return_reason: bool = False,
) -> bool | OTPValidationResult:
    """Check if given token is valid time-based one-time password for given
    secret.

    :param token: token which is being checked
    :type token: int or str
    :param secret: secret for which the token is being checked
    :type secret: str
    :param digest_method: method of generating digest (hashlib.sha1 by default)
    :type digest_method: callable
    :param token_length: length of the token (6 by default)
    :type token_length: int
    :param interval_length: length of TOTP interval (30 seconds by default)
    :type interval_length: int
    :param clock: time in epoch seconds to generate totp for, default is now
    :type clock: int
    :param window: compensate for clock skew, number of intervals to check on
        each side of the current time. (default is 0 - only check the current
        clock time)
    :type window: int (positive)
    :param last: last accepted interval number, used to detect replays. When
        omitted, replay detection is not possible because this function keeps
        no state.
    :type last: int or None
    :param return_reason: return ``OTPValidationResult`` instead of a bool,
        allowing ``expired``, ``future`` and ``replay`` to be distinguished
        (False by default)
    :type return_reason: bool
    :return: True, if is valid token, False otherwise
    :rtype: bool

    >>> secret = b'MFRGGZDFMZTWQ2LK'
    >>> token = get_totp(secret)
    >>> valid_totp(token, secret)
    True
    >>> valid_totp(token+1, secret)
    False
    >>> token = get_totp(secret, as_string=True)
    >>> valid_totp(token, secret)
    True
    >>> valid_totp(token + b'1', secret)
    False
    """
    result = _validate_totp(
        token=token,
        secret=secret,
        digest_method=digest_method,
        token_length=token_length,
        interval_length=interval_length,
        clock=clock,
        window=window,
        last=last,
        classify=return_reason,
    )
    if return_reason:
        return result
    return result.valid


def _validate_hotp(
        token: int | bytes | str,
        secret: bytes | str,
        last: int,
        trials: int,
        digest_method: Callable[..., Any],
        token_length: int,
        classify: bool,
) -> OTPValidationResult:
    """Validate HOTP without returning early, so work does not depend on the
    position of a matching counter."""
    last = _validate_last(last)
    trials = _validate_trials(trials)
    token_length = _validate_token_length(token_length)
    expected_counter = last + 1 if last < MAX_COUNTER else MAX_COUNTER

    token_str = _normalized_token(token, token_length)
    if token_str is None:
        return OTPValidationResult(
            False, ValidationReason.INVALID, None, expected_counter,
        )

    if classify and _token_matches(
            get_hotp(
                secret=secret,
                intervals_no=last,
                digest_method=digest_method,
                token_length=token_length,
            ),
            token_str,
            token_length,
    ):
        return OTPValidationResult(
            False, ValidationReason.REPLAY, last, expected_counter,
        )

    matched_counter = None
    for step in range(1, trials + 1):
        raw_counter = last + step
        candidate_counter = min(raw_counter, MAX_COUNTER)
        token_candidate = get_hotp(
            secret=secret,
            intervals_no=candidate_counter,
            digest_method=digest_method,
            token_length=token_length,
        )
        is_match = _token_matches(
            token_candidate, token_str, token_length,
        )
        if raw_counter <= MAX_COUNTER and is_match and matched_counter is None:
            matched_counter = raw_counter

    if matched_counter is not None:
        return OTPValidationResult(
            True, ValidationReason.VALID, matched_counter, expected_counter,
        )

    if not classify:
        return OTPValidationResult(
            False, ValidationReason.INVALID, None, expected_counter,
        )

    if last > 0:
        previous_counter = last - 1
        if _token_matches(
                get_hotp(
                    secret=secret,
                    intervals_no=previous_counter,
                    digest_method=digest_method,
                    token_length=token_length,
                ),
                token_str,
                token_length,
        ):
            return OTPValidationResult(
                False, ValidationReason.REPLAY, previous_counter,
                expected_counter,
            )

    future_counter = last + trials + 1
    if future_counter <= MAX_COUNTER and _token_matches(
            get_hotp(
                secret=secret,
                intervals_no=future_counter,
                digest_method=digest_method,
                token_length=token_length,
            ),
            token_str,
            token_length,
    ):
        return OTPValidationResult(
            False, ValidationReason.FUTURE, future_counter, expected_counter,
        )

    return OTPValidationResult(
        False, ValidationReason.INVALID, None, expected_counter,
    )


def _validate_totp(
        token: int | bytes | str,
        secret: bytes | str,
        digest_method: Callable[..., Any] = hashlib.sha1,
        token_length: int = 6,
        interval_length: int = 30,
        clock: float | None = None,
        window: int = 0,
        last: int | None = None,
        classify: bool = True,
) -> OTPValidationResult:
    """Validate TOTP across the whole window and classify failures.

    Every counter in ``[current-window, current+window]`` is evaluated, even
    after a match has been found. This keeps the number of HMAC calculations
    independent of where in the window the token matched.
    """
    token_length = _validate_token_length(token_length)
    interval_length = _validate_interval_length(interval_length)
    window = _validate_window(window)
    if last is not None:
        last = _validate_last(last)
    if clock is None:
        clock = time.time()
    current_counter = _clock_to_counter(clock, interval_length)

    token_str = _normalized_token(token, token_length)
    if token_str is None:
        return OTPValidationResult(
            False, ValidationReason.INVALID, None, current_counter,
        )

    if classify and last is not None and _token_matches(
            get_hotp(
                secret=secret,
                intervals_no=last,
                digest_method=digest_method,
                token_length=token_length,
            ),
            token_str,
            token_length,
    ):
        return OTPValidationResult(
            False, ValidationReason.REPLAY, last, current_counter,
        )

    matched_counter = None
    matched_distance = MAX_WINDOW + 1
    for offset in range(-window, window + 1):
        raw_counter = current_counter + offset
        candidate_counter = min(max(raw_counter, 0), MAX_COUNTER)
        token_candidate = get_hotp(
            secret=secret,
            intervals_no=candidate_counter,
            digest_method=digest_method,
            token_length=token_length,
        )
        is_match = _token_matches(
            token_candidate, token_str, token_length,
        )
        distance = abs(offset)
        if is_match and distance < matched_distance:
            matched_counter = candidate_counter
            matched_distance = distance

    if matched_counter is not None:
        if last is not None and matched_counter <= last:
            return OTPValidationResult(
                False, ValidationReason.REPLAY, matched_counter,
                current_counter,
            )
        return OTPValidationResult(
            True, ValidationReason.VALID, matched_counter, current_counter,
        )

    if not classify:
        return OTPValidationResult(
            False, ValidationReason.INVALID, None, current_counter,
        )

    past_counter = max(current_counter - window - 1, 0)
    past_match = _token_matches(
        get_hotp(
            secret=secret,
            intervals_no=past_counter,
            digest_method=digest_method,
            token_length=token_length,
        ),
        token_str,
        token_length,
    )
    if past_match:
        reason = ValidationReason.EXPIRED
        if last is not None and past_counter <= last:
            reason = ValidationReason.REPLAY
        return OTPValidationResult(
            False, reason, past_counter, current_counter,
        )

    future_counter = min(current_counter + window + 1, MAX_COUNTER)
    if _token_matches(
            get_hotp(
                secret=secret,
                intervals_no=future_counter,
                digest_method=digest_method,
                token_length=token_length,
            ),
            token_str,
            token_length,
    ):
        return OTPValidationResult(
            False, ValidationReason.FUTURE, future_counter, current_counter,
        )

    return OTPValidationResult(
        False, ValidationReason.INVALID, None, current_counter,
    )


def validate_hotp(
        token: int | bytes | str,
        secret: bytes | str,
        last: int = 1,
        trials: int = 1000,
        digest_method: Callable[..., Any] = hashlib.sha1,
        token_length: int = 6,
) -> OTPValidationResult:
    """Validate HOTP and return a result distinguishing replay and future
    counters from tokens that do not match at all.

    >>> secret = b'MFRGGZDFMZTWQ2LK'
    >>> validate_hotp(get_hotp(secret, 5), secret, last=1, trials=10).counter
    5
    >>> validate_hotp(get_hotp(secret, 1), secret, last=1, trials=10).reason
    'replay'
    """
    return _validate_hotp(
        token=token,
        secret=secret,
        last=last,
        trials=trials,
        digest_method=digest_method,
        token_length=token_length,
        classify=True,
    )


def validate_totp(
        token: int | bytes | str,
        secret: bytes | str,
        digest_method: Callable[..., Any] = hashlib.sha1,
        token_length: int = 6,
        interval_length: int = 30,
        clock: float | None = None,
        window: int = 0,
        last: int | None = None,
) -> OTPValidationResult:
    """Validate TOTP and return ``expired``, ``future`` and ``replay``
    separately from generic ``invalid`` tokens.

    >>> secret = b'MFRGGZDFMZTWQ2LK'
    >>> validate_totp(get_totp(secret, clock=300), secret, clock=300).reason
    'valid'
    >>> validate_totp(get_totp(secret, clock=270), secret, clock=300).reason
    'expired'
    >>> validate_totp(get_totp(secret, clock=330), secret, clock=300).reason
    'future'
    >>> validate_totp(get_totp(secret, clock=300), secret, clock=300,
    ...               last=10).reason
    'replay'
    """
    return _validate_totp(
        token=token,
        secret=secret,
        digest_method=digest_method,
        token_length=token_length,
        interval_length=interval_length,
        clock=clock,
        window=window,
        last=last,
        classify=True,
    )

__all__ = [
    'get_hotp',
    'get_totp',
    'valid_hotp',
    'valid_totp',
    'validate_hotp',
    'validate_totp',
    'OTPValidationResult',
    'ValidationReason',
    'VALID',
    'EXPIRED',
    'FUTURE',
    'REPLAY',
    'INVALID',
    'COUNTER_BITS',
    'MAX_COUNTER',
    'MAX_INTERVAL_LENGTH',
    'MAX_WINDOW',
    'MAX_TRIALS',
    'MAX_TOKEN_LENGTH',
]
