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
import binascii
import hashlib
import hmac
import struct
import time
from typing import Any, Callable

__author__ = 'Tomasz Jaskowski <tadeck@gmail.com>'
__date__ = '21 June 2026'
__version_info__ = (2, 0, 0)
__version__ = '%s.%s.%s' % __version_info__
__license__ = 'MIT'


class OTPError(ValueError):
    """Base class for all errors raised by onetimepass."""


class InvalidSecretError(OTPError):
    """Secret contains characters outside of the Base32 alphabet."""


class InvalidTokenError(OTPError):
    """Token contains non-numeric characters."""


class InvalidLengthError(OTPError):
    """Secret or token has an illegal length or padding."""


# ASCII whitespace that is tolerated (and stripped) in Base32 secrets:
_SECRET_WHITESPACE = frozenset(b' \t\n\r\x0b\x0c')

_BASE32_ALPHABET = frozenset(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')

_BASE32_ALPHABET_LOWER = frozenset(b'abcdefghijklmnopqrstuvwxyz')

# Legal lengths of an unpadded Base32 body, modulo 8:
_BASE32_VALID_REMAINDERS = frozenset((0, 2, 4, 5, 7))


def _decode_secret(secret: bytes | str, casefold: bool = True) -> bytes:
    """Normalize and decode a Base32-encoded secret.

    Accepts secrets regardless of letter case, ignores ASCII whitespace and
    allows padding to be either explicitly declared (and correct) or omitted
    (it is then derived from the length). Control characters, characters
    outside of the Base32 alphabet and illegal lengths are rejected.

    :param secret: the base32-encoded string acting as secret key
    :type secret: str or bytes
    :param casefold: True (default), if should accept also lowercase alphabet
    :type casefold: bool
    :return: decoded secret key
    :rtype: bytes
    :raises InvalidSecretError: if secret contains illegal characters
    :raises InvalidLengthError: if secret has illegal length or padding
    """
    if isinstance(secret, str):
        secret = secret.encode('utf-8')
    elif isinstance(secret, bytearray):
        secret = bytes(secret)
    if not isinstance(secret, bytes):
        raise InvalidSecretError('Secret must be bytes or string')
    cleaned = bytes(
        char for char in secret if char not in _SECRET_WHITESPACE
    )
    for char in cleaned:
        if char < 0x21 or char > 0x7e:
            raise InvalidSecretError(
                'Secret contains control or non-ASCII characters'
            )
    body = cleaned.rstrip(b'=')
    padding = cleaned[len(body):]
    if not casefold and any(
            char in _BASE32_ALPHABET_LOWER for char in body
    ):
        raise InvalidSecretError('Lowercase secret not allowed here')
    body = body.upper()
    if any(char not in _BASE32_ALPHABET for char in body):
        raise InvalidSecretError('Secret is not Base32-encoded')
    remainder = len(body) % 8
    if remainder not in _BASE32_VALID_REMAINDERS:
        raise InvalidLengthError('Secret has illegal length')
    expected_padding = b'=' * ((8 - remainder) % 8)
    if cleaned != body and padding != expected_padding:
        raise InvalidLengthError('Secret has incorrect padding')
    if not body:
        raise InvalidLengthError('Secret must not be empty')
    try:
        return base64.b32decode(body + expected_padding)
    except (binascii.Error, TypeError) as exc:
        raise InvalidSecretError('Incorrect secret') from exc


def _normalize_token(token: int | bytes | str, token_length: int = 6) -> bytes:
    """Normalize token to its zero-padded byte representation.

    :param token: token value to be normalized
    :type token: int or str or bytes
    :param token_length: allowed length of token
    :type token_length: int
    :return: zero-padded token as bytes
    :rtype: bytes
    :raises InvalidTokenError: if token contains non-numeric characters
    :raises InvalidLengthError: if token is longer than allowed
    """
    if isinstance(token, bool) or not isinstance(token, (int, bytes, str)):
        raise InvalidTokenError('Token must be int, bytes or string')
    if not isinstance(token, bytes):
        token = str(token).encode('utf-8')
    if not token.isdigit():
        raise InvalidTokenError('Token must contain only digits')
    if len(token) > token_length:
        raise InvalidLengthError('Token is too long')
    return token.rjust(token_length, b'0')


def _is_possible_token(token: int | bytes | str, token_length: int = 6) -> bool:
    """Determines if given value is acceptable as a token. Used when validating
    tokens.

    Currently allows only numeric tokens no longer than 6 chars.

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
    try:
        _normalize_token(token, token_length=token_length)
    except OTPError:
        return False
    return True


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
    """
    key = _decode_secret(secret, casefold=casefold)
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
    """
    if clock is None:
        clock = time.time()
    interv_no = int(clock) // interval_length
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
) -> int | bool:
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
    :return: interval number, or False if check unsuccessful
    :rtype: int or bool

    >>> secret = b'MFRGGZDFMZTWQ2LK'
    >>> valid_hotp(713385, secret, last=1, trials=5)
    4
    >>> valid_hotp(865438, secret, last=1, trials=5)
    False
    >>> valid_hotp(713385, secret, last=4, trials=5)
    False
    """
    try:
        token_bytes = _normalize_token(token, token_length=token_length)
    except OTPError:
        return False
    for i in range(last + 1, last + trials + 1):
        candidate = get_hotp(
            secret=secret,
            intervals_no=i,
            as_string=True,
            digest_method=digest_method,
            token_length=token_length,
        )
        if hmac.compare_digest(candidate, token_bytes):
            return i
    return False


def valid_totp(
        token: int | bytes | str,
        secret: bytes | str,
        digest_method: Callable[..., Any] = hashlib.sha1,
        token_length: int = 6,
        interval_length: int = 30,
        clock: float | None = None,
        window: int = 0,
) -> bool:
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
    try:
        token_bytes = _normalize_token(token, token_length=token_length)
    except OTPError:
        return False
    if clock is None:
        clock = time.time()
    for w in range(-window, window+1):
        candidate = get_totp(
            secret,
            as_string=True,
            digest_method=digest_method,
            token_length=token_length,
            interval_length=interval_length,
            clock=int(clock)+(w*interval_length)
        )
        if hmac.compare_digest(candidate, token_bytes):
            return True
    return False

__all__ = [
    'InvalidLengthError',
    'InvalidSecretError',
    'InvalidTokenError',
    'OTPError',
    'get_hotp',
    'get_totp',
    'valid_hotp',
    'valid_totp'
]
