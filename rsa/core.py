#  Copyright 2011 Sybren A. Stüvel <sybren@stuvel.eu>
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Core mathematical operations.

This is the actual core RSA implementation, which is only defined
mathematically on integers.
"""
import contextvars
import itertools
import typing


class BlindingError(RuntimeError):
    """Raised when blinding cannot be performed or its proof is invalid."""


class UnblindedOperationError(BlindingError, ValueError):
    """Raised when a private-key operation is attempted without blinding."""


_BLINDING_TOKEN_KEY = object()
_CURRENT_BLINDING_TOKEN: "contextvars.ContextVar[typing.Optional[BlindingToken]]" = (
    contextvars.ContextVar("rsa_current_blinding_token", default=None)
)


class BlindingToken:
    """One-shot proof that a private-key operation has been blinded.

    Tokens are created by :class:`rsa.key.PrivateKey` and consumed by the
    private-operation helpers in this module.  A token can only be used for one
    operation, which prevents a factor from being accidentally reused by
    concurrent or retried operations.
    """

    __slots__ = ("n", "factor", "inverse", "_used", "_closed")

    def __init__(
        self,
        n: int,
        factor: int,
        inverse: int,
        *,
        _factory_key: object,
    ) -> None:
        if _factory_key is not _BLINDING_TOKEN_KEY:
            raise TypeError("BlindingToken objects must be created by the RSA key")

        self.n = n
        self.factor = factor
        self.inverse = inverse
        self._used = False
        self._closed = False

    @property
    def blinded(self) -> bool:
        """Whether this token proves that blinding was completed."""

        return True

    def _consume(self, n: int) -> None:
        if self._closed:
            raise BlindingError("blinding token was already released")
        if self._used:
            raise BlindingError("blinding token was already used")
        if n != self.n:
            raise BlindingError("blinding token belongs to a different key")

        self._used = True

    def _close(self) -> None:
        self._closed = True


def _new_blinding_token(n: int, factor: int, inverse: int) -> BlindingToken:
    """Creates a one-shot blinding token for a private-key operation."""

    return BlindingToken(
        n=n,
        factor=factor,
        inverse=inverse,
        _factory_key=_BLINDING_TOKEN_KEY,
    )


def current_blinding_token() -> typing.Optional[BlindingToken]:
    """Returns the blinding token for the current operation, if any."""

    return _CURRENT_BLINDING_TOKEN.get()


def _set_current_blinding_token(
    token: BlindingToken,
) -> contextvars.Token:
    return _CURRENT_BLINDING_TOKEN.set(token)


def _reset_current_blinding_token(token: contextvars.Token) -> None:
    _CURRENT_BLINDING_TOKEN.reset(token)


def _require_blinding_token(
    blinding_token: typing.Optional[BlindingToken], n: int
) -> BlindingToken:
    if blinding_token is None:
        blinding_token = _CURRENT_BLINDING_TOKEN.get()

    if not isinstance(blinding_token, BlindingToken):
        raise UnblindedOperationError(
            "private-key operation requires a completed blinding token"
        )

    blinding_token._consume(n)
    return blinding_token


def assert_int(var: int, name: str) -> None:
    if isinstance(var, int):
        return

    raise TypeError("{} should be an integer, not {}".format(name, var.__class__))


def encrypt_int(message: int, ekey: int, n: int) -> int:
    """Encrypts a message using encryption key 'ekey', working modulo n"""

    assert_int(message, "message")
    assert_int(ekey, "ekey")
    assert_int(n, "n")

    if message < 0:
        raise ValueError("Only non-negative numbers are supported")

    if message >= n:
        raise OverflowError("The message %i is too long for n=%i" % (message, n))

    return pow(message, ekey, n)


def decrypt_int(
    cyphertext: int,
    dkey: int,
    n: int,
    *,
    blinding_token: typing.Optional[BlindingToken] = None,
) -> int:
    """Decrypts a cypher text using the decryption key 'dkey', working modulo n.

    This is the historical raw integer primitive.  Callers performing a
    private-key operation should use the blinded entry point on
    :class:`rsa.key.PrivateKey` instead.  Supplying ``blinding_token``
    additionally verifies that blinding was completed for this operation.
    """

    assert_int(cyphertext, "cyphertext")
    assert_int(dkey, "dkey")
    assert_int(n, "n")

    if blinding_token is not None:
        _require_blinding_token(blinding_token, n)

    message = pow(cyphertext, dkey, n)
    return message


def decrypt_int_blinded(
    cyphertext: int,
    dkey: int,
    n: int,
    *,
    blinding_token: BlindingToken,
) -> int:
    """Raw RSA private operation that refuses to run without blinding."""

    return decrypt_int(
        cyphertext,
        dkey,
        n,
        blinding_token=blinding_token,
    )


def decrypt_int_fast(
    cyphertext: int,
    rs: typing.List[int],
    ds: typing.List[int],
    ts: typing.List[int],
    *,
    blinding_token: typing.Optional[BlindingToken] = None,
) -> int:
    """Decrypts a cypher text more quickly using the Chinese Remainder Theorem."""

    assert_int(cyphertext, "cyphertext")
    for r in rs:
        assert_int(r, "r")
    for d in ds:
        assert_int(d, "d")
    for t in ts:
        assert_int(t, "t")

    n = 1
    for r in rs:
        n *= r
    _require_blinding_token(blinding_token, n)

    p, q, rs = rs[0], rs[1], rs[2:]
    exp1, exp2, ds = ds[0], ds[1], ds[2:]
    coef, ts = ts[0], ts[1:]

    M1 = pow(cyphertext, exp1, p)
    M2 = pow(cyphertext, exp2, q)
    h = ((M1 - M2) * coef) % p
    m = M2 + q * h

    Ms = [pow(cyphertext, d, r) for d, r in zip(ds, rs)]
    Rs = list(itertools.accumulate([p, q] + rs, lambda x, y: x*y))
    for R, r, M, t in zip(Rs[1:], rs, Ms, ts):
        h = ((M - m) * t) % r
        m += R * h

    return m
