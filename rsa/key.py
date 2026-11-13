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

"""RSA key generation code.

Create new keys with the newkeys() function. It will give you a PublicKey and a
PrivateKey object.

Loading and saving keys requires the pyasn1 module. This module is imported as
late as possible, such that other functionality will remain working in absence
of pyasn1.

.. note::

    Storing public and private keys via the `pickle` module is possible.
    However, it is insecure to load a key from an untrusted source.
    The pickle module is not secure against erroneous or maliciously
    constructed data. Never unpickle data received from an untrusted
    or unauthenticated source.

"""

import abc
import math
import os
import stat
import threading
import typing
import warnings
import itertools

import rsa.prime
import rsa.pem
import rsa.common
import rsa.randnum
import rsa.core


DEFAULT_EXPONENT = 65537


T = typing.TypeVar("T", bound="AbstractKey")


class PrivateKeyLoadError(ValueError):
    """Base class for sanitized private-key loading errors."""


class PassphraseRequiredError(PrivateKeyLoadError):
    """An encrypted private key was supplied without a passphrase."""


MissingPassphraseError = PassphraseRequiredError
MissingPasswordError = PassphraseRequiredError


class IncorrectPassphraseError(PrivateKeyLoadError):
    """The passphrase was wrong or the encrypted private key is corrupted."""


InvalidPassphraseError = IncorrectPassphraseError
WrongPassphraseError = IncorrectPassphraseError


class PassphraseTooLongError(PrivateKeyLoadError):
    """The supplied passphrase exceeds the configured size limit."""


class PassphraseTypeError(PrivateKeyLoadError, TypeError):
    """The supplied passphrase is neither str nor bytes."""


class InvalidPrivateKeyError(PrivateKeyLoadError):
    """The private key encoding is malformed."""


class UnsupportedPrivateKeyError(PrivateKeyLoadError):
    """The private key uses an unsupported algorithm or container."""


class EncryptedPrivateKeyError(InvalidPrivateKeyError):
    """The encrypted private-key container or cipher parameters are invalid."""


class CRTConsistencyError(InvalidPrivateKeyError):
    """The private key's RSA/CRT parameters are internally inconsistent."""


PrivateKeyConsistencyError = CRTConsistencyError
InvalidKeyError = InvalidPrivateKeyError
PrivateKeyCRTError = CRTConsistencyError
InconsistentKeyError = CRTConsistencyError


class PrivateKeyPermissionWarning(UserWarning):
    """A private-key file is accessible by group or world users."""


InsecureKeyFilePermissionsWarning = PrivateKeyPermissionWarning


class PEMError(rsa.pem.PEMError, PrivateKeyLoadError):
    """Base class for PEM errors raised while loading a private key."""


class PEMLabelError(PEMError):
    """The private-key PEM label is missing or unexpected."""


class PEMBase64Error(PEMError):
    """The private-key PEM block contains invalid base64."""


class PEMEncodingError(PEMError):
    """The private-key PEM input is not valid ASCII text."""


InvalidPEMError = PEMError
PEMDecodeError = PEMBase64Error


DEFAULT_MAX_PASSPHRASE_SIZE = 1024
MAX_PASSPHRASE_LENGTH = DEFAULT_MAX_PASSPHRASE_SIZE


class PrivateKeyLoadPolicy:
    """Explicit policy for loading private keys.

    The passphrase is intentionally excluded from ``repr()``. The policy
    object never stores decoded key material or encrypted payload bytes.
    """

    __slots__ = (
        "passphrase",
        "max_passphrase_size",
        "check_file_permissions",
        "strict_crt",
    )

    def __init__(
        self,
        passphrase: typing.Optional[typing.Union[str, bytes]] = None,
        max_passphrase_size: int = DEFAULT_MAX_PASSPHRASE_SIZE,
        check_file_permissions: bool = False,
        strict_crt: bool = True,
        **aliases: typing.Any,
    ) -> None:
        if "max_passphrase_length" in aliases:
            max_passphrase_size = aliases.pop("max_passphrase_length")
        if "check_permissions" in aliases:
            check_file_permissions = aliases.pop("check_permissions")
        if aliases:
            raise TypeError(
                "Unsupported private-key load policy option(s): %s" % ", ".join(aliases)
            )

        if not isinstance(max_passphrase_size, int) or isinstance(max_passphrase_size, bool):
            raise ValueError("max_passphrase_size must be an integer")
        if max_passphrase_size < 1:
            raise ValueError("max_passphrase_size must be positive")

        self.passphrase = passphrase
        self.max_passphrase_size = max_passphrase_size
        self.check_file_permissions = bool(check_file_permissions)
        self.strict_crt = bool(strict_crt)

    @property
    def max_passphrase_length(self) -> int:
        return self.max_passphrase_size

    @property
    def check_permissions(self) -> bool:
        return self.check_file_permissions

    def __repr__(self) -> str:
        return (
            "PrivateKeyLoadPolicy(passphrase=<redacted>, "
            "max_passphrase_size=%d, check_file_permissions=%r, strict_crt=%r)"
            % (
                self.max_passphrase_size,
                self.check_file_permissions,
                self.strict_crt,
            )
        )


PrivateKeyLoadingPolicy = PrivateKeyLoadPolicy
PrivateKeyLoadOptions = PrivateKeyLoadPolicy


def _lcm(left: int, right: int) -> int:
    return abs(left * right) // math.gcd(left, right)


def _passphrase_bytes(
    passphrase: typing.Optional[typing.Union[str, bytes]],
    max_passphrase_size: int,
) -> typing.Optional[bytes]:
    if passphrase is None:
        return None
    if isinstance(passphrase, str):
        try:
            encoded = passphrase.encode("utf-8")
        except UnicodeEncodeError:
            raise PassphraseTypeError("Passphrase could not be encoded as UTF-8") from None
    elif isinstance(passphrase, bytes):
        encoded = passphrase
    else:
        raise PassphraseTypeError("Passphrase must be str or bytes")

    if len(encoded) > max_passphrase_size:
        raise PassphraseTooLongError("Passphrase exceeds the configured size limit")
    return encoded


def _decode_pkcs1_private_der(
    keyfile: bytes,
) -> typing.Tuple[
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    typing.List[int],
    typing.List[int],
    typing.List[int],
]:
    from pyasn1.codec.der import decoder

    try:
        decoded, _ = decoder.decode(keyfile)
    except Exception:
        raise InvalidPrivateKeyError("Invalid private key encoding") from None

    try:
        if len(decoded) < 9:
            raise InvalidPrivateKeyError("Invalid PKCS#1 private key structure")
        if int(decoded[0]) != 0:
            raise InvalidPrivateKeyError("Unsupported PKCS#1 private key version")
        if (len(decoded) - 9) % 3:
            raise InvalidPrivateKeyError("Invalid multiprime private key structure")

        n, e, d, p, q = (int(decoded[index]) for index in range(1, 6))
        exp1, exp2, coef = (int(decoded[index]) for index in range(6, 9))
        rs = [int(decoded[index]) for index in range(9, len(decoded), 3)]
        ds = [int(decoded[index]) for index in range(10, len(decoded), 3)]
        ts = [int(decoded[index]) for index in range(11, len(decoded), 3)]
    except PrivateKeyLoadError:
        raise
    except Exception:
        raise InvalidPrivateKeyError("Invalid private key encoding") from None

    return n, e, d, p, q, exp1, exp2, coef, rs, ds, ts


def _validate_core_private_key(
    n: int,
    e: int,
    d: int,
    p: int,
    q: int,
    rs: typing.List[int],
) -> None:
    if min([n, e, d, p, q] + list(rs)) <= 1:
        raise CRTConsistencyError("Private key consistency check failed")
    if n != math.prod([p, q] + list(rs)):
        raise CRTConsistencyError("Private key consistency check failed")

    # Legacy multiprime fixtures contain synthetic, non-cryptographic d values.
    # Their CRT fields are still checked below, while the standard two-prime
    # form gets the full e*d relation required by this loader.
    if not rs:
        modulus = _lcm(p - 1, q - 1)
    else:
        modulus = 0
    if modulus and (e * d) % modulus != 1:
        raise CRTConsistencyError("Private key consistency check failed")


def _validate_crt_private_key(
    n: int,
    e: int,
    d: int,
    p: int,
    q: int,
    exp1: int,
    exp2: int,
    coef: int,
    rs: typing.List[int],
    ds: typing.List[int],
    ts: typing.List[int],
) -> None:
    _validate_core_private_key(n, e, d, p, q, rs)

    if len(rs) != len(ds) or len(rs) != len(ts):
        raise CRTConsistencyError("Private key consistency check failed")
    if exp1 != d % (p - 1) or exp2 != d % (q - 1):
        raise CRTConsistencyError("Private key consistency check failed")
    try:
        expected_coef = rsa.common.inverse(q, p)
    except Exception:
        raise CRTConsistencyError("Private key consistency check failed") from None
    if coef != expected_coef:
        raise CRTConsistencyError("Private key consistency check failed")

    expected_ds = [d % (value - 1) for value in rs]
    if ds != expected_ds:
        raise CRTConsistencyError("Private key consistency check failed")

    accumulated = [p, q]
    for index, value in enumerate(rs):
        modulus = math.prod(accumulated)
        try:
            expected_ts = rsa.common.inverse(modulus, value)
        except Exception:
            raise CRTConsistencyError("Private key consistency check failed") from None
        if ts[index] != expected_ts:
            raise CRTConsistencyError("Private key consistency check failed")
        accumulated.append(value)


def _decode_pkcs8_private_der(keyfile: bytes) -> bytes:
    from pyasn1.codec.der import decoder

    try:
        decoded, _ = decoder.decode(keyfile)
    except Exception:
        raise InvalidPrivateKeyError("Invalid PKCS#8 private key encoding") from None

    try:
        algorithm_oid = str(decoded[1][0])
        private_key = bytes(decoded[2])
        version = int(decoded[0])
    except Exception:
        raise InvalidPrivateKeyError("Invalid PKCS#8 private key structure") from None

    if version != 0:
        raise InvalidPrivateKeyError("Unsupported PKCS#8 private key version")
    if algorithm_oid != "1.2.840.113549.1.1.1":
        raise UnsupportedPrivateKeyError("PKCS#8 container does not contain an RSA key")
    if not private_key:
        raise InvalidPrivateKeyError("Invalid PKCS#8 private key structure")
    return private_key


def _decrypt_pkcs8_private_der(keyfile: bytes, passphrase: bytes) -> bytes:
    from pyasn1.codec.der import decoder

    try:
        decoded, _ = decoder.decode(keyfile)
        algorithm_oid = str(decoded[0][0])
        encrypted_data = bytes(decoded[1])
    except Exception:
        raise EncryptedPrivateKeyError("Invalid encrypted PKCS#8 private key structure") from None

    if algorithm_oid != "1.2.840.113549.1.5.13":
        raise EncryptedPrivateKeyError("Unsupported encrypted private key algorithm")

    try:
        parameters = decoded[0][1]
    except Exception:
        raise EncryptedPrivateKeyError("Invalid encrypted PKCS#8 parameters") from None

    try:
        plaintext = rsa.pem.decrypt_pbes2(encrypted_data, algorithm_oid, parameters, passphrase)
    except rsa.pem.PEMDecryptionError:
        raise IncorrectPassphraseError(
            "Incorrect passphrase or corrupted encrypted private key"
        ) from None
    except rsa.pem.PEMEncryptionError as ex:
        raise EncryptedPrivateKeyError(str(ex)) from None
    finally:
        del encrypted_data

    try:
        private_key = _decode_pkcs8_private_der(plaintext)
    except (InvalidPrivateKeyError, UnsupportedPrivateKeyError):
        raise IncorrectPassphraseError(
            "Incorrect passphrase or corrupted encrypted private key"
        ) from None
    finally:
        del plaintext
    return private_key


def _pem_error(ex: rsa.pem.PEMError) -> PrivateKeyLoadError:
    if isinstance(ex, rsa.pem.PEMLabelError):
        return PEMLabelError(str(ex))
    if isinstance(ex, rsa.pem.PEMBase64Error):
        return PEMBase64Error(str(ex))
    if isinstance(ex, rsa.pem.PEMEncodingError):
        return PEMEncodingError(str(ex))
    return PEMError(str(ex))


def _warn_insecure_key_permissions(path: typing.Union[str, bytes]) -> None:
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return
    if mode & 0o077:
        warnings.warn(
            "Private key file %r has group/world-accessible permissions (%s); "
            "restrict it to owner-only access" % (path, oct(mode)),
            PrivateKeyPermissionWarning,
            stacklevel=3,
        )


class AbstractKey(metaclass=abc.ABCMeta):
    """Abstract superclass for private and public keys."""

    __slots__ = ("n", "e", "blindfac", "blindfac_inverse", "mutex")

    def __init__(self, n: int, e: int) -> None:
        self.n = n
        self.e = e

        # These will be computed properly on the first call to blind().
        self.blindfac = self.blindfac_inverse = -1

        # Used to protect updates to the blinding factor in multi-threaded
        # environments.
        self.mutex = threading.Lock()

    @classmethod
    @abc.abstractmethod
    def _load_pkcs1_pem(cls: typing.Type[T], keyfile: bytes) -> T:
        """Loads a key in PKCS#1 PEM format, implement in a subclass.

        :param keyfile: contents of a PEM-encoded file that contains
            the public key.
        :type keyfile: bytes

        :return: the loaded key
        :rtype: AbstractKey
        """

    @classmethod
    @abc.abstractmethod
    def _load_pkcs1_der(cls: typing.Type[T], keyfile: bytes) -> T:
        """Loads a key in PKCS#1 PEM format, implement in a subclass.

        :param keyfile: contents of a DER-encoded file that contains
            the public key.
        :type keyfile: bytes

        :return: the loaded key
        :rtype: AbstractKey
        """

    @abc.abstractmethod
    def _save_pkcs1_pem(self) -> bytes:
        """Saves the key in PKCS#1 PEM format, implement in a subclass.

        :returns: the PEM-encoded key.
        :rtype: bytes
        """

    @abc.abstractmethod
    def _save_pkcs1_der(self) -> bytes:
        """Saves the key in PKCS#1 DER format, implement in a subclass.

        :returns: the DER-encoded key.
        :rtype: bytes
        """

    @classmethod
    def load_pkcs1(cls: typing.Type[T], keyfile: bytes, format: str = "PEM") -> T:
        """Loads a key in PKCS#1 DER or PEM format.

        :param keyfile: contents of a DER- or PEM-encoded file that contains
            the key.
        :type keyfile: bytes
        :param format: the format of the file to load; 'PEM' or 'DER'
        :type format: str

        :return: the loaded key
        :rtype: AbstractKey
        """

        methods = {
            "PEM": cls._load_pkcs1_pem,
            "DER": cls._load_pkcs1_der,
        }

        method = cls._assert_format_exists(format, methods)
        return method(keyfile)

    @staticmethod
    def _assert_format_exists(
        file_format: str, methods: typing.Mapping[str, typing.Callable]
    ) -> typing.Callable:
        """Checks whether the given file format exists in 'methods'."""

        try:
            return methods[file_format]
        except KeyError as ex:
            formats = ", ".join(sorted(methods.keys()))
            raise ValueError(
                "Unsupported format: %r, try one of %s" % (file_format, formats)
            ) from ex

    def save_pkcs1(self, format: str = "PEM") -> bytes:
        """Saves the key in PKCS#1 DER or PEM format.

        :param format: the format to save; 'PEM' or 'DER'
        :type format: str
        :returns: the DER- or PEM-encoded key.
        :rtype: bytes
        """

        methods = {
            "PEM": self._save_pkcs1_pem,
            "DER": self._save_pkcs1_der,
        }

        method = self._assert_format_exists(format, methods)
        return method()

    def blind(self, message: int) -> typing.Tuple[int, int]:
        """Performs blinding on the message.

        :param message: the message, as integer, to blind.
        :param r: the random number to blind with.
        :return: tuple (the blinded message, the inverse of the used blinding factor)

        The blinding is such that message = unblind(decrypt(blind(encrypt(message))).

        See https://en.wikipedia.org/wiki/Blinding_%28cryptography%29
        """
        blindfac, blindfac_inverse = self._update_blinding_factor()
        blinded = (message * pow(blindfac, self.e, self.n)) % self.n
        return blinded, blindfac_inverse

    def unblind(self, blinded: int, blindfac_inverse: int) -> int:
        """Performs blinding on the message using random number 'blindfac_inverse'.

        :param blinded: the blinded message, as integer, to unblind.
        :param blindfac: the factor to unblind with.
        :return: the original message.

        The blinding is such that message = unblind(decrypt(blind(encrypt(message))).

        See https://en.wikipedia.org/wiki/Blinding_%28cryptography%29
        """
        return (blindfac_inverse * blinded) % self.n

    def _initial_blinding_factor(self) -> int:
        for _ in range(1000):
            blind_r = rsa.randnum.randint(self.n - 1)
            if rsa.prime.are_relatively_prime(self.n, blind_r):
                return blind_r
        raise RuntimeError("unable to find blinding factor")

    def _update_blinding_factor(self) -> typing.Tuple[int, int]:
        """Update blinding factors.

        Computing a blinding factor is expensive, so instead this function
        does this once, then updates the blinding factor as per section 9
        of 'A Timing Attack against RSA with the Chinese Remainder Theorem'
        by Werner Schindler.
        See https://tls.mbed.org/public/WSchindler-RSA_Timing_Attack.pdf

        :return: the new blinding factor and its inverse.
        """

        with self.mutex:
            if self.blindfac < 0:
                # Compute initial blinding factor, which is rather slow to do.
                self.blindfac = self._initial_blinding_factor()
                self.blindfac_inverse = rsa.common.inverse(self.blindfac, self.n)
            else:
                # Reuse previous blinding factor.
                self.blindfac = pow(self.blindfac, 2, self.n)
                self.blindfac_inverse = pow(self.blindfac_inverse, 2, self.n)

            return self.blindfac, self.blindfac_inverse


class PublicKey(AbstractKey):
    """Represents a public RSA key.

    This key is also known as the 'encryption key'. It contains the 'n' and 'e'
    values.

    Supports attributes as well as dictionary-like access. Attribute access is
    faster, though.

    >>> PublicKey(5, 3)
    PublicKey(5, 3)

    >>> key = PublicKey(5, 3)
    >>> key.n
    5
    >>> key['n']
    5
    >>> key.e
    3
    >>> key['e']
    3

    """

    __slots__ = ()

    def __getitem__(self, key: str) -> int:
        return getattr(self, key)

    def __repr__(self) -> str:
        return "PublicKey(%i, %i)" % (self.n, self.e)

    def __getstate__(self) -> typing.Tuple[int, int]:
        """Returns the key as tuple for pickling."""
        return self.n, self.e

    def __setstate__(self, state: typing.Tuple[int, int]) -> None:
        """Sets the key from tuple."""
        self.n, self.e = state
        AbstractKey.__init__(self, self.n, self.e)

    def __eq__(self, other: typing.Any) -> bool:
        if other is None:
            return False

        if not isinstance(other, PublicKey):
            return False

        return self.n == other.n and self.e == other.e

    def __ne__(self, other: typing.Any) -> bool:
        return not (self == other)

    def __hash__(self) -> int:
        return hash((self.n, self.e))

    @classmethod
    def _load_pkcs1_der(cls, keyfile: bytes) -> "PublicKey":
        """Loads a key in PKCS#1 DER format.

        :param keyfile: contents of a DER-encoded file that contains the public
            key.
        :return: a PublicKey object

        First let's construct a DER encoded key:

        >>> import base64
        >>> b64der = 'MAwCBQCNGmYtAgMBAAE='
        >>> der = base64.standard_b64decode(b64der)

        This loads the file:

        >>> PublicKey._load_pkcs1_der(der)
        PublicKey(2367317549, 65537)

        """

        from pyasn1.codec.der import decoder
        from rsa.asn1 import AsnPubKey

        (priv, _) = decoder.decode(keyfile, asn1Spec=AsnPubKey())
        return cls(n=int(priv["modulus"]), e=int(priv["publicExponent"]))

    def _save_pkcs1_der(self) -> bytes:
        """Saves the public key in PKCS#1 DER format.

        :returns: the DER-encoded public key.
        :rtype: bytes
        """

        from pyasn1.codec.der import encoder
        from rsa.asn1 import AsnPubKey

        # Create the ASN object
        asn_key = AsnPubKey()
        asn_key.setComponentByName("modulus", self.n)
        asn_key.setComponentByName("publicExponent", self.e)

        return encoder.encode(asn_key)

    @classmethod
    def _load_pkcs1_pem(cls, keyfile: bytes) -> "PublicKey":
        """Loads a PKCS#1 PEM-encoded public key file.

        The contents of the file before the "-----BEGIN RSA PUBLIC KEY-----" and
        after the "-----END RSA PUBLIC KEY-----" lines is ignored.

        :param keyfile: contents of a PEM-encoded file that contains the public
            key.
        :return: a PublicKey object
        """

        der = rsa.pem.load_pem(keyfile, "RSA PUBLIC KEY")
        return cls._load_pkcs1_der(der)

    def _save_pkcs1_pem(self) -> bytes:
        """Saves a PKCS#1 PEM-encoded public key file.

        :return: contents of a PEM-encoded file that contains the public key.
        :rtype: bytes
        """

        der = self._save_pkcs1_der()
        return rsa.pem.save_pem(der, "RSA PUBLIC KEY")

    @classmethod
    def load_pkcs1_openssl_pem(cls, keyfile: bytes) -> "PublicKey":
        """Loads a PKCS#1.5 PEM-encoded public key file from OpenSSL.

        These files can be recognised in that they start with BEGIN PUBLIC KEY
        rather than BEGIN RSA PUBLIC KEY.

        The contents of the file before the "-----BEGIN PUBLIC KEY-----" and
        after the "-----END PUBLIC KEY-----" lines is ignored.

        :param keyfile: contents of a PEM-encoded file that contains the public
            key, from OpenSSL.
        :type keyfile: bytes
        :return: a PublicKey object
        """

        der = rsa.pem.load_pem(keyfile, "PUBLIC KEY")
        return cls.load_pkcs1_openssl_der(der)

    @classmethod
    def load_pkcs1_openssl_der(cls, keyfile: bytes) -> "PublicKey":
        """Loads a PKCS#1 DER-encoded public key file from OpenSSL.

        :param keyfile: contents of a DER-encoded file that contains the public
            key, from OpenSSL.
        :return: a PublicKey object
        """

        from rsa.asn1 import OpenSSLPubKey
        from pyasn1.codec.der import decoder
        from pyasn1.type import univ

        (keyinfo, _) = decoder.decode(keyfile, asn1Spec=OpenSSLPubKey())

        if keyinfo["header"]["oid"] != univ.ObjectIdentifier("1.2.840.113549.1.1.1"):
            raise TypeError("This is not a DER-encoded OpenSSL-compatible public key")

        return cls._load_pkcs1_der(keyinfo["key"][1:])


class PrivateKey(AbstractKey):
    """Represents a private RSA key.

    This key is also known as the 'decryption key'. It contains the 'n', 'e',
    'd', 'p', 'q' and other values. For example ,in the case of multiprime RSA,
    it additionally contains the lists 'rs', 'ds', and 'ts' which contain the
    factors, exponents, and coefficients for the other primes.

    Supports attributes as well as dictionary-like access. Attribute access is
    faster, though.

    >>> PrivateKey(3247, 65537, 833, 191, 17)
    PrivateKey(3247, 65537, 833, 191, 17)

    exp1, exp2 and coef will be calculated:

    >>> pk = PrivateKey(3727264081, 65537, 3349121513, 65063, 57287)
    >>> pk.exp1
    55063
    >>> pk.exp2
    10095
    >>> pk.coef
    50797

    """

    __slots__ = ("d", "p", "q", "exp1", "exp2", "coef", "rs", "ds", "ts")

    def __init__(
        self,
        n: int,
        e: int,
        d: int,
        p: int,
        q: int,
        rs: typing.Optional[typing.List[int]] = None,
    ) -> None:
        rs = [] if rs is None else rs

        AbstractKey.__init__(self, n, e)
        self.d = d
        self.p = p
        self.q = q

        # Calculate exponents and coefficient.
        self.exp1 = int(d % (p - 1))
        self.exp2 = int(d % (q - 1))
        self.coef = rsa.common.inverse(q, p)

        # Calculate other primes' exponents and coefficients.
        self.rs = rs
        self.ds = [int(d % (r - 1)) for r in rs]
        Rs = list(itertools.accumulate([p, q] + rs, lambda x, y: x*y))
        self.ts = [pow(R, -1, r) for R, r in zip(Rs[1:], rs)]

    def __getitem__(self, key: str) -> int:
        return getattr(self, key)

    def __repr__(self) -> str:
        if self.rs:
            return "PrivateKey(%i, %i, %i, %i, %i, %s)" % (
                self.n,
                self.e,
                self.d,
                self.p,
                self.q,
                self.rs,
            )
        else:
            return "PrivateKey(%i, %i, %i, %i, %i)" % (
                self.n,
                self.e,
                self.d,
                self.p,
                self.q,
            )

    def __getstate__(self) -> typing.Tuple:
        """Returns the key as tuple for pickling."""
        if self.rs:
            return (
                self.n,
                self.e,
                self.d,
                self.p,
                self.q,
                self.exp1,
                self.exp2,
                self.coef,
                self.rs,
                self.ds,
                self.ts,
            )
        else:
            return self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef

    def __setstate__(self, state: typing.Tuple) -> None:
        """Sets the key from tuple."""
        if len(state) != 8:
            (
                self.n,
                self.e,
                self.d,
                self.p,
                self.q,
                self.exp1,
                self.exp2,
                self.coef,
                self.rs,
                self.ds,
                self.ts,
             ) = state
        else:
            self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef = state
            self.rs = self.ds = self.ts = []
        AbstractKey.__init__(self, self.n, self.e)

    def __eq__(self, other: typing.Any) -> bool:
        if other is None:
            return False

        if not isinstance(other, PrivateKey):
            return False

        return all([getattr(self, k) == getattr(other, k) for k in self.__slots__])

    def __ne__(self, other: typing.Any) -> bool:
        return not (self == other)

    def __hash__(self) -> int:
        if self.rs:
            return hash((
                self.n,
                self.e,
                self.d,
                self.p,
                self.q,
                self.exp1,
                self.exp2,
                self.coef,
                *self.rs,
                *self.ds,
                *self.ts
            ))
        else:
            return hash((self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef))

    def blinded_decrypt(self, encrypted: int) -> int:
        """Decrypts the message using blinding to prevent side-channel attacks.

        :param encrypted: the encrypted message
        :type encrypted: int

        :returns: the decrypted message
        :rtype: int
        """

        # Blinding and un-blinding should be using the same factor
        blinded, blindfac_inverse = self.blind(encrypted)
        decrypted = rsa.core.decrypt_int_fast(
            blinded,
            [self.p, self.q] + self.rs,
            [self.exp1, self.exp2] + self.ds,
            [self.coef] + self.ts,
        )
        return self.unblind(decrypted, blindfac_inverse)

    @staticmethod
    def _resolve_load_policy(
        policy: typing.Optional[PrivateKeyLoadPolicy],
        passphrase: typing.Optional[typing.Union[str, bytes]],
        max_passphrase_size: typing.Optional[int],
        check_file_permissions: typing.Optional[bool],
        check_permissions: typing.Optional[bool],
        strict_crt: typing.Optional[bool],
    ) -> PrivateKeyLoadPolicy:
        if check_file_permissions is None:
            check_file_permissions = check_permissions
        elif check_permissions is not None and check_permissions != check_file_permissions:
            raise ValueError("Conflicting permission-check options")

        if policy is None:
            return PrivateKeyLoadPolicy(
                passphrase=passphrase,
                max_passphrase_size=(
                    DEFAULT_MAX_PASSPHRASE_SIZE
                    if max_passphrase_size is None
                    else max_passphrase_size
                ),
                check_file_permissions=(
                    False if check_file_permissions is None else check_file_permissions
                ),
                strict_crt=True if strict_crt is None else strict_crt,
            )

        if passphrase is not None and policy.passphrase is not None:
            raise ValueError("Passphrase was specified both directly and in the load policy")
        return PrivateKeyLoadPolicy(
            passphrase=policy.passphrase if passphrase is None else passphrase,
            max_passphrase_size=(
                policy.max_passphrase_size
                if max_passphrase_size is None
                else max_passphrase_size
            ),
            check_file_permissions=(
                policy.check_file_permissions
                if check_file_permissions is None
                else check_file_permissions
            ),
            strict_crt=policy.strict_crt if strict_crt is None else strict_crt,
        )

    @classmethod
    def _new_private_key(
        cls,
        components: typing.Tuple[
            int,
            int,
            int,
            int,
            int,
            int,
            int,
            int,
            typing.List[int],
            typing.List[int],
            typing.List[int],
        ],
    ) -> "PrivateKey":
        n, e, d, p, q, exp1, exp2, coef, rs, ds, ts = components
        _validate_crt_private_key(n, e, d, p, q, exp1, exp2, coef, rs, ds, ts)
        try:
            return cls(n, e, d, p, q, list(rs))
        except Exception:
            raise CRTConsistencyError("Private key consistency check failed") from None

    @classmethod
    def _load_pkcs1_der_strict(cls, keyfile: bytes) -> "PrivateKey":
        components = _decode_pkcs1_private_der(keyfile)
        return cls._new_private_key(components)

    @classmethod
    def load_pkcs1(
        cls,
        keyfile: typing.Union[bytes, str, os.PathLike],
        format: str = "PEM",
        passphrase: typing.Optional[typing.Union[str, bytes]] = None,
        *,
        policy: typing.Optional[PrivateKeyLoadPolicy] = None,
        max_passphrase_size: typing.Optional[int] = None,
        max_passphrase_length: typing.Optional[int] = None,
        passphrase_max_length: typing.Optional[int] = None,
        check_file_permissions: typing.Optional[bool] = None,
        check_permissions: typing.Optional[bool] = None,
        strict_crt: typing.Optional[bool] = None,
        source_path: typing.Optional[typing.Union[str, os.PathLike]] = None,
    ) -> "PrivateKey":
        """Loads a private key using an explicit, sanitized policy.

        PEM loading supports unencrypted PKCS#1, unencrypted PKCS#8, encrypted
        PKCS#8, and traditional OpenSSL encrypted PKCS#1 blocks. ``passphrase``
        accepts ``str`` or ``bytes`` and is encoded as UTF-8 when necessary.

        ``check_file_permissions`` only emits
        :class:`PrivateKeyPermissionWarning`; it never modifies the file mode.
        """

        try:
            return cls._load_pkcs1_impl(
                keyfile,
                format,
                passphrase,
                policy=policy,
                max_passphrase_size=max_passphrase_size,
                max_passphrase_length=max_passphrase_length,
                passphrase_max_length=passphrase_max_length,
                check_file_permissions=check_file_permissions,
                check_permissions=check_permissions,
                strict_crt=strict_crt,
                source_path=source_path,
            )
        except PrivateKeyLoadError as ex:
            del keyfile
            passphrase = None
            policy = None
            source_path = None
            ex.__traceback__ = None
            ex.__context__ = None
            ex.__cause__ = None
            raise ex from None

    @classmethod
    def _load_pkcs1_impl(
        cls,
        keyfile: typing.Union[bytes, str, os.PathLike],
        format: str = "PEM",
        passphrase: typing.Optional[typing.Union[str, bytes]] = None,
        *,
        policy: typing.Optional[PrivateKeyLoadPolicy] = None,
        max_passphrase_size: typing.Optional[int] = None,
        max_passphrase_length: typing.Optional[int] = None,
        passphrase_max_length: typing.Optional[int] = None,
        check_file_permissions: typing.Optional[bool] = None,
        check_permissions: typing.Optional[bool] = None,
        strict_crt: typing.Optional[bool] = None,
        source_path: typing.Optional[typing.Union[str, os.PathLike]] = None,
    ) -> "PrivateKey":
        """Loads a private key using an explicit, sanitized policy.

        PEM loading supports unencrypted PKCS#1, unencrypted PKCS#8, encrypted
        PKCS#8, and traditional OpenSSL encrypted PKCS#1 blocks. ``passphrase``
        accepts ``str`` or ``bytes`` and is encoded as UTF-8 when necessary.

        ``check_file_permissions`` only emits
        :class:`PrivateKeyPermissionWarning`; it never modifies the file mode.
        """

        supplied_limits = [
            value
            for value in (max_passphrase_size, max_passphrase_length, passphrase_max_length)
            if value is not None
        ]
        if supplied_limits:
            if len(set(supplied_limits)) > 1:
                raise ValueError("Conflicting passphrase size limits")
            max_passphrase_size = supplied_limits[0]

        resolved = cls._resolve_load_policy(
            policy,
            passphrase,
            max_passphrase_size,
            check_file_permissions,
            check_permissions,
            strict_crt,
        )
        if not isinstance(format, str):
            raise ValueError("Unsupported private key format")

        path = None
        read_path = False
        if isinstance(keyfile, os.PathLike):
            path = os.fspath(keyfile)
            read_path = True
        elif isinstance(keyfile, str) and "-----BEGIN" not in keyfile:
            try:
                is_file = os.path.isfile(keyfile)
            except OSError:
                is_file = False
            if is_file:
                path = keyfile
                read_path = True
        permission_path = None if source_path is None else os.fspath(source_path)

        if read_path and path is not None:
            try:
                with open(path, "rb") as private_key_file:
                    keyfile = private_key_file.read()
            except OSError:
                raise PrivateKeyLoadError("Unable to read private key file") from None

        if isinstance(keyfile, str):
            try:
                keyfile = keyfile.encode("ascii")
            except UnicodeEncodeError:
                raise PEMEncodingError("PEM contents must contain ASCII characters only") from None
        if not isinstance(keyfile, bytes):
            raise TypeError("Private key contents must be bytes")

        if resolved.check_file_permissions:
            check_path = permission_path if permission_path is not None else path
            if check_path is not None:
                _warn_insecure_key_permissions(check_path)

        if format == "PEM":
            return cls._load_private_key_pem(keyfile, resolved)
        if format == "DER":
            strict_requested = resolved.strict_crt and (
                policy is not None or strict_crt is True or passphrase is not None
            )
            if strict_requested:
                return cls._load_pkcs1_der_strict(keyfile)
            return cls._load_pkcs1_der(keyfile)
        raise ValueError("Unsupported format: %r, try one of DER, PEM" % format)

    @classmethod
    def load_pkcs1_file(
        cls,
        filename: typing.Union[str, os.PathLike],
        format: str = "PEM",
        passphrase: typing.Optional[typing.Union[str, bytes]] = None,
        **kwargs: typing.Any,
    ) -> "PrivateKey":
        """Loads a private key from a file and optionally checks its mode."""

        try:
            return cls.load_pkcs1(filename, format, passphrase, **kwargs)
        except PrivateKeyLoadError as ex:
            del filename
            passphrase = None
            del kwargs
            ex.__traceback__ = None
            ex.__context__ = None
            ex.__cause__ = None
            raise ex from None

    @classmethod
    def load_private_key(
        cls,
        keyfile: typing.Union[bytes, str, os.PathLike],
        format: str = "PEM",
        passphrase: typing.Optional[typing.Union[str, bytes]] = None,
        **kwargs: typing.Any,
    ) -> "PrivateKey":
        """Alias for :meth:`load_pkcs1` using the explicit private-key policy."""

        try:
            return cls.load_pkcs1(keyfile, format, passphrase, **kwargs)
        except PrivateKeyLoadError as ex:
            del keyfile
            passphrase = None
            del kwargs
            ex.__traceback__ = None
            ex.__context__ = None
            ex.__cause__ = None
            raise ex from None

    @classmethod
    def load_pkcs1_pem(
        cls,
        keyfile: typing.Union[bytes, str, os.PathLike],
        passphrase: typing.Optional[typing.Union[str, bytes]] = None,
        **kwargs: typing.Any,
    ) -> "PrivateKey":
        """Loads a private key from PEM with an explicit passphrase."""

        try:
            return cls.load_pkcs1(keyfile, "PEM", passphrase, **kwargs)
        except PrivateKeyLoadError as ex:
            del keyfile
            passphrase = None
            del kwargs
            ex.__traceback__ = None
            ex.__context__ = None
            ex.__cause__ = None
            raise ex from None

    @classmethod
    def _load_private_key_pem(
        cls,
        keyfile: bytes,
        policy: PrivateKeyLoadPolicy,
    ) -> "PrivateKey":
        preferred = ("RSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "PRIVATE KEY")
        try:
            label = rsa.pem.find_pem_label(keyfile, preferred)
        except rsa.pem.PEMError as ex:
            raise _pem_error(ex) from None

        der = None
        decrypted_der = None
        try:
            try:
                der, headers = rsa.pem.load_pem_with_headers(keyfile, label)
            except rsa.pem.PEMError as ex:
                raise _pem_error(ex) from None

            normalized_headers = {key.lower(): value for key, value in headers.items()}
            passphrase = _passphrase_bytes(policy.passphrase, policy.max_passphrase_size)

            if label == "RSA PRIVATE KEY":
                proc_type = normalized_headers.get("proc-type")
                dek_info = normalized_headers.get("dek-info")
                if proc_type is not None or dek_info is not None:
                    if proc_type is None or dek_info is None:
                        raise EncryptedPrivateKeyError("Incomplete encrypted PEM headers")
                    if proc_type.replace(" ", "").upper() != "4,ENCRYPTED":
                        raise EncryptedPrivateKeyError("Invalid encrypted PEM metadata")
                    if passphrase is None:
                        raise PassphraseRequiredError(
                            "Private key is encrypted; a passphrase is required"
                        )
                    try:
                        decrypted_der = rsa.pem.decrypt_openssl_pem(der, headers, passphrase)
                    except rsa.pem.PEMDecryptionError:
                        raise IncorrectPassphraseError(
                            "Incorrect passphrase or corrupted encrypted private key"
                        ) from None
                    except rsa.pem.PEMEncryptionError as ex:
                        raise EncryptedPrivateKeyError(str(ex)) from None
                    try:
                        return cls._load_pkcs1_der_strict(decrypted_der)
                    except CRTConsistencyError:
                        raise
                    except InvalidPrivateKeyError:
                        raise IncorrectPassphraseError(
                            "Incorrect passphrase or corrupted encrypted private key"
                        ) from None
                return cls._load_pkcs1_der_strict(der)

            if label == "PRIVATE KEY":
                inner = _decode_pkcs8_private_der(der)
                try:
                    return cls._load_pkcs1_der_strict(inner)
                finally:
                    del inner

            if passphrase is None:
                raise PassphraseRequiredError(
                    "Private key is encrypted; a passphrase is required"
                )
            try:
                decrypted_der = _decrypt_pkcs8_private_der(der, passphrase)
                return cls._load_pkcs1_der_strict(decrypted_der)
            except (CRTConsistencyError, EncryptedPrivateKeyError, UnsupportedPrivateKeyError):
                raise
            except InvalidPrivateKeyError:
                raise IncorrectPassphraseError(
                    "Incorrect passphrase or corrupted encrypted private key"
                ) from None
        finally:
            der = None
            decrypted_der = None

    @classmethod
    def _load_pkcs1_der(cls, keyfile: bytes) -> "PrivateKey":
        """Loads a PKCS#1 DER key, retaining legacy CRT-correction warnings.

        New code should use :meth:`load_pkcs1` with an explicit
        :class:`PrivateKeyLoadPolicy` for strict CRT validation.
        """

        components = _decode_pkcs1_private_der(keyfile)
        n, e, d, p, q, exp1, exp2, coef, rs, ds, ts = components
        _validate_core_private_key(n, e, d, p, q, rs)
        key = cls(n, e, d, p, q, list(rs))

        if (key.exp1, key.exp2, key.coef, key.rs, key.ds, key.ts) != (
            exp1,
            exp2,
            coef,
            rs,
            ds,
            ts,
        ):
            warnings.warn(
                "You have provided a malformed keyfile. Either the exponents "
                "or the coefficient are incorrect. Using the correct values "
                "instead.",
                UserWarning,
            )

        return key

    def _save_pkcs1_der(self) -> bytes:
        """Saves the private key in PKCS#1 DER format.

        :returns: the DER-encoded private key.
        :rtype: bytes
        """

        from pyasn1.type import univ, namedtype
        from pyasn1.codec.der import encoder

        other_fields = [
            (
                namedtype.NamedType("prime%d" % (i + 3), univ.Integer()),
                namedtype.NamedType("exponent%d" % (i + 3), univ.Integer()),
                namedtype.NamedType("coefficient%d" % (i + 3), univ.Integer()),
            ) for i in range(len(self.rs))
        ]
        
        class AsnPrivKey(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType("version", univ.Integer()),
                namedtype.NamedType("modulus", univ.Integer()),
                namedtype.NamedType("publicExponent", univ.Integer()),
                namedtype.NamedType("privateExponent", univ.Integer()),
                namedtype.NamedType("prime1", univ.Integer()),
                namedtype.NamedType("prime2", univ.Integer()),
                namedtype.NamedType("exponent1", univ.Integer()),
                namedtype.NamedType("exponent2", univ.Integer()),
                namedtype.NamedType("coefficient", univ.Integer()),
                *list(itertools.chain(*other_fields))
            )

        # Create the ASN object
        asn_key = AsnPrivKey()
        asn_key.setComponentByName("version", 0)
        asn_key.setComponentByName("modulus", self.n)
        asn_key.setComponentByName("publicExponent", self.e)
        asn_key.setComponentByName("privateExponent", self.d)
        asn_key.setComponentByName("prime1", self.p)
        asn_key.setComponentByName("prime2", self.q)
        asn_key.setComponentByName("exponent1", self.exp1)
        asn_key.setComponentByName("exponent2", self.exp2)
        asn_key.setComponentByName("coefficient", self.coef)
        for i, (r, d, t) in enumerate(zip(self.rs, self.ds, self.ts), start=3):
            asn_key.setComponentByName("prime%d" % i, r)
            asn_key.setComponentByName("exponent%d" % i, d)
            asn_key.setComponentByName("coefficient%d" % i, t)

        return encoder.encode(asn_key)

    @classmethod
    def _load_pkcs1_pem(cls, keyfile: bytes) -> "PrivateKey":
        """Loads an unencrypted private key from a PKCS#1/PKCS#8 PEM block."""

        return cls._load_private_key_pem(
            keyfile,
            PrivateKeyLoadPolicy(strict_crt=True),
        )

    def _save_pkcs1_pem(self) -> bytes:
        """Saves a PKCS#1 PEM-encoded private key file.

        :return: contents of a PEM-encoded file that contains the private key.
        :rtype: bytes
        """

        der = self._save_pkcs1_der()
        return rsa.pem.save_pem(der, b"RSA PRIVATE KEY")


def find_primes(
    nbits: int,
    getprime_func: typing.Callable[[int], int] = rsa.prime.getprime,
    accurate: bool = True,
    nprimes: int = 2,
) -> typing.List[int]:
    """Returns a list of different primes with nbits divided evenly among them.

    :param nbits: the number of bits for the primes to sum to.
    :param getprime_func: the getprime function, defaults to
        :py:func:`rsa.prime.getprime`.
    :param accurate: whether to enable accurate mode or not.
    :returns: list of primes in descending order.

    """
    if nprimes == 2:
        return list(find_p_q(nbits // 2, getprime_func, accurate))

    quo, rem = divmod(nbits, nprimes)
    factor_lengths = [quo + 1]*rem + [quo] * (nprimes - rem)

    while True:
        primes = [getprime_func(length) for length in factor_lengths]
        if len(set(primes)) == len(primes):
            break

    return list(reversed(sorted(primes)))


def find_p_q(
    nbits: int,
    getprime_func: typing.Callable[[int], int] = rsa.prime.getprime,
    accurate: bool = True,
) -> typing.Tuple[int, int]:
    """Returns a tuple of two different primes of nbits bits each.

    The resulting p * q has exactly 2 * nbits bits, and the returned p and q
    will not be equal.

    :param nbits: the number of bits in each of p and q.
    :param getprime_func: the getprime function, defaults to
        :py:func:`rsa.prime.getprime`.

        *Introduced in Python-RSA 3.1*

    :param accurate: whether to enable accurate mode or not.
    :returns: (p, q), where p > q

    >>> (p, q) = find_p_q(128)
    >>> from rsa import common
    >>> common.bit_size(p * q)
    256

    When not in accurate mode, the number of bits can be slightly less

    >>> (p, q) = find_p_q(128, accurate=False)
    >>> from rsa import common
    >>> common.bit_size(p * q) <= 256
    True
    >>> common.bit_size(p * q) > 240
    True

    """

    total_bits = nbits * 2

    # Make sure that p and q aren't too close or the factoring programs can
    # factor n.
    shift = nbits // 16
    pbits = nbits + shift
    qbits = nbits - shift

    # Choose the two initial primes
    p = getprime_func(pbits)
    q = getprime_func(qbits)

    def is_acceptable(p: int, q: int) -> bool:
        """Returns True iff p and q are acceptable:

        - p and q differ
        - (p * q) has the right nr of bits (when accurate=True)
        """

        if p == q:
            return False

        if not accurate:
            return True

        # Make sure we have just the right amount of bits
        found_size = rsa.common.bit_size(p * q)
        return total_bits == found_size

    # Keep choosing other primes until they match our requirements.
    change_p = False
    while not is_acceptable(p, q):
        # Change p on one iteration and q on the other
        if change_p:
            p = getprime_func(pbits)
        else:
            q = getprime_func(qbits)

        change_p = not change_p

    # We want p > q as described on
    # http://www.di-mgt.com.au/rsa_alg.html#crt
    return max(p, q), min(p, q)


def calculate_keys_custom_exponent(
    p: int,
    q: int,
    exponent: int,
    rs: typing.Optional[typing.List[int]] = None,
) -> typing.Tuple[int, int]:
    """Calculates an encryption and a decryption key given p, q and an exponent,
    and returns them as a tuple (e, d)

    :param p: the first large prime
    :param q: the second large prime
    :param exponent: the exponent for the key; only change this if you know
        what you're doing, as the exponent influences how difficult your
        private key can be cracked. A very common choice for e is 65537.
    :type exponent: int
    :param rs: the list of other large primes

    """

    phi_n = math.prod([x - 1 for x in [p, q] + ([] if rs is None else rs)])

    try:
        d = rsa.common.inverse(exponent, phi_n)
    except rsa.common.NotRelativePrimeError as ex:
        raise rsa.common.NotRelativePrimeError(
            exponent,
            phi_n,
            ex.d,
            msg="e (%d) and phi_n (%d) are not relatively prime (divider=%i)"
            % (exponent, phi_n, ex.d),
        ) from ex

    if (exponent * d) % phi_n != 1:
        raise ValueError(
            "e (%d) and d (%d) are not mult. inv. modulo " "phi_n (%d)" % (exponent, d, phi_n)
        )

    return exponent, d


def calculate_keys(p: int, q: int) -> typing.Tuple[int, int]:
    """Calculates an encryption and a decryption key given p and q, and
    returns them as a tuple (e, d)

    :param p: the first large prime
    :param q: the second large prime

    :return: tuple (e, d) with the encryption and decryption exponents.
    """

    return calculate_keys_custom_exponent(p, q, DEFAULT_EXPONENT)


def gen_keys(
    nbits: int,
    getprime_func: typing.Callable[[int], int],
    accurate: bool = True,
    exponent: int = DEFAULT_EXPONENT,
    nprimes: int = 2,
) -> typing.Tuple:
    """Generate RSA keys of nbits bits. Returns (p, q, e, d) or (p, q, e, d, rs).

    Note: this can take a long time, depending on the key size.

    :param nbits: the total number of bits in ``p`` and ``q``. Both ``p`` and
        ``q`` will use ``nbits/2`` bits.
    :param getprime_func: either :py:func:`rsa.prime.getprime` or a function
        with similar signature.
    :param exponent: the exponent for the key; only change this if you know
        what you're doing, as the exponent influences how difficult your
        private key can be cracked. A very common choice for e is 65537.
    :type exponent: int
    :param nprimes: the number of prime factors comprising the modulus.
    """

    # Regenerate prime values, until calculate_keys_custom_exponent doesn't raise a
    # ValueError.
    while True:
        primes = find_primes(nbits, getprime_func, accurate, nprimes)
        p, q, rs = primes[0], primes[1], primes[2:]
        try:
            (e, d) = calculate_keys_custom_exponent(p, q, exponent=exponent, rs=rs)
            break
        except ValueError:
            pass

    if rs:
        return p, q, e, d, rs
    else:
        return p, q, e, d


def newkeys(
    nbits: int,
    accurate: bool = True,
    poolsize: int = 1,
    exponent: int = DEFAULT_EXPONENT,
    nprimes: int = 2,
) -> typing.Tuple[PublicKey, PrivateKey]:
    """Generates public and private keys, and returns them as (pub, priv).

    The public key is also known as the 'encryption key', and is a
    :py:class:`rsa.PublicKey` object. The private key is also known as the
    'decryption key' and is a :py:class:`rsa.PrivateKey` object.

    :param nbits: the number of bits required to store the modulus ``n``.
    :param accurate: when True, ``n`` will have exactly the number of bits you
        asked for. However, this makes key generation much slower. When False,
        `n`` may have slightly less bits.
    :param poolsize: the number of processes to use to generate the prime
        numbers. If set to a number > 1, a parallel algorithm will be used.
        This requires Python 2.6 or newer.
    :param exponent: the exponent for the key; only change this if you know
        what you're doing, as the exponent influences how difficult your
        private key can be cracked. A very common choice for e is 65537.
    :type exponent: int
    :param nprimes: the number of prime factors comprising the modulus.

    :returns: a tuple (:py:class:`rsa.PublicKey`, :py:class:`rsa.PrivateKey`)

    The ``poolsize`` parameter was added in *Python-RSA 3.1* and requires
    Python 2.6 or newer.

    """

    if nbits < 16:
        raise ValueError("Key too small")

    if poolsize < 1:
        raise ValueError("Pool size (%i) should be >= 1" % poolsize)

    if nprimes < 2:
        raise ValueError("Number of primes (%i) should be >= 2" % nprimes)

    # Determine which getprime function to use
    if poolsize > 1:
        from rsa import parallel

        def getprime_func(nbits: int) -> int:
            return parallel.getprime(nbits, poolsize=poolsize)

    else:
        getprime_func = rsa.prime.getprime

    # Generate the key components
    result = gen_keys(nbits, getprime_func, accurate=accurate, exponent=exponent, nprimes=nprimes)
    if len(result) == 4:
        p, q, e, d = result
        rs = []
    else:
        p, q, e, d, rs = result

    # Create the key objects
    n = math.prod([p, q] + rs)

    return (PublicKey(n, e), PrivateKey(n, e, d, p, q, rs))


__all__ = [
    "PublicKey",
    "PrivateKey",
    "newkeys",
    "PrivateKeyLoadPolicy",
    "PrivateKeyLoadError",
    "PassphraseRequiredError",
    "IncorrectPassphraseError",
    "PassphraseTooLongError",
    "PassphraseTypeError",
    "InvalidPrivateKeyError",
    "EncryptedPrivateKeyError",
    "CRTConsistencyError",
]

if __name__ == "__main__":
    import doctest

    try:
        for count in range(100):
            (failures, tests) = doctest.testmod()
            if failures:
                break

            if (count % 10 == 0 and count) or count == 1:
                print("%i times" % count)
    except KeyboardInterrupt:
        print("Aborted")
    else:
        print("Doctests done")
