import base64
import binascii
import hashlib
import re
import unicodedata
from typing import Any, Dict, Sequence, Set
from urllib.parse import parse_qsl, unquote, urlparse

from . import contrib  # noqa:F401
from .compat import random
from .hotp import HOTP as HOTP
from .otp import OTP as OTP
from .totp import TOTP as TOTP

#: Maximum allowed length of an otpauth provisioning URI in strict mode.
MAX_URI_LENGTH = 4096

#: Query parameters that may appear at most once in a strict otpauth URI.
_SINGLETON_PARAMETERS = frozenset(("secret", "algorithm", "digits", "period", "counter", "issuer"))

#: Unicode bidi formatting and other invisible control characters that must
#: not appear in issuer or account names in strict mode.
_FORBIDDEN_LABEL_CHARACTERS = frozenset(
    (
        "\u0000",  # NUL
        "\u200e",  # LRM
        "\u200f",  # RLM
        "\u202a",  # LRE
        "\u202b",  # RLE
        "\u202c",  # PDF
        "\u202d",  # LRO
        "\u202e",  # RLO
        "\u2066",  # LRI
        "\u2067",  # RLI
        "\u2068",  # FSI
        "\u2069",  # PDI
        "\u061c",  # ALM
    )
)

_BASE32_RE = re.compile(r"^[A-Z2-7]+=*$", re.IGNORECASE)
_INTEGER_RE = re.compile(r"^\d+$")


def _validate_label_text(value: str, field_name: str) -> str:
    if not value.strip():
        raise ValueError("%s must not be empty" % field_name)
    for character in value:
        if (
            character in ("\r", "\n")
            or unicodedata.category(character) == "Cc"
            or character in _FORBIDDEN_LABEL_CHARACTERS
        ):
            raise ValueError("%s contains an invalid control character" % field_name)
    return value


def _validate_base32_secret(secret: str) -> str:
    if not secret:
        raise ValueError("No secret found in URI")
    for character in secret:
        if unicodedata.category(character) == "Cc":
            raise ValueError("secret contains an invalid control character")
    if not _BASE32_RE.match(secret):
        raise ValueError("secret is not valid case-insensitive Base32")
    core = secret.rstrip("=")
    expected_padding = "=" * (-len(core) % 8)
    if secret != core and secret != core + expected_padding:
        raise ValueError("secret has incorrect Base32 padding")
    padded_secret = core + expected_padding
    try:
        decoded = base64.b32decode(padded_secret, casefold=True)
    except binascii.Error as error:
        raise ValueError("secret is not valid Base32: %s" % error)
    if len(decoded) < 1:
        raise ValueError("secret is too short")
    return secret


def _parse_non_negative_integer(value: str, field_name: str) -> int:
    if not _INTEGER_RE.match(value):
        raise ValueError("%s must be a non-negative integer" % field_name)
    return int(value)


def _parse_uri_strict(uri: str) -> OTP:
    if not isinstance(uri, str):
        raise ValueError("otpauth URI must be a string")
    if len(uri) > MAX_URI_LENGTH:
        raise ValueError("otpauth URI exceeds the maximum length of %d" % MAX_URI_LENGTH)

    parsed_uri = urlparse(uri)

    if parsed_uri.scheme != "otpauth":
        raise ValueError("Not an otpauth URI")
    # netloc must be exactly the OTP type: userinfo and a port are not part
    # of the Key URI format, and urlparse normalizes the host to lower case.
    if parsed_uri.netloc not in ("totp", "hotp") or parsed_uri.hostname != parsed_uri.netloc:
        raise ValueError("otpauth URI host must be totp or hotp")
    if parsed_uri.fragment:
        raise ValueError("otpauth URI must not contain a fragment")
    if not parsed_uri.path or not parsed_uri.path.startswith("/") or len(parsed_uri.path) < 2:
        raise ValueError("otpauth URI must contain a label")

    label = parsed_uri.path[1:]
    label_parts = label.split(":", 1)
    label_issuer = None
    if len(label_parts) == 1:
        name = _validate_label_text(unquote(label_parts[0]), "account name")
    else:
        label_issuer = _validate_label_text(unquote(label_parts[0]), "issuer")
        name = _validate_label_text(unquote(label_parts[1]), "account name")

    otp_data: Dict[str, Any] = {"name": name}
    if label_issuer is not None:
        otp_data["issuer"] = label_issuer

    seen_parameters: Set[str] = set()
    secret = None
    encoder = None
    counter = None

    for key, value in parse_qsl(parsed_uri.query, keep_blank_values=True):
        if key in _SINGLETON_PARAMETERS:
            if key in seen_parameters:
                raise ValueError("otpauth URI contains a duplicate %s parameter" % key)
            seen_parameters.add(key)

        if key == "secret":
            secret = value
        elif key == "issuer":
            query_issuer = _validate_label_text(value, "issuer")
            if label_issuer is not None and query_issuer != label_issuer:
                raise ValueError("If issuer is specified in both label and parameters, it should be equal.")
            otp_data["issuer"] = query_issuer
        elif key == "algorithm":
            normalized_algorithm = value.upper()
            if normalized_algorithm not in ("SHA1", "SHA256", "SHA512"):
                raise ValueError("Invalid value for algorithm, must be SHA1, SHA256 or SHA512")
            otp_data["digest"] = {
                "SHA1": hashlib.sha1,
                "SHA256": hashlib.sha256,
                "SHA512": hashlib.sha512,
            }[normalized_algorithm]
        elif key == "encoder":
            encoder = value
        elif key == "digits":
            parsed_digits = _parse_non_negative_integer(value, "digits")
            if parsed_digits not in (6, 7, 8):
                raise ValueError("Digits may only be 6, 7, or 8")
            otp_data["digits"] = parsed_digits
        elif key == "period":
            parsed_period = _parse_non_negative_integer(value, "period")
            if not 1 <= parsed_period <= 86400:
                raise ValueError("period must be between 1 and 86400")
            otp_data["interval"] = parsed_period
        elif key == "counter":
            counter = _parse_non_negative_integer(value, "counter")
            otp_data["initial_count"] = counter

    if secret is None:
        raise ValueError("No secret found in URI")
    _validate_base32_secret(secret)

    if parsed_uri.netloc == "hotp" and counter is None:
        raise ValueError("hotp otpauth URI must contain a counter parameter")

    if encoder == "steam":
        return contrib.Steam(secret, **otp_data)
    if parsed_uri.netloc == "totp":
        return TOTP(secret, **otp_data)
    return HOTP(secret, **otp_data)


def random_base32(length: int = 32, chars: Sequence[str] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") -> str:
    # Note: the otpauth scheme DOES NOT use base32 padding for secret lengths not divisible by 8.
    # Some third-party tools have bugs when dealing with such secrets.
    # We might consider warning the user when generating a secret of length not divisible by 8.
    if length < 32:
        raise ValueError("Secrets should be at least 160 bits")

    return "".join(random.choice(chars) for _ in range(length))


def random_hex(length: int = 40, chars: Sequence[str] = "ABCDEF0123456789") -> str:
    if length < 40:
        raise ValueError("Secrets should be at least 160 bits")
    return random_base32(length=length, chars=chars)


def parse_uri(uri: str, strict: bool = False) -> OTP:
    """
    Parses the provisioning URI for the OTP; works for either TOTP or HOTP.

    See also:
        https://github.com/google/google-authenticator/wiki/Key-Uri-Format

    :param uri: the hotp/totp URI to parse
    :param strict: when True, fully validate the URI against the Key URI
        format instead of applying the lenient legacy parsing rules
    :returns: OTP object
    """

    if strict:
        return _parse_uri_strict(uri)

    # Secret (to be filled in later)
    secret = None

    # Encoder (to be filled in later)
    encoder = None

    # Digits (to be filled in later)
    digits = None

    # Data we'll parse to the correct constructor
    otp_data: Dict[str, Any] = {}

    # Parse the URI structure first, then unquote individual components.
    # Unquoting the whole URI before splitting the label would turn an
    # encoded colon (%3A) inside the issuer or account name into a literal
    # ":" and mis-parse the issuer:account separator (see GitHub issue #174).
    parsed_uri = urlparse(uri)

    if parsed_uri.scheme != "otpauth":
        raise ValueError("Not an otpauth URI")

    # Parse issuer/accountname info. The label uses a literal ":" as the
    # issuer:account separator; a percent-encoded "%3A" is a colon that is
    # part of the issuer or account name, not a separator. Split on the
    # literal ":" while the components are still percent-encoded, then
    # unquote each component on its own.
    accountinfo_parts = re.split(":", parsed_uri.path[1:], maxsplit=1)
    if len(accountinfo_parts) == 1:
        otp_data["name"] = unquote(accountinfo_parts[0])
    else:
        otp_data["issuer"] = unquote(accountinfo_parts[0])
        otp_data["name"] = unquote(accountinfo_parts[1])

    # Parse values
    for key, value in parse_qsl(parsed_uri.query):
        if key == "secret":
            secret = value
        elif key == "issuer":
            if "issuer" in otp_data and otp_data["issuer"] is not None and otp_data["issuer"] != value:
                raise ValueError("If issuer is specified in both label and parameters, it should be equal.")
            otp_data["issuer"] = value
        elif key == "algorithm":
            if value == "SHA1":
                otp_data["digest"] = hashlib.sha1
            elif value == "SHA256":
                otp_data["digest"] = hashlib.sha256
            elif value == "SHA512":
                otp_data["digest"] = hashlib.sha512
            else:
                raise ValueError("Invalid value for algorithm, must be SHA1, SHA256 or SHA512")
        elif key == "encoder":
            encoder = value
        elif key == "digits":
            digits = int(value)
            otp_data["digits"] = digits
        elif key == "period":
            otp_data["interval"] = int(value)
        elif key == "counter":
            otp_data["initial_count"] = int(value)

    if encoder != "steam":
        if digits is not None and digits not in [6, 7, 8]:
            raise ValueError("Digits may only be 6, 7, or 8")

    if not secret:
        raise ValueError("No secret found in URI")

    # Create objects
    if encoder == "steam":
        return contrib.Steam(secret, **otp_data)
    if parsed_uri.netloc == "totp":
        return TOTP(secret, **otp_data)
    elif parsed_uri.netloc == "hotp":
        return HOTP(secret, **otp_data)

    raise ValueError("Not a supported OTP type")
