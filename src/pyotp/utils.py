import datetime
import math
import unicodedata
from hmac import compare_digest
from typing import Dict, Optional, Union
from urllib.parse import quote, urlencode, urlparse

# Epoch-second range that datetime.datetime can represent. Numeric inputs
# outside it are almost always millisecond/nanosecond timestamps passed where
# seconds were expected; rejecting them prevents silently jumping to a timecode
# far in the future or past.
MIN_EPOCH_SECONDS = int(datetime.datetime.min.replace(tzinfo=datetime.timezone.utc).timestamp())
MAX_EPOCH_SECONDS = int(datetime.datetime.max.replace(tzinfo=datetime.timezone.utc).timestamp())


def normalize_timestamp(for_time: Union[int, float]) -> int:
    """
    Normalize a numeric Unix timestamp to whole epoch seconds.

    Integers are treated as timestamps in seconds and returned unchanged.
    Floats are truncated toward zero (matching the historical ``int(for_time)``
    behavior); the fractional second is dropped rather than rounded. Callers
    needing different rounding must round the value themselves before passing
    it in.

    Millisecond or nanosecond timestamps are not scaled: they fall outside the
    range representable by :class:`datetime.datetime` and raise ``ValueError``
    so that they cannot silently produce a wrong timecode. Booleans and
    non-numeric values raise ``TypeError``.

    :param for_time: Unix timestamp in seconds
    :returns: whole epoch seconds
    """
    if isinstance(for_time, bool) or not isinstance(for_time, (int, float)):
        raise TypeError(
            "for_time must be a datetime.datetime, an integer epoch-second timestamp, or a float epoch-second timestamp"
        )
    if isinstance(for_time, float):
        if math.isnan(for_time) or math.isinf(for_time):
            raise ValueError("for_time timestamp must be a finite number of seconds since the epoch")
        for_time = int(for_time)
    if for_time < MIN_EPOCH_SECONDS or for_time > MAX_EPOCH_SECONDS:
        raise ValueError(
            "for_time timestamp is outside the representable datetime range; timestamps must be given in seconds "
            "since the epoch (millisecond or nanosecond inputs must be scaled down before use)"
        )
    return for_time


def build_uri(
    secret: str,
    name: str,
    initial_count: Optional[int] = None,
    issuer: Optional[str] = None,
    algorithm: Optional[str] = None,
    digits: Optional[int] = None,
    period: Optional[int] = None,
    **kwargs,
) -> str:
    """
    Returns the provisioning URI for the OTP; works for either TOTP or HOTP.

    This can then be encoded in a QR Code and used to provision the Google
    Authenticator app.

    For module-internal use.

    See also:
        https://github.com/google/google-authenticator/wiki/Key-Uri-Format

    :param secret: the hotp/totp secret used to generate the URI
    :param name: name of the account
    :param initial_count: starting counter value, defaults to None.
        If none, the OTP type will be assumed as TOTP.
    :param issuer: the name of the OTP issuer; this will be the
        organization title of the OTP entry in Authenticator
    :param algorithm: the algorithm used in the OTP generation.
    :param digits: the length of the OTP generated code.
    :param period: the number of seconds the OTP generator is set to
        expire every code.
    :param kwargs: other query string parameters to include in the URI
    :returns: provisioning uri
    """
    # initial_count may be 0 as a valid param
    is_initial_count_present = initial_count is not None

    # Handling values different from defaults
    is_algorithm_set = algorithm is not None and algorithm != "sha1"
    is_digits_set = digits is not None and digits != 6
    is_period_set = period is not None and period != 30

    otp_type = "hotp" if is_initial_count_present else "totp"
    base_uri = "otpauth://{0}/{1}?{2}"

    url_args: Dict[str, Union[None, int, str]] = {"secret": secret}

    label = quote(name)
    if issuer is not None:
        label = quote(issuer) + ":" + label
        url_args["issuer"] = issuer

    if is_initial_count_present:
        url_args["counter"] = initial_count
    if is_algorithm_set:
        url_args["algorithm"] = algorithm.upper()  # type: ignore
    if is_digits_set:
        url_args["digits"] = digits
    if is_period_set:
        url_args["period"] = period
    for k, v in kwargs.items():
        if not isinstance(v, str):
            raise ValueError("All otpauth uri parameters must be strings")
        if k == "image":
            image_uri = urlparse(v)
            if image_uri.scheme != "https" or not image_uri.netloc or not image_uri.path:
                raise ValueError("{} is not a valid url".format(image_uri))
        url_args[k] = v

    uri = base_uri.format(otp_type, label, urlencode(url_args).replace("+", "%20"))
    return uri


def strings_equal(s1: str, s2: str) -> bool:
    """
    Timing-attack resistant string comparison.

    Normal comparison using == will short-circuit on the first mismatching
    character. This avoids that by scanning the whole string, though we
    still reveal to a timing attack whether the strings are the same
    length.
    """
    s1 = unicodedata.normalize("NFKC", s1)
    s2 = unicodedata.normalize("NFKC", s2)
    return compare_digest(s1.encode("utf-8"), s2.encode("utf-8"))
