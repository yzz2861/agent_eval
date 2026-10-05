""" """

from __future__ import annotations

import math
from enum import Enum
from functools import total_ordering

from limits.typing import ClassVar, NamedTuple, cast


class KeyEncodingVersion(Enum):
    V1 = 1
    V2 = 2


KeyIdentifier = bytes | str | int | float


def safe_string(value: bytes | str | int | float) -> str:
    """
    normalize a byte/str/int or float to a str
    """

    if isinstance(value, bytes):
        return value.decode()

    return str(value)


def _version2_tlv(tag: str, value: bytes) -> str:
    return f"{tag}{len(value)}:{value.hex()}"


def _version2_scalar(tag: str, value: KeyIdentifier) -> str:
    if isinstance(value, bool):
        payload = b"1" if value else b"0"
        tag = "z"
    elif isinstance(value, int):
        payload = str(value).encode("ascii")
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("rate limit identifiers must have a finite value")
        payload = float(value).hex().encode("ascii")
    elif isinstance(value, str):
        payload = value.encode("utf-8")
    elif isinstance(value, bytes):
        payload = value
    else:
        raise TypeError("rate limit identifiers must be bytes, str, int, or float")

    return _version2_tlv(tag, payload)


def _version2_key(
    namespace: str,
    identifiers: tuple[KeyIdentifier, ...],
    amount: int,
    multiples: int,
    granularity: Granularity,
) -> str:
    if not isinstance(namespace, str):
        raise TypeError("rate limit namespace must be a string")

    encoded_identifiers = []
    for identifier in identifiers:
        if isinstance(identifier, bytes):
            tag = "b"
        elif isinstance(identifier, str):
            tag = "s"
        elif isinstance(identifier, bool):
            tag = "z"
        elif isinstance(identifier, float):
            tag = "f"
        else:
            tag = "i"
        encoded_identifiers.append(_version2_scalar(tag, identifier))

    fields = [
        _version2_tlv("n", namespace.encode("utf-8")),
        f"i{len(encoded_identifiers)}:{''.join(encoded_identifiers)}",
        _version2_scalar("a", amount),
        _version2_scalar("m", multiples),
        "g2:"
        + _version2_scalar("s", granularity.seconds)
        + _version2_tlv("n", granularity.name.encode("utf-8")),
    ]

    return f"limits.v2:{''.join(fields)}"


class Granularity(NamedTuple):
    seconds: int
    name: str


TIME_TYPES = dict(
    day=Granularity(60 * 60 * 24, "day"),
    month=Granularity(60 * 60 * 24 * 30, "month"),
    year=Granularity(60 * 60 * 24 * 30 * 12, "year"),
    hour=Granularity(60 * 60, "hour"),
    minute=Granularity(60, "minute"),
    second=Granularity(1, "second"),
)

GRANULARITIES: dict[str, type[RateLimitItem]] = {}


class RateLimitItemMeta(type):
    def __new__(
        cls,
        name: str,
        parents: tuple[type, ...],
        dct: dict[str, Granularity | list[str]],
    ) -> RateLimitItemMeta:
        if "__slots__" not in dct:
            dct["__slots__"] = []
        granularity = super().__new__(cls, name, parents, dct)

        if "GRANULARITY" in dct:
            GRANULARITIES[dct["GRANULARITY"][1]] = cast(
                type[RateLimitItem], granularity
            )

        return granularity


# pylint: disable=no-member
@total_ordering
class RateLimitItem(metaclass=RateLimitItemMeta):
    """
    defines a Rate limited resource which contains the characteristic
    namespace, amount and granularity multiples of the rate limiting window.

    :param amount: the rate limit amount
    :param multiples: multiple of the 'per' :attr:`GRANULARITY`
     (e.g. 'n' per 'm' seconds)
    :param namespace: category for the specific rate limit
    :param key_encoding_version: version of the storage key encoding
    """

    __slots__ = ["namespace", "amount", "multiples", "key_encoding_version"]

    GRANULARITY: ClassVar[Granularity]
    """
    A tuple describing the granularity of this limit as
    (number of seconds, name)
    """

    def __init__(
        self,
        amount: int,
        multiples: int | None = 1,
        namespace: str = "LIMITER",
        key_encoding_version: KeyEncodingVersion = KeyEncodingVersion.V1,
    ):
        if not isinstance(key_encoding_version, KeyEncodingVersion):
            raise TypeError("key encoding version must be a KeyEncodingVersion")
        self.namespace = namespace
        self.amount = int(amount)
        self.multiples = int(multiples or 1)
        self.key_encoding_version = key_encoding_version

    @classmethod
    def check_granularity_string(cls, granularity_string: str) -> bool:
        """
        Checks if this instance matches a *granularity_string*
        of type ``n per hour``, ``n per minute`` etc,
        by comparing with :attr:`GRANULARITY`

        """

        return granularity_string.lower() in {
            cls.GRANULARITY.name,
            f"{cls.GRANULARITY.name}s",  # allow plurals like days, hours etc.
        }

    def get_expiry(self) -> int:
        """
        :return: the duration the limit is enforced for in seconds.
        """

        return self.GRANULARITY.seconds * self.multiples

    def key_for(self, *identifiers: KeyIdentifier) -> str:
        """
        Constructs a key for the current limit and any additional
        identifiers provided.

        :param identifiers: bytes, strings, integers, or finite floats
         identifying this instance of the limit
        :return: a string key identifying this resource with
         each identifier separated with a '/' delimiter when using the
         legacy encoding.
        """
        if self.key_encoding_version is KeyEncodingVersion.V2:
            return _version2_key(
                self.namespace,
                identifiers,
                self.amount,
                self.multiples,
                self.GRANULARITY,
            )

        remainder = "/".join(
            [safe_string(k) for k in identifiers]
            + [
                safe_string(self.amount),
                safe_string(self.multiples),
                self.GRANULARITY.name,
            ]
        )
        return f"{self.namespace}/{remainder}"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RateLimitItem):
            return (
                self.amount == other.amount
                and self.GRANULARITY == other.GRANULARITY
                and self.multiples == other.multiples
            )
        return False

    def __repr__(self) -> str:
        return f"{self.amount} per {self.multiples} {self.GRANULARITY.name}"

    def __lt__(self, other: RateLimitItem) -> bool:
        return self.GRANULARITY.seconds < other.GRANULARITY.seconds

    def __hash__(self) -> int:
        return hash((self.namespace, self.amount, self.multiples, self.GRANULARITY))


class RateLimitItemPerYear(RateLimitItem):
    """
    per year rate limited resource.
    """

    GRANULARITY = TIME_TYPES["year"]
    """A year"""


class RateLimitItemPerMonth(RateLimitItem):
    """
    per month rate limited resource.
    """

    GRANULARITY = TIME_TYPES["month"]
    """A month"""


class RateLimitItemPerDay(RateLimitItem):
    """
    per day rate limited resource.
    """

    GRANULARITY = TIME_TYPES["day"]
    """A day"""


class RateLimitItemPerHour(RateLimitItem):
    """
    per hour rate limited resource.
    """

    GRANULARITY = TIME_TYPES["hour"]
    """An hour"""


class RateLimitItemPerMinute(RateLimitItem):
    """
    per minute rate limited resource.
    """

    GRANULARITY = TIME_TYPES["minute"]
    """A minute"""


class RateLimitItemPerSecond(RateLimitItem):
    """
    per second rate limited resource.
    """

    GRANULARITY = TIME_TYPES["second"]
    """A second"""
