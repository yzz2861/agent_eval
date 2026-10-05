""" """

from __future__ import annotations

from functools import total_ordering

from limits.keys import DEFAULT_KEY_ENCODING, KeyEncoding, encode_key
from limits.keys import safe_string as safe_string
from limits.typing import ClassVar, NamedTuple, cast


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
    """

    __slots__ = ["namespace", "amount", "multiples"]

    GRANULARITY: ClassVar[Granularity]
    """
    A tuple describing the granularity of this limit as
    (number of seconds, name)
    """

    def __init__(
        self, amount: int, multiples: int | None = 1, namespace: str = "LIMITER"
    ):
        self.namespace = namespace
        self.amount = int(amount)
        self.multiples = int(multiples or 1)

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

    def key_for(
        self,
        *identifiers: bytes | str | int | float,
        encoding: KeyEncoding | None = None,
    ) -> str:
        """
        Constructs a key for the current limit and any additional
        identifiers provided.

        :param identifiers: a list of strings to append to the key
        :param encoding: the key encoding version to use. The default
         ``v1`` encoding separates each identifier with a '/' delimiter
         and is kept for backwards compatibility. The ``v2`` encoding
         preserves the number, types and boundaries of all key
         components (namespace, identifiers, amount, multiples and
         granularity) and rejects values without a stable
         representation. See :mod:`limits.keys` for details.
        :return: a string key identifying this resource
        """
        return encode_key(
            encoding or DEFAULT_KEY_ENCODING,
            self.namespace,
            identifiers,
            self.amount,
            self.multiples,
            self.GRANULARITY.name,
        )

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
