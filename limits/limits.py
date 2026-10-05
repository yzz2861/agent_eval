""" """

from __future__ import annotations

from functools import total_ordering
from zoneinfo import ZoneInfo

from limits.typing import ClassVar, NamedTuple, cast


def safe_string(value: bytes | str | int | float) -> str:
    """
    normalize a byte/str/int or float to a str
    """

    if isinstance(value, bytes):
        return value.decode()

    return str(value)


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

    def key_for(self, *identifiers: bytes | str | int | float) -> str:
        """
        Constructs a key for the current limit and any additional
        identifiers provided.

        :param identifiers: a list of strings to append to the key
        :return: a string key identifying this resource with
         each identifier separated with a '/' delimiter.
        """
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


class CalendarWindowRateLimitItem(RateLimitItem):
    """
    Base class for rate limited resources aligned to calendar windows
    (natural days or months) in a specific IANA timezone, for use with
    :class:`limits.strategies.CalendarWindowRateLimiter`.

    Unlike :class:`RateLimitItem` the window is not a fixed number of
    seconds: all hits that fall in the same local calendar day or month
    share one window with explicit start/end boundaries, and the window
    expires at its end.

    :param amount: the rate limit amount
    :param timezone: an IANA timezone name (e.g. ``"Asia/Shanghai"``)
     the calendar window is aligned to. Defaults to ``"UTC"``.
    :param multiples: multiple of the calendar period
     (e.g. ``3`` for quarterly windows with
     :class:`RateLimitItemPerCalendarMonth`)
    :param namespace: category for the specific rate limit
    """

    __slots__ = ["timezone", "_tzinfo"]

    CALENDAR_PERIOD: ClassVar[str]
    """
    The calendar period this limit aligns to: ``day`` or ``month``
    """

    def __init__(
        self,
        amount: int,
        timezone: str = "UTC",
        multiples: int | None = 1,
        namespace: str = "LIMITER",
    ):
        super().__init__(amount, multiples, namespace)
        self.timezone = timezone
        self._tzinfo = ZoneInfo(timezone)

    @property
    def tzinfo(self) -> ZoneInfo:
        """
        The :class:`zoneinfo.ZoneInfo` of :attr:`timezone`
        """
        return self._tzinfo

    def get_expiry(self) -> int:
        raise NotImplementedError(
            "calendar window limits do not have a fixed expiry in seconds;"
            " use them with CalendarWindowRateLimiter"
        )

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, CalendarWindowRateLimitItem)
            and self.timezone == other.timezone
            and super().__eq__(other)
        )

    def __repr__(self) -> str:
        return (
            f"{self.amount} per {self.multiples} {self.GRANULARITY.name}"
            f" ({self.timezone})"
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.namespace,
                self.amount,
                self.multiples,
                self.GRANULARITY,
                self.timezone,
            )
        )


class RateLimitItemPerCalendarDay(CalendarWindowRateLimitItem):
    """
    per calendar day rate limited resource. The window is aligned to
    local midnight in :attr:`CalendarWindowRateLimitItem.timezone`.
    """

    GRANULARITY = Granularity(0, "calendar-day")
    """A calendar day (not a fixed number of seconds)"""

    CALENDAR_PERIOD = "day"


class RateLimitItemPerCalendarMonth(CalendarWindowRateLimitItem):
    """
    per calendar month rate limited resource. The window is aligned to
    local midnight of the first of the month in
    :attr:`CalendarWindowRateLimitItem.timezone`.
    """

    GRANULARITY = Granularity(0, "calendar-month")
    """A calendar month (not a fixed number of seconds)"""

    CALENDAR_PERIOD = "month"
