"""
Calendar window computation.

Helpers to map a UTC instant to the calendar window (natural day or
month in a given IANA timezone) that contains it. All boundaries are
computed by converting local calendar midnights back to UTC through
:data:`zoneinfo.ZoneInfo`, so month lengths, leap years, DST
transitions and non-integral UTC offsets are handled by the tz
database instead of fixed second arithmetic.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, tzinfo
from typing import NamedTuple

CALENDAR_PERIODS = ("day", "month")

#: Local date used as the anchor for day windows with ``multiples > 1``
DAY_EPOCH = date(1970, 1, 1)


class CalendarWindow(NamedTuple):
    """
    A single calendar window aligned to a natural day or month
    in a specific timezone.
    """

    #: UTC epoch seconds at which the window starts (inclusive)
    start: float
    #: UTC epoch seconds at which the window ends (exclusive)
    end: float
    #: stable identifier of the window, e.g. ``2026-03-08`` or ``2026-03``
    key: str


def calendar_window(
    period: str, tz: tzinfo, at: float, multiples: int = 1
) -> CalendarWindow:
    """
    Compute the calendar window containing the instant ``at``.

    :param period: either ``"day"`` or ``"month"``
    :param tz: the timezone the calendar window is aligned to
    :param at: the instant to bucket, as UTC epoch seconds
    :param multiples: group this many consecutive periods into a single
     window (e.g. ``3`` months for quarterly windows). Day windows are
     anchored at 1970-01-01 (local) and month windows at January of
     year 1.
    :return: the :class:`CalendarWindow` containing ``at``
    """
    if multiples < 1:
        raise ValueError("multiples must be a positive integer")

    local = datetime.fromtimestamp(at, tz)

    if period == "day":
        index = (local.date() - DAY_EPOCH).days // multiples
        start_date = DAY_EPOCH + timedelta(days=index * multiples)
        end_date = start_date + timedelta(days=multiples)
        start_local = datetime(start_date.year, start_date.month, start_date.day)
        end_local = datetime(end_date.year, end_date.month, end_date.day)
        key = start_date.isoformat()
    elif period == "month":
        index = (local.year * 12 + local.month - 1) // multiples
        start_year, start_month = divmod(index * multiples, 12)
        end_year, end_month = divmod((index + 1) * multiples, 12)
        start_local = datetime(start_year, start_month + 1, 1)
        end_local = datetime(end_year, end_month + 1, 1)
        key = f"{start_year:04d}-{start_month + 1:02d}"
    else:
        raise ValueError(
            f"unknown calendar period: {period!r}"
            f" (expected one of {', '.join(CALENDAR_PERIODS)})"
        )

    return CalendarWindow(
        start_local.replace(tzinfo=tz).timestamp(),
        end_local.replace(tzinfo=tz).timestamp(),
        key,
    )
