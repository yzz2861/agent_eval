from __future__ import annotations

from datetime import datetime, timedelta, timezone as datetime_timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from limits.typing import Literal

CalendarWindowUnit = Literal["day", "month"]


def get_timezone(timezone: str | ZoneInfo) -> ZoneInfo:
    if isinstance(timezone, ZoneInfo):
        return timezone
    if isinstance(timezone, datetime_timezone):
        raise ValueError("fixed UTC offsets are not IANA time zones")
    try:
        return ZoneInfo(timezone)
    except (TypeError, ValueError, ZoneInfoNotFoundError) as exception:
        raise ValueError(f"invalid IANA time zone: {timezone!r}") from exception


def get_calendar_window(
    timestamp: float, zone: ZoneInfo, unit: CalendarWindowUnit
) -> tuple[float, float]:
    current = datetime.fromtimestamp(timestamp, tz=zone)

    if unit == "day":
        start_local = current.replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0,
            fold=0,
        )
        end_local = start_local + timedelta(days=1)
    elif unit == "month":
        start_local = current.replace(
            day=1,
            hour=0,
            minute=0,
            second=0,
            microsecond=0,
            fold=0,
        )
        month = current.month + 1
        year = current.year
        if month == 13:
            month = 1
            year += 1
        end_local = current.replace(
            year=year,
            month=month,
            day=1,
            hour=0,
            minute=0,
            second=0,
            microsecond=0,
            fold=0,
        )
    else:
        raise ValueError(f"unsupported calendar window unit: {unit!r}")

    return start_local.timestamp(), end_local.timestamp()


def calendar_window_key(
    key: str, start: float, zone: ZoneInfo, unit: CalendarWindowUnit
) -> str:
    return f"{key}|calendar|{unit}|{zone.key}|{start!r}"
