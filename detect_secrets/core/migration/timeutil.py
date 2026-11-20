from __future__ import annotations

from datetime import datetime
from datetime import timezone


def parse_timestamp(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    try:
        moment = datetime.fromisoformat(normalized)
    except ValueError as e:
        raise ValueError(
            "{} is not a valid ISO 8601 timestamp".format(value),
        ) from e
    if moment.tzinfo is None:
        raise ValueError("{} is missing a timezone offset".format(value))
    return moment.astimezone(timezone.utc)


def format_timestamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)
