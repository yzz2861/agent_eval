from __future__ import annotations

import os
import secrets

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING, NamedTuple

from sanic.exceptions import (
    BadRequest,
    HeaderNotFound,
    InvalidRangeType,
    RangeNotSatisfiable,
)
from sanic.models.protocol_types import Range


if TYPE_CHECKING:
    from sanic import Request


MAX_RANGES = 50
MAX_MULTIPART_OVERHEAD = 4096


class ByteRange(NamedTuple):
    start: int
    end: int


def if_range_matches(request: Request, stats: os.stat_result) -> bool:
    value = request.headers.getone("if-range", None)
    if value is None:
        return True

    if value.startswith(('"', "W/")):
        return False

    try:
        requested = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return False

    if requested.tzinfo is None:
        requested = requested.replace(tzinfo=timezone.utc)

    last_modified = datetime.fromtimestamp(
        stats.st_mtime, tz=timezone.utc
    ).replace(microsecond=0)
    return requested >= last_modified


class ContentRangeHandler(Range):
    """Parse, normalize, merge, and budget byte-range requests."""

    __slots__ = (
        "start",
        "end",
        "size",
        "total",
        "ranges",
        "boundary",
        "multipart",
        "media_type",
        "headers",
    )

    def __init__(
        self,
        request: Request,
        stats: os.stat_result,
        content_type: str | None = None,
    ) -> None:
        self.total = stats.st_size
        self.ranges: list[tuple[int, int]] = []
        self.boundary: str | None = None
        self.multipart = False
        self.media_type = content_type
        self.start = None
        self.end = None

        _range = request.headers.getone("range", None)
        if _range is None:
            raise HeaderNotFound("Range Header Not Found")

        unit, _, value = (part.strip() for part in _range.partition("="))
        if unit != "bytes":
            raise InvalidRangeType(
                "{} is not a valid Range Type".format(unit), self
            )

        range_specs = [spec.strip() for spec in value.split(",")]
        if len(range_specs) > MAX_RANGES:
            raise BadRequest("Too many byte ranges")

        for range_spec in range_specs:
            self._parse_range(range_spec)

        if not self.ranges:
            raise RangeNotSatisfiable(
                "Invalid for Content Range parameters", self
            )

        self.ranges.sort()
        merged = [self.ranges[0]]
        for start, end in self.ranges[1:]:
            previous_start, previous_end = merged[-1]
            if start <= previous_end + 1:
                merged[-1] = ByteRange(previous_start, max(previous_end, end))
            else:
                merged.append(ByteRange(start, end))
        self.ranges = merged

        self.size = sum(end - start + 1 for start, end in self.ranges)

        if len(self.ranges) == 1:
            self.start, self.end = self.ranges[0]
            self.headers = {
                "Content-Length": str(self.size),
                "Content-Range": "bytes %s-%s/%s"
                % (self.start, self.end, self.total),
            }
            return

        self.multipart = True
        self.boundary = f"sanic-{secrets.token_hex(16)}"
        overhead = self._multipart_overhead(content_type)
        if overhead > MAX_MULTIPART_OVERHEAD:
            raise BadRequest("Byte range response is too fragmented")

        self.headers = {
            "Content-Length": str(self.size + overhead),
            "Content-Type": (
                f"multipart/byteranges; boundary={self.boundary}"
            ),
        }

    def _parse_range(self, range_spec: str) -> None:
        start_b, separator, end_b = range_spec.partition("-")
        start_b = start_b.strip()
        end_b = end_b.strip()

        if separator != "-" or (not start_b and not end_b):
            raise RangeNotSatisfiable(
                "Invalid for Content Range parameters", self
            )

        try:
            start = self._parse_int(start_b) if start_b else None
        except ValueError:
            raise RangeNotSatisfiable(
                "'{}' is invalid for Content Range".format(start_b), self
            )
        try:
            end = self._parse_int(end_b) if end_b else None
        except ValueError:
            raise RangeNotSatisfiable(
                "'{}' is invalid for Content Range".format(end_b), self
            )

        if start is not None and end is not None:
            if start > end or start >= self.total:
                return
            end = min(end, self.total - 1)
        elif start is not None:
            if start >= self.total:
                return
            end = self.total - 1
        else:
            if end is None or end <= 0:
                return
            start = max(0, self.total - end)
            end = self.total - 1

        self.ranges.append(ByteRange(start, end))

    @staticmethod
    def _parse_int(value: str) -> int:
        if not value.isascii() or not value.isdigit():
            raise ValueError(value)
        return int(value)

    def _part_header(
        self,
        byte_range: ByteRange | tuple[int, int],
        content_type: str | None,
    ) -> bytes:
        lines = [f"--{self.boundary}"]
        if content_type:
            lines.append(f"Content-Type: {content_type}")
        lines.extend(
            (
                f"Content-Range: bytes {byte_range[0]}-"
                f"{byte_range[1]}/{self.total}",
                "",
                "",
            )
        )
        return "\r\n".join(lines).encode("ascii", errors="surrogateescape")

    def part_header(
        self,
        start: int,
        end: int,
        content_type: str | None,
    ) -> bytes:
        return self._part_header(ByteRange(start, end), content_type)

    def _multipart_overhead(self, content_type: str | None) -> int:
        final_boundary = f"--{self.boundary}--\r\n".encode("ascii")
        return sum(
            len(self._part_header(byte_range, content_type)) + 2
            for byte_range in self.ranges
        ) + len(final_boundary)

    def __bool__(self):
        return hasattr(self, "size") and self.size > 0
