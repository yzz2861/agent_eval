from __future__ import annotations

import os

from email.utils import parsedate_to_datetime
from secrets import token_hex
from typing import TYPE_CHECKING, NamedTuple

from sanic.exceptions import (
    HeaderNotFound,
    InvalidHeader,
    InvalidRangeType,
    RangeNotSatisfiable,
)


if TYPE_CHECKING:
    from sanic import Request


MAX_RANGES = 100
MAX_MULTIPART_OVERHEAD = 8192


class ByteRange(NamedTuple):
    start: int
    end: int

    @property
    def size(self) -> int:
        return self.end - self.start + 1


class ContentRangeHandler:
    """Parse and process the incoming request headers to extract the content range information.

    Args:
        request (Request): The incoming request object.
        stats (os.stat_result): The stats of the file being served.
    """  # noqa: E501

    __slots__ = (
        "boundary",
        "content_type",
        "end",
        "headers",
        "media_type",
        "multipart",
        "overhead",
        "ranges",
        "size",
        "start",
        "total",
    )

    def __init__(
        self,
        request: Request,
        stats: os.stat_result,
        *,
        content_type: str | None = None,
    ) -> None:
        self.total = stats.st_size
        range_header = request.headers.getone("range", None)
        if range_header is None:
            raise HeaderNotFound("Range Header Not Found")
        unit, separator, value = range_header.partition("=")
        unit = unit.strip()
        value = value.strip()
        if unit != "bytes" or not separator or not value:
            raise InvalidRangeType(
                "{} is not a valid Range Type".format(unit), self
            )

        try:
            if_range = request.headers.getone("if-range", None)
        except KeyError:
            if_range = None
        if if_range is not None and not self._if_range_matches(
            if_range.strip(), stats
        ):
            raise HeaderNotFound("Range Header Not Found")

        raw_ranges = [part.strip() for part in value.split(",")]
        if len(raw_ranges) > MAX_RANGES:
            raise InvalidHeader("Too many byte ranges")

        ranges: list[ByteRange] = []
        for raw_range in raw_ranges:
            requested_range = self._parse_range(raw_range)
            if requested_range is not None:
                ranges.append(requested_range)

        if not ranges:
            raise RangeNotSatisfiable(
                "Invalid for Content Range parameters", self
            )

        ranges.sort()
        merged_ranges: list[ByteRange] = []
        for requested_range in ranges:
            if not merged_ranges:
                merged_ranges.append(requested_range)
                continue

            previous_start, previous_end = merged_ranges[-1]
            start, end = requested_range
            if start <= previous_end + 1:
                merged_ranges[-1] = ByteRange(
                    previous_start, max(previous_end, end)
                )
            else:
                merged_ranges.append(requested_range)

        self.ranges = tuple(merged_ranges)
        self.size = sum(
            requested_range.size for requested_range in self.ranges
        )
        first_range = self.ranges[0]
        self.start = first_range.start
        self.end = first_range.end
        self.multipart = len(self.ranges) > 1
        self.boundary = ""
        self.overhead = 0
        self.media_type = content_type or "application/octet-stream"
        self.content_type = self.media_type

        self.headers = {
            "Content-Length": str(self._content_length(content_type)),
        }
        if not self.multipart:
            self.headers["Content-Range"] = (
                f"bytes {self.start}-{self.end}/{self.total}"
            )
        else:
            self.headers["Content-Type"] = self.content_type

    def _parse_range(self, raw_range: str) -> ByteRange | None:
        if not raw_range:
            raise RangeNotSatisfiable(
                "Invalid for Content Range parameters", self
            )

        start_text, separator, end_text = raw_range.partition("-")
        if not separator or "-" in end_text:
            raise RangeNotSatisfiable(
                "Invalid for Content Range parameters", self
            )

        try:
            start = int(start_text) if start_text else None
        except ValueError:
            raise RangeNotSatisfiable(
                "'{}' is invalid for Content Range".format(start_text),
                self,
            )
        if start is not None and (not start_text.isdigit() or start < 0):
            raise RangeNotSatisfiable(
                "'{}' is invalid for Content Range".format(start_text),
                self,
            )
        try:
            end = int(end_text) if end_text else None
        except ValueError:
            raise RangeNotSatisfiable(
                "'{}' is invalid for Content Range".format(end_text),
                self,
            )
        if end is not None and not end_text.isdigit():
            raise RangeNotSatisfiable(
                "'{}' is invalid for Content Range".format(end_text),
                self,
            )

        if start is not None and end is not None:
            if start < 0 or end < 0 or start > end:
                return None
            if start >= self.total:
                return None
            return ByteRange(start, min(end, self.total - 1))

        if start is not None:
            if start < 0 or start >= self.total:
                return None
            return ByteRange(start, self.total - 1)

        if end is not None:
            if end <= 0:
                return None
            start = max(0, self.total - end)
            end = self.total - 1
            if start > end:
                return None
            return ByteRange(start, end)

        raise RangeNotSatisfiable("Invalid for Content Range parameters", self)

    def _content_length(self, content_type: str | None) -> int:
        if not self.multipart:
            return self.size

        self.boundary = token_hex(16)
        self.content_type = f"multipart/byteranges; boundary={self.boundary}"
        self.media_type = content_type or "application/octet-stream"
        media_type = self.media_type
        boundary = self.boundary.encode("ascii")
        self.overhead = 0

        for index, requested_range in enumerate(self.ranges):
            part_header = (
                (b"\r\n--" if index else b"--") + boundary + b"\r\n"
                b"Content-Type: " + media_type.encode("utf-8") + b"\r\n"
                b"Content-Range: bytes "
                + (
                    f"{requested_range.start}-{requested_range.end}/"
                    f"{self.total}\r\n\r\n"
                ).encode("ascii")
            )
            self.overhead += len(part_header)

        self.overhead += len(b"\r\n--" + boundary + b"--\r\n")
        if self.overhead > MAX_MULTIPART_OVERHEAD:
            raise InvalidHeader("Byte range response overhead is too large")

        return self.size + self.overhead

    @staticmethod
    def _if_range_matches(value: str, stats: os.stat_result) -> bool:
        if not value:
            return False

        if value.startswith('"') or value.startswith('W/"'):
            if value.startswith("W/"):
                return False
            etag = f'"{stats.st_size:x}-{stats.st_mtime_ns:x}"'
            return value == etag

        try:
            if_date = parsedate_to_datetime(value)
            return int(if_date.timestamp()) == int(stats.st_mtime)
        except (TypeError, ValueError, OverflowError):
            return False

    def __bool__(self):
        return self.size > 0
