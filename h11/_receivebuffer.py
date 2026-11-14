import re
import sys
from typing import List, Optional, Union

__all__ = ["ReceiveBuffer"]


# Operations we want to support:
# - find next \r\n or \r\n\r\n (\n or \n\n are also acceptable),
#   or wait until there is one
# - read at-most-N bytes
#
# Goals:
# - on average, do this fast
# - worst case, do this in O(n) where n is the number of bytes processed,
#   even when the peer sends many tiny fragments that are consumed a few
#   bytes at a time (a stream of small pipelined requests, for example)
#
# Strategy:
# - keep a single bytearray as backing storage, plus a logical start offset;
#   "consuming" bytes only advances that offset instead of shifting or copying
#   the whole remaining buffer
# - maybe_extract_at_most hands out a zero-copy memoryview over the backing
#   bytearray instead of a copied bytearray
# - the consumed prefix is reclaimed lazily (only once it makes up at least
#   half of the backing storage), so each appended byte is still amortized
#   O(1). If a zero-copy view is still referencing the buffer, we copy the
#   live tail into a fresh bytearray rather than resizing in place
# - the separator search cursors track logical positions, so already-scanned
#   bytes are not rescanned after an append or a compaction
blank_line_regex = re.compile(b"\n\r?\n", re.MULTILINE)

# Don't bother reclaiming a consumed prefix from very small backing buffers;
# the copy would cost as much as it saves and keeps the hot path cheap.
_MIN_COMPACT_SIZE = 64


class ReceiveBuffer:
    def __init__(self) -> None:
        self._data = bytearray()
        # Logical index 0 lives at self._data[self._start].
        self._start = 0
        # Search cursors, expressed as logical indices into the live region.
        self._next_line_search = 0
        self._multiple_lines_search = 0

    def __iadd__(self, byteslike: Union[bytes, bytearray]) -> "ReceiveBuffer":
        # Reclaim the consumed prefix before appending once it dominates the
        # backing storage, so appends stay amortized O(1) per byte instead
        # of repeatedly copying the entire history (O(n^2) overall).
        if (
            self._start
            and len(self._data) >= _MIN_COMPACT_SIZE
            and self._start * 2 >= len(self._data)
        ):
            self._compact()
        try:
            self._data += byteslike
        except BufferError:
            # A zero-copy view returned to a caller is still exporting the
            # backing buffer, so it cannot be resized in place. Rebuild a
            # private copy of the live region and append to that instead;
            # the old buffer stays alive to keep the outstanding view valid.
            self._compact()
            self._data += byteslike
        return self

    def __bool__(self) -> bool:
        return self._start < len(self._data)

    def __len__(self) -> int:
        return len(self._data) - self._start

    # for @property unprocessed_data
    def __bytes__(self) -> bytes:
        return bytes(self._data[self._start :])

    def _compact(self) -> None:
        """Shift the still-unprocessed bytes back to index zero."""
        if self._start == 0:
            return
        try:
            del self._data[: self._start]
        except BufferError:
            # An exported zero-copy view blocks in-place resizing; copy the
            # live tail into a fresh buffer and leave the old one behind for
            # any outstanding view.
            self._data = bytearray(self._data[self._start :])
        self._start = 0

    def _consume(self, count: int) -> None:
        """Mark the first *count* logical bytes as processed."""
        self._start += count
        # Previous search positions now point into the consumed prefix, so any
        # subsequent search has to start at the new logical beginning.
        self._next_line_search = 0
        self._multiple_lines_search = 0

    def _extract(self, count: int) -> bytearray:
        # Extracting a copy of an initial slice of the live data.
        out = bytearray(self._data[self._start : self._start + count])
        self._consume(count)
        return out

    def maybe_extract_at_most(self, count: int) -> Optional[memoryview]:
        """
        Extract a fixed number of bytes from the buffer.
        """
        if self._start == len(self._data):
            return None
        end = min(self._start + count, len(self._data))
        # Zero-copy: return a view over the backing buffer rather than a copy.
        out = memoryview(self._data)[self._start : end]
        self._consume(end - self._start)
        return out

    def maybe_extract_next_line(self) -> Optional[bytearray]:
        """
        Extract the first line, if it is completed in the buffer.
        """
        # Only search in buffer space that we've not already looked at.
        search_start_index = self._start + max(0, self._next_line_search - 1)
        partial_idx = self._data.find(b"\r\n", search_start_index)

        if partial_idx == -1:
            self._next_line_search = len(self)
            return None

        # + 2 is to compensate len(b"\r\n")
        idx = partial_idx + 2 - self._start

        return self._extract(idx)

    def maybe_extract_lines(self) -> Optional[List[bytearray]]:
        """
        Extract everything up to the first blank line, and return a list of lines.
        """
        # Handle the case where we have an immediate empty line.
        if self._data[self._start : self._start + 1] == b"\n":
            self._consume(1)
            return []

        if self._data[self._start : self._start + 2] == b"\r\n":
            self._consume(2)
            return []

        # Only search in buffer space that we've not already looked at.
        match = blank_line_regex.search(
            self._data, self._start + self._multiple_lines_search
        )
        if match is None:
            self._multiple_lines_search = max(0, len(self) - 2)
            return None

        # Truncate the buffer and return it.
        idx = match.span(0)[-1] - self._start
        out = self._extract(idx)
        lines = out.split(b"\n")

        for line in lines:
            if line.endswith(b"\r"):
                del line[-1]

        assert lines[-2] == lines[-1] == b""

        del lines[-2:]

        return lines

    # In theory we should wait until `\r\n` before starting to validate
    # incoming data. However it's interesting to detect (very) invalid data
    # early given they might not even contain `\r\n` at all (hence only
    # timeout will get rid of them).
    # This is not a 100% effective detection but more of a cheap sanity check
    # allowing for early abort in some useful cases.
    # This is especially interesting when peer is messing up with HTTPS and
    # sent us a TLS stream where we were expecting plain HTTP given all
    # versions of TLS so far start handshake with a 0x16 message type code.
    def is_next_line_obviously_invalid_request_line(self) -> bool:
        try:
            # HTTP header line must not contain non-printable characters
            # and should not start with a space
            return self._data[self._start] < 0x21
        except IndexError:
            return False
