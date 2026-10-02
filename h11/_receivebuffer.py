import re
import sys
from typing import List, Optional, Union

from ._util import LocalProtocolError

__all__ = ["ReceiveBuffer"]


# Operations we want to support:
# - find next \r\n or \r\n\r\n (\n or \n\n are also acceptable),
#   or wait until there is one
# - read at-most-N bytes
# Goals:
# - on average, do this fast
# - worst case, do this in O(n) where n is the number of bytes processed
# Plan:
# - store bytearray, offset, how far we've searched for a separator token
# - use the how-far-we've-searched data to avoid rescanning
# - while doing a stream of uninterrupted processing, advance offset instead
#   of constantly copying
# WARNING:
# - I haven't benchmarked or profiled any of this yet.
#
# Note that starting in Python 3.4, deleting the initial n bytes from a
# bytearray is amortized O(n), thanks to some excellent work by Antoine
# Martin:
#
#     https://bugs.python.org/issue19087
#
# This means that if we only supported 3.4+, we could get rid of the code here
# involving self._start and self.compress, because it's doing exactly the same
# thing that bytearray now does internally.
#
# BUT unfortunately, we still support 2.7, and reading short segments out of a
# long buffer MUST be O(bytes read) to avoid DoS issues, so we can't actually
# delete this code. Yet:
#
#     https://pythonclock.org/
#
# (Two things to double-check first though: make sure PyPy also has the
# optimization, and benchmark to make sure it's a win, since we do have a
# slightly clever thing where we delay calling compress() until we've
# processed a whole event, which could in theory be slightly more efficient
# than the internal bytearray support.)
blank_line_regex = re.compile(b"\n\r?\n", re.MULTILINE)


class ReceiveBuffer:
    def __init__(self, strict: bool = False) -> None:
        # When strict is True, line-oriented framing data (request/status
        # lines, header fields, chunk headers/trailers) is only accepted when
        # terminated by the canonical CRLF sequence, and obsolete line
        # folding (RFC 7230 section 3.2.4) is rejected.
        #
        # In this mode we also validate each new fragment of framing data as
        # it arrives, rather than waiting for a complete line or header
        # block. This means an error is raised immediately when the offending
        # byte becomes visible -- even if a CRLF happens to be split across
        # two receive_data() calls -- without buffering an arbitrarily large
        # message first.
        self.strict = strict
        self._data = bytearray()
        self._next_line_search = 0
        self._multiple_lines_search = 0
        # Offset up to which the framing data has been strict-checked.
        self._strict_checked = 0

    def __iadd__(self, byteslike: Union[bytes, bytearray]) -> "ReceiveBuffer":
        self._data += byteslike
        return self

    def __bool__(self) -> bool:
        return bool(len(self))

    def __len__(self) -> int:
        return len(self._data)

    # for @property unprocessed_data
    def __bytes__(self) -> bytes:
        return bytes(self._data)

    def _extract(self, count: int) -> bytearray:
        # extracting an initial slice of the data buffer and return it
        out = self._data[:count]
        del self._data[:count]

        self._next_line_search = 0
        self._multiple_lines_search = 0
        # All remaining data is unchecked; an empty trailing CRLF of one
        # framing block is the start of the next one.
        self._strict_checked = 0

        return out

    def _maybe_raise_for_strict_line_endings(
        self, end: Optional[int] = None
    ) -> None:
        """Incrementally reject bare LF and obs-fold in framing data.

        Only bytes that have arrived since the previous successful check are
        examined, with one byte of lookbehind so a CRLF split across
        receive_data() calls is not mistaken for a bare LF.

        ``end`` optionally limits the check to the first ``end`` bytes
        (e.g. a completed line); otherwise the whole buffered prefix is
        checked, which is only valid while we are reading framing data.
        """
        if not self.strict:
            return
        if end is None:
            end = len(self._data)
        if end <= self._strict_checked:
            return
        # One byte of lookbehind: a CR already accepted on its own may be
        # completed by the LF in the new fragment.
        start = self._strict_checked - 1 if self._strict_checked else 0
        data = self._data
        index = start
        while index < end:
            if data[index] == 0x0A and (
                index == 0 or data[index - 1] != 0x0D
            ):
                raise LocalProtocolError(
                    "illegal line ending: expected CRLF, got bare LF"
                )
            # obs-fold: CRLF immediately followed by SP/HTAB starts a
            # continuation line.
            if (
                data[index] in (0x20, 0x09)
                and index >= 2
                and data[index - 2] == 0x0D
                and data[index - 1] == 0x0A
            ):
                raise LocalProtocolError(
                    "illegal header line: obsolete line folding is not allowed"
                )
            index += 1
        self._strict_checked = end

    def maybe_extract_at_most(self, count: int) -> Optional[bytearray]:
        """
        Extract a fixed number of bytes from the buffer.
        """
        out = self._data[:count]
        if not out:
            return None

        return self._extract(count)

    def maybe_extract_next_line(self) -> Optional[bytearray]:
        """
        Extract the first line, if it is completed in the buffer.
        """
        # Only search in buffer space that we've not already looked at.
        search_start_index = max(0, self._next_line_search - 1)
        partial_idx = self._data.find(b"\r\n", search_start_index)

        if partial_idx == -1:
            self._next_line_search = len(self._data)
            # No completed line yet -- validate everything that has arrived
            # so far, so a bare LF is reported immediately.
            self._maybe_raise_for_strict_line_endings()
            return None

        # + 2 is to compensate len(b"\r\n")
        idx = partial_idx + 2

        self._maybe_raise_for_strict_line_endings(idx)
        return self._extract(idx)

    def maybe_extract_lines(self) -> Optional[List[bytearray]]:
        """
        Extract everything up to the first blank line, and return a list of lines.
        """
        if self.strict:
            # A header block must begin with a proper line; a bare LF here
            # is an illegal (empty) request/status line, not a valid blank
            # line terminator.
            self._maybe_raise_for_strict_line_endings(1)

        # Handle the case where we have an immediate empty line.
        if self._data[:1] == b"\n":
            self._extract(1)
            return []

        if self._data[:2] == b"\r\n":
            self._extract(2)
            return []

        # Only search in buffer space that we've not already looked at.
        match = blank_line_regex.search(self._data, self._multiple_lines_search)
        if match is None:
            self._multiple_lines_search = max(0, len(self._data) - 2)
            # No complete header block yet -- validate the buffered prefix
            # so that bare LFs and obs-fold are detected immediately
            # instead of after the whole (possibly large) message arrives.
            self._maybe_raise_for_strict_line_endings()
            return None

        # Truncate the buffer and return it.
        idx = match.span(0)[-1]

        self._maybe_raise_for_strict_line_endings(idx)
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
            return self._data[0] < 0x21
        except IndexError:
            return False
