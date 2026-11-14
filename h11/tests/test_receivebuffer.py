import re
from typing import Tuple

import pytest

from .._receivebuffer import ReceiveBuffer


def test_receivebuffer() -> None:
    b = ReceiveBuffer()
    assert not b
    assert len(b) == 0
    assert bytes(b) == b""

    b += b"123"
    assert b
    assert len(b) == 3
    assert bytes(b) == b"123"

    assert bytes(b) == b"123"

    assert b.maybe_extract_at_most(2) == b"12"
    assert b
    assert len(b) == 1
    assert bytes(b) == b"3"

    assert bytes(b) == b"3"

    assert b.maybe_extract_at_most(10) == b"3"
    assert bytes(b) == b""

    assert b.maybe_extract_at_most(10) is None
    assert not b

    ################################################################
    # maybe_extract_until_next
    ################################################################

    b += b"123\n456\r\n789\r\n"

    assert b.maybe_extract_next_line() == b"123\n456\r\n"
    assert bytes(b) == b"789\r\n"

    assert b.maybe_extract_next_line() == b"789\r\n"
    assert bytes(b) == b""

    b += b"12\r"
    assert b.maybe_extract_next_line() is None
    assert bytes(b) == b"12\r"

    b += b"345\n\r"
    assert b.maybe_extract_next_line() is None
    assert bytes(b) == b"12\r345\n\r"

    # here we stopped at the middle of b"\r\n" delimiter

    b += b"\n6789aaa123\r\n"
    assert b.maybe_extract_next_line() == b"12\r345\n\r\n"
    assert b.maybe_extract_next_line() == b"6789aaa123\r\n"
    assert b.maybe_extract_next_line() is None
    assert bytes(b) == b""

    ################################################################
    # maybe_extract_lines
    ################################################################

    b += b"123\r\na: b\r\nfoo:bar\r\n\r\ntrailing"
    lines = b.maybe_extract_lines()
    assert lines == [b"123", b"a: b", b"foo:bar"]
    assert bytes(b) == b"trailing"

    assert b.maybe_extract_lines() is None

    b += b"\r\n\r"
    assert b.maybe_extract_lines() is None

    assert b.maybe_extract_at_most(100) == b"trailing\r\n\r"
    assert not b

    # Empty body case (as happens at the end of chunked encoding if there are
    # no trailing headers, e.g.)
    b += b"\r\ntrailing"
    assert b.maybe_extract_lines() == []
    assert bytes(b) == b"trailing"


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(
            (
                b"HTTP/1.1 200 OK\r\n",
                b"Content-type: text/plain\r\n",
                b"Connection: close\r\n",
                b"\r\n",
                b"Some body",
            ),
            id="with_crlf_delimiter",
        ),
        pytest.param(
            (
                b"HTTP/1.1 200 OK\n",
                b"Content-type: text/plain\n",
                b"Connection: close\n",
                b"\n",
                b"Some body",
            ),
            id="with_lf_only_delimiter",
        ),
        pytest.param(
            (
                b"HTTP/1.1 200 OK\n",
                b"Content-type: text/plain\r\n",
                b"Connection: close\n",
                b"\n",
                b"Some body",
            ),
            id="with_mixed_crlf_and_lf",
        ),
    ],
)
def test_receivebuffer_for_invalid_delimiter(data: Tuple[bytes]) -> None:
    b = ReceiveBuffer()

    for line in data:
        b += line

    lines = b.maybe_extract_lines()

    assert lines == [
        b"HTTP/1.1 200 OK",
        b"Content-type: text/plain",
        b"Connection: close",
    ]
    assert bytes(b) == b"Some body"


def test_receivebuffer_many_tiny_fragments_linear_memory() -> None:
    # A stream of small pipelined requests fed in one byte at a time must
    # stay O(n) overall: the consumed prefix has to be reclaimed instead of
    # copying the whole already-read history on every fragment.
    request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    b = ReceiveBuffer()
    iterations = 50
    for _ in range(iterations):
        extracted_lines = []
        for ch in request:
            b += bytes([ch])
            line = b.maybe_extract_next_line()
            while line is not None:
                extracted_lines.append(line)
                line = b.maybe_extract_next_line()
            lines = b.maybe_extract_lines()
            if lines is not None:
                assert lines == [b"GET / HTTP/1.1", b"Host: example.com"]
        assert b"".join(extracted_lines) == request
    assert not b
    # The backing storage must have been compacted, not grown without bound.
    assert len(b._data) < 4 * len(request)  # type: ignore[attr-defined]


def test_receivebuffer_compaction_resets_start_offset() -> None:
    # Once the backing storage is large enough and the consumed prefix
    # dominates it, the next append reclaims the prefix and resets the offset.
    b = ReceiveBuffer()
    b += b"p" * 128
    assert b.maybe_extract_at_most(128) == b"p" * 128
    assert not b
    assert b._start == 128  # type: ignore[attr-defined]
    b += b"q"
    assert b._start == 0  # type: ignore[attr-defined]
    assert bytes(b) == b"q"


def test_receivebuffer_extract_at_most_is_zero_copy() -> None:
    b = ReceiveBuffer()
    b += b"abcdef"

    out = b.maybe_extract_at_most(3)
    assert type(out) is memoryview
    assert out == b"abc"
    assert len(b) == 3
    assert bytes(b) == b"def"
    # The view keeps pointing at the original backing bytes.
    assert b"abc" == bytes(out)

    assert b.maybe_extract_at_most(10) == b"def"
    assert b.maybe_extract_at_most(1) is None


def test_receivebuffer_half_frames_wait_for_more_data() -> None:
    # Incomplete frames report "need more data" (None) and keep every byte
    # that has arrived so far; nothing is released or treated as an error.
    b = ReceiveBuffer()
    b += b"GET / HTTP/1.1\r"
    assert b.maybe_extract_next_line() is None
    assert bytes(b) == b"GET / HTTP/1.1\r"
    b += b"\nX"
    assert b.maybe_extract_next_line() == b"GET / HTTP/1.1\r\n"
    assert bytes(b) == b"X"

    # Blank-line separator split across every possible fragment boundary.
    for split in range(4):
        frame = b"a: b\r\n\r\nbody"
        head, tail = frame[:split], frame[split:]
        b = ReceiveBuffer()
        if head:
            b += head
            assert b.maybe_extract_lines() is None
            assert bytes(b) == head
        b += tail
        assert b.maybe_extract_lines() == [b"a: b"]
        assert bytes(b) == b"body"

    # A partial fixed-length read leaves the remainder pending.
    b = ReceiveBuffer()
    b += b"1234"
    assert b.maybe_extract_at_most(2) == b"12"
    assert b.maybe_extract_at_most(2) == b"34"
    assert b.maybe_extract_at_most(1) is None


def test_receivebuffer_overlapping_pipelined_frames_are_retained() -> None:
    # Two complete requests plus a third half-frame arrive together. Bytes
    # belonging to frames that have not been fully parsed yet must never be
    # released while earlier frames are consumed.
    first = b"GET /1 HTTP/1.1\r\nContent-Length: 5\r\n\r\n12345"
    second = b"GET /2 HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc"
    third_half = b"GET /3 HTTP/1.1\r\nX: "
    b = ReceiveBuffer()
    b += first + second + third_half

    assert b.maybe_extract_lines() == [
        b"GET /1 HTTP/1.1",
        b"Content-Length: 5",
    ]
    assert b.maybe_extract_at_most(5) == b"12345"

    assert b.maybe_extract_lines() == [
        b"GET /2 HTTP/1.1",
        b"Content-Length: 3",
    ]
    assert b.maybe_extract_at_most(3) == b"abc"

    # The third request is still a half-frame and stays fully buffered.
    assert b.maybe_extract_lines() is None
    assert bytes(b) == third_half
    b += b"y\r\n\r\n"
    assert b.maybe_extract_lines() == [b"GET /3 HTTP/1.1", b"X: y"]
    assert not b


def test_receivebuffer_delimiter_straddles_compaction_boundary() -> None:
    # Drain enough prefix bytes to force a compaction, with the next line
    # separator split right across the compaction point.
    b = ReceiveBuffer()
    prefix = b"a" * 100
    b += prefix
    assert b.maybe_extract_at_most(len(prefix)) == prefix
    assert not b

    b += b"partial-li"
    assert b.maybe_extract_next_line() is None
    b += b"ne\r"
    assert b.maybe_extract_next_line() is None
    b += b"\nnext\r\n"
    assert b.maybe_extract_next_line() == b"partial-line\r\n"
    assert b.maybe_extract_next_line() == b"next\r\n"
    assert b.maybe_extract_next_line() is None
    assert not b


def test_receivebuffer_compact_with_outstanding_view() -> None:
    # A zero-copy view handed to a caller stays valid even when later appends
    # have to reclaim the consumed prefix out from under it.
    b = ReceiveBuffer()
    b += b"x" * 128
    held = b.maybe_extract_at_most(64)
    assert held is not None
    assert bytes(held) == b"x" * 64

    # Consume the rest and then push enough data to trigger compaction while
    # the first view is still exported.
    rest = b.maybe_extract_at_most(64)
    assert rest is not None and bytes(rest) == b"x" * 64
    b += b"y" * 128
    assert bytes(b) == b"y" * 128
    assert b.maybe_extract_at_most(128) == b"y" * 128
    # The outstanding view is unchanged and still readable.
    assert bytes(held) == b"x" * 64
