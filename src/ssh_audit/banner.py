"""
   The MIT License (MIT)

   Copyright (C) 2017 Andris Raugulis (moo@arthepsy.eu)

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.
"""
import re
import socket
import time

# pylint: disable=unused-import
from typing import Dict, List, Set, Sequence, Tuple, Iterable, Callable, Optional, Union, Any  # noqa: F401

from ssh_audit.utils import Utils


class Banner:
    # Hard bounds applied while a banner is still being read, so a hostile or
    # broken server can never make us buffer unbounded amounts of data.
    MAX_LINE_BYTES = 1024       # Max bytes in a single banner/header line.
    MAX_TOTAL_BYTES = 4096      # Max bytes buffered across all lines.
    MAX_LINES = 32              # Max non-empty lines before an SSH banner.
    READ_TIMEOUT = 5.0          # Max seconds to wait for a complete banner.
    # Field length bounds shared with software.py; they keep the software
    # recognition regexes from being fed attacker-controlled long strings.
    MAX_SOFTWARE_LEN = 128
    MAX_COMMENT_LEN = 512

    # CSI (ESC [ ... final byte) and OSC (ESC ] ... BEL/ST) terminal sequences.
    _RX_CSI = re.compile(r'\x1b\[[\x20-\x3f]*[\x40-\x7e]')
    _RX_OSC = re.compile(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)')
    _RX_C0 = re.compile(r'[\x00-\x1f\x7f]')

    _RXP, _RXR = r'SSH-\d\.\s*?\d+', r'(-\s*([^\s]*)(?:\s+(.*))?)?'
    RX_PROTOCOL = re.compile(re.sub(r'\\d(\+?)', r'(\\d\g<1>)', _RXP))
    RX_BANNER = re.compile(r'^({0}(?:(?:-{0})*)){1}$'.format(_RXP, _RXR))

    def __init__(self, protocol: Tuple[int, int], software: Optional[str], comments: Optional[str], valid_ascii: bool, raw: Optional[str] = None) -> None:
        self.__protocol = protocol
        self.__software = software
        self.__comments = comments
        self.__valid_ascii = valid_ascii
        self.__raw = raw

    @property
    def protocol(self) -> Tuple[int, int]:
        return self.__protocol

    @property
    def software(self) -> Optional[str]:
        return self.__software

    @property
    def comments(self) -> Optional[str]:
        return self.__comments

    @property
    def valid_ascii(self) -> bool:
        return self.__valid_ascii

    @property
    def raw(self) -> Optional[str]:
        '''The original, un-sanitized line as received from the server.'''
        return self.__raw

    @property
    def escaped_raw(self) -> str:
        '''The original line with every terminal control character escaped.'''
        return self.escape(self.__raw if self.__raw is not None else str(self))

    def __str__(self) -> str:
        r = 'SSH-{}.{}'.format(self.protocol[0], self.protocol[1])
        if self.software is not None:
            r += '-{}'.format(self.software)
        if bool(self.comments):
            r += ' {}'.format(self.comments)
        return r

    def __repr__(self) -> str:
        p = '{}.{}'.format(self.protocol[0], self.protocol[1])
        r = 'protocol={}'.format(p)
        if self.software is not None:
            r += ', software={}'.format(self.software)
        if bool(self.comments):
            r += ', comments={}'.format(self.comments)
        return '<{}({})>'.format(self.__class__.__name__, r)

    @classmethod
    def escape(cls, line: str) -> str:
        '''Escapes terminal control characters so the result can be printed or
        logged without a malicious banner being able to rewrite the terminal.'''
        escapes = {
            0: '\\0', 7: '\\a', 8: '\\b', 9: '\\t', 10: '\\n', 11: '\\v',
            12: '\\f', 13: '\\r', 27: '\\e',
        }
        out = []
        for char in line:
            code = ord(char)
            if code in escapes:
                out.append(escapes[code])
            elif code < 0x20 or code == 0x7f or 0x80 <= code <= 0x9f:
                out.append('\\x{:02x}'.format(code))
            else:
                out.append(char)
        return ''.join(out)

    @classmethod
    def _strip_controls(cls, line: str) -> str:
        '''Removes CSI/OSC sequences and any remaining C0 control characters.
        NUL bytes are rejected instead of removed.'''
        if '\x00' in line:
            raise InvalidBannerError('banner contains NUL byte')
        line = cls._RX_CSI.sub('', line)
        line = cls._RX_OSC.sub('', line)
        return cls._RX_C0.sub('', line)

    @classmethod
    def parse(cls, banner: str) -> Optional['Banner']:
        '''Backwards-compatible parsing: returns None when the line is not an
        SSH banner or is malformed/over-limit.  Use parse_strict() to obtain
        the specific failure reason.'''
        try:
            return cls.parse_strict(banner)
        except BannerError:
            return None

    @classmethod
    def parse_strict(cls, banner: str) -> 'Banner':
        '''Parses a single banner line, raising a typed BannerError on failure:
        NotAnSshBannerError, InvalidBannerError or BannerLimitError.'''
        if len(banner.encode('utf-8', 'surrogatepass')) > cls.MAX_LINE_BYTES:
            raise BannerLimitError('banner line exceeds {} bytes'.format(cls.MAX_LINE_BYTES))

        raw = banner
        safe_banner = cls._strip_controls(banner)
        if not safe_banner.lstrip().upper().startswith('SSH-'):
            raise NotAnSshBannerError('line is not an SSH banner')

        valid_ascii = Utils.is_print_ascii(banner)
        ascii_banner = Utils.to_print_ascii(safe_banner)
        mx = cls.RX_BANNER.match(ascii_banner)
        if mx is None:
            raise InvalidBannerError('malformed SSH banner version format')
        protocol = min(re.findall(cls.RX_PROTOCOL, mx.group(1)))
        protocol = (int(protocol[0]), int(protocol[1]))
        software = (mx.group(3) or '').strip() or None
        if software is None and (mx.group(2) or '').startswith('-'):
            software = ''
        comments = (mx.group(4) or '').strip() or None
        if comments is not None:
            comments = re.sub(r'\s+', ' ', comments)
            if len(comments) > cls.MAX_COMMENT_LEN:
                raise BannerLimitError('banner comment exceeds {} characters'.format(cls.MAX_COMMENT_LEN))
        if software is not None and len(software) > cls.MAX_SOFTWARE_LEN:
            raise BannerLimitError('software field exceeds {} characters'.format(cls.MAX_SOFTWARE_LEN))
        return cls(protocol, software, comments, valid_ascii, raw)


class BannerError(Exception):
    '''Base class for every banner parsing/reading failure.'''


class NotAnSshBannerError(BannerError):
    '''The received data does not contain an SSH banner.'''


class InvalidBannerError(BannerError):
    '''An SSH-prefixed line violates the SSH version string format (or
    contains forbidden content such as NUL bytes).'''


class BannerLimitError(BannerError):
    '''A streaming resource budget (line/total bytes, line count, timeout) or
    a field length limit was exceeded.'''


class BannerEncodingError(BannerError):
    '''The banner stream contains bytes that are not valid UTF-8.'''


class BannerReader:
    '''Streaming, budget-bounded reader for an SSH version exchange.

    Data is pulled through a recv callback that must return the next bytes
    chunk, b'' on clean end-of-stream, or None when the read would block
    (retryable).  Hard limits on line length, total buffered bytes, line count
    and wait time guarantee memory usage stays bounded even if the peer never
    sends a newline.
    '''

    def __init__(self,
                 recv: Callable[[], Optional[bytes]],
                 max_line_bytes: int = Banner.MAX_LINE_BYTES,
                 max_total_bytes: int = Banner.MAX_TOTAL_BYTES,
                 max_lines: int = Banner.MAX_LINES,
                 timeout: float = Banner.READ_TIMEOUT,
                 time_func: Callable[[], float] = time.monotonic,
                 sleep_func: Callable[[float], None] = time.sleep) -> None:
        self.__recv = recv
        self.__max_line_bytes = max_line_bytes
        self.__max_total_bytes = max_total_bytes
        self.__max_lines = max_lines
        self.__timeout = timeout
        self.__time_func = time_func
        self.__sleep_func = sleep_func
        self.__buffer = b''
        self.__total_bytes = 0
        self.__line_count = 0
        self.__stream_finished = False
        self.__header: List[str] = []

    @property
    def header(self) -> List[str]:
        return self.__header

    @property
    def leftover(self) -> bytes:
        '''Bytes belonging to later SSH packets that arrived with the banner.'''
        return self.__buffer

    def __decode_line(self, raw_line: bytes) -> str:
        try:
            return raw_line.decode('utf-8')
        except UnicodeDecodeError as e:
            raise BannerEncodingError('banner contains invalid UTF-8: {}'.format(e)) from e

    def read(self) -> Banner:
        deadline = self.__time_func() + self.__timeout
        while True:
            raw_line = self.__read_line(deadline)
            if raw_line is None:
                # Stream finished with no more data to process.
                raise NotAnSshBannerError('connection closed without an SSH banner')

            if raw_line.endswith(b'\r'):
                raw_line = raw_line[:-1]
            if len(raw_line.strip()) == 0:
                continue
            line = self.__decode_line(raw_line)

            self.__line_count += 1
            if self.__line_count > self.__max_lines:
                raise BannerLimitError('banner stream exceeds {} lines'.format(self.__max_lines))

            if not line.lstrip().upper().startswith('SSH-'):
                self.__header.append(Banner.escape(line))
                continue

            return Banner.parse_strict(line)

    def __read_line(self, deadline: float) -> Optional[bytes]:
        '''Returns the next raw line, or None when the stream is fully consumed.'''
        while True:
            newline_pos = self.__buffer.find(b'\n')
            if newline_pos >= 0:
                raw_line = self.__buffer[:newline_pos]
                self.__buffer = self.__buffer[newline_pos + 1:]
                if len(raw_line) > self.__max_line_bytes:
                    raise BannerLimitError('banner line exceeds {} bytes'.format(self.__max_line_bytes))
                return raw_line

            if self.__stream_finished:
                if len(self.__buffer) == 0:
                    return None
                raw_line = self.__buffer
                self.__buffer = b''
                if len(raw_line) > self.__max_line_bytes:
                    raise BannerLimitError('banner line exceeds {} bytes'.format(self.__max_line_bytes))
                return raw_line

            self.__fill(deadline)

    def __fill(self, deadline: float) -> None:
        if self.__stream_finished:
            return
        if len(self.__buffer) >= self.__max_line_bytes:
            raise BannerLimitError('banner line exceeds {} bytes without a newline'.format(self.__max_line_bytes))
        if self.__total_bytes >= self.__max_total_bytes:
            raise BannerLimitError('banner stream exceeds {} bytes'.format(self.__max_total_bytes))

        remaining = max(0.0, deadline - self.__time_func())
        if remaining <= 0.0:
            raise BannerLimitError('timed out after {} seconds waiting for banner'.format(self.__timeout))

        try:
            chunk = self.__recv()
        except (TimeoutError, OSError) as e:
            if isinstance(e, (TimeoutError, socket.timeout)) or self.__time_func() >= deadline:
                raise BannerLimitError('timed out after {} seconds waiting for banner'.format(self.__timeout)) from e
            raise NotAnSshBannerError('connection error while reading banner: {}'.format(e)) from e

        if chunk is None:
            # Read would block (EAGAIN/EWOULDBLOCK): yield briefly and retry
            # until the timeout budget is exhausted.
            self.__sleep_func(min(0.01, max(0.0, deadline - self.__time_func())))
            return
        if len(chunk) == 0:
            self.__stream_finished = True
            return

        self.__total_bytes += len(chunk)
        if self.__total_bytes > self.__max_total_bytes:
            raise BannerLimitError('banner stream exceeds {} bytes'.format(self.__max_total_bytes))
        self.__buffer += chunk
        if len(self.__buffer) > self.__max_line_bytes and self.__buffer.find(b'\n') < 0:
            raise BannerLimitError('banner line exceeds {} bytes without a newline'.format(self.__max_line_bytes))
