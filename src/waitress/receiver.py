##############################################################################
#
# Copyright (c) 2001, 2002 Zope Foundation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""Data Chunk Receiver"""

from waitress.rfc7230 import (
    CHUNK_EXT_RE,
    FORBIDDEN_TRAILER_FIELDS,
    HEADER_FIELD_RE,
    ONLY_HEXDIG_RE,
)
from waitress.utilities import BadRequest, RequestHeaderFieldsTooLarge

# Limits for the trailer section of a chunked request body. They keep a
# client from exhausting memory or header parsing effort after the request
# body itself has already been fully buffered.
MAX_TRAILER_SIZE = 65536
MAX_TRAILER_LINE_SIZE = 1024
MAX_TRAILER_FIELDS = 100


class FixedStreamReceiver:
    # See IStreamConsumer
    completed = False
    error = None

    def __init__(self, cl, buf):
        self.remain = cl
        self.buf = buf

    def __len__(self):
        return self.buf.__len__()

    def received(self, data):
        "See IStreamConsumer"
        rm = self.remain

        if rm < 1:
            self.completed = True  # Avoid any chance of spinning

            return 0
        datalen = len(data)

        if rm <= datalen:
            self.buf.append(data[:rm])
            self.remain = 0
            self.completed = True

            return rm
        else:
            self.buf.append(data)
            self.remain -= datalen

            return datalen

    def getfile(self):
        return self.buf.getfile()

    def getbuf(self):
        return self.buf


class ChunkedReceiver:
    chunk_remainder = 0
    validate_chunk_end = False
    control_line = b""
    chunk_end = b""
    all_chunks_received = False
    trailer_buffer = b""
    trailers = ()
    completed = False
    error = None

    def __init__(
        self,
        buf,
        max_trailer_size=MAX_TRAILER_SIZE,
        max_trailer_line_size=MAX_TRAILER_LINE_SIZE,
        max_trailer_fields=MAX_TRAILER_FIELDS,
    ):
        self.buf = buf
        self.max_trailer_size = max_trailer_size
        self.max_trailer_line_size = max_trailer_line_size
        self.max_trailer_fields = max_trailer_fields
        self.trailer_fields = []
        self.trailer_size = 0

    def __len__(self):
        return self.buf.__len__()

    def received(self, s):
        # Returns the number of bytes consumed.

        if self.completed:
            return 0
        orig_size = len(s)

        while s:
            rm = self.chunk_remainder

            if rm > 0:
                # Receive the remainder of a chunk.
                to_write = s[:rm]
                self.buf.append(to_write)
                written = len(to_write)
                s = s[written:]

                self.chunk_remainder -= written

                if self.chunk_remainder == 0:
                    self.validate_chunk_end = True
            elif self.validate_chunk_end:
                s = self.chunk_end + s

                pos = s.find(b"\r\n")

                if pos < 0 and len(s) < 2:
                    self.chunk_end = s
                    s = b""
                else:
                    self.chunk_end = b""

                    if pos == 0:
                        # Chop off the terminating CR LF from the chunk
                        s = s[2:]
                    else:
                        self.error = BadRequest("Chunk not properly terminated")
                        self.all_chunks_received = True

                    # Always exit this loop
                    self.validate_chunk_end = False
            elif not self.all_chunks_received:
                # Receive a control line.
                s = self.control_line + s
                pos = s.find(b"\r\n")

                if pos < 0:
                    # Control line not finished.
                    self.control_line = s
                    s = b""
                else:
                    # Control line finished.
                    line = s[:pos]
                    s = s[pos + 2 :]
                    self.control_line = b""

                    if line:
                        # Begin a new chunk.
                        semi = line.find(b";")

                        if semi >= 0:
                            extinfo = line[semi:]
                            valid_ext_info = CHUNK_EXT_RE.match(extinfo)

                            if not valid_ext_info:
                                self.error = BadRequest("Invalid chunk extension")
                                self.all_chunks_received = True

                                break

                            line = line[:semi]

                        if not ONLY_HEXDIG_RE.match(line):
                            self.error = BadRequest("Invalid chunk size")
                            self.all_chunks_received = True

                            break

                        # Can not fail due to matching against the regular
                        # expression above
                        sz = int(line, 16)  # hexadecimal

                        if sz > 0:
                            # Start a new chunk.
                            self.chunk_remainder = sz
                        else:
                            # Finished chunks.
                            self.all_chunks_received = True
                    # else expect a control line.
            else:
                # Receive the trailer.
                already_consumed = orig_size - len(s)
                return already_consumed + self._receive_trailer(s)

        return orig_size

    def _receive_trailer(self, s):
        # Parse the trailer section one field line at a time, rather than
        # scanning for the terminating blank line, so that the fields can be
        # validated and handed to the application. Returns the number of bytes
        # of s that belong to (and thus delimit) this trailer section.
        orig_size = len(s)
        data = self.trailer_buffer + s

        while True:
            pos = data.find(b"\r\n")

            if pos < 0:
                # No complete line yet. Everything buffered so far is part of
                # the trailer section, as a pipelined request can not begin
                # until the section is terminated.
                pending = self.trailer_size + len(data)

                if len(data) > self.max_trailer_line_size:
                    self.error = RequestHeaderFieldsTooLarge(
                        "Trailer line exceeds max_trailer_line_size of %s"
                        % self.max_trailer_line_size
                    )
                elif pending > self.max_trailer_size:
                    self.error = RequestHeaderFieldsTooLarge(
                        "Trailer exceeds max_trailer_size of %s"
                        % self.max_trailer_size
                    )
                else:
                    self.trailer_buffer = data

                return orig_size

            if pos > self.max_trailer_line_size:
                self.error = RequestHeaderFieldsTooLarge(
                    "Trailer line exceeds max_trailer_line_size of %s"
                    % self.max_trailer_line_size
                )

                return orig_size

            line = data[:pos]
            data = data[pos + 2 :]

            if not line:
                # The empty line terminates the trailer section. Anything left
                # in data is the start of the next pipelined request and must
                # not be consumed. The trailer size limit was enforced above.
                # The terminating CRLF is framing and is not counted.

                self.trailer_buffer = b""
                self.trailers = tuple(self.trailer_fields)
                self.completed = True

                return orig_size - len(data)

            self.trailer_size += pos + 2

            if self.trailer_size > self.max_trailer_size:
                self.error = RequestHeaderFieldsTooLarge(
                    "Trailer exceeds max_trailer_size of %s"
                    % self.max_trailer_size
                )

                return orig_size

            header = HEADER_FIELD_RE.match(line)

            if header is None:
                self.error = BadRequest("Invalid trailer field")

                return orig_size

            name, value = header.group("name", "value")

            # RFC 9110 section 6.5 forbids generating framing, routing and
            # authentication fields as trailers, since they are only
            # interpreted from the header section. Accepting them would let a
            # client change the meaning of a request after its body was read.
            if name.lower() in FORBIDDEN_TRAILER_FIELDS:
                self.error = BadRequest(
                    'Forbidden trailer field "%s"' % name.decode("latin-1")
                )

                return orig_size

            if len(self.trailer_fields) >= self.max_trailer_fields:
                self.error = RequestHeaderFieldsTooLarge(
                    "Trailer fields exceed max_trailer_fields of %s"
                    % self.max_trailer_fields
                )

                return orig_size

            self.trailer_fields.append(
                (name.decode("latin-1"), value.strip(b" \t").decode("latin-1"))
            )

    def getfile(self):
        return self.buf.getfile()

    def getbuf(self):
        return self.buf
