# defusedxml
#
# Copyright (c) 2013-2020 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Shared support for explicitly closable, bounded read sessions.

A session reads one XML document from a stream and stops at the end of the
document element.  It never reads past that boundary on purpose: data that
was read ahead is either pushed back into a seekable stream or retained in
``unread`` for a non-seekable stream.
"""
from __future__ import print_function, absolute_import

import codecs
import os
from enum import Enum


class ReadState(str, Enum):
    """State of a :class:`ProtectedReadSession`."""

    OPEN = "open"
    COMPLETE = "complete"
    STOPPED = "stopped"
    FAILED = "failed"

    def __str__(self):
        return self.value

    @property
    def closed(self):
        return self is not ReadState.OPEN


class _StreamOwner(object):
    """Keep track of who opened a stream and of data read ahead."""

    def __init__(self, source, close_source=None, bufsize=16 * 1024):
        self.original_source = source
        if hasattr(source, "read"):
            self.stream = source
            opened = False
        else:
            self.stream = open(os.fspath(source), "rb")
            opened = True
        if close_source is not None:
            opened = bool(close_source)
        self.opened_by_session = opened
        self.bufsize = bufsize
        self.close_count = 0
        self.pending = None
        self._empty = None
        self.source_closed = False
        self.eof = False

    @property
    def seekable(self):
        try:
            return bool(self.stream.seekable())
        except (AttributeError, OSError, ValueError):
            return False

    def read(self, size):
        data = self.stream.read(size)
        if not data:
            self.eof = True
        return data

    def rewind(self, data):
        if not data:
            return
        if self.opened_by_session:
            return
        try:
            self.stream.seek(-len(data), os.SEEK_CUR)
        except (AttributeError, OSError, TypeError, ValueError):
            pending = self._pending()
            if not isinstance(pending, type(data)):
                pending = type(data)()
            self.pending = data + pending

    def _pending(self):
        if self.pending is None:
            if self._empty is None:
                try:
                    empty = self.stream.read(0)
                except (AttributeError, OSError, ValueError):
                    empty = b""
                self._empty = type(empty)()
            return self._empty
        return self.pending

    def close_owned(self):
        if not self.opened_by_session or self.source_closed:
            return
        self.source_closed = True
        try:
            self.stream.close()
        finally:
            self.close_count += 1

    @property
    def position(self):
        if self.opened_by_session and self.source_closed:
            return None
        try:
            position = self.stream.tell()
        except (AttributeError, OSError, ValueError):
            return None
        pending = self._pending()
        if pending:
            position -= len(pending)
        return position


class _SegmentReader(object):
    """Read chunks and cut them at tag boundaries.

    Feeding a parser up to and including a ``>`` byte is always safe.  It
    gives the session a chance to notice the end of the document element
    before handing the following segment to the parser.
    """

    def __init__(self, owner):
        self.owner = owner
        self.buffer = None
        self._gt_pattern = None
        self._gt_width = 1
        self._detected = False

    def _empty(self):
        if self.buffer is None:
            return None
        return type(self.buffer)()

    def _detect_boundary(self, data):
        if self._detected or not data:
            return
        if isinstance(data, str):
            self._gt_pattern = ">"
            self._gt_width = 1
            self._detected = True
            return

        # The BOM is the most reliable encoding hint.  XML without a BOM
        # also has recognizable byte order signatures for UTF-16 and
        # UTF-32.
        if data.startswith(codecs.BOM_UTF32_LE) or data.startswith(b"<\x00\x00\x00"):
            self._gt_pattern = b"\x3e\x00\x00\x00"
            self._gt_width = 4
        elif data.startswith(codecs.BOM_UTF32_BE) or data.startswith(b"\x00\x00\x00<"):
            self._gt_pattern = b"\x00\x00\x00\x3e"
            self._gt_width = 4
        elif data.startswith(codecs.BOM_UTF16_LE) or data.startswith(b"<\x00"):
            self._gt_pattern = b"\x3e\x00"
            self._gt_width = 2
        elif data.startswith(codecs.BOM_UTF16_BE) or data.startswith(b"\x00<"):
            self._gt_pattern = b"\x00\x3e"
            self._gt_width = 2
        else:
            self._gt_pattern = b">"
            self._gt_width = 1
        self._detected = True

    def _take_segment(self):
        buf = self.buffer
        if not buf:
            return None
        self._detect_boundary(buf)
        index = buf.find(self._gt_pattern)
        if index >= 0:
            end = index + self._gt_width
            self.buffer = buf[end:]
            return buf[:end]
        if self._gt_width == 1:
            self.buffer = buf[:0]
            return buf

        # Do not split a multi-byte character.  Without a boundary the
        # parser cannot reach the end of the document element yet.
        keep = self._gt_width - 1
        if len(buf) > keep:
            self.buffer = buf[-keep:]
            return buf[:-keep]
        return None

    def read_segment(self):
        while True:
            segment = self._take_segment()
            if segment is not None:
                return segment
            if self.owner.eof:
                if self.buffer:
                    segment = self.buffer
                    self.buffer = self._empty()
                    return segment
                return None
            self._fill()

    def _fill(self):
        if self.owner.eof:
            return False
        data = self.owner.read(self.owner.bufsize)
        if not data:
            return False
        if self.buffer:
            self.buffer = self.buffer + data
        else:
            self.buffer = data
        return True

    def _find_token(self, token):
        while True:
            if self.buffer:
                index = self.buffer.find(token)
                if index >= 0:
                    return index + len(token)
            if not self._fill():
                return None

    def read_trailing_misc_segment(self):
        """Return one segment of legal XML trivia after the root element."""
        # Do not block on a non-seekable source just to look for optional
        # trailing trivia.  For seekable sources read-ahead can be undone.
        if not self.buffer:
            if not self.owner.seekable or not self._fill():
                return None
        buf = self.buffer
        if not buf:
            return None
        if isinstance(buf, str):
            whitespace = " \t\r\n"
            comment_start, comment_end = "<!--", "-->"
            pi_start, pi_end = "<?", "?>"
            is_whitespace = buf[0] in whitespace
            width = 1
        else:
            width = self._gt_width
            if width == 1:
                whitespace = b" \t\r\n"
                comment_start, comment_end = b"<!--", b"-->"
                pi_start, pi_end = b"<?", b"?>"
            else:
                codec = "utf-32-le" if width == 4 else "utf-16-le"
                if self._gt_pattern in (b"\x00\x00\x00\x3e", b"\x00\x3e"):
                    codec = codec.replace("-le", "-be")
                whitespace = tuple(char.encode(codec) for char in " \t\r\n")
                comment_start = "<!--".encode(codec)
                comment_end = "-->".encode(codec)
                pi_start = "<?".encode(codec)
                pi_end = "?>".encode(codec)
            is_whitespace = buf[:width] in whitespace

        if is_whitespace:
            index = 0
            while index < len(buf):
                if isinstance(buf, str):
                    char = buf[index]
                else:
                    char = buf[index : index + width]
                if char not in whitespace:
                    break
                index += width
            segment, self.buffer = buf[:index], buf[index:]
            return segment

        for start, end in ((comment_start, comment_end), (pi_start, pi_end)):
            if buf.startswith(start):
                finish = self._find_token(end)
                if finish is None:
                    finish = len(self.buffer)
                segment, self.buffer = self.buffer[:finish], self.buffer[finish:]
                return segment
        return None

    def release(self):
        data = self.buffer
        self.buffer = self._empty()
        return data


class ProtectedReadSession(object):
    """Base class for a protected, explicitly closable read session.

    The session is an iterator over events.  Events that have already been
    returned are available through :attr:`events` even if the session is
    stopped early or fails.  :attr:`document` is only populated after the
    parser has confirmed the complete document.

    Use the session as a context manager for the common case::

        with ElementTree.iterparse(stream) as session:
            for event, element in session:
                if target(element):
                    break

        for event, element in session.events:
            ...

    A passed-in stream is never closed by the session.  A stream opened by
    the session (from a path) is closed on completion, early stop, failure
    and garbage collection.  Unread data from a seekable passed-in stream
    is pushed back; for a non-seekable stream it is exposed as
    :attr:`unread` and :meth:`read_remaining`.
    """

    def __init__(self, source, close_source=None, bufsize=16 * 1024):
        self._owner = _StreamOwner(source, close_source=close_source, bufsize=bufsize)
        self._reader = _SegmentReader(self._owner)
        self._state = ReadState.OPEN
        self._events = []
        self._document = None
        self._partial_document = None
        self._error = None
        self._close_calls = 0
        self._resources_closed = False
        self._finalized = False
        self._trailing_done = False

    # -- public description -------------------------------------------------
    @property
    def state(self):
        return self._state

    @property
    def final_state(self):
        return self._state

    @property
    def status(self):
        return self._state

    @property
    def closed(self):
        return self._state.closed and self._resources_closed

    @property
    def complete(self):
        return self._state is ReadState.COMPLETE

    @property
    def aborted(self):
        return self._state is ReadState.STOPPED

    @property
    def failed(self):
        return self._state is ReadState.FAILED

    @property
    def document_confirmed(self):
        return self.complete

    @property
    def document_ready(self):
        return self.complete

    @property
    def has_document(self):
        return self.complete and self._document is not None

    @property
    def events(self):
        return list(self._events)

    @property
    def event_count(self):
        return len(self._events)

    @property
    def events_usable(self):
        # Only events that were fully produced are recorded.  An event
        # that fails while it is being built is never appended.
        return True

    @property
    def events_valid(self):
        return self.events_usable

    @property
    def events_complete(self):
        return self.complete

    @property
    def document(self):
        if self.complete:
            return self._document
        return None

    @property
    def root(self):
        return self.document

    @property
    def partial_document(self):
        if self.complete:
            return self._document
        return self._partial_document

    @property
    def error(self):
        return self._error

    @property
    def source(self):
        return self._owner.stream

    @property
    def stream(self):
        return self._owner.stream

    @property
    def source_owned(self):
        return self._owner.opened_by_session

    @property
    def owns_source(self):
        return self._owner.opened_by_session

    @property
    def source_opened_by_session(self):
        return self._owner.opened_by_session

    @property
    def close_count(self):
        return self._owner.close_count

    @property
    def source_closed(self):
        return bool(getattr(self._owner.stream, "closed", self._owner.source_closed))

    @property
    def stream_closed(self):
        return self.source_closed

    @property
    def close_calls(self):
        return self._close_calls

    @property
    def seekable(self):
        return self._owner.seekable

    @property
    def position(self):
        return self._owner.position

    @property
    def unread(self):
        pending = self._owner._pending()
        return pending

    @property
    def buffered(self):
        return self.unread

    @property
    def readable_after_close(self):
        if self.source_owned:
            return False
        stream = self._owner.stream
        return not bool(getattr(stream, "closed", False))

    def read_remaining(self):
        """Return unread buffered data followed by the rest of the source."""
        buffered = self.unread
        try:
            rest = self._owner.stream.read()
        except (AttributeError, ValueError, OSError):
            rest = b""
        if buffered and rest and isinstance(buffered, type(rest)):
            return buffered + rest
        return buffered or rest

    # -- iteration ----------------------------------------------------------
    def __iter__(self):
        return self

    def __next__(self):
        if self._state is not ReadState.OPEN:
            raise StopIteration
        return self._next_event()

    next = __next__

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def finish(self):
        """Consume the rest of the document and return its confirmed document."""
        for _event in self:
            pass
        return self.document

    def close(self):
        """End the session explicitly.

        Closing before the document is complete stops the session.  Events
        that were already produced remain available.  Closing is
        idempotent.
        """
        self._close_calls += 1
        if self._state is not ReadState.OPEN:
            self._release_resources()
            return
        self._finish(ReadState.STOPPED)

    def __del__(self):
        try:
            if self._state is ReadState.OPEN:
                self._finish(ReadState.STOPPED)
        except Exception:
            pass

    # -- internal hooks -----------------------------------------------------
    def _next_event(self):
        raise NotImplementedError

    def _record_event(self, event):
        self._events.append(event)

    def _mark_complete(self, document):
        self._document = document
        self._partial_document = document
        self._finish(ReadState.COMPLETE)

    def _mark_failed(self, error):
        self._error = error
        self._finish(ReadState.FAILED)

    def _finish(self, state):
        if self._state is ReadState.OPEN:
            self._state = state
        self._release_resources()

    def _release_parser(self):
        pass

    def _release_resources(self):
        if self._resources_closed:
            return
        self._resources_closed = True
        pending = self._reader.release()
        if not self.source_owned:
            self._owner.rewind(pending)
        try:
            self._release_parser()
        finally:
            self._owner.close_owned()


# A short, convenient name for the base class.
ReadSession = ProtectedReadSession
BoundedReadSession = ProtectedReadSession
SessionState = ReadState
