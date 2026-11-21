# defusedxml
#
# Copyright (c) 2013 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Defused xml.dom.pulldom

The pull parser is deliberately explicit about the point at which a document
becomes complete.  A consumer may consume any bounded prefix of the event
stream, but :meth:`DOMEventStream.commit` only succeeds after the parser has
reached the end of the input.  This lets an importer stage an in-memory object
as events arrive, while withholding submission until the whole document has
passed the defused parser.
"""

from __future__ import print_function, absolute_import

import io
import os
from collections import namedtuple

from xml.dom.pulldom import DOMEventStream as _DOMEventStream
from xml.dom.pulldom import (
    CHARACTERS,
    COMMENT,
    END_DOCUMENT,
    END_ELEMENT,
    IGNORABLE_WHITESPACE,
    PROCESSING_INSTRUCTION,
    START_DOCUMENT,
    START_ELEMENT,
    default_bufsize,
)

from .common import NotSupportedError
from .sax import make_parser

__origin__ = "xml.dom.pulldom"

__all__ = [
    "CHARACTERS",
    "COMMENT",
    "DOMEventStream",
    "END_DOCUMENT",
    "END_ELEMENT",
    "IGNORABLE_WHITESPACE",
    "PROCESSING_INSTRUCTION",
    "Progress",
    "START_DOCUMENT",
    "START_ELEMENT",
    "default_bufsize",
    "parse",
    "parseString",
]


Progress = namedtuple("Progress", "bytes events pending complete")


class DOMEventStream(_DOMEventStream):
    """A pull event stream with an explicit document-completion boundary.

    ``owned`` indicates that this object opened ``stream`` and is therefore
    responsible for closing it.  A caller-provided stream is never closed by
    the reader.
    """

    def __init__(self, stream, parser, bufsize, owned=False):
        self._owned = owned
        self._closed = False
        self._finished = False
        self._parse_complete = False
        self._slurped = False
        self._bytes_read = 0
        self._delivered = 0
        self._slurped = False
        _DOMEventStream.__init__(self, stream, parser, bufsize)
        # xml.dom.pulldom installs a ``_slurp`` instance attribute for parsers
        # without an incremental ``feed`` method.  Route those parsers through
        # the same publication boundary as incremental parsers.
        self.getEvent = self._get_event

    def reset(self):
        _DOMEventStream.reset(self)
        self._finished = False
        self._parse_complete = False
        self._bytes_read = 0
        self._delivered = 0

    def _pending_events(self):
        if not hasattr(self, "pulldom"):
            return 0
        event = self.pulldom.firstEvent[1]
        count = 0
        while event is not None:
            count += 1
            event = event[1]
        return count

    def _release_source(self):
        if self._owned and self.stream is not None:
            try:
                self.stream.close()
            finally:
                self._owned = False

    @property
    def complete(self):
        """True once the parser has consumed a complete document."""
        return self._parse_complete

    @property
    def can_commit(self):
        """Whether the staged document may be submitted."""
        return self.complete and hasattr(self, "pulldom")

    @property
    def bytes_read(self):
        return self._bytes_read

    @property
    def events_delivered(self):
        return self._delivered

    @property
    def pending_events(self):
        return self._pending_events()

    @property
    def progress(self):
        """Bounded-read progress observed so far."""
        return Progress(
            self._bytes_read,
            self._delivered,
            self._pending_events(),
            self.complete,
        )

    def stage(self, data):
        """Feed another bounded chunk without closing the document.

        The return value is the number of parse events waiting to be
        published.  The document is not considered complete until the input
        has ended and the parser has been closed.
        """
        if self._closed or self._finished or not hasattr(self.parser, "feed"):
            raise ValueError("stage() called after end of stream")
        if not data:
            return self._pending_events()
        self._bytes_read += len(data)
        try:
            self.parser.feed(data)
        except BaseException:
            self._finished = True
            self._release_source()
            raise
        return self._pending_events()

    def publish(self):
        """Publish the next parse event.

        This is the pull-side counterpart of :meth:`stage`.  It raises
        ``StopIteration`` at the end of the event stream, matching normal
        iterator semantics.
        """
        event = self.getEvent()
        if event is None:
            raise StopIteration
        return event

    def commit(self):
        """Return the completed document.

        A document is only releasable after the complete input has been
        parsed without a security violation.  This method raises
        :class:`NotSupportedError` for an incomplete document.
        """
        if not self.can_commit:
            raise NotSupportedError("document is not complete")
        return self.pulldom.document

    def finish(self):
        """Declare end of input and run the final parser checks.

        On success the document becomes complete and any remaining events,
        including ``END_DOCUMENT``, can still be published.  A security or
        syntax failure propagates and leaves the document incomplete.
        """
        if self._parse_complete:
            return self.progress
        if self._closed:
            raise ValueError("finish() called after end of stream")
        if self._finished:
            raise ValueError("document closed before a successful finish()")
        try:
            self.parser.close()
            self._parse_complete = True
        except BaseException:
            self._release_source()
            raise
        finally:
            self._finished = True
        self._release_source()
        return self.progress

    def close(self):
        """Stop consuming input and release an owned source.

        This is the application-exit boundary, not a successful parse result.
        An incomplete document remains incomplete.  If the input was already
        fully staged, the final parser checks are still attempted, but this
        method never converts an incomplete document into a committable one.
        """
        if self._closed:
            return
        self._closed = True
        if not self._finished:
            try:
                self.parser.close()
            except Exception:
                # Early application exit is not a parse result.  The source
                # still has to be released below.
                pass
            self._finished = True
        self._release_source()

    def clear(self):
        """Release the parser, stream and any staged DOM objects."""
        self.close()
        if hasattr(self, "pulldom"):
            _DOMEventStream.clear(self)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def getEvent(self):
        return self._get_event()

    def _get_event(self):
        """Return the next event or ``None`` at the end of the stream.

        Unlike :class:`xml.dom.pulldom.DOMEventStream`, a successful end of
        input is published as an ``END_DOCUMENT`` event exactly once.
        """
        if self._closed:
            return None

        if not hasattr(self.parser, "feed"):
            if not self._slurped:
                try:
                    self.parser.parse(self.stream)
                except BaseException:
                    self._release_source()
                    raise
                finally:
                    self._slurped = True
                    self._finished = True
            return self._next_queued()

        return self._next_incremental()

    def _next_queued(self):
        if not self.pulldom.firstEvent[1]:
            self._release_source()
            return None
        return self._publish_queued()

    def _next_incremental(self):
        if not self.pulldom.firstEvent[1]:
            self.pulldom.lastEvent = self.pulldom.firstEvent

        while not self.pulldom.firstEvent[1]:
            if self._finished or self.stream is None:
                return None
            buf = self.stream.read(self.bufsize)
            if not buf:
                self.finish()
                if not self.pulldom.firstEvent[1]:
                    return None
                break
            self._bytes_read += len(buf)
            try:
                self.parser.feed(buf)
            except BaseException:
                self._finished = True
                self._release_source()
                raise

        return self._publish_queued()

    def _publish_queued(self):
        rc = self.pulldom.firstEvent[1][0]
        self.pulldom.firstEvent[1] = self.pulldom.firstEvent[1][1]
        self._delivered += 1
        if rc[0] == END_DOCUMENT:
            self._parse_complete = True
            self._finished = True
            self._release_source()
        return rc


def _make_parser(parser, forbid_dtd, forbid_entities, forbid_external):
    if parser is not None:
        return parser
    parser = make_parser()
    parser.forbid_dtd = forbid_dtd
    parser.forbid_entities = forbid_entities
    parser.forbid_external = forbid_external
    return parser


def parse(
    stream_or_string,
    parser=None,
    bufsize=None,
    forbid_dtd=False,
    forbid_entities=True,
    forbid_external=True,
):
    if bufsize is None:
        bufsize = default_bufsize
    if isinstance(stream_or_string, (str, os.PathLike)):
        stream = open(stream_or_string, "rb")
        owned = True
    else:
        stream = stream_or_string
        owned = False
    parser = _make_parser(parser, forbid_dtd, forbid_entities, forbid_external)
    return DOMEventStream(stream, parser, bufsize, owned=owned)


def parseString(
    string, parser=None, forbid_dtd=False, forbid_entities=True, forbid_external=True
):
    if isinstance(string, bytes):
        stream = io.BytesIO(string)
    else:
        stream = io.StringIO(string)
    parser = _make_parser(parser, forbid_dtd, forbid_entities, forbid_external)
    return DOMEventStream(stream, parser, max(len(string), 1), owned=True)
