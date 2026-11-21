# defusedxml
#
# Copyright (c) 2013 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Defused xml.sax"""

from __future__ import print_function, absolute_import

from collections import namedtuple

from xml.sax import InputSource as _InputSource
from xml.sax import ErrorHandler as _ErrorHandler
from xml.sax.handler import ContentHandler as _ContentHandler

from . import expatreader

__origin__ = "xml.sax"

__all__ = ["IncrementalReader", "Progress", "make_parser", "parse", "parseString"]

Progress = namedtuple("Progress", "bytes events complete")


def parse(
    source,
    handler,
    errorHandler=_ErrorHandler(),
    forbid_dtd=False,
    forbid_entities=True,
    forbid_external=True,
):
    parser = make_parser()
    parser.setContentHandler(handler)
    parser.setErrorHandler(errorHandler)
    parser.forbid_dtd = forbid_dtd
    parser.forbid_entities = forbid_entities
    parser.forbid_external = forbid_external
    parser.parse(source)


def parseString(
    string,
    handler,
    errorHandler=_ErrorHandler(),
    forbid_dtd=False,
    forbid_entities=True,
    forbid_external=True,
):
    from io import BytesIO

    if errorHandler is None:
        errorHandler = _ErrorHandler()
    parser = make_parser()
    parser.setContentHandler(handler)
    parser.setErrorHandler(errorHandler)
    parser.forbid_dtd = forbid_dtd
    parser.forbid_entities = forbid_entities
    parser.forbid_external = forbid_external

    inpsrc = _InputSource()
    inpsrc.setByteStream(BytesIO(string))
    parser.parse(inpsrc)


def make_parser(parser_list=[]):
    return expatreader.create_parser()


class _CountingHandler(_ContentHandler):
    # Forward every SAX event to the application handler while keeping a
    # progress counter.  Application exceptions are deliberately not caught.
    def __init__(self, target=None):
        self.target = target
        self.events = 0

    def _call(self, name, *args):
        self.events += 1
        method = getattr(self.target, name, None)
        if method is not None:
            method(*args)

    def setDocumentLocator(self, locator):
        method = getattr(self.target, "setDocumentLocator", None)
        if method is not None:
            method(locator)

    def startDocument(self):
        self._call("startDocument")

    def endDocument(self):
        self._call("endDocument")

    def startPrefixMapping(self, prefix, uri):
        self._call("startPrefixMapping", prefix, uri)

    def endPrefixMapping(self, prefix):
        self._call("endPrefixMapping", prefix)

    def startElement(self, name, attrs):
        self._call("startElement", name, attrs)

    def endElement(self, name):
        self._call("endElement", name)

    def startElementNS(self, name, qname, attrs):
        self._call("startElementNS", name, qname, attrs)

    def endElementNS(self, name, qname):
        self._call("endElementNS", name, qname)

    def characters(self, content):
        self._call("characters", content)

    def ignorableWhitespace(self, whitespace):
        self._call("ignorableWhitespace", whitespace)

    def processingInstruction(self, target, data):
        self._call("processingInstruction", target, data)

    def skippedEntity(self, name):
        self._call("skippedEntity", name)


class IncrementalReader:
    """Bounded SAX reader with explicit staging and completion boundaries.

    ``stage(data)`` feeds one bounded chunk and publishes its SAX events to
    the application handler immediately.  ``finish()`` is the document
    completion boundary and emits ``endDocument`` exactly once.  ``close()``
    is the application-exit boundary: it never turns a partial document into
    a completed one.  A handler exception propagates unchanged and aborts the
    reader, so an importer cannot accidentally commit a half-built object.

    The reader itself does not own a stream.  :meth:`from_source` opens and
    closes a filename it was given, but leaves a caller-provided stream open.
    """

    def __init__(
        self,
        handler=None,
        parser=None,
        forbid_dtd=False,
        forbid_entities=True,
        forbid_external=True,
    ):
        self.handler = _CountingHandler(handler)
        self.parser = parser if parser is not None else make_parser()
        self.parser.setContentHandler(self.handler)
        if parser is None:
            self.parser.forbid_dtd = forbid_dtd
            self.parser.forbid_entities = forbid_entities
            self.parser.forbid_external = forbid_external
        self.bytes_read = 0
        self._finished = False
        self._complete = False
        self._closed = False

    @property
    def complete(self):
        return self._complete

    @property
    def can_commit(self):
        return self._complete

    @property
    def progress(self):
        return Progress(self.bytes_read, self.handler.events, self._complete)

    def stage(self, data):
        """Feed one bounded chunk and publish its events."""
        if self._closed or self._finished:
            raise ValueError("stage() called after end of stream")
        if not data:
            return self.progress
        self.bytes_read += len(data)
        try:
            self.parser.feed(data)
        except BaseException:
            # Handler and security failures abort this document.  A later
            # stage() must not look like a fresh attempt.
            self._finished = True
            raise
        return self.progress

    def finish(self):
        """Run the final checks and emit ``endDocument`` once."""
        if self._complete:
            return self.progress
        if self._closed:
            raise ValueError("finish() called after close()")
        if self._finished:
            raise ValueError("document closed before a successful finish()")
        try:
            self.parser.close()
            self._complete = True
        finally:
            self._finished = True
        return self.progress

    def close(self):
        """Abandon the current document without marking it complete.

        The application-exit path deliberately does not call the parser close
        method: no synthetic endDocument is published for a partial import and
        can_commit remains false.
        """
        if self._closed:
            return
        self._closed = True
        self._finished = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    @classmethod
    def from_source(cls, source, handler=None, bufsize=2**16, **kwargs):
        """Consume a filename or stream in bounded chunks.

        Filenames opened here are closed on every exit path.  A caller-owned
        stream is never closed.
        """
        reader = cls(handler, **kwargs)
        owned = None
        if not hasattr(source, "read"):
            owned = open(source, "rb")
            source = owned
        try:
            while True:
                data = source.read(bufsize)
                if not data:
                    break
                reader.stage(data)
            reader.finish()
        except BaseException:
            reader.close()
            raise
        finally:
            if owned is not None:
                owned.close()
        return reader
