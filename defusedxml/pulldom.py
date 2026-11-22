# defusedxml
#
# Copyright (c) 2013 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Defused xml.dom.pulldom
"""
from __future__ import print_function, absolute_import

from io import BytesIO, StringIO

import xml.sax
from xml.dom.pulldom import (
    END_DOCUMENT,
    END_ELEMENT,
    START_ELEMENT,
    PullDOM,
)
from xml.sax import InputSource

from .common import NotSupportedError
from .session import ProtectedReadSession, ReadState
from .sax import make_parser

__origin__ = "xml.dom.pulldom"

default_bufsize = (2 ** 14) - 20


class _PullDomHandler(object):
    """Track the document element while delegating to ``PullDOM``."""

    def __init__(self, target):
        self.target = target
        self.depth = 0
        self.root_closed = False

    def __getattr__(self, name):
        return getattr(self.target, name)

    def startElement(self, name, attrs):
        self.depth += 1
        return self.target.startElement(name, attrs)

    def endElement(self, name):
        result = self.target.endElement(name)
        if self.depth:
            self.depth -= 1
        if self.depth == 0:
            self.root_closed = True
        return result

    def startElementNS(self, name, tagName, attrs):
        self.depth += 1
        return self.target.startElementNS(name, tagName, attrs)

    def endElementNS(self, name, tagName):
        result = self.target.endElementNS(name, tagName)
        if self.depth:
            self.depth -= 1
        if self.depth == 0:
            self.root_closed = True
        return result


class PullDomSession(ProtectedReadSession):
    """Bounded, explicitly closable session for :mod:`xml.dom.pulldom`.

    Events are handed out as soon as they are produced.  ``document`` is
    only available after the parser has confirmed the complete document;
    an early stop leaves the events and an optional ``partial_document``.
    """

    def __init__(
        self,
        source,
        parser=None,
        bufsize=None,
        forbid_dtd=False,
        forbid_entities=True,
        forbid_external=True,
        close_source=None,
    ):
        if bufsize is None:
            bufsize = default_bufsize
        super().__init__(source, close_source=close_source, bufsize=bufsize)
        self.bufsize = bufsize
        self.parser = None
        self.pulldom = None
        self._handler = None
        try:
            if parser is None:
                parser = make_parser()
                parser.forbid_dtd = forbid_dtd
                parser.forbid_entities = forbid_entities
                parser.forbid_external = forbid_external
            if not hasattr(parser, "feed"):
                raise NotSupportedError(
                    "bounded pulldom sessions require an incremental parser"
                )
            self.parser = parser
            self._parser = parser
            self.pulldom = PullDOM()
            self._handler = _PullDomHandler(self.pulldom)
            parser.setFeature(xml.sax.handler.feature_namespaces, 1)
            parser.setContentHandler(self._handler)
        except BaseException as exc:
            self._mark_failed(exc)
            raise

    def _record_event(self, event):
        super()._record_event(event)
        document = getattr(self.pulldom, "document", None) if self.pulldom else None
        if document is not None:
            self._partial_document = document

    def _poll_event(self):
        pulldom = self.pulldom
        if pulldom is None:
            return None
        if not pulldom.firstEvent[1]:
            pulldom.lastEvent = pulldom.firstEvent
        if pulldom.firstEvent[1]:
            event = pulldom.firstEvent[1][0]
            pulldom.firstEvent[1] = pulldom.firstEvent[1][1]
            return event
        return None

    def _next_event(self):
        while True:
            if self._state is not ReadState.OPEN:
                raise StopIteration
            event = self._poll_event()
            if event is not None:
                self._record_event(event)
                if event[0] == END_DOCUMENT:
                    document = event[1]
                    if document is None:
                        document = getattr(self.pulldom, "document", None)
                    self._mark_complete(document)
                return event
            if self._handler is not None and self._handler.root_closed:
                segment = self._reader.read_trailing_misc_segment()
                if segment is not None:
                    try:
                        self.parser.feed(segment)
                    except BaseException as exc:
                        self._mark_failed(exc)
                        raise
                    continue
                if not self._finalized:
                    self._finalize_complete()
                    continue
                if self._state is ReadState.OPEN:
                    document = getattr(self.pulldom, "document", None)
                    self._mark_complete(document)
                raise StopIteration
            if self._owner.eof:
                if not self._finalized:
                    self._finalize_complete()
                    continue
                if self._state is ReadState.OPEN:
                    document = getattr(self.pulldom, "document", None)
                    self._mark_complete(document)
                raise StopIteration
            segment = self._reader.read_segment()
            if segment is None:
                continue
            try:
                self.parser.feed(segment)
            except BaseException as exc:
                self._mark_failed(exc)
                raise

    def _finalize_complete(self):
        if self._finalized:
            return
        self._finalized = True
        parser = self.parser
        source = getattr(parser, "_source", None)
        try:
            if source is not None:
                parser._source = InputSource()
            parser.close()
        except BaseException as exc:
            self._mark_failed(exc)
            raise
        finally:
            if source is not None:
                try:
                    parser._source = source
                except AttributeError:
                    pass

    def _release_parser(self):
        parser = self.parser
        self.parser = None
        if parser is not None:
            try:
                parser.setContentHandler(xml.sax.ContentHandler())
            except Exception:
                pass

    def getEvent(self):
        """Return the next event, or ``None`` at the end of the session."""
        try:
            return next(self)
        except StopIteration:
            return None

    def expandNode(self, node):
        event = self.getEvent()
        parents = [node]
        while event:
            token, cur_node = event
            if cur_node is node:
                return
            if token != END_ELEMENT:
                parents[-1].appendChild(cur_node)
            if token == START_ELEMENT:
                parents.append(cur_node)
            elif token == END_ELEMENT:
                del parents[-1]
            event = self.getEvent()

    def clear(self):
        """Explicitly release parsing structures."""
        self.close()


def parse(
    stream_or_string,
    parser=None,
    bufsize=None,
    forbid_dtd=False,
    forbid_entities=True,
    forbid_external=True,
    close_source=None,
):
    return PullDomSession(
        stream_or_string,
        parser=parser,
        bufsize=bufsize,
        forbid_dtd=forbid_dtd,
        forbid_entities=forbid_entities,
        forbid_external=forbid_external,
        close_source=close_source,
    )


def parseString(
    string,
    parser=None,
    forbid_dtd=False,
    forbid_entities=True,
    forbid_external=True,
    close_source=True,
):
    if isinstance(string, bytes):
        stream = BytesIO(string)
    else:
        stream = StringIO(string)
    return PullDomSession(
        stream,
        parser=parser,
        bufsize=max(len(string), 1),
        forbid_dtd=forbid_dtd,
        forbid_entities=forbid_entities,
        forbid_external=forbid_external,
        close_source=close_source,
    )


parse_session = parse
open_session = parse
parseString_session = parseString
PulldomSession = PullDomSession
BoundedPullDomSession = PullDomSession
