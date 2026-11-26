# defusedxml
#
# Copyright (c) 2013-2020 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Defused xml.etree.ElementTree facade
"""
from __future__ import print_function, absolute_import

import sys
import warnings
from xml.etree.ElementTree import ParseError
from xml.etree.ElementTree import TreeBuilder as _TreeBuilder
from xml.etree.ElementTree import XMLPullParser as _XMLPullParser
from xml.etree.ElementTree import parse as _parse
from xml.etree.ElementTree import tostring

import importlib


from .common import DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden
from .budget import (
    BudgetedReader,
    SecurityBudget,
)

__origin__ = "xml.etree.ElementTree"


def _get_py3_cls():
    """Python 3.3 hides the pure Python code but defusedxml requires it.

    The code is based on test.support.import_fresh_module().
    """
    pymodname = "xml.etree.ElementTree"
    cmodname = "_elementtree"

    pymod = sys.modules.pop(pymodname, None)
    cmod = sys.modules.pop(cmodname, None)

    sys.modules[cmodname] = None
    try:
        pure_pymod = importlib.import_module(pymodname)
    finally:
        # restore module
        sys.modules[pymodname] = pymod
        if cmod is not None:
            sys.modules[cmodname] = cmod
        else:
            sys.modules.pop(cmodname, None)
        # restore attribute on original package
        etree_pkg = sys.modules["xml.etree"]
        if pymod is not None:
            etree_pkg.ElementTree = pymod
        elif hasattr(etree_pkg, "ElementTree"):
            del etree_pkg.ElementTree

    _XMLParser = pure_pymod.XMLParser
    _iterparse = pure_pymod.iterparse
    # patch pure module to use ParseError from C extension
    pure_pymod.ParseError = ParseError

    return _XMLParser, _iterparse


_XMLParser, _iterparse = _get_py3_cls()

_sentinel = object()


class DefusedXMLParser(_XMLParser):
    def __init__(
        self,
        html=_sentinel,
        target=None,
        encoding=None,
        forbid_dtd=False,
        forbid_entities=True,
        forbid_external=True,
    ):
        super().__init__(target=target, encoding=encoding)
        if html is not _sentinel:
            # the 'html' argument has been deprecated and ignored in all
            # supported versions of Python. Python 3.8 finally removed it.
            if html:
                raise TypeError("'html=True' is no longer supported.")
            else:
                warnings.warn(
                    "'html' keyword argument is no longer supported. Pass "
                    "in arguments as keyword arguments.",
                    category=DeprecationWarning,
                )

        self.forbid_dtd = forbid_dtd
        self.forbid_entities = forbid_entities
        self.forbid_external = forbid_external
        parser = self.parser
        if self.forbid_dtd:
            parser.StartDoctypeDeclHandler = self.defused_start_doctype_decl
        if self.forbid_entities:
            parser.EntityDeclHandler = self.defused_entity_decl
            parser.UnparsedEntityDeclHandler = self.defused_unparsed_entity_decl
        if self.forbid_external:
            parser.ExternalEntityRefHandler = self.defused_external_entity_ref_handler

    def defused_start_doctype_decl(self, name, sysid, pubid, has_internal_subset):
        raise DTDForbidden(name, sysid, pubid)

    def defused_entity_decl(
        self, name, is_parameter_entity, value, base, sysid, pubid, notation_name
    ):
        raise EntitiesForbidden(name, value, base, sysid, pubid, notation_name)

    def defused_unparsed_entity_decl(self, name, base, sysid, pubid, notation_name):
        # expat 1.2
        raise EntitiesForbidden(name, None, base, sysid, pubid, notation_name)  # pragma: no cover

    def defused_external_entity_ref_handler(self, context, base, sysid, pubid):
        raise ExternalReferenceForbidden(context, base, sysid, pubid)


# aliases
# XMLParse is a typo, keep it for backwards compatibility
XMLTreeBuilder = XMLParse = XMLParser = DefusedXMLParser


def parse(source, parser=None, forbid_dtd=False, forbid_entities=True, forbid_external=True):
    if parser is None:
        parser = DefusedXMLParser(
            target=_TreeBuilder(),
            forbid_dtd=forbid_dtd,
            forbid_entities=forbid_entities,
            forbid_external=forbid_external,
        )
    return _parse(source, parser)


def iterparse(
    source,
    events=None,
    parser=None,
    forbid_dtd=False,
    forbid_entities=True,
    forbid_external=True,
):
    if parser is None:
        parser = DefusedXMLParser(
            target=_TreeBuilder(),
            forbid_dtd=forbid_dtd,
            forbid_entities=forbid_entities,
            forbid_external=forbid_external,
        )
    return _iterparse(source, events, parser)


def fromstring(text, forbid_dtd=False, forbid_entities=True, forbid_external=True):
    parser = DefusedXMLParser(
        target=_TreeBuilder(),
        forbid_dtd=forbid_dtd,
        forbid_entities=forbid_entities,
        forbid_external=forbid_external,
    )
    parser.feed(text)
    return parser.close()


XML = fromstring


def fromstringlist(sequence, forbid_dtd=False, forbid_entities=True, forbid_external=True):
    parser = DefusedXMLParser(
        target=_TreeBuilder(),
        forbid_dtd=forbid_dtd,
        forbid_entities=forbid_entities,
        forbid_external=forbid_external,
    )
    for text in sequence:
        parser.feed(text)
    return parser.close()


class BudgetedXMLParser(object):
    """Full-tree XML parser guarded by a :class:`SecurityBudget`.

    Every chunk handed to :meth:`feed` is charged to the shared budget before
    it reaches the underlying defused parser. A document counts as accepted
    only after :meth:`close` parses the complete stream; abandoning the parser
    early is recorded as a cancellation instead of a successful decision.
    """

    def __init__(
        self,
        budget,
        target=None,
        encoding=None,
        forbid_dtd=False,
        forbid_entities=True,
        forbid_external=True,
    ):
        if not isinstance(budget, SecurityBudget):
            raise TypeError("budget must be a SecurityBudget instance")
        self._budget = budget
        self._parser = DefusedXMLParser(
            target=_TreeBuilder() if target is None else target,
            encoding=encoding,
            forbid_dtd=forbid_dtd,
            forbid_entities=forbid_entities,
            forbid_external=forbid_external,
        )

    @property
    def budget(self):
        return self._budget

    @property
    def parser(self):
        return self._parser

    def feed(self, data):
        if data:
            self._budget.charge(len(data))
        return self._parser.feed(data)

    def close(self):
        root = self._parser.close()
        self._budget.complete()
        return root

    def cancel(self):
        """Release the parser and record an early cancellation."""
        self._budget.cancel()

    def __getattr__(self, name):
        return getattr(self._parser, name)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._budget.is_active:
            if exc_type is None:
                self.close()
            else:
                self.cancel()


class BudgetedPullParser(object):
    """Incremental pull parser guarded by a :class:`SecurityBudget`.

    The adapter mirrors :class:`xml.etree.ElementTree.XMLPullParser` while
    charging every fed chunk to the same budget ledger used by
    :class:`BudgetedXMLParser`. Events already produced by a complete element
    remain readable even when the next chunk would exceed the budget.
    """

    def __init__(
        self,
        budget,
        events=None,
        forbid_dtd=False,
        forbid_entities=True,
        forbid_external=True,
    ):
        if not isinstance(budget, SecurityBudget):
            raise TypeError("budget must be a SecurityBudget instance")
        self._budget = budget
        parser = DefusedXMLParser(
            target=_TreeBuilder(),
            forbid_dtd=forbid_dtd,
            forbid_entities=forbid_entities,
            forbid_external=forbid_external,
        )
        self._pull = _XMLPullParser(events=events, _parser=parser)

    @property
    def budget(self):
        return self._budget

    @property
    def parser(self):
        return self._pull

    def feed(self, data):
        if data:
            self._budget.charge(len(data))
        self._pull.feed(data)

    def read_events(self):
        return self._pull.read_events()

    def drain_events(self):
        """Return all currently available events as a list."""
        return list(self._pull.read_events())

    def flush(self):
        return self._pull.flush()

    def close(self):
        self._pull.close()
        self._budget.complete()

    def cancel(self):
        """Stop consuming and record an early cancellation."""
        self._budget.cancel()

    def __getattr__(self, name):
        return getattr(self._pull, name)

    def __iter__(self):
        return self

    def __next__(self):
        for event in self._pull.read_events():
            return event
        raise StopIteration

    next = __next__

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._budget.is_active:
            if exc_type is None:
                self.close()
            else:
                self.cancel()


def budgeted_iterparse(
    source,
    budget,
    events=None,
    chunk_size=16 * 1024,
    forbid_dtd=False,
    forbid_entities=True,
    forbid_external=True,
):
    """Incrementally parse a file object while charging bytes to ``budget``.

    The returned iterator records completion once the whole stream has been
    consumed. Abandoning the iterator before exhaustion cancels the budget so
    that a partially read document is never mistaken for an accepted one.
    """
    if not hasattr(source, "read"):
        raise TypeError("source must be a file-like object with a read() method")
    parser = DefusedXMLParser(
        target=_TreeBuilder(),
        forbid_dtd=forbid_dtd,
        forbid_entities=forbid_entities,
        forbid_external=forbid_external,
    )
    reader = BudgetedReader(source, budget, chunk_size=chunk_size)
    iterator = iter(_iterparse(reader, events, parser))

    def budgeted_iterator():
        try:
            for item in iterator:
                yield item
            budget.complete()
        except GeneratorExit:
            budget.cancel()
            raise

    return budgeted_iterator()


def fromstring_budget(text, budget, forbid_dtd=False, forbid_entities=True, forbid_external=True):
    """Parse ``text`` in one shot against an explicit security budget."""
    parser = BudgetedXMLParser(
        budget,
        forbid_dtd=forbid_dtd,
        forbid_entities=forbid_entities,
        forbid_external=forbid_external,
    )
    parser.feed(text)
    return parser.close()


__all__ = [
    "ParseError",
    "BudgetedPullParser",
    "BudgetedXMLParser",
    "XML",
    "XMLParse",
    "XMLParser",
    "XMLTreeBuilder",
    "SecurityBudget",
    "budgeted_iterparse",
    "fromstring_budget",
    "fromstring",
    "fromstringlist",
    "iterparse",
    "parse",
    "tostring",
]
