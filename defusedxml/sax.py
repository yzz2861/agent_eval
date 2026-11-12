# defusedxml
#
# Copyright (c) 2013 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Defused xml.sax
"""
from __future__ import print_function, absolute_import

from xml.sax import InputSource as _InputSource
from xml.sax import ErrorHandler as _ErrorHandler

from . import expatreader

__origin__ = "xml.sax"


def parse(
    source,
    handler,
    errorHandler=_ErrorHandler(),
    forbid_dtd=False,
    forbid_entities=True,
    forbid_external=True,
    policy=None,
):
    parser = make_parser(policy=policy)
    parser.setContentHandler(handler)
    parser.setErrorHandler(errorHandler)
    if policy is None:
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
    policy=None,
):
    from io import BytesIO

    if errorHandler is None:
        errorHandler = _ErrorHandler()
    parser = make_parser(policy=policy)
    parser.setContentHandler(handler)
    parser.setErrorHandler(errorHandler)
    if policy is None:
        parser.forbid_dtd = forbid_dtd
        parser.forbid_entities = forbid_entities
        parser.forbid_external = forbid_external

    inpsrc = _InputSource()
    inpsrc.setByteStream(BytesIO(string))
    parser.parse(inpsrc)


def make_parser(parser_list=[], policy=None, backend=None):
    parser = expatreader.create_parser(policy=policy)
    if backend is not None:
        parser._backend = backend
    return parser
