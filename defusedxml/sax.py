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
from .common import _UNSET, resolve_request_config

__origin__ = "xml.sax"


def parse(
    source,
    handler,
    errorHandler=_ErrorHandler(),
    forbid_dtd=_UNSET,
    forbid_entities=_UNSET,
    forbid_external=_UNSET,
    request_config=None,
):
    forbid_dtd, forbid_entities, forbid_external = resolve_request_config(
        request_config, forbid_dtd, forbid_entities, forbid_external
    )
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
    forbid_dtd=_UNSET,
    forbid_entities=_UNSET,
    forbid_external=_UNSET,
    request_config=None,
):
    from io import BytesIO

    if errorHandler is None:
        errorHandler = _ErrorHandler()
    forbid_dtd, forbid_entities, forbid_external = resolve_request_config(
        request_config, forbid_dtd, forbid_entities, forbid_external
    )
    parser = make_parser()
    parser.setContentHandler(handler)
    parser.setErrorHandler(errorHandler)
    parser.forbid_dtd = forbid_dtd
    parser.forbid_entities = forbid_entities
    parser.forbid_external = forbid_external

    inpsrc = _InputSource()
    inpsrc.setByteStream(BytesIO(string))
    parser.parse(inpsrc)


def make_parser(parser_list=[], request_config=None):
    return expatreader.create_parser(request_config=request_config)
