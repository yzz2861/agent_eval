# defusedxml
#
# Copyright (c) 2013 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Defused xml.dom.pulldom
"""
from __future__ import print_function, absolute_import

from xml.dom.pulldom import parse as _parse
from xml.dom.pulldom import parseString as _parseString
from .sax import make_parser
from .common import _UNSET, resolve_request_config

__origin__ = "xml.dom.pulldom"


def parse(
    stream_or_string,
    parser=None,
    bufsize=None,
    forbid_dtd=_UNSET,
    forbid_entities=_UNSET,
    forbid_external=_UNSET,
    request_config=None,
):
    if parser is None:
        forbid_dtd, forbid_entities, forbid_external = resolve_request_config(
            request_config, forbid_dtd, forbid_entities, forbid_external
        )
        parser = make_parser()
        parser.forbid_dtd = forbid_dtd
        parser.forbid_entities = forbid_entities
        parser.forbid_external = forbid_external
    return _parse(stream_or_string, parser, bufsize)


def parseString(
    string,
    parser=None,
    forbid_dtd=_UNSET,
    forbid_entities=_UNSET,
    forbid_external=_UNSET,
    request_config=None,
):
    if parser is None:
        forbid_dtd, forbid_entities, forbid_external = resolve_request_config(
            request_config, forbid_dtd, forbid_entities, forbid_external
        )
        parser = make_parser()
        parser.forbid_dtd = forbid_dtd
        parser.forbid_entities = forbid_entities
        parser.forbid_external = forbid_external
    return _parseString(string, parser)
