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
from .policy import BACKEND_PULLDOM

__origin__ = "xml.dom.pulldom"


def parse(
    stream_or_string,
    parser=None,
    bufsize=None,
    forbid_dtd=False,
    forbid_entities=True,
    forbid_external=True,
    policy=None,
):
    if parser is None:
        parser = make_parser(policy=policy, backend=BACKEND_PULLDOM)
        if policy is None:
            parser.forbid_dtd = forbid_dtd
            parser.forbid_entities = forbid_entities
            parser.forbid_external = forbid_external
    return _parse(stream_or_string, parser, bufsize)


def parseString(
    string,
    parser=None,
    forbid_dtd=False,
    forbid_entities=True,
    forbid_external=True,
    policy=None,
):
    if parser is None:
        parser = make_parser(policy=policy, backend=BACKEND_PULLDOM)
        if policy is None:
            parser.forbid_dtd = forbid_dtd
            parser.forbid_entities = forbid_entities
            parser.forbid_external = forbid_external
    if isinstance(string, bytes):
        # stdlib pulldom.parseString wraps the input in StringIO and
        # therefore only accepts text, unlike the other pyexpat backends.
        string = string.decode("utf-8")
    return _parseString(string, parser)
