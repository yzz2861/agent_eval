# defusedxml
#
# Copyright (c) 2013 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Defused xml.dom.minidom
"""
from __future__ import print_function, absolute_import

from xml.dom.minidom import _do_pulldom_parse
from . import expatbuilder as _expatbuilder
from . import pulldom as _pulldom
from .common import _UNSET, resolve_request_config

__origin__ = "xml.dom.minidom"


def parse(
    file,
    parser=None,
    bufsize=None,
    forbid_dtd=_UNSET,
    forbid_entities=_UNSET,
    forbid_external=_UNSET,
    request_config=None,
):
    """Parse a file into a DOM by filename or file object."""
    forbid_dtd, forbid_entities, forbid_external = resolve_request_config(
        request_config, forbid_dtd, forbid_entities, forbid_external
    )
    if parser is None and not bufsize:
        return _expatbuilder.parse(
            file,
            forbid_dtd=forbid_dtd,
            forbid_entities=forbid_entities,
            forbid_external=forbid_external,
        )
    else:
        return _do_pulldom_parse(
            _pulldom.parse,
            (file,),
            {
                "parser": parser,
                "bufsize": bufsize,
                "forbid_dtd": forbid_dtd,
                "forbid_entities": forbid_entities,
                "forbid_external": forbid_external,
                "request_config": request_config,
            },
        )


def parseString(
    string,
    parser=None,
    forbid_dtd=_UNSET,
    forbid_entities=_UNSET,
    forbid_external=_UNSET,
    request_config=None,
):
    """Parse a file into a DOM from a string."""
    forbid_dtd, forbid_entities, forbid_external = resolve_request_config(
        request_config, forbid_dtd, forbid_entities, forbid_external
    )
    if parser is None:
        return _expatbuilder.parseString(
            string,
            forbid_dtd=forbid_dtd,
            forbid_entities=forbid_entities,
            forbid_external=forbid_external,
        )
    else:
        return _do_pulldom_parse(
            _pulldom.parseString,
            (string,),
            {
                "parser": parser,
                "forbid_dtd": forbid_dtd,
                "forbid_entities": forbid_entities,
                "forbid_external": forbid_external,
                "request_config": request_config,
            },
        )
