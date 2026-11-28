# defusedxml
#
# Copyright (c) 2013 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Defuse XML bomb denial of service vulnerabilities
"""
from __future__ import print_function, absolute_import

import warnings

from .common import (
    DEFAULT_FORBID_DTD,
    DEFAULT_FORBID_ENTITIES,
    DEFAULT_FORBID_EXTERNAL,
    DefusedXmlException,
    DTDForbidden,
    EntitiesForbidden,
    ExternalReferenceForbidden,
    NotSupportedError,
    RequestConfig,
    _apply_defusing,
    get_request_config,
    request_config,
    resolve_request_config,
)


def defuse_stdlib():
    """Monkey patch and defuse all stdlib packages

    :warning: The monkey patch is an EXPERIMENTAL feature.
    """
    defused = {}

    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning, module="defusedxml")
        from . import cElementTree
    from . import ElementTree
    from . import minidom
    from . import pulldom
    from . import sax
    from . import expatbuilder
    from . import expatreader
    from . import xmlrpc

    xmlrpc.monkey_patch()
    defused[xmlrpc] = None

    defused_mods = [
        cElementTree,
        ElementTree,
        minidom,
        pulldom,
        sax,
        expatbuilder,
        expatreader,
    ]

    for defused_mod in defused_mods:
        stdlib_mod = _apply_defusing(defused_mod)
        defused[defused_mod] = stdlib_mod

    return defused


__version__ = "0.8.0rc2"

__all__ = [
    "DEFAULT_FORBID_DTD",
    "DEFAULT_FORBID_ENTITIES",
    "DEFAULT_FORBID_EXTERNAL",
    "DefusedXmlException",
    "DTDForbidden",
    "EntitiesForbidden",
    "ExternalReferenceForbidden",
    "NotSupportedError",
    "RequestConfig",
    "get_request_config",
    "request_config",
    "resolve_request_config",
]
