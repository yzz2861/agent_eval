# defusedxml
#
# Copyright (c) 2013-2020 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Common constants, exceptions and helper functions
"""
import sys
import xml.parsers.expat

PY3 = True

# Fail early when pyexpat is not installed correctly
if not hasattr(xml.parsers.expat, "ParserCreate"):
    raise ImportError("pyexpat")  # pragma: no cover


class DefusedXmlException(ValueError):
    """Base exception"""

    def __repr__(self):
        return str(self)


class DTDForbidden(DefusedXmlException):
    """Document type definition is forbidden"""

    def __init__(
        self,
        name,
        sysid,
        pubid,
        construct=None,
        depth=0,
        source=None,
        line=None,
        column=None,
        offset=None,
    ):
        super().__init__()
        self.name = name
        self.sysid = sysid
        self.pubid = pubid
        self.construct = construct or "doctype"
        self.depth = depth
        self.source = source
        self.line = line
        self.column = column
        self.offset = offset

    def __str__(self):
        tpl = "{}(name='{}', system_id={!r}, public_id={!r})"
        return tpl.format(self.__class__.__name__, self.name, self.sysid, self.pubid)


class EntitiesForbidden(DefusedXmlException):
    """Entity definition is forbidden"""

    def __init__(
        self,
        name,
        value,
        base,
        sysid,
        pubid,
        notation_name,
        construct=None,
        depth=0,
        source=None,
        line=None,
        column=None,
        offset=None,
    ):
        super().__init__()
        self.name = name
        self.value = value
        self.base = base
        self.sysid = sysid
        self.pubid = pubid
        self.notation_name = notation_name
        self.construct = construct or "entity-declaration"
        self.depth = depth
        self.source = source
        self.line = line
        self.column = column
        self.offset = offset

    def __str__(self):
        tpl = "{}(name='{}', system_id={!r}, public_id={!r})"
        return tpl.format(self.__class__.__name__, self.name, self.sysid, self.pubid)


class ExternalReferenceForbidden(DefusedXmlException):
    """Resolving an external reference is forbidden"""

    def __init__(
        self,
        context,
        base,
        sysid,
        pubid,
        construct=None,
        depth=0,
        source=None,
        line=None,
        column=None,
        offset=None,
    ):
        super().__init__()
        self.context = context
        self.base = base
        self.sysid = sysid
        self.pubid = pubid
        self.construct = construct or "external-reference"
        self.depth = depth
        self.source = source
        self.line = line
        self.column = column
        self.offset = offset

    def __str__(self):
        tpl = "{}(system_id='{}', public_id={})"
        return tpl.format(self.__class__.__name__, self.sysid, self.pubid)


class ParameterEntityForbidden(EntitiesForbidden):
    """A parameter entity declaration or reference is forbidden"""


class UnparsedEntityForbidden(EntitiesForbidden):
    """An unparsed entity declaration is forbidden"""


class NotationForbidden(EntitiesForbidden):
    """A notation declaration is forbidden"""


class ConditionalSectionForbidden(EntitiesForbidden):
    """An INCLUDE or IGNORE conditional section is forbidden"""


class ExternalSubsetForbidden(ExternalReferenceForbidden):
    """An external DTD subset is forbidden"""


class NotSupportedError(DefusedXmlException):
    """The operation is not supported"""


def _apply_defusing(defused_mod):
    assert defused_mod is sys.modules[defused_mod.__name__]
    stdlib_name = defused_mod.__origin__
    __import__(stdlib_name, {}, {}, ["*"])
    stdlib_mod = sys.modules[stdlib_name]
    stdlib_names = set(dir(stdlib_mod))
    for name, obj in vars(defused_mod).items():
        if name.startswith("_") or name not in stdlib_names:
            continue
        setattr(stdlib_mod, name, obj)
    return stdlib_mod
