# defusedxml
#
# Copyright (c) 2013-2020 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Common constants, exceptions and helper functions

All policy violations carry a common set of diagnostic attributes so that
callers can trace *which* backend rejected *which* policy item at *which*
document offset, without ever embedding the parsed document or any resolved
external content in the error message.
"""
import sys
import xml.parsers.expat

PY3 = True

# Fail early when pyexpat is not installed correctly
if not hasattr(xml.parsers.expat, "ParserCreate"):
    raise ImportError("pyexpat")  # pragma: no cover


class DefusedXmlException(ValueError):
    """Base exception for all defusedxml policy violations.

    Attributes
    ----------
    backend:
        Name of the backend that detected the violation, e.g. ``"etree"``,
        ``"minidom"``, ``"sax"``, ``"pulldom"``, ``"lxml"`` or
        ``"xmlrpc"``.
    policy_item:
        The policy item that was violated, one of the ``POLICY_*`` string
        constants defined in :mod:`defusedxml.policy`.
    position:
        A :class:`XMLPosition` describing where in the XML byte stream the
        violation was detected, or ``None`` if the backend cannot report a
        position.  Document content is never included.
    """

    backend = None
    policy_item = None
    position = None

    def __repr__(self):
        return str(self)

    def _set_diagnostics(self, backend=None, policy_item=None, position=None):
        """Attach backend / policy / offset traceability information."""
        if backend is not None:
            self.backend = backend
        if policy_item is not None:
            self.policy_item = policy_item
        if position is not None:
            self.position = position
        return self


class XMLPosition:
    """Location of a policy violation inside an XML document.

    The class only stores numeric offsets and line/column information.  It
    never holds a reference to the document itself or to the content of an
    external entity.
    """

    __slots__ = ("byte_index", "line", "column")

    def __init__(self, byte_index=None, line=None, column=None):
        self.byte_index = byte_index
        self.line = line
        self.column = column

    def __repr__(self):
        return "XMLPosition(byte_index={!r}, line={!r}, column={!r})".format(
            self.byte_index, self.line, self.column
        )

    def __str__(self):
        return "offset={}, line={}, column={}".format(
            self.byte_index, self.line, self.column
        )

    def __eq__(self, other):
        if not isinstance(other, XMLPosition):
            return NotImplemented
        return (
            self.byte_index == other.byte_index
            and self.line == other.line
            and self.column == other.column
        )


class DTDForbidden(DefusedXmlException):
    """Document type definition is forbidden"""

    def __init__(self, name, sysid, pubid, position=None):
        super().__init__()
        self.name = name
        self.sysid = sysid
        self.pubid = pubid
        self.position = position

    def __str__(self):
        tpl = "DTDForbidden(name='{}', system_id={!r}, public_id={!r})"
        return tpl.format(self.name, self.sysid, self.pubid)


class EntitiesForbidden(DefusedXmlException):
    """Entity definition is forbidden"""

    def __init__(
        self, name, value, base, sysid, pubid, notation_name, position=None
    ):
        super().__init__()
        self.name = name
        self.value = value
        self.base = base
        self.sysid = sysid
        self.pubid = pubid
        self.notation_name = notation_name
        self.position = position

    def __str__(self):
        tpl = "EntitiesForbidden(name='{}', system_id={!r}, public_id={!r})"
        return tpl.format(self.name, self.sysid, self.pubid)


class ExternalReferenceForbidden(DefusedXmlException):
    """Resolving an external reference is forbidden"""

    def __init__(self, context, base, sysid, pubid, position=None):
        super().__init__()
        self.context = context
        self.base = base
        self.sysid = sysid
        self.pubid = pubid
        self.position = position

    def __str__(self):
        tpl = "ExternalReferenceForbidden(system_id='{}', public_id={})"
        return tpl.format(self.sysid, self.pubid)


class ExternalDTDForbidden(DefusedXmlException):
    """An external DTD subset (SYSTEM/PUBLIC doctype) is forbidden"""

    def __init__(self, name, sysid, pubid, position=None):
        super().__init__()
        self.name = name
        self.sysid = sysid
        self.pubid = pubid
        self.position = position

    def __str__(self):
        tpl = "ExternalDTDForbidden(name='{}', system_id={!r}, public_id={!r})"
        return tpl.format(self.name, self.sysid, self.pubid)


class UnparsedEntityForbidden(DefusedXmlException):
    """An unparsed (NDATA) entity declaration is forbidden"""

    def __init__(self, name, base, sysid, pubid, notation_name, position=None):
        super().__init__()
        self.name = name
        self.base = base
        self.sysid = sysid
        self.pubid = pubid
        self.notation_name = notation_name
        self.position = position

    def __str__(self):
        tpl = (
            "UnparsedEntityForbidden(name='{}', system_id={!r}, "
            "public_id={!r}, notation={!r})"
        )
        return tpl.format(self.name, self.sysid, self.pubid, self.notation_name)


class ParameterEntityForbidden(DefusedXmlException):
    """A parameter entity (``%name;``) declaration is forbidden"""

    def __init__(self, name, base, sysid, pubid, position=None):
        super().__init__()
        self.name = name
        self.base = base
        self.sysid = sysid
        self.pubid = pubid
        self.position = position

    def __str__(self):
        tpl = "ParameterEntityForbidden(name='{}', system_id={!r}, public_id={!r})"
        return tpl.format(self.name, self.sysid, self.pubid)


class BackendUnavailable(DefusedXmlException):
    """A requested backend is not installed or cannot be imported."""

    def __init__(self, backend, cause=None):
        super().__init__()
        self.backend = backend
        self.cause = cause

    def __str__(self):
        if self.cause is None:
            return "BackendUnavailable(backend='{}')".format(self.backend)
        return "BackendUnavailable(backend='{}', cause={!r})".format(
            self.backend, "{}: {}".format(type(self.cause).__name__, self.cause)
        )


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
