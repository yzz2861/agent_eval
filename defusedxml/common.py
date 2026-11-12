# defusedxml
#
# Copyright (c) 2013-2020 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Common constants, exceptions and helper functions
"""
import hashlib
import sys
import uuid
from collections import OrderedDict
from urllib.parse import urlsplit
import xml.parsers.expat

PY3 = True

# Security modes.  ``KEEP`` preserves the historical, verbose exception
# strings.  ``SAFE`` removes every piece of environment information
# (absolute paths, internal URLs, entity values and document fragments) from
# the exception objects that may cross a trust boundary.
KEEP = "keep"
SAFE = "safe"
_SECURITY_MODES = frozenset((KEEP, SAFE))

# Bounded registry of audit records.  The raw system id never leaves this
# module; only redacted, serializable views are exposed.
_AUDIT_LIMIT = 4096
_audit_records = OrderedDict()

# How many characters of an entity / DTD name are kept in a name summary.
_NAME_SUMMARY_LIMIT = 32

# Fail early when pyexpat is not installed correctly
if not hasattr(xml.parsers.expat, "ParserCreate"):
    raise ImportError("pyexpat")  # pragma: no cover


def get_security_mode():
    """Return the process wide default security mode."""
    return _security_mode


# Default to the historical, backwards compatible behavior.
_security_mode = KEEP


def set_security_mode(mode):
    """Set the process wide default security mode.

    The mode only affects exceptions that are constructed after the call.
    Existing exception instances keep the mode they were created with so
    that their string representation never changes out from under a
    caller that already caught them.
    """
    global _security_mode
    if mode not in _SECURITY_MODES:
        raise ValueError(
            "security mode must be one of {!r}, got {!r}".format(
                sorted(_SECURITY_MODES), mode
            )
        )
    _security_mode = mode


class security_mode:
    """Context manager to temporarily override the default security mode."""

    def __init__(self, mode):
        if mode not in _SECURITY_MODES:
            raise ValueError(
                "security mode must be one of {!r}, got {!r}".format(
                    sorted(_SECURITY_MODES), mode
                )
            )
        self.mode = mode
        self._previous = None

    def __enter__(self):
        self._previous = get_security_mode()
        set_security_mode(self.mode)
        return self

    def __exit__(self, exc_type, exc, tb):
        set_security_mode(self._previous)


def _sanitize_text(text):
    """Replace control characters so that values cannot forge log lines."""
    if not isinstance(text, str):
        try:
            text = str(text)
        except Exception:
            return "<unrepresentable>"
    return "".join(ch if (ch >= " " and ch != "\x7f") else "?" for ch in text)


def summarize_name(name):
    """Return a non-reversible summary of an entity or DTD name.

    The full name is treated as potentially sensitive input.  A short
    prefix plus a hash keeps the summary useful for correlation without
    echoing an attacker controlled identifier verbatim.
    """
    if name is None:
        return None
    if not isinstance(name, str):
        name = str(name)
    digest = hashlib.sha256(name.encode("utf-8", "replace")).hexdigest()[:12]
    if len(name) > _NAME_SUMMARY_LIMIT:
        prefix = _sanitize_text(name[:_NAME_SUMMARY_LIMIT])
        return "{}...(len={},sha256={})".format(prefix, len(name), digest)
    return "{}(sha256={})".format(_sanitize_text(name), digest)


def source_category(sysid):
    """Classify a system id without returning the identifier itself."""
    if sysid is None:
        return "none"
    if not isinstance(sysid, str):
        return "other"
    stripped = sysid.strip()
    if not stripped:
        return "none"
    split = urlsplit(stripped)
    scheme = split.scheme.lower()
    if scheme:
        if scheme == "file":
            return "file"
        if scheme in ("http", "https"):
            return "http"
        if scheme in ("ftp", "ftps"):
            return "ftp"
        if scheme == "data":
            return "data"
        if scheme == "jar":
            return "jar"
        return "scheme:{}".format(scheme)
    if stripped.startswith("/") or (len(stripped) > 1 and stripped[1] == ":"):
        return "file"
    return "relative"


class AuditRecord:
    """Server side audit entry with a redacted, serialization safe view.

    The raw system id is held in a private attribute and is never part of
    ``to_dict()``, ``str()`` or ``repr()``.  Auditing code can only learn
    the coarse :meth:`source_category` through the controlled interface.
    """

    def __init__(self, audit_id, exception_category, source, name, line, column):
        self._audit_id = audit_id
        self.exception_category = exception_category
        self.source_category = source_category(source)
        self.name_summary = summarize_name(name)
        self.line = line
        self.column = column
        self._sysid = source

    @property
    def audit_id(self):
        return self._audit_id

    def to_dict(self):
        """Return a redacted mapping suitable for log serialization."""
        return {
            "audit_id": self._audit_id,
            "exception_category": self.exception_category,
            "source_category": self.source_category,
            "name_summary": self.name_summary,
            "line": self.line,
            "column": self.column,
        }

    def __repr__(self):
        return "AuditRecord({})".format(self.to_dict())

    __str__ = __repr__


def register_audit_record(record):
    """Store an audit record in the bounded registry."""
    _audit_records[record.audit_id] = record
    _audit_records.move_to_end(record.audit_id)
    while len(_audit_records) > _AUDIT_LIMIT:
        _audit_records.popitem(last=False)
    return record.audit_id


def get_audit_record(audit_id):
    """Controlled lookup for server side auditing code.

    Returns the redacted :class:`AuditRecord` or ``None``.  The record's
    serialization view never contains the raw system id.
    """
    return _audit_records.get(audit_id)


def clear_audit_records():
    """Remove all audit records (primarily intended for tests)."""
    _audit_records.clear()


def _new_audit_id():
    return uuid.uuid4().hex


def parser_position(parser):
    """Best effort ``(line, column)`` for an expat based parser.

    pyexpat keeps cumulative line and column counters across ``feed()``
    calls, so the position stays accurate when a document is parsed in
    several chunks.
    """
    if parser is None:
        return None, None
    if hasattr(parser, "CurrentLineNumber"):
        # A raw pyexpat parser exposes the counters directly.
        expat_parser = parser
    else:
        expat_parser = getattr(parser, "parser", None) or getattr(
            parser, "_parser", None
        )
    if expat_parser is None:
        return None, None
    try:
        return expat_parser.CurrentLineNumber, expat_parser.CurrentColumnNumber
    except (AttributeError, xml.parsers.expat.ExpatError):
        return None, None


class _SecurityMixin:
    """Shared initialization and redaction helpers for defused exceptions."""

    exception_category = "defused_xml"

    def _init_security(self, mode, parser, name, source, line=None, column=None):
        if mode is None:
            mode = get_security_mode()
        if mode not in _SECURITY_MODES:
            raise ValueError(
                "security mode must be one of {!r}, got {!r}".format(
                    sorted(_SECURITY_MODES), mode
                )
            )
        self.security_mode = mode
        if line is None or column is None:
            parser_line, parser_column = parser_position(parser)
            if line is None:
                line = parser_line
            if column is None:
                column = parser_column
        self.line = line
        self.column = column
        self.name_summary = summarize_name(name)
        self.audit_id = None
        if mode == SAFE:
            self.audit_id = _new_audit_id()
            register_audit_record(
                AuditRecord(
                    self.audit_id, self.exception_category, source, name, line, column
                )
            )

    def client_details(self):
        """Serialization safe keyword details for the safe representation."""
        return (
            "category={!r}, line={!r}, column={!r}, "
            "name_summary={!r}, audit_id={!r}"
        ).format(
            self.exception_category,
            self.line,
            self.column,
            self.name_summary,
            self.audit_id,
        )

    def client_dict(self):
        """Redacted mapping suitable for client responses or structured logs."""
        return {
            "category": self.exception_category,
            "line": self.line,
            "column": self.column,
            "name_summary": self.name_summary,
            "audit_id": self.audit_id,
        }


class DefusedXmlException(ValueError):
    """Base exception"""

    def __repr__(self):
        return str(self)


class DTDForbidden(DefusedXmlException, _SecurityMixin):
    """Document type definition is forbidden"""

    exception_category = "dtd_forbidden"

    def __init__(
        self,
        name,
        sysid,
        pubid,
        security_mode=None,
        parser=None,
        line=None,
        column=None,
    ):
        super().__init__()
        self._init_security(security_mode, parser, name, sysid, line, column)
        if self.security_mode == SAFE:
            # Keep the attributes for backwards compatible attribute access
            # but strip every value that could identify the environment.
            name = None
            sysid = None
            pubid = None
        self.name = name
        self.sysid = sysid
        self.pubid = pubid

    def __str__(self):
        if self.security_mode == SAFE:
            return "DTDForbidden({})".format(self.client_details())
        tpl = "DTDForbidden(name='{}', system_id={!r}, public_id={!r})"
        return tpl.format(self.name, self.sysid, self.pubid)


class EntitiesForbidden(DefusedXmlException, _SecurityMixin):
    """Entity definition is forbidden"""

    exception_category = "entity_forbidden"

    def __init__(
        self,
        name,
        value,
        base,
        sysid,
        pubid,
        notation_name,
        security_mode=None,
        parser=None,
        line=None,
        column=None,
    ):
        super().__init__()
        self._init_security(security_mode, parser, name, sysid, line, column)
        if self.security_mode == SAFE:
            name = None
            value = None
            base = None
            sysid = None
            pubid = None
            notation_name = None
        self.name = name
        self.value = value
        self.base = base
        self.sysid = sysid
        self.pubid = pubid
        self.notation_name = notation_name

    def __str__(self):
        if self.security_mode == SAFE:
            return "EntitiesForbidden({})".format(self.client_details())
        tpl = "EntitiesForbidden(name='{}', system_id={!r}, public_id={!r})"
        return tpl.format(self.name, self.sysid, self.pubid)


class ExternalReferenceForbidden(DefusedXmlException, _SecurityMixin):
    """Resolving an external reference is forbidden"""

    exception_category = "external_reference_forbidden"

    def __init__(
        self,
        context,
        base,
        sysid,
        pubid,
        security_mode=None,
        parser=None,
        line=None,
        column=None,
    ):
        super().__init__()
        self._init_security(security_mode, parser, None, sysid, line, column)
        if self.security_mode == SAFE:
            context = None
            base = None
            sysid = None
            pubid = None
        self.context = context
        self.base = base
        self.sysid = sysid
        self.pubid = pubid

    def __str__(self):
        if self.security_mode == SAFE:
            return "ExternalReferenceForbidden({})".format(self.client_details())
        tpl = "ExternalReferenceForbidden(system_id='{}', public_id={})"
        return tpl.format(self.sysid, self.pubid)


class NotSupportedError(DefusedXmlException, _SecurityMixin):
    """The operation is not supported"""

    exception_category = "not_supported"

    def __init__(self, message=None, security_mode=None, parser=None):
        super().__init__()
        self._init_security(security_mode, parser, None, None)
        if self.security_mode == SAFE:
            message = None
        self.message = message

    def __str__(self):
        if self.security_mode == SAFE:
            return "NotSupportedError({})".format(self.client_details())
        if self.message is None:
            return ""
        return str(self.message)


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
