# defusedxml
#
# Copyright (c) 2013-2020 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Explicit forensic analysis mode for defusedxml

The forensic mode runs a sample through one or more defused backends and
produces a structured, JSON serializable error profile instead of a bare
exception. Profiles are designed for malware triage pipelines:

* stable error categories and per-backend statuses, including
  ``unsupported`` when a backend cannot perform a check
* line / column / byte offset when the backend reports them, explicitly
  ``None`` otherwise
* sanitized DTD / entity summaries (no entity values, no absolute paths,
  no document content)
* a content hash of the sample and a cluster key so that near-duplicate
  samples group together

The module never modifies the existing parser classes. Exceptions raised
by :func:`parse` keep their original type and raise location and simply
carry an additional ``forensic_profile`` attribute.
"""
from __future__ import print_function, absolute_import

import hashlib
import io
import json
import warnings

from .common import (
    DTDForbidden,
    EntitiesForbidden,
    ExternalReferenceForbidden,
    NotSupportedError,
)

__all__ = [
    "FORMAT_VERSION",
    "STATUS_BLOCKED",
    "STATUS_CLEAN",
    "STATUS_ERROR",
    "STATUS_SYNTAX_ERROR",
    "STATUS_UNSUPPORTED",
    "CATEGORY_DTD_FORBIDDEN",
    "CATEGORY_ENTITIES_FORBIDDEN",
    "CATEGORY_EXTERNAL_REFERENCE_FORBIDDEN",
    "CATEGORY_NOT_SUPPORTED",
    "CATEGORY_SYNTAX_ERROR",
    "CATEGORY_UNKNOWN_ERROR",
    "DEFAULT_BACKENDS",
    "ForensicReport",
    "analyze",
    "analyze_backend",
    "parse",
    "sanitize_identifier",
]

FORMAT_VERSION = "defusedxml-forensic/1"

#: forensic statuses, ``unsupported`` is a first class state and is never
#: folded into parse failures
STATUS_CLEAN = "clean"
STATUS_BLOCKED = "blocked"
STATUS_SYNTAX_ERROR = "syntax_error"
STATUS_UNSUPPORTED = "unsupported"
STATUS_ERROR = "error"

#: stable error categories
CATEGORY_DTD_FORBIDDEN = "dtd_forbidden"
CATEGORY_ENTITIES_FORBIDDEN = "entities_forbidden"
CATEGORY_EXTERNAL_REFERENCE_FORBIDDEN = "external_reference_forbidden"
CATEGORY_NOT_SUPPORTED = "not_supported"
CATEGORY_SYNTAX_ERROR = "syntax_error"
CATEGORY_UNKNOWN_ERROR = "unknown_error"

#: backends probed by default, in a stable order
DEFAULT_BACKENDS = ("ElementTree", "minidom", "pulldom", "sax", "lxml")

_REDACTED = "<redacted>"


def _to_bytes(data):
    if isinstance(data, str):
        return data.encode("utf-8")
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    raise TypeError("data must be str or bytes, not %s" % type(data).__name__)


def sanitize_identifier(value):
    """Redact directory components of a system/public identifier.

    Only the URI scheme (if any) and the final path component survive, so
    absolute paths and internal hosts never leak into a report. The mapping
    is deterministic for a given input.
    """
    if value is None:
        return None
    text = str(value)
    if not text:
        return ""
    scheme = ""
    rest = text
    if "://" in text:
        scheme, rest = text.split("://", 1)
        scheme = scheme + "://"
    normalized = rest.replace("\\", "/")
    if "/" in normalized:
        tail = normalized.rsplit("/", 1)[-1] or _REDACTED
        return "%s%s/%s" % (scheme, _REDACTED, tail)
    return scheme + normalized


def _hash_text(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _dtd_summary(exc):
    return {
        "name": exc.name,
        "system_id": sanitize_identifier(exc.sysid),
        "public_id": sanitize_identifier(exc.pubid),
    }


def _entity_summary(exc):
    value = exc.value
    return {
        "name": exc.name,
        "has_value": value is not None,
        "value_length": len(value) if value is not None else None,
        "value_sha256": _hash_text(value) if value is not None else None,
        "system_id": sanitize_identifier(exc.sysid),
        "public_id": sanitize_identifier(exc.pubid),
        "notation_name": exc.notation_name,
    }


def _external_reference_summary(exc):
    return {
        "context": sanitize_identifier(exc.context),
        "system_id": sanitize_identifier(exc.sysid),
        "public_id": sanitize_identifier(exc.pubid),
    }


def _syntax_error_types():
    from xml.etree.ElementTree import ParseError as ETParseError
    from xml.parsers.expat import ExpatError
    from xml.sax import SAXParseException

    types = [ETParseError, ExpatError, SAXParseException]
    try:
        from lxml.etree import XMLSyntaxError
    except ImportError:
        pass
    else:
        types.append(XMLSyntaxError)
    return tuple(types)


def _extract_position(exc):
    """Best effort line / column / byte offset, None when unavailable."""
    line = column = byte_offset = None
    position = getattr(exc, "position", None)
    if position is not None:
        # xml.etree.ElementTree.ParseError and lxml XMLSyntaxError
        line, column = position
    get_line = getattr(exc, "getLineNumber", None)
    if line is None and get_line is not None:
        # xml.sax.SAXParseException
        line = get_line()
        column = exc.getColumnNumber()
    if line is None and getattr(exc, "lineno", None) is not None:
        # xml.parsers.expat.ExpatError
        line = exc.lineno
        column = getattr(exc, "offset", None)
    byte_offset = getattr(exc, "byte_index", None)
    return line, column, byte_offset


def _profile_from_exception(backend, exc):
    profile = {
        "backend": backend,
        "status": STATUS_ERROR,
        "category": CATEGORY_UNKNOWN_ERROR,
        "exception_type": type(exc).__name__,
        "line": None,
        "column": None,
        "byte_offset": None,
        "dtd": None,
        "entity": None,
        "external_reference": None,
        "policy_hits": [],
    }
    if isinstance(exc, NotSupportedError):
        profile["status"] = STATUS_UNSUPPORTED
        profile["category"] = CATEGORY_NOT_SUPPORTED
        return profile
    if isinstance(exc, DTDForbidden):
        profile["status"] = STATUS_BLOCKED
        profile["category"] = CATEGORY_DTD_FORBIDDEN
        profile["dtd"] = _dtd_summary(exc)
        profile["policy_hits"] = ["forbid_dtd"]
        return profile
    if isinstance(exc, EntitiesForbidden):
        profile["status"] = STATUS_BLOCKED
        profile["category"] = CATEGORY_ENTITIES_FORBIDDEN
        profile["entity"] = _entity_summary(exc)
        profile["policy_hits"] = ["forbid_entities"]
        return profile
    if isinstance(exc, ExternalReferenceForbidden):
        profile["status"] = STATUS_BLOCKED
        profile["category"] = CATEGORY_EXTERNAL_REFERENCE_FORBIDDEN
        profile["external_reference"] = _external_reference_summary(exc)
        profile["policy_hits"] = ["forbid_external"]
        return profile
    if isinstance(exc, _syntax_error_types()):
        profile["status"] = STATUS_SYNTAX_ERROR
        profile["category"] = CATEGORY_SYNTAX_ERROR
        line, column, byte_offset = _extract_position(exc)
        profile["line"] = line
        profile["column"] = column
        profile["byte_offset"] = byte_offset
        return profile
    return profile


def _clean_profile(backend):
    return {
        "backend": backend,
        "status": STATUS_CLEAN,
        "category": None,
        "exception_type": None,
        "line": None,
        "column": None,
        "byte_offset": None,
        "dtd": None,
        "entity": None,
        "external_reference": None,
        "policy_hits": [],
    }


def _run_elementtree(data, forbid_dtd, forbid_entities, forbid_external):
    from . import ElementTree

    ElementTree.fromstring(
        data,
        forbid_dtd=forbid_dtd,
        forbid_entities=forbid_entities,
        forbid_external=forbid_external,
    )


def _run_minidom(data, forbid_dtd, forbid_entities, forbid_external):
    from . import minidom

    minidom.parseString(
        data,
        forbid_dtd=forbid_dtd,
        forbid_entities=forbid_entities,
        forbid_external=forbid_external,
    )


def _run_pulldom(data, forbid_dtd, forbid_entities, forbid_external):
    from . import pulldom

    events = pulldom.parse(
        io.BytesIO(_to_bytes(data)),
        forbid_dtd=forbid_dtd,
        forbid_entities=forbid_entities,
        forbid_external=forbid_external,
    )
    # pulldom parses lazily, consume the stream to surface errors
    for _event in events:
        pass


def _run_sax(data, forbid_dtd, forbid_entities, forbid_external):
    from xml.sax.handler import ContentHandler

    from . import sax

    sax.parseString(
        _to_bytes(data),
        ContentHandler(),
        forbid_dtd=forbid_dtd,
        forbid_entities=forbid_entities,
        forbid_external=forbid_external,
    )


def _run_lxml(data, forbid_dtd, forbid_entities, forbid_external):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from . import lxml
    except ImportError:
        raise NotSupportedError("lxml backend is not available")
    # defusedxml.lxml has no forbid_external support
    lxml.fromstring(data, forbid_dtd=forbid_dtd, forbid_entities=forbid_entities)


_BACKENDS = {
    "ElementTree": _run_elementtree,
    "minidom": _run_minidom,
    "pulldom": _run_pulldom,
    "sax": _run_sax,
    "lxml": _run_lxml,
}


def analyze_backend(
    data, backend, forbid_dtd=False, forbid_entities=True, forbid_external=True
):
    """Analyze *data* with a single backend and return a profile dict.

    The profile is a plain dict of JSON serializable values. It never
    contains entity values, absolute paths, or document content.
    """
    try:
        runner = _BACKENDS[backend]
    except KeyError:
        raise ValueError(
            "unknown backend %r, expected one of %s"
            % (backend, ", ".join(sorted(_BACKENDS)))
        )
    try:
        runner(
            data,
            forbid_dtd=forbid_dtd,
            forbid_entities=forbid_entities,
            forbid_external=forbid_external,
        )
    except Exception as exc:
        profile = _profile_from_exception(backend, exc)
        try:
            exc.forensic_profile = profile
        except (AttributeError, TypeError):
            pass
        return profile
    return _clean_profile(backend)


def parse(data, backend, forbid_dtd=False, forbid_entities=True, forbid_external=True):
    """Parse *data* with one backend in forensic mode.

    Behaves like the backend's own parse function: the same exception
    classes are raised from the same locations. On failure the exception
    carries a structured profile in its ``forensic_profile`` attribute.
    """
    try:
        runner = _BACKENDS[backend]
    except KeyError:
        raise ValueError(
            "unknown backend %r, expected one of %s"
            % (backend, ", ".join(sorted(_BACKENDS)))
        )
    try:
        runner(
            data,
            forbid_dtd=forbid_dtd,
            forbid_entities=forbid_entities,
            forbid_external=forbid_external,
        )
    except Exception as exc:
        exc.forensic_profile = _profile_from_exception(backend, exc)
        raise
    return _clean_profile(backend)


class ForensicReport:
    """Cross-backend forensic report for one sample.

    ``to_dict()`` / ``to_json()`` are deterministic for a given sample and
    option set, contain no entity values, absolute paths, or document
    content, and round-trip through :meth:`from_json`.
    """

    def __init__(self, sample, options, backends):
        self.sample = sample
        self.options = options
        self.backends = backends

    @property
    def cluster_key(self):
        """Stable grouping key that ignores entity names, values, positions
        and content, so samples that differ only by one entity cluster
        together."""
        material = {
            name: [profile["status"], profile["category"]]
            for name, profile in sorted(self.backends.items())
        }
        canonical = json.dumps(material, sort_keys=True)
        return hashlib.sha256(canonical.encode("ascii")).hexdigest()

    @property
    def backends_differ(self):
        """True when backends disagree on status or category."""
        outcomes = {
            (profile["status"], profile["category"])
            for profile in self.backends.values()
        }
        return len(outcomes) > 1

    def compare(self):
        """Compact per-backend view for cross-backend comparison."""
        return {
            name: {"status": p["status"], "category": p["category"]}
            for name, p in self.backends.items()
        }

    def to_dict(self):
        return {
            "format": FORMAT_VERSION,
            "sample": dict(self.sample),
            "options": dict(self.options),
            "cluster_key": self.cluster_key,
            "backends": {name: dict(p) for name, p in self.backends.items()},
        }

    def to_json(self):
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, payload):
        if payload.get("format") != FORMAT_VERSION:
            raise ValueError("unsupported forensic report format")
        return cls(
            sample=dict(payload["sample"]),
            options=dict(payload["options"]),
            backends={name: dict(p) for name, p in payload["backends"].items()},
        )

    @classmethod
    def from_json(cls, text):
        return cls.from_dict(json.loads(text))

    def __eq__(self, other):
        if not isinstance(other, ForensicReport):
            return NotImplemented
        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __repr__(self):
        return "ForensicReport(sample=%r, backends=%r)" % (
            self.sample,
            self.compare(),
        )


def analyze(data, backends=None, forbid_dtd=False, forbid_entities=True, forbid_external=True):
    """Run *data* through several backends and build a forensic report.

    :param data: XML sample as ``str`` or ``bytes``
    :param backends: iterable of backend names, defaults to
        :data:`DEFAULT_BACKENDS`
    :returns: :class:`ForensicReport`
    """
    raw = _to_bytes(data)
    if backends is None:
        backends = DEFAULT_BACKENDS
    profiles = {}
    for name in backends:
        profiles[name] = analyze_backend(
            data,
            name,
            forbid_dtd=forbid_dtd,
            forbid_entities=forbid_entities,
            forbid_external=forbid_external,
        )
    sample = {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
    }
    options = {
        "forbid_dtd": bool(forbid_dtd),
        "forbid_entities": bool(forbid_entities),
        "forbid_external": bool(forbid_external),
    }
    return ForensicReport(sample=sample, options=options, backends=profiles)
