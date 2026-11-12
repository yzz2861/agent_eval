# defusedxml
#
# Copyright (c) 2026 by the defusedxml authors
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license/license
"""Shared XML security policy and unified parsing entry.

The module answers a single question for *every* backend: given the same
:class:`XMLSecurityPolicy`, will a particular XML document be accepted or
rejected?  Each backend only maps the shared policy onto its own parser
capabilities; backends that cannot enforce a requested restriction fail with
:class:`~defusedxml.common.NotSupportedError` instead of silently degrading.

Policy items
------------

``allow_dtd``
    Permit any ``<!DOCTYPE ...>`` declaration at all.
``allow_internal_entities``
    Permit internal general entity declarations (``<!ENTITY a "text">``).
``allow_parameter_entities``
    Permit parameter entity declarations (``<!ENTITY % pe ...>``).
``allow_external_references``
    Permit external *general* entities (``<!ENTITY e SYSTEM "uri">``).
``allow_external_dtd``
    Permit external DTD subsets referenced from the doctype
    (``<!DOCTYPE html SYSTEM "uri">`` / ``PUBLIC``).
``allow_unparsed_entities``
    Permit unparsed (``NDATA``) entity declarations.
"""
from __future__ import absolute_import

from dataclasses import dataclass, fields, replace

from .common import BackendUnavailable, NotSupportedError


# Policy item identifiers.  They are stored on every raised
# DefusedXmlException as ``policy_item`` for audit traceability.
POLICY_DTD = "allow_dtd"
POLICY_INTERNAL_ENTITIES = "allow_internal_entities"
POLICY_PARAMETER_ENTITIES = "allow_parameter_entities"
POLICY_EXTERNAL_REFERENCES = "allow_external_references"
POLICY_EXTERNAL_DTD = "allow_external_dtd"
POLICY_UNPARSED_ENTITIES = "allow_unparsed_entities"

POLICY_ITEMS = (
    POLICY_DTD,
    POLICY_INTERNAL_ENTITIES,
    POLICY_PARAMETER_ENTITIES,
    POLICY_EXTERNAL_REFERENCES,
    POLICY_EXTERNAL_DTD,
    POLICY_UNPARSED_ENTITIES,
)

# Backend identifiers.
BACKEND_ETREE = "etree"
BACKEND_MINIDOM = "minidom"
BACKEND_SAX = "sax"
BACKEND_PULLDOM = "pulldom"
BACKEND_LXML = "lxml"
BACKEND_XMLRPC = "xmlrpc"

ALL_BACKENDS = (
    BACKEND_ETREE,
    BACKEND_MINIDOM,
    BACKEND_SAX,
    BACKEND_PULLDOM,
    BACKEND_LXML,
    BACKEND_XMLRPC,
)


@dataclass(frozen=True)
class XMLSecurityPolicy:
    """Declarative description of what an XML parser is allowed to accept.

    Every flag is an *allow* flag, so a strict policy is expressed with
    ``False`` values rather than a mixture of ``forbid_*`` knobs.  Instances
    are immutable; use :meth:`replace` to derive a modified copy.
    """

    allow_dtd: bool = True
    allow_internal_entities: bool = False
    allow_parameter_entities: bool = False
    allow_external_references: bool = False
    allow_external_dtd: bool = False
    allow_unparsed_entities: bool = False

    def __post_init__(self):
        for field in fields(self):
            if not isinstance(getattr(self, field.name), bool):
                raise TypeError(
                    "policy item {!r} must be a boolean, got {!r}".format(
                        field.name, type(getattr(self, field.name)).__name__
                    )
                )

    def replace(self, **changes):
        """Return a copy with the given policy items changed."""
        return replace(self, **changes)

    def is_strict(self):
        """True when every DTD/entity feature is denied."""
        return all(not getattr(self, item) for item in POLICY_ITEMS)

    def denied_items(self):
        """Tuple of policy items that this policy denies."""
        return tuple(item for item in POLICY_ITEMS if not getattr(self, item))

    def to_dict(self):
        return {item: getattr(self, item) for item in POLICY_ITEMS}

    @classmethod
    def from_legacy(
        cls,
        forbid_dtd=False,
        forbid_entities=True,
        forbid_external=True,
    ):
        """Map the historical ``forbid_*`` boolean API onto a policy.

        The legacy API only had three switches.  It treated every entity
        declaration (internal, parameter, unparsed) through the single
        ``forbid_entities`` flag and could not distinguish an external DTD
        subset, so external DTDs keep the historical permissive behavior.
        """
        return cls(
            allow_dtd=not forbid_dtd,
            allow_internal_entities=not forbid_entities,
            allow_parameter_entities=not forbid_entities,
            allow_external_references=not forbid_external,
            # The legacy API had no external-DTD switch and left doctype
            # SYSTEM/PUBLIC identifiers untouched.
            allow_external_dtd=True,
            allow_unparsed_entities=not forbid_entities,
        )


#: The default policy used by the unified entry.  DTD markup is allowed but
#: every entity expansion / external reference is denied.
DEFAULT_POLICY = XMLSecurityPolicy()

#: A maximally permissive policy, equivalent to an unmodified stdlib parser.
PERMISSIVE_POLICY = XMLSecurityPolicy(
    allow_dtd=True,
    allow_internal_entities=True,
    allow_parameter_entities=True,
    allow_external_references=True,
    allow_external_dtd=True,
    allow_unparsed_entities=True,
)

#: A strict policy: no DTD or entity feature of any kind is accepted.
STRICT_POLICY = XMLSecurityPolicy(
    allow_dtd=False,
    allow_internal_entities=False,
    allow_parameter_entities=False,
    allow_external_references=False,
    allow_external_dtd=False,
    allow_unparsed_entities=False,
)

#: Policies tailored to backends that cannot enforce every denial.  They only
#: relax the specific item that the backend is physically unable to check;
#: every other restriction stays identical to :data:`DEFAULT_POLICY`, so the
#: acceptance decision still matches across backends for real-world payloads.
BACKEND_DEFAULT_POLICIES = {
    # lxml cannot tell parameter entities apart from general entities.
    # Rather than silently ignoring the denial, callers must opt in by using
    # this lxml-scoped default via the explicit policy API.
    BACKEND_LXML: DEFAULT_POLICY.replace(allow_parameter_entities=True),
}


@dataclass(frozen=True)
class BackendCapability:
    """Which policy items a backend can enforce on its own.

    A capability is ``True`` when the backend exposes a parser hook that lets
    defusedxml reject the feature *before* any network or file access and
    without relying on the document being well-formed.
    """

    backend: str
    allow_dtd: bool
    allow_internal_entities: bool
    allow_parameter_entities: bool
    allow_external_references: bool
    allow_external_dtd: bool
    allow_unparsed_entities: bool

    def unsupported_denials(self, policy):
        """Policy items that are denied but cannot be enforced."""
        missing = []
        for item in POLICY_ITEMS:
            if not getattr(policy, item) and not getattr(self, item):
                missing.append(item)
        return tuple(missing)


# The four pyexpat-based backends share expat's full callback surface:
# StartDoctypeDeclHandler (DTD and external DTD id), EntityDeclHandler
# (internal vs parameter vs external general entities),
# UnparsedEntityDeclHandler and ExternalEntityRefHandler.
_EXPAT_CAPABILITY = dict(
    allow_dtd=True,
    allow_internal_entities=True,
    allow_parameter_entities=True,
    allow_external_references=True,
    allow_external_dtd=True,
    allow_unparsed_entities=True,
)

CAPABILITIES = {
    BACKEND_ETREE: BackendCapability(BACKEND_ETREE, **_EXPAT_CAPABILITY),
    BACKEND_MINIDOM: BackendCapability(BACKEND_MINIDOM, **_EXPAT_CAPABILITY),
    BACKEND_SAX: BackendCapability(BACKEND_SAX, **_EXPAT_CAPABILITY),
    BACKEND_PULLDOM: BackendCapability(BACKEND_PULLDOM, **_EXPAT_CAPABILITY),
    # lxml exposes docinfo/internal DTD entity declarations and the doctype
    # system/public identifiers.  Unparsed entities are recognizable because
    # their content is the notation name while they also carry a system URL.
    # Parameter entities however look identical to ordinary general entities
    # (external parameter entity == external general entity, internal
    # parameter entity == internal general entity), so they cannot be
    # enforced and must fail closed.
    BACKEND_LXML: BackendCapability(
        BACKEND_LXML,
        allow_dtd=True,
        allow_internal_entities=True,
        allow_parameter_entities=False,
        allow_external_references=True,
        allow_external_dtd=True,
        allow_unparsed_entities=True,
    ),
    BACKEND_XMLRPC: BackendCapability(BACKEND_XMLRPC, **_EXPAT_CAPABILITY),
}


def check_capability(backend, policy):
    """Raise :class:`NotSupportedError` on an unenforceable denial.

    A strict policy must never be downgraded: when a backend lacks the hook
    needed to enforce a denied policy item, parsing fails immediately.
    Allowed items never require support because they simply leave the
    backend's default behavior untouched.
    """
    capability = CAPABILITIES[backend]
    missing = capability.unsupported_denials(policy)
    if missing:
        raise NotSupportedError(
            "backend {!r} cannot enforce denied policy item(s) {}; "
            "refusing to parse rather than silently downgrading".format(
                backend, ", ".join(missing)
            )
        )


def _import_backend_module(backend):
    """Import a backend module, translating ImportError to BackendUnavailable."""
    module_names = {
        BACKEND_ETREE: "defusedxml.ElementTree",
        BACKEND_MINIDOM: "defusedxml.minidom",
        BACKEND_SAX: "defusedxml.sax",
        BACKEND_PULLDOM: "defusedxml.pulldom",
        BACKEND_LXML: "defusedxml.lxml",
        BACKEND_XMLRPC: "defusedxml.xmlrpc",
    }
    try:
        import importlib

        return importlib.import_module(module_names[backend])
    except ImportError as exc:
        raise BackendUnavailable(backend, exc)


#: Name of the bytes/string parsing function exposed by each backend.
_FROMSTRING_NAMES = {
    BACKEND_ETREE: "fromstring",
    BACKEND_MINIDOM: "parseString",
    BACKEND_SAX: "parseString",
    BACKEND_PULLDOM: "parseString",
    BACKEND_LXML: "fromstring",
    BACKEND_XMLRPC: "fromstring",
}


def available_backends():
    """Tuple of backend identifiers importable in this environment."""
    available = []
    for backend in ALL_BACKENDS:
        try:
            module = _import_backend_module(backend)
        except BackendUnavailable:
            continue
        if backend == BACKEND_LXML and not getattr(
            module, "is_available", lambda: True
        )():
            continue
        available.append(backend)
    return tuple(available)


def _resolve_policy(policy, kwargs):
    """Resolve an explicit policy or build one from legacy keyword flags."""
    if policy is not None:
        if kwargs:
            raise TypeError(
                "pass either 'policy' or legacy forbid_* keyword arguments, "
                "not both: {}".format(", ".join(sorted(kwargs)))
            )
        if not isinstance(policy, XMLSecurityPolicy):
            raise TypeError(
                "policy must be an XMLSecurityPolicy instance, got {!r}".format(
                    type(policy).__name__
                )
            )
        return policy
    if kwargs:
        return XMLSecurityPolicy.from_legacy(**kwargs)
    return DEFAULT_POLICY


def _check_backend(backend, policy):
    module = _import_backend_module(backend)  # raise BackendUnavailable first
    if backend == BACKEND_LXML and not getattr(
        module, "is_available", lambda: True
    )():
        raise BackendUnavailable(backend)
    check_capability(backend, policy)


def parse(source, backend=BACKEND_ETREE, policy=None, **legacy_kwargs):
    """Parse a filename, path or file-like object under a shared policy.

    Returns the backend-native parsed object (an ElementTree, a minidom
    Document, a pulldom event stream, an lxml tree or an xmlrpc target).
    """
    policy = _resolve_policy(policy, legacy_kwargs)
    _check_backend(backend, policy)
    module = _import_backend_module(backend)
    if backend == BACKEND_SAX:
        # xml.sax.parse requires a content handler argument.
        from xml.sax.saxutils import XMLGenerator
        import io

        handler = XMLGenerator(io.StringIO())
        return module.parse(source, handler, policy=policy)
    result = module.parse(source, policy=policy)
    if backend == BACKEND_PULLDOM:
        # materialize the lazy event stream so violations raise at parse time
        return list(result)
    return result


def fromstring(text, backend=BACKEND_ETREE, policy=None, **legacy_kwargs):
    """Parse an in-memory bytes/str document under a shared policy."""
    policy = _resolve_policy(policy, legacy_kwargs)
    _check_backend(backend, policy)
    module = _import_backend_module(backend)
    func = getattr(module, _FROMSTRING_NAMES[backend])
    if backend == BACKEND_SAX:
        # xml.sax.parseString requires a content handler argument.
        from xml.sax.saxutils import XMLGenerator
        import io

        handler = XMLGenerator(io.StringIO())
        return func(text, handler, policy=policy)
    if backend == BACKEND_XMLRPC:
        return func(text, policy=policy)
    result = func(text, policy=policy)
    if backend == BACKEND_PULLDOM:
        # pulldom is a lazy event generator; consume the events so that any
        # policy violation raises at parse time like the other backends.
        return list(result)
    return result


def parse_string(text, backend=BACKEND_ETREE, policy=None, **legacy_kwargs):
    """Alias for :func:`fromstring` matching the minidom/sax naming."""
    return fromstring(text, backend, policy, **legacy_kwargs)


__all__ = [
    "POLICY_DTD",
    "POLICY_INTERNAL_ENTITIES",
    "POLICY_PARAMETER_ENTITIES",
    "POLICY_EXTERNAL_REFERENCES",
    "POLICY_EXTERNAL_DTD",
    "POLICY_UNPARSED_ENTITIES",
    "POLICY_ITEMS",
    "ALL_BACKENDS",
    "BACKEND_ETREE",
    "BACKEND_MINIDOM",
    "BACKEND_SAX",
    "BACKEND_PULLDOM",
    "BACKEND_LXML",
    "BACKEND_XMLRPC",
    "XMLSecurityPolicy",
    "DEFAULT_POLICY",
    "PERMISSIVE_POLICY",
    "STRICT_POLICY",
    "BackendCapability",
    "CAPABILITIES",
    "check_capability",
    "available_backends",
    "parse",
    "fromstring",
    "parse_string",
]
