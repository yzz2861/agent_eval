"""
Offline reconciliation of signed originals, revisions, and review receipts.

XML Signature verification answers a narrow question: did a particular key sign a particular byte sequence? Legal
archives often need a second, local question answered without contacting the sender: which signed original does a
revision belong to, and which revision does a signed review receipt approve? A receipt can be cryptographically valid
yet be filed next to the wrong revision, and a revision can be signed correctly yet have a missing or contradictory
predecessor.

This module adds an offline acceptance check on top of :class:`signxml.VerifyResult` objects. It never re-verifies a
signature and never makes a new trust decision. Callers pass results that were already obtained from
:meth:`signxml.XMLVerifier.verify`. The module then:

* reads each document's signed content declaration and checks the declared digest against the signed content;
* follows revision predecessors by their signed identifiers, so sibling element order and input order do not matter;
* verifies that each receipt's signed target identifier and digest identify the document it claims to approve;
* checks that the receipt's signed role and scope are authorised for the trusted signer and the target document; and
* reports missing predecessors, contradictory lineage order, and receipt role mismatches separately.

The check supports a graph rather than a single chain. One original may have several parallel revisions, each accepted
by a different reviewer. Receipts are bound to the object they signed, not to the position where they were filed.

Canonical XML shape
-------------------

The parser accepts several common local names (see :class:`ReceiptPolicy`), but the canonical shape is::

    <Original Id="original-1">
      <Body>...</Body>
      <ContentDeclaration Kind="original" Object="original-1"
                          DigestMethod="sha256" Digest="..."/>
    </Original>

    <Revision Id="revision-a">
      <Body>...</Body>
      <ContentDeclaration Kind="revision" Object="revision-a"
                          DigestMethod="sha256" Digest="...">
        <Predecessor Ref="original-1" DigestMethod="sha256" Digest="..."/>
      </ContentDeclaration>
    </Revision>

    <Receipt Id="receipt-a">
      <Decision>Approved</Decision>
      <ReceiptDeclaration Role="reviewer" Scope="legal-review"
                          DigestMethod="sha256" Target="revision-a" Digest="..."/>
    </Receipt>

``Digest`` on a document declaration is the digest of the signed document content with the declaration and any
``ds:Signature`` elements removed. ``Digest`` on a receipt declaration is the digest of the approved target's content.
The declaration itself is inside the signed object; changing the target, predecessor, role, scope, or digest therefore
invalidates the XML signature.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from lxml import etree

from .exceptions import InvalidInput, SignXMLException
from .util import ds_tag
from .verifier import VerifyResult

_DS_SIGNATURE = ds_tag("Signature")
_ID_ATTRIBUTES = ("Id", "ID", "id", "{http://www.w3.org/XML/1998/namespace}id")

_DECLARATION_NAMES = frozenset(
    {
        "contentdeclaration",
        "documentdeclaration",
        "receiptdeclaration",
        "approvaldeclaration",
        "commitment",
        "declaration",
    }
)
_ORIGINAL_NAMES = frozenset({"original", "originaldocument", "source", "sourcedocument", "base"})
_REVISION_NAMES = frozenset({"revision", "revised", "reviseddocument", "amendment", "amend", "revisiondocument", "rev"})
_RECEIPT_NAMES = frozenset(
    {"receipt", "reviewreceipt", "approvalreceipt", "acknowledgement", "acknowledgment", "acceptance"}
)

_PREDECESSOR_NAMES = frozenset(
    {
        "predecessor",
        "predecessorref",
        "previous",
        "previousref",
        "parent",
        "parentref",
        "base",
        "baseref",
        "supersedes",
        "supersedesref",
    }
)
_TARGET_NAMES = frozenset(
    {
        "target",
        "targetref",
        "approves",
        "approved",
        "approvesref",
        "objectref",
        "subject",
        "subjectref",
        "decisionref",
        "reference",
        "ref",
        "uri",
    }
)
_OBJECT_NAMES = frozenset({"object", "objectid", "about", "subject", "target", "ref", "uri"})
_DIGEST_NAMES = frozenset({"digest", "digestvalue", "contentdigest", "hash", "value"})
_DIGEST_METHOD_NAMES = frozenset({"digestmethod", "algorithm", "hashalgorithm"})
_ROLE_NAMES = frozenset({"role", "receiptrole", "reviewerrole", "capacity", "actedas"})
_SCOPE_NAMES = frozenset(
    {"scope", "scopes", "appliesto", "applicability", "domain", "scopeofapplication", "jurisdiction"}
)
_SEQUENCE_NAMES = frozenset({"sequence", "seq", "order", "revisionnumber", "generation", "version"})
_ISSUED_NAMES = frozenset({"issuedat", "signedat", "createdat", "timestamp", "notbefore"})

_DIGEST_ALIASES = {
    "sha256": "sha256",
    "sha384": "sha384",
    "sha512": "sha512",
    "sha1": "sha1",
}
_TRAILING_REFERENCE_PUNCTUATION = ".,;:)]}"


def _local_name(qualified_name: str) -> str:
    if not isinstance(qualified_name, str):
        return ""
    if qualified_name.startswith("{"):
        return qualified_name.rsplit("}", 1)[-1]
    return qualified_name


def _normal_name(value: str | None) -> str:
    if not value:
        return ""
    return re.sub(r"[\s_.-]+", "", value).lower()


def _element_id(element: etree._Element | None) -> str | None:
    if element is None:
        return None
    for attribute in _ID_ATTRIBUTES:
        value = element.get(attribute)
        if value:
            return value.strip()
    return None


def _reference_value(value: str | None) -> tuple[str, ...]:
    if value is None:
        return ()
    text = value.strip()
    if not text:
        return ()
    matches = re.findall(r"#([^\s#<>\"']+)", text)
    if matches:
        return tuple(token.rstrip(_TRAILING_REFERENCE_PUNCTUATION) for token in matches)
    if any(separator in text for separator in (",", ";")):
        return tuple(part.strip().lstrip("#") for part in re.split(r"[,;]+", text) if part.strip())
    return (text.lstrip("#"),)


def _first_reference(value: str | None) -> str | None:
    references = _reference_value(value)
    return references[0] if references else None


def _split_values(value: str | None) -> frozenset[str]:
    if value is None:
        return frozenset()
    parts = re.split(r"[\s,;]+", value.strip())
    return frozenset(part.strip().lower() for part in parts if part.strip())


def _attribute(element: etree._Element, names: Iterable[str]) -> str | None:
    wanted = {_normal_name(name) for name in names}
    for attribute_name, value in element.attrib.items():
        if _normal_name(_local_name(attribute_name)) in wanted and value is not None:
            return value
    return None


def _direct_child(element: etree._Element, names: Iterable[str]) -> etree._Element | None:
    wanted = {_normal_name(name) for name in names}
    for child in element:
        if isinstance(child.tag, str) and _normal_name(_local_name(child.tag)) in wanted:
            return child
    return None


def _descendant(element: etree._Element, names: Iterable[str]) -> etree._Element | None:
    direct = _direct_child(element, names)
    if direct is not None:
        return direct
    wanted = {_normal_name(name) for name in names}
    for child in element.iterdescendants():
        if isinstance(child.tag, str) and _normal_name(_local_name(child.tag)) in wanted:
            return child
    return None


def _first_value(element: etree._Element, names: Iterable[str]) -> str | None:
    value = _attribute(element, names)
    if value is not None:
        return value.strip()
    child = _direct_child(element, names)
    if child is not None and child.text:
        return child.text.strip()
    return None


def _child_value(element: etree._Element, names: Iterable[str]) -> str | None:
    child = _direct_child(element, names)
    if child is None:
        return None
    value = _attribute(child, names)
    if value is not None:
        return value.strip()
    if child.get("Ref"):
        return child.get("Ref").strip()
    if child.get("URI"):
        return child.get("URI").strip()
    if child.text:
        return child.text.strip()
    return None


def _normalize_digest_algorithm(algorithm: str | None) -> str:
    if algorithm is None:
        return "sha256"
    value = str(getattr(algorithm, "name", algorithm)).strip()
    if value.startswith("{"):
        value = _local_name(value)
    value = value.rsplit("#", 1)[-1].rsplit("/", 1)[-1]
    value = re.sub(r"[^a-z0-9]", "", value.lower())
    if value.startswith("sha3"):
        raise InvalidInput(f"Unsupported receipt digest algorithm: {algorithm}")
    if value not in _DIGEST_ALIASES:
        raise InvalidInput(f"Unsupported receipt digest algorithm: {algorithm}")
    return _DIGEST_ALIASES[value]


def _parse_digest_algorithm(element: etree._Element) -> str | None:
    value = _attribute(element, _DIGEST_METHOD_NAMES)
    if value:
        return value
    method = _direct_child(element, _DIGEST_METHOD_NAMES)
    if method is not None:
        value = method.get("Algorithm") or method.get("algorithm") or method.text
        if value:
            return value.strip()
    return None


def _parse_digest(element: etree._Element) -> str | None:
    value = _attribute(element, _DIGEST_NAMES)
    if value:
        return value.strip()
    child = _direct_child(element, _DIGEST_NAMES)
    if child is not None and child.text:
        return child.text.strip()
    return None


def _digest_bytes(value: str, algorithm: str) -> bytes | None:
    text = re.sub(r"\s+", "", value)
    if not text:
        return None
    if re.fullmatch(r"[0-9a-fA-F]+", text):
        try:
            return bytes.fromhex(text)
        except ValueError:
            return None
    try:
        return base64.b64decode(text, validate=False)
    except (ValueError, TypeError):
        return None


def _digests_equal(declared: str, actual: str, algorithm: str) -> bool:
    declared_bytes = _digest_bytes(declared, algorithm)
    actual_bytes = _digest_bytes(actual, algorithm)
    if declared_bytes is None or actual_bytes is None:
        return False
    return hmac.compare_digest(declared_bytes, actual_bytes)


def _strip_content_noise(element: etree._Element) -> None:
    for child in list(element):
        if not isinstance(child.tag, str):
            element.remove(child)
            continue
        child_name = _normal_name(_local_name(child.tag))
        if child_name == _normal_name(_local_name(_DS_SIGNATURE)) or child_name in _DECLARATION_NAMES:
            element.remove(child)
            continue
        _strip_content_noise(child)


def content_digest(element: etree._Element, algorithm: str = "sha256") -> str:
    """
    Return the base64 SHA digest of a signed document's content.

    The digest covers the document subtree after removing its declaration element(s) and any XMLDSig ``Signature``
    element. It is the value used by :class:`ContentDeclaration`-style commitments described in the module
    documentation. ``algorithm`` may be ``"sha256"`` (the default), ``"sha384"``, ``"sha512"``, or a digest URI whose
    final path component names one of those algorithms.

    :param element: The lxml element whose content should be digested.
    :param algorithm: Digest algorithm name or URI.
    :raises signxml.exceptions.InvalidInput: If the input is not an XML element or the algorithm is unsupported.
    """
    if not isinstance(element, etree._Element):
        raise InvalidInput("content_digest expects an lxml XML element")
    digest_algorithm = _normalize_digest_algorithm(algorithm)
    node = copy.deepcopy(element)
    node.tail = None
    _strip_content_noise(node)
    serialized = etree.tostring(node, with_tail=False)
    node = etree.fromstring(serialized, parser=etree.XMLParser(resolve_entities=False))
    canonical = etree.tostring(node, method="c14n", exclusive=False, with_comments=False)
    return base64.b64encode(hashlib.new(digest_algorithm, canonical).digest()).decode("ascii")


def signer_identity(result: VerifyResult) -> str:
    """
    Return a stable identity for the trusted signer of a verified result.

    When the result carries the X.509 certificate that the verifier actually trusted, the certificate's common name
    is returned as ``CN=<value>`` (or the full subject if it has no common name). Otherwise a SHA-256 fingerprint of
    the verified signature key is returned. The identity is derived from trusted verification data, never from an
    unsigned element in the document.
    """
    certificate = getattr(result, "signing_certificate", None)
    if certificate is not None:
        common_names = certificate.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if common_names:
            return "CN=" + str(common_names[0].value)
        try:
            subject = certificate.subject.rfc4514_string()
        except ValueError:
            subject = ""
        if subject:
            return subject
        return "cert-sha256:" + certificate.fingerprint(hashes.SHA256()).hex()
    return "key-sha256:" + hashlib.sha256(result.signature_key).hexdigest()


def _identity_matches(identity: str | None, seats: frozenset[str]) -> bool:
    if identity is None:
        return False
    if identity in seats:
        return True
    if identity.startswith("CN=") and identity[3:] in seats:
        return True
    if not identity.startswith("CN=") and ("CN=" + identity) in seats:
        return True
    return False


@dataclass(frozen=True)
class ReceiptRole:
    """
    A role that may issue a receipt, and the seats authorised to act in it.

    :param name: Role name, for example ``"reviewer"``.
    :param seats: Trusted signer identities allowed to issue receipts in this role. Use the values returned by
        :func:`signer_identity` (for example ``"CN=reviewer-a"``).
    :param scopes: Applicable scopes for this role. A receipt may name one or more scopes. If set to ``None``, the
        role is not restricted by the role declaration, but a receipt still has to carry a scope when the target
        document declares one.
    :param document_kinds: Document kinds this role may approve (``"original"``, ``"revision"``, or both). If set to
        ``None``, the role may approve any document kind.
    :param required_distinct_signatures: Number of distinct seats whose valid receipts must be present when this role
        is required. A seat counts once regardless of how many receipts it signed.
    """

    name: str
    seats: frozenset[str] | Iterable[str]
    scopes: frozenset[str] | Iterable[str] | None = None
    document_kinds: frozenset[str] | Iterable[str] | None = None
    required_distinct_signatures: int = 1

    def __post_init__(self):
        if not isinstance(self.name, str) or not self.name.strip():
            raise InvalidInput("ReceiptRole.name must be a non-empty string")
        seats = frozenset(str(seat).strip() for seat in self.seats if str(seat).strip())
        if not seats:
            raise InvalidInput(f"ReceiptRole {self.name!r} must declare at least one seat")
        object.__setattr__(self, "seats", seats)
        if self.scopes is None:
            object.__setattr__(self, "scopes", None)
        else:
            object.__setattr__(
                self,
                "scopes",
                frozenset(str(scope).strip().lower() for scope in self.scopes if str(scope).strip()),
            )
        if self.document_kinds is None:
            object.__setattr__(self, "document_kinds", None)
        else:
            object.__setattr__(
                self,
                "document_kinds",
                frozenset(_normal_name(kind) for kind in self.document_kinds if str(kind).strip()),
            )
        if not isinstance(self.required_distinct_signatures, int) or self.required_distinct_signatures < 0:
            raise InvalidInput("ReceiptRole.required_distinct_signatures must be a non-negative integer")
        if self.required_distinct_signatures > len(seats):
            raise InvalidInput(f"ReceiptRole {self.name!r} requires more distinct seats than it declares as eligible")

    @property
    def eligible_seats(self) -> frozenset[str]:
        """Alias for :attr:`seats`, provided for readability."""
        return self.seats


def _normalize_role_spec(roles: tuple[ReceiptRole, ...] | Mapping[str, ReceiptRole]) -> tuple[ReceiptRole, ...]:
    if isinstance(roles, Mapping):
        result = tuple(roles.values())
        for key, role in roles.items():
            if key != role.name:
                raise InvalidInput("ReceiptPolicy role mapping keys must match role names")
        return result
    return tuple(roles)


def _normalize_role_names(value: Iterable[str] | str) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    return tuple(str(item) for item in value)


@dataclass(frozen=True)
class ReceiptPolicy:
    """
    Declarative policy for offline receipt reconciliation.

    :param roles: Roles that may issue receipts. Pass a tuple of :class:`ReceiptRole` objects or a mapping from role
        name to role object.
    :param required_roles: Mapping from document kind (``"original"`` or ``"revision"``), root element local name, or
        ``"*"`` to the role names that must have valid receipts for that document. A document kind key takes
        precedence over a local-name key, which takes precedence over ``"*"``.
    :param default_required_roles: Required roles to use when no more specific entry is present. By default a document
        needs no receipt; in a legal review workflow the caller will normally set ``{"revision": ("reviewer",)}``.
    :param kind_for: Optional mapping or callable that classifies a verified object as ``"original"``,
        ``"revision"``, or ``"receipt"``. A mapping is keyed by root local name. If omitted, the standard local names
        and signed declaration contents are inspected.
    :param seat_for: Optional mapping or callable that maps a :class:`signxml.VerifyResult` to the signer's seat.
        If omitted, :func:`signer_identity` is used. Mapping keys are usually values returned by
        :func:`signer_identity`; values are the seat names used in :class:`ReceiptRole`.
    :param require_document_digest: Require originals and revisions to carry a digest in their signed content
        declaration. Defaults to ``True`` because the declaration is the commitment to the actual object.
    :param require_predecessor_digest: Require revisions to commit to the predecessor's content digest. Defaults to
        ``True``. Set to ``False`` only for archives whose signed predecessor identifier is considered sufficient.
    :param require_receipt_digest: Require receipts to carry a digest of the approved target. Defaults to ``False``;
        the signed target identifier is always required, and a supplied digest is always checked.
    """

    roles: tuple[ReceiptRole, ...] | Mapping[str, ReceiptRole]
    required_roles: Mapping[str, Iterable[str] | str] = field(default_factory=dict)
    default_required_roles: Iterable[str] | str = ()
    kind_for: Mapping[str, str] | Callable[[VerifyResult], str | None] | None = None
    seat_for: Mapping[str, str] | Callable[[VerifyResult], str | None] = signer_identity
    require_document_digest: bool = True
    require_predecessor_digest: bool = True
    require_receipt_digest: bool = False
    receipt_types: frozenset[str] | Iterable[str] = _RECEIPT_NAMES
    original_types: frozenset[str] | Iterable[str] = _ORIGINAL_NAMES
    revision_types: frozenset[str] | Iterable[str] = _REVISION_NAMES

    def __post_init__(self):
        roles = _normalize_role_spec(self.roles)
        if not roles:
            raise InvalidInput("ReceiptPolicy must declare at least one role")
        names = [role.name for role in roles]
        if len(names) != len(set(names)):
            raise InvalidInput("ReceiptPolicy role names must be unique")
        object.__setattr__(self, "roles", roles)
        object.__setattr__(self, "_roles_by_name", {role.name: role for role in roles})
        normalized_required = {}
        for key, value in self.required_roles.items():
            normalized_required[_normal_name(key)] = _normalize_role_names(value)
        object.__setattr__(self, "required_roles", normalized_required)
        object.__setattr__(self, "default_required_roles", _normalize_role_names(self.default_required_roles))
        for role_names in normalized_required.values():
            for role_name in role_names:
                if role_name not in self._roles_by_name:
                    raise InvalidInput(f"ReceiptPolicy refers to undeclared role {role_name!r}")
        for role_name in self.default_required_roles:
            if role_name not in self._roles_by_name:
                raise InvalidInput(f"ReceiptPolicy refers to undeclared role {role_name!r}")
        if isinstance(self.kind_for, Mapping):
            object.__setattr__(self, "kind_for", {_normal_name(key): value for key, value in self.kind_for.items()})
        elif self.kind_for is not None and not callable(self.kind_for):
            raise InvalidInput("ReceiptPolicy.kind_for must be a mapping or a callable")
        if isinstance(self.seat_for, Mapping):
            object.__setattr__(self, "seat_for", {str(key): str(value) for key, value in self.seat_for.items()})
        elif not callable(self.seat_for):
            raise InvalidInput("ReceiptPolicy.seat_for must be a mapping or a callable")
        for attribute in ("receipt_types", "original_types", "revision_types"):
            values = getattr(self, attribute)
            object.__setattr__(self, attribute, frozenset(_normal_name(value) for value in values))

    def role(self, name: str) -> ReceiptRole | None:
        """Return the declared role named ``name``, or ``None``."""
        return self._roles_by_name.get(name)

    def seat(self, result: VerifyResult) -> str | None:
        """Resolve the trusted signer seat for a verified result."""
        if callable(self.seat_for):
            return self.seat_for(result)
        identity = signer_identity(result)
        if identity in self.seat_for:
            return self.seat_for[identity]
        if identity.startswith("CN=") and identity[3:] in self.seat_for:
            return self.seat_for[identity[3:]]
        return identity

    def required_roles_for(self, kind: str, local_name: str) -> tuple[str, ...]:
        """Return the receipt roles required for a document kind or root local name."""
        normalized_kind = _normal_name(kind)
        normalized_name = _normal_name(local_name)
        for key in (normalized_kind, normalized_name, "*"):
            if key in self.required_roles:
                return tuple(self.required_roles[key])
        return tuple(self.default_required_roles)


@dataclass(frozen=True)
class ReceiptIssue:
    """
    One diagnostic produced by the offline receipt check.

    ``code`` is stable and machine-readable. The principal categories are ``missing_predecessor``,
    ``out_of_order``, ``role_mismatch``, ``scope_mismatch``, ``receipt_target_mismatch``, ``commitment_mismatch``,
    ``missing_receipt``, ``receipt_unbound``, and ``receipt_unknown_target``.
    """

    code: str
    message: str
    object_id: str | None = None
    receipt_id: str | None = None
    role: str | None = None

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class DocumentStatus:
    """
    Acceptance status of one original or revision.

    ``accepted`` (also available as ``signable``) is true only when the document's lineage and commitment are sound and
    all required receipt roles are satisfied by receipts bound to this exact object. ``issues`` explains every
    diagnostic that concerns the document; a bad extra receipt does not make an otherwise valid document
    unacceptable.
    """

    object_id: str | None
    kind: str
    predecessor: str | None
    sequence: int | None
    accepted: bool
    required_roles: tuple[str, ...]
    satisfied_roles: tuple[str, ...]
    missing_roles: tuple[str, ...]
    receipts: tuple[str, ...]
    commitment_digest: str | None
    predecessor_digest: str | None
    signer: str | None
    local_name: str
    issues: tuple[ReceiptIssue, ...]
    result: VerifyResult

    @property
    def signable(self) -> bool:
        """Alias for :attr:`accepted` (the document may still be signed/accepted)."""
        return self.accepted


@dataclass(frozen=True)
class ReceiptStatus:
    """
    Acceptance status of one signed review receipt.

    ``target_object_ids`` lists the targets named by the receipt. ``target_object_id`` is the first one for
    convenience. ``accepted`` means the receipt was authorised by the policy for at least one supplied target; it
    does not override a target document's own lineage or commitment problems.
    """

    receipt_id: str
    target_object_ids: tuple[str, ...]
    role: str | None
    scopes: frozenset[str]
    signer: str | None
    accepted: bool
    issues: tuple[ReceiptIssue, ...]
    result: VerifyResult

    @property
    def target_object_id(self) -> str | None:
        """The first target named by the receipt, if any."""
        return self.target_object_ids[0] if self.target_object_ids else None


@dataclass(frozen=True)
class ReceiptVerificationResult:
    """
    Result of an offline receipt reconciliation.

    Documents are sorted by object identifier and receipts by receipt identifier, so the result does not depend on
    the order in which the caller supplied verified results. Use :attr:`accepted_documents` to see which objects
    remain signable, or :meth:`format` for a human-readable report.
    """

    documents: tuple[DocumentStatus, ...]
    receipts: tuple[ReceiptStatus, ...]
    issues: tuple[ReceiptIssue, ...]

    @property
    def accepted_documents(self) -> tuple[str, ...]:
        """Identifiers of documents that are acceptable (signable) in this check."""
        return tuple(document.object_id for document in self.documents if document.accepted and document.object_id)

    @property
    def blocked_documents(self) -> tuple[str, ...]:
        """Identifiers of documents that are not acceptable in this check."""
        return tuple(document.object_id for document in self.documents if not document.accepted and document.object_id)

    @property
    def signable_object_ids(self) -> tuple[str, ...]:
        """Alias for :attr:`accepted_documents`."""
        return self.accepted_documents

    @property
    def accepted(self) -> bool:
        """True when every supplied document is acceptable."""
        return bool(self.documents) and not self.blocked_documents

    @property
    def complete(self) -> bool:
        """Alias for :attr:`accepted`."""
        return self.accepted

    @property
    def any_accepted(self) -> bool:
        """True when at least one supplied document is acceptable."""
        return bool(self.accepted_documents)

    @property
    def problems(self) -> tuple[str, ...]:
        """Diagnostic messages, provided as a convenience for rejection handling."""
        return tuple(str(issue) for issue in self.issues)

    def document(self, object_id: str) -> DocumentStatus | None:
        """Return the status for ``object_id``, or ``None``."""
        return next((document for document in self.documents if document.object_id == object_id), None)

    def receipt(self, receipt_id: str) -> ReceiptStatus | None:
        """Return the status for ``receipt_id``, or ``None``."""
        return next((receipt for receipt in self.receipts if receipt.receipt_id == receipt_id), None)

    def raise_for_rejection(self) -> ReceiptVerificationResult:
        """
        Return this result if every supplied document is acceptable; otherwise raise :class:`ReceiptRejected`.
        """
        if not self.accepted:
            raise ReceiptRejected(self)
        return self

    def format(self) -> str:
        """Render a stable, human-readable summary of document and receipt status."""
        lines = [f"Receipt check: {len(self.accepted_documents)}/{len(self.documents)} document(s) signable"]
        if self.accepted_documents:
            lines.append("Signable: " + ", ".join(self.accepted_documents))
        if self.blocked_documents:
            lines.append("Blocked: " + ", ".join(self.blocked_documents))
        for document in self.documents:
            status = "SIGNABLE" if document.accepted else "NOT SIGNABLE"
            detail = f"  {document.object_id or '<no-id>'} [{document.kind}] {status}"
            if document.predecessor is not None:
                detail += f" predecessor={document.predecessor}"
            if document.required_roles:
                detail += " required=" + ",".join(document.required_roles)
            if document.receipts:
                detail += " receipts=" + ",".join(document.receipts)
            lines.append(detail)
            for issue in document.issues:
                lines.append(f"    - {issue}")
        for receipt in self.receipts:
            status = "ACCEPTED" if receipt.accepted else "REJECTED"
            targets = ",".join(receipt.target_object_ids) if receipt.target_object_ids else "<none>"
            scopes = ",".join(sorted(receipt.scopes)) if receipt.scopes else "<none>"
            detail = (
                f"  {receipt.receipt_id} -> {targets} role={receipt.role or '<none>'} "
                f"scope={scopes} signer={receipt.signer or '<unknown>'} {status}"
            )
            lines.append(detail)
            for issue in receipt.issues:
                lines.append(f"    - {issue}")
        return "\n".join(lines)

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly summary of the result."""
        return {
            "accepted": self.accepted,
            "signable": list(self.accepted_documents),
            "blocked": list(self.blocked_documents),
            "documents": [
                {
                    "object_id": document.object_id,
                    "kind": document.kind,
                    "predecessor": document.predecessor,
                    "accepted": document.accepted,
                    "receipts": list(document.receipts),
                    "required_roles": list(document.required_roles),
                    "satisfied_roles": list(document.satisfied_roles),
                    "missing_roles": list(document.missing_roles),
                    "issues": [
                        {
                            "code": issue.code,
                            "message": issue.message,
                            "role": issue.role,
                        }
                        for issue in document.issues
                    ],
                }
                for document in self.documents
            ],
            "receipts": [
                {
                    "receipt_id": receipt.receipt_id,
                    "target_object_ids": list(receipt.target_object_ids),
                    "role": receipt.role,
                    "scopes": sorted(receipt.scopes),
                    "signer": receipt.signer,
                    "accepted": receipt.accepted,
                    "issues": [
                        {
                            "code": issue.code,
                            "message": issue.message,
                            "role": issue.role,
                        }
                        for issue in receipt.issues
                    ],
                }
                for receipt in self.receipts
            ],
            "issues": [
                {
                    "code": issue.code,
                    "message": issue.message,
                    "object_id": issue.object_id,
                    "receipt_id": issue.receipt_id,
                    "role": issue.role,
                }
                for issue in self.issues
            ],
        }

    def __str__(self) -> str:
        return self.format()


ReceiptResult = ReceiptVerificationResult
ReceiptCheckResult = ReceiptVerificationResult


class ReceiptRejected(SignXMLException):
    """
    Raised by :meth:`ReceiptVerificationResult.raise_for_rejection` when one or more documents are not acceptable.
    """

    def __init__(self, result: ReceiptVerificationResult):
        self.result = result
        message = "; ".join(result.problems) if result.problems else "Receipt check rejected"
        super().__init__(message)


@dataclass(frozen=True)
class _Declaration:
    element: etree._Element
    kind: str | None
    object_id: str | None
    digest: str | None
    digest_algorithm: str | None
    predecessor: str | None
    predecessor_digest: str | None
    predecessor_digest_algorithm: str | None
    targets: tuple[str, ...]
    target_digest: str | None
    target_digest_algorithm: str | None
    role: str | None
    scopes: frozenset[str]
    sequence: int | None
    issued_at: str | None


def _find_declaration(root: etree._Element, names: Iterable[str]) -> etree._Element:
    name = _normal_name(_local_name(root.tag))
    if name in {_normal_name(candidate) for candidate in names}:
        return root
    declaration = _direct_child(root, names)
    if declaration is not None:
        return declaration
    declaration = _descendant(root, names)
    if declaration is not None:
        return declaration
    return root


def _parse_sequence(element: etree._Element) -> int | None:
    value = _first_value(element, _SEQUENCE_NAMES)
    if value is None:
        return None
    try:
        return int(value.strip())
    except ValueError:
        raise InvalidInput(f"Invalid document sequence value: {value!r}")


def _parse_predecessor(declaration: etree._Element) -> tuple[str | None, str | None, str | None]:
    ref = _first_value(declaration, _PREDECESSOR_NAMES)
    digest = None
    digest_algorithm = None
    child = _direct_child(declaration, _PREDECESSOR_NAMES)
    if child is not None:
        ref = _attribute(child, ("Ref", "Id", "ID", "URI", "Href", "Object")) or (
            child.text.strip() if child.text and child.text.strip() else ref
        )
        digest = _parse_digest(child)
        digest_algorithm = _parse_digest_algorithm(child)
    if ref is not None:
        ref = _first_reference(ref)
    if digest is None:
        digest = _first_value(declaration, ("PredecessorDigest", "PreviousDigest", "BaseDigest"))
    if digest_algorithm is None:
        digest_algorithm = _first_value(
            declaration, ("PredecessorDigestMethod", "PreviousDigestMethod", "BaseDigestMethod")
        )
    return ref, digest, digest_algorithm


def _parse_targets(
    declaration: etree._Element, root: etree._Element, receipt: bool
) -> tuple[tuple[str, ...], str | None, str | None]:
    target_names = _TARGET_NAMES if receipt else _OBJECT_NAMES
    targets: list[str] = []
    if receipt:
        value = _first_value(declaration, target_names)
        if value:
            targets.extend(_reference_value(value))
        for child in declaration:
            if not isinstance(child.tag, str):
                continue
            if _normal_name(_local_name(child.tag)) not in {_normal_name(name) for name in target_names}:
                continue
            child_ref = _attribute(child, ("Ref", "Id", "ID", "URI", "Href", "Object", "Target"))
            if child_ref is None and child.text:
                child_ref = child.text
            if child_ref:
                targets.extend(_reference_value(child_ref))
    else:
        value = _first_value(declaration, target_names)
        if value:
            targets.append(_first_reference(value))
    targets = [target for target in targets if target]
    digest = _parse_digest(declaration)
    digest_algorithm = _parse_digest_algorithm(declaration)
    return tuple(dict.fromkeys(targets)), digest, digest_algorithm


def _parse_declaration(root: etree._Element, *, receipt: bool) -> _Declaration:
    names = (
        frozenset(
            {
                "receiptdeclaration",
                "approval",
                "approvaldeclaration",
                "contentdeclaration",
                "commitment",
                "declaration",
            }
        )
        if receipt
        else frozenset(
            {
                "contentdeclaration",
                "documentdeclaration",
                "commitment",
                "declaration",
            }
        )
    )
    declaration = _find_declaration(root, names)
    targets, target_digest, target_digest_algorithm = _parse_targets(declaration, root, receipt)
    object_id = None if receipt else _first_reference(_first_value(declaration, _OBJECT_NAMES))
    if not receipt and object_id is None:
        object_id = _element_id(root)
    predecessor, predecessor_digest, predecessor_digest_algorithm = _parse_predecessor(declaration)
    scopes = _split_values(_first_value(declaration, _SCOPE_NAMES))
    if not scopes:
        scopes = _split_values(_first_value(root, _SCOPE_NAMES))
    try:
        sequence = _parse_sequence(declaration)
    except InvalidInput:
        sequence = None
    return _Declaration(
        element=declaration,
        kind=_first_value(declaration, ("Kind", "Type", "DocumentKind")),
        object_id=object_id,
        digest=_parse_digest(declaration),
        digest_algorithm=_parse_digest_algorithm(declaration),
        predecessor=predecessor,
        predecessor_digest=predecessor_digest,
        predecessor_digest_algorithm=predecessor_digest_algorithm,
        targets=targets,
        target_digest=target_digest,
        target_digest_algorithm=target_digest_algorithm,
        role=_first_value(declaration, _ROLE_NAMES),
        scopes=scopes,
        sequence=sequence,
        issued_at=_first_value(declaration, _ISSUED_NAMES),
    )


def _synthetic_id(result: VerifyResult, prefix: str) -> str:
    return f"{prefix}-" + hashlib.sha256(result.signature_key).hexdigest()[:12]


def _document_kind(policy: ReceiptPolicy, result: VerifyResult, declaration: _Declaration | None) -> str | None:
    root = result.signed_xml
    if root is None:
        return None
    local_name = _normal_name(_local_name(root.tag))
    if callable(policy.kind_for):
        return policy.kind_for(result)
    if isinstance(policy.kind_for, Mapping) and local_name in policy.kind_for:
        return policy.kind_for[local_name]
    if local_name in policy.receipt_types:
        return "receipt"
    if local_name in policy.original_types:
        return "original"
    if local_name in policy.revision_types:
        return "revision"
    if declaration is not None and declaration.kind:
        kind = _normal_name(declaration.kind)
        if kind in {"original", "source", "base"}:
            return "original"
        if kind in {"revision", "revised", "amendment", "amend", "rev"}:
            return "revision"
        if kind in {"receipt", "approval", "reviewreceipt", "acceptance"}:
            return "receipt"
    if declaration is not None and declaration.role:
        return "receipt"
    if declaration is not None and declaration.targets and not declaration.predecessor:
        object_id = _element_id(root)
        if object_id is not None and object_id in declaration.targets:
            return "original"
    if declaration is not None and declaration.predecessor:
        return "revision"
    if declaration is not None and declaration.targets:
        return "receipt"
    return None


def _issue(
    code: str,
    message: str,
    *,
    object_id: str | None = None,
    receipt_id: str | None = None,
    role: str | None = None,
) -> ReceiptIssue:
    return ReceiptIssue(code=code, message=message, object_id=object_id, receipt_id=receipt_id, role=role)


def _dedupe_issues(issues: Iterable[ReceiptIssue]) -> tuple[ReceiptIssue, ...]:
    seen = set()
    result = []
    for issue in issues:
        key = (issue.code, issue.message, issue.object_id, issue.receipt_id, issue.role)
        if key in seen:
            continue
        seen.add(key)
        result.append(issue)
    return tuple(result)


class XMLReceiptVerifier:
    """
    Perform an offline sign-off check over already-verified signed XML objects.

    This class is a companion to :class:`signxml.XMLVerifier`. It does not verify XML signatures; pass it
    :class:`signxml.VerifyResult` objects returned by the normal verifier. It then reconciles originals, revisions, and
    review receipts using the signed declarations inside those verified objects.

    Example::

        policy = ReceiptPolicy(
            roles=(ReceiptRole("reviewer", {"CN=reviewer-a", "CN=reviewer-b"}, scopes={"legal-review"},
                               document_kinds={"revision"}),),
            required_roles={"revision": ("reviewer",)},
        )
        result = XMLReceiptVerifier(policy).verify(verified_results)
        print(result.format())  # shows which revisions remain signable
        result.raise_for_rejection()
    """

    def __init__(self, policy: ReceiptPolicy):
        if not isinstance(policy, ReceiptPolicy):
            raise InvalidInput("XMLReceiptVerifier requires a ReceiptPolicy")
        self.policy = policy

    def verify(self, results: VerifyResult | Iterable[VerifyResult]) -> ReceiptVerificationResult:
        """
        Reconcile a set of verified results.

        :param results: One :class:`signxml.VerifyResult` or an iterable of them. Mapping inputs are accepted; each
            mapping value is treated as an iterable of results and the mapping keys are not used as evidence.
        :returns: A :class:`ReceiptVerificationResult` containing per-document and per-receipt status.
        :raises signxml.exceptions.InvalidInput: If an input item is not a :class:`signxml.VerifyResult`.
        """
        raw_results: list[VerifyResult] = []
        if isinstance(results, VerifyResult):
            raw_results = [results]
        elif isinstance(results, Mapping):
            for value in results.values():
                if isinstance(value, VerifyResult):
                    raw_results.append(value)
                else:
                    raw_results.extend(value)
        else:
            raw_results = list(results)
        if not raw_results:
            return ReceiptVerificationResult(documents=(), receipts=(), issues=())

        unique_results: list[VerifyResult] = []
        seen = set()
        for result in raw_results:
            if not isinstance(result, VerifyResult):
                raise InvalidInput("XMLReceiptVerifier.verify expects VerifyResult objects")
            fingerprint = (
                result.signed_data,
                result.signature_key,
                etree.tostring(result.signature_xml),
            )
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            unique_results.append(result)

        issues: list[ReceiptIssue] = []
        documents: dict[str, dict[str, Any]] = {}
        receipts: list[dict[str, Any]] = []

        for index, result in enumerate(unique_results):
            if result.signed_xml is None:
                issues.append(_issue("non_xml_result", "Verified result does not contain an XML object"))
                continue
            root = result.signed_xml
            local_name = _local_name(root.tag)
            provisional = _parse_declaration(root, receipt=False)
            kind = _document_kind(self.policy, result, provisional)
            if kind is None:
                issues.append(
                    _issue(
                        "unclassified_result",
                        f"Verified object {local_name!r} is not an original, revision, or receipt under this policy",
                    )
                )
                continue
            if kind == "receipt":
                declaration = _parse_declaration(root, receipt=True)
                receipt_id = _element_id(root) or _synthetic_id(result, "receipt")
                if _element_id(root) is None:
                    issues.append(
                        _issue("missing_receipt_id", "Receipt has no signed identifier", receipt_id=receipt_id)
                    )
                receipts.append(
                    {
                        "index": index,
                        "result": result,
                        "declaration": declaration,
                        "receipt_id": receipt_id,
                        "issues": [],
                    }
                )
                continue

            declaration = provisional
            object_id = _element_id(root) or declaration.object_id
            if object_id is None:
                object_id = _synthetic_id(result, kind)
                issues.append(
                    _issue("missing_object_id", f"{kind.capitalize()} has no signed identifier", object_id=object_id)
                )
            if object_id in documents:
                issue = _issue(
                    "duplicate_object",
                    f"More than one verified {kind} claims identifier {object_id!r}",
                    object_id=object_id,
                )
                issues.append(issue)
                continue

            document_issues: list[ReceiptIssue] = []
            actual_digest = None
            declared_algorithm = declaration.digest_algorithm
            try:
                actual_digest = content_digest(root, algorithm=declared_algorithm or "sha256")
            except InvalidInput as exc:
                document_issues.append(_issue("unsupported_digest", str(exc), object_id=object_id))
            if self.policy.require_document_digest and declaration.digest is None:
                document_issues.append(
                    _issue(
                        "commitment_missing",
                        f"{kind.capitalize()} {object_id} has no content digest in its signed declaration",
                        object_id=object_id,
                    )
                )
            elif declaration.digest is not None and actual_digest is not None:
                if not _digests_equal(
                    declaration.digest, actual_digest, _normalize_digest_algorithm(declared_algorithm)
                ):
                    document_issues.append(
                        _issue(
                            "commitment_mismatch",
                            f"{kind.capitalize()} {object_id} content does not match its signed declaration digest",
                            object_id=object_id,
                        )
                    )
            if declaration.object_id is not None and declaration.object_id != _element_id(root):
                document_issues.append(
                    _issue(
                        "commitment_target_mismatch",
                        f"{kind.capitalize()} declaration names {declaration.object_id!r}, "
                        f"not its own identifier {_element_id(root)!r}",
                        object_id=object_id,
                    )
                )
            if kind == "original" and declaration.predecessor is not None:
                document_issues.append(
                    _issue(
                        "out_of_order",
                        f"Original {object_id} declares predecessor {declaration.predecessor!r}",
                        object_id=object_id,
                    )
                )
            if kind == "revision" and declaration.predecessor is None:
                document_issues.append(
                    _issue(
                        "missing_predecessor",
                        f"Revision {object_id} has no signed predecessor declaration",
                        object_id=object_id,
                    )
                )
            documents[object_id] = {
                "result": result,
                "declaration": declaration,
                "object_id": object_id,
                "kind": kind,
                "local_name": _normal_name(local_name),
                "actual_digest": actual_digest,
                "issues": document_issues,
            }

        documents_by_id = dict(documents)
        for object_id, document in documents.items():
            declaration: _Declaration = document["declaration"]
            if document["kind"] != "revision":
                continue
            predecessor_id = declaration.predecessor
            if predecessor_id is None:
                continue
            predecessor = documents_by_id.get(predecessor_id)
            if predecessor is None:
                document["issues"].append(
                    _issue(
                        "missing_predecessor",
                        f"Revision {object_id} declares missing predecessor {predecessor_id!r}",
                        object_id=object_id,
                    )
                )
                continue
            if predecessor["kind"] not in {"original", "revision"}:
                document["issues"].append(
                    _issue(
                        "out_of_order",
                        f"Revision {object_id} declares non-document predecessor {predecessor_id!r}",
                        object_id=object_id,
                    )
                )
                continue
            if declaration.predecessor_digest is None and self.policy.require_predecessor_digest:
                document["issues"].append(
                    _issue(
                        "predecessor_digest_missing",
                        f"Revision {object_id} does not commit to the predecessor content digest",
                        object_id=object_id,
                    )
                )
            elif declaration.predecessor_digest is not None:
                algorithm = declaration.predecessor_digest_algorithm or "sha256"
                try:
                    actual_predecessor_digest = content_digest(predecessor["result"].signed_xml, algorithm=algorithm)
                except InvalidInput as exc:
                    document["issues"].append(_issue("unsupported_digest", str(exc), object_id=object_id))
                else:
                    if not _digests_equal(
                        declaration.predecessor_digest,
                        actual_predecessor_digest,
                        _normalize_digest_algorithm(algorithm),
                    ):
                        document["issues"].append(
                            _issue(
                                "predecessor_mismatch",
                                f"Revision {object_id} predecessor content does not match its signed digest",
                                object_id=object_id,
                            )
                        )
            if (
                declaration.sequence is not None
                and predecessor["declaration"].sequence is not None
                and declaration.sequence <= predecessor["declaration"].sequence
            ):
                document["issues"].append(
                    _issue(
                        "out_of_order",
                        f"Revision {object_id} sequence {declaration.sequence} does not follow "
                        f"predecessor {predecessor_id} sequence {predecessor['declaration'].sequence}",
                        object_id=object_id,
                    )
                )

        # Detect cycles and revisions whose ancestor chain never reaches an original.
        visiting: set[str] = set()
        finished: set[str] = set()

        def visit(object_id: str, trail: list[str]) -> None:
            if object_id in visiting:
                cycle = trail[trail.index(object_id) :] if object_id in trail else [object_id]
                for cycle_id in cycle:
                    documents[cycle_id]["issues"].append(
                        _issue(
                            "out_of_order",
                            "Revision lineage contains a cycle: " + " -> ".join(cycle + [object_id]),
                            object_id=cycle_id,
                        )
                    )
                return
            if object_id in finished or object_id not in documents:
                return
            document = documents[object_id]
            if document["kind"] == "original":
                finished.add(object_id)
                return
            visiting.add(object_id)
            predecessor_id = document["declaration"].predecessor
            if predecessor_id is None:
                visiting.discard(object_id)
                finished.add(object_id)
                return
            if predecessor_id not in documents:
                visiting.discard(object_id)
                finished.add(object_id)
                return
            visit(predecessor_id, trail + [object_id])
            visiting.discard(object_id)
            finished.add(object_id)

        for object_id in list(documents):
            visit(object_id, [])

        # Validate receipts against their signed targets.
        bindings: dict[str, list[dict[str, Any]]] = {object_id: [] for object_id in documents}
        receipt_statuses: list[ReceiptStatus] = []
        for receipt in receipts:
            declaration: _Declaration = receipt["declaration"]
            receipt_issues: list[ReceiptIssue] = []
            receipt_id = receipt["receipt_id"]
            role_name = declaration.role
            role = self.policy.role(role_name) if role_name is not None else None
            signer = self.policy.seat(receipt["result"])
            authorised = role is not None and signer is not None and _identity_matches(signer, role.seats)
            if not declaration.targets:
                receipt_issues.append(
                    _issue(
                        "receipt_unbound",
                        f"Receipt {receipt_id} does not name an approved target",
                        receipt_id=receipt_id,
                        role=role_name,
                    )
                )
            if role_name is None:
                receipt_issues.append(
                    _issue(
                        "role_mismatch",
                        f"Receipt {receipt_id} carries no signed role",
                        receipt_id=receipt_id,
                    )
                )
            elif role is None:
                receipt_issues.append(
                    _issue(
                        "role_mismatch",
                        f"Receipt {receipt_id} claims undeclared role {role_name!r}",
                        receipt_id=receipt_id,
                        role=role_name,
                    )
                )
            elif not authorised:
                receipt_issues.append(
                    _issue(
                        "role_mismatch",
                        f"Receipt {receipt_id} signer {signer or '<unknown>'} is not an eligible seat for "
                        f"role {role_name!r}",
                        receipt_id=receipt_id,
                        role=role_name,
                    )
                )
            accepted_targets: list[str] = []
            for target_id in declaration.targets:
                target = documents.get(target_id)
                if target is None:
                    issue = _issue(
                        "receipt_unknown_target",
                        f"Receipt {receipt_id} names target {target_id!r}, which is not in the verified document set",
                        object_id=target_id,
                        receipt_id=receipt_id,
                        role=role_name,
                    )
                    receipt_issues.append(issue)
                    issues.append(issue)
                    continue
                target_issue_count = len(receipt_issues)
                if role is not None:
                    if role.document_kinds is not None and _normal_name(target["kind"]) not in role.document_kinds:
                        receipt_issues.append(
                            _issue(
                                "role_mismatch",
                                f"Receipt {receipt_id} role {role_name!r} does not apply to "
                                f"{target['kind']} {target_id}",
                                object_id=target_id,
                                receipt_id=receipt_id,
                                role=role_name,
                            )
                        )
                    receipt_scopes = declaration.scopes
                    if role.scopes is not None:
                        disallowed = receipt_scopes - role.scopes
                        if disallowed or not receipt_scopes and role.scopes:
                            receipt_issues.append(
                                _issue(
                                    "scope_mismatch",
                                    f"Receipt {receipt_id} scope {sorted(receipt_scopes) or '<none>'} is not "
                                    f"authorised for role {role_name!r}",
                                    object_id=target_id,
                                    receipt_id=receipt_id,
                                    role=role_name,
                                )
                            )
                    target_scopes = target["declaration"].scopes
                    if target_scopes:
                        if not receipt_scopes:
                            receipt_issues.append(
                                _issue(
                                    "scope_mismatch",
                                    f"Receipt {receipt_id} has no scope for {target_id}, which requires "
                                    f"{sorted(target_scopes)}",
                                    object_id=target_id,
                                    receipt_id=receipt_id,
                                    role=role_name,
                                )
                            )
                        elif not (target_scopes & receipt_scopes):
                            receipt_issues.append(
                                _issue(
                                    "scope_mismatch",
                                    f"Receipt {receipt_id} scope {sorted(receipt_scopes)} does not apply to "
                                    f"{target_id} scope {sorted(target_scopes)}",
                                    object_id=target_id,
                                    receipt_id=receipt_id,
                                    role=role_name,
                                )
                            )
                if declaration.target_digest is None:
                    if self.policy.require_receipt_digest:
                        receipt_issues.append(
                            _issue(
                                "receipt_digest_missing",
                                f"Receipt {receipt_id} does not commit to {target_id} content digest",
                                object_id=target_id,
                                receipt_id=receipt_id,
                                role=role_name,
                            )
                        )
                else:
                    algorithm = declaration.target_digest_algorithm or "sha256"
                    try:
                        actual_target_digest = content_digest(target["result"].signed_xml, algorithm=algorithm)
                    except InvalidInput as exc:
                        receipt_issues.append(
                            _issue(
                                "unsupported_digest",
                                str(exc),
                                object_id=target_id,
                                receipt_id=receipt_id,
                                role=role_name,
                            )
                        )
                    else:
                        if not _digests_equal(
                            declaration.target_digest,
                            actual_target_digest,
                            _normalize_digest_algorithm(algorithm),
                        ):
                            receipt_issues.append(
                                _issue(
                                    "receipt_target_mismatch",
                                    f"Receipt {receipt_id} content does not match {target_id}; "
                                    "it was not filed with the object it approves",
                                    object_id=target_id,
                                    receipt_id=receipt_id,
                                    role=role_name,
                                )
                            )
                if authorised and len(receipt_issues) == target_issue_count:
                    accepted_targets.append(target_id)
                    bindings[target_id].append(
                        {
                            "receipt_id": receipt_id,
                            "role": role_name,
                            "signer": signer,
                            "scopes": declaration.scopes,
                        }
                    )
                for issue in receipt_issues:
                    target["issues"].append(issue)
            receipt["issues"].extend(receipt_issues)
            receipt_statuses.append(
                ReceiptStatus(
                    receipt_id=receipt_id,
                    target_object_ids=declaration.targets,
                    role=role_name,
                    scopes=declaration.scopes,
                    signer=signer,
                    accepted=bool(accepted_targets),
                    issues=_dedupe_issues(receipt_issues),
                    result=receipt["result"],
                )
            )
            issues.extend(receipt_issues)

        document_statuses: list[DocumentStatus] = []
        for object_id in sorted(documents):
            document = documents[object_id]
            required_roles = self.policy.required_roles_for(document["kind"], document["local_name"])
            satisfied_roles = []
            missing_roles = []
            document_bindings = bindings.get(object_id, [])
            for role_name in required_roles:
                role = self.policy.role(role_name)
                if role is None:
                    missing_roles.append(role_name)
                    document["issues"].append(
                        _issue(
                            "missing_receipt",
                            f"Document {object_id} requires undeclared role {role_name!r}",
                            object_id=object_id,
                            role=role_name,
                        )
                    )
                    continue
                seats = {
                    binding["signer"]
                    for binding in document_bindings
                    if binding["role"] == role_name and _identity_matches(binding["signer"], role.seats)
                }
                if len(seats) >= role.required_distinct_signatures:
                    satisfied_roles.append(role_name)
                else:
                    missing_roles.append(role_name)
                    document["issues"].append(
                        _issue(
                            "missing_receipt",
                            f"Document {object_id} has {len(seats)} distinct authorised receipt signer(s) "
                            f"for required role {role_name!r} "
                            f"(requires {role.required_distinct_signatures})",
                            object_id=object_id,
                            role=role_name,
                        )
                    )
            blocking_codes = {
                "missing_object_id",
                "duplicate_object",
                "commitment_missing",
                "commitment_mismatch",
                "commitment_target_mismatch",
                "predecessor_mismatch",
                "predecessor_digest_missing",
                "missing_predecessor",
                "out_of_order",
                "unsupported_digest",
            }
            blocking = [issue for issue in document["issues"] if issue.code in blocking_codes]
            accepted = not blocking and not missing_roles
            document_statuses.append(
                DocumentStatus(
                    object_id=object_id,
                    kind=document["kind"],
                    predecessor=document["declaration"].predecessor,
                    sequence=document["declaration"].sequence,
                    accepted=accepted,
                    required_roles=tuple(required_roles),
                    satisfied_roles=tuple(satisfied_roles),
                    missing_roles=tuple(missing_roles),
                    receipts=tuple(
                        sorted(
                            {
                                binding["receipt_id"]
                                for binding in document_bindings
                                if binding["role"] in required_roles
                            }
                        )
                    ),
                    commitment_digest=document["actual_digest"],
                    predecessor_digest=document["declaration"].predecessor_digest,
                    signer=self.policy.seat(document["result"]),
                    local_name=document["local_name"],
                    issues=_dedupe_issues(document["issues"]),
                    result=document["result"],
                )
            )

        for document in document_statuses:
            issues.extend(document.issues)

        return ReceiptVerificationResult(
            documents=tuple(document_statuses),
            receipts=tuple(sorted(receipt_statuses, key=lambda item: item.receipt_id)),
            issues=_dedupe_issues(issues),
        )


ReceiptVerifier = XMLReceiptVerifier


def verify_receipts(results, policy: ReceiptPolicy) -> ReceiptVerificationResult:
    """
    Convenience wrapper around :class:`XMLReceiptVerifier`.

    :param results: One :class:`signxml.VerifyResult` or an iterable of results already produced by
        :meth:`signxml.XMLVerifier.verify`.
    :param policy: The :class:`ReceiptPolicy` describing roles, scopes, and required receipts.
    :returns: A :class:`ReceiptVerificationResult`.
    """
    return XMLReceiptVerifier(policy).verify(results)
