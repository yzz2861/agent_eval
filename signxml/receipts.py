"""Offline combination of verified XML Signature references.

Verification results are often archived and reviewed later, when the original
XML document or some of its attachments may no longer be available.  This
module turns :class:`signxml.VerifyResult` objects into small, self-contained
attachments and combines them without performing any additional cryptographic
operations.

An attachment is identified by its archive name and signed digest rather than
by position in the input.  This keeps lookups stable when results are
reordered or when some declarations are missing.  A combined verification can
also report the distinct signing sources that cover a group and the smallest
set of independent sources that is sufficient to prove it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import itertools
import json
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Iterable, Iterator, Mapping, Sequence
from urllib.parse import urlsplit

from .algorithms import DigestAlgorithm, SignatureMethod

if TYPE_CHECKING:
    from lxml import etree

    from .verifier import VerifyResult


_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_PATH_SEPARATOR_RE = re.compile(r"[\\/]+")


def _first(mapping: Mapping[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in mapping and mapping[name] is not None:
            return mapping[name]
    return default


def _decode_digest(value: Any) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if hasattr(value, "text"):
        value = value.text
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return b""
        compact = re.sub(r"[\s:]", "", text)
        if _HEX_RE.fullmatch(compact) and len(compact) % 2 == 0:
            return bytes.fromhex(compact)
        try:
            return base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError):
            return text.encode("utf-8")
    return bytes(value)


def _coerce_bytes(value: Any) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        try:
            return base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            return value.encode("utf-8")
    return bytes(value)


def _digest_text(value: bytes | None) -> str | None:
    if value is None:
        return None
    return base64.b64encode(value).decode("ascii")


def _digest_hex(value: bytes | None) -> str | None:
    if value is None:
        return None
    return value.hex()


def _coerce_digest_algorithm(value: Any) -> DigestAlgorithm | str | None:
    if value is None or isinstance(value, DigestAlgorithm):
        return value
    candidate = getattr(value, "value", value)
    if isinstance(candidate, str):
        try:
            return DigestAlgorithm(candidate)
        except ValueError:
            pass
    name = getattr(value, "name", None) or str(value)
    normalized = name.upper().replace("-", "").replace("_", "")
    for algorithm in DigestAlgorithm:
        if algorithm.name.replace("_", "") == normalized:
            return algorithm
    return name


def _coerce_signature_method(value: Any) -> SignatureMethod | str | None:
    if value is None or isinstance(value, SignatureMethod):
        return value
    candidate = getattr(value, "value", value)
    if isinstance(candidate, str):
        try:
            return SignatureMethod(candidate)
        except ValueError:
            pass
    name = getattr(value, "name", None) or str(value)
    normalized = name.upper().replace("-", "").replace("_", "")
    for method in SignatureMethod:
        if method.name.replace("_", "") == normalized:
            return method
    return name


def _algorithm_name(value: Any) -> str | None:
    if value is None:
        return None
    return getattr(value, "name", None) or str(value)


def archive_name_from_uri(uri: str | None) -> str | None:
    """Return the ordinary archive name for a reference URI.

    Fragment-only references (``#name``) use the fragment.  External URIs use
    the last path component.  The exact URI is still retained separately so
    two attachments with the same name can be distinguished by digest.
    """

    if uri is None:
        return None
    if not uri:
        return None
    if uri.startswith("#"):
        return uri[1:] or None
    path = urlsplit(uri).path if "://" in uri else uri.split("?", 1)[0].split("#", 1)[0]
    name = _PATH_SEPARATOR_RE.split(path.rstrip("/"))[-1]
    return name or None


def _signature_source_id(result: Any) -> str:
    certificate = getattr(result, "signing_certificate", None)
    if certificate is not None:
        try:
            from cryptography.hazmat.primitives.serialization import Encoding

            fingerprint = hashlib.sha256(certificate.public_bytes(Encoding.DER)).hexdigest()
            return f"cert:{fingerprint}"
        except Exception:
            pass
    signature_key = _coerce_bytes(getattr(result, "signature_key", None))
    if signature_key is not None:
        return "key:" + hashlib.sha256(signature_key).hexdigest()
    signature_xml = getattr(result, "signature_xml", None)
    if signature_xml is not None:
        try:
            from lxml import etree

            serialized = etree.tostring(signature_xml, method="c14n")
        except Exception:
            serialized = repr(signature_xml).encode("utf-8", "replace")
        return "signature:" + hashlib.sha256(serialized).hexdigest()
    return "unknown"


def _coerce_roles(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(role) for role in value)


@dataclass(frozen=True, init=False)
class AttachmentDeclaration:
    """The declaration an archived verification result is checked against.

    ``archive_name`` and ``digest_value`` identify the attachment.  The
    remaining fields describe how it was signed and who is responsible for it.
    Declarations are intentionally usable without a live XML document.
    """

    archive_name: str | None
    digest_value: bytes | None
    digest_algorithm: DigestAlgorithm | str | None
    clause_version: str | None
    responsibility: str | None
    roles: tuple[str, ...]
    reference_uri: str | None
    reference_id: str | None
    metadata: Mapping[str, Any] = field(default_factory=dict, compare=False, hash=False)

    def __init__(
        self,
        archive_name: str | None = None,
        digest_value: Any = None,
        digest_algorithm: Any = None,
        clause_version: str | None = None,
        responsibility: str | None = None,
        roles: Any = None,
        reference_uri: str | None = None,
        reference_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        archive_name = archive_name or _first(kwargs, "name", "filename", "file_name", "archive")
        digest_value = digest_value if digest_value is not None else _first(kwargs, "digest", "signed_digest")
        digest_algorithm = (
            digest_algorithm if digest_algorithm is not None else _first(kwargs, "digest_method", "hash_algorithm")
        )
        clause_version = clause_version or _first(kwargs, "version", "policy_version", "signature_algorithm")
        responsibility = responsibility or _first(kwargs, "role", "signer_role", "signer")
        roles = roles if roles is not None else _first(kwargs, "claimed_roles")
        reference_uri = reference_uri if reference_uri is not None else _first(kwargs, "uri", "reference")
        reference_id = reference_id if reference_id is not None else _first(kwargs, "id", "reference_ref")
        if archive_name is None:
            archive_name = archive_name_from_uri(reference_uri)
        if responsibility is None and roles:
            responsibility = _coerce_roles(roles)[0]
        object.__setattr__(self, "archive_name", archive_name)
        object.__setattr__(self, "digest_value", _decode_digest(digest_value))
        object.__setattr__(self, "digest_algorithm", _coerce_digest_algorithm(digest_algorithm))
        object.__setattr__(self, "clause_version", clause_version)
        object.__setattr__(self, "responsibility", responsibility)
        object.__setattr__(self, "roles", _coerce_roles(roles))
        object.__setattr__(self, "reference_uri", reference_uri)
        object.__setattr__(self, "reference_id", reference_id)
        object.__setattr__(self, "metadata", dict(metadata or {}))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> AttachmentDeclaration:
        """Build a declaration from a mapping using common field aliases."""

        return cls(**dict(value))

    @property
    def name(self) -> str | None:
        """Alias for :attr:`archive_name`."""

        return self.archive_name

    @property
    def archive_path(self) -> str | None:
        """The exact reference URI retained in the declaration."""

        return self.reference_uri

    @property
    def digest(self) -> bytes | None:
        """Alias for :attr:`digest_value`."""

        return self.digest_value

    @property
    def signed_digest(self) -> bytes | None:
        """Alias for :attr:`digest_value`."""

        return self.digest_value

    @property
    def digest_b64(self) -> str | None:
        """The signed digest encoded as in an XML ``DigestValue`` element."""

        return _digest_text(self.digest_value)

    @property
    def digest_hex(self) -> str | None:
        """The signed digest as lowercase hexadecimal."""

        return _digest_hex(self.digest_value)

    @property
    def digest_text(self) -> str | None:
        """Alias for :attr:`digest_b64`."""

        return self.digest_b64

    @property
    def version(self) -> str | None:
        """Alias for :attr:`clause_version`."""

        return self.clause_version

    @property
    def role(self) -> str | None:
        """Alias for :attr:`responsibility`."""

        return self.responsibility

    @property
    def signer_role(self) -> str | None:
        """Alias for :attr:`responsibility`."""

        return self.responsibility

    @property
    def match_key(self) -> tuple[str | None, bytes | None]:
        """The order-independent key used to match this declaration."""

        return (self.archive_name, self.digest_value)

    @property
    def association(self) -> dict[str, Any]:
        """The archive name, digest, clause version, and responsibility together."""

        return {
            "archive_name": self.archive_name,
            "signed_digest": self.digest_value,
            "clause_version": self.clause_version,
            "responsibility": self.responsibility,
        }

    @property
    def association_key(self) -> tuple[str | None, bytes | None, str | None, str | None]:
        """A tuple form of :attr:`association`."""

        return (self.archive_name, self.digest_value, self.clause_version, self.responsibility)

    def matches(self, attachment: VerifiedAttachment) -> bool:
        """Return whether a verified attachment satisfies this declaration."""

        if self.archive_name is not None and attachment.archive_name != self.archive_name:
            return False
        if self.digest_value is not None and attachment.digest_value != self.digest_value:
            return False
        if self.reference_uri is not None and attachment.reference_uri != self.reference_uri:
            return False
        if self.clause_version is not None and attachment.clause_version is not None:
            if self.clause_version != attachment.clause_version:
                return False
        if self.responsibility is not None:
            return self.responsibility in attachment.roles or self.responsibility == attachment.responsibility
        return True

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the declaration."""

        return {
            "archive_name": self.archive_name,
            "digest_value": self.digest_b64,
            "digest_algorithm": _algorithm_name(self.digest_algorithm),
            "clause_version": self.clause_version,
            "responsibility": self.responsibility,
            "roles": list(self.roles),
            "reference_uri": self.reference_uri,
            "reference_id": self.reference_id,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class AttachmentKey:
    """A stable lookup key for a verified attachment."""

    archive_name: str | None
    digest_value: bytes | None = None
    reference_uri: str | None = field(default=None, compare=False)

    @property
    def name(self) -> str | None:
        """Alias for :attr:`archive_name`."""

        return self.archive_name

    @property
    def archive_path(self) -> str | None:
        """The exact reference URI retained by the result."""

        return self.reference_uri

    @property
    def digest_hex(self) -> str | None:
        """The digest as lowercase hexadecimal."""

        return _digest_hex(self.digest_value)

    def as_tuple(self) -> tuple[str | None, bytes | None]:
        """Return the minimal order-independent matching tuple."""

        return (self.archive_name, self.digest_value)


@dataclass(frozen=True, init=False)
class VerifiedAttachment:
    """A verified reference/attachment with its declaration and signer source.

    The object is detached from the input ordering: :attr:`archive_name` and
    :attr:`digest_value` are sufficient to look it up later.  :attr:`result`
    retains the original :class:`signxml.VerifyResult` for callers that need
    the signed bytes or XML.
    """

    result: Any
    archive_name: str | None
    digest_value: bytes | None
    digest_algorithm: DigestAlgorithm | str | None
    clause_version: str | None
    responsibility: str | None
    roles: tuple[str, ...]
    reference_uri: str | None
    reference_id: str | None
    reference_type: str | None
    signature_method: SignatureMethod | str | None
    signature_key: bytes | None
    signing_certificate: Any | None
    signing_certificate_digest: str | None
    signature_policy_identifier: str | None
    signature_policy_digest: str | None
    source_id: str
    metadata: Mapping[str, Any] = field(default_factory=dict, compare=False, hash=False)

    def __init__(self, result: Any = None, **kwargs: Any) -> None:
        if result is None:
            result = _first(kwargs, "verify_result", "verification", "value")
        if result is not None and not isinstance(result, Mapping):
            get = lambda name, default=None: getattr(result, name, default)  # noqa: E731
        elif isinstance(result, Mapping):
            get = lambda name, default=None: result.get(name, default)  # noqa: E731
        else:
            get = lambda name, default=None: kwargs.get(name, default)  # noqa: E731

        archive_name = kwargs.get("archive_name")
        if archive_name is None:
            archive_name = _first(kwargs, "name", "filename", "file_name")
        reference_uri = kwargs.get("reference_uri")
        if reference_uri is None:
            reference_uri = get("reference_uri", get("reference", None))
        if archive_name is None:
            archive_name = get("archive_name", None) or archive_name_from_uri(reference_uri)

        digest_value = kwargs.get("digest_value")
        if digest_value is None:
            digest_value = _first(kwargs, "digest", "signed_digest")
        if digest_value is None:
            digest_value = get("digest_value", get("digest", None))

        digest_algorithm = kwargs.get("digest_algorithm")
        if digest_algorithm is None:
            digest_algorithm = _first(kwargs, "digest_method", "hash_algorithm")
        if digest_algorithm is None:
            digest_algorithm = get("digest_algorithm", get("digest_method", None))

        clause_version = kwargs.get("clause_version")
        if clause_version is None:
            clause_version = _first(kwargs, "version", "policy_version")
        if clause_version is None:
            clause_version = get("clause_version", get("policy_version", None))
        signature_method = kwargs.get("signature_method")
        if signature_method is None:
            signature_method = get("signature_method", get("signature_algorithm", None))
        if clause_version is None:
            clause_version = _algorithm_name(signature_method)

        roles = kwargs.get("roles")
        if roles is None:
            roles = _first(kwargs, "claimed_roles")
        if roles is None:
            roles = get("roles", get("claimed_roles", ()))
        responsibility = kwargs.get("responsibility")
        if responsibility is None:
            responsibility = _first(kwargs, "role", "signer_role")
        if responsibility is None:
            responsibility = get("responsibility", get("role", None))
        roles = _coerce_roles(roles)
        if responsibility is None and roles:
            responsibility = roles[0]

        signature_key = kwargs.get("signature_key")
        if signature_key is None:
            signature_key = get("signature_key", None)
        signing_certificate = kwargs.get("signing_certificate")
        if signing_certificate is None:
            signing_certificate = get("signing_certificate", get("certificate", None))
        signing_certificate_digest = kwargs.get("signing_certificate_digest")
        if signing_certificate_digest is None:
            signing_certificate_digest = get("signing_certificate_digest", get("cert_digest", None))
        signature_policy_identifier = kwargs.get("signature_policy_identifier")
        if signature_policy_identifier is None:
            signature_policy_identifier = get(
                "signature_policy_identifier", get("policy_identifier", get("policy_version", None))
            )
        signature_policy_digest = kwargs.get("signature_policy_digest")
        if signature_policy_digest is None:
            signature_policy_digest = get("signature_policy_digest", get("policy_digest", None))
        source_id = kwargs.get("source_id")
        if source_id is None:
            source_id = _first(kwargs, "source", "signer_id", "key_id")
        if source_id is None:
            source_id = get("source_id", None)
        if source_id is None:
            source_id = _first(
                {"source": get("source", None), "signer_id": get("signer_id", None), "key_id": get("key_id", None)},
                "source",
                "signer_id",
                "key_id",
            )
        if source_id is None:
            source_id = _signature_source_id(result if result is not None else kwargs)

        metadata = dict(kwargs.get("metadata") or {})
        if isinstance(result, Mapping):
            metadata.setdefault("input", dict(result))

        object.__setattr__(self, "result", result)
        object.__setattr__(self, "archive_name", archive_name)
        object.__setattr__(self, "digest_value", _decode_digest(digest_value))
        object.__setattr__(self, "digest_algorithm", _coerce_digest_algorithm(digest_algorithm))
        object.__setattr__(self, "clause_version", clause_version)
        object.__setattr__(self, "responsibility", responsibility)
        object.__setattr__(self, "roles", roles)
        object.__setattr__(self, "reference_uri", reference_uri)
        object.__setattr__(self, "reference_id", get("reference_id", kwargs.get("reference_id")))
        object.__setattr__(self, "reference_type", get("reference_type", kwargs.get("reference_type")))
        object.__setattr__(self, "signature_method", _coerce_signature_method(signature_method))
        object.__setattr__(self, "signature_key", _coerce_bytes(signature_key))
        object.__setattr__(self, "signing_certificate", signing_certificate)
        object.__setattr__(self, "signing_certificate_digest", signing_certificate_digest)
        object.__setattr__(self, "signature_policy_identifier", signature_policy_identifier)
        object.__setattr__(self, "signature_policy_digest", signature_policy_digest)
        object.__setattr__(self, "source_id", str(source_id))
        object.__setattr__(self, "metadata", metadata)

    @classmethod
    def from_result(cls, result: VerifyResult) -> VerifiedAttachment:
        """Build an attachment from a :class:`signxml.VerifyResult`."""

        if isinstance(result, VerifiedAttachment):
            return result
        return cls(result=result)

    def __getattr__(self, name: str) -> Any:
        result = object.__getattribute__(self, "result")
        if result is None:
            raise AttributeError(name)
        return getattr(result, name)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> VerifiedAttachment:
        """Build an attachment from an archived mapping/JSON record."""

        return cls(result=value, **dict(value))

    @property
    def verify_result(self) -> Any:
        """Alias for :attr:`result`."""

        return self.result

    @property
    def name(self) -> str | None:
        """Alias for :attr:`archive_name`."""

        return self.archive_name

    @property
    def digest(self) -> bytes | None:
        """Alias for :attr:`digest_value`."""

        return self.digest_value

    @property
    def signed_digest(self) -> bytes | None:
        """Alias for :attr:`digest_value`."""

        return self.digest_value

    @property
    def digest_b64(self) -> str | None:
        """The signed digest encoded as in an XML ``DigestValue`` element."""

        return _digest_text(self.digest_value)

    @property
    def digest_hex(self) -> str | None:
        """The signed digest as lowercase hexadecimal."""

        return _digest_hex(self.digest_value)

    @property
    def digest_text(self) -> str | None:
        """Alias for :attr:`digest_b64`."""

        return self.digest_b64

    @property
    def version(self) -> str | None:
        """Alias for :attr:`clause_version`."""

        return self.clause_version

    @property
    def role(self) -> str | None:
        """Alias for :attr:`responsibility`."""

        return self.responsibility

    @property
    def signer_role(self) -> str | None:
        """Alias for :attr:`responsibility`."""

        return self.responsibility

    @property
    def key(self) -> AttachmentKey:
        """The stable lookup key for this attachment."""

        return AttachmentKey(self.archive_name, self.digest_value, self.reference_uri)

    @property
    def association(self) -> dict[str, Any]:
        """The archive name, digest, clause version, and responsibility together."""

        return self.declaration.association

    @property
    def association_key(self) -> tuple[str | None, bytes | None, str | None, str | None]:
        """A tuple form of :attr:`association`."""

        return self.declaration.association_key

    @property
    def declaration(self) -> AttachmentDeclaration:
        """The declaration reconstructed from this verified attachment."""

        return AttachmentDeclaration(
            archive_name=self.archive_name,
            digest_value=self.digest_value,
            digest_algorithm=self.digest_algorithm,
            clause_version=self.clause_version,
            responsibility=self.responsibility,
            roles=self.roles,
            reference_uri=self.reference_uri,
            reference_id=self.reference_id,
            metadata=self.metadata,
        )

    @property
    def declared(self) -> AttachmentDeclaration:
        """Alias for :attr:`declaration`."""

        return self.declaration

    @property
    def source_fingerprint(self) -> str:
        """The fingerprint portion of :attr:`source_id`."""

        return self.source_id.split(":", 1)[-1]

    @property
    def signed_data(self) -> bytes | None:
        """The signed bytes retained by the original result."""

        if isinstance(self.result, Mapping):
            return self.result.get("signed_data")
        return getattr(self.result, "signed_data", None)

    @property
    def signed_xml(self) -> etree._Element | None:
        """The parsed signed XML retained by the original result."""

        if isinstance(self.result, Mapping):
            return self.result.get("signed_xml")
        return getattr(self.result, "signed_xml", None)

    @property
    def signature_xml(self) -> etree._Element | None:
        """The signature XML retained by the original result."""

        if isinstance(self.result, Mapping):
            return self.result.get("signature_xml")
        return getattr(self.result, "signature_xml", None)

    def matches(self, declaration: AttachmentDeclaration) -> bool:
        """Return whether this attachment satisfies a declaration."""

        return declaration.matches(self)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the attachment."""

        return {
            **self.declaration.to_dict(),
            "reference_type": self.reference_type,
            "signature_method": _algorithm_name(self.signature_method),
            "signing_certificate_digest": self.signing_certificate_digest,
            "signature_policy_identifier": self.signature_policy_identifier,
            "signature_policy_digest": self.signature_policy_digest,
            "source_id": self.source_id,
        }


@dataclass(frozen=True)
class VerificationSource:
    """The stable identity of one signing source and what it covers."""

    source_id: str
    signature_key: bytes | None
    signing_certificate: Any | None
    attachments: tuple[AttachmentKey, ...]

    @property
    def keys(self) -> tuple[AttachmentKey, ...]:
        """Alias for :attr:`attachments`."""

        return self.attachments

    @property
    def archive_names(self) -> tuple[str | None, ...]:
        """The archive names covered by this source."""

        return tuple(key.archive_name for key in self.attachments)

    def __str__(self) -> str:
        return self.source_id

    def __hash__(self) -> int:
        return hash(self.source_id)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, VerificationSource):
            return self.source_id == other.source_id
        if isinstance(other, str):
            return self.source_id == other
        return NotImplemented


def _coerce_attachment(value: Any) -> VerifiedAttachment:
    if isinstance(value, VerifiedAttachment):
        return value
    if isinstance(value, AttachmentDeclaration):
        return VerifiedAttachment(**value.to_dict())
    if isinstance(value, Mapping):
        return VerifiedAttachment(result=value, **dict(value))
    return VerifiedAttachment(result=value)


def _coerce_declaration(value: Any) -> AttachmentDeclaration:
    if isinstance(value, AttachmentDeclaration):
        return value
    if isinstance(value, VerifiedAttachment):
        return value.declaration
    if isinstance(value, Mapping):
        return AttachmentDeclaration.from_mapping(value)
    if isinstance(value, str):
        return AttachmentDeclaration(archive_name=value)
    return AttachmentDeclaration(archive_name=str(value))


def _coerce_declarations(value: Any) -> tuple[AttachmentDeclaration, ...]:
    if value is None:
        return ()
    if isinstance(value, Mapping):
        declaration_keys = {
            "archive_name",
            "name",
            "filename",
            "file_name",
            "reference_uri",
            "digest_value",
            "digest",
        }
        if declaration_keys.intersection(value):
            return (_coerce_declaration(value),)
        declarations = []
        for name, item in value.items():
            if isinstance(item, Mapping):
                payload = dict(item)
                payload.setdefault("archive_name", str(name))
            else:
                payload = {"archive_name": str(name), "digest_value": item}
            declarations.append(AttachmentDeclaration.from_mapping(payload))
        return tuple(declarations)
    if isinstance(value, (AttachmentDeclaration, VerifiedAttachment, str)):
        return (_coerce_declaration(value),)
    return tuple(_coerce_declaration(item) for item in value)


def _normalize_required_responsibilities(value: Any) -> dict[str, int]:
    if value is None:
        return {}
    if isinstance(value, str):
        return {value: 1}
    if isinstance(value, Mapping):
        result = {}
        for role, count in value.items():
            if isinstance(count, bool):
                count = 1 if count else 0
            result[str(role)] = int(count)
        return result
    return {str(role): 1 for role in value}


def _source_coverage(attachments: Sequence[VerifiedAttachment]) -> dict[str, set[AttachmentKey]]:
    coverage: dict[str, set[AttachmentKey]] = {}
    for attachment in attachments:
        coverage.setdefault(attachment.source_id, set()).add(attachment.key)
    return coverage


def _minimal_covers(
    coverage: Mapping[str, set[AttachmentKey]],
    required: set[AttachmentKey],
) -> tuple[tuple[str, ...], ...]:
    if not required:
        return ((),)
    sources = sorted(coverage)
    universal = set().union(*coverage.values()) if coverage else set()
    if not required.issubset(universal):
        return ()
    for size in range(1, len(sources) + 1):
        covers = []
        for combination in itertools.combinations(sources, size):
            covered: set[AttachmentKey] = set()
            for source_id in combination:
                covered.update(coverage[source_id])
            if required.issubset(covered):
                covers.append(combination)
        if covers:
            return tuple(covers)
    return ()


class CombinedVerification:
    """An offline, order-independent view of a group of verified attachments.

    The constructor accepts verified results in any order.  Attachments are
    never re-verified and no network or filesystem access is performed.
    ``expected`` may list declarations that the combination should account
    for; missing declarations are reported without hiding the attachments that
    are present.
    """

    def __init__(
        self,
        results: Iterable[Any] | Any | None = None,
        *more: Any,
        expected: Iterable[Any] | Any | None = None,
        required_responsibilities: Any = None,
        metadata: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        if expected is None:
            expected = kwargs.pop(
                "expected_declarations",
                kwargs.pop("declarations", kwargs.pop("expected_names", kwargs.pop("required", None))),
            )
        if required_responsibilities is None:
            required_responsibilities = kwargs.pop("required_roles", kwargs.pop("responsibilities", None))
        if metadata is None:
            metadata = kwargs.pop("extra", None)
        kwargs.clear()
        if results is None:
            results = ()
        elif isinstance(results, (Mapping, VerifiedAttachment, AttachmentDeclaration)) or not isinstance(
            results, Iterable
        ):
            results = (results,)
        batch = list(results)
        extra_expected = []
        for item in more:
            if isinstance(item, (AttachmentDeclaration, str)) or (
                isinstance(item, (list, tuple))
                and item
                and all(isinstance(entry, (AttachmentDeclaration, Mapping, str)) for entry in item)
            ):
                extra_expected.append(item)
            elif isinstance(item, (list, tuple, set)) and item:
                batch.extend(item)
            else:
                batch.append(item)
        if extra_expected:
            expected = list(_coerce_declarations(expected))
            for entry in extra_expected:
                expected.extend(_coerce_declarations(entry))
        self.results: tuple[Any, ...] = tuple(batch)
        self.attachments: tuple[VerifiedAttachment, ...] = tuple(_coerce_attachment(item) for item in batch)
        self.expected: tuple[AttachmentDeclaration, ...] = _coerce_declarations(expected)
        self.required_responsibilities: dict[str, int] = _normalize_required_responsibilities(required_responsibilities)
        self.metadata: Mapping[str, Any] = dict(metadata or {})

        source_metadata: dict[str, dict[str, Any]] = {}
        for attachment in self.attachments:
            values = source_metadata.setdefault(attachment.source_id, {})
            for field_name in (
                "signing_certificate_digest",
                "signature_policy_identifier",
                "signature_policy_digest",
            ):
                value = getattr(attachment, field_name)
                if value is not None:
                    values.setdefault(field_name, value)
        for attachment in self.attachments:
            for field_name, value in source_metadata.get(attachment.source_id, {}).items():
                if getattr(attachment, field_name) is None:
                    object.__setattr__(attachment, field_name, value)

        by_key: dict[AttachmentKey, list[VerifiedAttachment]] = {}
        by_name: dict[str | None, list[VerifiedAttachment]] = {}
        by_digest: dict[bytes | None, list[VerifiedAttachment]] = {}
        by_uri: dict[str | None, list[VerifiedAttachment]] = {}
        for attachment in self.attachments:
            by_key.setdefault(attachment.key, []).append(attachment)
            by_name.setdefault(attachment.archive_name, []).append(attachment)
            by_digest.setdefault(attachment.digest_value, []).append(attachment)
            by_uri.setdefault(attachment.reference_uri, []).append(attachment)
        self._by_key = {key: tuple(values) for key, values in by_key.items()}
        self._by_name = {key: tuple(values) for key, values in by_name.items()}
        self._by_digest = {key: tuple(values) for key, values in by_digest.items()}
        self._by_uri = {key: tuple(values) for key, values in by_uri.items()}

        coverage = _source_coverage(self.attachments)
        self._coverage = coverage
        self._source_objects = tuple(
            VerificationSource(
                source_id=source_id,
                signature_key=next(
                    (a.signature_key for a in self.attachments if a.source_id == source_id and a.signature_key),
                    None,
                ),
                signing_certificate=next(
                    (
                        a.signing_certificate
                        for a in self.attachments
                        if a.source_id == source_id and a.signing_certificate is not None
                    ),
                    None,
                ),
                attachments=tuple(sorted(keys, key=lambda key: (key.archive_name or "", key.digest_value or b""))),
            )
            for source_id, keys in sorted(coverage.items())
        )

    @classmethod
    def from_records(cls, records: Iterable[Any], **kwargs: Any) -> CombinedVerification:
        """Build a combination from archived results or mapping records."""

        return cls(records, **kwargs)

    @classmethod
    def from_dicts(cls, records: Iterable[Mapping[str, Any]], **kwargs: Any) -> CombinedVerification:
        """Alias for :meth:`from_records`."""

        return cls.from_records(records, **kwargs)

    @classmethod
    def from_json(cls, payload: str | bytes, **kwargs: Any) -> CombinedVerification:
        """Build a combination from archived JSON records."""

        records = json.loads(payload)
        if isinstance(records, Mapping):
            records = records.get("attachments", records.get("results", ()))
        return cls.from_records(records, **kwargs)

    def __len__(self) -> int:
        return len(self.attachments)

    def __iter__(self) -> Iterator[VerifiedAttachment]:
        return iter(self.attachments)

    def __bool__(self) -> bool:
        return self.sufficient

    def __contains__(self, key: Any) -> bool:
        if isinstance(key, AttachmentKey):
            return key in self._by_key or bool(self.lookup(key.archive_name, key.digest_value))
        if isinstance(key, tuple):
            return bool(self.lookup(*key))
        if isinstance(key, str):
            return bool(self.lookup(key))
        return False

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, slice):
            return self.attachments[key]
        if isinstance(key, int):
            return self.attachments[key]
        if isinstance(key, AttachmentKey):
            values = self._by_key.get(key)
            if values is None:
                values = self.lookup(key.archive_name, key.digest_value)
            if len(values) == 1:
                return values[0]
            return values
        if isinstance(key, tuple):
            return self.lookup(*key)
        if isinstance(key, str):
            values = self.lookup(key)
            if len(values) == 1:
                return values[0]
            return values
        raise KeyError(key)

    def add(self, *results: Any, expected: Iterable[Any] | Any | None = None) -> CombinedVerification:
        """Return a new combination that also includes the given verified results."""

        return CombinedVerification(
            (*self.attachments, *results),
            expected=self.expected if expected is None else expected,
            required_responsibilities=self.required_responsibilities,
            metadata=self.metadata,
        )

    @property
    def by_key(self) -> Mapping[AttachmentKey, tuple[VerifiedAttachment, ...]]:
        """Attachments indexed by archive name and digest."""

        return self._by_key

    @property
    def by_name(self) -> Mapping[str | None, tuple[VerifiedAttachment, ...]]:
        """Attachments indexed by archive name."""

        return self._by_name

    @property
    def by_digest(self) -> Mapping[bytes | None, tuple[VerifiedAttachment, ...]]:
        """Attachments indexed by signed digest."""

        return self._by_digest

    @property
    def by_reference_uri(self) -> Mapping[str | None, tuple[VerifiedAttachment, ...]]:
        """Attachments indexed by the exact reference URI."""

        return self._by_uri

    @property
    def results_by_name(self) -> Mapping[str | None, tuple[VerifiedAttachment, ...]]:
        """Alias for :attr:`by_name`."""

        return self.by_name

    @property
    def results_by_digest(self) -> Mapping[bytes | None, tuple[VerifiedAttachment, ...]]:
        """Alias for :attr:`by_digest`."""

        return self.by_digest

    @property
    def attachment_map(self) -> Mapping[str | None, tuple[VerifiedAttachment, ...]]:
        """Alias for :attr:`by_name`."""

        return self.by_name

    @property
    def attachment_index(self) -> Mapping[AttachmentKey, tuple[VerifiedAttachment, ...]]:
        """Alias for :attr:`by_key`."""

        return self.by_key

    @property
    def declarations(self) -> tuple[AttachmentDeclaration, ...]:
        """The declarations of all verified attachments."""

        return tuple(attachment.declaration for attachment in self.attachments)

    @property
    def associations(self) -> tuple[Mapping[str, Any], ...]:
        """The four-part association for each verified attachment."""

        return tuple(attachment.association for attachment in self.attachments)

    def keys(self) -> tuple[AttachmentKey, ...]:
        """Return the stable keys of the verified attachments."""

        return tuple(self._by_key)

    def values(self) -> tuple[VerifiedAttachment, ...]:
        """Alias for :attr:`attachments`."""

        return self.attachments

    def items(self) -> tuple[tuple[AttachmentKey, VerifiedAttachment], ...]:
        """Return stable keys paired with their first verified attachment."""

        return tuple((key, values[0]) for key, values in self._by_key.items())

    def lookup(
        self,
        archive_name: str | None,
        digest: Any = None,
        *,
        clause_version: str | None = None,
        responsibility: str | None = None,
    ) -> tuple[VerifiedAttachment, ...]:
        """Look up verified attachments by declaration details.

        When ``digest`` is omitted, all verified attachments with the archive
        name are returned.  Supplying a digest disambiguates attachments that
        share an ordinary filename.
        """

        if isinstance(archive_name, AttachmentKey):
            digest = archive_name.digest_value
            archive_name = archive_name.archive_name
        digest_bytes = _decode_digest(digest)
        candidates = self._by_name.get(archive_name, ())
        if not candidates:
            normalized_name = archive_name_from_uri(archive_name)
            if normalized_name != archive_name:
                candidates = self._by_name.get(normalized_name, ())
        if not candidates:
            candidates = self._by_uri.get(archive_name, ())
        result = []
        for attachment in candidates:
            if digest_bytes is not None and attachment.digest_value != digest_bytes:
                continue
            if clause_version is not None and attachment.clause_version != clause_version:
                continue
            if responsibility is not None:
                if responsibility != attachment.responsibility and responsibility not in attachment.roles:
                    continue
            result.append(attachment)
        return tuple(result)

    def get(
        self,
        archive_name: str | None,
        digest: Any = None,
        *,
        clause_version: str | None = None,
        responsibility: str | None = None,
    ) -> VerifiedAttachment | None:
        """Return the first matching attachment, or ``None`` if absent."""

        matches = self.lookup(
            archive_name,
            digest,
            clause_version=clause_version,
            responsibility=responsibility,
        )
        return matches[0] if matches else None

    def find(self, **query: Any) -> tuple[VerifiedAttachment, ...]:
        """Find attachments using declaration field names as keywords."""

        declaration = AttachmentDeclaration(**query)
        return tuple(attachment for attachment in self.attachments if declaration.matches(attachment))

    def declaration_for(self, archive_name: str | None, digest: Any = None) -> AttachmentDeclaration | None:
        """Return the declaration of the first matching verified attachment."""

        attachment = self.get(archive_name, digest)
        return attachment.declaration if attachment is not None else None

    def get_declaration(self, archive_name: str | None, digest: Any = None) -> AttachmentDeclaration | None:
        """Alias for :meth:`declaration_for`."""

        return self.declaration_for(archive_name, digest)

    def attachment_for(self, archive_name: str | None, digest: Any = None) -> VerifiedAttachment | None:
        """Alias for :meth:`get`."""

        return self.get(archive_name, digest)

    @property
    def missing(self) -> tuple[AttachmentDeclaration, ...]:
        """Expected declarations that have no verified attachment."""

        missing = []
        for declaration in self.expected:
            if not any(declaration.matches(attachment) for attachment in self.attachments):
                missing.append(declaration)
        return tuple(missing)

    @property
    def unexpected(self) -> tuple[VerifiedAttachment, ...]:
        """Verified attachments not covered by any expected declaration."""

        if not self.expected:
            return ()
        return tuple(
            attachment
            for attachment in self.attachments
            if not any(declaration.matches(attachment) for declaration in self.expected)
        )

    @property
    def missing_names(self) -> tuple[str | None, ...]:
        """The archive names of expected declarations that are absent."""

        return tuple(declaration.archive_name for declaration in self.missing)

    @property
    def present(self) -> tuple[VerifiedAttachment, ...]:
        """Alias for :attr:`attachments`."""

        return self.attachments

    @property
    def present_names(self) -> tuple[str | None, ...]:
        """The archive names of the verified attachments."""

        return tuple(attachment.archive_name for attachment in self.attachments)

    @property
    def complete(self) -> bool:
        """Whether every expected declaration is present."""

        return not self.missing

    @property
    def sources(self) -> tuple[str, ...]:
        """The distinct signing sources in the combination."""

        return tuple(source.source_id for source in self._source_objects)

    @property
    def source_objects(self) -> tuple[VerificationSource, ...]:
        """Detailed coverage information for each distinct source."""

        return self._source_objects

    @property
    def independent_sources(self) -> tuple[str, ...]:
        """Alias for :attr:`sources`."""

        return self.sources

    @property
    def independent_source_ids(self) -> tuple[str, ...]:
        """Alias for :attr:`sources`."""

        return self.sources

    @property
    def source_ids(self) -> tuple[str, ...]:
        """Alias for :attr:`sources`."""

        return self.sources

    @property
    def source_fingerprints(self) -> tuple[str, ...]:
        """The fingerprints of the distinct signing sources."""

        return tuple(source_id.split(":", 1)[-1] for source_id in self.sources)

    @property
    def independent_source_count(self) -> int:
        """The number of distinct signing sources."""

        return len(self.sources)

    @property
    def signature_keys(self) -> tuple[bytes, ...]:
        """Distinct signing keys represented in the combination."""

        keys = {attachment.signature_key for attachment in self.attachments if attachment.signature_key is not None}
        return tuple(sorted(keys))

    @property
    def signing_certificates(self) -> tuple[Any, ...]:
        """Distinct signing certificates represented in the combination."""

        certificates = []
        seen = set()
        for attachment in self.attachments:
            certificate = attachment.signing_certificate
            if certificate is None:
                continue
            fingerprint = getattr(certificate, "fingerprint", None)
            marker = repr(fingerprint) if fingerprint is not None else id(certificate)
            if marker not in seen:
                seen.add(marker)
                certificates.append(certificate)
        return tuple(certificates)

    @property
    def responsibilities(self) -> Mapping[str, tuple[str, ...]]:
        """Map each responsibility/role to the sources asserting it."""

        result: dict[str, set[str]] = {}
        for attachment in self.attachments:
            roles = set(attachment.roles)
            if attachment.responsibility:
                roles.add(attachment.responsibility)
            for role in roles:
                result.setdefault(role, set()).add(attachment.source_id)
        return {role: tuple(sorted(sources)) for role, sources in sorted(result.items())}

    @property
    def responsibility_sources(self) -> Mapping[str, tuple[str, ...]]:
        """Alias for :attr:`responsibilities`."""

        return self.responsibilities

    @property
    def unsatisfied_responsibilities(self) -> tuple[str, ...]:
        """Required responsibilities that do not have enough distinct sources."""

        return tuple(
            role
            for role, required_count in self.required_responsibilities.items()
            if len(self.responsibilities.get(role, ())) < required_count
        )

    def _required_keys(self) -> set[AttachmentKey]:
        if self.expected:
            keys = set()
            for declaration in self.expected:
                for attachment in self.attachments:
                    if declaration.matches(attachment):
                        keys.add(attachment.key)
                        break
            return keys
        return {attachment.key for attachment in self.attachments}

    @property
    def minimal_source_sets(self) -> tuple[tuple[str, ...], ...]:
        """All smallest independent source sets covering the required attachments."""

        return _minimal_covers(self._coverage, self._required_keys())

    @property
    def minimal_sources(self) -> tuple[str, ...]:
        """One smallest independent source set, or an empty tuple if impossible."""

        covers = self.minimal_source_sets
        return covers[0] if covers else ()

    @property
    def required_sources(self) -> tuple[str, ...]:
        """Alias for :attr:`minimal_sources`."""

        return self.minimal_sources

    @property
    def minimal_source_set(self) -> tuple[str, ...]:
        """Alias for :attr:`minimal_sources`."""

        return self.minimal_sources

    @property
    def required_independent_sources(self) -> tuple[str, ...]:
        """Alias for :attr:`minimal_sources`."""

        return self.minimal_sources

    @property
    def sufficient(self) -> bool:
        """Whether present attachments, sources, and responsibilities prove the group."""

        return self.complete and bool(self.minimal_sources) and not self.unsatisfied_responsibilities

    @property
    def proves_all(self) -> bool:
        """Alias for :attr:`sufficient`."""

        return self.sufficient

    @property
    def is_sufficient(self) -> bool:
        """Alias for :attr:`sufficient`."""

        return self.sufficient

    @property
    def minimal_source_count(self) -> int:
        """The number of sources in the smallest sufficient cover."""

        return len(self.minimal_sources)

    @property
    def required_source_count(self) -> int:
        """Alias for :attr:`minimal_source_count`."""

        return self.minimal_source_count

    def source_coverage(self) -> Mapping[str, tuple[AttachmentKey, ...]]:
        """Return the attachment keys covered by each source."""

        return {
            source_id: tuple(sorted(keys, key=lambda key: (key.archive_name or "", key.digest_value or b"")))
            for source_id, keys in sorted(self._coverage.items())
        }

    @property
    def attachment_sources(self) -> Mapping[AttachmentKey, tuple[str, ...]]:
        """Map each verified attachment key to the sources that support it."""

        result: dict[AttachmentKey, list[str]] = {}
        for attachment in self.attachments:
            result.setdefault(attachment.key, []).append(attachment.source_id)
        return {key: tuple(sorted(set(sources))) for key, sources in result.items()}

    def sources_for(self, archive_name: str | None, digest: Any = None) -> tuple[str, ...]:
        """Return the distinct sources that verified a named attachment."""

        return tuple(sorted({attachment.source_id for attachment in self.lookup(archive_name, digest)}))

    def required_sources_for(self, archive_name: str | None, digest: Any = None) -> tuple[str, ...]:
        """Alias for :meth:`sources_for`."""

        return self.sources_for(archive_name, digest)

    def verify(self) -> dict[str, Any]:
        """Return the offline combination report (alias for :meth:`report`)."""

        return self.report()

    def satisfies(self, required_responsibilities: Any) -> bool:
        """Return whether the combination has enough distinct sources per responsibility."""

        requirements = _normalize_required_responsibilities(required_responsibilities)
        return all(
            len(self.responsibilities.get(role, ())) >= required_count for role, required_count in requirements.items()
        )

    def report(self) -> dict[str, Any]:
        """Return a JSON-serializable audit report."""

        return {
            "attachments": [attachment.to_dict() for attachment in self.attachments],
            "expected": [declaration.to_dict() for declaration in self.expected],
            "missing": [declaration.to_dict() for declaration in self.missing],
            "unexpected": [attachment.to_dict() for attachment in self.unexpected],
            "complete": self.complete,
            "sources": list(self.sources),
            "source_coverage": {
                source_id: [key.archive_name for key in keys] for source_id, keys in self.source_coverage().items()
            },
            "minimal_sources": list(self.minimal_sources),
            "minimal_source_sets": [list(cover) for cover in self.minimal_source_sets],
            "responsibilities": {role: list(sources) for role, sources in self.responsibilities.items()},
            "unsatisfied_responsibilities": list(self.unsatisfied_responsibilities),
            "sufficient": self.sufficient,
            "metadata": dict(self.metadata),
        }

    def to_dict(self) -> dict[str, Any]:
        """Alias for :meth:`report`."""

        return self.report()

    def to_json(self, **kwargs: Any) -> str:
        """Serialize the audit report to JSON."""

        kwargs.setdefault("sort_keys", True)
        return json.dumps(self.report(), **kwargs)


def combine_verifications(
    results: Iterable[Any] | Any | None = None,
    *more: Any,
    expected: Iterable[Any] | Any | None = None,
    required_responsibilities: Any = None,
    metadata: Mapping[str, Any] | None = None,
    **kwargs: Any,
) -> CombinedVerification:
    """Combine already-verified results without performing cryptography.

    ``results`` may be a single result, an iterable of results, or results
    passed as additional positional arguments.  ``expected`` declares the
    archived attachments that the combination should account for.  Input order
    does not affect any lookup or source calculation.
    """

    return CombinedVerification(
        results,
        *more,
        expected=expected,
        required_responsibilities=required_responsibilities,
        metadata=metadata,
        **kwargs,
    )


def combine_verified_results(
    results: Iterable[Any] | Any | None = None,
    *more: Any,
    **kwargs: Any,
) -> CombinedVerification:
    """Alias for :func:`combine_verifications`."""

    return combine_verifications(results, *more, **kwargs)


def combine_verification_results(
    results: Iterable[Any] | Any | None = None,
    *more: Any,
    **kwargs: Any,
) -> CombinedVerification:
    """Alias for :func:`combine_verifications`."""

    return combine_verifications(results, *more, **kwargs)


def combine(
    results: Iterable[Any] | Any | None = None,
    *more: Any,
    **kwargs: Any,
) -> CombinedVerification:
    """Alias for :func:`combine_verifications`."""

    return combine_verifications(results, *more, **kwargs)


def offline_combine(
    results: Iterable[Any] | Any | None = None,
    *more: Any,
    **kwargs: Any,
) -> CombinedVerification:
    """Alias for :func:`combine_verifications`."""

    return combine_verifications(results, *more, **kwargs)


def offline_combined_verification(
    results: Iterable[Any] | Any | None = None,
    *more: Any,
    **kwargs: Any,
) -> CombinedVerification:
    """Alias for :func:`combine_verifications`."""

    return combine_verifications(results, *more, **kwargs)


def verify_offline(
    results: Iterable[Any] | Any | None = None,
    *more: Any,
    **kwargs: Any,
) -> CombinedVerification:
    """Alias for :func:`combine_verifications`."""

    return combine_verifications(results, *more, **kwargs)


def combine_results(
    results: Iterable[Any] | Any | None = None,
    *more: Any,
    **kwargs: Any,
) -> CombinedVerification:
    """Alias for :func:`combine_verifications`."""

    return combine_verifications(results, *more, **kwargs)


def combine_verify_results(
    results: Iterable[Any] | Any | None = None,
    *more: Any,
    **kwargs: Any,
) -> CombinedVerification:
    """Alias for :func:`combine_verifications`."""

    return combine_verifications(results, *more, **kwargs)


def verified_attachments(results: Iterable[Any] | Any) -> tuple[VerifiedAttachment, ...]:
    """Convert verified results to :class:`VerifiedAttachment` objects."""

    if isinstance(results, (VerifiedAttachment, Mapping)) or not isinstance(results, Iterable):
        results = (results,)
    return tuple(_coerce_attachment(result) for result in results)


def source_id(result: Any) -> str:
    """Return the stable independent-source identifier for a verified result."""

    return _signature_source_id(result)


CombinedVerificationResult = CombinedVerification
OfflineCombinedVerification = CombinedVerification
ReceiptGroup = CombinedVerification
VerificationResultSet = CombinedVerification
VerificationSet = CombinedVerification
