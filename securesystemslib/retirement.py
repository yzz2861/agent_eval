"""Signed approval-index based attachment retirement.

This module implements a deliberately small archival workflow on top of the
``securesystemslib`` signing, hashing, and storage APIs:

* a signed *approval index* describes attachments, the case files that use
  them, and approver-signed authorization records,
* a signed *retirement manifest* records which one attachment was withdrawn and
  which digest and authorization record were retained, and
* a retirement service verifies both documents before deleting anything.

The important archival property is that deleting an attachment is never enough
to lose its provenance: the manifest keeps the attachment digest and the
approver-signed authorization that covered that exact digest.  If another case
still refers to the attachment the retirement is rejected and the bytes stay in
storage.

Older, unsigned or schema version 1 indexes are still readable.  They are not
silently treated as complete: the read result carries an explicit
``missing-evidence`` status naming the absent digest, authorization, or index
signature.
"""

from __future__ import annotations

import copy
import io
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from securesystemslib import exceptions, formats, hash
from securesystemslib.dsse import Envelope
from securesystemslib.signer import Key, Signature, Signer
from securesystemslib.storage import FilesystemBackend, StorageBackendInterface

INDEX_PAYLOAD_TYPE = "application/vnd.securesystemslib.approval-index+json"
MANIFEST_PAYLOAD_TYPE = "application/vnd.securesystemslib.retirement-manifest+json"
INDEX_SCHEMA_VERSION = 2
MANIFEST_SCHEMA_VERSION = 2
DEFAULT_DIGEST_ALGORITHM = "sha256"

INDEX_TYPE = "approval-storage-index"
MANIFEST_TYPE = "retirement-manifest"


class RetirementError(exceptions.Error):
    """Base class for retirement workflow errors."""


class InvalidRequestError(RetirementError):
    """The retirement request does not identify exactly one attachment."""


class AuthorizationError(RetirementError):
    """An authorization record is absent, invalid, or does not match."""


class MissingEvidenceError(RetirementError):
    """Evidence needed to prove a retirement is explicitly missing."""

    def __init__(self, evidence: EvidenceReport) -> None:
        self.evidence = evidence
        missing = ", ".join(evidence.missing) or "unknown evidence"
        super().__init__(f"missing evidence: {missing}")


class EvidenceStatus(StrEnum):
    """Whether a document contains all evidence needed for retirement."""

    COMPLETE = "complete"
    MISSING = "missing-evidence"


class RetirementStatus(StrEnum):
    """Outcome of a retirement attempt."""

    RETIRED = "retired"
    REJECTED = "rejected"


class RejectionReason(StrEnum):
    """Machine-readable reasons why a retirement was refused."""

    INVALID_REQUEST = "invalid-request"
    INDEX_SIGNATURE = "index-signature"
    MISSING_EVIDENCE = "missing-evidence"
    UNKNOWN_CASE = "unknown-case"
    UNKNOWN_ATTACHMENT = "unknown-attachment"
    SHARED_REFERENCE = "shared-reference"
    ATTACHMENT_MISSING = "attachment-missing"
    DIGEST_MISMATCH = "digest-mismatch"
    UNAUTHORIZED = "unauthorized"
    ALREADY_RETIRED = "already-retired"


class VerificationStatus(StrEnum):
    """Outcome of checking retirement or rejection evidence."""

    VALID = "valid"
    INVALID = "invalid"
    MISSING_EVIDENCE = "missing-evidence"


@dataclass(frozen=True)
class CheckResult:
    """One named check performed while retiring or verifying."""

    name: str
    passed: bool
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class EvidenceReport:
    """Explicit completeness report for an index or manifest."""

    status: EvidenceStatus
    missing: tuple[str, ...] = ()
    legacy: bool = False

    @classmethod
    def complete(cls) -> EvidenceReport:
        return cls(EvidenceStatus.COMPLETE)

    @classmethod
    def from_missing(
        cls, missing: Iterable[str], *, legacy: bool = False
    ) -> EvidenceReport:
        unique = tuple(dict.fromkeys(missing))
        status = EvidenceStatus.MISSING if unique else EvidenceStatus.COMPLETE
        return cls(status, unique, legacy)

    def merged(
        self, extra_missing: Iterable[str], *, legacy: bool = False
    ) -> EvidenceReport:
        return EvidenceReport.from_missing(
            (*self.missing, *extra_missing), legacy=self.legacy or legacy
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "legacy": self.legacy,
            "missing": list(self.missing),
        }


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _normalize_digest(digest: Mapping[str, Any] | None) -> dict[str, str] | None:
    if not isinstance(digest, Mapping) or not digest:
        return None
    normalized: dict[str, str] = {}
    for algorithm, value in digest.items():
        if not isinstance(algorithm, str) or not isinstance(value, str):
            return None
        normalized[algorithm] = value
    return normalized


def _digest_bytes(
    data: bytes, algorithm: str = DEFAULT_DIGEST_ALGORITHM
) -> dict[str, str]:
    digest_object = hash.digest(algorithm)
    digest_object.update(data)
    return {algorithm: digest_object.hexdigest()}


def _read_json(path: str | Path, storage: StorageBackendInterface) -> Any:
    with storage.get(str(path)) as fileobj:
        return json.load(fileobj)


def _write_json(
    path: str | Path,
    data: Any,
    storage: StorageBackendInterface,
    *,
    restrict: bool = True,
) -> None:
    destination = Path(path)
    storage.create_folder(str(destination.parent))
    encoded = (
        json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    storage.put(io.BytesIO(encoded), str(destination), restrict=restrict)


def _as_key_list(keys: Key | Iterable[Key]) -> list[Key]:
    if isinstance(keys, Key):
        return [keys]
    return list(keys)


def _looks_like_envelope(data: Mapping[str, Any]) -> bool:
    return {"payload", "payloadType", "signatures"}.issubset(data)


@dataclass(frozen=True)
class AuthorizationRecord:
    """An approver's signature over the case, attachments, and their digests.

    The signature covers ``record_id``, ``case_id``, ``attachment_ids``,
    ``approved_at``, ``approver_keyid``, and ``authorized_digests``.  Verifying
    the signature therefore proves that the named approver authorized those
    exact attachment bytes, not merely that a case existed.
    """

    record_id: str
    case_id: str
    attachment_ids: tuple[str, ...]
    approved_at: str
    approver_keyid: str
    authorized_digests: Mapping[str, Mapping[str, str]] = field(default_factory=dict)
    signature: Signature | None = None

    def body_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "case_id": self.case_id,
            "attachment_ids": list(self.attachment_ids),
            "approved_at": self.approved_at,
            "approver_keyid": self.approver_keyid,
            "authorized_digests": {
                attachment_id: dict(digest)
                for attachment_id, digest in self.authorized_digests.items()
            },
        }

    def signed_bytes(self) -> bytes:
        encoded = formats.encode_canonical(self.body_dict())
        if encoded is None:  # pragma: no cover - encode_canonical raises instead
            raise RetirementError("could not encode authorization record")
        return encoded.encode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        data = self.body_dict()
        if self.signature is not None:
            data["signature"] = self.signature.to_dict()
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AuthorizationRecord:
        raw_attachment_ids = data.get("attachment_ids", [])
        if isinstance(raw_attachment_ids, str):
            attachment_ids = [raw_attachment_ids]
        elif isinstance(raw_attachment_ids, Iterable):
            attachment_ids = list(raw_attachment_ids)
        else:
            attachment_ids = [raw_attachment_ids]

        authorized_digests: dict[str, dict[str, str]] = {}
        raw_digests = data.get("authorized_digests", {})
        if isinstance(raw_digests, Mapping):
            for attachment_id, digest in raw_digests.items():
                if isinstance(attachment_id, str):
                    normalized = _normalize_digest(digest)
                    if normalized is not None:
                        authorized_digests[attachment_id] = normalized

        signature = None
        raw_signature = data.get("signature")
        if isinstance(raw_signature, Mapping):
            try:
                signature = Signature.from_dict(dict(raw_signature))
            except (KeyError, TypeError):
                signature = None

        return cls(
            record_id=str(data.get("record_id", "")),
            case_id=str(data.get("case_id", "")),
            attachment_ids=tuple(str(item) for item in attachment_ids),
            approved_at=str(data.get("approved_at", "")),
            approver_keyid=str(data.get("approver_keyid", "")),
            authorized_digests=authorized_digests,
            signature=signature,
        )

    @classmethod
    def create(  # noqa: PLR0913
        cls,
        *,
        record_id: str,
        case_id: str,
        attachment_ids: Iterable[str],
        approved_at: str,
        authorized_digests: Mapping[str, Mapping[str, str]],
        approver: Signer,
    ) -> AuthorizationRecord:
        record = cls(
            record_id=record_id,
            case_id=case_id,
            attachment_ids=tuple(attachment_ids),
            approved_at=approved_at,
            approver_keyid=approver.public_key.keyid,
            authorized_digests=authorized_digests,
        )
        return replace(record, signature=approver.sign(record.signed_bytes()))

    def verify(self, key: Key) -> None:
        """Verify this record's approver signature with ``key``."""

        if self.signature is None:
            raise AuthorizationError(f"authorization {self.record_id} has no signature")
        if self.signature.keyid != self.approver_keyid:
            raise AuthorizationError(
                f"authorization {self.record_id} signature keyid "
                f"{self.signature.keyid} does not match approver "
                f"{self.approver_keyid}"
            )
        if key.keyid != self.approver_keyid:
            raise AuthorizationError(
                f"authorization {self.record_id} names key {self.approver_keyid}, "
                f"not {key.keyid}"
            )
        key.verify_signature(self.signature, self.signed_bytes())


@dataclass(frozen=True)
class ApprovalAttachment:
    """An approval attachment named by a storage index."""

    attachment_id: str
    path: str
    digest: Mapping[str, str] | None = None
    size: int | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"path": self.path}
        if self.digest is not None:
            data["digest"] = dict(self.digest)
        if self.size is not None:
            data["size"] = self.size
        return data

    @classmethod
    def from_dict(
        cls, attachment_id: str, data: Mapping[str, Any] | str
    ) -> ApprovalAttachment:
        if isinstance(data, str):
            return cls(attachment_id=attachment_id, path=data)

        size = data.get("size")
        return cls(
            attachment_id=attachment_id,
            path=str(data.get("path", "")),
            digest=_normalize_digest(data.get("digest")),
            size=size if isinstance(size, int) else None,
        )


@dataclass(frozen=True)
class ApprovalCase:
    """A case file, its attachment references, and its authorization record."""

    case_id: str
    attachment_ids: tuple[str, ...]
    authorization: AuthorizationRecord | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"attachments": list(self.attachment_ids)}
        if self.authorization is not None:
            data["authorization"] = self.authorization.to_dict()
        return data

    @classmethod
    def from_dict(cls, case_id: str, data: Any) -> ApprovalCase:
        if isinstance(data, (list, tuple)):
            raw_attachments = data
            raw_authorization = None
        elif isinstance(data, Mapping):
            raw_attachments = data.get(
                "attachments", data.get("attachment_ids", data.get("attachment", []))
            )
            raw_authorization = data.get("authorization")
        else:
            raw_attachments = []
            raw_authorization = None

        if isinstance(raw_attachments, str):
            attachment_ids = [raw_attachments]
        elif isinstance(raw_attachments, Iterable):
            attachment_ids = []
            for attachment in raw_attachments:
                if isinstance(attachment, str):
                    attachment_ids.append(attachment)
                elif isinstance(attachment, Mapping) and "id" in attachment:
                    attachment_ids.append(str(attachment["id"]))
        else:
            attachment_ids = []

        authorization = None
        if isinstance(raw_authorization, Mapping):
            authorization = AuthorizationRecord.from_dict(raw_authorization)

        return cls(
            case_id=case_id,
            attachment_ids=tuple(attachment_ids),
            authorization=authorization,
        )


@dataclass(frozen=True)
class ApprovalIndex:
    """An approval storage index.

    Schema version 2 contains attachment digests and embedded, signed
    authorization records.  Older schemas are parsed but marked as missing
    evidence rather than being rejected during reading.
    """

    schema_version: int
    attachments: Mapping[str, ApprovalAttachment]
    cases: Mapping[str, ApprovalCase]
    created_at: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ApprovalIndex:
        raw_version = data.get(
            "schema_version", data.get("schema", data.get("version", 1))
        )
        try:
            schema_version = int(raw_version)
        except (TypeError, ValueError):
            schema_version = 1

        raw_attachments = data.get("attachments", {})
        attachments: dict[str, ApprovalAttachment] = {}
        if isinstance(raw_attachments, Mapping):
            for attachment_id, attachment_data in raw_attachments.items():
                if isinstance(attachment_id, str) and isinstance(
                    attachment_data, (Mapping, str)
                ):
                    attachments[attachment_id] = ApprovalAttachment.from_dict(
                        attachment_id, attachment_data
                    )

        raw_cases = data.get("cases", {})
        cases: dict[str, ApprovalCase] = {}
        if isinstance(raw_cases, Mapping):
            for case_id, case_data in raw_cases.items():
                if isinstance(case_id, str):
                    cases[case_id] = ApprovalCase.from_dict(case_id, case_data)

        created_at = data.get("created_at")
        return cls(
            schema_version=schema_version,
            attachments=attachments,
            cases=cases,
            created_at=created_at if isinstance(created_at, str) else None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "_type": INDEX_TYPE,
            "schema_version": self.schema_version,
            "created_at": self.created_at,
            "attachments": {
                attachment_id: attachment.to_dict()
                for attachment_id, attachment in self.attachments.items()
            },
            "cases": {case_id: case.to_dict() for case_id, case in self.cases.items()},
        }

    def references_to(self, attachment_id: str) -> list[str]:
        """Return sorted case ids that reference ``attachment_id``."""

        return sorted(
            case_id
            for case_id, case in self.cases.items()
            if attachment_id in case.attachment_ids
        )

    def evidence_report(self) -> EvidenceReport:  # noqa: PLR0912
        missing: list[str] = []
        legacy = self.schema_version < INDEX_SCHEMA_VERSION
        if legacy:
            missing.append("index.schema_version>=2")
        if not self.attachments:
            missing.append("index.attachments")
        if not self.cases:
            missing.append("index.cases")

        for attachment_id, attachment in self.attachments.items():
            if not attachment.path:
                missing.append(f"attachments.{attachment_id}.path")
            if attachment.digest is None:
                missing.append(f"attachments.{attachment_id}.digest")

        for case_id, case in self.cases.items():
            if not case.attachment_ids:
                missing.append(f"cases.{case_id}.attachments")
            for attachment_id in case.attachment_ids:
                if attachment_id not in self.attachments:
                    missing.append(f"cases.{case_id}.attachment:{attachment_id}")
            authorization = case.authorization
            if authorization is None:
                missing.append(f"cases.{case_id}.authorization")
                continue
            if authorization.signature is None:
                missing.append(f"cases.{case_id}.authorization.signature")
            if authorization.case_id != case_id:
                missing.append(f"cases.{case_id}.authorization.case_id")
            if not authorization.record_id:
                missing.append(f"cases.{case_id}.authorization.record_id")
            if not authorization.approved_at:
                missing.append(f"cases.{case_id}.authorization.approved_at")
            if not authorization.approver_keyid:
                missing.append(f"cases.{case_id}.authorization.approver_keyid")
            for attachment_id in case.attachment_ids:
                if attachment_id not in authorization.attachment_ids:
                    missing.append(
                        f"cases.{case_id}.authorization.attachment:{attachment_id}"
                    )
                if attachment_id not in authorization.authorized_digests:
                    missing.append(
                        f"cases.{case_id}.authorization.digest:{attachment_id}"
                    )
        return EvidenceReport.from_missing(missing, legacy=legacy)

    def require_complete(self) -> None:
        report = self.evidence_report()
        if report.status is not EvidenceStatus.COMPLETE:
            raise MissingEvidenceError(report)


@dataclass(frozen=True)
class IndexReadResult:
    """A parsed index plus signature and evidence status."""

    index: ApprovalIndex
    path: str
    envelope: Mapping[str, Any]
    payload_digest: Mapping[str, str]
    verified_keyids: tuple[str, ...] = ()
    signature_verified: bool = False
    document_format: str = "dsse"

    @property
    def evidence_report(self) -> EvidenceReport:
        report = self.index.evidence_report()
        missing = list(report.missing)
        if not self.signature_verified:
            missing.insert(0, "index.signature")
        return EvidenceReport.from_missing(
            missing, legacy=report.legacy or not self.signature_verified
        )

    @property
    def status(self) -> EvidenceStatus:
        return self.evidence_report.status

    def require_complete(self) -> None:
        report = self.evidence_report
        if report.status is not EvidenceStatus.COMPLETE:
            raise MissingEvidenceError(report)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "format": self.document_format,
            "payload_digest": dict(self.payload_digest),
            "verified_keyids": list(self.verified_keyids),
            "signature_verified": self.signature_verified,
            "evidence": self.evidence_report.to_dict(),
        }


@dataclass(frozen=True)
class RetirementRequest:
    """A request to withdraw exactly one attachment from one case."""

    request_id: str
    case_id: str
    attachment_id: str

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RetirementRequest:
        request_id = data.get("request_id", data.get("id"))
        case_id = data.get("case_id", data.get("case"))
        if not isinstance(request_id, str) or not request_id:
            raise InvalidRequestError("request_id is required")
        if not isinstance(case_id, str) or not case_id:
            raise InvalidRequestError("case_id is required")

        if "attachment_ids" in data:
            attachment_ids = data["attachment_ids"]
            if isinstance(attachment_ids, str):
                attachment_ids = [attachment_ids]
            elif not isinstance(attachment_ids, (list, tuple)):
                raise InvalidRequestError("attachment_ids must be a list")
            if len(attachment_ids) != 1:
                raise InvalidRequestError(
                    "a retirement request must name exactly one attachment"
                )
            attachment_id = attachment_ids[0]
            if "attachment_id" in data and data["attachment_id"] != attachment_id:
                raise InvalidRequestError("attachment_id and attachment_ids disagree")
        else:
            attachment_id = data.get("attachment_id", data.get("attachment"))

        if not isinstance(attachment_id, str) or not attachment_id:
            raise InvalidRequestError("attachment_id is required")
        return cls(request_id, case_id, attachment_id)

    def to_dict(self) -> dict[str, str]:
        return {
            "request_id": self.request_id,
            "case_id": self.case_id,
            "attachment_id": self.attachment_id,
        }


@dataclass(frozen=True)
class RetirementEntry:
    """One manifest entry: one withdrawn attachment and its retained proof."""

    attachment_id: str
    case_id: str
    path: str
    digest: Mapping[str, str] | None
    authorization: AuthorizationRecord | None
    index_digest: Mapping[str, str] | None
    retired_at: str
    request_id: str

    def to_dict(self) -> dict[str, Any]:
        retained: dict[str, Any] = {
            "digest": dict(self.digest) if self.digest is not None else None,
            "authorization": (
                self.authorization.to_dict() if self.authorization is not None else None
            ),
            "index_digest": (
                dict(self.index_digest) if self.index_digest is not None else None
            ),
        }
        return {
            "attachment_id": self.attachment_id,
            "case_id": self.case_id,
            "withdrawn": {
                "attachment_id": self.attachment_id,
                "path": self.path,
            },
            "retained": retained,
            "retired_at": self.retired_at,
            "request_id": self.request_id,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RetirementEntry:
        withdrawn = data.get("withdrawn", {})
        retained = data.get("retained", {})
        if not isinstance(withdrawn, Mapping):
            withdrawn = {}
        if not isinstance(retained, Mapping):
            retained = {}

        attachment_id = data.get("attachment_id", withdrawn.get("attachment_id"))
        path = data.get("path", withdrawn.get("path"))
        digest = retained.get("digest", data.get("digest"))
        raw_authorization = retained.get("authorization", data.get("authorization"))
        index_digest = retained.get("index_digest", data.get("index_digest"))
        authorization = (
            AuthorizationRecord.from_dict(raw_authorization)
            if isinstance(raw_authorization, Mapping)
            else None
        )
        return cls(
            attachment_id=str(attachment_id or ""),
            case_id=str(data.get("case_id", "")),
            path=str(path or ""),
            digest=_normalize_digest(digest) if isinstance(digest, Mapping) else None,
            authorization=authorization,
            index_digest=(
                _normalize_digest(index_digest)
                if isinstance(index_digest, Mapping)
                else None
            ),
            retired_at=str(data.get("retired_at", "")),
            request_id=str(data.get("request_id", "")),
        )


@dataclass(frozen=True)
class RetirementManifest:
    """A manifest of completed single-attachment retirements."""

    schema_version: int
    entries: tuple[RetirementEntry, ...] = ()
    created_at: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RetirementManifest:
        raw_version = data.get(
            "schema_version", data.get("schema", data.get("version", 1))
        )
        try:
            schema_version = int(raw_version)
        except (TypeError, ValueError):
            schema_version = 1

        raw_entries = data.get("retirements", data.get("entries", []))
        entries: list[RetirementEntry] = []
        if isinstance(raw_entries, list):
            for raw_entry in raw_entries:
                if isinstance(raw_entry, Mapping):
                    entries.append(RetirementEntry.from_dict(raw_entry))
        elif isinstance(raw_entries, Mapping):
            for attachment_id, raw_entry in raw_entries.items():
                if isinstance(attachment_id, str) and isinstance(raw_entry, Mapping):
                    entry_data = dict(raw_entry)
                    entry_data.setdefault("attachment_id", attachment_id)
                    entries.append(RetirementEntry.from_dict(entry_data))

        created_at = data.get("created_at")
        return cls(
            schema_version=schema_version,
            entries=tuple(entries),
            created_at=created_at if isinstance(created_at, str) else None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "_type": MANIFEST_TYPE,
            "schema_version": self.schema_version,
            "created_at": self.created_at,
            "retirements": [entry.to_dict() for entry in self.entries],
        }

    def entry_for(self, attachment_id: str) -> RetirementEntry | None:
        for entry in self.entries:
            if entry.attachment_id == attachment_id:
                return entry
        return None

    def evidence_report(self) -> EvidenceReport:  # noqa: PLR0912
        missing: list[str] = []
        legacy = self.schema_version < MANIFEST_SCHEMA_VERSION
        if legacy:
            missing.append("manifest.schema_version>=2")
        if not self.entries:
            missing.append("manifest.retirements")

        seen: set[str] = set()
        for index, entry in enumerate(self.entries):
            prefix = f"manifest.retirements[{index}]"
            if not entry.attachment_id:
                missing.append(f"{prefix}.attachment_id")
            elif entry.attachment_id in seen:
                missing.append(f"{prefix}.duplicate:{entry.attachment_id}")
            else:
                seen.add(entry.attachment_id)
            if not entry.case_id:
                missing.append(f"{prefix}.case_id")
            if not entry.path:
                missing.append(f"{prefix}.path")
            if entry.digest is None:
                missing.append(f"{prefix}.retained.digest")
            if entry.index_digest is None:
                missing.append(f"{prefix}.retained.index_digest")
            if entry.authorization is None:
                missing.append(f"{prefix}.retained.authorization")
            else:
                if entry.authorization.signature is None:
                    missing.append(f"{prefix}.retained.authorization.signature")
                if entry.authorization.case_id != entry.case_id:
                    missing.append(f"{prefix}.retained.authorization.case_id")
                if not entry.authorization.approved_at:
                    missing.append(f"{prefix}.retained.authorization.approved_at")
                if not entry.authorization.approver_keyid:
                    missing.append(f"{prefix}.retained.authorization.approver_keyid")
                if entry.attachment_id not in entry.authorization.attachment_ids:
                    missing.append(f"{prefix}.retained.authorization.attachment")
                if entry.attachment_id not in entry.authorization.authorized_digests:
                    missing.append(f"{prefix}.retained.authorization.digest")
        return EvidenceReport.from_missing(missing, legacy=legacy)

    def require_complete(self) -> None:
        report = self.evidence_report()
        if report.status is not EvidenceStatus.COMPLETE:
            raise MissingEvidenceError(report)


@dataclass(frozen=True)
class ManifestReadResult:
    """A parsed manifest plus signature and evidence status."""

    manifest: RetirementManifest
    path: str
    envelope: Mapping[str, Any]
    payload_digest: Mapping[str, str]
    verified_keyids: tuple[str, ...] = ()
    signature_verified: bool = False
    document_format: str = "dsse"

    @property
    def evidence_report(self) -> EvidenceReport:
        report = self.manifest.evidence_report()
        missing = list(report.missing)
        if not self.signature_verified:
            missing.insert(0, "manifest.signature")
        return EvidenceReport.from_missing(
            missing, legacy=report.legacy or not self.signature_verified
        )

    @property
    def status(self) -> EvidenceStatus:
        return self.evidence_report.status

    def require_complete(self) -> None:
        report = self.evidence_report
        if report.status is not EvidenceStatus.COMPLETE:
            raise MissingEvidenceError(report)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "format": self.document_format,
            "payload_digest": dict(self.payload_digest),
            "verified_keyids": list(self.verified_keyids),
            "signature_verified": self.signature_verified,
            "evidence": self.evidence_report.to_dict(),
        }


@dataclass(frozen=True)
class VerificationReport:
    """The result of checking a retirement or a justified rejection."""

    scope: str
    status: VerificationStatus
    checks: tuple[CheckResult, ...]
    entries: tuple[Mapping[str, Any], ...] = ()

    @property
    def valid(self) -> bool:
        return self.status is VerificationStatus.VALID

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "status": self.status.value,
            "checks": [check.to_dict() for check in self.checks],
            "entries": [dict(entry) for entry in self.entries],
        }


@dataclass(frozen=True)
class RetirementResult:
    """The outcome and proof material of one retirement attempt."""

    status: RetirementStatus
    reason: str
    request: Mapping[str, Any]
    checks: tuple[CheckResult, ...]
    attachment_id: str | None = None
    digest: Mapping[str, str] | None = None
    authorization: Mapping[str, Any] | None = None
    index_digest: Mapping[str, str] | None = None
    referencing_cases: tuple[str, ...] = ()
    evidence_dir: str | None = None
    verification: Mapping[str, Any] | None = None

    @property
    def retired(self) -> bool:
        return self.status is RetirementStatus.RETIRED

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "reason": self.reason,
            "request": dict(self.request),
            "attachment_id": self.attachment_id,
            "digest": dict(self.digest) if self.digest is not None else None,
            "authorization": (
                dict(self.authorization) if self.authorization is not None else None
            ),
            "index_digest": (
                dict(self.index_digest) if self.index_digest is not None else None
            ),
            "referencing_cases": list(self.referencing_cases),
            "checks": [check.to_dict() for check in self.checks],
            "evidence_dir": self.evidence_dir,
            "verification": (
                dict(self.verification) if self.verification is not None else None
            ),
        }


# Descriptive alias for callers that think in storage-index terms.
StorageIndex = ApprovalIndex


def sign_document(
    payload: Mapping[str, Any], payload_type: str, signer: Signer
) -> Envelope:
    """Return a DSSE envelope over canonical JSON ``payload``."""

    encoded = formats.encode_canonical(dict(payload))
    if encoded is None:  # pragma: no cover - encode_canonical raises instead
        raise RetirementError("could not encode document")
    envelope = Envelope(encoded.encode("utf-8"), payload_type, {})
    envelope.sign(signer)
    return envelope


def write_signed_document(
    path: str | Path,
    payload: Mapping[str, Any],
    payload_type: str,
    signer: Signer,
    *,
    storage_backend: StorageBackendInterface | None = None,
) -> Envelope:
    """Sign ``payload`` and write the DSSE envelope as JSON to ``path``."""

    storage = storage_backend or FilesystemBackend()
    envelope = sign_document(payload, payload_type, signer)
    _write_json(path, envelope.to_dict(), storage)
    return envelope


class RetirementService:
    """Verify approval indexes and retire one attachment at a time.

    Args:
        index_keys: Public keys trusted to sign the approval index.
        authorization_keys: Public keys trusted to sign authorization records.
            A mapping keyed by keyid or an iterable of keys is accepted.
        manifest_keys: Keys trusted to sign retirement manifests.  Defaults to
            ``index_keys``.
        signer: Signer used to sign new retirement manifests.
        threshold: Number of distinct index/manifest signatures required.
        storage_backend: Storage used for attachments, indexes, and evidence.
        attachment_root: Base directory for relative attachment paths.  Defaults
            to the directory containing the signed index.
        digest_algorithm: Hash algorithm recorded in new manifest entries.
    """

    def __init__(  # noqa: PLR0913
        self,
        index_keys: Key | Iterable[Key],
        authorization_keys: Key | Iterable[Key] | Mapping[str, Key],
        *,
        manifest_keys: Key | Iterable[Key] | None = None,
        signer: Signer | None = None,
        threshold: int = 1,
        storage_backend: StorageBackendInterface | None = None,
        attachment_root: str | Path | None = None,
        digest_algorithm: str = DEFAULT_DIGEST_ALGORITHM,
    ) -> None:
        if threshold <= 0:
            raise ValueError("threshold must be greater than 0")

        self.index_keys = _as_key_list(index_keys)
        self.manifest_keys = (
            self.index_keys if manifest_keys is None else _as_key_list(manifest_keys)
        )

        if isinstance(authorization_keys, Mapping):
            authorization_key_list = list(authorization_keys.values())
        else:
            authorization_key_list = _as_key_list(authorization_keys)
        self.authorization_keys = {key.keyid: key for key in authorization_key_list}

        if signer is not None and signer.public_key.keyid not in {
            key.keyid for key in self.manifest_keys
        }:
            raise ValueError(
                "manifest signer key is not among manifest_keys; the produced "
                "manifest would not verify"
            )

        self.signer = signer
        self.threshold = threshold
        self.storage = storage_backend or FilesystemBackend()
        self.attachment_root = (
            Path(attachment_root) if attachment_root is not None else None
        )
        self.digest_algorithm = digest_algorithm

    def load_index(self, path: str | Path) -> IndexReadResult:
        """Read and verify an approval index, preserving legacy status."""

        raw = _read_json(path, self.storage)
        if not isinstance(raw, Mapping):
            raise exceptions.FormatError("approval index must be a JSON object")

        if _looks_like_envelope(raw):
            envelope_dict = copy.deepcopy(dict(raw))
            envelope = Envelope.from_dict(copy.deepcopy(dict(raw)))
            if envelope.payload_type != INDEX_PAYLOAD_TYPE:
                raise exceptions.FormatError(
                    f"expected payload type {INDEX_PAYLOAD_TYPE}, "
                    f"got {envelope.payload_type}"
                )
            accepted = envelope.verify(self.index_keys, self.threshold)
            payload_bytes = envelope.payload
            document_format = "dsse"
            signature_verified = True
            verified_keyids = tuple(sorted(accepted))
        else:
            envelope_dict = copy.deepcopy(dict(raw))
            encoded = formats.encode_canonical(dict(raw))
            if encoded is None:  # pragma: no cover - encode_canonical raises instead
                raise exceptions.FormatError("could not encode index")
            payload_bytes = encoded.encode("utf-8")
            document_format = "legacy-plain-json"
            signature_verified = False
            verified_keyids = ()

        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise exceptions.FormatError("approval index payload is not JSON") from e
        if not isinstance(payload, Mapping):
            raise exceptions.FormatError("approval index payload must be an object")

        return IndexReadResult(
            index=ApprovalIndex.from_dict(payload),
            path=str(path),
            envelope=envelope_dict,
            payload_digest=_digest_bytes(payload_bytes, self.digest_algorithm),
            verified_keyids=verified_keyids,
            signature_verified=signature_verified,
            document_format=document_format,
        )

    def load_manifest(self, path: str | Path) -> ManifestReadResult:
        """Read and verify a retirement manifest, preserving legacy status."""

        raw = _read_json(path, self.storage)
        if not isinstance(raw, Mapping):
            raise exceptions.FormatError("retirement manifest must be a JSON object")

        if _looks_like_envelope(raw):
            envelope_dict = copy.deepcopy(dict(raw))
            envelope = Envelope.from_dict(copy.deepcopy(dict(raw)))
            if envelope.payload_type != MANIFEST_PAYLOAD_TYPE:
                raise exceptions.FormatError(
                    f"expected payload type {MANIFEST_PAYLOAD_TYPE}, "
                    f"got {envelope.payload_type}"
                )
            accepted = envelope.verify(self.manifest_keys, self.threshold)
            payload_bytes = envelope.payload
            document_format = "dsse"
            signature_verified = True
            verified_keyids = tuple(sorted(accepted))
        else:
            envelope_dict = copy.deepcopy(dict(raw))
            encoded = formats.encode_canonical(dict(raw))
            if encoded is None:  # pragma: no cover - encode_canonical raises instead
                raise exceptions.FormatError("could not encode manifest")
            payload_bytes = encoded.encode("utf-8")
            document_format = "legacy-plain-json"
            signature_verified = False
            verified_keyids = ()

        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise exceptions.FormatError("manifest payload is not JSON") from e
        if not isinstance(payload, Mapping):
            raise exceptions.FormatError("manifest payload must be an object")

        return ManifestReadResult(
            manifest=RetirementManifest.from_dict(payload),
            path=str(path),
            envelope=envelope_dict,
            payload_digest=_digest_bytes(payload_bytes, self.digest_algorithm),
            verified_keyids=verified_keyids,
            signature_verified=signature_verified,
            document_format=document_format,
        )

    def _resolve_attachment_path(
        self, index_path: str | Path, attachment_path: str
    ) -> Path:
        path = Path(attachment_path)
        if path.is_absolute():
            return path
        root = (
            self.attachment_root
            if self.attachment_root is not None
            else Path(index_path).resolve().parent
        )
        return root / path

    def _file_digest(self, path: Path) -> dict[str, str]:
        with self.storage.get(str(path)) as fileobj:
            digest = hash.digest_fileobject(fileobj, algorithm=self.digest_algorithm)
        return {self.digest_algorithm: digest.hexdigest()}

    def _attachment_state(self, path: Path) -> tuple[bool, dict[str, str] | None]:
        try:
            return True, self._file_digest(path)
        except exceptions.StorageError:
            return False, None

    def _default_evidence_dir(self, index_path: str | Path, request_id: str) -> Path:
        safe_request = (
            "".join(
                character if character.isalnum() or character in "-_." else "_"
                for character in request_id
            )
            or "unknown-request"
        )
        return Path(index_path).resolve().parent / "retirement-evidence" / safe_request

    def _write_index_copy(
        self, evidence_dir: Path, index_result: IndexReadResult
    ) -> None:
        _write_json(
            evidence_dir / "index.dsse.json", index_result.envelope, self.storage
        )

    def _write_rejection_evidence(
        self,
        *,
        evidence_dir: Path,
        index_result: IndexReadResult,
        request: Mapping[str, Any],
        result: RetirementResult,
        index_path: str | Path,
    ) -> dict[str, Any]:
        attachment = (
            index_result.index.attachments.get(result.attachment_id or "")
            if result.attachment_id is not None
            else None
        )
        attachment_state: dict[str, Any] = {
            "attachment_id": result.attachment_id,
            "path": attachment.path if attachment is not None else None,
            "digest": dict(attachment.digest or {}) if attachment is not None else None,
            "present": False,
            "computed_digest": None,
        }
        if attachment is not None and attachment.path:
            resolved = self._resolve_attachment_path(index_path, attachment.path)
            present, computed = self._attachment_state(resolved)
            attachment_state["path"] = str(resolved)
            attachment_state["present"] = present
            attachment_state["computed_digest"] = computed
            attachment_state["digest_matches_index"] = (
                computed is not None and dict(attachment.digest or {}) == computed
            )

        verification_checks = [
            CheckResult(
                "index-signature",
                index_result.signature_verified,
                ",".join(index_result.verified_keyids),
            ),
            CheckResult(
                "index-evidence",
                index_result.evidence_report.status is EvidenceStatus.COMPLETE,
                ",".join(index_result.evidence_report.missing),
            ),
            CheckResult(
                "rejection-reason",
                result.reason == RejectionReason.SHARED_REFERENCE.value,
                result.reason,
            ),
            CheckResult(
                "attachment-preserved",
                attachment_state["present"],
                str(attachment_state["path"]),
            ),
            CheckResult(
                "attachment-digest",
                bool(attachment_state.get("digest_matches_index", False)),
                str(attachment_state.get("computed_digest")),
            ),
            CheckResult(
                "shared-reference",
                len(result.referencing_cases) > 1,
                ",".join(result.referencing_cases),
            ),
        ]
        verification_status = (
            VerificationStatus.VALID
            if all(check.passed for check in verification_checks)
            else VerificationStatus.INVALID
        )
        verification = {
            "scope": "shared-reference-rejection",
            "status": verification_status.value,
            "request": dict(request),
            "index": index_result.to_dict(),
            "attachment": attachment_state,
            "referencing_cases": list(result.referencing_cases),
            "checks": [check.to_dict() for check in verification_checks],
        }

        self._write_index_copy(evidence_dir, index_result)
        _write_json(evidence_dir / "request.json", dict(request), self.storage)
        if result.authorization is not None:
            _write_json(
                evidence_dir / "authorization-record.json",
                result.authorization,
                self.storage,
            )
        if result.digest is not None:
            _write_json(
                evidence_dir / "attachment-digest.json",
                {
                    "attachment_id": result.attachment_id,
                    "digest": dict(result.digest),
                },
                self.storage,
            )
        _write_json(evidence_dir / "rejection.json", result.to_dict(), self.storage)
        _write_json(
            evidence_dir / "verification-report.json", verification, self.storage
        )
        return verification

    def _reject(  # noqa: PLR0913
        self,
        *,
        reason: RejectionReason,
        checks: Iterable[CheckResult],
        evidence_dir: Path,
        index_result: IndexReadResult,
        request: Mapping[str, Any],
        index_path: str | Path,
        attachment_id: str | None = None,
        digest: Mapping[str, str] | None = None,
        authorization: Mapping[str, Any] | None = None,
        referencing_cases: Iterable[str] = (),
    ) -> RetirementResult:
        result = RetirementResult(
            status=RetirementStatus.REJECTED,
            reason=reason.value,
            request=dict(request),
            checks=tuple(checks),
            attachment_id=attachment_id,
            digest=digest,
            authorization=authorization,
            index_digest=index_result.payload_digest,
            referencing_cases=tuple(referencing_cases),
            evidence_dir=str(evidence_dir),
        )
        verification = self._write_rejection_evidence(
            evidence_dir=evidence_dir,
            index_result=index_result,
            request=request,
            result=result,
            index_path=index_path,
        )
        result = replace(result, verification=verification)
        _write_json(evidence_dir / "rejection.json", result.to_dict(), self.storage)
        return result

    def retire(  # noqa: PLR0911, PLR0912, PLR0915
        self,
        index_path: str | Path,
        request: RetirementRequest | Mapping[str, Any],
        *,
        manifest_path: str | Path | None = None,
        evidence_dir: str | Path | None = None,
    ) -> RetirementResult:
        """Retire exactly one attachment if all evidence and reference rules pass.

        A rejected request never removes the attachment.  Both accepted and
        rejected attempts write an evidence bundle when ``evidence_dir`` is
        usable (a default directory is derived when it is omitted).
        """

        index_path = Path(index_path)
        request_data = (
            request.to_dict()
            if isinstance(request, RetirementRequest)
            else dict(request)
        )
        temporary_request_id = str(
            request_data.get("request_id", request_data.get("id", "unknown-request"))
        )
        evidence_path = (
            Path(evidence_dir)
            if evidence_dir is not None
            else self._default_evidence_dir(index_path, temporary_request_id)
        )

        index_result = self.load_index(index_path)
        index = index_result.index
        checks: list[CheckResult] = [
            CheckResult(
                "index-signature",
                index_result.signature_verified,
                ",".join(index_result.verified_keyids),
            ),
            CheckResult(
                "index-evidence",
                index_result.evidence_report.status is EvidenceStatus.COMPLETE,
                ",".join(index_result.evidence_report.missing),
            ),
        ]

        try:
            retirement_request = (
                request
                if isinstance(request, RetirementRequest)
                else RetirementRequest.from_dict(request_data)
            )
        except InvalidRequestError as e:
            checks.append(CheckResult("request-single-attachment", False, str(e)))
            return self._reject(
                reason=RejectionReason.INVALID_REQUEST,
                checks=checks,
                evidence_dir=evidence_path,
                index_result=index_result,
                request=request_data,
                index_path=index_path,
            )
        checks.append(
            CheckResult(
                "request-single-attachment",
                True,
                retirement_request.attachment_id,
            )
        )

        if index_result.evidence_report.status is not EvidenceStatus.COMPLETE:
            return self._reject(
                reason=RejectionReason.MISSING_EVIDENCE,
                checks=checks,
                evidence_dir=evidence_path,
                index_result=index_result,
                request=retirement_request.to_dict(),
                index_path=index_path,
                attachment_id=retirement_request.attachment_id,
            )

        attachment_id = retirement_request.attachment_id
        attachment = index.attachments.get(attachment_id)
        if attachment is None:
            checks.append(
                CheckResult("attachment-known", False, f"unknown {attachment_id}")
            )
            return self._reject(
                reason=RejectionReason.UNKNOWN_ATTACHMENT,
                checks=checks,
                evidence_dir=evidence_path,
                index_result=index_result,
                request=retirement_request.to_dict(),
                index_path=index_path,
                attachment_id=attachment_id,
            )
        checks.append(CheckResult("attachment-known", True, attachment.path))

        case = index.cases.get(retirement_request.case_id)
        if case is None:
            checks.append(
                CheckResult(
                    "case-known", False, f"unknown {retirement_request.case_id}"
                )
            )
            return self._reject(
                reason=RejectionReason.UNKNOWN_CASE,
                checks=checks,
                evidence_dir=evidence_path,
                index_result=index_result,
                request=retirement_request.to_dict(),
                index_path=index_path,
                attachment_id=attachment_id,
                digest=attachment.digest,
            )
        checks.append(CheckResult("case-known", True, case.case_id))

        case_references_attachment = attachment_id in case.attachment_ids
        checks.append(
            CheckResult(
                "case-reference",
                case_references_attachment,
                ",".join(case.attachment_ids),
            )
        )
        if not case_references_attachment:
            return self._reject(
                reason=RejectionReason.INVALID_REQUEST,
                checks=checks,
                evidence_dir=evidence_path,
                index_result=index_result,
                request=retirement_request.to_dict(),
                index_path=index_path,
                attachment_id=attachment_id,
                digest=attachment.digest,
            )

        referencing_cases = tuple(index.references_to(attachment_id))
        checks.append(
            CheckResult(
                "shared-reference",
                referencing_cases == (retirement_request.case_id,),
                ",".join(referencing_cases),
            )
        )
        if referencing_cases != (retirement_request.case_id,):
            return self._reject(
                reason=RejectionReason.SHARED_REFERENCE,
                checks=checks,
                evidence_dir=evidence_path,
                index_result=index_result,
                request=retirement_request.to_dict(),
                index_path=index_path,
                attachment_id=attachment_id,
                digest=attachment.digest,
                authorization=(
                    case.authorization.to_dict()
                    if case.authorization is not None
                    else None
                ),
                referencing_cases=referencing_cases,
            )

        attachment_path = self._resolve_attachment_path(index_path, attachment.path)
        present, actual_digest = self._attachment_state(attachment_path)
        checks.append(
            CheckResult(
                "attachment-present",
                present,
                str(attachment_path),
            )
        )
        if not present:
            return self._reject(
                reason=RejectionReason.ATTACHMENT_MISSING,
                checks=checks,
                evidence_dir=evidence_path,
                index_result=index_result,
                request=retirement_request.to_dict(),
                index_path=index_path,
                attachment_id=attachment_id,
                digest=attachment.digest,
            )

        declared_digest = dict(attachment.digest or {})
        digest_matches = actual_digest == declared_digest
        checks.append(
            CheckResult(
                "attachment-digest",
                digest_matches,
                f"expected {declared_digest}, got {actual_digest}",
            )
        )
        if not digest_matches:
            return self._reject(
                reason=RejectionReason.DIGEST_MISMATCH,
                checks=checks,
                evidence_dir=evidence_path,
                index_result=index_result,
                request=retirement_request.to_dict(),
                index_path=index_path,
                attachment_id=attachment_id,
                digest=actual_digest,
            )

        authorization = case.authorization
        if authorization is None:
            checks.append(CheckResult("authorization-record", False, "absent"))
            return self._reject(
                reason=RejectionReason.MISSING_EVIDENCE,
                checks=checks,
                evidence_dir=evidence_path,
                index_result=index_result,
                request=retirement_request.to_dict(),
                index_path=index_path,
                attachment_id=attachment_id,
                digest=actual_digest,
            )
        checks.append(
            CheckResult("authorization-record", True, authorization.record_id)
        )

        authorization_key = self.authorization_keys.get(authorization.approver_keyid)
        if authorization_key is None:
            checks.append(
                CheckResult(
                    "authorization-key",
                    False,
                    f"no trusted key {authorization.approver_keyid}",
                )
            )
            return self._reject(
                reason=RejectionReason.UNAUTHORIZED,
                checks=checks,
                evidence_dir=evidence_path,
                index_result=index_result,
                request=retirement_request.to_dict(),
                index_path=index_path,
                attachment_id=attachment_id,
                digest=actual_digest,
                authorization=authorization.to_dict(),
            )

        try:
            authorization.verify(authorization_key)
        except (AuthorizationError, exceptions.UnverifiedSignatureError) as e:
            checks.append(CheckResult("authorization-signature", False, str(e)))
            return self._reject(
                reason=RejectionReason.UNAUTHORIZED,
                checks=checks,
                evidence_dir=evidence_path,
                index_result=index_result,
                request=retirement_request.to_dict(),
                index_path=index_path,
                attachment_id=attachment_id,
                digest=actual_digest,
                authorization=authorization.to_dict(),
            )
        checks.append(
            CheckResult(
                "authorization-signature",
                True,
                authorization.approver_keyid,
            )
        )

        authorized_digest = authorization.authorized_digests.get(attachment_id)
        authorization_binding = (
            authorization.case_id == retirement_request.case_id
            and attachment_id in authorization.attachment_ids
            and authorized_digest == actual_digest
        )
        checks.append(
            CheckResult(
                "authorization-binding",
                authorization_binding,
                f"expected {authorized_digest}, got {actual_digest}",
            )
        )
        if not authorization_binding:
            return self._reject(
                reason=RejectionReason.UNAUTHORIZED,
                checks=checks,
                evidence_dir=evidence_path,
                index_result=index_result,
                request=retirement_request.to_dict(),
                index_path=index_path,
                attachment_id=attachment_id,
                digest=actual_digest,
                authorization=authorization.to_dict(),
            )

        if self.signer is None:
            raise ValueError("a retirement signer is required to read a manifest")

        if manifest_path is None:
            manifest_path = index_path.parent / "retirement-manifest.dsse.json"
        manifest_path = Path(manifest_path)

        try:
            manifest_result = self.load_manifest(manifest_path)
        except exceptions.StorageError:
            manifest_result = None

        if manifest_result is not None:
            if manifest_result.evidence_report.status is not EvidenceStatus.COMPLETE:
                checks.append(
                    CheckResult(
                        "manifest-evidence",
                        False,
                        ",".join(manifest_result.evidence_report.missing),
                    )
                )
                return self._reject(
                    reason=RejectionReason.MISSING_EVIDENCE,
                    checks=checks,
                    evidence_dir=evidence_path,
                    index_result=index_result,
                    request=retirement_request.to_dict(),
                    index_path=index_path,
                    attachment_id=attachment_id,
                    digest=actual_digest,
                    authorization=authorization.to_dict(),
                )
            previous = manifest_result.manifest.entry_for(attachment_id)
            if previous is not None:
                checks.append(
                    CheckResult("already-retired", False, previous.request_id)
                )
                return self._reject(
                    reason=RejectionReason.ALREADY_RETIRED,
                    checks=checks,
                    evidence_dir=evidence_path,
                    index_result=index_result,
                    request=retirement_request.to_dict(),
                    index_path=index_path,
                    attachment_id=attachment_id,
                    digest=actual_digest,
                    authorization=authorization.to_dict(),
                )
            manifest = RetirementManifest(
                schema_version=MANIFEST_SCHEMA_VERSION,
                entries=manifest_result.manifest.entries,
                created_at=manifest_result.manifest.created_at or _utc_now(),
            )
        else:
            manifest = RetirementManifest(
                schema_version=MANIFEST_SCHEMA_VERSION,
                entries=(),
                created_at=_utc_now(),
            )

        entry = RetirementEntry(
            attachment_id=attachment_id,
            case_id=retirement_request.case_id,
            path=attachment.path,
            digest=actual_digest,
            authorization=authorization,
            index_digest=dict(index_result.payload_digest),
            retired_at=_utc_now(),
            request_id=retirement_request.request_id,
        )
        manifest = replace(manifest, entries=(*manifest.entries, entry))
        manifest_envelope = sign_document(
            manifest.to_dict(), MANIFEST_PAYLOAD_TYPE, self.signer
        )

        _write_json(manifest_path, manifest_envelope.to_dict(), self.storage)
        self.storage.remove(str(attachment_path))
        still_present, _ = self._attachment_state(attachment_path)
        checks.append(
            CheckResult("attachment-removed", not still_present, str(attachment_path))
        )

        retention_record = {
            "attachment_id": attachment_id,
            "case_id": retirement_request.case_id,
            "withdrawn": {"attachment_id": attachment_id, "path": attachment.path},
            "retained": {
                "digest": dict(actual_digest),
                "authorization": authorization.to_dict(),
                "index_digest": dict(index_result.payload_digest),
            },
            "manifest_digest": _digest_bytes(
                manifest_envelope.payload, self.digest_algorithm
            ),
        }

        self._write_index_copy(evidence_path, index_result)
        _write_json(
            evidence_path / "request.json", retirement_request.to_dict(), self.storage
        )
        _write_json(
            evidence_path / "retirement-manifest.dsse.json",
            manifest_envelope.to_dict(),
            self.storage,
        )
        _write_json(
            evidence_path / "retention-record.json", retention_record, self.storage
        )
        _write_json(
            evidence_path / "retained-digest.json",
            {"attachment_id": attachment_id, "digest": dict(actual_digest)},
            self.storage,
        )
        _write_json(
            evidence_path / "authorization-record.json",
            authorization.to_dict(),
            self.storage,
        )

        verification_report = self.verify_retirement(
            index_path,
            manifest_path,
            evidence_dir=evidence_path,
        )
        result = RetirementResult(
            status=RetirementStatus.RETIRED,
            reason="retired",
            request=retirement_request.to_dict(),
            checks=tuple(checks),
            attachment_id=attachment_id,
            digest=actual_digest,
            authorization=authorization.to_dict(),
            index_digest=dict(index_result.payload_digest),
            referencing_cases=referencing_cases,
            evidence_dir=str(evidence_path),
            verification=verification_report.to_dict(),
        )
        _write_json(evidence_path / "receipt.json", result.to_dict(), self.storage)
        return result

    def verify_retirement(  # noqa: PLR0912, PLR0915
        self,
        index_path: str | Path,
        manifest_path: str | Path,
        *,
        evidence_dir: str | Path | None = None,
    ) -> VerificationReport:
        """Verify that a manifest proves a safe, authorized withdrawal."""

        index_path = Path(index_path)
        manifest_path = Path(manifest_path)
        checks: list[CheckResult] = []
        entries: list[Mapping[str, Any]] = []
        missing_evidence = False

        try:
            index_result = self.load_index(index_path)
        except exceptions.StorageError as e:
            checks.append(CheckResult("index-signature", False, str(e)))
            report = VerificationReport(
                "retirement", VerificationStatus.MISSING_EVIDENCE, tuple(checks)
            )
            if evidence_dir is not None:
                _write_json(
                    Path(evidence_dir) / "verification-report.json",
                    report.to_dict(),
                    self.storage,
                )
            return report
        except (exceptions.Error, ValueError) as e:
            checks.append(CheckResult("index-signature", False, str(e)))
            report = VerificationReport(
                "retirement", VerificationStatus.INVALID, tuple(checks)
            )
            if evidence_dir is not None:
                _write_json(
                    Path(evidence_dir) / "verification-report.json",
                    report.to_dict(),
                    self.storage,
                )
            return report

        checks.append(
            CheckResult(
                "index-signature",
                index_result.signature_verified,
                ",".join(index_result.verified_keyids),
            )
        )
        index_evidence = index_result.evidence_report
        checks.append(
            CheckResult(
                "index-evidence",
                index_evidence.status is EvidenceStatus.COMPLETE,
                ",".join(index_evidence.missing),
            )
        )
        if index_evidence.status is not EvidenceStatus.COMPLETE:
            missing_evidence = True

        try:
            manifest_result = self.load_manifest(manifest_path)
        except exceptions.StorageError as e:
            checks.append(CheckResult("manifest-signature", False, str(e)))
            report = VerificationReport(
                "retirement",
                VerificationStatus.MISSING_EVIDENCE,
                tuple(checks),
            )
            if evidence_dir is not None:
                _write_json(
                    Path(evidence_dir) / "verification-report.json",
                    report.to_dict(),
                    self.storage,
                )
            return report
        except (exceptions.Error, ValueError) as e:
            checks.append(CheckResult("manifest-signature", False, str(e)))
            report = VerificationReport(
                "retirement",
                VerificationStatus.INVALID,
                tuple(checks),
            )
            if evidence_dir is not None:
                _write_json(
                    Path(evidence_dir) / "verification-report.json",
                    report.to_dict(),
                    self.storage,
                )
            return report

        checks.append(
            CheckResult(
                "manifest-signature",
                manifest_result.signature_verified,
                ",".join(manifest_result.verified_keyids),
            )
        )
        manifest_evidence = manifest_result.evidence_report
        checks.append(
            CheckResult(
                "manifest-evidence",
                manifest_evidence.status is EvidenceStatus.COMPLETE,
                ",".join(manifest_evidence.missing),
            )
        )
        if manifest_evidence.status is not EvidenceStatus.COMPLETE:
            missing_evidence = True

        manifest = manifest_result.manifest
        if not manifest.entries:
            checks.append(CheckResult("manifest-entry", False, "empty manifest"))

        for entry in manifest.entries:
            prefix = f"{entry.attachment_id}."
            entry_report: dict[str, Any] = {
                "attachment_id": entry.attachment_id,
                "case_id": entry.case_id,
                "digest": dict(entry.digest) if entry.digest is not None else None,
                "authorization_record_id": (
                    entry.authorization.record_id
                    if entry.authorization is not None
                    else None
                ),
                "checks": [],
            }
            entry_checks: list[CheckResult] = []

            attachment = index_result.index.attachments.get(entry.attachment_id)
            entry_checks.append(
                CheckResult(
                    prefix + "index-attachment",
                    attachment is not None,
                    entry.attachment_id,
                )
            )
            if attachment is None:
                missing_evidence = True

            references = tuple(index_result.index.references_to(entry.attachment_id))
            entry_checks.append(
                CheckResult(
                    prefix + "sole-reference",
                    references == (entry.case_id,),
                    ",".join(references),
                )
            )

            index_digest_matches = entry.index_digest == index_result.payload_digest
            entry_checks.append(
                CheckResult(
                    prefix + "index-digest",
                    index_digest_matches,
                    dumps_digest(entry.index_digest),
                )
            )

            entry_checks.append(
                CheckResult(
                    prefix + "retained-digest",
                    entry.digest is not None and bool(entry.digest),
                    dumps_digest(entry.digest),
                )
            )
            if entry.digest is None:
                missing_evidence = True

            entry_checks.append(
                CheckResult(
                    prefix + "retained-authorization",
                    entry.authorization is not None,
                    entry.authorization.record_id
                    if entry.authorization is not None
                    else "absent",
                )
            )
            if entry.authorization is None:
                missing_evidence = True
            else:
                authorization = entry.authorization
                authorization_key = self.authorization_keys.get(
                    authorization.approver_keyid
                )
                if authorization_key is None:
                    entry_checks.append(
                        CheckResult(
                            prefix + "authorization-key",
                            False,
                            authorization.approver_keyid,
                        )
                    )
                else:
                    try:
                        authorization.verify(authorization_key)
                    except (
                        AuthorizationError,
                        exceptions.UnverifiedSignatureError,
                    ) as e:
                        entry_checks.append(
                            CheckResult(
                                prefix + "authorization-signature", False, str(e)
                            )
                        )
                    else:
                        entry_checks.append(
                            CheckResult(
                                prefix + "authorization-signature",
                                True,
                                authorization.approver_keyid,
                            )
                        )

                authorization_digest = authorization.authorized_digests.get(
                    entry.attachment_id
                )
                entry_checks.append(
                    CheckResult(
                        prefix + "authorization-binding",
                        authorization.case_id == entry.case_id
                        and entry.attachment_id in authorization.attachment_ids
                        and authorization_digest == entry.digest,
                        f"recorded {authorization_digest}, retained {entry.digest}",
                    )
                )
                if authorization.signature is None:
                    missing_evidence = True

            if attachment is not None:
                entry_checks.append(
                    CheckResult(
                        prefix + "index-binding",
                        attachment.path == entry.path
                        and dict(attachment.digest or {}) == dict(entry.digest or {}),
                        attachment.path,
                    )
                )
                attachment_path = self._resolve_attachment_path(
                    index_path, attachment.path
                )
                present, _ = self._attachment_state(attachment_path)
                entry_checks.append(
                    CheckResult(
                        prefix + "attachment-withdrawn",
                        not present,
                        str(attachment_path),
                    )
                )

            checks.extend(entry_checks)
            entry_report["checks"] = [check.to_dict() for check in entry_checks]
            entry_report["valid"] = all(check.passed for check in entry_checks)
            entries.append(entry_report)

        all_passed = all(check.passed for check in checks) and bool(entries)
        if all_passed:
            status = VerificationStatus.VALID
        elif missing_evidence:
            status = VerificationStatus.MISSING_EVIDENCE
        else:
            status = VerificationStatus.INVALID

        report = VerificationReport(
            scope="retirement",
            status=status,
            checks=tuple(checks),
            entries=tuple(entries),
        )
        if evidence_dir is not None:
            _write_json(
                Path(evidence_dir) / "verification-report.json",
                report.to_dict(),
                self.storage,
            )
        return report

    def verify_rejection(
        self,
        index_path: str | Path,
        request: RetirementRequest | Mapping[str, Any],
        *,
        evidence_dir: str | Path | None = None,
    ) -> VerificationReport:
        """Verify that a shared-reference rejection preserved the attachment."""

        index_path = Path(index_path)
        try:
            retirement_request = (
                request
                if isinstance(request, RetirementRequest)
                else RetirementRequest.from_dict(dict(request))
            )
        except InvalidRequestError as e:
            report = VerificationReport(
                "shared-reference-rejection",
                VerificationStatus.INVALID,
                (CheckResult("request-single-attachment", False, str(e)),),
            )
            if evidence_dir is not None:
                _write_json(
                    Path(evidence_dir) / "verification-report.json",
                    report.to_dict(),
                    self.storage,
                )
            return report

        index_result = self.load_index(index_path)
        index = index_result.index
        attachment = index.attachments.get(retirement_request.attachment_id)
        references = tuple(index.references_to(retirement_request.attachment_id))
        checks: list[CheckResult] = [
            CheckResult(
                "index-signature",
                index_result.signature_verified,
                ",".join(index_result.verified_keyids),
            ),
            CheckResult(
                "index-evidence",
                index_result.evidence_report.status is EvidenceStatus.COMPLETE,
                ",".join(index_result.evidence_report.missing),
            ),
            CheckResult(
                "shared-reference",
                len(references) > 1,
                ",".join(references),
            ),
        ]

        present = False
        computed_digest = None
        if attachment is not None:
            attachment_path = self._resolve_attachment_path(index_path, attachment.path)
            present, computed_digest = self._attachment_state(attachment_path)
        checks.append(
            CheckResult(
                "attachment-preserved",
                present,
                attachment.path if attachment is not None else "unknown attachment",
            )
        )
        checks.append(
            CheckResult(
                "attachment-digest",
                computed_digest == dict(attachment.digest or {})
                if attachment is not None
                else False,
                str(computed_digest),
            )
        )

        case = index.cases.get(retirement_request.case_id)
        authorization = case.authorization if case is not None else None
        checks.append(
            CheckResult(
                "authorization-record",
                authorization is not None,
                authorization.record_id if authorization is not None else "absent",
            )
        )
        if authorization is not None:
            authorization_key = self.authorization_keys.get(
                authorization.approver_keyid
            )
            if authorization_key is None:
                checks.append(
                    CheckResult(
                        "authorization-signature",
                        False,
                        authorization.approver_keyid,
                    )
                )
            else:
                try:
                    authorization.verify(authorization_key)
                except (
                    AuthorizationError,
                    exceptions.UnverifiedSignatureError,
                ) as e:
                    checks.append(CheckResult("authorization-signature", False, str(e)))
                else:
                    checks.append(
                        CheckResult(
                            "authorization-signature",
                            True,
                            authorization.approver_keyid,
                        )
                    )
            authorized_digest = (
                authorization.authorized_digests.get(retirement_request.attachment_id)
                if attachment is not None
                else None
            )
            checks.append(
                CheckResult(
                    "authorization-binding",
                    attachment is not None
                    and retirement_request.case_id == authorization.case_id
                    and retirement_request.attachment_id in authorization.attachment_ids
                    and authorized_digest == dict(attachment.digest or {}),
                    authorization.record_id,
                )
            )

        status = (
            VerificationStatus.VALID
            if all(check.passed for check in checks)
            else VerificationStatus.INVALID
        )
        report = VerificationReport("shared-reference-rejection", status, tuple(checks))
        if evidence_dir is not None:
            _write_json(
                Path(evidence_dir) / "verification-report.json",
                report.to_dict(),
                self.storage,
            )
        return report


def dumps_digest(digest: Mapping[str, str] | None) -> str:
    """Return a short human-readable digest for check details."""

    if digest is None:
        return "absent"
    return ",".join(
        f"{algorithm}:{value}" for algorithm, value in sorted(digest.items())
    )


__all__ = [
    "ApprovalAttachment",
    "ApprovalCase",
    "ApprovalIndex",
    "AuthorizationError",
    "AuthorizationRecord",
    "CheckResult",
    "DEFAULT_DIGEST_ALGORITHM",
    "EvidenceReport",
    "EvidenceStatus",
    "INDEX_PAYLOAD_TYPE",
    "INDEX_SCHEMA_VERSION",
    "IndexReadResult",
    "InvalidRequestError",
    "MANIFEST_PAYLOAD_TYPE",
    "MANIFEST_SCHEMA_VERSION",
    "ManifestReadResult",
    "MissingEvidenceError",
    "RejectionReason",
    "RetirementEntry",
    "RetirementError",
    "RetirementManifest",
    "RetirementRequest",
    "RetirementResult",
    "RetirementService",
    "RetirementStatus",
    "StorageIndex",
    "VerificationReport",
    "VerificationStatus",
    "sign_document",
    "write_signed_document",
]
