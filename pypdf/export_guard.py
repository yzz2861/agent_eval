"""Optional export guardrails for application-level PDF assembly.

Applications that assemble a hand-over document from several sources often
verify an authorization out-of-band: a reviewer picks a purpose and the pages
that may leave the system.  :class:`ExportGuard` lets those applications pass
the already verified purpose and page selection to the regular writer calls
without trusting a file name.

The guard identifies a document by a fingerprint of its decrypted page content
and page geometry.  Authorizations are bound to that fingerprint, so two files
with the same name but different content cannot share an authorization.  Every
allowed and blocked export is written to an audit log, and a partial page
selection leaves an explicit :attr:`ExportAuditEvent.PARTIAL_SELECTION` record.

The guard is optional.  Without it, :class:`~pypdf.PdfWriter` behaves exactly
as before.
"""

import hashlib
import secrets
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, NoReturn

from ._page import PageObject
from .errors import PyPdfError
from .generic import IndirectObject, StreamObject
from .pagerange import PageRange

_IDENTITY_VERSION = b"pypdf-export-identity-v1"
_PAGE_KEYS_FOR_IDENTITY = (
    "/Resources",
    "/Annots",
    "/MediaBox",
    "/CropBox",
    "/Rotate",
    "/UserUnit",
)


class ExportBlockReason(str, Enum):
    """Why the guard refused an export."""

    MISSING_PURPOSE = "missing_purpose"
    PURPOSE_MISMATCH = "purpose_mismatch"
    DOCUMENT_MISMATCH = "document_mismatch"
    DOCUMENT_NOT_AUTHORIZED = "document_not_authorized"
    AUTHORIZATION_REVOKED = "authorization_revoked"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    PAGE_NOT_AUTHORIZED = "page_not_authorized"
    NOT_DECRYPTED = "not_decrypted"


class ExportAuditEvent(str, Enum):
    """Events written to an :class:`ExportGuard` audit log."""

    EXPORT_AUTHORIZED = "export_authorized"
    EXPORT_BLOCKED = "export_blocked"
    PARTIAL_SELECTION = "partial_selection"


@dataclass(frozen=True, slots=True)
class DocumentIdentity:
    """Content-derived identity of a PDF document.

    ``name`` is a human-readable label for auditing only.  Equality and hashing
    intentionally use :attr:`fingerprint` exclusively: the same content found
    through two paths or two roles is the same document, while two files that
    happen to share a name are not.
    """

    fingerprint: str
    page_count: int
    name: str | None = None

    @classmethod
    def from_pdf(cls, source: Any, *, name: str | None = None) -> "DocumentIdentity":
        """Build an identity from a reader, writer or any ``.pages`` holder."""
        _ensure_decrypted(source)
        pages = source.pages
        digest = hashlib.sha256(_IDENTITY_VERSION)
        digest.update(len(pages).to_bytes(8, "big"))
        for index, page in enumerate(pages):
            digest.update(b"\x00")
            digest.update(index.to_bytes(8, "big"))
            digest.update(_page_identity_digest(page))
        return cls(digest.hexdigest(), len(pages), name if name is not None else _source_label(source))

    @property
    def short(self) -> str:
        """A short, log-friendly fingerprint."""
        return self.fingerprint[:12]

    @property
    def display_name(self) -> str:
        """A label suitable for error messages and audit records."""
        return self.name or "<unnamed>"

    def matches(self, other: "DocumentIdentity") -> bool:
        """Return whether both identities describe the same content."""
        return self.fingerprint == other.fingerprint

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DocumentIdentity):
            return NotImplemented
        return self.fingerprint == other.fingerprint

    def __hash__(self) -> int:
        return hash(self.fingerprint)

    def as_dict(self) -> dict[str, Any]:
        """Serialize for audit storage."""
        return {
            "fingerprint": self.fingerprint,
            "short_fingerprint": self.short,
            "page_count": self.page_count,
            "name": self.name,
        }


@dataclass(slots=True)
class ExportAuthorization:
    """A verified permission to export specific pages for one purpose.

    Instances are normally created with :meth:`issue`, which computes the
    document identity from the actual decrypted content.
    """

    document: DocumentIdentity
    purpose: str
    pages: frozenset[int]
    authorization_id: str
    subject: str | None = None
    issued_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    revoked_at: datetime | None = None

    @classmethod
    def issue(
        cls,
        source: Any,
        purpose: str,
        pages: Any = None,
        *,
        document_name: str | None = None,
        subject: str | None = None,
        expires_at: datetime | None = None,
        expires_in: float | timedelta | None = None,
        authorization_id: str | None = None,
    ) -> "ExportAuthorization":
        """Create an authorization bound to the source's actual content.

        Args:
            source: A :class:`~pypdf.PdfReader`, writer or similar object with
                a ``pages`` sequence.
            purpose: The verified purpose, for example ``"legal_transmittal"``.
            pages: Authorized zero-based page indices.  ``None`` means every
                page.  A :class:`~pypdf.PageRange`, slice, tuple, integer or
                iterable of integers is accepted.
            document_name: Label used in audit records.  It never participates
                in identity matching.
            subject: Optional principal (for example ``"auditor"``).
            expires_at: Absolute expiry time.  Naive values are treated as UTC.
            expires_in: Relative expiry, mutually exclusive with ``expires_at``.
            authorization_id: Explicit id; a random id is generated by default.

        """
        if not isinstance(purpose, str) or not purpose:
            raise ValueError("purpose must be a non-empty string")
        if expires_at is not None and expires_in is not None:
            raise ValueError("expires_at and expires_in are mutually exclusive")
        document = DocumentIdentity.from_pdf(source, name=document_name)
        page_set = frozenset(_normalize_pages(pages, document.page_count))
        issued_at = datetime.now(timezone.utc)
        if isinstance(expires_in, timedelta):
            expires_at = issued_at + expires_in
        elif expires_in is not None:
            expires_at = issued_at + timedelta(seconds=float(expires_in))
        return cls(
            document=document,
            purpose=purpose,
            pages=page_set,
            authorization_id=authorization_id or f"auth-{secrets.token_hex(8)}",
            subject=subject,
            issued_at=issued_at,
            expires_at=expires_at,
        )

    def revoke(self, at: datetime | None = None) -> None:
        """Revoke this authorization; the revocation is effective immediately."""
        self.revoked_at = at or datetime.now(timezone.utc)

    def is_valid(self, now: datetime | None = None) -> bool:
        """Return whether the authorization is neither revoked nor expired."""
        current = _as_utc(now or datetime.now(timezone.utc))
        if self.revoked_at is not None and _as_utc(self.revoked_at) <= current:
            return False
        return not (self.expires_at is not None and _as_utc(self.expires_at) <= current)

    def covers(self, page_index: int) -> bool:
        """Return whether ``page_index`` is inside the granted page set."""
        return page_index in self.pages

    def as_dict(self) -> dict[str, Any]:
        """Serialize for audit storage."""
        return {
            "authorization_id": self.authorization_id,
            "purpose": self.purpose,
            "subject": self.subject,
            "pages": list(pages_to_numbers(sorted(self.pages))),
            "document": self.document.as_dict(),
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
        }


@dataclass(frozen=True, slots=True)
class ExportAuditRecord:
    """One auditable decision made by an :class:`ExportGuard`."""

    event: ExportAuditEvent
    occurred_at: datetime
    reason: ExportBlockReason | None = None
    purpose: str | None = None
    document_id: str | None = None
    document_name: str | None = None
    authorization_id: str | None = None
    page_indices: tuple[int, ...] = ()
    details: Mapping[str, Any] = field(default_factory=dict)

    @property
    def page_numbers(self) -> tuple[int, ...]:
        """The selected pages as one-based page numbers."""
        return pages_to_numbers(self.page_indices)

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            "event": self.event.value,
            "occurred_at": self.occurred_at.isoformat(),
            "reason": self.reason.value if self.reason is not None else None,
            "purpose": self.purpose,
            "document_id": self.document_id,
            "document_name": self.document_name,
            "authorization_id": self.authorization_id,
            "page_indices": list(self.page_indices),
            "page_numbers": list(self.page_numbers),
            "details": dict(self.details),
        }


@dataclass(frozen=True, slots=True)
class ExportDecision:
    """Successful result of :meth:`ExportGuard.check`."""

    document: DocumentIdentity
    purpose: str
    authorization: ExportAuthorization
    requested_pages: tuple[int, ...]
    authorized_pages: tuple[int, ...]
    unexported_authorized_pages: tuple[int, ...]
    unselected_document_pages: tuple[int, ...]
    partial: bool

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            "document": self.document.as_dict(),
            "purpose": self.purpose,
            "authorization_id": self.authorization.authorization_id,
            "requested_pages": list(self.requested_pages),
            "authorized_pages": list(self.authorized_pages),
            "unexported_authorized_pages": list(self.unexported_authorized_pages),
            "unselected_document_pages": list(self.unselected_document_pages),
            "partial": self.partial,
        }


@dataclass(frozen=True, slots=True)
class ExportedPageRecord:
    """Provenance of one page written through a guarded export."""

    output_page_index: int
    document_id: str
    document_name: str | None
    source_page_index: int
    authorization_id: str
    purpose: str

    @property
    def output_page_number(self) -> int:
        """The output page as a one-based page number."""
        return self.output_page_index + 1

    @property
    def source_page_number(self) -> int:
        """The source page as a one-based page number."""
        return self.source_page_index + 1

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            "output_page_index": self.output_page_index,
            "output_page_number": self.output_page_number,
            "document_id": self.document_id,
            "document_name": self.document_name,
            "source_page_index": self.source_page_index,
            "source_page_number": self.source_page_number,
            "authorization_id": self.authorization_id,
            "purpose": self.purpose,
        }


class ExportGuardError(PyPdfError):
    """Raised when an export has no valid authorization.

    The exception always names the first page that could not be justified.
    ``page_index`` is zero-based (matching pypdf page indices), while
    ``page_number`` is the one-based number suitable for humans.
    """

    def __init__(
        self,
        message: str,
        *,
        reason: ExportBlockReason,
        document_id: str | None = None,
        document_name: str | None = None,
        authorization_id: str | None = None,
        purpose: str | None = None,
        page_index: int | None = None,
        unauthorized_pages: Iterable[int] = (),
        audit_record: ExportAuditRecord | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.document_id = document_id
        self.document_name = document_name
        self.authorization_id = authorization_id
        self.purpose = purpose
        self.page_index = page_index
        self.page_number = page_index + 1 if page_index is not None else None
        self.unauthorized_pages = tuple(unauthorized_pages)
        self.unauthorized_page_numbers = pages_to_numbers(self.unauthorized_pages)
        self.audit_record = audit_record


class ExportGuard:
    """Register authorizations and check application-level exports.

    Args:
        authorizations: Initial authorizations to register.
        audit_hook: Optional callback invoked for every audit record as it is
            created.  Use it to stream records to an external audit store.

    """

    def __init__(
        self,
        authorizations: Iterable[ExportAuthorization] = (),
        *,
        audit_hook: Callable[[ExportAuditRecord], None] | None = None,
    ) -> None:
        self._authorizations: dict[str, ExportAuthorization] = {}
        self._audit_log: list[ExportAuditRecord] = []
        self._audit_hook = audit_hook
        for authorization in authorizations:
            self.register(authorization)

    def register(self, authorization: ExportAuthorization) -> ExportAuthorization:
        """Register (or replace) an authorization and return it."""
        self._authorizations[authorization.authorization_id] = authorization
        return authorization

    def unregister(self, authorization_id: str) -> None:
        """Remove an authorization from the registry."""
        self._authorizations.pop(authorization_id, None)

    def revoke(self, authorization_id: str, at: datetime | None = None) -> None:
        """Revoke a registered authorization."""
        self._authorizations[authorization_id].revoke(at)

    def authorizations_for(
        self, source: Any, purpose: str | None = None
    ) -> tuple[ExportAuthorization, ...]:
        """Return registered authorizations for ``source``'s content.

        This is useful for a review program that has to display which grant
        corresponds to the pages about to be submitted.
        """
        identity = DocumentIdentity.from_pdf(source)
        return tuple(
            authorization
            for authorization in self._authorizations.values()
            if authorization.document.fingerprint == identity.fingerprint
            and (purpose is None or authorization.purpose == purpose)
        )

    @property
    def audit_log(self) -> tuple[ExportAuditRecord, ...]:
        """All audit records produced so far, in order."""
        return tuple(self._audit_log)

    def clear_audit_log(self) -> None:
        """Drop all in-memory audit records."""
        self._audit_log.clear()

    def check(
        self,
        source: Any,
        purpose: str | None,
        pages: Any = None,
        *,
        authorization: ExportAuthorization | None = None,
        now: datetime | None = None,
    ) -> ExportDecision:
        """Verify that ``source``'s selected pages may be exported.

        Args:
            source: The document pages are copied from.
            purpose: The already verified purpose supplied by the caller.
            pages: The selected zero-based page indices.  ``None`` means all
                pages.
            authorization: Bind the export to one specific authorization.  If
                omitted, the guard selects a registered grant for the actual
                document content and purpose.
            now: Clock override for deterministic authorization expiry tests.

        Returns:
            The successful decision, including the authorization actually used.

        Raises:
            ExportGuardError: If the purpose, document, authorization or page
                selection cannot be justified.

        """
        current = _as_utc(now or datetime.now(timezone.utc))
        if purpose is None and authorization is not None:
            purpose = authorization.purpose
        try:
            identity = DocumentIdentity.from_pdf(source)
        except ExportGuardError as error:
            if error.audit_record is not None:
                self._emit(error.audit_record)
            raise
        requested = _normalize_pages(pages, identity.page_count)

        if not isinstance(purpose, str) or not purpose:
            self._block(
                ExportBlockReason.MISSING_PURPOSE,
                "An export purpose is required. Pass purpose=... to the writer call.",
                identity=identity,
                purpose=purpose,
                pages=requested,
                now=current,
            )

        chosen = authorization
        if chosen is not None:
            if chosen.document.fingerprint != identity.fingerprint:
                self._block(
                    ExportBlockReason.DOCUMENT_MISMATCH,
                    _document_mismatch_message(chosen.document, identity, requested),
                    identity=identity,
                    purpose=purpose,
                    authorization=chosen,
                    pages=requested,
                    unauthorized_pages=requested,
                    now=current,
                    extra={
                        "authorization_document": chosen.document.as_dict(),
                        "source_document": identity.as_dict(),
                        "same_name_different_content": _same_name(
                            chosen.document, identity
                        ),
                    },
                )
            if chosen.purpose != purpose:
                self._block(
                    ExportBlockReason.PURPOSE_MISMATCH,
                    f"Authorization {chosen.authorization_id} is for purpose "
                    f"{chosen.purpose!r}, not {purpose!r}; source page "
                    f"{_first_page_label(requested)} has no matching authorization.",
                    identity=identity,
                    purpose=purpose,
                    authorization=chosen,
                    pages=requested,
                    unauthorized_pages=requested,
                    now=current,
                )
        else:
            chosen = self._select(identity, purpose, requested, current)
            if chosen is None:
                candidates = [
                    item
                    for item in self._authorizations.values()
                    if item.document.fingerprint == identity.fingerprint
                ]
                if not candidates:
                    self._block(
                        ExportBlockReason.DOCUMENT_NOT_AUTHORIZED,
                        f"No export authorization is registered for document "
                        f"{identity.display_name} ({identity.short}); source page "
                        f"{_first_page_label(requested)} has no basis.",
                        identity=identity,
                        purpose=purpose,
                        pages=requested,
                        unauthorized_pages=requested,
                        now=current,
                    )
                self._block(
                    ExportBlockReason.PURPOSE_MISMATCH,
                    f"No authorization for document {identity.display_name} "
                    f"({identity.short}) covers purpose {purpose!r}; source page "
                    f"{_first_page_label(requested)} has no basis.",
                    identity=identity,
                    purpose=purpose,
                    pages=requested,
                    unauthorized_pages=requested,
                    now=current,
                    extra={
                        "available_purposes": sorted(
                            {item.purpose for item in candidates}
                        )
                    },
                )

        assert chosen is not None  # narrowed by the branches above
        if chosen.revoked_at is not None and _as_utc(chosen.revoked_at) <= current:
            self._block(
                ExportBlockReason.AUTHORIZATION_REVOKED,
                f"Authorization {chosen.authorization_id} was revoked at "
                f"{_as_utc(chosen.revoked_at).isoformat()}; source page "
                f"{_first_page_label(requested)} has no basis.",
                identity=identity,
                purpose=purpose,
                authorization=chosen,
                pages=requested,
                unauthorized_pages=requested,
                now=current,
            )
        if chosen.expires_at is not None and _as_utc(chosen.expires_at) <= current:
            self._block(
                ExportBlockReason.AUTHORIZATION_EXPIRED,
                f"Authorization {chosen.authorization_id} expired at "
                f"{_as_utc(chosen.expires_at).isoformat()}; source page "
                f"{_first_page_label(requested)} has no basis.",
                identity=identity,
                purpose=purpose,
                authorization=chosen,
                pages=requested,
                unauthorized_pages=requested,
                now=current,
            )

        unauthorized = tuple(page for page in requested if page not in chosen.pages)
        if unauthorized:
            self._block(
                ExportBlockReason.PAGE_NOT_AUTHORIZED,
                f"Authorization {chosen.authorization_id} does not cover source "
                f"page {_first_page_label(unauthorized)} of document "
                f"{identity.display_name} ({identity.short}); unauthorized pages: "
                f"{_page_label_list(unauthorized)}.",
                identity=identity,
                purpose=purpose,
                authorization=chosen,
                pages=requested,
                unauthorized_pages=unauthorized,
                now=current,
            )

        requested_set = set(requested)
        authorized_pages = tuple(sorted(chosen.pages))
        unexported = tuple(sorted(chosen.pages - requested_set))
        unselected = tuple(sorted(set(range(identity.page_count)) - requested_set))
        partial = bool(unselected)
        self._emit(
            ExportAuditRecord(
                event=ExportAuditEvent.EXPORT_AUTHORIZED,
                occurred_at=current,
                purpose=purpose,
                document_id=identity.fingerprint,
                document_name=identity.name,
                authorization_id=chosen.authorization_id,
                page_indices=tuple(requested),
                details={
                    "document_page_count": identity.page_count,
                    "authorized_pages": list(authorized_pages),
                    "subject": chosen.subject,
                },
            )
        )
        if partial:
            self._emit(
                ExportAuditRecord(
                    event=ExportAuditEvent.PARTIAL_SELECTION,
                    occurred_at=current,
                    purpose=purpose,
                    document_id=identity.fingerprint,
                    document_name=identity.name,
                    authorization_id=chosen.authorization_id,
                    page_indices=tuple(requested),
                    details={
                        "document_page_count": identity.page_count,
                        "unselected_document_pages": list(unselected),
                        "unexported_authorized_pages": list(unexported),
                    },
                )
            )
        return ExportDecision(
            document=identity,
            purpose=purpose,
            authorization=chosen,
            requested_pages=tuple(requested),
            authorized_pages=authorized_pages,
            unexported_authorized_pages=unexported,
            unselected_document_pages=unselected,
            partial=partial,
        )

    def _select(
        self,
        identity: DocumentIdentity,
        purpose: str,
        requested: tuple[int, ...],
        now: datetime,
    ) -> ExportAuthorization | None:
        candidates = [
            authorization
            for authorization in self._authorizations.values()
            if authorization.document.fingerprint == identity.fingerprint
            and authorization.purpose == purpose
        ]
        if not candidates:
            return None
        requested_set = set(requested)

        def score(authorization: ExportAuthorization) -> tuple[int, int, int, int, str]:
            return (
                int(authorization.is_valid(now)),
                int(requested_set <= authorization.pages),
                len(requested_set & authorization.pages),
                len(authorization.pages),
                authorization.authorization_id,
            )

        return max(candidates, key=score)

    def _emit(self, record: ExportAuditRecord) -> None:
        self._audit_log.append(record)
        if self._audit_hook is not None:
            self._audit_hook(record)

    def _block(
        self,
        reason: ExportBlockReason,
        message: str,
        *,
        identity: DocumentIdentity,
        purpose: str | None,
        pages: tuple[int, ...],
        now: datetime,
        authorization: ExportAuthorization | None = None,
        unauthorized_pages: tuple[int, ...] = (),
        extra: Mapping[str, Any] | None = None,
    ) -> NoReturn:
        details: dict[str, Any] = {
            "document_page_count": identity.page_count,
            "unauthorized_pages": list(unauthorized_pages),
            "unauthorized_page_numbers": list(pages_to_numbers(unauthorized_pages)),
        }
        if extra:
            details.update(extra)
        record = ExportAuditRecord(
            event=ExportAuditEvent.EXPORT_BLOCKED,
            occurred_at=now,
            reason=reason,
            purpose=purpose,
            document_id=identity.fingerprint,
            document_name=identity.name,
            authorization_id=(
                authorization.authorization_id if authorization is not None else None
            ),
            page_indices=pages,
            details=details,
        )
        self._emit(record)
        raise ExportGuardError(
            message,
            reason=reason,
            document_id=identity.fingerprint,
            document_name=identity.name,
            authorization_id=(
                authorization.authorization_id if authorization is not None else None
            ),
            purpose=purpose,
            page_index=unauthorized_pages[0] if unauthorized_pages else (
                pages[0] if pages else None
            ),
            unauthorized_pages=unauthorized_pages,
            audit_record=record,
        )


def pages_to_numbers(pages: Iterable[int]) -> tuple[int, ...]:
    """Convert zero-based page indices to one-based page numbers."""
    return tuple(page + 1 for page in pages)


def _normalize_pages(pages: Any, page_count: int) -> tuple[int, ...]:
    if pages is None:
        return tuple(range(page_count))
    if isinstance(pages, (PageRange, slice)):
        raw = list(range(*pages.indices(page_count)))
    elif isinstance(pages, int) and not isinstance(pages, bool):
        raw = [pages]
    elif isinstance(pages, tuple):
        raw = list(range(*pages))
    else:
        raw = list(pages)
    normalized: list[int] = []
    for page in raw:
        if not isinstance(page, int) or isinstance(page, bool):
            raise TypeError(f"page indices must be integers, got {type(page).__name__}")
        index = page + page_count if page < 0 else page
        if index < 0 or index >= page_count:
            raise IndexError(
                f"page index {page} is outside document range of {page_count} pages"
            )
        normalized.append(index)
    return tuple(normalized)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _ensure_decrypted(source: Any) -> None:
    encryption = getattr(source, "_encryption", None)
    if encryption is not None and not encryption.is_decrypted():
        record = ExportAuditRecord(
            event=ExportAuditEvent.EXPORT_BLOCKED,
            occurred_at=datetime.now(timezone.utc),
            reason=ExportBlockReason.NOT_DECRYPTED,
            document_name=_source_label(source),
            details={"message": "document must be decrypted before it can be identified"},
        )
        raise ExportGuardError(
            "Cannot establish the document identity: the PDF is still encrypted. "
            "Pass the verified password to PdfReader first.",
            reason=ExportBlockReason.NOT_DECRYPTED,
            document_name=_source_label(source),
            audit_record=record,
        )


def _basename(value: str) -> str:
    return Path(value).name


def _source_label(source: Any) -> str | None:
    stream = getattr(source, "stream", None)
    name = getattr(stream, "name", None)
    if isinstance(name, str) and name and not name.startswith("<"):
        return Path(name).name
    try:
        metadata = source.metadata
        title = getattr(metadata, "title", None)
        if isinstance(title, str) and title:
            return title
    except Exception:
        return None
    return None


def _page_identity_digest(page: PageObject) -> bytes:
    digest = hashlib.sha256()
    try:
        contents = page._get_contents_as_bytes()
    except Exception:
        contents = None
    if contents is None:
        digest.update(b"<no-contents>")
    else:
        digest.update(len(contents).to_bytes(8, "big"))
        digest.update(contents)
    for key in _PAGE_KEYS_FOR_IDENTITY:
        if key in page:
            digest.update(key.encode())
            _update_object_digest(digest, page[key])
    return digest.digest()


def _update_object_digest(
    digest: Any, obj: Any, active: frozenset[tuple[int, int, int]] = frozenset()
) -> None:
    if isinstance(obj, IndirectObject):
        key = (id(obj.pdf), obj.idnum, obj.generation)
        if key in active:
            digest.update(b"<cycle>")
            return
        try:
            resolved = obj.get_object()
        except Exception:
            digest.update(b"<unresolved>")
            return
        _update_object_digest(digest, resolved, active | {key})
        return
    if isinstance(obj, StreamObject):
        digest.update(b"stream(")
        stream_dictionary = {
            key: value
            for key, value in obj.items()
            if str(key) not in ("/Length", "/Filter", "/DecodeParms")
        }
        _update_object_digest(digest, stream_dictionary, active)
        digest.update(b"|")
        try:
            data = obj.get_data()
        except Exception:
            data = b""
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
        digest.update(b")")
        return
    if isinstance(obj, Mapping):
        digest.update(b"{")
        for key in sorted(obj.keys(), key=str):
            if str(key) == "/Parent":
                continue
            digest.update(str(key).encode("utf-8", "backslashreplace"))
            digest.update(b"=")
            _update_object_digest(digest, obj[key], active)
            digest.update(b";")
        digest.update(b"}")
        return
    if isinstance(obj, (list, tuple)):
        digest.update(b"[")
        for item in obj:
            _update_object_digest(digest, item, active)
            digest.update(b";")
        digest.update(b"]")
        return
    digest.update(type(obj).__name__.encode())
    digest.update(b":")
    digest.update(str(obj).encode("utf-8", "backslashreplace"))


def _same_name(first: DocumentIdentity, second: DocumentIdentity) -> bool:
    return bool(
        first.name
        and second.name
        and _basename(first.name) == _basename(second.name)
    )


def _document_mismatch_message(
    authorized: DocumentIdentity,
    actual: DocumentIdentity,
    pages: tuple[int, ...],
) -> str:
    suffix = (
        " The names match but the document content does not."
        if _same_name(authorized, actual)
        else ""
    )
    return (
        f"Authorization was issued for document {authorized.display_name} "
        f"({authorized.short}) but the pages come from {actual.display_name} "
        f"({actual.short}); source page {_first_page_label(pages)} has no "
        f"matching authorization.{suffix}"
    )


def _first_page_label(pages: tuple[int, ...]) -> str:
    if not pages:
        return "<unknown>"
    return f"{pages[0] + 1} (index {pages[0]})"


def _page_label_list(pages: tuple[int, ...]) -> str:
    return ", ".join(f"{page + 1} (index {page})" for page in pages)


__all__ = [
    "DocumentIdentity",
    "ExportAuditEvent",
    "ExportAuditRecord",
    "ExportAuthorization",
    "ExportBlockReason",
    "ExportDecision",
    "ExportGuard",
    "ExportGuardError",
    "ExportedPageRecord",
    "pages_to_numbers",
]
