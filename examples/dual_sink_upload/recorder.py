"""Streaming dual-sink recorder built on python-multipart callbacks.

The recorder wires the existing ``MultipartParser`` notification/data callbacks
to a small per-part state machine. Raw part bytes are only fed to streaming
hash objects; they are never buffered wholesale and never passed to a sink.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from python_multipart.exceptions import MultipartParseError
from python_multipart.multipart import MultipartParser, parse_options_header

from .records import (
    ConfirmedMetadata,
    PartStatus,
    PublicReference,
    RejectionInfo,
    RejectReason,
    RequestStatus,
    RequestSummary,
    new_part_ref,
    new_request_ref,
    redact_label,
)
from .sinks import BusinessReceiptSink, CustomerServiceLogSink

if TYPE_CHECKING:
    from python_multipart.multipart import MultipartCallbacks

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RecorderConfig:
    """Configuration for :class:`UploadRecorder`.

    Both sinks are optional, so either output can be switched off independently
    ("optional dual outlet"). Parsing always runs, and limits are enforced
    regardless of which sinks are attached.
    """

    max_body_size: int | float = float("inf")
    max_part_size: int | float = float("inf")
    max_header_count: int = 10
    max_header_size: int = 4096
    # When non-empty, a part must declare one of these content types. Parts
    # with no usable content type are rejected as "unknown content type".
    allowed_content_types: frozenset[str] = frozenset()


@dataclass(slots=True)
class AuditCallback:
    """Pluggable moderation/audit hook invoked once per completed part.

    Implementations return ``False`` (optionally with a reason) for a policy
    rejection and ``True`` to accept. An unexpected exception is captured as an
    audit infrastructure failure rather than crashing the whole request.
    """

    check: Callable[[ConfirmedMetadata], bool]
    reason: str = "audit_rejected"

    def __call__(self, metadata: ConfirmedMetadata) -> bool:
        return self.check(metadata)


@dataclass(slots=True)
class _PartState:
    """Mutable state for the part currently being streamed."""

    part_ref: str
    header_name_parts: list[bytes] = field(default_factory=list)
    header_value_parts: list[bytes] = field(default_factory=list)
    headers: dict[bytes, bytes] = field(default_factory=dict)
    plain_hasher: Any = field(default_factory=lambda: hashlib.sha256())
    salted_hasher: Any = None
    bytes_received: int = 0
    chunk_count: int = 0
    oversized: bool = False


class UploadRecorder:
    """Drive a :class:`MultipartParser` and fan classified records out.

    The two sinks are independent trust domains:

    * :attr:`business_sink` receives :class:`ConfirmedMetadata` (including field
      names and redacted filenames) plus minimum rejection records, enabling
      reconciliation back to the original request;
    * :attr:`support_sink` receives only :class:`PublicReference` and
      :class:`RejectionInfo` - opaque references, statuses and reason codes.

    Use :meth:`ingest` to stream arbitrary chunks (fields may be split across
    any number of them) and :meth:`finish` to flush the final request summary.
    """

    def __init__(
        self,
        boundary: bytes | str,
        *,
        config: RecorderConfig | None = None,
        business_sink: BusinessReceiptSink | None = None,
        support_sink: CustomerServiceLogSink | None = None,
        audit: AuditCallback | None = None,
        request_ref: str | None = None,
    ) -> None:
        self.config = config or RecorderConfig()
        self.business_sink = business_sink
        self.support_sink = support_sink
        self.audit = audit
        self.request_ref = request_ref or new_request_ref()
        # Per-request salt makes content fingerprints non-linkable across
        # requests; only the business receipt and this process hold the salt.
        self._salt = secrets.token_bytes(16)
        self._current: _PartState | None = None
        self._total_parts = 0
        self._accepted = 0
        self._rejected = 0
        self._total_bytes = 0
        self._rejections: list[RejectionInfo] = []
        self._finished_emitted = False

        callbacks: MultipartCallbacks = {
            "on_part_begin": self._on_part_begin,
            "on_header_field": self._on_header_field,
            "on_header_value": self._on_header_value,
            "on_header_end": self._on_header_end,
            "on_part_data": self._on_part_data,
            "on_part_end": self._on_part_end,
            "on_end": self._on_body_end,
        }
        self._parser = MultipartParser(
            boundary,
            callbacks=callbacks,
            max_size=self.config.max_body_size,
            max_header_count=self.config.max_header_count,
            max_header_size=self.config.max_header_size,
        )

    @property
    def total_parts(self) -> int:
        return self._total_parts

    @property
    def accepted_parts(self) -> int:
        return self._accepted

    @property
    def rejected_parts(self) -> int:
        return self._rejected

    def ingest(self, chunk: bytes) -> int:
        """Feed one transport chunk; returns the number of bytes consumed.

        Malformed bodies raise :class:`MultipartParseError`, which is also
        recorded as a request-level failure before propagating so both sinks
        keep a trace without any half-parsed content.
        """
        try:
            return self._parser.write(chunk)
        except MultipartParseError:
            self._record_request_failure(RejectReason.MALFORMED_BODY, "malformed multipart body")
            raise

    def finish(self) -> RequestSummary:
        """Finalise parsing and emit the per-request summary exactly once."""
        self._parser.finalize()
        if not self._finished_emitted:
            self._emit_summary()
        return self._build_summary()

    def _on_part_begin(self) -> None:
        self._current = _PartState(part_ref=new_part_ref(), salted_hasher=hmac.new(self._salt, b"", hashlib.sha256))
        self._total_parts += 1

    def _on_header_field(self, data: bytes, start: int, end: int) -> None:
        assert self._current is not None
        self._current.header_name_parts.append(data[start:end])

    def _on_header_value(self, data: bytes, start: int, end: int) -> None:
        assert self._current is not None
        self._current.header_value_parts.append(data[start:end])

    def _on_header_end(self) -> None:
        assert self._current is not None
        name = b"".join(self._current.header_name_parts).strip().lower()
        value = b"".join(self._current.header_value_parts).strip()
        if name:
            self._current.headers[name] = value
        self._current.header_name_parts.clear()
        self._current.header_value_parts.clear()

    def _on_part_data(self, data: bytes, start: int, end: int) -> None:
        assert self._current is not None
        chunk = data[start:end]
        state = self._current
        state.bytes_received += len(chunk)
        state.chunk_count += 1
        self._total_bytes += len(chunk)
        if state.bytes_received > self.config.max_part_size:
            state.oversized = True
        if not state.oversized:
            state.plain_hasher.update(chunk)
            assert state.salted_hasher is not None
            state.salted_hasher.update(chunk)

    def _on_body_end(self) -> None:
        return None

    def _on_part_end(self) -> None:
        assert self._current is not None
        state = self._current
        disposition_name, filename = self._parse_disposition(state.headers)
        content_type = self._parse_content_type(state.headers)
        if not disposition_name:
            self._reject_part(state, RejectReason.EMPTY_NAME, "part has no form field name")
            self._current = None
            return
        if state.oversized:
            self._reject_part(state, RejectReason.TOO_LARGE, "part exceeded the configured size limit")
            self._current = None
            return
        if not self._content_type_allowed(content_type):
            self._reject_part(state, RejectReason.UNKNOWN_CONTENT_TYPE, "part content type is missing or not allowed")
            self._current = None
            return

        metadata = self._build_metadata(state, disposition_name, content_type, filename)
        if self.audit is not None:
            try:
                allowed = self.audit(metadata)
            except Exception as exc:
                logger.warning("audit callback failed for part %s: %s", state.part_ref, exc)
                self._reject_part(state, RejectReason.AUDIT_CALLBACK_FAILED, "audit callback raised an exception")
                self._current = None
                return
            if not allowed:
                self._reject_part(state, RejectReason.AUDIT_CALLBACK_FAILED, self.audit.reason)
                self._current = None
                return

        self._accept_part(metadata)
        self._current = None

    # -- classification helpers -----------------------------------------

    def _parse_disposition(self, headers: dict[bytes, bytes]) -> tuple[str | None, bytes | None]:
        raw = headers.get(b"content-disposition")
        if raw is None:
            return None, None
        _, options = parse_options_header(raw)
        name = options.get(b"name")
        filename = options.get(b"filename")
        if name is None or not name:
            return None, filename
        return name.decode("utf-8", errors="replace"), filename

    def _parse_content_type(self, headers: dict[bytes, bytes]) -> str | None:
        raw = headers.get(b"content-type")
        if raw is None:
            return None
        ctype, _ = parse_options_header(raw)
        if not ctype:
            return None
        return ctype.decode("ascii", errors="replace")

    def _content_type_allowed(self, content_type: str | None) -> bool:
        if not self.config.allowed_content_types:
            return True
        return content_type in self.config.allowed_content_types

    def _build_metadata(
        self, state: _PartState, field_name: str, content_type: str | None, filename: bytes | None
    ) -> ConfirmedMetadata:
        assert state.salted_hasher is not None
        return ConfirmedMetadata(
            request_ref=self.request_ref,
            part_ref=state.part_ref,
            field_name=field_name,
            is_file=filename is not None,
            content_type=content_type,
            bytes_received=state.bytes_received,
            chunk_count=state.chunk_count,
            content_hash="sha256:" + state.plain_hasher.hexdigest(),
            fingerprint="sha256:" + state.salted_hasher.hexdigest(),
            redacted_filename=redact_label(filename),
        )

    def _accept_part(self, metadata: ConfirmedMetadata) -> None:
        self._accepted += 1
        if self.business_sink is not None:
            self.business_sink.accept(metadata)
        if self.support_sink is not None:
            self.support_sink.reference(metadata.to_public_reference())

    def _reject_part(self, state: _PartState, reason: RejectReason, detail: str) -> None:
        self._rejected += 1
        fingerprint = None if state.oversized else "sha256:" + state.salted_hasher.hexdigest()
        info = RejectionInfo(
            part_ref=state.part_ref,
            status=PartStatus.REJECTED,
            reason=reason,
            bytes_received=state.bytes_received,
            detail=detail,
        )
        self._rejections.append(info)
        if self.business_sink is not None:
            self.business_sink.reject(info)
        if self.support_sink is not None:
            disposition = state.headers.get(b"content-disposition", b"")
            reference = PublicReference(
                request_ref=self.request_ref,
                part_ref=state.part_ref,
                status=PartStatus.REJECTED,
                bytes_received=state.bytes_received,
                fingerprint=fingerprint,
                reason=reason,
                is_file=b"filename" in disposition,
            )
            self.support_sink.reference(reference)
            self.support_sink.reject(info)

    def _record_request_failure(self, reason: RejectReason, detail: str) -> None:
        part_ref = self._current.part_ref if self._current is not None else new_part_ref()
        info = RejectionInfo(
            part_ref=part_ref,
            status=PartStatus.FAILED,
            reason=reason,
            bytes_received=self._current.bytes_received if self._current is not None else 0,
            detail=detail,
        )
        self._rejections.append(info)
        if self.business_sink is not None:
            self.business_sink.reject(info)
        if self.support_sink is not None:
            self.support_sink.reject(info)

    def _build_summary(self) -> RequestSummary:
        if self._rejections:
            status = RequestStatus.REJECTED if self._accepted else RequestStatus.FAILED
        else:
            status = RequestStatus.COMPLETED
        return RequestSummary(
            request_ref=self.request_ref,
            status=status,
            total_parts=self._total_parts,
            accepted_parts=self._accepted,
            rejected_parts=self._rejected,
            total_bytes=self._total_bytes,
            rejections=tuple(self._rejections),
        )

    def _emit_summary(self) -> None:
        summary = self._build_summary()
        if self.business_sink is not None:
            self.business_sink.finish(summary)
        if self.support_sink is not None:
            self.support_sink.finish(summary)
        self._finished_emitted = True
