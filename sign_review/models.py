"""Data models for the post-signature review pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ChangeType(str, Enum):
    """Every kind of post-signature change the reviewer can classify."""

    FIELD_VALUE = "field_value"
    FIELD_APPEARANCE = "field_appearance"
    FIELD_ADDED = "field_added"
    FIELD_REMOVED = "field_removed"
    PAGE_CONTENT = "page_content"
    PAGE_GEOMETRY = "page_geometry"
    PAGE_COUNT = "page_count"
    SHARED_RESOURCE = "shared_resource"
    INHERITED_ATTR = "inherited_attr"
    TRUNCATED_REVISION = "truncated_revision"


class ReviewDecision(str, Enum):
    """Routing decision for the whole reviewed document."""

    CONTINUE = "clear_to_proceed"
    MANUAL = "manual_review"


@dataclass(frozen=True)
class ReviewPolicy:
    """Explicit permissions supplied by the calling legal workflow."""

    allowed_field_fills: frozenset[str] = frozenset()
    allowed_field_appearance: frozenset[str] = frozenset()
    allow_page_changes: bool = False
    allow_shared_resource_changes: bool = False
    allow_inherited_attr_changes: bool = False


@dataclass
class SignatureInfo:
    field_name: str
    field_ref: str | None
    value_ref: str | None
    byte_range: list[int]
    covered_end: int | None
    signed_revision: int | None
    valid: bool | None = None
    verifier: str | None = None
    detail: dict[str, Any] | None = None


@dataclass
class FieldSnapshot:
    object_key: str
    index: int
    full_name: str
    field_type: str | None
    value: Any
    default_value: Any
    appearance_stream_hash: dict[str, Any] | None
    widget_annotation_hash: dict[str, Any]
    page_index: int | None
    is_signature: bool
    signature_value: dict[str, Any] | None
    flags: int | None


@dataclass
class PageSnapshot:
    object_key: str
    index: int
    media_box: Any
    rotation: int
    contents: list[dict[str, Any]]
    resources_ref: str
    resources: Any
    inherited: dict[str, dict[str, Any]]
    inherited_from: str | None
    annotations: list[Any]


@dataclass
class Snapshot:
    pages: list[PageSnapshot]
    fields: dict[str, FieldSnapshot]
    resource_impact: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


@dataclass
class Finding:
    change_type: ChangeType
    severity: str
    target: str
    object_ref: str | None
    detail: Any
    explanation: str
    from_revision: int | None = None
    to_revision: int | None = None
    policy_basis: str | None = None


@dataclass
class ReviewRecord:
    source: str
    total_bytes: int
    revision_count: int
    signed_revision_index: int | None
    signatures: list[SignatureInfo]
    findings: list[Finding]
    decision: str
    truncated: bool
    revision_offsets: list[int]
    deciding_findings: list[dict[str, Any]] = field(default_factory=list)
    routing_reason: str = ""


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    verifier: str
    detail: dict[str, Any] = field(default_factory=dict)
