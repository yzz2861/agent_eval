"""
Offline acceptance contract for a gateway that is about to upgrade ``hpack``.

The security-audit layer depends on three properties of the header field list:

1. the order in which fields arrived;
2. every duplicate field instance; and
3. the HPACK "never indexed" (sensitive) attribute.

This module runs those properties through the real encoder, the real decoder,
and an in-memory application-adapter double.  It is deliberately independent of
the large fixture story suites, so it can be run on its own::

    pytest tests/test_hpack_gateway_contract.py

All fixtures use inert placeholder values.  "Sensitive" below means the
``NeverIndexedHeaderTuple`` metadata, not that the value contains a secret.
"""

from __future__ import annotations

from collections import Counter, OrderedDict
from collections.abc import Sequence
from dataclasses import dataclass, replace
from enum import Enum
from typing import Protocol

import pytest

from hpack import Decoder, Encoder, HeaderTuple, NeverIndexedHeaderTuple


Header = HeaderTuple | NeverIndexedHeaderTuple


class Step(str, Enum):
    """The pipeline boundary at which audit evidence disappeared."""

    ENCODER = "encoder"
    DECODER = "decoder"
    ADAPTER = "adapter"


class Verdict(str, Enum):
    """The result of checking the security-audit contract."""

    PRESERVED = "audit-preserved"
    DISPLAY_MERGED = "display-merged"
    LOST = "audit-lost"

    @property
    def accepted(self) -> bool:
        return self is not Verdict.LOST


@dataclass(frozen=True)
class Field:
    """A single header field instance as it exists at one pipeline stage."""

    ordinal: int
    name: bytes
    value: bytes
    sensitive: bool


@dataclass(frozen=True)
class Loss:
    """One concrete piece of audit evidence missing from a later stage."""

    step: Step
    kind: str
    field: Field
    instance: str
    detail: str


@dataclass(frozen=True)
class AdaptedHeaders:
    """What the application adapter exposes after receiving decoded fields."""

    display: tuple[tuple[bytes, bytes], ...]
    audit: tuple[Field, ...] | None
    merged_for_display: bool


@dataclass(frozen=True)
class PipelineResult:
    """Snapshots taken at each boundary in encoder -> decoder -> adapter."""

    source: tuple[Field, ...]
    encoded: bytes
    encoded_fields: tuple[Field, ...]
    decoded: tuple[Field, ...]
    adapted: AdaptedHeaders


@dataclass(frozen=True)
class ContractReport:
    """The contract verdict plus field-level, stage-level diagnostics."""

    verdict: Verdict
    findings: tuple[Loss, ...]
    adapted: AdaptedHeaders
    source: tuple[Field, ...]
    encoded_fields: tuple[Field, ...]
    decoded: tuple[Field, ...]

    @property
    def accepted(self) -> bool:
        return self.verdict.accepted

    def render(self) -> str:
        audit_size = "none" if self.adapted.audit is None else str(len(self.adapted.audit))
        lines = [
            f"transaction: verdict={self.verdict.value} "
            f"({'accepted' if self.verdict.accepted else 'rejected'})",
            f"display: merge={self.adapted.merged_for_display} "
            f"source={len(self.source)} encoded={len(self.encoded_fields)} "
            f"decoded={len(self.decoded)} audit={audit_size}",
        ]
        if self.findings:
            lines.append("findings:")
            lines.extend(
                f"  - step={loss.step.value} kind={loss.kind} "
                f"{loss.instance}; {loss.detail}"
                for loss in self.findings
            )
        else:
            lines.append("findings: none")
        return "\n".join(lines)


class HeaderAdapter(Protocol):
    """In-memory application-adapter boundary used by the contract tests."""

    def adapt(self, headers: Sequence[HeaderTuple]) -> AdaptedHeaders:
        """Turn decoded HPACK fields into the application's header views."""


class PassThroughAdapter:
    """Adapter double that keeps an exact audit copy of every decoded field."""

    def adapt(self, headers: Sequence[HeaderTuple]) -> AdaptedHeaders:
        fields = _adapted_fields(headers)
        return AdaptedHeaders(
            display=tuple((field.name, field.value) for field in fields),
            audit=fields,
            merged_for_display=False,
        )


class DisplayMergeAdapter:
    """Combine repeated names for display while retaining a per-instance audit."""

    def adapt(self, headers: Sequence[HeaderTuple]) -> AdaptedHeaders:
        fields = _adapted_fields(headers)
        by_name: OrderedDict[bytes, list[bytes]] = OrderedDict()
        for field in fields:
            by_name.setdefault(field.name, []).append(field.value)
        display = tuple((name, b", ".join(values)) for name, values in by_name.items())
        return AdaptedHeaders(
            display=display,
            audit=fields,
            merged_for_display=True,
        )


class DuplicateCollapsingAdapter:
    """Adapter double that keeps only the first instance of each field name."""

    def adapt(self, headers: Sequence[HeaderTuple]) -> AdaptedHeaders:
        fields = _adapted_fields(headers)
        first_by_name: dict[bytes, Field] = {}
        for field in fields:
            first_by_name.setdefault(field.name, field)
        audit = tuple(first_by_name.values())
        return AdaptedHeaders(
            display=tuple((field.name, field.value) for field in audit),
            audit=audit,
            merged_for_display=False,
        )


class SensitivityStrippingAdapter:
    """Adapter double that copies fields but silently clears the sensitive bit."""

    def adapt(self, headers: Sequence[HeaderTuple]) -> AdaptedHeaders:
        fields = _adapted_fields(headers)
        audit = tuple(replace(field, sensitive=False) for field in fields)
        return AdaptedHeaders(
            display=tuple((field.name, field.value) for field in fields),
            audit=audit,
            merged_for_display=False,
        )


class AuditReorderingAdapter:
    """Adapter double that keeps the fields but sorts the audit copy."""

    def adapt(self, headers: Sequence[HeaderTuple]) -> AdaptedHeaders:
        fields = _adapted_fields(headers)
        audit = tuple(sorted(fields, key=lambda field: (field.name, field.value, field.ordinal)))
        return AdaptedHeaders(
            display=tuple((field.name, field.value) for field in fields),
            audit=audit,
            merged_for_display=False,
        )


class _RecordingEncoder(Encoder):
    """Encoder that records how each field was represented on the wire."""

    def __init__(self) -> None:
        super().__init__()
        self.encoded_fields: list[Field] = []

    def add(self, to_add: tuple[bytes, bytes], sensitive: bool, huffman: bool = False) -> bytes:
        chunk = super().add(to_add, sensitive, huffman)
        self.encoded_fields.append(
            Field(
                ordinal=len(self.encoded_fields) + 1,
                name=_as_bytes(to_add[0]),
                value=_as_bytes(to_add[1]),
                sensitive=_has_never_index_marker(chunk),
            ),
        )
        return chunk


FIXED_HEADER_LISTS: dict[str, tuple[Header, ...]] = {
    "baseline": (
        HeaderTuple(b":method", b"GET"),
        HeaderTuple(b":scheme", b"https"),
        HeaderTuple(b":path", b"/internal/audit/baseline"),
        HeaderTuple(b"user-agent", b"gateway-contract-fixture"),
        HeaderTuple(b"accept", b"application/json"),
        HeaderTuple(b"x-audit-step", b"ingress"),
    ),
    "ordered_duplicates": (
        HeaderTuple(b":method", b"POST"),
        HeaderTuple(b":scheme", b"https"),
        HeaderTuple(b":path", b"/internal/audit/duplicates"),
        HeaderTuple(b"x-audit-note", b"alpha"),
        HeaderTuple(b"x-audit-note", b"beta"),
        HeaderTuple(b"x-audit-sequence", b"1"),
        HeaderTuple(b"x-audit-note", b"alpha"),
    ),
    "sensitive_attributes": (
        HeaderTuple(b":method", b"GET"),
        HeaderTuple(b":scheme", b"https"),
        HeaderTuple(b":path", b"/internal/audit/sensitive-flags"),
        NeverIndexedHeaderTuple(b"x-audit-marker", b"placeholder-one"),
        NeverIndexedHeaderTuple(b"x-audit-marker", b"placeholder-two"),
        HeaderTuple(b"x-audit-step", b"egress"),
    ),
    "mixed": (
        HeaderTuple(b":method", b"GET"),
        HeaderTuple(b":scheme", b"https"),
        HeaderTuple(b":path", b"/internal/audit/mixed"),
        HeaderTuple(b"x-audit-note", b"first"),
        NeverIndexedHeaderTuple(b"x-audit-marker", b"placeholder-alpha"),
        HeaderTuple(b"x-audit-note", b"second"),
        HeaderTuple(b"x-audit-sequence", b"2"),
        NeverIndexedHeaderTuple(b"x-audit-marker", b"placeholder-beta"),
        HeaderTuple(b"x-audit-note", b"first"),
        HeaderTuple(b"x-audit-step", b"post"),
    ),
}


def run_pipeline(headers: Sequence[Header], adapter: HeaderAdapter) -> PipelineResult:
    """Run a fixed field list through encode, decode, and the adapter double."""
    source = tuple(_field_from_header(header, ordinal) for ordinal, header in enumerate(headers, 1))

    encoder = _RecordingEncoder()
    encoded = encoder.encode(headers, huffman=False)

    decoder = Decoder()
    decoded_headers = decoder.decode(encoded, raw=True)
    decoded = tuple(_field_from_header(header, ordinal) for ordinal, header in enumerate(decoded_headers, 1))

    return PipelineResult(
        source=source,
        encoded=encoded,
        encoded_fields=tuple(encoder.encoded_fields),
        decoded=decoded,
        adapted=adapter.adapt(decoded_headers),
    )


def evaluate_contract(result: PipelineResult) -> ContractReport:
    """Compare every boundary and report the first place each instance is lost."""
    findings: list[Loss] = []
    findings.extend(_compare(result.source, result.encoded_fields, step=Step.ENCODER))
    findings.extend(_compare(result.encoded_fields, result.decoded, step=Step.DECODER))

    if result.adapted.audit is None:
        findings.extend(
            _loss(
                Step.ADAPTER,
                "audit_copy_missing",
                field,
                result.decoded,
                "adapter returned no per-instance audit field list",
            )
            for field in result.decoded
        )
    else:
        findings.extend(_compare(result.decoded, result.adapted.audit, step=Step.ADAPTER))

    if findings:
        verdict = Verdict.LOST
    elif result.adapted.merged_for_display:
        verdict = Verdict.DISPLAY_MERGED
    else:
        verdict = Verdict.PRESERVED

    return ContractReport(
        verdict=verdict,
        findings=tuple(findings),
        adapted=result.adapted,
        source=result.source,
        encoded_fields=result.encoded_fields,
        decoded=result.decoded,
    )


def _compare(expected: Sequence[Field], actual: Sequence[Field], *, step: Step) -> list[Loss]:
    """Compare field instances by value, duplicate occurrence, order, and flag."""
    findings: list[Loss] = []
    expected_tokens = _tokenize(expected)
    actual_tokens = _tokenize(actual)

    for token, expected_field in expected_tokens.items():
        if token in actual_tokens:
            continue
        expected_name_count = sum(1 for field in expected if field.name == expected_field.name)
        actual_name_count = sum(1 for field in actual if field.name == expected_field.name)
        if actual_name_count < expected_name_count:
            kind = "duplicate_collapsed"
            detail = "the field name survives, but this instance was merged or dropped"
        else:
            kind = "field_dropped"
            detail = "no field with this name/value occurrence exists in the next stage"
        findings.append(_loss(step, kind, expected_field, expected, detail))

    for token, actual_field in actual_tokens.items():
        if token not in expected_tokens:
            findings.append(
                _loss(
                    step,
                    "unexpected_field",
                    actual_field,
                    actual,
                    "field has no matching name/value occurrence in the previous stage",
                ),
            )

    common_expected = [token for token in expected_tokens if token in actual_tokens]
    common_actual = [token for token in actual_tokens if token in expected_tokens]
    for expected_token, actual_token in zip(common_expected, common_actual):
        if expected_token == actual_token:
            continue
        expected_field = expected_tokens[expected_token]
        actual_field = actual_tokens[actual_token]
        findings.append(
            _loss(
                step,
                "reordered",
                expected_field,
                expected,
                f"next stage has {_instance_label(actual_field, actual)} at this position",
            ),
        )
        break

    for token, expected_field in expected_tokens.items():
        actual_field = actual_tokens.get(token)
        if actual_field is None:
            continue
        if expected_field.sensitive and not actual_field.sensitive:
            findings.append(
                _loss(
                    step,
                    "sensitive_attribute_dropped",
                    expected_field,
                    expected,
                    "the field survives by name/value but is no longer marked never-indexed",
                ),
            )

    return findings


def _tokenize(fields: Sequence[Field]) -> dict[tuple[bytes, bytes, int], Field]:
    """Return fields keyed by (name, value, occurrence) in encounter order."""
    counts: Counter[tuple[bytes, bytes]] = Counter()
    tokens: dict[tuple[bytes, bytes, int], Field] = {}
    for field in fields:
        key = (field.name, field.value)
        counts[key] += 1
        tokens[(*key, counts[key])] = field
    return tokens


def _loss(step: Step, kind: str, field: Field, reference: Sequence[Field], detail: str) -> Loss:
    return Loss(
        step=step,
        kind=kind,
        field=field,
        instance=_instance_label(field, reference),
        detail=detail,
    )


def _instance_label(field: Field, reference: Sequence[Field]) -> str:
    same_name = [item for item in reference if item.name == field.name]
    occurrence = sum(1 for item in same_name if item.ordinal <= field.ordinal)
    return (
        f"field #{field.ordinal} {field.name.decode('utf-8', 'backslashreplace')}="
        f"{field.value.decode('utf-8', 'backslashreplace')} "
        f"(occurrence {occurrence}/{len(same_name)} of this name, "
        f"sensitive={'yes' if field.sensitive else 'no'})"
    )


def _adapted_fields(headers: Sequence[HeaderTuple]) -> tuple[Field, ...]:
    return tuple(_field_from_header(header, ordinal) for ordinal, header in enumerate(headers, 1))


def _field_from_header(header: Header | tuple[bytes | str, bytes | str], ordinal: int) -> Field:
    if isinstance(header, HeaderTuple):
        sensitive = not header.indexable
    else:
        sensitive = bool(header[2]) if len(header) > 2 else False
    return Field(
        ordinal=ordinal,
        name=_as_bytes(header[0]),
        value=_as_bytes(header[1]),
        sensitive=sensitive,
    )


def _as_bytes(value: bytes | str) -> bytes:
    return value if isinstance(value, bytes) else value.encode("utf-8")


def _has_never_index_marker(encoded_field: bytes) -> bool:
    """Return whether the field representation carries HPACK's never-indexed bit."""
    first_byte = encoded_field[0]
    if first_byte & 0x80:  # Indexed representation: no per-field metadata exists.
        return False
    if first_byte & 0x40:  # Incremental indexing: deliberately indexable.
        return False
    return bool(first_byte & 0x10)  # Literal with the never-indexed bit.


@pytest.mark.parametrize("case_name", tuple(FIXED_HEADER_LISTS))
def test_codec_preserves_order_duplicates_and_sensitive_flags(case_name: str) -> None:
    """Encode/decode must retain all three audit dimensions before the adapter runs."""
    result = run_pipeline(FIXED_HEADER_LISTS[case_name], PassThroughAdapter())
    report = evaluate_contract(result)

    assert report.verdict is Verdict.PRESERVED, report.render()
    assert report.findings == (), report.render()
    assert result.encoded_fields == result.source, report.render()
    assert result.decoded == result.source, report.render()
    assert result.adapted.audit == result.source, report.render()


def test_display_merge_is_accepted_when_audit_instances_survive() -> None:
    """Combining duplicate values for display is fine if audit keeps each instance."""
    result = run_pipeline(FIXED_HEADER_LISTS["ordered_duplicates"], DisplayMergeAdapter())
    report = evaluate_contract(result)

    assert report.verdict is Verdict.DISPLAY_MERGED, report.render()
    assert report.accepted, report.render()
    assert report.findings == (), report.render()
    assert result.adapted.audit == result.decoded, report.render()
    assert dict(result.adapted.display)[b"x-audit-note"] == b"alpha, beta, alpha"


def test_duplicate_collapse_is_rejected_with_specific_instances() -> None:
    """A display shortcut that also collapses the audit copy must be rejected."""
    result = run_pipeline(FIXED_HEADER_LISTS["ordered_duplicates"], DuplicateCollapsingAdapter())
    report = evaluate_contract(result)

    assert report.verdict is Verdict.LOST, report.render()
    assert not report.accepted, report.render()
    assert report.findings, report.render()

    lost_duplicates = [
        loss for loss in report.findings
        if loss.step is Step.ADAPTER
        and loss.kind == "duplicate_collapsed"
        and loss.field.name == b"x-audit-note"
    ]
    assert {
        (loss.field.ordinal, loss.field.value) for loss in lost_duplicates
    } == {(5, b"beta"), (7, b"alpha")}, report.render()
    assert all(loss.step is Step.ADAPTER for loss in report.findings), report.render()


def test_sensitive_attribute_loss_is_rejected_at_adapter() -> None:
    """Clearing the sensitive bit after decode loses audit evidence at the adapter."""
    result = run_pipeline(FIXED_HEADER_LISTS["sensitive_attributes"], SensitivityStrippingAdapter())
    report = evaluate_contract(result)

    assert report.verdict is Verdict.LOST, report.render()
    sensitive_losses = [
        loss for loss in report.findings if loss.kind == "sensitive_attribute_dropped"
    ]
    assert len(sensitive_losses) == 2, report.render()
    assert {loss.field.value for loss in sensitive_losses} == {
        b"placeholder-one",
        b"placeholder-two",
    }, report.render()
    assert all(loss.step is Step.ADAPTER for loss in sensitive_losses), report.render()

    rendered = report.render()
    assert "step=adapter" in rendered
    assert "field #4" in rendered
    assert "field #5" in rendered
    assert "sensitive_attribute_dropped" in rendered


def test_audit_reordering_is_rejected_with_first_moved_instance() -> None:
    """Sorting the audit copy changes order, even though every value survives."""
    result = run_pipeline(FIXED_HEADER_LISTS["ordered_duplicates"], AuditReorderingAdapter())
    report = evaluate_contract(result)

    assert report.verdict is Verdict.LOST, report.render()
    reordered = [loss for loss in report.findings if loss.kind == "reordered"]
    assert len(reordered) == 1, report.render()
    assert reordered[0].step is Step.ADAPTER, report.render()
    assert reordered[0].field.ordinal == 2, report.render()
    assert reordered[0].field.name == b":scheme", report.render()

    rendered = report.render()
    assert "step=adapter" in rendered
    assert "field #2" in rendered
    assert "reordered" in rendered


def test_decoder_stage_attribution_is_distinct_from_encoder_and_adapter() -> None:
    """A decoder-side loss must be labelled at the decoder boundary."""
    result = run_pipeline(FIXED_HEADER_LISTS["sensitive_attributes"], PassThroughAdapter())
    decoded_with_lost_flag = tuple(
        replace(field, sensitive=False) if field.sensitive else field
        for field in result.decoded
    )
    adapted = AdaptedHeaders(
        display=tuple((field.name, field.value) for field in decoded_with_lost_flag),
        audit=decoded_with_lost_flag,
        merged_for_display=False,
    )
    broken = replace(result, decoded=decoded_with_lost_flag, adapted=adapted)
    report = evaluate_contract(broken)

    assert report.verdict is Verdict.LOST, report.render()
    sensitive_losses = [
        loss for loss in report.findings if loss.kind == "sensitive_attribute_dropped"
    ]
    assert len(sensitive_losses) == 2, report.render()
    assert all(loss.step is Step.DECODER for loss in sensitive_losses), report.render()
    assert "step=decoder" in report.render()
    assert "field #4" in report.render()


def test_encoder_stage_loss_is_reported_for_static_table_match() -> None:
    """
    Pin the current codec boundary: an exact static-table match is sent indexed.

    HPACK's indexed representation has no never-indexed bit, so a sensitive
    field with a public static-table value loses that attribute at the encoder.
    The contract accepts the value but rejects the audit evidence and names the
    exact source instance and stage.
    """
    headers = (
        HeaderTuple(b":method", b"GET"),
        HeaderTuple(b":scheme", b"https"),
        HeaderTuple(b":path", b"/internal/audit/static-match"),
        NeverIndexedHeaderTuple(b"accept-encoding", b"gzip, deflate"),
    )
    result = run_pipeline(headers, PassThroughAdapter())
    report = evaluate_contract(result)

    assert report.verdict is Verdict.LOST, report.render()
    sensitive_losses = [
        loss for loss in report.findings if loss.kind == "sensitive_attribute_dropped"
    ]
    assert len(sensitive_losses) == 1, report.render()
    loss = sensitive_losses[0]
    assert loss.step is Step.ENCODER, report.render()
    assert loss.field.ordinal == 4, report.render()
    assert loss.field.name == b"accept-encoding", report.render()
    assert loss.field.value == b"gzip, deflate", report.render()

    rendered = report.render()
    assert "step=encoder" in rendered
    assert "field #4 accept-encoding=gzip, deflate" in rendered
    assert "sensitive_attribute_dropped" in rendered
