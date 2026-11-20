"""Review engine: correlate signed revisions with later changes.

The engine never verifies cryptographic signatures itself.  A caller-supplied
SignatureVerifier decides whether each ByteRange is valid; this module maps
each signature to the revision it covers and evaluates every later revision
against an explicit ReviewPolicy.
"""

from __future__ import annotations

from dataclasses import asdict
from io import BytesIO
from pathlib import Path
from typing import Any

from pypdf import PdfReader

from .models import (
    ChangeType,
    FieldSnapshot,
    Finding,
    PageSnapshot,
    ReviewDecision,
    ReviewPolicy,
    ReviewRecord,
    SignatureInfo,
    Snapshot,
)
from .revisions import RevisionInfo, RevisionScan, scan_revisions
from .snapshot import build_snapshot
from .verifiers import SignatureVerifier

def _field_value_change(before: FieldSnapshot, after: FieldSnapshot) -> bool:
    return before.value != after.value or before.default_value != after.default_value


def _field_appearance_change(before: FieldSnapshot, after: FieldSnapshot) -> bool:
    return (before.appearance_stream_hash != after.appearance_stream_hash
            or before.widget_annotation_hash != after.widget_annotation_hash)


def _diff_fields(before: Snapshot, after: Snapshot) -> list[Finding]:
    findings: list[Finding] = []
    keys = sorted(set(before.fields) | set(after.fields))
    for key in keys:
        old = before.fields.get(key)
        new = after.fields.get(key)
        if old is None and new is not None:
            if new.is_signature:
                continue
            findings.append(Finding(
                change_type=ChangeType.FIELD_ADDED, severity="unauthorized",
                target=f"field:{new.full_name}", object_ref=key,
                detail={"full_name": new.full_name, "field_type": new.field_type,
                        "value": new.value},
                explanation=f"新增字段 {new.full_name}（类型 {new.field_type}）。"))
            continue
        if old is not None and new is None:
            findings.append(Finding(
                change_type=ChangeType.FIELD_REMOVED, severity="unauthorized",
                target=f"field:{old.full_name}", object_ref=key,
                detail={"full_name": old.full_name, "field_type": old.field_type},
                explanation=f"字段 {old.full_name} 被删除。"))
            continue
        if old is None or new is None:
            continue
        if old.is_signature or new.is_signature:
            continue
        if _field_value_change(old, new):
            findings.append(Finding(
                change_type=ChangeType.FIELD_VALUE, severity="pending",
                target=f"field:{new.full_name}", object_ref=key,
                detail={"before": old.value, "after": new.value,
                        "default_before": old.default_value,
                        "default_after": new.default_value},
                explanation=f"字段 {new.full_name} 的值在签后发生变化。"))
        if _field_appearance_change(old, new) and not _field_value_change(old, new):
            findings.append(Finding(
                change_type=ChangeType.FIELD_APPEARANCE, severity="pending",
                target=f"field:{new.full_name}", object_ref=key,
                detail={"appearance_before": old.appearance_stream_hash,
                        "appearance_after": new.appearance_stream_hash,
                        "widget_before": old.widget_annotation_hash,
                        "widget_after": new.widget_annotation_hash},
                explanation=f"字段 {new.full_name} 的外观流或部件注解发生变化。"))
    return findings

def _diff_pages(before: Snapshot, after: Snapshot) -> list[Finding]:
    findings: list[Finding] = []
    old_by_index = {page.index: page for page in before.pages}
    new_by_index = {page.index: page for page in after.pages}
    if len(before.pages) != len(after.pages):
        findings.append(Finding(
            change_type=ChangeType.PAGE_COUNT, severity="pending",
            target="document:page-count", object_ref=None,
            detail={"before": len(before.pages), "after": len(after.pages)},
            explanation=f"页数由 {len(before.pages)} 变为 {len(after.pages)}。"))
    for index in sorted(set(old_by_index) & set(new_by_index)):
        findings.extend(_diff_single_page(old_by_index[index], new_by_index[index]))
    for index in sorted(set(new_by_index) - set(old_by_index)):
        page = new_by_index[index]
        findings.append(Finding(
            change_type=ChangeType.PAGE_CONTENT, severity="pending",
            target=f"page:{index}", object_ref=page.object_key,
            detail={"contents": page.contents, "rotation": page.rotation},
            explanation=f"新增第 {index + 1} 页及其内容。"))
    return findings


def _diff_single_page(old: PageSnapshot, new: PageSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    target = f"page:{new.index}"
    if old.contents != new.contents:
        findings.append(Finding(
            change_type=ChangeType.PAGE_CONTENT, severity="pending",
            target=target, object_ref=new.object_key,
            detail={"before": old.contents, "after": new.contents},
            explanation=f"第 {new.index + 1} 页内容流发生变化。"))
    if old.media_box != new.media_box or old.rotation != new.rotation:
        findings.append(Finding(
            change_type=ChangeType.PAGE_GEOMETRY, severity="pending",
            target=target, object_ref=new.object_key,
            detail={"media_box_before": old.media_box,
                    "media_box_after": new.media_box,
                    "rotation_before": old.rotation,
                    "rotation_after": new.rotation},
            explanation=f"第 {new.index + 1} 页尺寸或旋转发生变化。"))
    return findings

def _diff_resources(before: Snapshot, after: Snapshot, findings: list[Finding]) -> None:
    old_refs = set(before.resource_impact)
    new_refs = set(after.resource_impact)
    for ref in sorted(new_refs - old_refs):
        findings.append(Finding(
            change_type=ChangeType.SHARED_RESOURCE, severity="pending",
            target=f"resource:{ref}", object_ref=ref,
            detail={"impacted_pages": after.resource_impact[ref]},
            explanation=_resource_explanation("新增共享资源", ref, after.resource_impact[ref])))
    for ref in sorted(old_refs & new_refs):
        old_pages = before.resource_impact[ref]
        new_pages = after.resource_impact[ref]
        if old_pages != new_pages:
            findings.append(Finding(
                change_type=ChangeType.SHARED_RESOURCE, severity="pending",
                target=f"resource:{ref}", object_ref=ref,
                detail={"before": old_pages, "after": new_pages},
                explanation=_resource_explanation("共享资源引用关系变化", ref, new_pages)))



def _resource_explanation(prefix: str, ref: str, impacted: list[dict[str, Any]]) -> str:
    page_ids = ', '.join(str(item['page_index'] + 1) for item in impacted) or '无'
    names = '; '.join(
        f"第 {item['page_index'] + 1} 页: {', '.join(item['names'])}" for item in impacted)
    return f'{prefix} {ref}，影响页面 {page_ids}。逐项：{names}'


def _diff_inherited(before: Snapshot, after: Snapshot) -> list[Finding]:
    findings: list[Finding] = []
    old_pages = {page.index: page for page in before.pages}
    for new in after.pages:
        old = old_pages.get(new.index)
        if old is None:
            continue
        for attr, info in new.inherited.items():
            old_info = old.inherited.get(attr)
            if old_info is None or old_info.get('value') == info.get('value'):
                continue
            findings.append(Finding(
                change_type=ChangeType.INHERITED_ATTR, severity='pending',
                target=f'page:{new.index}:{attr}', object_ref=info.get('defined_on'),
                detail={'attribute': attr, 'before': old_info.get('value'),
                        'after': info.get('value'), 'defined_on': info.get('defined_on')},
                explanation=(
                    f'第 {new.index + 1} 页继承属性 {attr} 变化，'
                    f"当前定义于节点 {info.get('defined_on')}，该节点可能被多个页面共享。")))
    return findings


def _apply_policy(finding: Finding, policy: ReviewPolicy) -> Finding:
    if finding.severity == 'truncated':
        return finding
    allowed = False
    reason = ''
    if finding.change_type == ChangeType.FIELD_VALUE:
        name = finding.target.split(':', 1)[1]
        allowed = name in policy.allowed_field_fills
        reason = f'字段 {name} 不在允许填写清单 {sorted(policy.allowed_field_fills)}'
    elif finding.change_type == ChangeType.FIELD_APPEARANCE:
        name = finding.target.split(':', 1)[1]
        allowed = name in policy.allowed_field_appearance
        reason = f'字段 {name} 的外观变更未获许可'
    elif finding.change_type in (ChangeType.PAGE_CONTENT, ChangeType.PAGE_COUNT):
        allowed = policy.allow_page_changes
        reason = '策略未许可页面内容/页数改动'
    elif finding.change_type == ChangeType.PAGE_GEOMETRY:
        allowed = policy.allow_page_changes
        reason = '策略未许可页面几何改动'
    elif finding.change_type == ChangeType.SHARED_RESOURCE:
        allowed = policy.allow_shared_resource_changes
        reason = '策略未许可共享资源改动'
    elif finding.change_type == ChangeType.INHERITED_ATTR:
        allowed = policy.allow_inherited_attr_changes
        reason = '策略未许可继承属性改动'
    if allowed:
        finding.severity = 'allowed'
        finding.policy_basis = 'explicit-permission'
    else:
        finding.severity = 'unauthorized'
        finding.policy_basis = reason
    return finding


def _resolve(obj: Any) -> Any:
    if hasattr(obj, 'get_object'):
        try:
            return obj.get_object()
        except Exception:
            return obj
    return obj


def _extract_signatures(reader: PdfReader, scan: RevisionScan) -> list[SignatureInfo]:
    signatures: list[SignatureInfo] = []
    root = _resolve(reader.trailer['/Root'])
    acroform = _resolve(root.get('/AcroForm')) if hasattr(root, 'get') else None
    if not isinstance(acroform, dict):
        return signatures
    fields = acroform.get('/Fields', [])
    for index, field_ref in enumerate(fields):
        field = _resolve(field_ref)
        if not isinstance(field, dict) or str(field.get('/FT')) != '/Sig':
            continue
        value = _resolve(field.get('/V'))
        if not isinstance(value, dict):
            continue
        byte_range = [int(part) for part in value.get('/ByteRange', [])]
        covered_end = byte_range[2] + byte_range[3] if len(byte_range) == 4 else None
        # The covered range can include the newline after %%EOF; map using a
        # byte safely inside the covered tail of the signature revision.
        anchor = byte_range[2] + 1 if len(byte_range) == 4 else None
        signed_revision = scan.revision_for_offset(anchor)
        signatures.append(SignatureInfo(
            field_name=str(field.get('/T')) if '/T' in field else f'sig-{index}',
            field_ref=_field_ref(field),
            value_ref=_ref(value),
            byte_range=byte_range,
            covered_end=covered_end,
            signed_revision=signed_revision,
            valid=None, verifier=None, detail=None))
    return signatures


def _field_ref(field: Any) -> str | None:
    ref = getattr(field, 'indirect_reference', None)
    if ref is not None:
        return f'{ref.idnum} {ref.generation} R'
    return None


def _ref(obj: Any) -> str | None:
    if hasattr(obj, 'indirect_reference') and obj.indirect_reference is not None:
        ref = obj.indirect_reference
        return f'{ref.idnum} {ref.generation} R'
    return None


def _snapshot_for_revision(data: bytes, revision: RevisionInfo) -> Snapshot:
    reader = PdfReader(BytesIO(data[: revision.end_offset]))
    return build_snapshot(reader)


def _truncation_findings(scan: RevisionScan) -> list[Finding]:
    findings: list[Finding] = []
    for fragment in scan.truncated_fragments:
        findings.append(Finding(
            change_type=ChangeType.TRUNCATED_REVISION, severity='truncated',
            target=f'truncated:{fragment.start_offset}', object_ref=None,
            detail={
                'start_offset': fragment.start_offset,
                'end_offset': fragment.end_offset,
                'reason': fragment.reason,
            },
            explanation=('检测到未以完整 %%EOF 收尾的尾部修订片段，无法可靠解析，'
                         '保留为人工待查。')))
    return findings


def _revision_findings(before: Snapshot, after: Snapshot) -> list[Finding]:
    findings = _diff_fields(before, after)
    page_findings = _diff_pages(before, after)
    findings.extend(page_findings)
    _diff_resources(before, after, findings)
    findings.extend(_diff_inherited(before, after))
    return findings


def review_pdf_bytes(data: bytes, policy: ReviewPolicy,
                    verifier: SignatureVerifier,
                    source: str = '<bytes>') -> ReviewRecord:
    scan = scan_revisions(data)
    latest_reader = PdfReader(BytesIO(data))
    signatures = _extract_signatures(latest_reader, scan)
    for signature in signatures:
        result = verifier.verify(data, signature)
        signature.valid = result.valid
        signature.verifier = result.verifier
        signature.detail = result.detail
    snapshots = [_snapshot_for_revision(data, rev) for rev in scan.revisions]
    findings: list[Finding] = []
    if not signatures:
        findings.append(Finding(
            change_type=ChangeType.TRUNCATED_REVISION, severity='truncated',
            target='signature:none', object_ref=None, detail={},
            explanation='未找到任何签名字段，无法确定签名覆盖边界，转人工待查。'))
    signed_index = max((sig.signed_revision for sig in signatures
                        if sig.signed_revision is not None), default=None)
    first_post_signature = signed_index if signed_index is not None else 1
    for index in range(first_post_signature, len(snapshots)):
        for finding in _revision_findings(snapshots[index - 1], snapshots[index]):
            finding.from_revision = index - 1
            finding.to_revision = index
            findings.append(finding)
    findings.extend(_truncation_findings(scan))
    evaluated = [_apply_policy(finding, policy) for finding in findings]
    decision, deciding, routing_reason = _decide(evaluated, signatures, signed_index)
    return ReviewRecord(
        source=source, total_bytes=len(data),
        revision_count=len(scan.revisions),
        signed_revision_index=signed_index,
        signatures=signatures, findings=evaluated, decision=decision,
        truncated=bool(scan.truncated_fragments),
        revision_offsets=[rev.end_offset for rev in scan.revisions],
        deciding_findings=deciding, routing_reason=routing_reason)


def _decide(findings: list[Finding], signatures: list[SignatureInfo],
            signed_index: int | None) -> tuple[str, list[dict[str, Any]], str]:
    invalid = [sig for sig in signatures if sig.valid is False]
    if invalid:
        names = ', '.join(sig.field_name for sig in invalid)
        return (ReviewDecision.MANUAL, [], f'签名验证未通过: {names}')
    truncated = [f for f in findings if f.severity == 'truncated']
    if truncated:
        return (ReviewDecision.MANUAL, [_finding_brief(f) for f in truncated],
                '存在无法解析的截断修订，需人工待查')
    unauthorized = [f for f in findings if f.severity == 'unauthorized']
    if unauthorized:
        first = unauthorized[0]
        return (ReviewDecision.MANUAL, [_finding_brief(f) for f in unauthorized],
                f'签后未授权变更触发人工流转，首项: {first.target} ({first.change_type.value})')
    if signed_index is None:
        return (ReviewDecision.MANUAL, [], '未能定位签名覆盖的修订边界')
    return (ReviewDecision.CONTINUE, [], '所有签后变更均在显式许可范围内')


def _finding_brief(finding: Finding) -> dict[str, Any]:
    return {
        'change_type': finding.change_type.value,
        'severity': finding.severity,
        'target': finding.target,
        'object_ref': finding.object_ref,
        'from_revision': finding.from_revision,
        'to_revision': finding.to_revision,
        'explanation': finding.explanation,
    }


def review_pdf_file(path: str | Path, policy: ReviewPolicy,
                    verifier: SignatureVerifier) -> ReviewRecord:
    path = Path(path)
    return review_pdf_bytes(path.read_bytes(), policy, verifier, source=path.name)


def review_pdf(reader: PdfReader, policy: ReviewPolicy,
               verifier: SignatureVerifier, source: str = '<reader>') -> ReviewRecord:
    stream = reader.stream
    stream.seek(0)
    return review_pdf_bytes(stream.read(), policy, verifier, source=source)


def record_to_dict(record: ReviewRecord) -> dict[str, Any]:
    return asdict(record)
