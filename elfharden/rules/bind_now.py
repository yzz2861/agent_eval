"""Binding-time rule (lazy vs immediate).

BIND_NOW may appear as DT_BIND_NOW, DF_BIND_NOW in DT_FLAGS or DF_1_NOW in
DT_FLAGS_1. Entries are read independently from the PT_DYNAMIC segment and
the .dynamic section; a loader that maps the segment can see a different
table than the one described by section headers, so a disagreement is a
conflict rather than a default pass.
"""

from __future__ import annotations

from ..model import Evidence, RuleResult, Status, ViewKind
from ..views import DynamicTagRecord, ELFViews

RULE_ID = "bind_now"


def audit(views: ELFViews) -> RuleResult:
    result = RuleResult(rule_id=RULE_ID)
    has_dynamic_segment = bool(views.segment_by_type("PT_DYNAMIC"))
    if not has_dynamic_segment:
        result.status = Status.NOT_APPLICABLE
        result.summary = "static image without PT_DYNAMIC; symbol binding timing does not apply"
        return result
    segment_tags = [tag for tag in views.dynamic_tags if tag.source.startswith("segment:")]
    section_tags = [tag for tag in views.dynamic_tags if tag.source.startswith("section:")]
    segment_now = _record(segment_tags, ViewKind.SEGMENT, result)
    if not section_tags and not views.section_view_present:
        result.evidence.append(
            Evidence(
                view=ViewKind.SECTION,
                kind="section_header_table:absent",
                detail={"reason": "fully stripped; section view unavailable"},
                file_range=None,
                memory_range=None,
            )
        )
        result.status = segment_now
        result.summary = "verdict based on PT_DYNAMIC only; section headers absent"
        return result
    section_now = _record(section_tags, ViewKind.SECTION, result)
    if segment_now == section_now:
        result.status = segment_now
        result.summary = "segment and section dynamic tables agree on binding timing"
    else:
        result.status = Status.CONFLICT
        result.summary = "PT_DYNAMIC and .dynamic disagree on BIND_NOW"
        result.conflicts.append({
            "segment_verdict": segment_now.value,
            "section_verdict": section_now.value,
        })
    return result


def _record(tags: list[DynamicTagRecord], view: ViewKind, result: RuleResult) -> Status:
    relevant = [tag for tag in tags if tag.requests_now()]
    for tag in relevant:
        result.evidence.append(
            Evidence(
                view=view,
                kind="dynamic_tag:bind_now",
                detail={
                    "tag": tag.tag,
                    "tag_value": tag.tag_value,
                    "value": tag.value,
                    "source": tag.source,
                },
                file_range=tag.range,
                memory_range=None,
                supports_verdict=Status.PASS,
            )
        )
    if relevant:
        return Status.PASS
    # Witness the terminator so the machine output still names the interval
    # that proves the table was parsed and contained no BIND_NOW marker.
    terminator = next((tag for tag in tags if tag.tag == "DT_NULL"), None)
    result.evidence.append(
        Evidence(
            view=view,
            kind="dynamic_table:no_bind_now",
            detail={"entries_parsed": len(tags)},
            file_range=terminator.range if terminator else None,
            memory_range=None,
            supports_verdict=Status.FAIL,
        )
    )
    return Status.FAIL
