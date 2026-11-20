"""RELRO rule.

PT_GNU_RELRO is the load-time evidence that a region is remapped read-only.
BIND_NOW dynamic entries distinguish full RELRO (lazy binding disabled) from
partial RELRO. Sections inside the region are corroborating witnesses only;
a section header without a PT_GNU_RELRO segment never upgrades the verdict.
"""

from __future__ import annotations

from ..model import Evidence, RuleResult, Status, ViewKind
from ..views import ELFViews, PT_GNU_RELRO

RULE_ID = "relro"


def audit(views: ELFViews) -> RuleResult:
    result = RuleResult(rule_id=RULE_ID)
    relro_segments = views.segment_by_type(PT_GNU_RELRO)
    if not relro_segments:
        _section_only_witness(views, result)
        result.status = Status.INDETERMINATE
        result.summary = "no PT_GNU_RELRO segment; section headers cannot establish loader protection"
        return result
    for segment in relro_segments:
        result.evidence.append(
            Evidence(
                view=ViewKind.SEGMENT,
                kind="program_header:PT_GNU_RELRO",
                detail={"p_flags": segment.p_flags},
                file_range=segment.file_range if segment.file_range.size else segment.header_range,
                memory_range=segment.memory_range,
            )
        )
        for section in views.sections_in_segment(segment):
            result.evidence.append(
                Evidence(
                    view=ViewKind.SECTION,
                    kind="section_inside:PT_GNU_RELRO",
                    detail={"name": section.name, "sh_flags": section.sh_flags},
                    file_range=section.file_range,
                    memory_range=section.memory_range,
                )
            )
    now_requested = _dynamic_now(views, result)
    if not views.dynamic_present:
        result.status = Status.INDETERMINATE
        result.summary = "PT_GNU_RELRO present but static image has no dynamic table; full vs partial not decidable"
    elif now_requested:
        result.status = Status.PASS
        result.summary = "full RELRO: PT_GNU_RELRO plus immediate binding"
    else:
        result.status = Status.PARTIAL
        result.summary = "partial RELRO: PT_GNU_RELRO present without BIND_NOW"
    return result


def _dynamic_now(views: ELFViews, result: RuleResult) -> bool:
    now_evidence = [tag for tag in views.dynamic_tags if tag.requests_now()]
    for tag in now_evidence:
        result.evidence.append(
            Evidence(
                view=ViewKind.DYNAMIC,
                kind="dynamic_tag:bind_now",
                detail={"tag": tag.tag, "value": tag.value, "source": tag.source},
                file_range=tag.range,
                memory_range=None,
            )
        )
    return bool(now_evidence)


def _section_only_witness(views: ELFViews, result: RuleResult) -> None:
    if not views.section_view_present:
        result.evidence.append(
            Evidence(
                view=ViewKind.SECTION,
                kind="section_header_table:absent",
                detail={"reason": "fully stripped; section view unavailable"},
                file_range=None,
                memory_range=None,
            )
        )
        return
    for section in views.sections:
        if section.name in {".got", ".got.plt", ".init_array", ".fini_array"}:
            result.evidence.append(
                Evidence(
                    view=ViewKind.SECTION,
                    kind="section_header:candidate_relro_target",
                    detail={"name": section.name, "sh_flags": section.sh_flags},
                    file_range=section.file_range,
                    memory_range=section.memory_range,
                )
            )
