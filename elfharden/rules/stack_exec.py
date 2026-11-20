"""Stack executability rule (NX stack)."

The loader consults PT_GNU_STACK; the .note.GNU-stack section is the
link-time declaration that normally produces it. Both views are parsed
independently and any disagreement is reported rather than resolved by
convention.
"""

from __future__ import annotations

from ..model import Evidence, RuleResult, Status, ViewKind
from ..views import ELFViews, PT_GNU_STACK

RULE_ID = "stack_executable"
NOTE_NAME = ".note.GNU-stack"


def audit(views: ELFViews) -> RuleResult:
    result = RuleResult(rule_id=RULE_ID)
    segment_verdict = _segment_verdict(views, result)
    section_verdict = _section_verdict(views, result)
    if segment_verdict is None and section_verdict is None:
        result.status = Status.INDETERMINATE
        result.summary = "no PT_GNU_STACK segment and no .note.GNU-stack section declare stack rights"
    elif segment_verdict is None:
        result.status = section_verdict or Status.INDETERMINATE
        result.summary = "only the section view declares stack rights; the loader view is silent"
    elif section_verdict is None:
        result.status = segment_verdict
        result.summary = "only the program-header view declares stack rights"
    elif segment_verdict == section_verdict:
        result.status = segment_verdict
        result.summary = "segment and section views agree on stack executability"
    else:
        result.status = Status.CONFLICT
        result.summary = "PT_GNU_STACK flags contradict .note.GNU-stack flags"
        result.conflicts.append({
            "segment_verdict": segment_verdict.value,
            "section_verdict": section_verdict.value,
        })
    return result


def _segment_verdict(views: ELFViews, result: RuleResult) -> Status | None:
    stacks = views.segment_by_type(PT_GNU_STACK)
    if not stacks:
        return None
    verdicts: set[Status] = set()
    for segment in stacks:
        verdict = Status.FAIL if segment.executable else Status.PASS
        verdicts.add(verdict)
        result.evidence.append(
            Evidence(
                view=ViewKind.SEGMENT,
                kind="program_header:PT_GNU_STACK",
                detail={
                    "p_flags": segment.p_flags,
                    "executable": segment.executable,
                    "note": "p_filesz is 0 for GNU_STACK; the program header entry is the file evidence",
                },
                file_range=segment.file_range if segment.file_range.size else segment.header_range,
                memory_range=segment.memory_range,
                supports_verdict=verdict,
            )
        )
    if len(verdicts) > 1:
        result.conflicts.append({
            "program_headers": "multiple PT_GNU_STACK segments disagree on PF_X"
        })
        return Status.CONFLICT
    return next(iter(verdicts))


def _section_verdict(views: ELFViews, result: RuleResult) -> Status | None:
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
        return None
    notes = views.section_by_name(NOTE_NAME)
    if not notes:
        return None
    verdicts: set[Status] = set()
    for section in notes:
        verdict = Status.FAIL if section.executable else Status.PASS
        verdicts.add(verdict)
        result.evidence.append(
            Evidence(
                view=ViewKind.SECTION,
                kind="section_header:.note.GNU-stack",
                detail={
                    "sh_flags": section.sh_flags,
                    "executable": section.executable,
                    "sh_type": section.sh_type,
                },
                file_range=section.file_range,
                memory_range=section.memory_range,
                supports_verdict=verdict,
            )
        )
    if len(verdicts) > 1:
        result.conflicts.append({
            "sections": "multiple .note.GNU-stack sections disagree on SHF_EXECINSTR"
        })
        return Status.CONFLICT
    return next(iter(verdicts))
