"""Offline hardening audit entry point built only on pyelftools.

No binary is ever executed; every conclusion references byte intervals in
the input file. Rules are opt-in/selectable via ``rules``.
"""

from __future__ import annotations

import io
from collections.abc import Iterable, Mapping
from typing import IO
from pathlib import Path

from elftools.elf.elffile import ELFFile

from .model import AuditReport, RuleId, RuleResult
from .rules import bind_now, relro, stack_exec
from .views import ELFViews

ALL_RULES: tuple[RuleId, ...] = (
    RuleId.STACK_EXECUTABLE,
    RuleId.RELRO,
    RuleId.BIND_NOW,
)

_RULE_FUNCTIONS = {
    RuleId.STACK_EXECUTABLE: stack_exec.audit,
    RuleId.RELRO: relro.audit,
    RuleId.BIND_NOW: bind_now.audit,
}


def audit_stream(
    stream: IO[bytes],
    rules: Iterable[RuleId | str] | None = None,
    source: str | None = None,
) -> AuditReport:
    elf = ELFFile(stream)
    selected = _select_rules(rules)
    views = ELFViews.collect(elf)
    results: list[RuleResult] = []
    for rule_id in selected:
        results.append(_RULE_FUNCTIONS[rule_id](views))
    return AuditReport(
        source=source or "<stream>",
        elf_class=elf.elfclass,
        endianness="little" if elf.little_endian else "big",
        elf_type=str(elf["e_type"]),
        machine=str(elf["e_machine"]),
        is_dynamic=any(segment.p_type == "PT_DYNAMIC" for segment in views.segments),
        section_headers_present=views.section_view_present,
        rules_selected=[rule.value for rule in selected],
        results=results,
    )


def audit_elf(
    path: str | Path,
    rules: Iterable[RuleId | str] | None = None,
) -> AuditReport:
    with open(path, "rb") as stream:
        return audit_stream(stream, rules=rules, source=str(path))


def audit_bytes(
    data: bytes,
    rules: Iterable[RuleId | str] | None = None,
    source: str = "<bytes>",
) -> AuditReport:
    return audit_stream(io.BytesIO(data), rules=rules, source=source)


def _select_rules(rules: Iterable[RuleId | str] | None) -> list[RuleId]:
    if rules is None:
        return list(ALL_RULES)
    resolved: list[RuleId] = []
    for rule in rules:
        rule_id = rule if isinstance(rule, RuleId) else RuleId(rule)
        if rule_id not in resolved:
            resolved.append(rule_id)
    unknown = [item for item in resolved if item not in _RULE_FUNCTIONS]
    if unknown:
        raise ValueError(f"unknown rules: {[item.value for item in unknown]}")
    return resolved


def report_as_dict(report: AuditReport) -> Mapping[str, object]:
    return report.to_dict()
