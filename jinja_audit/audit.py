"""Audit orchestration: allow-list checks, holds, version pinning, decision."""

from __future__ import annotations

from collections.abc import Collection, Mapping

from jinja2 import Environment

from .models import (
    Approval,
    AuditReport,
    Decision,
    Finding,
    Reference,
    Severity,
    TemplateRepository,
)
from .references import CandidateMap, TemplateParseError, closure_first_pass

# test marker


def audit_entry(
    entry: str,
    repository: TemplateRepository,
    allowed: Collection[str],
    *,
    candidates: CandidateMap | None = None,
    approval: Approval | None = None,
    environment: Environment | None = None,
) -> AuditReport:
    """Run the full offline pre-audit for one user entry template.

    The decision is the worst severity observed:

    * ``reject``  - malformed template, entry/target missing or not allow-listed;
    * ``hold``    - an unbounded template-name expression needs a host decision;
    * ``release`` - every reachable template is allow-listed and the approval
                    still matches the current content hashes.

    ``allowed`` is the caller's set of templates the user may use.  An
    allow-listed entry is never enough on its own: every transitive reference
    must also be allow-listed, and the approval must cover the current versions.
    """
    allowed_set = set(allowed)
    findings: list[Finding] = []

    if not repository.exists(entry):
        return _reject(
            entry,
            Finding(
                code="entry.missing",
                severity=Severity.ERROR,
                message=f"entry template '{entry}' is not in the repository",
                template=entry,
            ),
        )

    if entry not in allowed_set:
        findings.append(
            Finding(
                code="entry.not_allowed",
                severity=Severity.ERROR,
                message=(
                    f"entry template '{entry}' is not on the caller allow-list"
                ),
                template=entry,
            )
        )

    references, parse_errors = closure_first_pass(
        repository, entry, candidates, environment
    )
    for error in parse_errors:
        findings.append(
            Finding(
                code="template.parse_error",
                severity=Severity.ERROR,
                message=f"template cannot be parsed: {error}",
            )
        )

    closure = _compute_closure(entry, references)
    _check_targets(references, repository, allowed_set, findings)
    _check_holds(references, findings)
    _check_closure_allowed(entry, closure, allowed_set, repository, findings)
    _check_approval(entry, approval, repository, closure, references, findings)

    decision = _final_decision(findings)
    return AuditReport(
        entry=entry,
        decision=decision,
        findings=findings,
        references=references,
        closure=tuple(sorted(closure)),
        versions={
            name: repository.version_of(name)
            for name in closure
            if repository.exists(name)
        },
    )


def _reject(entry: str, finding: Finding) -> AuditReport:
    return AuditReport(
        entry=entry,
        decision=Decision.REJECT,
        findings=[finding],
        closure=(entry,),
    )


def _compute_closure(entry: str, references: list[Reference]) -> set[str]:
    closure = {entry}
    for ref in references:
        closure.add(ref.source)
        closure.update(ref.targets)
    return closure


def _check_targets(
    references: list[Reference],
    repository: TemplateRepository,
    allowed_set: set[str],
    findings: list[Finding],
) -> None:
    for ref in references:
        for target in ref.targets:
            if not repository.exists(target):
                severity = (
                    Severity.WARNING if ref.ignore_missing else Severity.ERROR
                )
                findings.append(
                    Finding(
                        code="template.missing",
                        severity=severity,
                        message=(
                            f"{ref.kind.value} target '{target}' from "
                            f"'{ref.source}' is not present in the repository"
                        ),
                        template=ref.source,
                        lineno=ref.lineno,
                        reference=ref,
                    )
                )
            elif target not in allowed_set:
                findings.append(
                    Finding(
                        code="target.not_allowed",
                        severity=Severity.ERROR,
                        message=(
                            f"{ref.kind.value} target '{target}' referenced by "
                            f"'{ref.source}' is not on the allow-list"
                        ),
                        template=ref.source,
                        lineno=ref.lineno,
                        reference=ref,
                    )
                )


def _check_holds(
    references: list[Reference],
    findings: list[Finding],
) -> None:
    for ref in references:
        if not ref.is_unknown:
            continue
        findings.append(
            Finding(
                code="reference.unbounded",
                severity=Severity.HOLD,
                message=(
                    f"{ref.kind.value} in '{ref.source}' line {ref.lineno} "
                    f"uses expression {ref.expression} that cannot be bounded "
                    f"offline: {ref.unknown_reason}"
                ),
                template=ref.source,
                lineno=ref.lineno,
                reference=ref,
            )
        )


def _check_closure_allowed(
    entry: str,
    closure: set[str],
    allowed_set: set[str],
    repository: TemplateRepository,
    findings: list[Finding],
) -> None:
    for name in sorted(closure):
        if name == entry or name in allowed_set or not repository.exists(name):
            continue
        findings.append(
            Finding(
                code="closure.not_allowed",
                severity=Severity.ERROR,
                message=(
                    f"template '{name}' is transitively reachable from "
                    f"'{entry}' but is not on the allow-list"
                ),
                template=name,
            )
        )


def _check_approval(
    entry: str,
    approval: Approval | None,
    repository: TemplateRepository,
    closure: set[str],
    references: list[Reference],
    findings: list[Finding],
) -> None:
    if approval is None:
        findings.append(
            Finding(
                code="approval.missing",
                severity=Severity.ERROR,
                message=f"no recorded approval for entry '{entry}'",
                template=entry,
            )
        )
        return

    if approval.entry != entry:
        findings.append(
            Finding(
                code="approval.entry_mismatch",
                severity=Severity.ERROR,
                message=(
                    f"approval was issued for '{approval.entry}', "
                    f"not for '{entry}'"
                ),
                template=entry,
            )
        )
        return

    for name in _stale_versions(approval, repository, closure):
        findings.append(
            Finding(
                code="approval.stale",
                severity=Severity.ERROR,
                message=(
                    f"approval is invalid: content of '{name}' changed "
                    "since the review; re-review the closure and issue a new approval"
                ),
                template=name,
            )
        )

    for name in sorted(set(approval.versions) - closure):
        findings.append(
            Finding(
                code="approval.orphan",
                severity=Severity.WARNING,
                message=(
                    f"approval pins '{name}' which is no longer reachable; "
                    "issue a fresh approval for the current closure"
                ),
                template=name,
            )
        )


def _stale_versions(
    approval: Approval,
    repository: TemplateRepository,
    closure: set[str],
) -> list[str]:
    stale: list[str] = []
    for name in sorted(closure):
        if not repository.exists(name):
            continue
        expected = approval.versions.get(name)
        if expected is None:
            stale.append(name)
            continue
        if not repository.exists(name) or repository.version_of(name) != expected:
            stale.append(name)
    return stale


SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.WARNING: 1,
    Severity.HOLD: 2,
    Severity.ERROR: 3,
}


def _final_decision(findings: list[Finding]) -> Decision:
    worst = max(
        (f.severity for f in findings),
        key=lambda severity: SEVERITY_ORDER[severity],
        default=Severity.INFO,
    )
    if worst is Severity.ERROR:
        return Decision.REJECT
    if worst is Severity.HOLD:
        return Decision.HOLD
    return Decision.RELEASE
