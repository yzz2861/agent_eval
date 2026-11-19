from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dissect.cstruct.discriminator.evidence import build_evidence_plan
from dissect.cstruct.discriminator.exceptions import TruncatedRead
from dissect.cstruct.discriminator.io import ReadCache
from dissect.cstruct.discriminator.model import (
    CandidateStatus,
    DiscriminationOutcome,
    DiscriminationResult,
    Verdict,
    Violation,
)

if TYPE_CHECKING:
    from collections.abc import BinaryIO, Sequence

    from dissect.cstruct.discriminator.io import ByteWindow
    from dissect.cstruct.discriminator.model import EvidencePlan, SchemaSpec

LOG = logging.getLogger(__name__)


@dataclass(slots=True)
class _Context:
    """Per-candidate scratch space.

    Each candidate receives its own instance, so parsed field state can never
    leak between candidates. Only raw byte reads go through the shared cache.
    """

    schema: SchemaSpec
    cache: ReadCache
    values: dict[str, int | bytes] = field(default_factory=dict)
    pending: set[str] = field(default_factory=set)

    def value(self, name: str) -> int | bytes:
        if name in self.values:
            return self.values[name]
        spec = self.schema.field(name)
        try:
            raw = self.cache.read(spec.offset, spec.size)
        except TruncatedRead:
            self.pending.add(name)
            raise
        parsed = spec.parse(raw)
        self.values[name] = parsed
        return parsed

    def bytes_for(self, offset: int, size: int) -> bytes:
        return self.cache.read(offset, size)


def _check_fields(ctx: _Context) -> tuple[list[Violation], bool]:
    violations: list[Violation] = []
    had_unknown = False
    for spec in ctx.schema.fields:
        if spec.constraint is None:
            continue
        try:
            observed = ctx.value(spec.name)
        except TruncatedRead as err:
            had_unknown = True
            LOG.debug("candidate %s: field %s unreadable: %s", ctx.schema.name, spec.name, err)
            continue
        if not spec.constraint.matches(observed):
            violations.append(
                Violation(
                    kind="field",
                    name=spec.name,
                    reason=f"constraint {spec.constraint.describe()} violated, observed {observed!r}",
                    span=(spec.span,),
                    observed=observed,
                )
            )
    return violations, had_unknown


def _check_invariants(ctx: _Context) -> tuple[list[Violation], bool]:
    violations: list[Violation] = []
    had_unknown = False
    for invariant in ctx.schema.invariants:
        try:
            outcome = invariant.check(ctx)
        except TruncatedRead as err:
            had_unknown = True
            ctx.pending.add(invariant.name)
            LOG.debug("candidate %s: invariant %s unreadable: %s", ctx.schema.name, invariant.name, err)
            continue
        except Exception as err:
            violations.append(
                Violation(
                    kind="invariant",
                    name=invariant.name,
                    reason=f"raised {type(err).__name__}: {err}",
                    span=tuple(invariant.evidence_spans(ctx)),
                )
            )
            continue
        if outcome.violated:
            violations.append(
                Violation(
                    kind="invariant",
                    name=invariant.name,
                    reason=outcome.reason,
                    span=tuple(invariant.evidence_spans(ctx)),
                )
            )
        elif outcome.unknown:
            had_unknown = True
            ctx.pending.add(invariant.name)
    return violations, had_unknown


def evaluate_candidate(schema: SchemaSpec, window: ByteWindow, cache: ReadCache | None = None) -> Verdict:
    """Evaluate one candidate against the readable window.

    Parsing success is never treated as semantic correctness: a schema that
    decodes but violates a declared invariant is excluded. Missing bytes yield
    ``PENDING`` rather than a guess, and every check still runs, so one failed
    check cannot mask the others.
    """
    cache = cache if cache is not None else ReadCache(window)
    ctx = _Context(schema=schema, cache=cache)
    field_violations, field_unknown = _check_fields(ctx)
    invariant_violations, invariant_unknown = _check_invariants(ctx)
    violations = field_violations + invariant_violations
    if violations:
        return Verdict(schema_name=schema.name, status=CandidateStatus.EXCLUDED, violations=tuple(violations))
    if field_unknown or invariant_unknown:
        return Verdict(schema_name=schema.name, status=CandidateStatus.PENDING)
    return Verdict(schema_name=schema.name, status=CandidateStatus.CONFIRMED)


def _classify(verdicts: Sequence[Verdict]) -> DiscriminationOutcome:
    surviving = [verdict for verdict in verdicts if verdict.status is not CandidateStatus.EXCLUDED]
    if not surviving:
        return DiscriminationOutcome.ALL_FAILED
    if len(surviving) == 1 and surviving[0].status is CandidateStatus.CONFIRMED:
        return DiscriminationOutcome.UNIQUE_MATCH
    return DiscriminationOutcome.AMBIGUOUS


def discriminate(
    candidates: Sequence[SchemaSpec],
    source: bytes | ByteWindow | BinaryIO,
    *,
    window_size: int | None = None,
) -> DiscriminationResult:
    """Discriminate between version-less firmware record schemas.

    The decision uses the caller-declared structural invariants and the bytes
    actually readable from ``source``. The result is independent of candidate
    order: candidates are processed in name order and selection is driven only
    by verdicts. Returns ``UNIQUE_MATCH``, ``AMBIGUOUS`` (with a minimum
    evidence plan and the byte ranges still missing) or ``ALL_FAILED`` (with a
    concrete violation per candidate).
    """
    from dissect.cstruct.discriminator.io import ByteWindow

    window = source if isinstance(source, ByteWindow) else ByteWindow(source, window_size)
    ordered = sorted(candidates, key=lambda schema: schema.name)
    cache = ReadCache(window)

    contexts: dict[str, _Context] = {}
    verdicts: list[Verdict] = []
    for schema in ordered:
        ctx = _Context(schema=schema, cache=cache)
        contexts[schema.name] = ctx
        field_violations, field_unknown = _check_fields(ctx)
        invariant_violations, invariant_unknown = _check_invariants(ctx)
        violations = field_violations + invariant_violations
        if violations:
            status = CandidateStatus.EXCLUDED
        elif field_unknown or invariant_unknown:
            status = CandidateStatus.PENDING
        else:
            status = CandidateStatus.CONFIRMED
        verdicts.append(Verdict(schema_name=schema.name, status=status, violations=tuple(violations)))

    outcome = _classify(verdicts)
    plan: EvidencePlan | None = None
    if outcome is DiscriminationOutcome.AMBIGUOUS:
        survivors = [
            schema
            for schema, verdict in zip(ordered, verdicts, strict=True)
            if verdict.status is not CandidateStatus.EXCLUDED
        ]
        plan = build_evidence_plan(survivors, contexts, cache)

    return DiscriminationResult(
        outcome=outcome,
        verdicts=tuple(verdicts),
        evidence_plan=plan,
        cache_stats=cache.stats(),
    )
