from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations
from typing import TYPE_CHECKING

from dissect.cstruct.discriminator.model import EvidenceItem, EvidencePlan

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from dissect.cstruct.discriminator.engine import _Context
    from dissect.cstruct.discriminator.io import ReadCache
    from dissect.cstruct.discriminator.model import SchemaSpec


@dataclass(slots=True)
class _Group:
    """One evidence location with each candidate asserted constraint text."""

    key: str
    span: tuple[int, int]
    descriptors: dict[str, str]

    @property
    def size(self) -> int:
        return self.span[1] - self.span[0]

    def distinguishes(self, pair: tuple[str, str]) -> bool:
        left, right = pair
        if left not in self.descriptors or right not in self.descriptors:
            return False
        return self.descriptors[left] != self.descriptors[right]


def _field_groups(schemas: Sequence[SchemaSpec]) -> list[_Group]:
    grouped: dict[tuple[int, int], _Group] = {}
    for schema in schemas:
        for spec in schema.fields:
            if spec.constraint is None:
                continue
            group = grouped.setdefault(
                spec.span,
                _Group(key=f"field:{spec.name}", span=spec.span, descriptors={}),
            )
            group.descriptors[schema.name] = spec.constraint.describe()
    return list(grouped.values())


def _invariant_groups(schemas: Sequence[SchemaSpec], contexts: Mapping[str, _Context]) -> list[_Group]:
    groups: list[_Group] = []
    for schema in schemas:
        ctx = contexts[schema.name]
        for invariant in schema.invariants:
            spans = invariant.evidence_spans(ctx)
            span = spans[0] if spans else (0, 0)
            existing = next(
                (group for group in groups if group.key == f"invariant:{invariant.name}"),
                None,
            )
            if existing is None:
                existing = _Group(
                    key=f"invariant:{invariant.name}",
                    span=span,
                    descriptors={},
                )
                groups.append(existing)
            existing.descriptors[schema.name] = invariant.describe()
    return groups


def _pairs(schemas: Sequence[SchemaSpec]) -> list[tuple[str, str]]:
    names = sorted(schema.name for schema in schemas)
    return list(combinations(names, 2))


def _missing(span: tuple[int, int], cache: ReadCache) -> tuple[tuple[int, int], ...]:
    return cache.missing(span[0], span[1] - span[0])


def _readable_missing(span: tuple[int, int], cache: ReadCache) -> tuple[tuple[int, int], ...]:
    missing = _missing(span, cache)
    return tuple((start, min(end, cache.readable_length)) for start, end in missing if start < cache.readable_length)


def _rank(group: _Group, cache: ReadCache) -> tuple:
    # When bytes are missing, prefer evidence a follow-up read can settle; for
    # fully readable windows prefer the smallest, earliest evidence. The final
    # tie-break is a stable key, never candidate order.
    fetchable = bool(_readable_missing(group.span, cache))
    return (0 if fetchable else 1, group.size, group.span[0], group.key)


def _covers(groups: Sequence[_Group], pairs: Sequence[tuple[str, str]]) -> bool:
    return all(any(group.distinguishes(pair) for group in groups) for pair in pairs)


def _merge(ranges: Sequence[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return tuple(merged)


def _make_item(
    group: _Group,
    cache: ReadCache,
    pairs: Sequence[tuple[str, str]],
    involved: tuple[str, ...],
) -> EvidenceItem:
    item_missing = _missing(group.span, cache)
    return EvidenceItem(
        key=group.key,
        span=group.span,
        constraints=dict(sorted(group.descriptors.items())),
        distinguishes=tuple(pair for pair in pairs if group.distinguishes(pair)),
        missing_ranges=item_missing,
        involved_candidates=involved,
        readable_missing_ranges=_readable_missing(group.span, cache),
    )


def _plan_for_pending(schema: SchemaSpec, ctx: _Context, cache: ReadCache) -> EvidencePlan:
    """Plan for a single pending survivor: list the evidence still missing."""
    items: list[EvidenceItem] = []
    missing: list[tuple[int, int]] = []
    readable_missing: list[tuple[int, int]] = []
    for spec in schema.fields:
        if spec.name not in ctx.pending or spec.constraint is None:
            continue
        group = _Group(
            key=f"field:{spec.name}",
            span=spec.span,
            descriptors={schema.name: spec.constraint.describe()},
        )
        item = _make_item(group, cache, (), (schema.name,))
        items.append(item)
        missing.extend(item.missing_ranges)
        readable_missing.extend(item.readable_missing_ranges)
    for invariant in schema.invariants:
        if invariant.name not in ctx.pending:
            continue
        for span in invariant.evidence_spans(ctx):
            group = _Group(
                key=f"invariant:{invariant.name}",
                span=span,
                descriptors={schema.name: invariant.describe()},
            )
            item = _make_item(group, cache, (), (schema.name,))
            items.append(item)
            missing.extend(item.missing_ranges)
            readable_missing.extend(item.readable_missing_ranges)
    return EvidencePlan(
        items=tuple(items),
        missing_ranges=_merge(missing),
        resolvable=bool(items),
        intrinsic=False,
        readable_missing_ranges=_merge(readable_missing),
    )


def build_evidence_plan(
    survivors: Sequence[SchemaSpec],
    contexts: Mapping[str, _Context],
    cache: ReadCache,
) -> EvidencePlan:
    """Compute the minimum evidence set separating the surviving candidates."""
    if len(survivors) == 1:
        return _plan_for_pending(survivors[0], contexts[survivors[0].name], cache)

    pairs = _pairs(survivors)
    groups = sorted(
        _field_groups(survivors) + _invariant_groups(survivors, contexts),
        key=lambda group: _rank(group, cache),
    )
    discriminating = [group for group in groups if any(group.distinguishes(pair) for pair in pairs)]

    minimum: list[_Group] = []
    for width in range(1, len(discriminating) + 1):
        for combo in combinations(discriminating, width):
            if _covers(combo, pairs):
                minimum = list(combo)
                break
        if minimum:
            break

    items: list[EvidenceItem] = []
    missing: list[tuple[int, int]] = []
    readable_missing: list[tuple[int, int]] = []
    for group in minimum:
        item = _make_item(
            group,
            cache,
            pairs,
            tuple(sorted(group.descriptors)),
        )
        items.append(item)
        missing.extend(item.missing_ranges)
        readable_missing.extend(item.readable_missing_ranges)

    # Intrinsic ambiguity requires every distinguishing evidence location to be
    # fully readable already; any fetchable gap means more bytes can decide.
    intrinsic = bool(minimum) and all(item.fully_readable for item in items)
    return EvidencePlan(
        items=tuple(items),
        missing_ranges=_merge(missing),
        resolvable=bool(minimum),
        intrinsic=intrinsic,
        readable_missing_ranges=_merge(readable_missing),
    )
