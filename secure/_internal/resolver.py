from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
import logging
from types import MappingProxyType
from typing import TYPE_CHECKING

from ..headers.base_header import BaseHeader
from .constants import COMMA_JOIN_OK, MULTI_OK
from .normalize import validate_header_name, validate_header_pair

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from .types import HeaderEffect, HeaderItems, HeaderPair, OnConflictPolicy, OnInvalidPolicy

HEADER_PAIR_SIZE = 2


class PolicyConflictError(ValueError):
    """Raised when layered policies cannot be merged for a single-valued header."""

    def __init__(self, diagnostics: Sequence[PolicyDiagnostic]) -> None:
        self.diagnostics = tuple(diagnostics)
        summary = "; ".join(diagnostic.message for diagnostic in self.diagnostics)
        super().__init__(f"Unresolvable header policy conflict(s): {summary}")


@dataclass(frozen=True)
class PolicyEntry:
    """A single allow/deny rule from one policy layer."""

    name: str
    value: str = ""
    effect: HeaderEffect = "allow"
    source: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise TypeError("PolicyEntry name must be a non-empty string")
        if not isinstance(self.value, str):
            raise TypeError("PolicyEntry value must be a string")
        if self.effect not in ("allow", "deny"):
            raise ValueError("PolicyEntry effect must be 'allow' or 'deny'")

    @classmethod
    def allow(cls, name: str, value: str, *, source: str = "") -> PolicyEntry:
        """Create an explicit allow entry."""
        return cls(name=name, value=value, effect="allow", source=source)

    @classmethod
    def deny(cls, name: str, *, source: str = "") -> PolicyEntry:
        """Create an explicit deny entry (the header must not be emitted)."""
        return cls(name=name, value="", effect="deny", source=source)


@dataclass(frozen=True)
class PolicyLayer:
    """
    One policy layer carrying a source identifier and an explicit priority.

    Higher ``priority`` values win. Layers with equal priority are treated as
    part of the same precedence band; conflicting single-valued headers inside
    one band are reported instead of silently taking the last value.
    """

    source: str
    priority: int
    entries: tuple[PolicyEntry, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.source, str) or not self.source:
            raise TypeError("PolicyLayer source must be a non-empty string")
        if not isinstance(self.priority, int):
            raise TypeError("PolicyLayer priority must be an int")
        object.__setattr__(self, "entries", tuple(self.entries))

    @classmethod
    def from_headers(
        cls,
        source: str,
        priority: int,
        headers: Iterable[BaseHeader | HeaderPair | PolicyEntry],
    ) -> PolicyLayer:
        """Build a layer from header builders, ``(name, value)`` pairs, or entries."""
        entries = tuple(_coerce_entry(header, source=source) for header in headers)
        return cls(source=source, priority=priority, entries=entries)


@dataclass(frozen=True)
class HeaderOrigin:
    """Provenance record for one emitted header line."""

    source: str
    priority: int
    effect: HeaderEffect
    value: str = ""


@dataclass(frozen=True)
class PolicyDiagnostic:
    """Human-readable description of a conflict encountered while resolving."""

    header: str
    message: str
    origins: tuple[HeaderOrigin, ...] = ()


@dataclass(frozen=True)
class ResolvedPolicy:
    """
    Immutable snapshot of headers effective for a single request.

    The snapshot copies every emitted string, so later mutation of the source
    layers or header builders cannot change it. Instances are safe to share
    across threads and across a configuration reload boundary.
    """

    items: HeaderItems
    origins: Mapping[str, tuple[HeaderOrigin, ...]]
    diagnostics: tuple[PolicyDiagnostic, ...] = ()
    layers: tuple[PolicyLayer, ...] = ()

    @property
    def header_items(self) -> HeaderItems:
        """Immutable ``(name, value)`` pairs, one per emitted header line."""
        return self.items

    @property
    def headers(self) -> Mapping[str, str]:
        """Single-valued immutable mapping; raises if a header has multiple lines."""
        mapping: dict[str, str] = {}
        seen: set[str] = set()
        for name, value in self.items:
            lowered = name.lower()
            if lowered in seen:
                raise ValueError(f"Multiple '{name}' headers present; use `header_items` when emitting multiples.")
            seen.add(lowered)
            mapping[name] = value
        return MappingProxyType(mapping)


@dataclass(frozen=True)
class _Candidate:
    entry: PolicyEntry
    layer_index: int
    order: int


@dataclass
class _Accumulator:
    display_name: str
    first_seen: int
    allows: list[_Candidate] = field(default_factory=list)
    denies: list[_Candidate] = field(default_factory=list)


class PolicyResolver:
    """
    Resolve layered header policies into one immutable :class:`ResolvedPolicy`.

    Each input :class:`PolicyLayer` carries its own source identifier and
    priority. Single-valued headers are decided by priority (an explicit deny
    at the highest precedence suppresses lower-priority allows), multi-valued
    headers follow their declared merge rule, and unresolvable conflicts
    produce readable diagnostics instead of silently taking the last value.
    """

    def __init__(  # noqa: PLR0913
        self,
        *,
        multi_ok: Iterable[str] = MULTI_OK,
        comma_join_ok: Iterable[str] = COMMA_JOIN_OK,
        on_conflict: OnConflictPolicy = "raise",
        on_invalid: OnInvalidPolicy = "raise",
        strict: bool = True,
        allow_obs_text: bool = False,
        logger: logging.Logger | None = None,
    ) -> None:
        self._multi_ok = frozenset(name.lower() for name in multi_ok)
        self._comma_join_ok = frozenset(name.lower() for name in comma_join_ok)
        self._on_conflict: OnConflictPolicy = on_conflict
        self._on_invalid: OnInvalidPolicy = on_invalid
        self._strict = strict
        self._allow_obs_text = allow_obs_text
        self._logger = logger or logging.getLogger(__name__)

    def resolve(self, layers: Iterable[PolicyLayer]) -> ResolvedPolicy:
        """Merge ``layers`` into an immutable resolved snapshot."""
        frozen_layers = tuple(layers)
        self._validate_layers(frozen_layers)

        accumulators: OrderedDict[str, _Accumulator] = OrderedDict()
        global_order = 0

        for layer_index, layer in enumerate(frozen_layers):
            for entry in layer.entries:
                validated = self._validate_entry(entry)
                if validated is None:
                    continue
                name, value = validated
                lowered = name.lower()
                accumulator = accumulators.get(lowered)
                if accumulator is None:
                    accumulator = _Accumulator(display_name=name, first_seen=global_order)
                    accumulators[lowered] = accumulator
                candidate = _Candidate(
                    entry=PolicyEntry(
                        name=name,
                        value=value,
                        effect=entry.effect,
                        source=entry.source or layer.source,
                    ),
                    layer_index=layer_index,
                    order=global_order,
                )
                if entry.effect == "deny":
                    accumulator.denies.append(candidate)
                else:
                    accumulator.allows.append(candidate)
                global_order += 1

        return self._build_snapshot(frozen_layers, accumulators)

    # Kept as an explicit alias so callers can name the operation they mean.
    merge = resolve

    def _validate_layers(self, layers: tuple[PolicyLayer, ...]) -> None:
        for layer in layers:
            if not isinstance(layer, PolicyLayer):
                raise TypeError("PolicyResolver.resolve() expects PolicyLayer instances")

    def _validate_entry(self, entry: PolicyEntry) -> HeaderPair | None:
        if entry.effect == "deny":
            validated_name = validate_header_name(
                entry.name,
                on_invalid=self._on_invalid,
                logger=self._logger,
            )
            if validated_name is None:
                return None
            return validated_name, ""

        return validate_header_pair(
            entry.name,
            entry.value,
            on_invalid=self._on_invalid,
            strict=self._strict,
            allow_obs_text=self._allow_obs_text,
            logger=self._logger,
        )

    def _build_snapshot(
        self,
        layers: tuple[PolicyLayer, ...],
        accumulators: Mapping[str, _Accumulator],
    ) -> ResolvedPolicy:
        items: list[HeaderPair] = []
        origins: dict[str, tuple[HeaderOrigin, ...]] = {}
        diagnostics: list[PolicyDiagnostic] = []

        ordered_accumulators = sorted(accumulators.values(), key=lambda acc: acc.first_seen)

        for accumulator in ordered_accumulators:
            name = accumulator.display_name
            lowered = name.lower()
            highest_priority = self._top_priority(accumulator, layers)
            top_denies = [
                candidate for candidate in accumulator.denies if self._priority(candidate, layers) == highest_priority
            ]

            if top_denies:
                origins[lowered] = tuple(self._origin(candidate, layers) for candidate in top_denies)
                continue

            effective_deny_priority = max(
                (self._priority(candidate, layers) for candidate in accumulator.denies),
                default=None,
            )
            surviving_allows = [
                candidate
                for candidate in accumulator.allows
                if effective_deny_priority is None or self._priority(candidate, layers) > effective_deny_priority
            ]
            winners = sorted(surviving_allows, key=lambda candidate: candidate.order)
            if not winners:
                continue

            highest_allow_priority = max(self._priority(candidate, layers) for candidate in winners)
            if lowered not in self._multi_ok and lowered not in self._comma_join_ok:
                winners = [
                    candidate for candidate in winners if self._priority(candidate, layers) == highest_allow_priority
                ]

            emitted, diagnostic = self._merge_winners(
                lowered,
                name,
                winners,
                layers,
                top_priority=highest_allow_priority,
            )

            if diagnostic is not None:
                diagnostics.append(diagnostic)
                if self._on_conflict == "raise":
                    raise PolicyConflictError([diagnostic])
                continue

            if emitted:
                items.extend(emitted)
                origins[lowered] = tuple(self._origin(candidate, layers) for candidate in winners)

        return ResolvedPolicy(
            items=tuple(items),
            origins=MappingProxyType(origins),
            diagnostics=tuple(diagnostics),
            layers=layers,
        )

    def _merge_winners(
        self,
        lowered_name: str,
        display_name: str,
        winners: Sequence[_Candidate],
        layers: Sequence[PolicyLayer],
        *,
        top_priority: int,
    ) -> tuple[list[HeaderPair], PolicyDiagnostic | None]:
        unique_values = list(dict.fromkeys(candidate.entry.value for candidate in winners))

        if len(unique_values) == 1:
            return [(display_name, unique_values[0])], None

        if lowered_name in self._multi_ok:
            return [(display_name, value) for value in unique_values], None

        if lowered_name in self._comma_join_ok:
            return [(display_name, ", ".join(unique_values))], None

        top_winners = [candidate for candidate in winners if self._priority(candidate, layers) == top_priority]
        top_values = list(dict.fromkeys(candidate.entry.value for candidate in top_winners))
        if len(top_values) == 1:
            return [(display_name, top_values[0])], None

        diagnostic = PolicyDiagnostic(
            header=display_name,
            message=(
                f"Conflicting policies for {display_name!r} at priority {top_priority}: "
                + " vs ".join(repr(value) for value in top_values)
                + ". Declare the header in multi_ok/comma_join_ok, align the values, or use an explicit deny."
            ),
            origins=tuple(self._origin(candidate, layers) for candidate in top_winners),
        )
        return [], diagnostic

    @staticmethod
    def _priority(candidate: _Candidate, layers: Sequence[PolicyLayer]) -> int:
        return layers[candidate.layer_index].priority

    @staticmethod
    def _top_priority(accumulator: _Accumulator, layers: Sequence[PolicyLayer]) -> int:
        candidates = [*accumulator.allows, *accumulator.denies]
        return max(PolicyResolver._priority(candidate, layers) for candidate in candidates)

    @staticmethod
    def _origin(candidate: _Candidate, layers: Sequence[PolicyLayer]) -> HeaderOrigin:
        layer = layers[candidate.layer_index]
        return HeaderOrigin(
            source=candidate.entry.source,
            priority=layer.priority,
            effect=candidate.entry.effect,
            value=candidate.entry.value,
        )


def _coerce_entry(header: BaseHeader | HeaderPair | PolicyEntry, *, source: str) -> PolicyEntry:
    if isinstance(header, PolicyEntry):
        return header

    if isinstance(header, BaseHeader):
        return PolicyEntry(
            name=header.header_name,
            value=header.header_value,
            effect="allow",
            source=source,
        )

    if isinstance(header, tuple | list) and len(header) == HEADER_PAIR_SIZE:
        name, value = header
        if isinstance(name, str) and isinstance(value, str):
            return PolicyEntry(name=name, value=value, effect="allow", source=source)

    raise TypeError("PolicyLayer expects BaseHeader objects, (name, value) pairs, or PolicyEntry instances")
