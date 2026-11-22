"""Caller-supplied, type-tagged path rules.

A rule is the dotted ijson *prefix* of a value (for example
``batches.item.records.item.risk_level``) together with the JSON type the
value is required to have. The type tag doubles as the event contract: a
present value whose event type differs from the tag is a type mismatch rather
than a silent pass.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence, Union

#: ijson leaf event names accepted as type tags. ``map_key`` and the
#: container start/end events are structural, not value types, and are
#: deliberately excluded.
LEAF_TYPES = frozenset(
    {"null", "boolean", "number", "string"}
)

#: Container rules may instead require a value to be a map or array.
CONTAINER_TYPES = frozenset({"map", "array"})

TYPE_TAGS = LEAF_TYPES | CONTAINER_TYPES

#: Friendly aliases so callers can write ``"str"`` / ``"int"`` if they prefer.
TYPE_ALIASES = {
    "str": "string",
    "string": "string",
    "int": "number",
    "float": "number",
    "number": "number",
    "bool": "boolean",
    "boolean": "boolean",
    "null": "null",
    "object": "map",
    "map": "map",
    "dict": "map",
    "array": "array",
    "list": "array",
}

#: Event name emitted when a container of the tagged type opens.
CONTAINER_START_EVENT = {"map": "start_map", "array": "start_array"}

#: Event name emitted when a container of the tagged type closes.
CONTAINER_END_EVENT = {"map": "end_map", "array": "end_array"}


@dataclass(frozen=True)
class Rule:
    """A normalized rule: dotted prefix plus a validated JSON type tag."""

    name: str
    prefix: str
    type_tag: str

    def __post_init__(self) -> None:
        if not self.prefix:
            raise ValueError("rule prefix must not be empty")
        if self.type_tag not in TYPE_TAGS:
            raise ValueError(
                "unsupported type tag %r; expected one of %s"
                % (self.type_tag, sorted(TYPE_TAGS))
            )


RuleSpec = Union[Rule, Mapping[str, str], Sequence[str]]
"""
Accepted caller shapes for a single rule:

* a :class:`Rule`;
* a mapping with ``name``/``prefix``/``type`` (``name`` and ``type``
  optional);
* a sequence ``[prefix, type_tag]`` or ``[prefix, type_tag, name]``.
"""


def _coerce_tag(raw_tag: str) -> str:
    tag = TYPE_ALIASES.get(str(raw_tag).lower())
    if tag is None:
        raise ValueError(
            "unsupported type tag %r; expected one of %s"
            % (raw_tag, sorted(TYPE_ALIASES))
        )
    return tag


def normalize_rules(specs: Sequence[RuleSpec]) -> list[Rule]:
    """Normalize every accepted rule shape into a frozen :class:`Rule`."""
    rules: list[Rule] = []
    seen_names: set[str] = set()
    for index, spec in enumerate(specs):
        if isinstance(spec, Rule):
            rule = spec
        elif isinstance(spec, Mapping):
            prefix = spec["prefix"]
            tag = _coerce_tag(spec.get("type", "string"))
            name = spec.get("name") or prefix
            rule = Rule(name=name, prefix=prefix, type_tag=tag)
        elif isinstance(spec, (list, tuple)):
            if len(spec) == 2:
                prefix, raw_tag = spec
                name = prefix
            elif len(spec) == 3:
                prefix, raw_tag, name = spec
            else:
                raise ValueError(
                    "sequence rule %d must be [prefix, type] or "
                    "[prefix, type, name]" % index
                )
            rule = Rule(name=name, prefix=prefix, type_tag=_coerce_tag(raw_tag))
        else:
            raise TypeError(
                "rule %d has unsupported shape %r" % (index, type(spec))
            )
        if rule.name in seen_names:
            raise ValueError("duplicate rule name %r" % rule.name)
        seen_names.add(rule.name)
        rules.append(rule)
    if not rules:
        raise ValueError("at least one rule is required")
    return rules


# --- observer-facing compiled view ---------------------------------------


@dataclass(frozen=True)
class CallerRule:
    """Rule expanded into the prefix pieces the event observer matches on."""

    rule_id: str
    path: str
    expected_types: tuple
    container_prefix: str
    key: object


def compile_rules(specs):
    """Normalize caller rules and pre-split each ijson dotted prefix."""
    compiled = []
    for rule in normalize_rules(specs):
        segments = tuple(segment for segment in rule.prefix.split(".") if segment)
        if not segments:
            raise ValueError("rule prefix must not be empty")
        key = segments[-1]
        container_prefix = ".".join(segments[:-1])
        compiled.append(
            CallerRule(
                rule_id=rule.name,
                path=rule.prefix,
                expected_types=(rule.type_tag,),
                container_prefix=container_prefix,
                key=key,
            )
        )
    return tuple(compiled)
