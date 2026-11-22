"""Entity merge reconciliation for STIX object identifiers.

STIX producers frequently represent the same real-world entity with different
object identifiers.  Offline archiving often requires deciding which of those
identifiers may be treated as one entity, while honouring explicit
"these two are different" constraints (for example a legal hold).

This module deliberately separates two ideas:

* **Evidence** says that two identifiers *may* denote the same entity.  Merge
  evidence is an equivalence relation: it is symmetric and transitive.  It is
  defeasible by default, because intelligence reporting is often incomplete or
  contradictory.
* **Separation** is a hard constraint.  Two identifiers marked as separate may
  never be placed in the same equivalence class.  Separations propagate through
  merge classes: if ``A`` merges with ``B`` and ``A`` is separate from ``C``,
  then ``B`` is necessarily separate from ``C`` too.

A set of merge evidence may be inconsistent with a set of separations.  For
example, ``A ~ B`` and ``B ~ C`` together imply ``A ~ C``, which contradicts an
explicit ``A !~ C``.  In that case :func:`reconcile_entity_merges` reports the
smallest conflicting sets of assertions and all maximal compatible groupings.
It does not silently pick one grouping.  Pairs for which there is neither
positive nor negative evidence are reported as undetermined.

The module accepts plain identifiers as well as STIX objects and can read
equivalence evidence from STIX ``Relationship`` objects, JSON documents, and
explicit positive/negative collections.  See
:func:`reconcile_entity_merges` for the main entry point.
"""

from __future__ import annotations

import argparse
import collections
import dataclasses
import itertools
import json
import os
import re
import sys


__all__ = [
    "Assertion",
    "EntityMergeReconciler",
    "assertions_from_objects",
    "assertions_from_stix",
    "check_consistency",
    "check_merge_consistency",
    "analyse_merges",
    "analyze_merges",
    "compatible_groups",
    "compatible_partitions",
    "entity_groups",
    "entity_merge_reconciliation",
    "equivalence_evidence_from_objects",
    "evidence_from_similarity",
    "evidence_from_stix",
    "find_conflicts",
    "find_minimal_conflicts",
    "group_entities",
    "load_evidence",
    "merge_entities",
    "minimal_conflicts",
    "reconcile_entities",
    "reconcile_entity_merges",
    "read_evidence",
    "reconcile_merges",
    "resolve_entity_merges",
    "resolve_merges",
    "similarity_evidence",
]


_POSITIVE_RELATIONS = {
    "=",
    "==",
    "~",
    "alias",
    "alias-of",
    "co-referent",
    "coreferent",
    "duplicate",
    "duplicate-of",
    "equal",
    "equals",
    "equivalence",
    "equivalent",
    "equivalent-to",
    "identifies",
    "identical",
    "merge",
    "merged",
    "merged-from",
    "same",
    "same-as",
    "same-entity",
    "same-object",
    "positive",
    "support",
    "supported",
    "same_as",
    "equivalent_to",
}

_NEGATIVE_RELATIONS = {
    "!=",
    "!~",
    "<>",
    "cannot-merge",
    "cannot_merge",
    "different",
    "different-from",
    "disjoint",
    "distinct",
    "distinct-from",
    "do-not-merge",
    "exclude",
    "excluded",
    "forbidden",
    "not-equal",
    "not-equivalent",
    "not-same",
    "not-same-as",
    "not_same",
    "negative",
    "non-equivalent",
    "separate",
    "separate-from",
    "separated",
    "separation",
    "conflict",
    "no",
    "false",
}

_GLOBAL_PURPOSES = {None, "", "*", "all", "any", "global"}

_LEFT_KEYS = (
    "left", "lhs", "source_ref", "source", "from", "a", "object1", "id1",
    "first", "subject", "entity1", "x_left", "left_id", "id_a", "a_id",
    "first_id", "entity_a", "left_object", "source_id", "from_id", "object_ref1",
)
_RIGHT_KEYS = (
    "right", "rhs", "target_ref", "target", "to", "b", "object2", "id2",
    "second", "entity2", "x_right", "right_id", "object", "id_b", "b_id",
    "second_id", "entity_b", "right_object", "target_id", "to_id", "object_ref2",
)
_PAIR_KEYS = (
    "pair", "entity_pair", "id_pair", "ids", "entity_ids", "refs",
)
_RELATION_KEYS = (
    "relation", "relationship", "relationship_type", "kind", "polarity",
    "merge_type", "equivalence", "constraint_type", "x_relation", "positive",
    "negative", "same", "different", "separate", "merge", "equivalent",
    "same_entity", "is_same", "is_different", "mergeable", "forbidden",
    "type",
)
_PURPOSE_KEYS = (
    "purpose", "purposes", "use", "usage", "scope", "context", "profile",
    "for", "x_purpose", "use_case", "usage_context", "purpose_set",
)
_WEIGHT_KEYS = (
    "weight", "confidence", "score", "strength", "priority", "x_weight",
    "support_score",
)
_ID_KEYS = ("evidence_id", "assertion_id", "x_id", "id", "uid")

_COLLECTION_KEYS = {
    "evidence": None,
    "assertions": None,
    "constraints": None,
    "merges": True,
    "merge_evidence": True,
    "positive": True,
    "positives": True,
    "positive_constraints": True,
    "supported": True,
    "same": True,
    "separations": False,
    "separates": False,
    "negative": False,
    "negatives": False,
    "negative_constraints": False,
    "separate": False,
    "different": False,
    "cannot_merge": False,
    "forbidden_merges": False,
    "legal_separations": False,
    "equivalences": True,
    "equivalent": True,
    "aliases": True,
    "same_as": True,
    "duplicate_of": True,
    "positive_pairs": True,
    "must_merge": True,
    "allowed_merges": True,
    "non_equivalent": False,
    "distinct": False,
    "excluded": False,
    "forbidden": False,
    "negative_pairs": False,
    "must_not_merge": False,
    "cannot_merge_pairs": False,
}


class _Record(dict):
    """A small dict subclass that also supports attribute access."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def to_dict(self):
        return _plain(self)


def _record(**kwargs):
    return _Record(kwargs)


def _plain(value):
    """Return a JSON-friendly copy of ``value``."""

    if isinstance(value, _Record):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(_plain(item) for item in value)
    return value


def _node_id(value):
    """Coerce an identifier, STIX object, or reference mapping to a string ID."""

    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8")
    if isinstance(value, dict):
        for key in ("id", "identifier", "object_ref", "ref"):
            if key in value and value[key] is not None:
                return _node_id(value[key])
    for attr in ("id", "identifier"):
        attr_value = getattr(value, attr, None)
        if attr_value is not None:
            return _node_id(attr_value)
    return str(value)


def _purpose_set(value):
    """Normalise a purpose/scope value to a frozenset, or None for global."""

    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        if value.lower() in {item for item in _GLOBAL_PURPOSES if item}:
            return None
        return frozenset([value])
    if isinstance(value, (set, frozenset, list, tuple)):
        purposes = set()
        for item in value:
            if item is None:
                return None
            item = str(item).strip()
            if not item:
                continue
            if item.lower() in {entry for entry in _GLOBAL_PURPOSES if entry}:
                return None
            purposes.add(item)
        return frozenset(purposes) if purposes else None
    return frozenset([str(value).strip()])


def _relation_polarity(value):
    """Return True for merge evidence, False for separation, else None."""

    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if not isinstance(value, str):
        return None

    relation = value.strip().lower()
    relation = relation.replace("_", "-").replace(" ", "-")
    if relation.startswith("x-"):
        relation = relation[2:]
    if relation in ("yes", "true"):
        return True
    if relation in ("no", "false"):
        return False
    if relation in _POSITIVE_RELATIONS:
        return True
    if relation in _NEGATIVE_RELATIONS:
        return False
    return None


def _weight(value, default=1.0):
    if value is None:
        return default
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default
    return result if result > 0 else default


def _first(mapping, keys, default=None):
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return default


def _metadata_value(record):
    if isinstance(record, dict):
        return {
            key: value
            for key, value in record.items()
            if key not in _LEFT_KEYS + _RIGHT_KEYS + _RELATION_KEYS
        }
    return {}


@dataclasses.dataclass(frozen=True)
class Assertion:
    """One positive or negative assertion about two entity identifiers."""

    left: str
    right: str
    positive: bool
    purpose: frozenset | None = None
    weight: float = 1.0
    identifier: str = ""
    evidence_ids: tuple = ()
    source: object = None
    metadata: dict = dataclasses.field(default_factory=dict, compare=False, hash=False)

    @property
    def relation(self):
        return "merge" if self.positive else "separate"

    @property
    def pair(self):
        return tuple(sorted((self.left, self.right)))

    def other(self, node):
        return self.right if node == self.left else self.left

    def applies_to(self, purpose=None):
        if self.purpose is None:
            return True
        if purpose is None:
            return True
        return purpose in self.purpose

    def to_dict(self):
        source = self.source
        if not isinstance(source, (str, int, float, bool, dict, list, type(None))):
            source = str(source)
        return _record(
            id=self.identifier,
            evidence_ids=list(self.evidence_ids) or [self.identifier],
            left=self.left,
            right=self.right,
            relation=self.relation,
            positive=self.positive,
            pair=list(self.pair),
            weight=self.weight,
            purpose=sorted(self.purpose) if self.purpose else None,
            source=source,
        )


def _pair_like(value):
    if not isinstance(value, (list, tuple)) or len(value) < 2:
        return False
    if isinstance(value, str):
        return False
    # A pair of evidence records is a collection, not a single assertion.
    for item in value[:2]:
        if isinstance(item, (dict, Assertion, list, tuple, set, frozenset)):
            return False
    return True


_STRING_ASSERTION_RE = re.compile(
    r"^\s*(?P<left>.+?)\s*(?P<op>!~|!=|<>|==|=|~)\s*(?P<right>.+?)"
    r"(?:\s*@\s*(?P<purpose>[^\s#]+))?"
    r"(?:\s*#\s*(?P<weight>[0-9]*\.?[0-9]+))?\s*$",
)


def _coerce_assertion(
    record,
    *,
    default_polarity=None,
    default_purpose=None,
    source=None,
    index=0,
):
    if isinstance(record, Assertion):
        return record

    if isinstance(record, str):
        match = _STRING_ASSERTION_RE.match(record)
        if not match:
            raise ValueError(
                "Cannot interpret %r as an entity merge assertion; expected "
                "'LEFT ~ RIGHT' or 'LEFT != RIGHT'." % (record,)
            )
        polarity = _relation_polarity(match.group("op"))
        if polarity is None:
            polarity = default_polarity
        if polarity is None:
            raise ValueError("Assertion %r does not specify a polarity" % (record,))
        purpose = match.group("purpose") or default_purpose
        return Assertion(
            left=match.group("left"),
            right=match.group("right"),
            positive=polarity,
            purpose=_purpose_set(purpose),
            weight=_weight(match.group("weight")),
            identifier="e%d" % index,
            evidence_ids=("e%d" % index,),
            source=source,
        )

    if isinstance(record, (list, tuple)):
        if len(record) < 2:
            raise ValueError("An assertion pair must contain two identifiers")
        left = _node_id(record[0])
        right = _node_id(record[1])
        payload = {}
        if len(record) >= 3 and record[2] is not None:
            if isinstance(record[2], dict):
                payload.update(record[2])
            elif _relation_polarity(record[2]) is not None:
                payload["relation"] = record[2]
            elif isinstance(record[2], (int, float)) and not isinstance(record[2], bool):
                payload["weight"] = record[2]
            else:
                payload["purpose"] = record[2]
        if len(record) >= 4 and not isinstance(record[2], dict):
            if "purpose" not in payload:
                payload["purpose"] = record[3]
            elif "relation" not in payload and _relation_polarity(record[3]) is not None:
                payload["relation"] = record[3]
            else:
                payload["weight"] = record[3]
        if len(record) >= 5:
            payload["weight"] = record[4]
        return _coerce_assertion(
            dict(payload, left=left, right=right),
            default_polarity=default_polarity,
            default_purpose=default_purpose,
            source=source,
            index=index,
        )

    if not isinstance(record, dict):
        # STIX object-like input: only relationship-like objects carry evidence.
        obj_type = getattr(record, "type", None)
        relationship_type = getattr(record, "relationship_type", None)
        if obj_type == "relationship":
            polarity = _relation_polarity(relationship_type)
            if polarity is None:
                raise ValueError(
                    "Relationship %r has unsupported relationship_type %r"
                    % (getattr(record, "id", None), relationship_type)
                )
            return Assertion(
                left=_node_id(getattr(record, "source_ref")),
                right=_node_id(getattr(record, "target_ref")),
                positive=polarity,
                purpose=_purpose_set(default_purpose),
                weight=1.0,
                identifier=getattr(record, "id", "e%d" % index),
                evidence_ids=(getattr(record, "id", "e%d" % index),),
                source=source,
            )
        raise ValueError("Unsupported assertion record: %r" % (record,))

    obj_type = record.get("type")
    if obj_type == "relationship" and (
        "source_ref" in record or "target_ref" in record or "relationship_type" in record
    ):
        relationship_type = _first(record, _RELATION_KEYS)
        polarity = _relation_polarity(relationship_type)
        if polarity is None:
            polarity = default_polarity
        if polarity is None:
            raise ValueError(
                "Relationship %r has unsupported relationship_type %r"
                % (record.get("id"), relationship_type)
            )
        left = _node_id(_first(record, _LEFT_KEYS))
        right = _node_id(_first(record, _RIGHT_KEYS))
        evidence_id = record.get("id", "e%d" % index)
        return Assertion(
            left=left,
            right=right,
            positive=polarity,
            purpose=_purpose_set(_first(record, _PURPOSE_KEYS, default_purpose)),
            weight=_weight(_first(record, _WEIGHT_KEYS)),
            identifier=evidence_id,
            evidence_ids=(evidence_id,),
            source=record.get("created_by_ref", source),
        )

    left = _first(record, _LEFT_KEYS)
    right = _first(record, _RIGHT_KEYS)
    embedded_pair = _first(record, _PAIR_KEYS)
    if embedded_pair is not None and (left is None or right is None):
        if isinstance(embedded_pair, (str, bytes)) or len(embedded_pair) != 2:
            raise ValueError(
                "An embedded entity pair must contain exactly two identifiers: %r"
                % (embedded_pair,)
            )
        left, right = embedded_pair[0], embedded_pair[1]
    if left is None or right is None:
        # A nested collection is handled by _normalise_evidence; this is an
        # unsupported leaf.
        raise ValueError(
            "Assertion record is missing a left/right identifier: %r" % (record,)
        )

    negative_boolean_keys = {
        "negative", "different", "separate", "distinct", "forbidden",
        "non_equivalent", "is_different",
    }
    polarity = None
    for key in _RELATION_KEYS:
        if key in record:
            value = record[key]
            if isinstance(value, bool) and key in negative_boolean_keys:
                polarity = not value
            else:
                polarity = _relation_polarity(value)
            if polarity is not None:
                break
    if polarity is None:
        for key in ("merge", "same", "identical", "equivalent", "positive", "support"):
            if key in record and isinstance(record[key], bool):
                polarity = record[key]
                break
    if polarity is None:
        for key in ("separate", "different", "distinct", "negative", "exclude"):
            if key in record and isinstance(record[key], bool):
                polarity = not record[key]
                break
    if polarity is None:
        polarity = default_polarity
    if polarity is None:
        raise ValueError(
            "Cannot determine whether %r is merge evidence or a separation"
            % (record,)
        )

    purpose = _first(record, _PURPOSE_KEYS, default_purpose)
    evidence_id = _first(record, _ID_KEYS, "e%d" % index)
    weight_value = _weight(_first(record, _WEIGHT_KEYS))
    return Assertion(
        left=_node_id(left),
        right=_node_id(right),
        positive=polarity,
        purpose=_purpose_set(purpose),
        weight=weight_value,
        identifier=str(evidence_id),
        evidence_ids=(str(evidence_id),),
        source=record.get("source_ref", source),
        metadata=_metadata_value(record),
    )


def _normalise_evidence(
    value,
    *,
    default_polarity=None,
    default_purpose=None,
    source=None,
    index_start=0,
):
    """Normalise many accepted evidence shapes into a list of Assertions."""

    if value is None:
        return []

    if isinstance(value, Assertion):
        return [value]

    if isinstance(value, (str, os.PathLike)):
        if os.path.exists(os.fspath(value)):
            return load_evidence(value, purpose=default_purpose)
        return [
            _coerce_assertion(
                value,
                default_polarity=default_polarity,
                default_purpose=default_purpose,
                source=source,
                index=index_start,
            ),
        ]

    if isinstance(value, dict):
        if value.get("type") == "relationship":
            return [
                _coerce_assertion(
                    value,
                    default_polarity=default_polarity,
                    default_purpose=default_purpose,
                    source=source,
                    index=index_start,
                ),
            ]
        if "objects" in value:
            return assertions_from_stix(value["objects"], purpose=default_purpose)

        collection_keys = [key for key in _COLLECTION_KEYS if key in value]
        has_pair_keys = (
            any(key in value for key in _LEFT_KEYS)
            and any(key in value for key in _RIGHT_KEYS)
        ) or any(key in value for key in _PAIR_KEYS)
        if not has_pair_keys:
            purpose_map = None
            for purpose_key in ("by_purpose", "purposes"):
                candidate = value.get(purpose_key)
                if isinstance(candidate, dict):
                    purpose_map = candidate
                    break
            if purpose_map is not None:
                assertions = []
                cursor = index_start
                for nested_purpose, items in purpose_map.items():
                    nested = _normalise_evidence(
                        items,
                        default_polarity=default_polarity,
                        default_purpose=nested_purpose,
                        source=source,
                        index_start=cursor,
                    )
                    assertions.extend(nested)
                    cursor += len(nested)
                return assertions
        if collection_keys and not has_pair_keys:
            assertions = []
            cursor = index_start
            for key in collection_keys:
                if key not in value:
                    continue
                polarity = _COLLECTION_KEYS[key]
                item = value[key]
                if key == "constraints" and isinstance(item, dict):
                    nested = _normalise_evidence(
                        item,
                        default_polarity=default_polarity,
                        default_purpose=default_purpose,
                        source=source,
                        index_start=cursor,
                    )
                else:
                    nested = _normalise_evidence(
                        item,
                        default_polarity=polarity,
                        default_purpose=default_purpose,
                        source=source,
                        index_start=cursor,
                    )
                assertions.extend(nested)
                cursor += len(nested)
            if assertions:
                return assertions

        return [
            _coerce_assertion(
                value,
                default_polarity=default_polarity,
                default_purpose=default_purpose,
                source=source,
                index=index_start,
            ),
        ]

    if isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)

        # A bare pair such as ("A", "B") is a single assertion.  A list of two
        # strings without any relational operator is also treated that way for
        # convenience; lists of records remain collections.
        if _pair_like(items):
            if len(items) <= 4 and not any(
                isinstance(item, str) and _relation_polarity(item) is None
                and _STRING_ASSERTION_RE.match(item)
                for item in items
            ):
                return [
                    _coerce_assertion(
                        items,
                        default_polarity=default_polarity,
                        default_purpose=default_purpose,
                        source=source,
                        index=index_start,
                    ),
                ]

        assertions = []
        cursor = index_start
        for item in items:
            nested = _normalise_evidence(
                item,
                default_polarity=default_polarity,
                default_purpose=default_purpose,
                source=source,
                index_start=cursor,
            )
            assertions.extend(nested)
            cursor += len(nested)
        return assertions

    return [
        _coerce_assertion(
            value,
            default_polarity=default_polarity,
            default_purpose=default_purpose,
            source=source,
            index=index_start,
        ),
    ]


def _custom_evidence_records(obj):
    """Yield evidence records embedded on a STIX-like object."""

    if isinstance(obj, dict):
        getter = obj.get
    else:
        getter = lambda key, default=None: getattr(obj, key, default)  # noqa: E731

    for key in (
        "x_merge_evidence",
        "x_equivalence_evidence",
        "merge_evidence",
        "equivalence_evidence",
        "x_entity_merge_evidence",
    ):
        value = getter(key)
        if value:
            yield value, None

    for key, polarity in (
        ("x_positive_constraints", True),
        ("positive_constraints", True),
        ("x_negative_constraints", False),
        ("negative_constraints", False),
        ("x_legal_separations", False),
        ("legal_separations", False),
        ("x_cannot_merge", False),
        ("cannot_merge", False),
    ):
        value = getter(key)
        if value:
            yield value, polarity


def assertions_from_stix(objects, purpose=None, source=None):
    """Extract merge/separation assertions from STIX objects and relationships.

    Both Python STIX objects and JSON-compatible mappings are accepted.  A
    :class:`stix2.Bundle`, a bundle mapping, a list, or a single object may be
    supplied.

    Supported relationship types include ``same-as``/``equivalent-to`` (merge)
    and ``different-from``/``distinct-from`` (separation).  Objects may also
    carry explicit evidence in ``x_merge_evidence`` /
    ``x_equivalence_evidence``, or constraints in
    ``x_positive_constraints`` / ``x_negative_constraints``.
    """

    if hasattr(objects, "objects"):
        objects = objects.objects
    elif hasattr(objects, "query"):
        objects = objects.query([])
    elif isinstance(objects, dict) and "objects" in objects:
        objects = objects["objects"]
    elif not isinstance(objects, (list, tuple, set, frozenset)):
        objects = [objects]

    assertions = []
    cursor = 0
    for obj in objects:
        obj_type = obj.get("type") if isinstance(obj, dict) else getattr(obj, "type", None)
        obj_id = obj.get("id") if isinstance(obj, dict) else getattr(obj, "id", None)

        if obj_type == "relationship":
            relationship_type = (
                obj.get("relationship_type")
                if isinstance(obj, dict)
                else getattr(obj, "relationship_type", None)
            )
            polarity = _relation_polarity(relationship_type)
            if polarity is not None:
                left = obj.get("source_ref") if isinstance(obj, dict) else obj.source_ref
                right = obj.get("target_ref") if isinstance(obj, dict) else obj.target_ref
                obj_purpose = _first(obj, _PURPOSE_KEYS, purpose)
                obj_weight = _weight(_first(obj, _WEIGHT_KEYS))
                assertions.append(
                    Assertion(
                        left=_node_id(left),
                        right=_node_id(right),
                        positive=polarity,
                        purpose=_purpose_set(obj_purpose),
                        weight=obj_weight,
                        identifier=str(obj_id or "e%d" % cursor),
                        evidence_ids=(str(obj_id or "e%d" % cursor),),
                        source=source or obj_id,
                    ),
                )
                cursor += 1

        for value, polarity in _custom_evidence_records(obj):
            nested = _normalise_evidence(
                value,
                default_polarity=polarity,
                default_purpose=purpose,
                source=source or obj_id,
                index_start=cursor,
            )
            assertions.extend(nested)
            cursor += len(nested)

    return assertions


evidence_from_stix = assertions_from_stix
assertions_from_objects = assertions_from_stix


def evidence_from_similarity(objects, threshold=70, purpose=None):
    """Build defeasible merge evidence from STIX object similarity scores.

    This is opt-in because similarity is not proof of identity; callers should
    usually combine it with explicit relationships and legal separations.
    """

    return _similarity_assertions(
        objects,
        threshold=threshold,
        purpose=purpose,
    )


similarity_evidence = evidence_from_similarity
equivalence_evidence_from_objects = evidence_from_similarity


def _entity_ids_from_objects(objects):
    """Return the IDs of non-relationship STIX objects."""

    if hasattr(objects, "objects"):
        objects = objects.objects
    elif hasattr(objects, "query"):
        objects = objects.query([])
    elif isinstance(objects, dict) and "objects" in objects:
        objects = objects["objects"]
    elif not isinstance(objects, (list, tuple, set, frozenset)):
        objects = [objects]

    identifiers = []
    for obj in objects:
        obj_type = obj.get("type") if isinstance(obj, dict) else getattr(obj, "type", None)
        obj_id = obj.get("id") if isinstance(obj, dict) else getattr(obj, "id", None)
        if obj_type != "relationship" and obj_id is not None:
            identifier = _node_id(obj_id)
            if identifier not in identifiers:
                identifiers.append(identifier)
    return identifiers


def load_evidence(source, purpose=None, encoding="utf-8"):
    """Read evidence from a JSON file, JSON Lines file, or in-memory value."""

    if isinstance(source, (str, os.PathLike)):
        path = os.fspath(source)
        if not os.path.exists(path):
            return _normalise_evidence(source, default_purpose=purpose)
        with open(path, encoding=encoding) as handle:
            text = handle.read()
        if path.lower().endswith((".jsonl", ".ndjson")):
            payload = [json.loads(line) for line in text.splitlines() if line.strip()]
        else:
            payload = json.loads(text)
        return _normalise_evidence(payload, default_purpose=purpose)
    return _normalise_evidence(source, default_purpose=purpose)


read_evidence = load_evidence


def _dedupe_assertions(assertions):
    """Collapse identical topological assertions while retaining evidence IDs."""

    grouped = {}
    order = []
    for index, assertion in enumerate(assertions):
        key = (assertion.left, assertion.right, assertion.positive, assertion.purpose)
        if key not in grouped:
            grouped[key] = [assertion]
            order.append(key)
        else:
            grouped[key].append(assertion)

    result = []
    used_identifiers = set()
    for index, key in enumerate(order):
        group = grouped[key]
        best = max(group, key=lambda item: item.weight)
        evidence_ids = []
        for item in group:
            for evidence_id in (item.evidence_ids or (item.identifier,)):
                if evidence_id and evidence_id not in evidence_ids:
                    evidence_ids.append(evidence_id)
        identifier = best.identifier or "e%d" % index
        if identifier in used_identifiers:
            suffix = 1
            while "%s-%d" % (identifier, suffix) in used_identifiers:
                suffix += 1
            identifier = "%s-%d" % (identifier, suffix)
        used_identifiers.add(identifier)
        result.append(
            dataclasses.replace(
                best,
                identifier=identifier,
                evidence_ids=tuple(evidence_ids) or (identifier,),
                source=best.source,
            ),
        )
    return result


def _collect_assertions(
    evidence=None,
    positive=None,
    negative=None,
    merges=None,
    separations=None,
    constraints=None,
    objects=None,
    purpose=None,
    infer_similarity=False,
    similarity_threshold=70,
    **kwargs,
):
    """Collect and normalise all supported evidence inputs."""

    positive = positive if positive is not None else kwargs.pop("positives", None)
    negative = negative if negative is not None else kwargs.pop("negatives", None)
    merges = merges if merges is not None else kwargs.pop("same", None)
    separations = separations if separations is not None else kwargs.pop("different", None)
    if kwargs:
        unknown = ", ".join(sorted(kwargs))
        raise TypeError("Unexpected reconciliation argument(s): %s" % unknown)

    assertions = []
    cursor = 0
    for value, polarity in (
        (evidence, True),
        (constraints, None),
        (merges, True),
        (positive, True),
        (separations, False),
        (negative, False),
    ):
        if value is None:
            continue
        nested = _normalise_evidence(
            value,
            default_polarity=polarity,
            # The query purpose is applied when filtering, not when reading
            # evidence.  Unscoped evidence remains global.
            default_purpose=None,
            index_start=cursor,
        )
        assertions.extend(nested)
        cursor += len(nested)

    if objects is not None:
        nested = assertions_from_stix(objects, purpose=None)
        assertions.extend(nested)
        cursor += len(nested)
        if infer_similarity:
            similarity_assertions = _similarity_assertions(
                objects,
                threshold=similarity_threshold,
                purpose=None,
                index_start=cursor,
            )
            assertions.extend(similarity_assertions)

    for index, assertion in enumerate(assertions):
        if not assertion.identifier:
            assertions[index] = dataclasses.replace(
                assertion,
                identifier="e%d" % index,
                evidence_ids=assertion.evidence_ids or ("e%d" % index,),
            )

    return _dedupe_assertions(assertions)


def _similarity_assertions(objects, threshold=70, purpose=None, index_start=0):
    """Generate positive evidence from STIX semantic object similarity."""

    if hasattr(objects, "objects"):
        objects = objects.objects
    elif hasattr(objects, "query"):
        objects = objects.query([])
    elif isinstance(objects, dict) and "objects" in objects:
        objects = objects["objects"]
    elif not isinstance(objects, (list, tuple, set, frozenset)):
        objects = [objects]

    try:
        from .object import object_similarity
    except ImportError:  # pragma: no cover - only relevant in partial installs
        return []

    assertions = []
    cursor = index_start
    for left, right in itertools.combinations(objects, 2):
        left_type = left.get("type") if isinstance(left, dict) else getattr(left, "type", None)
        right_type = right.get("type") if isinstance(right, dict) else getattr(right, "type", None)
        if left_type != right_type:
            continue
        try:
            score = object_similarity(
                left,
                right,
                ignore_spec_version=True,
                versioning_checks=False,
                max_depth=1,
            )
        except (ImportError, KeyError, TypeError, ValueError):
            continue
        if score < threshold:
            continue
        assertions.append(
            Assertion(
                left=_node_id(left),
                right=_node_id(right),
                positive=True,
                purpose=_purpose_set(purpose),
                weight=max(score / 100.0, 0.01),
                identifier="sim-%d" % cursor,
                evidence_ids=("sim-%d" % cursor,),
                source="object_similarity",
            ),
        )
        cursor += 1
    return assertions


def _build_components(nodes, assertions):
    parent = {node: node for node in nodes}

    def find(node):
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def union(left, right):
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    for assertion in assertions:
        if assertion.positive:
            union(assertion.left, assertion.right)

    groups = collections.defaultdict(list)
    for node in nodes:
        groups[find(node)].append(node)
    return {
        node: find(node)
        for node in nodes
    }, [sorted(group) for group in groups.values()]


def _induced_positive_paths(positive_edges, start, end, max_paths=10000):
    """Enumerate simple positive-edge paths from start to end.

    Every simple path is an inclusion-minimal edge set connecting its
    endpoints: removing any edge from the path breaks that particular
    connection.  A chord using an edge outside the path does not make the
    path redundant, because the chord is not part of the conflict core.
    """

    if start == end:
        return [], False

    adjacency = collections.defaultdict(list)
    for edge in positive_edges:
        if edge.left == edge.right:
            continue
        adjacency[edge.left].append((edge.right, edge))
        adjacency[edge.right].append((edge.left, edge))

    if start not in adjacency or end not in adjacency:
        return [], False

    results = []
    seen = set()
    visited = {start}
    path_nodes = [start]
    path_edges = []
    truncated = False

    def dfs(node):
        nonlocal truncated
        if truncated:
            return
        for other, edge in adjacency.get(node, ()):
            if other in visited:
                continue
            visited.add(other)
            path_nodes.append(other)
            path_edges.append(edge)
            if other == end:
                signature = tuple(sorted(item.identifier for item in path_edges))
                if signature not in seen:
                    seen.add(signature)
                    results.append(list(path_edges))
                    if len(results) >= max_paths:
                        truncated = True
            else:
                dfs(other)
            path_edges.pop()
            path_nodes.pop()
            visited.remove(other)
            if truncated:
                return

    dfs(start)
    return results, truncated


def _edge_dict(assertion):
    return _record(
        id=assertion.identifier,
        evidence_ids=list(assertion.evidence_ids) or [assertion.identifier],
        left=assertion.left,
        right=assertion.right,
        relation=assertion.relation,
        positive=assertion.positive,
        pair=list(assertion.pair),
        weight=assertion.weight,
        purpose=sorted(assertion.purpose) if assertion.purpose else None,
    )


def _conflict_record(negative, positive_path):
    positive_edges = [_edge_dict(edge) for edge in positive_path]
    negative_edge = _edge_dict(negative)
    pairs = [list(edge["pair"]) for edge in positive_edges]
    pairs.append(list(negative_edge["pair"]))
    relations = ["merge"] * len(positive_edges) + ["separate"]
    nodes = []
    if positive_path:
        nodes.append(positive_path[0].left)
        for edge in positive_path:
            nodes.append(edge.other(nodes[-1]))
    else:
        nodes.extend([negative.left, negative.right])

    if positive_path:
        explanation = (
            "Merge evidence %s places %s and %s in the same equivalence class, "
            "but the explicit separation %s forbids that.  Dropping any one of "
            "these %d assertions removes this particular conflict."
            % (
                " -> ".join(
                    "%s~%s" % (edge.left, edge.right)
                    for edge in positive_path
                ),
                negative.left,
                negative.right,
                "%s!~%s" % (negative.left, negative.right),
                len(positive_path) + 1,
            )
        )
    else:
        explanation = (
            "The separation %s!~%s is self-contradictory and cannot be repaired "
            "by dropping merge evidence."
            % (negative.left, negative.right)
        )

    return _record(
        type="minimal-conflict",
        kind="minimal",
        nodes=nodes,
        positive_edges=positive_edges,
        negative_edge=negative_edge,
        edges=positive_edges + [negative_edge],
        pairs=pairs,
        relations=relations,
        size=len(positive_edges) + 1,
        minimal=True,
        is_minimal=True,
        explanation=explanation,
    )


def _dedupe_conflicts(conflicts):
    seen = set()
    result = []
    for conflict in conflicts:
        key = (
            conflict["negative_edge"]["id"],
            tuple(sorted(edge["id"] for edge in conflict["positive_edges"])),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(conflict)
    return sorted(
        result,
        key=lambda item: (
            item["negative_edge"]["id"],
            item["size"],
            item["pairs"],
        ),
    )


def _find_conflicts(positive_edges, negative_edges, max_paths=10000):
    conflicts = []
    truncated = False
    for negative in negative_edges:
        if negative.left == negative.right:
            conflicts.append(_conflict_record(negative, []))
            continue
        paths, path_truncated = _induced_positive_paths(
            positive_edges,
            negative.left,
            negative.right,
            max_paths=max_paths,
        )
        truncated = truncated or path_truncated
        for path in paths:
            conflicts.append(_conflict_record(negative, path))
    return _dedupe_conflicts(conflicts), truncated


def _minimal_hitting_sets(hyperedges, max_solutions=1000):
    """Return inclusion-minimal hitting sets of the conflict hyperedges."""

    hyperedges = [set(edge) for edge in hyperedges if edge]
    if not hyperedges:
        return [frozenset()], False

    # Remove duplicates and supersets.  Minimal conflicts are already minimal,
    # but duplicate hyperedges are common when a pair has several evidence IDs.
    unique = []
    for edge in sorted(hyperedges, key=len):
        if not any(existing <= edge for existing in unique):
            unique.append(edge)
    hyperedges = unique

    solutions = []
    truncated = False

    def visit(chosen, remaining):
        nonlocal truncated
        if len(solutions) >= max_solutions:
            truncated = True
            return
        if not remaining:
            candidate = frozenset(chosen)
            if not any(existing < candidate for existing in solutions):
                solutions[:] = [
                    existing for existing in solutions
                    if not candidate < existing
                ]
                if candidate not in solutions:
                    solutions.append(candidate)
            return

        smallest = min(remaining, key=len)
        for item in sorted(smallest):
            visit(
                chosen | {item},
                [edge for edge in remaining if item not in edge],
            )

    visit(set(), hyperedges)
    return solutions, truncated


def _solution_record(nodes, kept, dropped, negative_edges):
    component_of, groups = _build_components(nodes, kept)
    groups = sorted(groups, key=lambda group: (group[0], len(group)))

    merged_groups = [group for group in groups if len(group) > 1]
    known_separations = set()
    for negative in negative_edges:
        left_group = component_of[negative.left]
        right_group = component_of[negative.right]
        if left_group == right_group:
            # A consistent solution must never reach this branch.
            continue
        left_nodes = [node for node in nodes if component_of[node] == left_group]
        right_nodes = [node for node in nodes if component_of[node] == right_group]
        for left in left_nodes:
            for right in right_nodes:
                known_separations.add(tuple(sorted((left, right))))

    return _record(
        groups=merged_groups,
        partition=groups,
        kept_merges=[list(edge.pair) for edge in kept],
        dropped_merges=[list(edge.pair) for edge in dropped],
        kept_weight=sum(edge.weight for edge in kept),
        dropped_weight=sum(edge.weight for edge in dropped),
        separations=[list(pair) for pair in sorted(known_separations)],
        component_of=component_of,
        known_separations=tuple(sorted(known_separations)),
        consistent=True,
    )


def _partition_signature(solution):
    return tuple(tuple(group) for group in solution["partition"])


def _analyse(
    assertions,
    *,
    label=None,
    positive_mode="defeasible",
    max_paths=10000,
    max_solutions=1000,
    max_undetermined_pairs=1000,
    extra_nodes=(),
):
    positive_edges = [assertion for assertion in assertions if assertion.positive]
    negative_edges = [assertion for assertion in assertions if not assertion.positive]

    nodes = sorted(
        {
            node
            for assertion in assertions
            for node in (assertion.left, assertion.right)
        }
        | {str(node) for node in extra_nodes},
    )

    conflicts, paths_truncated = _find_conflicts(
        positive_edges,
        negative_edges,
        max_paths=max_paths,
    )
    warnings = []
    if paths_truncated:
        warnings.append(
            "Negative-path enumeration was truncated at max_paths=%d; some "
            "minimal conflicts may be missing." % max_paths
        )

    inherently_unsatisfiable = any(
        not conflict["positive_edges"] for conflict in conflicts
    )
    if positive_mode in ("required", "hard", "strict") and conflicts:
        resolvable = not conflicts
        solutions = []
        hitting_sets = []
        if conflicts:
            warnings.append(
                "Positive merge evidence was declared required, so a conflict "
                "makes the constraint set unsatisfiable."
            )
    elif inherently_unsatisfiable:
        resolvable = False
        solutions = []
        hitting_sets = []
    else:
        conflict_edges = [
            frozenset(edge["id"] for edge in conflict["positive_edges"])
            for conflict in conflicts
            if conflict["positive_edges"]
        ]
        hitting_sets, hitting_truncated = _minimal_hitting_sets(
            conflict_edges,
            max_solutions=max_solutions,
        )
        if hitting_truncated:
            warnings.append(
                "Compatible-solution enumeration was truncated at "
                "max_solutions=%d; some alternatives may be missing."
                % max_solutions
            )
        solutions = []
        seen_partitions = set()
        for hitting_set in hitting_sets:
            kept = [
                edge for edge in positive_edges
                if edge.identifier not in hitting_set
            ]
            dropped = [
                edge for edge in positive_edges
                if edge.identifier in hitting_set
            ]
            solution = _solution_record(nodes, kept, dropped, negative_edges)
            signature = _partition_signature(solution)
            if signature in seen_partitions:
                continue
            seen_partitions.add(signature)
            solutions.append(solution)
        resolvable = bool(solutions)

    solutions.sort(
        key=lambda item: (
            item["dropped_weight"],
            len(item["dropped_merges"]),
            _partition_signature(item),
        ),
    )

    pair_status = {}
    relevant_pairs = set()

    # Pairs that could possibly be merged according to the full positive graph.
    positive_nodes = sorted(
        {node for edge in positive_edges for node in (edge.left, edge.right)},
    )
    _, full_positive_groups = _build_components(positive_nodes, positive_edges)
    for group in full_positive_groups:
        for pair in itertools.combinations(group, 2):
            relevant_pairs.add(tuple(sorted(pair)))

    for negative in negative_edges:
        relevant_pairs.add(tuple(sorted((negative.left, negative.right))))

    pairs_limited = False
    if (not assertions or extra_nodes) and len(nodes) > 1:
        # When the caller supplies an entity set, pairs without evidence are
        # explicitly left undetermined rather than silently collapsed.  Keep
        # this to a reasonable size for large archives.
        if len(nodes) <= 100:
            relevant_pairs.update(
                tuple(sorted(pair))
                for pair in itertools.combinations(nodes, 2)
            )
        else:
            pairs_limited = True
            warnings.append(
                "Pair-level undetermined reporting was limited because the "
                "supplied entity set contains more than 100 nodes."
            )

    for solution in solutions:
        component_of = solution["component_of"]
        for pair in relevant_pairs | set(solution["known_separations"]):
            statuses = pair_status.setdefault(pair, {"equal": 0, "separate": 0})
            if component_of[pair[0]] == component_of[pair[1]]:
                statuses["equal"] += 1
            elif pair in solution["known_separations"]:
                statuses["separate"] += 1
        for pair in solution["known_separations"]:
            relevant_pairs.add(pair)

    solution_count = len(solutions)
    explicit_negative_pairs = {
        tuple(sorted((negative.left, negative.right)))
        for negative in negative_edges
        if negative.left != negative.right
    }
    certain_merges = []
    possible_merges = []
    impossible_merges = []
    certain_separations = []
    possible_separations = []
    undetermined_pairs = []

    for pair in sorted(relevant_pairs):
        statuses = pair_status.get(pair, {"equal": 0, "separate": 0})
        if solution_count and statuses["equal"] == solution_count:
            certain_merges.append(list(pair))
        if statuses["equal"] > 0:
            possible_merges.append(list(pair))
        elif solution_count and statuses["equal"] == 0:
            impossible_merges.append(list(pair))
        if (
            solution_count and statuses["separate"] == solution_count
        ) or (
            not solution_count and pair in explicit_negative_pairs
        ):
            certain_separations.append(list(pair))
        if statuses["separate"] > 0:
            possible_separations.append(list(pair))
        determined = (
            solution_count
            and (
                statuses["equal"] == solution_count
                or statuses["separate"] == solution_count
            )
        ) or (
            not solution_count and pair in explicit_negative_pairs
        )
        if not determined:
            undetermined_pairs.append(list(pair))

    undetermined_truncated = len(undetermined_pairs) > max_undetermined_pairs
    if undetermined_truncated:
        warnings.append(
            "undetermined_pairs was truncated at max_undetermined_pairs=%d."
            % max_undetermined_pairs
        )
        undetermined_pairs = undetermined_pairs[:max_undetermined_pairs]

    explicit_merge_pairs = sorted({tuple(edge.pair) for edge in positive_edges})
    explicit_separation_pairs = sorted({tuple(edge.pair) for edge in negative_edges})
    possible_merge_set = {tuple(pair) for pair in possible_merges}
    certain_merge_set = {tuple(pair) for pair in certain_merges}
    impossible_merge_set = {tuple(pair) for pair in impossible_merges}
    possible_direct_merges = [
        list(pair) for pair in explicit_merge_pairs if pair in possible_merge_set
    ]
    certain_direct_merges = [
        list(pair) for pair in explicit_merge_pairs if pair in certain_merge_set
    ]
    impossible_direct_merges = [
        list(pair) for pair in explicit_merge_pairs if pair in impossible_merge_set
    ]

    certain_merge_graph = [
        Assertion(left=pair[0], right=pair[1], positive=True, identifier="certain-%d" % index)
        for index, pair in enumerate(certain_merges)
    ]
    certain_nodes = sorted(
        {node for pair in certain_merges for node in pair},
    )
    _, certain_groups = _build_components(certain_nodes, certain_merge_graph)
    certain_groups = [group for group in certain_groups if len(group) > 1]

    unique_solution = solutions[0] if len(solutions) == 1 else None
    if not resolvable:
        groups = None
        partition = None
        preferred = None
        status = "unsatisfiable"
    elif conflicts and len(solutions) > 1:
        groups = None
        partition = None
        preferred = None
        status = "ambiguous"
    elif conflicts:
        groups = unique_solution["groups"]
        partition = unique_solution["partition"]
        preferred = unique_solution
        status = "resolved"
    else:
        groups = unique_solution["groups"] if unique_solution else []
        partition = unique_solution["partition"] if unique_solution else []
        preferred = unique_solution
        status = "consistent" if assertions else "insufficient"

    # A unique best solution is reported as preferred when weights/counts make
    # it strictly better than every alternative.  Equal alternatives remain
    # ambiguous and are never promoted to a single answer.
    if resolvable and len(solutions) > 1:
        best_key = (solutions[0]["dropped_weight"], len(solutions[0]["dropped_merges"]))
        tied = [
            solution for solution in solutions
            if (solution["dropped_weight"], len(solution["dropped_merges"])) == best_key
        ]
        if len(tied) == 1:
            preferred = solutions[0]

    fully_determined = (
        not undetermined_pairs
        and not undetermined_truncated
        and not pairs_limited
    )
    evidence_sufficient = bool(assertions)

    if not assertions:
        summary = "No merge or separation evidence was supplied; no grouping is asserted."
    elif status == "consistent":
        summary = "Evidence is consistent; merged groups follow from transitive merge closure."
    elif status == "resolved":
        summary = (
            "Evidence is inconsistent, but a unique best compatible grouping was "
            "found by dropping the lowest-cost conflicting merge evidence."
        )
    elif status == "ambiguous":
        summary = (
            "Evidence is inconsistent and several equally compatible groupings "
            "remain; no single grouping is asserted."
        )
    elif status == "unsatisfiable":
        summary = "The constraint set is unsatisfiable; no compatible grouping exists."
    else:
        summary = "Evidence is insufficient to determine a grouping."

    result = _record(
        purpose=label,
        status=status,
        consistent=not conflicts,
        compatible=not conflicts,
        inconsistent=bool(conflicts),
        resolvable=resolvable,
        satisfiable=resolvable,
        unsatisfiable=not resolvable,
        ambiguous=len(solutions) > 1,
        needs_review=bool(conflicts) or not fully_determined,
        evidence_sufficient=evidence_sufficient,
        fully_determined=fully_determined,
        determined=fully_determined,
        groups=groups,
        merge_groups=groups,
        compatible_groups=groups,
        partition=partition,
        grouping=partition,
        partitions=[solution["partition"] for solution in solutions],
        compatible_partitions=[solution["partition"] for solution in solutions],
        groupings=[solution["partition"] for solution in solutions],
        solutions=solutions,
        minimal_conflicts=conflicts,
        conflicts=conflicts,
        minimal_conflict=conflicts[0] if conflicts else None,
        minimal_conflict_pairs=[conflict["pairs"] for conflict in conflicts],
        conflict_sets=[conflict["pairs"] for conflict in conflicts],
        has_conflict=bool(conflicts),
        certain_merges=certain_merges,
        stable_merges=certain_merges,
        certain_groups=certain_groups,
        possible_merges=possible_merges,
        still_valid_merges=possible_direct_merges,
        surviving_merges=possible_merges,
        impossible_merges=impossible_merges,
        explicit_merges=[list(pair) for pair in explicit_merge_pairs],
        explicit_separations=[list(pair) for pair in explicit_separation_pairs],
        possible_direct_merges=possible_direct_merges,
        certain_direct_merges=certain_direct_merges,
        impossible_direct_merges=impossible_direct_merges,
        certain_separations=certain_separations,
        cannot_merge=certain_separations,
        possible_separations=possible_separations,
        undetermined_pairs=undetermined_pairs,
        unknown_pairs=undetermined_pairs,
        unresolved_pairs=undetermined_pairs,
        unresolved=undetermined_pairs,
        valid_merges=possible_direct_merges,
        preferred_solution=preferred,
        preferred_partition=preferred["partition"] if preferred else None,
        preferred_groups=preferred["groups"] if preferred else None,
        warnings=warnings,
        summary=summary,
        assertion_count=len(assertions),
        positive_assertion_count=len(positive_edges),
        negative_assertion_count=len(negative_edges),
        nodes=nodes,
    )
    return result


def _resolve_purposes(assertions, purpose=None, purposes=None):
    discovered = sorted(
        {
            item
            for assertion in assertions
            if assertion.purpose
            for item in assertion.purpose
        },
    )
    if purposes is None:
        selected = [] if purpose is not None else list(discovered)
    elif isinstance(purposes, str):
        selected = [purposes]
    else:
        selected = [str(item) for item in purposes]

    if purpose is not None:
        purpose = str(purpose)
        if purpose not in selected:
            selected.append(purpose)

    return selected


def reconcile_entity_merges(
    evidence=None,
    *,
    positive=None,
    negative=None,
    merges=None,
    separations=None,
    constraints=None,
    objects=None,
    entities=None,
    purpose=None,
    purposes=None,
    infer_similarity=False,
    similarity_threshold=70,
    positive_mode="defeasible",
    max_paths=10000,
    max_solutions=1000,
    max_undetermined_pairs=1000,
    **kwargs,
):
    """Reconcile entity identifiers before an offline archive is built.

    Parameters
    ----------
    evidence:
        A single assertion, a collection of assertions, a JSON/JSON Lines file
        path, a STIX bundle, or a mapping containing ``merges`` /
        ``separations``.  Records may use STIX relationship fields.
    positive, negative, merges, separations, constraints:
        Explicit positive (merge) and negative (separation) collections.  Each
        item may be a pair tuple, a mapping, a string such as ``"A ~ B"`` or
        ``"A != B"``, or a STIX relationship.
    objects:
        STIX objects from which relationship/embedded evidence should be read.
    purpose:
        Analyse a single purpose/context.  Global assertions (no purpose) are
        always included.  Purpose-scoped assertions apply only to that purpose.
    purposes:
        Analyse several purposes and return a report per purpose plus a
        combined report.
    infer_similarity:
        Additionally generate positive evidence from STIX object similarity.
        This is off by default because similarity is not proof of identity.
    positive_mode:
        ``"defeasible"`` (default) allows conflicting merge evidence to be
        dropped when reporting alternatives.  ``"required"`` treats all merge
        evidence as hard, so any conflict makes the input unsatisfiable.

    Returns
    -------
    dict-like
        The primary report.  Important keys include:

        ``groups``
            The unique merged groups (only groups of two or more nodes), or
            ``None`` when no single grouping can be asserted.
        ``partitions``
            Every maximal compatible grouping.  Each partition includes
            singleton classes; singletons are not claims that the entity is
            distinct from every other entity.
        ``minimal_conflicts``
            Inclusion-minimal conflicting assertion sets.  Each contains
            ``positive_edges``, ``negative_edge``, ``pairs`` and a readable
            ``explanation``.
        ``certain_merges`` / ``possible_merges`` / ``impossible_merges``
            Pair-level results across all compatible groupings.
        ``certain_separations`` / ``possible_separations``
            Explicit and transitively derived separations.
        ``undetermined_pairs``
            Pairs for which the available evidence does not decide equality or
            separation.  These are not silently forced into one group.
        ``by_purpose`` / ``combined``
            Per-purpose reports and the union of all assertions.  A conflict in
            the union is reported separately from the purpose-specific views.

    Notes
    -----
    A merge is an equivalence relation.  Therefore ``A ~ B`` and ``B ~ C``
    imply ``A ~ C``.  Adding ``A !~ C`` makes the three assertions a minimal
    conflict.  The compatible answers are ``{A, B}`` or ``{B, C}``; both are
    returned.  A weight-based preference is exposed separately and never
    replaces the alternatives or turns ambiguity into a forced grouping.
    """

    if positive_mode not in ("defeasible", "soft", "required", "hard", "strict"):
        raise ValueError(
            "positive_mode must be 'defeasible' or 'required', got %r"
            % (positive_mode,)
        )
    if max_paths <= 0:
        raise ValueError("max_paths must be a positive integer")
    if max_solutions <= 0:
        raise ValueError("max_solutions must be a positive integer")

    assertions = _collect_assertions(
        evidence=evidence,
        positive=positive,
        negative=negative,
        merges=merges,
        separations=separations,
        constraints=constraints,
        objects=objects,
        purpose=purpose,
        infer_similarity=infer_similarity,
        similarity_threshold=similarity_threshold,
        **kwargs,
    )

    entity_nodes = set()
    if entities is not None:
        if isinstance(entities, (str, bytes)):
            entity_nodes.add(_node_id(entities))
        else:
            entity_nodes.update(_node_id(item) for item in entities)
    if objects is not None:
        entity_nodes.update(_entity_ids_from_objects(objects))

    selected_purposes = _resolve_purposes(assertions, purpose=purpose, purposes=purposes)
    combined = _analyse(
        assertions,
        label="combined" if selected_purposes else purpose,
        positive_mode=positive_mode,
        max_paths=max_paths,
        max_solutions=max_solutions,
        max_undetermined_pairs=max_undetermined_pairs,
        extra_nodes=entity_nodes,
    )

    by_purpose = {}
    for selected in selected_purposes:
        active = [
            assertion for assertion in assertions if assertion.applies_to(selected)
        ]
        by_purpose[selected] = _analyse(
            active,
            label=selected,
            positive_mode=positive_mode,
            max_paths=max_paths,
            max_solutions=max_solutions,
            max_undetermined_pairs=max_undetermined_pairs,
            extra_nodes=entity_nodes,
        )

    if purpose is not None:
        primary = _Record(by_purpose[str(purpose)])
    else:
        # Shallow copy so that primary["combined"] does not create a
        # self-referential structure that cannot be JSON-serialised.
        primary = _Record(combined)

    primary["by_purpose"] = by_purpose
    primary["per_purpose"] = by_purpose
    primary["purpose_reports"] = by_purpose
    primary["purposes"] = selected_purposes
    primary["combined"] = combined
    primary["combined_consistent"] = combined["consistent"]
    primary["purposes_compatible"] = all(
        item["consistent"] for item in by_purpose.values()
    )
    primary["cross_purpose_compatible"] = combined["consistent"]
    primary["cross_purpose_disagreements"] = _cross_purpose_disagreements(assertions)
    primary["assertions"] = [assertion.to_dict() for assertion in assertions]
    primary["evidence"] = primary["assertions"]

    return primary


def _cross_purpose_disagreements(assertions):
    by_pair = collections.defaultdict(list)
    for assertion in assertions:
        if assertion.purpose is None:
            continue
        for purpose in assertion.purpose:
            by_pair[assertion.pair].append((purpose, assertion.positive))

    disagreements = []
    for pair, entries in sorted(by_pair.items()):
        positive_purposes = sorted(
            {purpose for purpose, positive in entries if positive},
        )
        negative_purposes = sorted(
            {purpose for purpose, positive in entries if not positive},
        )
        if positive_purposes and negative_purposes:
            disagreements.append(
                _record(
                    pair=list(pair),
                    positive_purposes=positive_purposes,
                    negative_purposes=negative_purposes,
                    explanation=(
                        "The same pair is merge evidence in one purpose and a "
                        "separation in another; purpose-specific reports remain "
                        "valid, but the combined view is inconsistent."
                    ),
                ),
            )
    return disagreements


def check_merge_consistency(evidence=None, *, details=False, **kwargs):
    """Return whether the supplied merge/separation evidence is consistent."""

    report = reconcile_entity_merges(evidence, **kwargs)
    return report if details else report["consistent"]


def check_consistency(evidence=None, *, details=False, **kwargs):
    """Alias for :func:`check_merge_consistency`."""

    return check_merge_consistency(evidence, details=details, **kwargs)


def find_minimal_conflicts(evidence=None, **kwargs):
    """Return the inclusion-minimal conflicting assertion sets."""

    kwargs.pop("details", None)
    report = reconcile_entity_merges(evidence, **kwargs)
    return report["minimal_conflicts"]


def minimal_conflicts(evidence=None, **kwargs):
    """Alias for :func:`find_minimal_conflicts`."""

    return find_minimal_conflicts(evidence, **kwargs)


def compatible_groups(evidence=None, *, return_alternatives=False, **kwargs):
    """Return the unique compatible groups, or alternatives when ambiguous."""

    report = reconcile_entity_merges(evidence, **kwargs)
    if report["groups"] is not None:
        return report["groups"]
    return report["partitions"] if return_alternatives else None


def compatible_partitions(evidence=None, **kwargs):
    """Return every maximal compatible partition (including singletons)."""

    report = reconcile_entity_merges(evidence, **kwargs)
    return report["partitions"]


def entity_groups(evidence=None, **kwargs):
    """Alias for :func:`compatible_groups`."""

    return compatible_groups(evidence, **kwargs)


class EntityMergeReconciler:
    """Reusable wrapper around :func:`reconcile_entity_merges`."""

    def __init__(
        self,
        evidence=None,
        *,
        positive=None,
        negative=None,
        merges=None,
        separations=None,
        constraints=None,
        objects=None,
        entities=None,
        infer_similarity=False,
        similarity_threshold=70,
        **kwargs,
    ):
        self.entities = entities
        self.object_nodes = _entity_ids_from_objects(objects) if objects is not None else []
        self.assertions = _collect_assertions(
            evidence=evidence,
            positive=positive,
            negative=negative,
            merges=merges,
            separations=separations,
            constraints=constraints,
            objects=objects,
            infer_similarity=infer_similarity,
            similarity_threshold=similarity_threshold,
            **kwargs,
        )

    def reconcile(self, purpose=None, purposes=None, **kwargs):
        entities = list(self.object_nodes)
        if self.entities is not None:
            if isinstance(self.entities, (str, bytes)):
                entities.append(self.entities)
            else:
                entities.extend(self.entities)
        return reconcile_entity_merges(
            self.assertions,
            entities=entities or None,
            purpose=purpose,
            purposes=purposes,
            **kwargs,
        )

    def check(self, **kwargs):
        return self.reconcile(**kwargs)["consistent"]

    def minimal_conflicts(self, **kwargs):
        return self.reconcile(**kwargs)["minimal_conflicts"]

    def compatible_groups(self, return_alternatives=False, **kwargs):
        report = self.reconcile(**kwargs)
        if report["groups"] is not None:
            return report["groups"]
        return report["partitions"] if return_alternatives else None

    def compatible_partitions(self, **kwargs):
        return self.reconcile(**kwargs)["partitions"]


# Common spellings; the underlying behaviour is identical.
reconcile_merges = reconcile_entity_merges
reconcile_entities = reconcile_entity_merges
entity_merge_reconciliation = reconcile_entity_merges
resolve_entity_merges = reconcile_entity_merges
resolve_merges = reconcile_entity_merges
merge_entities = reconcile_entity_merges
analyze_merges = reconcile_entity_merges
analyse_merges = reconcile_entity_merges
find_conflicts = find_minimal_conflicts
group_entities = compatible_groups


def main(argv=None):
    """Command line entry point for offline archive checks."""

    parser = argparse.ArgumentParser(
        description=(
            "Reconcile STIX entity merge evidence and explicit separations."
        ),
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="JSON/JSONL evidence file, STIX bundle, or - for stdin.",
    )
    parser.add_argument(
        "--purpose",
        action="append",
        default=None,
        help="Purpose/context to analyse; may be repeated.",
    )
    parser.add_argument(
        "--required-positive",
        action="store_true",
        help="Treat all merge evidence as hard instead of defeasible.",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        help="JSON indentation (default: 2).",
    )
    args = parser.parse_args(argv)

    if args.input in (None, "-"):
        payload = json.load(sys.stdin)
    else:
        payload = load_evidence(args.input)

    purposes = args.purpose
    result = reconcile_entity_merges(
        payload,
        purposes=purposes,
        positive_mode="required" if args.required_positive else "defeasible",
    )
    json.dump(_plain(result), sys.stdout, indent=args.indent, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":  # pragma: no cover
    main()
