#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""
Collection-plan pre-check built on CPE 2.3 ranges.

The classes in this module answer a narrower question than CPE name
matching: given an advisory range and a set of collection channels, which
parts of the advisory can actually be asserted from the observations that
the channels can prove?

A channel is described by:

* the CPE attributes it can observe (``vendor``, ``product``, ``version``,
  ...),
* the CPE range of assets to which it applies, and
* a name used in reports.

Advisory ranges, channel scopes and exclusions are CPE 2.3 names in any of
the supported bindings (WFN, URI or formatted string).  They are normalised
to WFN before being compared.  This keeps the coverage pre-check aligned
with the package's existing CPE 2.3 comparison conventions while leaving
``CPE.__eq__``, ``CPESet2_3.cpe_*`` and ``CPESet2_3.name_match`` untouched.

The central rule is intentionally conservative:

    A channel can assert an advisory range only when it applies to the
    relevant assets *and* can prove every CPE attribute constrained by the
    advisory.  ``part`` is structural (an asset class, not an observation),
    so it is not required as an evidence field.

Consequently, a collector that only proves ``vendor`` and ``product`` can
assert ``cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*`` but cannot assert
``cpe:2.3:a:acme:widget:4.2:*:*:*:*:*:*:*``.  Adding more collectors of the
first kind does not change that verdict; the missing observation is
``version``.

Example::

    from cpe.coverage import CollectionChannel, precheck_coverage

    report = precheck_coverage(
        advisories=["cpe:2.3:a:acme:widget:4.2:*:*:*:*:*:*:*"],
        channels=[
            CollectionChannel(
                "inventory",
                fields=["vendor", "product"],
                assets="cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
            ),
        ],
    )

    report.asserted_ranges       # []
    report.unclear[0].missing_observations  # ("version",)
"""

from __future__ import absolute_import, unicode_literals

import re

from .cpe import CPE
from .cpe2_3_wfn import CPE2_3_WFN
from .comp.cpecomp import CPEComponent


try:
    _STRING_TYPES = (basestring,)
except NameError:  # Python 3
    _STRING_TYPES = (str,)


__all__ = [
    "AdvisoryCoverage",
    "Channel",
    "CollectionChannel",
    "CollectionPlan",
    "CoveragePrecheck",
    "CoverageReport",
    "IDENTIFYING_FIELDS",
    "OBSERVATION_FIELDS",
    "check_coverage",
    "analyze_coverage",
    "precheck_coverage",
    "required_observations",
]


#: Attributes that can be supplied as channel evidence.
OBSERVATION_FIELDS = CPEComponent.CPE_COMP_KEYS_EXTENDED

#: Canonical formatted-string range that covers every CPE 2.3 asset.
ALL_ASSETS_RANGE = "cpe:2.3:*:*:*:*:*:*:*:*:*:*:*"

#: Attributes that identify a product.  ``part`` is structural.
IDENTIFYING_FIELDS = tuple(
    att for att in OBSERVATION_FIELDS
    if att != CPEComponent.ATT_PART
)


_FIELD_ALIASES = {
    "part": "part",
    "vendor": "vendor",
    "product": "product",
    "version": "version",
    "update": "update",
    "edition": "edition",
    "language": "language",
    "sw_edition": "sw_edition",
    "software_edition": "sw_edition",
    "target_sw": "target_sw",
    "target_software": "target_sw",
    "target_hw": "target_hw",
    "target_hardware": "target_hw",
    "other": "other",
}


def _normalise_field_name(value):
    text = value if isinstance(value, _STRING_TYPES) else str(value)
    key = text.strip().lower().replace("-", "_")
    if key not in _FIELD_ALIASES:
        raise ValueError(
            "Unknown CPE observation field '{0}'. Valid fields are: {1}".format(
                value, ", ".join(OBSERVATION_FIELDS)
            )
        )
    return _FIELD_ALIASES[key]


def _normalise_fields(fields):
    if fields is None:
        return frozenset()
    if isinstance(fields, _STRING_TYPES):
        values = re.split(r"[,\s;|/+&]+", fields.strip())
    else:
        values = list(fields)
    return frozenset(
        _normalise_field_name(value)
        for value in values
        if (value if isinstance(value, _STRING_TYPES) else str(value)).strip()
    )


# ---------------------------------------------------------------------------
# CPE value constraints
# ---------------------------------------------------------------------------


def _wfn_unescape(value):
    """Decode a WFN-escaped string into its literal characters."""
    result = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            result.append(value[index + 1])
            index += 2
        else:
            result.append(char)
            index += 1
    return "".join(result)


def _wfn_escape(value):
    """Escape a literal value for use inside a WFN quoted string."""
    result = []
    for char in value:
        if char.isalnum() or char == "_":
            result.append(char)
        else:
            result.append("\\")
            result.append(char)
    return "".join(result)


def _pattern_tokens(value):
    """
    Split a WFN string value into ``(kind, text)`` tokens.

    ``kind`` is ``"literal"`` for decoded characters and ``"star"`` or
    ``"question"`` for unescaped CPE wildcards.
    """
    tokens = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            tokens.append(("literal", value[index + 1]))
            index += 2
        elif char == "*":
            tokens.append(("star", "*"))
            index += 1
        elif char == "?":
            tokens.append(("question", "?"))
            index += 1
        else:
            tokens.append(("literal", char))
            index += 1
    return tokens


def _has_wildcard(value):
    return any(kind != "literal" for kind, unused in _pattern_tokens(value))


def _pattern_regex(value):
    parts = []
    for kind, text in _pattern_tokens(value):
        if kind == "star":
            parts.append(".*")
        elif kind == "question":
            parts.append(".")
        else:
            parts.append(re.escape(text))
    return re.compile("^" + "".join(parts) + "$")


def _pattern_matches(pattern, literal):
    return _pattern_regex(pattern).match(literal) is not None


def _pattern_prefix_suffix(value):
    """
    Return the guaranteed literal prefix and suffix of a WFN pattern.
    """
    tokens = _pattern_tokens(value)
    first_wild = None
    last_wild = None
    for index, (kind, unused) in enumerate(tokens):
        if kind != "literal":
            if first_wild is None:
                first_wild = index
            last_wild = index

    if first_wild is None:
        text = "".join(text for unused, text in tokens)
        return text, text

    prefix = "".join(text for unused, text in tokens[:first_wild])
    suffix = "".join(text for unused, text in tokens[last_wild + 1:])
    return prefix, suffix


def _pattern_contains(outer, inner):
    """
    Conservative language-inclusion test for two WFN patterns.

    It is exact for literals and handles the common ``prefix*``,
    ``*suffix`` and ``prefix*suffix`` shapes.  Other combinations fall back
    to equality.  A ``False`` result therefore means "not proven", never
    "proven disjoint".
    """
    if outer == inner:
        return True

    outer_tokens = _pattern_tokens(outer)

    outer_has_star = any(kind == "star" for kind, unused in outer_tokens)
    outer_has_question = any(kind == "question" for kind, unused in outer_tokens)

    # Question marks constrain length; only equality/literal matching is
    # handled for them.
    if outer_has_question:
        return False

    if not outer_has_star:
        return False

    outer_prefix, outer_suffix = _pattern_prefix_suffix(outer)
    inner_prefix, inner_suffix = _pattern_prefix_suffix(inner)

    outer_starts_wild = bool(outer_tokens) and outer_tokens[0][0] == "star"
    outer_ends_wild = bool(outer_tokens) and outer_tokens[-1][0] == "star"

    if outer_starts_wild and outer_ends_wild and outer_prefix == "" and outer_suffix == "":
        return True

    if outer_starts_wild and not outer_ends_wild:
        # *suffix
        return inner_suffix.endswith(outer_suffix)

    if outer_ends_wild and not outer_starts_wild:
        # prefix* (question marks were rejected above, so trailing "*")
        return inner_prefix.startswith(outer_prefix)

    if outer_ends_wild and outer_starts_wild:
        # *middle* only guarantees that middle occurs somewhere; this is
        # conservatively treated as not proven unless the patterns are equal.
        return False

    # prefix*suffix
    return (inner_prefix.startswith(outer_prefix) and
            inner_suffix.endswith(outer_suffix))


class _Constraint(object):
    """An attribute-value constraint used by the range algebra."""

    __slots__ = ("kind", "value", "items")

    def __init__(self, kind, value=None, items=None):
        self.kind = kind
        self.value = value
        self.items = tuple(items or ())

    def __repr__(self):
        if self.kind in ("any", "na", "empty"):
            return "<{0}>".format(self.kind)
        if self.kind in ("lit", "pat"):
            return "{0}({1!r})".format(self.kind, self.value)
        return "{0}({1!r})".format(self.kind, self.items)


_ANY = _Constraint("any")
_NA = _Constraint("na")
_EMPTY = _Constraint("empty")


def _is_empty(constraint):
    if constraint.kind == "empty":
        return True
    if constraint.kind == "not":
        return _is_empty(constraint.items[0]) or constraint.items[0].kind == "any"
    if constraint.kind == "and":
        items = constraint.items
        for index, item in enumerate(items):
            if _is_empty(item):
                return True
            for other in items[index + 1:]:
                if _intersect(item, other).kind == "empty":
                    return True
        return False
    return False


def _make_and(items):
    flat = []
    for item in items:
        if item.kind == "empty":
            return _EMPTY
        if item.kind == "any":
            continue
        if item.kind == "and":
            flat.extend(item.items)
        else:
            flat.append(item)

    unique = []
    seen = set()
    for item in flat:
        key = repr(item)
        if key not in seen:
            seen.add(key)
            unique.append(item)

    literals = [item for item in unique if item.kind == "lit"]
    if len(set(item.value for item in literals)) > 1:
        return _EMPTY

    for item in unique:
        if item.kind != "not":
            continue
        for other in unique:
            if other is item:
                continue
            if _contains(item.items[0], other):
                return _EMPTY

    if not unique:
        return _ANY
    if len(unique) == 1:
        return unique[0]
    return _Constraint("and", items=unique)


def _make_not(item):
    if item.kind == "empty":
        return _ANY
    if item.kind == "any":
        return _EMPTY
    if item.kind == "not":
        return item.items[0]
    return _Constraint("not", items=(item,))


def _make_value(value):
    if not _has_wildcard(value):
        return _Constraint("lit", value=_wfn_unescape(value))
    tokens = _pattern_tokens(value)
    if tokens and all(kind == "star" for kind, unused in tokens):
        return _ANY
    return _Constraint("pat", value=value)


def _contains(outer, inner):
    """Return True when every value in ``inner`` is also in ``outer``."""
    if inner.kind == "empty":
        return True
    if outer.kind == "empty":
        return False
    if outer.kind == "any":
        return True
    if inner.kind == "any":
        return outer.kind == "any"
    if outer.kind == "na":
        return inner.kind == "na"
    if inner.kind == "na":
        return outer.kind == "na"

    if inner.kind == "and":
        # An intersection is a subset of each of its members.
        return any(_contains(outer, item) for item in inner.items)

    if outer.kind == "lit":
        return inner.kind == "lit" and outer.value == inner.value

    if outer.kind == "pat":
        if inner.kind == "lit":
            return _pattern_matches(outer.value, inner.value)
        if inner.kind == "pat":
            return _pattern_contains(outer.value, inner.value)
        return False

    if outer.kind == "not":
        return _is_empty(_intersect(outer.items[0], inner))

    if outer.kind == "and":
        return all(_contains(item, inner) for item in outer.items)

    return False


def _intersect(left, right):
    """Return the intersection constraint, or ``_EMPTY``."""
    if left.kind == "empty" or right.kind == "empty":
        return _EMPTY
    if left.kind == "any":
        return right
    if right.kind == "any":
        return left

    if left.kind == "na" or right.kind == "na":
        if left.kind == "na" and right.kind == "na":
            return _NA
        return _EMPTY

    if left.kind == "lit" and right.kind == "lit":
        return left if left.value == right.value else _EMPTY

    if left.kind == "lit" and right.kind == "pat":
        return left if _pattern_matches(right.value, left.value) else _EMPTY
    if left.kind == "pat" and right.kind == "lit":
        return right if _pattern_matches(left.value, right.value) else _EMPTY

    if left.kind == "pat" and right.kind == "pat":
        if left.value == right.value:
            return left
        if _pattern_contains(left.value, right.value):
            return right
        if _pattern_contains(right.value, left.value):
            return left
        return _make_and((left, right))

    if left.kind == "not":
        if _contains(left.items[0], right):
            return _EMPTY
        inner = _intersect(left.items[0], right)
        if inner.kind == "empty":
            return right
        return _make_and((left, right))
    if right.kind == "not":
        return _intersect(right, left)

    if left.kind == "and":
        return _make_and([_intersect(item, right) for item in left.items])
    if right.kind == "and":
        return _make_and([_intersect(left, item) for item in right.items])

    return _make_and((left, right))


def _constraint_to_wfn(constraint):
    if constraint.kind == "any":
        return "ANY"
    if constraint.kind == "na":
        return "NA"
    if constraint.kind == "lit":
        return '"{0}"'.format(_wfn_escape(constraint.value))
    if constraint.kind == "pat":
        return '"{0}"'.format(constraint.value)
    return None


def _constraint_description(constraint):
    if constraint.kind == "any":
        return "ANY"
    if constraint.kind == "na":
        return "NA"
    if constraint.kind == "lit":
        return repr(constraint.value)
    if constraint.kind == "pat":
        return "pattern {0!r}".format(constraint.value)
    if constraint.kind == "not":
        return "not {0}".format(_constraint_description(constraint.items[0]))
    if constraint.kind == "and":
        return " and ".join(_constraint_description(item)
                            for item in constraint.items)
    return "empty"


# ---------------------------------------------------------------------------
# CPE range cubes
# ---------------------------------------------------------------------------


_ATTRS = CPEComponent.CPE_COMP_KEYS_EXTENDED
_ANY_CUBE = tuple(_ANY for unused in _ATTRS)


def _parse_cpe_range(value, label="CPE range"):
    try:
        cpe = value if isinstance(value, CPE) else CPE(str(value))
    except (ValueError, NotImplementedError) as error:
        raise ValueError("Invalid {0} '{1}': {2}".format(label, value, error))

    if cpe.VERSION != CPE.VERSION_2_3:
        raise ValueError(
            "{0} '{1}' is CPE {2}; CPE 2.3 is required".format(
                label, value, cpe.VERSION
            )
        )

    wfn = CPE2_3_WFN(cpe.as_wfn())
    cube = []
    for attribute in _ATTRS:
        values = wfn.get_attribute_values(attribute)
        raw = values[0] if values else "ANY"
        if raw == "ANY":
            constraint = _ANY
        elif raw == "NA":
            constraint = _NA
        else:
            if raw.startswith('"') and raw.endswith('"'):
                raw = raw[1:-1]
            constraint = _make_value(raw)
        cube.append(constraint)

    return tuple(cube), wfn.as_fs()


def _cube_intersect(left, right):
    pieces = [
        _intersect(left[index], right[index])
        for index in range(len(_ATTRS))
    ]
    if any(_is_empty(piece) for piece in pieces):
        return None
    return tuple(pieces)


def _cube_is_empty(cube):
    return cube is None or any(_is_empty(part) for part in cube)


def _cube_to_cpe(cube):
    if _cube_is_empty(cube):
        return None
    values = []
    for attribute, constraint in zip(_ATTRS, cube):
        value = _constraint_to_wfn(constraint)
        if value is None:
            return None
        values.append("{0}={1}".format(attribute, value))
    wfn = "wfn:[{0}]".format(", ".join(values))
    try:
        return CPE2_3_WFN(wfn).as_fs()
    except (ValueError, NotImplementedError):
        return None


def _cube_description(cube):
    if _cube_is_empty(cube):
        return "<empty>"
    parts = []
    for attribute, constraint in zip(_ATTRS, cube):
        if constraint.kind != "any":
            parts.append("{0}={1}".format(
                attribute, _constraint_description(constraint)
            ))
    return "CPE 2.3 range where " + ", ".join(parts) if parts else "CPE 2.3 range"


def _cube_subtract(cube, subtrahend):
    """Return a list of cubes representing ``cube - subtrahend``."""
    if _cube_is_empty(cube) or _cube_is_empty(subtrahend):
        return [cube]

    intersection = _cube_intersect(cube, subtrahend)
    if intersection is None:
        return [cube]

    if all(_contains(intersection[index], cube[index])
           for index in range(len(_ATTRS))):
        return []

    pieces = []
    for index in range(len(_ATTRS)):
        remainder = _intersect(
            cube[index], _make_not(intersection[index])
        )
        if _is_empty(remainder):
            continue

        piece = list(cube)
        for earlier in range(index):
            piece[earlier] = intersection[earlier]
        piece[index] = remainder
        pieces.append(tuple(piece))

    return pieces


def _subtract_many(cubes, subtrahends):
    result = list(cubes)
    for subtrahend in subtrahends:
        next_result = []
        for cube in result:
            next_result.extend(_cube_subtract(cube, subtrahend))
        result = next_result
    return result


def _cube_key(cube):
    return repr(cube)


def _merge_cubes(cubes):
    """Deduplicate ranges and drop ranges absorbed by a wider range."""
    unique = []
    seen = set()
    for cube in cubes:
        if _cube_is_empty(cube):
            continue
        key = _cube_key(cube)
        if key in seen:
            continue
        seen.add(key)
        unique.append(cube)

    merged = []
    for index, cube in enumerate(unique):
        absorbed = False
        for other_index, other in enumerate(unique):
            if index == other_index:
                continue
            if all(_contains(other[attr], cube[attr])
                   for attr in range(len(_ATTRS))):
                strictly_wider = any(
                    not _contains(cube[attr], other[attr])
                    for attr in range(len(_ATTRS))
                )
                # A wider range absorbs a narrower one.  For two equal
                # ranges, keep the earlier entry as a stable tie-break.
                if strictly_wider or other_index < index:
                    absorbed = True
                    break
        if not absorbed:
            merged.append(cube)
    return merged


def _covers(target, covers):
    return not _subtract_many([target], covers)


def _serialise_cubes(cubes):
    ranges = []
    exact = True
    for cube in cubes:
        value = _cube_to_cpe(cube)
        if value is None:
            exact = False
        else:
            ranges.append(value)
    return ranges, exact


def required_observations(value):
    """
    Return the CPE attributes constrained by an advisory range.

    ``part`` is structural and therefore omitted.  ``version`` is included
    whenever the advisory does not use ``*`` for that attribute, whether its
    value is concrete, a wildcard pattern or ``NA``.
    """
    cube, unused = _parse_cpe_range(value, "advisory range")
    return tuple(
        attribute
        for attribute, constraint in zip(_ATTRS, cube)
        if attribute != CPEComponent.ATT_PART and constraint.kind != "any"
    )


# ---------------------------------------------------------------------------
# Public collection-plan objects
# ---------------------------------------------------------------------------


_CHANNEL_COUNTER = [0]


class CollectionChannel(object):
    """
    A collection channel and the observations it can prove.

    :param name: human-readable channel name
    :param fields: iterable (or comma-separated string) of CPE attribute
        names that the channel can prove
    :param assets: CPE 2.3 range (or iterable of ranges) to which the
        channel applies.  ``None`` means "all assets"; an empty iterable
        means "no assets".

    ``observations=`` and ``scope=`` are accepted as aliases for ``fields``
    and ``assets``.
    """

    def __init__(self, name=None, fields=None, assets=None,
                 observations=None, scope=None, evidence=None,
                 asset_range=None, **kwargs):
        if fields is None and observations is not None:
            fields = observations
        if fields is None and evidence is not None:
            fields = evidence
        if assets is None and scope is not None:
            assets = scope
        if assets is None and asset_range is not None:
            assets = asset_range

        if fields is None:
            fields = kwargs.pop("proven_fields", None)
        if assets is None:
            assets = kwargs.pop("asset_scope", None)
        if kwargs:
            raise TypeError("Unexpected channel arguments: {0}".format(
                ", ".join(sorted(kwargs))
            ))

        # Allow CollectionChannel(fields, assets=...) without a name.
        if (fields is None and name is not None and
                not isinstance(name, _STRING_TYPES)):
            fields = name
            name = None

        if name is None:
            _CHANNEL_COUNTER[0] += 1
            name = "channel-{0}".format(_CHANNEL_COUNTER[0])

        self.name = str(name)
        self.fields = _normalise_fields(fields)

        if assets is None:
            self.scope_sources = (None,)
            self._scope_cubes = (_ANY_CUBE,)
            self.scope_ranges = (ALL_ASSETS_RANGE,)
        else:
            if isinstance(assets, _STRING_TYPES + (CPE,)):
                sources = (assets,)
            else:
                sources = tuple(assets)
            self.scope_sources = sources
            scopes = []
            ranges = []
            for source in sources:
                cube, canonical = _parse_cpe_range(source, "channel scope")
                scopes.append(cube)
                ranges.append(canonical)
            self._scope_cubes = tuple(scopes)
            self.scope_ranges = tuple(ranges)

    @property
    def observations(self):
        return self.fields

    @property
    def proven_fields(self):
        return self.fields

    @property
    def assets(self):
        return self.scope_ranges

    @property
    def scope(self):
        return self.scope_ranges

    def __repr__(self):
        return "CollectionChannel({0!r}, fields={1!r}, assets={2!r})".format(
            self.name, sorted(self.fields), list(self.scope_ranges)
        )

    def as_dict(self):
        return {
            "name": self.name,
            "fields": sorted(self.fields),
            "assets": list(self.scope_ranges),
        }

    @classmethod
    def from_dict(cls, value):
        if isinstance(value, cls):
            return value
        if isinstance(value, dict):
            data = dict(value)
            name = data.pop("name", None)
            fields = data.pop("fields", data.pop("observations", None))
            assets = data.pop("assets", data.pop("scope", None))
            return cls(name=name, fields=fields, assets=assets, **data)
        if hasattr(value, "fields") and hasattr(value, "assets"):
            return cls(
                name=getattr(value, "name", None),
                fields=value.fields,
                assets=value.assets,
            )
        raise TypeError(
            "A channel must be a CollectionChannel, a dict or an object "
            "with fields and assets"
        )


Channel = CollectionChannel


class AdvisoryCoverage(object):
    """Coverage verdict and diagnostics for one advisory range."""

    def __init__(self, advisory, cpe, status, asserted_ranges,
                 unclear_ranges, excluded_ranges, missing_observations,
                 channels, reason, partial=False, approximate=False):
        self.advisory = advisory
        self.cpe = cpe
        self.status = status
        self.asserted_ranges = tuple(asserted_ranges)
        self.unclear_ranges = tuple(unclear_ranges)
        self.excluded_ranges = tuple(excluded_ranges)
        self.missing_observations = tuple(missing_observations)
        self.channels = tuple(channels)
        self.reason = reason
        self.partial = bool(partial)
        self.approximate = bool(approximate)

    @property
    def range(self):
        return self.cpe

    @property
    def missing_fields(self):
        return tuple(
            value for value in self.missing_observations
            if value != "asset_scope"
        )

    @property
    def is_asserted(self):
        return self.status == "asserted"

    @property
    def is_unclear(self):
        return self.status == "unclear"

    @property
    def is_excluded(self):
        return self.status == "excluded"

    def as_dict(self):
        return {
            "advisory": str(self.advisory),
            "cpe": self.cpe,
            "status": self.status,
            "asserted_ranges": list(self.asserted_ranges),
            "unclear_ranges": list(self.unclear_ranges),
            "excluded_ranges": list(self.excluded_ranges),
            "missing_observations": list(self.missing_observations),
            "channels": list(self.channels),
            "reason": self.reason,
            "partial": self.partial,
            "approximate": self.approximate,
        }

    def __repr__(self):
        return (
            "AdvisoryCoverage({0!r}, status={1!r}, "
            "missing_observations={2!r})"
        ).format(self.cpe, self.status, self.missing_observations)


class CoverageReport(object):
    """Result of :func:`precheck_coverage`."""

    def __init__(self, assessments):
        self.assessments = tuple(assessments)

    def __iter__(self):
        return iter(self.assessments)

    def __len__(self):
        return len(self.assessments)

    def __getitem__(self, index):
        return self.assessments[index]

    @property
    def advisories(self):
        return self.assessments

    @property
    def asserted(self):
        return tuple(item for item in self.assessments if item.is_asserted)

    @property
    def unclear(self):
        return tuple(item for item in self.assessments if item.is_unclear)

    @property
    def unknown(self):
        return self.unclear

    @property
    def missed(self):
        return self.unclear

    @property
    def excluded(self):
        return tuple(item for item in self.assessments if item.is_excluded)

    @property
    def covered(self):
        return self.asserted

    @property
    def uncovered(self):
        return self.unclear

    @property
    def asserted_ranges(self):
        result = []
        for item in self.assessments:
            result.extend(item.asserted_ranges)
        return tuple(result)

    @property
    def covered_ranges(self):
        return self.asserted_ranges

    @property
    def unclear_ranges(self):
        result = []
        for item in self.assessments:
            result.extend(item.unclear_ranges)
        return tuple(result)

    @property
    def uncovered_ranges(self):
        return self.unclear_ranges

    @property
    def unknown_ranges(self):
        return self.unclear_ranges

    @property
    def excluded_ranges(self):
        result = []
        for item in self.assessments:
            result.extend(item.excluded_ranges)
        return tuple(result)

    @property
    def missing_observations(self):
        result = []
        for item in self.assessments:
            result.extend(item.missing_observations)
        return tuple(sorted(set(result)))

    @property
    def complete(self):
        return all(item.status in ("asserted", "excluded")
                   for item in self.assessments)

    @property
    def is_complete(self):
        return self.complete

    @property
    def fully_covered(self):
        return self.complete

    def as_dict(self):
        return {
            "complete": self.complete,
            "asserted_ranges": list(self.asserted_ranges),
            "unclear_ranges": list(self.unclear_ranges),
            "excluded_ranges": list(self.excluded_ranges),
            "missing_observations": list(self.missing_observations),
            "advisories": [item.as_dict() for item in self.assessments],
        }

    def summary(self):
        return (
            "{0} asserted, {1} unclear, {2} excluded; "
            "missing observations: {3}"
        ).format(
            len(self.asserted),
            len(self.unclear),
            len(self.excluded),
            ", ".join(self.missing_observations) or "none",
        )


class CoveragePrecheck(object):
    """
    Pre-check whether collection channels can assert advisory CPE ranges.

    :param advisories: advisory CPE 2.3 range or iterable of ranges
    :param channels: :class:`CollectionChannel` instances or dicts
    :param exclusions: explicit CPE 2.3 ranges to remove after merging
        channel coverage

    Exclusions are unioned first and then subtracted from the merged
    coverage, matching the "merge, then deduct" rule.  A range that is
    completely excluded is reported separately and is not a coverage gap.
    """

    def __init__(self, advisories=None, channels=None, exclusions=None,
                 advisory=None, exclude=None, advisory_ranges=None,
                 collection_channels=None, excluded=None):
        if advisories is None:
            advisories = advisory
        if advisories is None:
            advisories = advisory_ranges
        if advisories is None:
            raise TypeError("advisories are required")
        if channels is None:
            channels = collection_channels
        if channels is None:
            raise TypeError("channels are required")
        if exclusions is None:
            exclusions = exclude
        if exclusions is None:
            exclusions = excluded
        if exclusions is None:
            exclusions = ()

        if isinstance(advisories, _STRING_TYPES + (CPE,)):
            advisories = (advisories,)
        if isinstance(exclusions, _STRING_TYPES + (CPE,)):
            exclusions = (exclusions,)
        if isinstance(channels, (CollectionChannel, dict)):
            channels = (channels,)

        self.advisories = tuple(advisories)
        self.channels = tuple(
            CollectionChannel.from_dict(channel) for channel in channels
        )
        self.exclusions = tuple(exclusions)

        self._advisory_data = [
            _parse_cpe_range(value, "advisory range")
            for value in self.advisories
        ]
        self._exclusion_cubes = []
        self.exclusion_ranges = []
        for value in self.exclusions:
            cube, canonical = _parse_cpe_range(value, "exclusion")
            self._exclusion_cubes.append(cube)
            self.exclusion_ranges.append(canonical)

        # Explicit exclusions are unioned before they are deducted.
        self._merged_exclusions = _merge_cubes(self._exclusion_cubes)
        merged_ranges, unused = _serialise_cubes(self._merged_exclusions)
        self.merged_exclusions = tuple(merged_ranges)

    def run(self):
        assessments = []
        for index, (cube, canonical) in enumerate(self._advisory_data):
            assessments.append(
                self._assess(self.advisories[index], cube, canonical)
            )
        return CoverageReport(assessments)

    def check(self):
        return self.run()

    def analyze(self):
        return self.run()

    def _assess(self, advisory, advisory_cube, advisory_cpe):
        required = set(
            attribute
            for attribute, constraint in zip(_ATTRS, advisory_cube)
            if (attribute != CPEComponent.ATT_PART and
                constraint.kind != "any")
        )

        covered = []
        overlapping = set()
        capable = set()

        for channel in self.channels:
            channel_overlaps = []
            channel_is_capable = required.issubset(channel.fields)
            for scope in channel._scope_cubes:
                intersection = _cube_intersect(advisory_cube, scope)
                if intersection is None:
                    continue
                channel_overlaps.append(intersection)
                if channel_is_capable:
                    covered.append(intersection)

            if channel_overlaps:
                overlapping.add(channel.name)
                if channel_is_capable:
                    capable.add(channel.name)

        # Merge channel coverage first, then deduct merged exclusions.
        merged_coverage = _merge_cubes(covered)
        effective_coverage = _subtract_many(
            merged_coverage, self._merged_exclusions
        )
        effective_coverage = _merge_cubes(effective_coverage)

        excluded = []
        for exclusion in self._merged_exclusions:
            intersection = _cube_intersect(advisory_cube, exclusion)
            if intersection is not None:
                excluded.append(intersection)
        excluded = _merge_cubes(excluded)

        fully_excluded = _covers(advisory_cube, self._merged_exclusions)
        # Check coverage against the un-deducted union as well as the merged
        # exclusions.  This is the "merge, then deduct" rule: an exclusion can
        # split a representable range into pieces that no longer round-trip to
        # a single CPE range, but it must not turn a fully covered advisory
        # into a false coverage gap.
        residual = _subtract_many(
            [advisory_cube], merged_coverage + excluded
        )
        residual = _merge_cubes(residual)

        if fully_excluded:
            status = "excluded"
        elif not residual:
            status = "asserted"
        else:
            status = "unclear"

        partial = bool(effective_coverage) and bool(residual)

        if status == "asserted":
            asserted_ranges = (advisory_cpe,)
            approximate = False
        elif status == "excluded":
            asserted_ranges = ()
            approximate = False
        else:
            asserted_ranges, approximate = _serialise_cubes(effective_coverage)

        if status == "unclear":
            unclear_ranges, residual_exact = _serialise_cubes(residual)
            if not residual_exact or not unclear_ranges:
                # A non-CPE-complement residual cannot be represented as a
                # single range.  Fall back to the advisory range and mark the
                # report as approximate rather than silently dropping it.
                unclear_ranges = [advisory_cpe]
                approximate = True
        else:
            unclear_ranges = ()

        excluded_ranges, unused = _serialise_cubes(excluded)

        if status == "unclear":
            missing = self._missing_observations(
                residual, required
            )
            if missing == ("asset_scope",):
                reason = (
                    "no_channel_covers_range"
                    if not overlapping
                    else "asset_scope_gap"
                )
            else:
                reason = "missing_observation"
        elif status == "excluded":
            missing = ()
            reason = "explicitly_excluded"
        else:
            missing = ()
            reason = "asserted"

        return AdvisoryCoverage(
            advisory=advisory,
            cpe=advisory_cpe,
            status=status,
            asserted_ranges=asserted_ranges,
            unclear_ranges=unclear_ranges,
            excluded_ranges=excluded_ranges,
            missing_observations=missing,
            channels=sorted(overlapping),
            reason=reason,
            partial=partial,
            approximate=approximate,
        )

    def _missing_observations(self, residual, required):
        missing_fields = set()
        asset_gap = False

        for cube in residual:
            if _cube_is_empty(cube):
                continue

            missing_for_channels = []
            found_channel = False
            for channel in self.channels:
                for scope in channel._scope_cubes:
                    if _cube_intersect(cube, scope) is not None:
                        found_channel = True
                        missing_for_channels.append(
                            required - set(channel.fields)
                        )
                        break

            if not found_channel:
                asset_gap = True
                continue

            # Evidence is a property of one collector: do not assume that
            # two collectors observing different fields can be joined into a
            # single assertion.  Keep the closest collector's missing set.
            missing = min(
                missing_for_channels,
                key=lambda values: (len(values), tuple(sorted(values))),
            )
            if missing:
                missing_fields.update(missing)
            else:
                # The observation types exist, but no channel reaches every
                # asset in this residual range.
                asset_gap = True

        result = tuple(sorted(missing_fields))
        if asset_gap:
            result = tuple(sorted(set(result) | set(("asset_scope",))))
        if not result:
            return ("asset_scope",)
        return result


CollectionPlan = CoveragePrecheck


def precheck_coverage(advisories=None, channels=None, exclusions=None,
                      advisory=None, exclude=None, advisory_ranges=None,
                      collection_channels=None, excluded=None):
    """Analyse a collection plan and return a :class:`CoverageReport`."""
    return CoveragePrecheck(
        advisories=advisories,
        channels=channels,
        exclusions=exclusions,
        advisory=advisory,
        exclude=exclude,
        advisory_ranges=advisory_ranges,
        collection_channels=collection_channels,
        excluded=excluded,
    ).run()


analyze_coverage = precheck_coverage
check_coverage = precheck_coverage
precheck = precheck_coverage
