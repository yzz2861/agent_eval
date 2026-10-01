from __future__ import annotations

from fractions import Fraction
from typing import Any

from attrs import frozen

from jsonschema import _types


CONSTRUCTIBLE = "constructible"
CONTRADICTORY = "contradictory"
UNKNOWN = "unknown"

DEFAULT_SEARCH_BUDGET = 1000

_ANNOTATION_KEYWORDS = frozenset({
    "$anchor",
    "$comment",
    "$defs",
    "$dynamicAnchor",
    "$id",
    "$recursiveAnchor",
    "$schema",
    "$vocabulary",
    "default",
    "definitions",
    "deprecated",
    "description",
    "examples",
    "id",
    "readOnly",
    "title",
    "writeOnly",
})

_SUPPORTED_KEYWORDS = frozenset({
    "additionalProperties",
    "allOf",
    "anyOf",
    "const",
    "enum",
    "exclusiveMaximum",
    "exclusiveMinimum",
    "maxLength",
    "maximum",
    "minLength",
    "minimum",
    "properties",
    "required",
    "type",
})

_STANDARD_TYPE_CHECKERS = frozenset({
    _types.draft3_type_checker,
    _types.draft4_type_checker,
    _types.draft6_type_checker,
    _types.draft7_type_checker,
    _types.draft201909_type_checker,
    _types.draft202012_type_checker,
})


@frozen
class UnsupportedKeyword:
    path: tuple[str | int, ...]
    keyword: str
    reason: str


@frozen
class Conflict:
    paths: tuple[tuple[str | int, ...], ...] = ()
    alternatives: tuple["Conflict", ...] = ()


@frozen
class ContradictionResult:
    status: str
    example: Any = None
    conflict: Conflict | None = None
    unsupported: tuple[UnsupportedKeyword, ...] = ()
    budget_exhausted: bool = False
    search_budget: int = DEFAULT_SEARCH_BUDGET


@frozen
class _Budget:
    remaining: int

    def charge(self, amount: int = 1) -> bool:
        if self.remaining <= 0:
            return False
        charged = min(amount, self.remaining)
        object.__setattr__(self, "remaining", self.remaining - charged)
        return self.remaining > 0 or charged == amount


@frozen
class _FalseSchema:
    source: tuple[str | int, ...]


@frozen
class _TypeConstraint:
    source: tuple[str | int, ...]
    types: frozenset[str]


@frozen
class _EnumValues:
    source: tuple[str | int, ...]
    values: tuple[Any, ...]


@frozen
class _FixedValue:
    sources: tuple[tuple[str | int, ...], ...]
    value: Any


@frozen
class _Minimum:
    source: tuple[str | int, ...]
    value: Fraction
    inclusive: bool


@frozen
class _Maximum:
    source: tuple[str | int, ...]
    value: Fraction
    inclusive: bool


@frozen
class _MinLength:
    source: tuple[str | int, ...]
    value: int


@frozen
class _MaxLength:
    source: tuple[str | int, ...]
    value: int


@frozen
class _Required:
    source: tuple[str | int, ...]
    name: str


@frozen
class _Property:
    source: tuple[str | int, ...]
    name: str
    formula: "_Formula"
    evaluated: bool = True


@frozen
class _AdditionalSchema:
    source: tuple[str | int, ...]
    formula: "_Formula"


@frozen
class _Formula:
    atoms: tuple[Any, ...] = ()
    properties: tuple[_Property, ...] = ()
    additional: tuple[_AdditionalSchema, ...] = ()
    groups: tuple[tuple["_Formula", ...], ...] = ()


@frozen
class _Sat:
    examples: tuple[Any, ...]


@frozen
class _Unsat:
    conflict: Conflict


class _Unknown:
    pass


_UNKNOWN = _Unknown()
_EMPTY_FORMULA = _Formula()


def check_contradiction(
    schema: Any,
    validator: Any = None,
    *,
    search_budget: int = DEFAULT_SEARCH_BUDGET,
) -> ContradictionResult:
    """Check whether the supported schema fragment is satisfiable."""
    if validator is None:
        from jsonschema.validators import validator_for

        validator = validator_for(schema)(schema)
    elif isinstance(validator, type):
        validator = validator(schema)
    elif getattr(validator, "schema", None) != schema:
        validator = validator.evolve(schema=schema)

    budget = _Budget(max(1, search_budget))
    unsupported: list[UnsupportedKeyword] = []
    formula = _parse_schema(
        validator.schema,
        (),
        validator,
        budget,
        unsupported,
    )
    exhausted = budget.remaining == 0
    integral_floats = _supports_integral_floats(validator)
    outcome = _solve_formula(formula, budget, integral_floats)

    if exhausted:
        return ContradictionResult(
            status=UNKNOWN,
            unsupported=tuple(unsupported),
            budget_exhausted=True,
            search_budget=search_budget,
        )

    if isinstance(outcome, _Sat):
        for example in outcome.examples:
            try:
                valid = validator.is_valid(example)
            except Exception:
                continue
            if valid:
                return ContradictionResult(
                    status=CONSTRUCTIBLE,
                    example=example,
                    unsupported=tuple(unsupported),
                    budget_exhausted=exhausted,
                    search_budget=search_budget,
                )
        return ContradictionResult(
            status=UNKNOWN,
            unsupported=tuple(unsupported),
            budget_exhausted=exhausted,
            search_budget=search_budget,
        )

    if isinstance(outcome, _Unsat) and not exhausted:
        return ContradictionResult(
            status=CONTRADICTORY,
            conflict=outcome.conflict,
            unsupported=tuple(unsupported),
            search_budget=search_budget,
        )

    return ContradictionResult(
        status=UNKNOWN,
        unsupported=tuple(unsupported),
        budget_exhausted=exhausted or isinstance(outcome, _Unknown),
        search_budget=search_budget,
    )


def _parse_schema(schema, path, validator, budget, unsupported):
    if not budget.charge():
        return _EMPTY_FORMULA
    if schema is True:
        return _EMPTY_FORMULA
    if schema is False:
        return _Formula(atoms=(_FalseSchema(path),))
    if not isinstance(schema, dict):
        unsupported.append(
            UnsupportedKeyword(
                path,
                "",
                "schema must be an object or boolean",
            ),
        )
        return _EMPTY_FORMULA

    formula = _EMPTY_FORMULA
    ref_siblings_ignored = (
        "$ref" in schema
        and "$ref" in validator.VALIDATORS
        and "allOf" not in validator.VALIDATORS
    )

    for keyword, value in schema.items():
        if ref_siblings_ignored and keyword != "$ref":
            continue
        keyword_path = (*path, keyword)

        if keyword in _ANNOTATION_KEYWORDS:
            continue
        legacy_bound = (
            keyword in {"exclusiveMinimum", "exclusiveMaximum"}
            and isinstance(value, bool)
            and _has_legacy_bounds(validator)
        )
        if (
            (
                keyword not in _SUPPORTED_KEYWORDS
                or keyword not in validator.VALIDATORS
            )
            and not legacy_bound
        ):
            unsupported.append(
                UnsupportedKeyword(
                    keyword_path,
                    str(keyword),
                    "unsupported keyword",
                ),
            )
            continue

        if keyword == "allOf":
            formula = _merge(formula, _parse_all_of(
                value,
                keyword_path,
                validator,
                budget,
                unsupported,
            ))
        elif keyword == "anyOf":
            formula = _merge(
                formula,
                _parse_any_of(
                    value,
                    keyword_path,
                    validator,
                    budget,
                    unsupported,
                ),
            )
        elif keyword == "properties":
            formula = _merge(
                formula,
                _parse_properties(
                    value,
                    keyword_path,
                    validator,
                    budget,
                    unsupported,
                ),
            )
        elif keyword == "additionalProperties":
            formula = _merge(
                formula,
                _parse_additional(
                    value,
                    keyword_path,
                    schema,
                    validator,
                    budget,
                    unsupported,
                ),
            )
        elif keyword == "required":
            formula = _merge(
                formula,
                _parse_required(value, keyword_path, unsupported),
            )
        elif keyword == "type":
            atom = _parse_type(
                value,
                keyword_path,
                validator,
                unsupported,
            )
            if atom is not None:
                formula = _merge(formula, _Formula(atoms=(atom,)))
        elif keyword == "enum":
            atom = _parse_enum(value, keyword_path, unsupported)
            if atom is not None:
                formula = _merge(formula, _Formula(atoms=(atom,)))
        elif keyword == "const":
            atom = _FixedValue((keyword_path,), value)
            formula = _merge(formula, _Formula(atoms=(atom,)))
        elif keyword in {"minimum", "maximum", "exclusiveMinimum",
                         "exclusiveMaximum"}:
            if (
                keyword in {"exclusiveMinimum", "exclusiveMaximum"}
                and isinstance(value, bool)
                and _has_legacy_bounds(validator)
            ):
                continue
            atom = _parse_bound(
                keyword,
                value,
                schema,
                keyword_path,
                validator,
                unsupported,
            )
            if atom is not None:
                formula = _merge(formula, _Formula(atoms=(atom,)))
        elif keyword in {"minLength", "maxLength"}:
            atom = _parse_length(keyword, value, keyword_path, unsupported)
            if atom is not None:
                formula = _merge(formula, _Formula(atoms=(atom,)))

    return formula


def _merge(left, right):
    atoms = list(left.atoms)
    properties = list(left.properties)
    additional = list(left.additional)
    groups = list(left.groups)

    for atom in right.atoms:
        atoms = _merge_atom(atoms, atom)

    for property in right.properties:
        properties.append(_Property(
            source=property.source,
            name=property.name,
            formula=property.formula,
            evaluated=property.evaluated,
        ))

    additional.extend(right.additional)
    groups.extend(right.groups)
    return _Formula(
        atoms=tuple(atoms),
        properties=tuple(properties),
        additional=tuple(additional),
        groups=tuple(groups),
    )


def _merge_atom(atoms, atom):
    if isinstance(atom, _FixedValue):
        for index, existing in enumerate(atoms):
            if isinstance(existing, _FixedValue):
                if _json_equal(existing.value, atom.value):
                    merged = _FixedValue(
                        existing.sources + atom.sources,
                        atom.value,
                    )
                    return [*atoms[:index], merged, *atoms[index + 1:]]
                return [*atoms, atom]
        return [*atoms, atom]

    return [*atoms, atom]


def _has_legacy_bounds(validator):
    minimum = validator.VALIDATORS.get("minimum")
    maximum = validator.VALIDATORS.get("maximum")
    return (
        minimum is not None
        and maximum is not None
        and minimum.__name__ == "minimum_draft3_draft4"
        and maximum.__name__ == "maximum_draft3_draft4"
    )


def _json_equal(left, right):
    if left is True or left is False or right is True or right is False:
        return type(left) is type(right) and left == right
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(
            _json_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(
            _json_equal(left_item, right_item)
            for left_item, right_item in zip(left, right)
        )
    return left == right


def _as_unevaluated(formula):
    properties = tuple(
        _unevaluate_property(property)
        for property in formula.properties
    )
    groups = tuple(
        tuple(_as_unevaluated(branch) for branch in group)
        for group in formula.groups
    )
    return _Formula(
        atoms=formula.atoms,
        properties=properties,
        additional=formula.additional,
        groups=groups,
    )


def _unevaluate_property(property):
    return _Property(
        source=property.source,
        name=property.name,
        formula=_as_unevaluated(property.formula),
        evaluated=False,
    )


def _parse_all_of(value, path, validator, budget, unsupported):
    if not isinstance(value, list):
        unsupported.append(
            UnsupportedKeyword(path, "allOf", "must be a list"),
        )
        return _EMPTY_FORMULA

    formula = _EMPTY_FORMULA
    for index, subschema in enumerate(value):
        formula = _merge(
            formula,
            _parse_schema(
                subschema,
                (*path, index),
                validator,
                budget,
                unsupported,
            ),
        )
    return _as_unevaluated(formula)


def _parse_any_of(value, path, validator, budget, unsupported):
    if not isinstance(value, list):
        unsupported.append(
            UnsupportedKeyword(path, "anyOf", "must be a list"),
        )
        return _EMPTY_FORMULA
    if not value:
        return _Formula(atoms=(_FalseSchema(path),))
    return _Formula(groups=(tuple(
        _as_unevaluated(_parse_schema(
            subschema,
            (*path, index),
            validator,
            budget,
            unsupported,
        ))
        for index, subschema in enumerate(value)
    ),))


def _parse_properties(value, path, validator, budget, unsupported):
    if not isinstance(value, dict):
        unsupported.append(
            UnsupportedKeyword(path, "properties", "must be an object"),
        )
        return _EMPTY_FORMULA

    properties = tuple(
        _Property(
            source=(*path, name),
            name=name,
            formula=_parse_schema(
                subschema,
                (*path, name),
                validator,
                budget,
                unsupported,
            ),
        )
        for name, subschema in value.items()
    )
    return _Formula(properties=properties)


def _parse_additional(
    value,
    path,
    schema,
    validator,
    budget,
    unsupported,
):
    if "patternProperties" in schema:
        return _EMPTY_FORMULA
    if value is True:
        return _EMPTY_FORMULA
    if value is False:
        false_formula = _Formula(atoms=(_FalseSchema(path),))
        return _Formula(additional=(_AdditionalSchema(path, false_formula),))
    if not isinstance(value, dict):
        unsupported.append(
            UnsupportedKeyword(
                path,
                "additionalProperties",
                "must be a schema",
            ),
        )
        return _EMPTY_FORMULA

    formula = _parse_schema(value, path, validator, budget, unsupported)
    return _Formula(additional=(_AdditionalSchema(path, formula),))


def _parse_required(value, path, unsupported):
    if not isinstance(value, list) or not all(
        isinstance(name, str) for name in value
    ):
        unsupported.append(
            UnsupportedKeyword(path, "required", "must be a list of strings"),
        )
        return _EMPTY_FORMULA

    names = set()
    atoms = []
    for index, name in enumerate(value):
        if name in names:
            continue
        names.add(name)
        atoms.append(_Required((*path, index), name))
    return _Formula(atoms=tuple(atoms))


def _parse_type(value, path, validator, unsupported):
    if validator.TYPE_CHECKER not in _STANDARD_TYPE_CHECKERS:
        unsupported.append(
            UnsupportedKeyword(
                path,
                "type",
                "custom TypeChecker is unsupported",
            ),
        )
        return None

    values = value if isinstance(value, list) else [value]
    if not values or not all(isinstance(name, str) for name in values):
        unsupported.append(
            UnsupportedKeyword(path, "type", "must be a string or list"),
        )
        return None

    try:
        types = frozenset().union(*(_expanded_type(name) for name in values))
    except Exception:
        unsupported.append(UnsupportedKeyword(path, "type", "unknown type"))
        return None

    return _TypeConstraint(path, types)


def _expanded_type(name):
    if name == "any":
        return frozenset({
            "null",
            "boolean",
            "object",
            "array",
            "string",
            "integer",
            "noninteger",
        })
    if name == "number":
        return frozenset({"integer", "noninteger"})
    if name in {"null", "boolean", "object", "array", "string",
                "integer"}:
        return frozenset({name})
    raise ValueError(name)


def _parse_enum(value, path, unsupported):
    if not isinstance(value, list):
        unsupported.append(
            UnsupportedKeyword(path, "enum", "must be a list"),
        )
        return None
    return _EnumValues(path, tuple(value))


def _parse_bound(
    keyword,
    value,
    schema,
    path,
    validator,
    unsupported,
):
    if (
        keyword in {"exclusiveMinimum", "exclusiveMaximum"}
        and isinstance(value, bool)
        and _has_legacy_bounds(validator)
    ):
        return None

    if not isinstance(value, (int, float)) or isinstance(value, bool):
        unsupported.append(
            UnsupportedKeyword(path, keyword, "bound must be numeric"),
        )
        return None

    number = Fraction(value)
    if keyword == "minimum":
        legacy = (
            "exclusiveMinimum" in schema
            and validator.VALIDATORS.get("minimum")
            and validator.VALIDATORS["minimum"].__name__
            == "minimum_draft3_draft4"
        )
        exclusive = (
            legacy
            and schema.get("exclusiveMinimum", False) is True
        )
        return _Minimum(path, number, not exclusive)

    if keyword == "maximum":
        legacy = (
            "exclusiveMaximum" in schema
            and validator.VALIDATORS.get("maximum")
            and validator.VALIDATORS["maximum"].__name__
            == "maximum_draft3_draft4"
        )
        exclusive = (
            legacy
            and schema.get("exclusiveMaximum", False) is True
        )
        return _Maximum(path, number, not exclusive)

    inclusive = False
    number_type = _Minimum if keyword == "exclusiveMinimum" else _Maximum
    return number_type(path, number, inclusive)


def _parse_length(keyword, value, path, unsupported):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        unsupported.append(
            UnsupportedKeyword(
                path,
                keyword,
                "length must be a non-negative integer",
            ),
        )
        return None

    length_type = _MinLength if keyword == "minLength" else _MaxLength
    return length_type(path, value)


def _supports_integral_floats(validator):
    return validator.TYPE_CHECKER not in {
        _types.draft3_type_checker,
        _types.draft4_type_checker,
    }


def _solve_formula(formula, budget, integral_floats):
    base_conflict = _flat_base_conflict(formula)
    if base_conflict is not None:
        return _Unsat(base_conflict)

    if not formula.groups:
        return _solve_flat(formula, budget, integral_floats)

    group, *remaining_groups = formula.groups
    base = _Formula(
        atoms=formula.atoms,
        properties=formula.properties,
        additional=formula.additional,
        groups=tuple(remaining_groups),
    )
    examples = []
    unknown = False
    conflicts = []

    for branch in group:
        if not budget.charge():
            unknown = True
            break
        outcome = _solve_formula(
            _merge(base, branch),
            budget,
            integral_floats,
        )
        if isinstance(outcome, _Sat):
            examples.extend(outcome.examples)
            if len(examples) >= 8:
                return _Sat(tuple(examples))
        elif isinstance(outcome, _Unknown):
            unknown = True
        else:
            conflicts.append(outcome.conflict)

    if examples:
        return _Sat(tuple(examples))
    if unknown or len(conflicts) != len(group):
        return _UNKNOWN
    conflict = Conflict(alternatives=tuple(conflicts))
    return _Unsat(conflict)


def _flat_base_conflict(formula):
    false_atoms = [
        atom for atom in formula.atoms if isinstance(atom, _FalseSchema)
    ]
    if false_atoms:
        return Conflict(paths=(false_atoms[0].source,))

    fixed = [atom for atom in formula.atoms if isinstance(atom, _FixedValue)]
    if len({_fingerprint(atom.value) for atom in fixed}) > 1:
        return Conflict(paths=tuple(atom.sources[0] for atom in fixed[:2]))

    enums = [atom for atom in formula.atoms if isinstance(atom, _EnumValues)]
    enum_conflict = _enum_intersection_conflict(enums, fixed)
    if enum_conflict is not None:
        return enum_conflict

    type_atoms = [
        atom for atom in formula.atoms if isinstance(atom, _TypeConstraint)
    ]
    if type_atoms and not _intersect_types(type_atoms):
        return _type_intersection_conflict(type_atoms)
    return None


def _enum_intersection_conflict(enums, fixed):
    if fixed and enums:
        allowed = fixed[0].value
        for enum in enums:
            if not any(_json_equal(allowed, value) for value in enum.values):
                return Conflict(paths=(fixed[0].sources[0], enum.source))
        return None

    if len(enums) < 2:
        return None

    if any(not enum.values for enum in enums):
        return Conflict(paths=(next(
            enum.source for enum in enums if not enum.values
        ),))

    minimal = list(enums)
    for enum in enums:
        remaining = [other for other in minimal if other is not enum]
        if not _enum_values_intersect(remaining):
            minimal = remaining

    if _enum_values_intersect(minimal):
        return None
    return Conflict(paths=tuple(enum.source for enum in minimal))


def _enum_values_intersect(enums):
    if not enums:
        return True
    values = set(map(_fingerprint, enums[0].values))
    for enum in enums[1:]:
        values &= set(map(_fingerprint, enum.values))
        if not values:
            return False
    return bool(values)


def _intersect_types(type_atoms):
    intersection = set(type_atoms[0].types)
    for atom in type_atoms[1:]:
        intersection &= atom.types
    return frozenset(intersection)


def _type_intersection_conflict(type_atoms):
    for size in range(2, len(type_atoms) + 1):
        for start in range(0, len(type_atoms) - size + 1):
            subset = type_atoms[start:start + size]
            if not _intersect_types(subset):
                return Conflict(paths=tuple(atom.source for atom in subset))
    return Conflict(paths=(type_atoms[0].source,))


def _fingerprint(value):
    if isinstance(value, dict):
        return ("object", tuple(sorted(
            (key, _fingerprint(item)) for key, item in value.items()
        )))
    if isinstance(value, list):
        return ("array", tuple(_fingerprint(item) for item in value))
    return (type(value).__name__, value)


def _solve_flat(formula, budget, integral_floats):
    fixed = [atom for atom in formula.atoms if isinstance(atom, _FixedValue)]
    enums = [atom for atom in formula.atoms if isinstance(atom, _EnumValues)]

    if fixed:
        return _validate_value(
            formula,
            fixed[0].value,
            fixed[0].sources,
            budget,
            integral_floats,
        )

    if enums:
        if not enums[0].values:
            return _Unsat(Conflict(paths=(enums[0].source,)))
        candidates = list(enums[0].values)
        for enum in enums[1:]:
            candidates = [
                value
                for value in candidates
                if any(_json_equal(value, other) for other in enum.values)
            ]
        conflicts = []
        examples = []
        for value in candidates:
            if not budget.charge():
                return _UNKNOWN
            outcome = _validate_value(
                formula,
                value,
                (enums[0].source,),
                budget,
                integral_floats,
            )
            if isinstance(outcome, _Sat):
                examples.append(value)
                if len(examples) == 3:
                    return _Sat(tuple(examples))
            elif isinstance(outcome, _Unknown):
                return _UNKNOWN
            else:
                conflicts.append(outcome.conflict)
        if examples:
            return _Sat(tuple(examples))
        if not conflicts:
            return _Unsat(Conflict(paths=(enums[0].source,)))
        return _Unsat(Conflict(alternatives=tuple(conflicts)))

    type_atoms = [
        atom for atom in formula.atoms if isinstance(atom, _TypeConstraint)
    ]
    allowed = frozenset().union(*(atom.types for atom in type_atoms))
    if type_atoms:
        outcomes = []
        examples = []
        unknown = False
        for type_name in _candidate_type_order(allowed):
            if not budget.charge():
                return _UNKNOWN
            outcome = _construct_typed(
                type_name,
                formula,
                type_atoms,
                budget,
                integral_floats,
            )
            if isinstance(outcome, _Sat):
                examples.extend(outcome.examples)
                return _Sat(tuple(examples))
            if isinstance(outcome, _Unknown):
                unknown = True
                continue
            outcomes.append(outcome.conflict)
        if unknown and not outcomes:
            return _UNKNOWN
        if len(outcomes) == 1:
            return _UNKNOWN if unknown else _Unsat(outcomes[0])
        if unknown:
            return _UNKNOWN
        return _Unsat(Conflict(alternatives=tuple(outcomes)))

    if formula.properties or formula.additional or any(
        isinstance(atom, _Required) for atom in formula.atoms
    ):
        object_outcome = _construct_object(
            formula,
            budget,
            integral_floats,
            (),
        )
        if isinstance(object_outcome, _Sat):
            return object_outcome
        if isinstance(object_outcome, _Unknown):
            return _UNKNOWN

    for value in (None, True, [], 0, 0.5, ""):
        if not budget.charge():
            return _UNKNOWN
        outcome = _validate_value(
            formula,
            value,
            (),
            budget,
            integral_floats,
        )
        if isinstance(outcome, _Sat):
            return _Sat((value,))
        if isinstance(outcome, _Unknown):
            return _UNKNOWN
    return _UNKNOWN


def _candidate_type_order(allowed):
    order = [
        "null",
        "boolean",
        "array",
        "integer",
        "noninteger",
        "string",
        "object",
    ]
    return [name for name in order if name in allowed]


def _construct_typed(
    type_name,
    formula,
    type_atoms,
    budget,
    integral_floats,
):
    type_source = next(
        atom.source
        for atom in type_atoms
        if type_name in atom.types
        or (type_name == "noninteger" and "noninteger" in atom.types)
    )

    if type_name == "null":
        return _Sat((None,))
    if type_name == "boolean":
        return _Sat((True,))
    if type_name == "array":
        return _Sat(([],))
    if type_name in {"integer", "noninteger"}:
        return _construct_number(
            type_name,
            formula,
            type_source,
            integral_floats,
        )
    if type_name == "string":
        return _construct_string(formula, type_source)
    return _construct_object(
        formula,
        budget,
        integral_floats,
        (type_source,),
    )


def _construct_number(type_name, formula, type_source, integral_floats):
    minima = [atom for atom in formula.atoms if isinstance(atom, _Minimum)]
    maxima = [atom for atom in formula.atoms if isinstance(atom, _Maximum)]
    lower = max((atom.value for atom in minima), default=None)
    upper = min((atom.value for atom in maxima), default=None)

    if type_name == "integer":
        low = _integer_lower(minima)
        high = _integer_upper(maxima)
        if low is not None and high is not None and low <= high:
            return _Sat((low,))
        conflict_sources = [type_source]
        if lower is not None:
            conflict_sources.append(_closest_minimum(lower, minima).source)
        if upper is not None:
            conflict_sources.append(_closest_maximum(upper, maxima).source)
        return _Unsat(Conflict(paths=tuple(conflict_sources)))

    if lower is not None and upper is not None and lower < upper:
        value = _float_between(lower, upper, minima, maxima)
        if value is not None:
            return _Sat((value,))

    if lower is None or upper is None or lower < upper:
        return _UNKNOWN

    conflict_sources = [type_source]
    if lower is not None:
        conflict_sources.append(_closest_minimum(lower, minima).source)
    if upper is not None:
        conflict_sources.append(_closest_maximum(upper, maxima).source)
    return _Unsat(Conflict(paths=tuple(conflict_sources)))


def _integer_lower(minima):
    if not minima:
        return 0
    value = max(atom.value for atom in minima)
    atom = _closest_minimum(value, minima)
    if atom.inclusive and value.denominator == 1:
        return int(value)
    return int(value.numerator // value.denominator) + 1


def _integer_upper(maxima):
    if not maxima:
        return 2**64
    value = min(atom.value for atom in maxima)
    atom = _closest_maximum(value, maxima)
    if atom.inclusive and value.denominator == 1:
        return int(value)
    return int(-(-value.numerator // value.denominator)) - 1


def _closest_minimum(value, minima):
    return next(atom for atom in minima if atom.value == value)


def _closest_maximum(value, maxima):
    return next(atom for atom in maxima if atom.value == value)


def _float_between(lower, upper, minima, maxima):
    quarter = (upper - lower) / 4
    candidates = [
        float(lower + quarter),
        float(lower + 2 * quarter),
        float(lower + 3 * quarter),
    ]
    for candidate in candidates:
        if _number_passes(candidate, minima, maxima):
            return candidate
    return None




def _number_passes(value, minima, maxima):
    number = Fraction(value)
    return all(
        number > atom.value if not atom.inclusive else number >= atom.value
        for atom in minima
    ) and all(
        number < atom.value if not atom.inclusive else number <= atom.value
        for atom in maxima
    )


def _construct_string(formula, type_source):
    min_lengths = [
        atom for atom in formula.atoms if isinstance(atom, _MinLength)
    ]
    max_lengths = [
        atom for atom in formula.atoms if isinstance(atom, _MaxLength)
    ]
    minimum = max((atom.value for atom in min_lengths), default=0)
    maximum = min((atom.value for atom in max_lengths), default=None)

    if maximum is None or minimum <= maximum:
        return _Sat(("a" * minimum,))

    return _Unsat(Conflict(paths=(
        type_source,
        next(atom.source for atom in min_lengths if atom.value == minimum),
        next(atom.source for atom in max_lengths if atom.value == maximum),
    )))


def _property_formulas(formula):
    merged = {}
    for property in formula.properties:
        existing = merged.get(property.name)
        if existing is None:
            merged[property.name] = property
            continue

        merged[property.name] = _Property(
            source=existing.source,
            name=property.name,
            formula=_merge(existing.formula, property.formula),
            evaluated=existing.evaluated or property.evaluated,
        )
    return merged


def _construct_object(formula, budget, integral_floats, type_sources):
    required = {
        atom.name: atom
        for atom in formula.atoms
        if isinstance(atom, _Required)
    }
    properties = _property_formulas(formula)
    additional_schemas = formula.additional
    additional_false = [
        additional.source
        for additional in additional_schemas
        if any(
            isinstance(atom, _FalseSchema)
            for atom in additional.formula.atoms
        )
    ]

    if additional_false:
        evaluated_names = {
            name
            for name, property in properties.items()
            if property.evaluated
        }
        blocked = set(required) - evaluated_names
        if blocked:
            name = next(iter(blocked))
            return _Unsat(Conflict(paths=(
                *type_sources,
                additional_false[0],
                required[name].source,
            )))

    instance = {}
    for name in required:
        if not budget.charge():
            return _UNKNOWN
        property_formula = properties.get(name)
        if property_formula is not None:
            child = _solve_formula(
                property_formula.formula,
                budget,
                integral_floats,
            )
            if isinstance(child, _Sat):
                instance[name] = child.examples[0]
            elif isinstance(child, _Unsat):
                return _Unsat(_nested_property_conflict(
                    type_sources,
                    required[name],
                    property_formula.source,
                    child.conflict,
                ))
            else:
                return _UNKNOWN
        elif additional_schemas:
            additional = additional_schemas[0]
            child = _solve_formula(
                additional.formula,
                budget,
                integral_floats,
            )
            if isinstance(child, _Sat):
                instance[name] = child.examples[0]
            elif isinstance(child, _Unsat):
                return _Unsat(_nested_property_conflict(
                    type_sources,
                    required[name],
                    additional.source,
                    child.conflict,
                ))
            else:
                return _UNKNOWN
        else:
            instance[name] = None

    return _Sat((instance,))


def _nested_property_conflict(
    type_sources,
    required,
    schema_source,
    child_conflict,
):
    alternatives = (
        child_conflict.alternatives
        if not child_conflict.paths
        else (child_conflict,)
    )
    return Conflict(
        paths=(
            *type_sources,
            required.source,
            schema_source,
        ),
        alternatives=alternatives,
    )


def _formula_without_groups(formula):
    return _Formula(
        atoms=formula.atoms,
        properties=formula.properties,
        additional=formula.additional,
    )


def _validate_groups(
    formula,
    value,
    value_sources,
    budget,
    integral_floats,
):
    group, *remaining_groups = formula.groups
    conflicts = []
    for branch in group:
        candidate = _merge(_formula_without_groups(formula), branch)
        candidate = _Formula(
            atoms=candidate.atoms,
            properties=candidate.properties,
            additional=candidate.additional,
            groups=tuple(remaining_groups),
        )
        outcome = _validate_value(
            candidate,
            value,
            value_sources,
            budget,
            integral_floats,
        )
        if isinstance(outcome, _Sat):
            return outcome
        if isinstance(outcome, _Unknown):
            return outcome
        conflicts.append(outcome.conflict)
    return _Unsat(Conflict(alternatives=tuple(conflicts)))


def _validate_value(
    formula,
    value,
    value_sources,
    budget,
    integral_floats,
):
    if not budget.charge():
        return _UNKNOWN
    if any(isinstance(atom, _FalseSchema) for atom in formula.atoms):
        false_atom = next(
            atom for atom in formula.atoms if isinstance(atom, _FalseSchema)
        )
        return _Unsat(Conflict(paths=value_sources + (false_atom.source,)))

    if formula.groups:
        return _validate_groups(
            formula,
            value,
            value_sources,
            budget,
            integral_floats,
        )

    type_atoms = [
        atom for atom in formula.atoms if isinstance(atom, _TypeConstraint)
    ]
    if type_atoms:
        actual_type = _actual_type(value, integral_floats)
        matching = [atom for atom in type_atoms if actual_type in atom.types]
        if not matching:
            return _Unsat(Conflict(paths=(
                *value_sources,
                type_atoms[0].source,
            )))

    if isinstance(value, dict):
        return _validate_object(
            formula,
            value,
            value_sources,
            budget,
            integral_floats,
        )

    enum_atoms = [
        atom for atom in formula.atoms if isinstance(atom, _EnumValues)
    ]
    failed_enum = next(
        (
            atom
            for atom in enum_atoms
            if not any(_json_equal(value, enum_value)
                       for enum_value in atom.values)
        ),
        None,
    )
    if failed_enum is not None:
        return _Unsat(Conflict(paths=(
            *value_sources,
            failed_enum.source,
        )))

    if isinstance(value, bool):
        return _Sat((value,))
    if value is None or isinstance(value, list):
        return _Sat((value,))

    if isinstance(value, (int, float)):
        number = Fraction(value)
        minima = [
            atom for atom in formula.atoms if isinstance(atom, _Minimum)
        ]
        maxima = [
            atom for atom in formula.atoms if isinstance(atom, _Maximum)
        ]
        failed = [
            atom.source
            for atom in minima
            if (
                number <= atom.value
                if not atom.inclusive
                else number < atom.value
            )
        ]
        failed.extend(
            atom.source
            for atom in maxima
            if (
                number >= atom.value
                if not atom.inclusive
                else number > atom.value
            )
        )
        if failed:
            return _Unsat(Conflict(paths=(*value_sources, failed[0])))
        return _Sat((value,))

    if isinstance(value, str):
        min_lengths = [
            atom for atom in formula.atoms if isinstance(atom, _MinLength)
        ]
        max_lengths = [
            atom for atom in formula.atoms if isinstance(atom, _MaxLength)
        ]
        failed = [
            atom.source for atom in min_lengths if len(value) < atom.value
        ]
        failed.extend(
            atom.source for atom in max_lengths if len(value) > atom.value
        )
        if failed:
            return _Unsat(Conflict(paths=(*value_sources, failed[0])))
        return _Sat((value,))

    return _UNKNOWN


def _actual_type(value, integral_floats):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        if integral_floats and value.is_integer():
            return "integer"
        return "noninteger"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def _validate_object(
    formula,
    value,
    value_sources,
    budget,
    integral_floats,
):
    properties = _property_formulas(formula)
    for name, property in properties.items():
        if name in value:
            outcome = _validate_value(
                property.formula,
                value[name],
                (property.source,),
                budget,
                integral_floats,
            )
            if isinstance(outcome, _Unsat):
                return _Unsat(Conflict(
                    paths=value_sources,
                    alternatives=(outcome.conflict,),
                ))
            if isinstance(outcome, _Unknown):
                return _UNKNOWN

    required = [
        atom for atom in formula.atoms if isinstance(atom, _Required)
    ]
    missing = next((atom for atom in required if atom.name not in value), None)
    if missing is not None:
        return _Unsat(Conflict(paths=(*value_sources, missing.source)))

    evaluated_names = {
        name for name, property in properties.items() if property.evaluated
    }

    for additional in formula.additional:
        if any(
            isinstance(atom, _FalseSchema)
            for atom in additional.formula.atoms
        ):
            extra = next(
                (name for name in value if name not in evaluated_names),
                None,
            )
            if extra is not None:
                return _Unsat(Conflict(paths=(
                    *value_sources,
                    additional.source,
                )))
            continue

        for name in value:
            if name in evaluated_names:
                continue
            outcome = _validate_value(
                additional.formula,
                value[name],
                (additional.source,),
                budget,
                integral_floats,
            )
            if isinstance(outcome, _Unsat):
                return _Unsat(Conflict(
                    paths=value_sources,
                    alternatives=(outcome.conflict,),
                ))
            if isinstance(outcome, _Unknown):
                return _UNKNOWN

    return _Sat((value,))
