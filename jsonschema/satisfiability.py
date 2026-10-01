"""Conservative satisfiability checks for supported JSON Schema subsets."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from fractions import Fraction
from itertools import combinations
from operator import methodcaller
from typing import TYPE_CHECKING, Any

from jsonschema import exceptions
from jsonschema._utils import equal
from jsonschema.validators import validator_for

if TYPE_CHECKING:
    from jsonschema.protocols import Validator

Path = tuple[str | int, ...]


class SatisfiabilityStatus(str, Enum):
    """Possible outcomes of a conservative satisfiability check."""

    CONSTRUCTIBLE = "constructible"
    CONTRADICTION = "contradiction"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class UnsupportedStructure:
    """A supported-search location containing an unsupported keyword."""

    path: Path
    keyword: str


@dataclass(frozen=True)
class Constructible:
    """A valid example was constructed and validated."""

    status: SatisfiabilityStatus
    example: Any
    unsupported: tuple[UnsupportedStructure, ...]
    budget_exhausted: bool


@dataclass(frozen=True)
class Contradiction:
    """A direct supported contradiction was detected."""

    status: SatisfiabilityStatus
    conflicts: tuple[tuple[Path, ...], ...]
    unsupported: tuple[UnsupportedStructure, ...]
    budget_exhausted: bool


@dataclass(frozen=True)
class Unknown:
    """The checker could neither construct an example nor prove failure."""

    status: SatisfiabilityStatus
    unsupported: tuple[UnsupportedStructure, ...]
    budget_exhausted: bool
    reason: str | None = None


SatisfiabilityResult = Constructible | Contradiction | Unknown


class BudgetExhausted(Exception):
    """Internal signal that the configured search budget was used up."""


class _Unknown(Exception):
    pass


class _Contradiction(Exception):
    def __init__(self, *paths: Path):
        self.paths = tuple(dict.fromkeys(paths))


class _Budget:
    def __init__(self, total: int):
        self.remaining = total
        self.exhausted = False

    def visit(self) -> None:
        if self.remaining <= 0:
            self.exhausted = True
            raise BudgetExhausted
        self.remaining -= 1


SUPPORTED_KEYWORDS = frozenset(
    {
        "additionalProperties",
        "allOf",
        "anyOf",
        "const",
        "enum",
        "exclusiveMaximum",
        "exclusiveMinimum",
        "maximum",
        "maxLength",
        "minimum",
        "minLength",
        "properties",
        "required",
        "type",
    },
)
ROOT_TYPES = (
    "null",
    "boolean",
    "integer",
    "number",
    "string",
    "object",
    "array",
)


def check_satisfiability(
    schema_or_validator: Any,
    search_budget: int = 100,
    **kwargs: Any,
) -> SatisfiabilityResult:
    """Conservatively check whether a schema can have an instance."""
    if search_budget < 1:
        raise ValueError("search_budget must be at least 1")

    validator = _validator_for(schema_or_validator, **kwargs)
    validator.check_schema(validator.schema)
    budget = _Budget(search_budget)
    unsupported = tuple(
        _find_unsupported(
            validator.schema,
            validator,
            (),
            budget,
        ),
    )
    if budget.exhausted:
        return Unknown(
            SatisfiabilityStatus.UNKNOWN,
            unsupported,
            True,
            "search budget exhausted",
        )

    construction_unknown = False
    example = None
    try:
        example = _construct_node(
            validator.schema,
            validator,
            (),
            budget,
        )
        if not validator.is_valid(example):
            construction_unknown = True
    except _Contradiction as error:
        if budget.exhausted:
            return Unknown(
                SatisfiabilityStatus.UNKNOWN,
                unsupported,
                True,
                "search budget exhausted",
            )
        return Contradiction(
            SatisfiabilityStatus.CONTRADICTION,
            (error.paths,),
            unsupported,
            budget.exhausted,
        )
    except BudgetExhausted:
        return Unknown(
            SatisfiabilityStatus.UNKNOWN,
            unsupported,
            True,
            "search budget exhausted",
        )
    except _Unknown:
        construction_unknown = True
    if construction_unknown:
        if budget.exhausted:
            return Unknown(
                SatisfiabilityStatus.UNKNOWN,
                unsupported,
                True,
                "search budget exhausted",
            )
        return Unknown(
            SatisfiabilityStatus.UNKNOWN,
            unsupported,
            budget.exhausted,
            "unsupported or unmodeled constraints rejected the example",
        )

    return Constructible(
        SatisfiabilityStatus.CONSTRUCTIBLE,
        example,
        unsupported,
        budget.exhausted,
    )


def _validator_for(schema_or_validator: Any, **kwargs: Any) -> Validator:
    if hasattr(schema_or_validator, "iter_errors") and hasattr(
        schema_or_validator,
        "schema",
    ):
        return schema_or_validator

    if isinstance(schema_or_validator, type) and hasattr(
        schema_or_validator,
        "VALIDATORS",
    ):
        schema = kwargs.pop("schema", None)
        if schema is None:
            raise TypeError("schema=... is required for a validator class")
        return schema_or_validator(schema, **kwargs)

    return validator_for(schema_or_validator)(schema_or_validator, **kwargs)


def _applicable_items(validator, schema):
    applicable = validator._APPLICABLE_VALIDATORS
    if isinstance(applicable, methodcaller):
        return applicable(schema)
    if hasattr(applicable, "__func__"):
        return applicable.__func__(schema)
    return applicable(schema)


def _find_unsupported(schema, validator, path, budget):
    try:
        budget.visit()
    except BudgetExhausted:
        return []
    if not isinstance(schema, Mapping):
        return []

    found = []
    applicable_items = _applicable_items(validator, schema)
    for keyword, value in applicable_items:
        keyword_path = (*path, keyword)
        if keyword in {"$defs", "definitions"}:
            continue
        if (
            keyword in validator.VALIDATORS
            and keyword not in SUPPORTED_KEYWORDS
        ):
            found.append(UnsupportedStructure(keyword_path, keyword))

        containers = ()
        if keyword in {"allOf", "anyOf"} and isinstance(value, Sequence):
            containers = enumerate(value)
        elif keyword == "properties" and isinstance(value, Mapping):
            containers = value.items()
        elif keyword == "additionalProperties" and isinstance(value, Mapping):
            found.extend(
                _find_unsupported(
                    value,
                    validator,
                    keyword_path,
                    budget,
                ),
            )

        for part, subschema in containers:
            found.extend(
                _find_unsupported(
                    subschema,
                    validator,
                    (*keyword_path, part),
                    budget,
                ),
            )
    return found


def _nodes_are_valid(value, nodes, validator):
    for schema, _ in nodes:
        evolved = validator.evolve(
            schema=_without_applicators(
                schema,
                validator,
            ),
        )
        if list(evolved.iter_errors(value)):
            return False
    return True


def _iter_node_errors(value, nodes, validator):
    for schema, node_path in nodes:
        evolved = validator.evolve(
            schema=_without_applicators(
                schema,
                validator,
            ),
        )
        for error in evolved.iter_errors(value):
            schema_path = tuple(error.absolute_schema_path)
            if node_path:
                schema_path = node_path + schema_path
            yield _NodeError(schema_path)


@dataclass(frozen=True)
class _NodeError:
    schema_path: Path


def _without_applicators(schema, validator):
    if not isinstance(schema, Mapping):
        return schema
    return {
        keyword: value
        for keyword, value in _applicable_items(validator, schema)
        if keyword not in {"allOf", "anyOf"}
    }


def _construct_node(schema, validator, path, budget):
    return _construct_nodes([(schema, path)], validator, budget)


def _construct_nodes(nodes, validator, budget):
    base, groups = _flatten_nodes(nodes, validator, budget)
    return _solve_selection(base, groups, validator, budget)


def _flatten_nodes(nodes, validator, budget):
    conjunction = []
    groups = []
    pending = list(nodes)
    seen = set()
    while pending:
        schema, path = pending.pop(0)
        budget.visit()
        if path in seen:
            continue
        seen.add(path)
        if schema is False:
            raise _Contradiction(path)
        if schema is True or not isinstance(schema, Mapping):
            continue

        conjunction.append((schema, path))
        applicable_items = _applicable_items(validator, schema)
        applicable = dict(applicable_items)
        all_of = applicable.get("allOf", ())
        if isinstance(all_of, Sequence):
            for index, subschema in enumerate(all_of):
                pending.append((subschema, (*path, "allOf", index)))
        any_of = applicable.get("anyOf")
        if isinstance(any_of, Sequence):
            if not any_of:
                raise _Contradiction((*path, "anyOf"))
            groups.append(
                [
                    (subschema, (*path, "anyOf", index))
                    for index, subschema in enumerate(any_of)
                ],
            )
    return conjunction, groups


def _solve_selection(base, groups, validator, budget):
    if not groups:
        value = _construct_conjunction(
            base,
            validator,
            budget,
            base,
        )
        if not _nodes_are_valid(value, base, validator):
            raise _Unknown
        return value

    group, *remaining = groups
    failures = []
    saw_unknown = False
    for branch in group:
        try:
            branch_base, branch_groups = _flatten_nodes(
                [branch],
                validator,
                budget,
            )
            return _solve_selection(
                base + branch_base,
                remaining + branch_groups,
                validator,
                budget,
            )
        except _Contradiction as error:
            failures.append(error.paths)
        except _Unknown:
            saw_unknown = True

    if saw_unknown:
        raise _Unknown
    selected = []
    for paths in failures:
        for path in paths:
            if path not in selected:
                selected.append(path)
    raise _Contradiction(*selected)


def _construct_conjunction(conjunction, validator, budget, validation_nodes):
    type_sets = []
    enum_sets = []
    constants = []
    numeric_bounds = []
    string_bounds = []
    required = set()
    required_paths = {}

    for schema, path in conjunction:
        applicable_items = _applicable_items(validator, schema)
        applicable = dict(applicable_items)
        if "type" in applicable:
            names = applicable["type"]
            names = (names,) if isinstance(names, str) else tuple(names)
            for name in names:
                try:
                    validator.is_type(None, name)
                except exceptions.UnknownType:
                    raise _Unknown
            type_sets.append((frozenset(names), (*path, "type")))
        if "enum" in applicable:
            enum_sets.append((applicable["enum"], (*path, "enum")))
        if "const" in applicable:
            constants.append((applicable["const"], (*path, "const")))

        numeric_keywords = (
            "minimum",
            "maximum",
            "exclusiveMinimum",
            "exclusiveMaximum",
        )
        numeric_bounds.extend(
            (keyword, applicable[keyword], (*path, keyword))
            for keyword in numeric_keywords
            if keyword in applicable
        )
        if isinstance(
            applicable.get("minimum"),
            (int, float),
        ) and not isinstance(
            applicable["minimum"],
            bool,
        ):
            if applicable.get("exclusiveMinimum") is True:
                numeric_bounds.append(
                    (
                        "exclusiveMinimum",
                        applicable["minimum"],
                        (*path, "minimum"),
                    ),
                )
            if applicable.get("exclusiveMaximum") is True:
                numeric_bounds.append(
                    (
                        "exclusiveMaximum",
                        applicable["maximum"],
                        (*path, "maximum"),
                    ),
                )
        string_bounds.extend(
            (keyword, applicable[keyword], (*path, keyword))
            for keyword in ("minLength", "maxLength")
            if keyword in applicable
        )

        if isinstance(applicable.get("required"), Sequence):
            names = set(applicable["required"])
            required.update(names)
            for name in applicable["required"]:
                required_paths.setdefault(name, (*path, "required"))

    allowed_types = _intersect_types(type_sets)
    fixed = _fixed_candidates(enum_sets, constants)
    if fixed is not None:
        return _construct_fixed(
            fixed,
            allowed_types,
            type_sets,
            enum_sets,
            constants,
            validator,
            budget,
            validation_nodes,
        )

    numeric_range = _numeric_range(numeric_bounds)
    string_range = _string_range(string_bounds)
    type_paths = tuple(path for _, path in type_sets)
    attempts = _type_attempts(allowed_types, type_sets, budget)
    failures = []

    for type_name in attempts:
        try:
            return _construct_typed(
                type_name,
                numeric_range,
                string_range,
                required,
                required_paths,
                conjunction,
                validator,
                budget,
                validation_nodes,
                type_paths,
            )
        except _Contradiction as error:
            failures.append(error.paths)
        except _Unknown:
            continue

    if failures:
        raise _Contradiction(*_primitive_conflicts(failures))
    raise _Unknown


def _intersect_types(type_sets):
    if not type_sets:
        return None

    types = frozenset(type_sets[0][0])
    for names, _ in type_sets[1:]:
        types &= frozenset(names)
    return types


def _fixed_candidates(enum_sets, constants):
    candidates = None
    if enum_sets:
        candidates = list(enum_sets[0][0])
        for values, _ in enum_sets[1:]:
            candidates = [
                candidate
                for candidate in candidates
                if any(equal(candidate, value) for value in values)
            ]

    for value, _ in constants:
        if candidates is None:
            candidates = [value]
        else:
            candidates = [
                candidate
                for candidate in candidates
                if equal(candidate, value)
            ]
    return candidates


def _construct_fixed(
    candidates,
    allowed_types,
    type_sets,
    enum_sets,
    constants,
    validator,
    budget,
    validation_nodes,
):
    type_paths = tuple(path for _, path in type_sets)
    if not candidates:
        paths = tuple(path for _, path in enum_sets + constants)
        raise _Contradiction(*(paths or ()))

    if allowed_types is not None:
        candidates = [
            candidate
            for candidate in candidates
            if _json_type(candidate, validator)
            in _expanded_types(
                allowed_types,
            )
        ]
        if not candidates:
            domain_paths = tuple(path for _, path in enum_sets + constants)
            raise _Contradiction(*dict.fromkeys(domain_paths + type_paths))

    errors_by_candidate = []
    for candidate in candidates:
        budget.visit()
        node_errors = list(
            _iter_node_errors(
                candidate,
                validation_nodes,
                validator,
            ),
        )
        if not node_errors:
            return candidate
        errors_by_candidate.append((candidate, node_errors))

    conflict = _finite_candidate_conflict(
        errors_by_candidate,
        enum_sets,
        constants,
        type_paths,
        budget,
    )
    if conflict is not None:
        raise _Contradiction(*conflict)
    raise _Unknown


def _numeric_range(bounds):
    lower = None
    upper = None
    lower_path = None
    upper_path = None
    lower_exclusive = False
    upper_exclusive = False

    for keyword, value, path in bounds:
        if isinstance(value, bool):
            continue
        if keyword == "minimum":
            if (
                lower is None
                or value > lower
                or (value == lower and not lower_exclusive)
            ):
                lower, lower_path, lower_exclusive = value, path, False
        elif keyword == "exclusiveMinimum":
            if lower is None or value >= lower:
                lower, lower_path, lower_exclusive = value, path, True
        elif keyword == "maximum":
            if (
                upper is None
                or value < upper
                or (value == upper and not upper_exclusive)
            ):
                upper, upper_path, upper_exclusive = value, path, False
        elif keyword == "exclusiveMaximum" and (
            upper is None or value <= upper
        ):
            upper, upper_path, upper_exclusive = value, path, True

    invalid = (
        lower is not None
        and upper is not None
        and (
            lower > upper
            or (lower == upper and (lower_exclusive or upper_exclusive))
        )
    )

    return {
        "lower": lower,
        "upper": upper,
        "lower_path": lower_path,
        "upper_path": upper_path,
        "lower_exclusive": lower_exclusive,
        "upper_exclusive": upper_exclusive,
        "invalid": invalid,
    }


def _string_range(bounds):
    lower = 0
    upper = None
    lower_path = None
    upper_path = None
    for keyword, value, path in bounds:
        if keyword == "minLength" and value > lower:
            lower, lower_path = value, path
        elif keyword == "maxLength" and (upper is None or value < upper):
            upper, upper_path = value, path
    return (
        lower,
        upper,
        upper is not None and lower > upper,
        lower_path,
        upper_path,
    )


def _type_attempts(allowed_types, type_sets, budget):
    types = (
        ROOT_TYPES
        if allowed_types is None
        else tuple(
            type_name
            for type_name in ROOT_TYPES
            if type_name in _expanded_types(allowed_types)
        )
    )
    if not types:
        raise _Contradiction(
            *_minimal_type_conflict(type_sets, budget),
        )
    return types


def _expanded_types(types):
    result = set(types)
    if "number" in result:
        result.add("integer")
    return result


def _json_type(value, validator):
    for type_name in ROOT_TYPES:
        if validator.is_type(value, type_name):
            if type_name == "number" and validator.is_type(value, "integer"):
                continue
            return type_name
    return None


def _construct_typed(
    type_name,
    numeric_range,
    string_range,
    required,
    required_paths,
    conjunction,
    validator,
    budget,
    validation_nodes,
    type_paths,
):
    if type_name == "null":
        value = None
    elif type_name == "boolean":
        value = True
    elif type_name == "array":
        value = []
    elif type_name in {"integer", "number"}:
        if numeric_range["invalid"]:
            raise _Contradiction(*filter(None, (
                numeric_range["lower_path"],
                numeric_range["upper_path"],
                *type_paths,
            )))  # fmt: skip
        value = _construct_number(type_name, numeric_range, type_paths)
    elif type_name == "string":
        _, _, invalid, lower_path, upper_path = string_range
        if invalid:
            raise _Contradiction(
                *filter(
                    None,
                    (
                        lower_path,
                        upper_path,
                        *type_paths,
                    ),
                ),
            )
        value = _construct_string(string_range)
    else:
        value = _construct_object(
            required,
            required_paths,
            conjunction,
            validator,
            budget,
            type_paths,
        )

    if not _nodes_are_valid(value, validation_nodes, validator):
        raise _Unknown
    return value


def _construct_number(type_name, bounds, type_paths):
    lower = bounds["lower"]
    upper = bounds["upper"]
    lower_exclusive = bounds["lower_exclusive"]
    upper_exclusive = bounds["upper_exclusive"]

    if type_name == "integer":
        minimum = _integer_lower(lower, lower_exclusive)
        if upper is not None:
            maximum = _integer_upper(upper, upper_exclusive)
            if minimum > maximum:
                raise _Contradiction(
                    *filter(
                        None,
                        (
                            bounds["lower_path"],
                            bounds["upper_path"],
                            *type_paths,
                        ),
                    ),
                )
        return minimum

    if lower is not None:
        candidate = lower
        if lower_exclusive:
            candidate = _next_number(lower, upper, upper_exclusive)
    elif upper is not None:
        candidate = upper - 1
    else:
        return 0

    if _number_invalid(candidate, bounds):
        candidate = _midpoint(lower, upper)
    if _number_invalid(candidate, bounds):
        raise _Unknown
    return candidate


def _integer_lower(value, exclusive):
    if value is None:
        return 0
    fraction = Fraction(value)
    if fraction.denominator == 1:
        return int(fraction) + (1 if exclusive else 0)
    return -(-fraction.numerator // fraction.denominator)


def _integer_upper(value, exclusive):
    fraction = Fraction(value)
    if fraction.denominator == 1:
        return int(fraction) - (1 if exclusive else 0)
    return fraction.numerator // fraction.denominator


def _next_number(lower, upper, upper_exclusive):
    if upper is None:
        return lower + 1
    candidate = lower + 1
    if candidate < upper or (candidate == upper and not upper_exclusive):
        return candidate
    return _midpoint(lower, upper)


def _midpoint(lower, upper):
    if lower is None or upper is None:
        return 0
    return float((Fraction(lower) + Fraction(upper)) / 2)


def _number_invalid(value, bounds):
    lower = bounds["lower"]
    upper = bounds["upper"]
    if lower is not None and (
        value < lower or (value == lower and bounds["lower_exclusive"])
    ):
        return True
    return upper is not None and (
        value > upper or (value == upper and bounds["upper_exclusive"])
    )


def _construct_string(bounds):
    minimum, maximum, invalid, _, _ = bounds
    if invalid:
        raise _Contradiction()
    if maximum is not None and minimum > maximum:
        raise _Contradiction()
    return "a" * minimum


def _construct_object(
    required,
    required_paths,
    conjunction,
    validator,
    budget,
    type_paths,
):
    result = {}
    for name in sorted(required):
        nodes = _property_nodes(
            name,
            required_paths,
            conjunction,
            validator,
            type_paths,
        )
        result[name] = _construct_nodes(nodes, validator, budget)
    return result


def _property_nodes(
    name,
    required_paths,
    conjunction,
    validator,
    type_paths,
):
    nodes = []
    for schema, path in conjunction:
        applicable_items = _applicable_items(validator, schema)
        applicable = dict(applicable_items)
        properties_schema = applicable.get("properties")
        if (
            isinstance(properties_schema, Mapping)
            and name in properties_schema
        ):
            nodes.append(
                (
                    properties_schema[name],
                    (*path, "properties", name),
                ),
            )
            continue

        additional = applicable.get("additionalProperties")
        if additional is False:
            required_path = required_paths[name]
            raise _Contradiction(
                *filter(
                    None,
                    (
                        required_path,
                        (*path, "additionalProperties"),
                        *type_paths,
                    ),
                ),
            )
        if isinstance(additional, Mapping):
            nodes.append((additional, (*path, "additionalProperties")))
    return nodes


def _primitive_conflicts(failures):
    paths = []
    for group in failures:
        for path in group:
            if path not in paths:
                paths.append(path)
    return tuple(paths)


def _minimal_type_conflict(paths, budget):
    sets = [frozenset(names) for names, _ in paths]
    result_paths = tuple(path for _, path in paths)
    for size in range(1, len(sets) + 1):
        for indexes in combinations(range(len(sets)), size):
            budget.visit()
            if not frozenset.intersection(*(sets[i] for i in indexes)):
                return tuple(result_paths[i] for i in indexes)
    return result_paths


def _finite_candidate_conflict(
    errors_by_candidate,
    enum_sets,
    constants,
    type_paths,
    budget,
):
    if type_paths:
        domain_paths = tuple(path for _, path in enum_sets + constants)
        return tuple(dict.fromkeys(domain_paths + type_paths))

    candidate_errors = []
    for _, errors in errors_by_candidate:
        paths = {
            error.schema_path
            for error in errors
            if _supported_error_path(error.schema_path)
        }
        if not paths:
            return None
        candidate_errors.append(paths)

    cover = _minimum_hitting_set(candidate_errors, budget)
    if not cover:
        return None
    domain_paths = tuple(path for _, path in enum_sets + constants)
    return tuple(dict.fromkeys(domain_paths + cover))


def _supported_error_path(path):
    return any(part in SUPPORTED_KEYWORDS for part in reversed(path))


def _minimum_hitting_set(candidate_errors, budget=None):
    sets = list(
        dict.fromkeys(
            tuple(sorted(paths, key=repr)) for paths in candidate_errors
        ),
    )
    for size in range(1, len(sets) + 1):
        stack = [((), 0, frozenset())]
        while stack:
            chosen, start, covered = stack.pop()
            if len(chosen) == size:
                if len(covered) == len(sets):
                    return chosen
                continue
            for position in range(start, len(sets)):
                for path in sets[position]:
                    if budget is not None:
                        budget.visit()
                    next_covered = covered | {position}
                    for other, other_paths in enumerate(sets):
                        if path in other_paths:
                            next_covered = next_covered | {other}
                    stack.append(
                        (
                            (*chosen, path),
                            position + 1,
                            next_covered,
                        ),
                    )
    return ()
