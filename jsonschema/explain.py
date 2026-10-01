"""
An optional explanation mode describing how a schema validated an instance.

Call `explain` (or the ``explain`` method on a validator) to validate an
instance once while recording which keywords ran, which applicator
branches were entered and whether they succeeded, and where each evaluated
property or array item was evaluated from.  The resulting
`Explanation` locates everything with JSON Pointers and, by default, does
not include input values.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from jsonschema._explain import (
    BranchEvaluation,
    EvaluationSource,
    Explanation,
    KeywordEvaluation,
    pointer as json_pointer,
)
from jsonschema.validators import validator_for

if TYPE_CHECKING:
    import referencing.jsonschema

__all__ = [
    "BranchEvaluation",
    "EvaluationSource",
    "Explanation",
    "KeywordEvaluation",
    "explain",
    "json_pointer",
]


def explain(
    instance: Any,
    schema: referencing.jsonschema.Schema,
    *,
    cls: type | None = None,
    registry: referencing.jsonschema.SchemaRegistry | None = None,
    format_checker: Any = None,
    include_values: bool = False,
    max_events: int = 10_000,
    max_depth: int = 1_000,
) -> Explanation:
    """
    Validate ``instance`` under ``schema`` and return an `Explanation`.

    Validation runs exactly once over the normal traversal; the returned
    object contains the `jsonschema.exceptions.ValidationError` objects that
    ``iter_errors`` would produce, in the same order, in addition to the
    recorded keyword, branch and evaluation-source information.

    Arguments:

    instance:

        the instance to validate

    schema:

        the schema to validate with

    cls:

        the validator class; defaults to the class selected via
        :kw:`$schema`

    registry:

        an optional `referencing.Registry` used to resolve references

    format_checker:

        an optional format checker

    include_values:

        include evaluated input values in the report; defaults to ``False``,
        so that only JSON Pointers are recorded

    max_events:

        cap on the number of recorded events; when reached, the report is
        marked truncated

    max_depth:

        cap on the depth of recorded schema frames, so that recursive
        references always produce a finite report

    """
    if cls is None:
        cls = validator_for(schema)
    cls.check_schema(schema)
    kwargs = {}
    if registry is not None:
        kwargs["registry"] = registry
    if format_checker is not None:
        kwargs["format_checker"] = format_checker
    validator = cls(schema, **kwargs)
    return validator.explain(
        instance,
        include_values=include_values,
        max_events=max_events,
        max_depth=max_depth,
    )
