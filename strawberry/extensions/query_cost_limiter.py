from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from graphql import (
    FieldNode,
    FragmentDefinitionNode,
    FragmentSpreadNode,
    GraphQLError,
    GraphQLIncludeDirective,
    GraphQLObjectType,
    GraphQLSkipDirective,
    InlineFragmentNode,
    OperationType,
    SchemaMetaFieldDef,
    TypeMetaFieldDef,
    TypeNameMetaFieldDef,
    get_argument_values,
    get_directive_values,
    get_named_type,
    get_operation_ast,
    is_abstract_type,
)
from graphql.execution.values import get_variable_values

from strawberry.extensions.base_extension import SchemaExtension

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator, Mapping

    from graphql import (
        GraphQLField,
        GraphQLOutputType,
        GraphQLSchema,
        NamedTypeNode,
        OperationDefinitionNode,
        SelectionNode,
    )

    from strawberry.types.execution import ExecutionContext

COST_METADATA_KEY = "cost"


@dataclass(frozen=True)
class FieldCost:
    """Cost configuration for a single field, used by `QueryCostLimiter`.

    Attach it to a field through the field metadata:

    ```python
    @strawberry.type
    class Query:
        users: list[User] = strawberry.field(
            metadata={COST_METADATA_KEY: FieldCost(cost=2, multipliers=("first",))}
        )
    ```

    For convenience a plain number can be used instead of `FieldCost` when
    only the base cost is needed:

    ```python
        users: list[User] = strawberry.field(metadata={COST_METADATA_KEY: 2})
    ```
    """

    cost: float = 1
    multipliers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.cost, bool) or not isinstance(self.cost, (int, float)):
            raise TypeError(f"Field cost must be a number, received {self.cost!r}.")
        if self.cost < 0:
            raise ValueError(
                f"Field cost must not be negative, received {self.cost!r}."
            )
        multipliers = self.multipliers
        if isinstance(multipliers, str):
            multipliers = (multipliers,)
        else:
            multipliers = tuple(multipliers)
        for multiplier in multipliers:
            if not isinstance(multiplier, str):
                raise TypeError(
                    "Field cost multipliers must be argument names (str),"
                    f" received {multiplier!r}."
                )
        object.__setattr__(self, "multipliers", multipliers)


_DEFAULT_FIELD_COST = FieldCost()


@dataclass(frozen=True)
class CostContributor:
    """A field and the cost it contributed to an operation's total cost."""

    path: str
    cost: float


@dataclass(frozen=True)
class QueryCostReport:
    """The computed cost of the operation being executed."""

    operation_name: str
    cost: float
    top_contributors: tuple[CostContributor, ...]


class QueryCostLimiter(SchemaExtension):
    """Reject operations whose estimated cost exceeds a budget, before execution.

    Every field contributes a base cost (1 by default) and fields can declare
    arguments that multiply the cost of their sub-selections, which makes wide
    list queries expensive even when they are shallow:

    ```python
    import strawberry
    from strawberry.extensions import QueryCostLimiter
    from strawberry.extensions.query_cost_limiter import COST_METADATA_KEY, FieldCost


    @strawberry.type
    class Query:
        users: list[User] = strawberry.field(
            metadata={COST_METADATA_KEY: FieldCost(cost=2, multipliers=("first",))}
        )


    schema = strawberry.Schema(
        Query,
        extensions=[lambda: QueryCostLimiter(max_cost=100)],
    )
    ```

    The cost is computed with the coerced variable values and argument
    defaults of the operation being executed. Fields merged at the same
    response position (same alias or name) are only charged once, while
    different aliases are charged separately. For interface and union types
    the cost of each possible concrete type is computed and the largest one
    is used, so the estimate never underestimates the worst case for a
    response position. Fields skipped via `@skip`/`@include` are not
    charged. Multiplier arguments that are missing, negative or not numeric
    never lower the cost; they behave as a multiplier of 1.
    """

    def __init__(
        self,
        max_cost: float,
        callback: Callable[[QueryCostReport], None] | None = None,
    ) -> None:
        """Initialize the QueryCostLimiter.

        Args:
            max_cost: The maximum allowed cost for an operation. Operations
                that exceed it are rejected before any resolver runs.
            callback: Called for every executed operation with its
                `QueryCostReport`, whether or not the budget was exceeded.
        """
        if callback is not None and not callable(callback):
            raise TypeError(
                "The `callback` argument to `QueryCostLimiter` must be a callable."
            )
        self.max_cost = max_cost
        self.callback = callback

    def on_execute(self) -> Iterator[None]:
        report = analyze_operation_cost(self.execution_context)
        if report is not None:
            if self.callback is not None:
                self.callback(report)
            if report.cost > self.max_cost:
                raise GraphQLError(
                    _exceeded_message(report, self.max_cost),
                    extensions={
                        "code": "QUERY_COST_EXCEEDED",
                        "cost": report.cost,
                        "maxCost": self.max_cost,
                    },
                )
        yield


def analyze_operation_cost(
    execution_context: ExecutionContext,
) -> QueryCostReport | None:
    """Compute the cost report for the operation being executed, if possible.

    Returns `None` when the cost cannot be computed, e.g. when the document
    failed to parse, the operation cannot be determined or the variables fail
    to coerce. In those cases execution reports the underlying error anyway.
    """
    document = execution_context.graphql_document
    if document is None:
        return None

    operation = get_operation_ast(document, execution_context.operation_name)
    if operation is None:
        return None

    schema = execution_context.schema._schema
    variable_values = _coerce_variable_values(
        schema, operation, execution_context.variables
    )
    if variable_values is None:
        return None

    fragments: dict[str, FragmentDefinitionNode] = {
        definition.name.value: definition
        for definition in document.definitions
        if isinstance(definition, FragmentDefinitionNode)
    }

    analyzer = _CostAnalyzer(schema, fragments, variable_values)
    operation_name = operation.name.value if operation.name else "anonymous"
    cost = analyzer.operation_cost(operation)
    return QueryCostReport(
        operation_name=operation_name,
        cost=cost,
        top_contributors=analyzer.top_contributors(),
    )


def _coerce_variable_values(
    schema: GraphQLSchema,
    operation: OperationDefinitionNode,
    raw_variables: dict[str, Any] | None,
) -> dict[str, Any] | None:
    result = get_variable_values(
        schema, operation.variable_definitions or [], raw_variables or {}
    )
    if isinstance(result, dict):
        # graphql-core 3.2 returns the coerced values directly on success
        return result
    # graphql-core 3.3+ returns a CoercedVariableValues, while graphql-core
    # 3.2 returns a list of errors on failure
    errors = getattr(result, "errors", None)
    if errors:
        return None
    return getattr(result, "coerced", None)


def _exceeded_message(report: QueryCostReport, max_cost: float) -> str:
    message = (
        f"'{report.operation_name}' exceeds the maximum operation cost of"
        f" {_format_cost(max_cost)} (actual cost: {_format_cost(report.cost)})."
    )
    if report.top_contributors:
        contributors = ", ".join(
            f'"{contributor.path}" (cost {_format_cost(contributor.cost)})'
            for contributor in report.top_contributors
        )
        message += f" Top contributors: {contributors}."
    return message


def _format_cost(cost: float) -> str:
    return f"{cost:g}"


class _CostAnalyzer:
    """Computes the cost of one operation against a schema."""

    def __init__(
        self,
        schema: GraphQLSchema,
        fragments: Mapping[str, FragmentDefinitionNode],
        variable_values: dict[str, Any],
    ) -> None:
        self.schema = schema
        self.fragments = fragments
        self.variable_values = variable_values
        self._contributors: dict[str, float] = {}

    def operation_cost(self, operation: OperationDefinitionNode) -> float:
        root_type = {
            OperationType.QUERY: self.schema.query_type,
            OperationType.MUTATION: self.schema.mutation_type,
            OperationType.SUBSCRIPTION: self.schema.subscription_type,
        }[operation.operation]
        if root_type is None:
            return 0
        return self.selections_cost(operation.selection_set.selections, [root_type], ())

    def top_contributors(self, count: int = 3) -> tuple[CostContributor, ...]:
        paths = sorted(
            self._contributors.items(), key=lambda item: item[1], reverse=True
        )
        return tuple(
            CostContributor(path=path, cost=cost) for path, cost in paths[:count]
        )

    def selections_cost(
        self,
        selections: Iterable[SelectionNode],
        possible_types: list[GraphQLObjectType],
        path: tuple[str, ...],
    ) -> float:
        """Cost of a selection set, as the worst case over concrete types.

        For abstract types the fields are collected separately for every
        possible concrete type (exactly like execution does) and the largest
        total is used. This is the conservative rule for abstract types: the
        estimate never underestimates the cost of any single response
        position.
        """
        worst = 0.0
        for runtime_type in possible_types:
            grouped: dict[str, list[FieldNode]] = {}
            self._collect_fields(selections, runtime_type, frozenset(), grouped)
            cost = 0.0
            for response_key, field_nodes in grouped.items():
                cost += self._field_group_cost(
                    response_key, field_nodes, runtime_type, path
                )
            worst = max(worst, cost)
        return worst

    def _field_group_cost(
        self,
        response_key: str,
        field_nodes: list[FieldNode],
        parent_type: GraphQLObjectType,
        path: tuple[str, ...],
    ) -> float:
        node = field_nodes[0]
        field_def = _get_field_def(self.schema, parent_type, node.name.value)
        if field_def is None:
            # Invalid document; validation reports the unknown field and the
            # operation never executes, so it contributes no cost.
            return 0

        field_path = (*path, response_key)
        config = _get_field_cost(field_def)

        child_cost = 0.0
        child_selections = [
            selection
            for field_node in field_nodes
            if field_node.selection_set
            for selection in field_node.selection_set.selections
        ]
        if child_selections:
            child_cost = self.selections_cost(
                child_selections,
                _possible_types(self.schema, field_def.type),
                field_path,
            )

        multiplier = 1.0
        if config.multipliers:
            arguments = _get_arguments(field_def, node, self.variable_values)
            for name in config.multipliers:
                multiplier *= _sanitize_multiplier(arguments.get(name))

        total = config.cost + multiplier * child_cost
        dotted_path = ".".join(field_path)
        self._contributors[dotted_path] = max(
            total, self._contributors.get(dotted_path, 0)
        )
        return total

    def _collect_fields(
        self,
        selections: Iterable[SelectionNode],
        runtime_type: GraphQLObjectType,
        visited_fragments: frozenset[str],
        grouped: dict[str, list[FieldNode]],
    ) -> None:
        """Group fields by response key, mirroring graphql-core's collect_fields.

        Fields with the same response key (alias or name) end up in the same
        group and are therefore only charged once; different aliases produce
        different groups and are charged separately.
        """
        for selection in selections:
            if _is_skipped(selection, self.variable_values):
                continue
            if isinstance(selection, FieldNode):
                response_key = (
                    selection.alias.value if selection.alias else selection.name.value
                )
                grouped.setdefault(response_key, []).append(selection)
            elif isinstance(selection, InlineFragmentNode):
                if _fragment_applies(
                    self.schema, selection.type_condition, runtime_type
                ):
                    self._collect_fields(
                        selection.selection_set.selections,
                        runtime_type,
                        visited_fragments,
                        grouped,
                    )
            elif isinstance(selection, FragmentSpreadNode):
                fragment_name = selection.name.value
                if fragment_name in visited_fragments:
                    continue
                fragment = self.fragments.get(fragment_name)
                if fragment is None or not _fragment_applies(
                    self.schema, fragment.type_condition, runtime_type
                ):
                    continue
                self._collect_fields(
                    fragment.selection_set.selections,
                    runtime_type,
                    visited_fragments | {fragment_name},
                    grouped,
                )


def _is_skipped(
    node: FieldNode | InlineFragmentNode | FragmentSpreadNode,
    variable_values: dict[str, Any],
) -> bool:
    try:
        skip = get_directive_values(GraphQLSkipDirective, node, variable_values)
        if skip and skip.get("if"):
            return True
        include = get_directive_values(GraphQLIncludeDirective, node, variable_values)
        return bool(include) and not include.get("if", True)
    except GraphQLError:
        # Invalid directive usage; validation reports it and the operation
        # never executes. Treat the node as included.
        return False


def _fragment_applies(
    schema: GraphQLSchema,
    type_condition: NamedTypeNode | None,
    runtime_type: GraphQLObjectType,
) -> bool:
    if type_condition is None:
        return True
    type_ = schema.get_type(type_condition.name.value)
    if type_ is None:
        return False
    if type_ is runtime_type:
        return True
    return is_abstract_type(type_) and runtime_type in schema.get_possible_types(type_)


def _get_field_def(
    schema: GraphQLSchema, parent_type: GraphQLObjectType, field_name: str
) -> GraphQLField | None:
    if field_name == "__typename":
        return TypeNameMetaFieldDef
    if parent_type is schema.query_type:
        if field_name == "__schema":
            return SchemaMetaFieldDef
        if field_name == "__type":
            return TypeMetaFieldDef
    return parent_type.fields.get(field_name)


def _possible_types(
    schema: GraphQLSchema, type_: GraphQLOutputType
) -> list[GraphQLObjectType]:
    named_type = get_named_type(type_)
    if is_abstract_type(named_type):
        return list(schema.get_possible_types(named_type))
    if isinstance(named_type, GraphQLObjectType):
        return [named_type]
    return []


def _get_arguments(
    field_def: GraphQLField, node: FieldNode, variable_values: dict[str, Any]
) -> dict[str, Any]:
    try:
        return get_argument_values(field_def, node, variable_values)
    except GraphQLError:
        # Invalid arguments; validation reports them and the operation never
        # executes. Treat every multiplier argument as absent.
        return {}


def _sanitize_multiplier(value: Any) -> float:
    """Coerce a multiplier argument to a factor that never lowers the cost."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 1
    if not value >= 1:  # NaN, negative, zero and fractions all clamp to 1
        return 1
    return value


def _get_field_cost(field_def: GraphQLField) -> FieldCost:
    from strawberry.schema.schema_converter import GraphQLCoreConverter

    extensions = field_def.extensions or {}
    strawberry_field = extensions.get(GraphQLCoreConverter.DEFINITION_BACKREF)
    if strawberry_field is None:
        return _DEFAULT_FIELD_COST
    raw = (strawberry_field.metadata or {}).get(COST_METADATA_KEY)
    if raw is None:
        return _DEFAULT_FIELD_COST
    if isinstance(raw, FieldCost):
        return raw
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise TypeError(
            f"Invalid {COST_METADATA_KEY!r} metadata on field"
            f" {strawberry_field.name!r}: expected a number or a FieldCost,"
            f" received {raw!r}."
        )
    return FieldCost(cost=raw)


__all__ = [
    "COST_METADATA_KEY",
    "CostContributor",
    "FieldCost",
    "QueryCostLimiter",
    "QueryCostReport",
]
