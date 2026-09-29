from __future__ import annotations

from typing import TYPE_CHECKING, Any, TypeAlias

from graphql import (
    FieldNode,
    FragmentDefinitionNode,
    FragmentSpreadNode,
    GraphQLError,
    GraphQLIncludeDirective,
    GraphQLInterfaceType,
    GraphQLObjectType,
    GraphQLSkipDirective,
    GraphQLUnionType,
    InlineFragmentNode,
    OperationDefinitionNode,
    OperationType,
    SelectionSetNode,
    get_directive_values,
    get_named_type,
    get_operation_ast,
)
from graphql.execution.values import get_variable_values
from graphql.pyutils import Undefined
from graphql.type.introspection import (
    SchemaMetaFieldDef,
    TypeMetaFieldDef,
    TypeNameMetaFieldDef,
)
from graphql.utilities import value_from_ast

from strawberry.extensions.base_extension import SchemaExtension
from strawberry.extensions.field_extension import FieldExtension
from strawberry.types.execution import PreExecutionError
from strawberry.utils.str_converters import to_camel_case

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping, Sequence

    from graphql import (
        GraphQLArgument,
        GraphQLField,
        GraphQLSchema,
        NamedTypeNode,
    )

    from strawberry.types import ExecutionContext

Cost: TypeAlias = "int | float"
# Maps a response path (relative to the operation root) to the cost of the
# field at that position, including its sub-selections.
Contributions: TypeAlias = "list[tuple[tuple[str, ...], Cost]]"

DEFAULT_FIELD_COST = 1
TOP_CONTRIBUTORS_COUNT = 3


class FieldCost(FieldExtension):
    """Declare the cost of a field for the `QueryCostLimiter` extension.

    Example:

    ```python
    import strawberry
    from strawberry.extensions import FieldCost


    @strawberry.type
    class Query:
        users: list[User] = strawberry.field(
            extensions=[FieldCost(cost=1, multipliers=["first", "last"])]
        )
    ```
    """

    def __init__(self, cost: int = 1, multipliers: Sequence[str] | None = None) -> None:
        """Initialize the field cost declaration.

        Args:
            cost: The base cost of the field, charged once per position in the
                operation. Fields without a declaration cost `1`.
            multipliers: Names of arguments whose values multiply the cost of
                the field's sub-selections (e.g. pagination arguments such as
                `first`). Both GraphQL and Python argument names are accepted.
                Values are clamped to a minimum of `1`, so negative, missing or
                non-numeric values never reduce the cost.
        """
        if cost < 0:
            raise ValueError("Field cost cannot be negative")
        self.cost = cost
        self.multipliers = list(multipliers) if multipliers else []


def _sanitize_multiplier(value: Any) -> Cost:
    # Booleans are ints in Python, but they are not meaningful multipliers.
    # Anything non-numeric, NaN or smaller than 1 is treated as 1 so that it
    # can never make the estimated cost smaller.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 1
    if value != value or value < 1:  # noqa: PLR0124
        return 1
    return value


def _format_cost(cost: Cost) -> str:
    if isinstance(cost, float) and cost.is_integer():
        return str(int(cost))
    return str(cost)


def _get_strawberry_field(field_def: GraphQLField) -> Any:
    # Imported lazily to avoid a circular import with the schema converter.
    from strawberry.schema.schema_converter import GraphQLCoreConverter

    return (field_def.extensions or {}).get(GraphQLCoreConverter.DEFINITION_BACKREF)


class _QueryCostComputer:
    """Estimate the cost of a single operation against a schema."""

    def __init__(
        self,
        schema: GraphQLSchema,
        fragments: Mapping[str, FragmentDefinitionNode],
        variables: dict[str, Any],
    ) -> None:
        self.schema = schema
        self.fragments = fragments
        self.variables = variables
        self._memo: dict[tuple[str, tuple[int, ...]], tuple[Cost, Contributions]] = {}
        self._cost_configs: dict[int, tuple[Cost, tuple[str, ...]]] = {}

    def compute(self, operation: OperationDefinitionNode) -> tuple[Cost, Contributions]:
        root_types = {
            OperationType.QUERY: self.schema.query_type,
            OperationType.MUTATION: self.schema.mutation_type,
            OperationType.SUBSCRIPTION: self.schema.subscription_type,
        }
        root_type = root_types.get(operation.operation)
        if root_type is None:
            return 0, []
        return self._selection_set_cost(root_type, (operation.selection_set,))

    def _selection_set_cost(
        self,
        parent_type: GraphQLObjectType | GraphQLInterfaceType | GraphQLUnionType,
        selection_sets: tuple[SelectionSetNode, ...],
    ) -> tuple[Cost, Contributions]:
        """Cost of a selection set, with paths relative to its own position."""
        if isinstance(parent_type, (GraphQLInterfaceType, GraphQLUnionType)):
            # Conservative rule for abstract types: the cost is the most
            # expensive concrete type that could be resolved at this position.
            best: tuple[Cost, Contributions] = (0, [])
            for possible_type in self.schema.get_possible_types(parent_type):
                candidate = self._selection_set_cost(possible_type, selection_sets)
                if candidate[0] > best[0]:
                    best = candidate
            return best

        memo_key = (parent_type.name, tuple(id(s) for s in selection_sets))
        cached = self._memo.get(memo_key)
        if cached is not None:
            return cached

        total: Cost = 0
        contributions: Contributions = []
        field_groups = self._collect_fields(parent_type, selection_sets)
        for response_key, field_nodes in field_groups.items():
            field_cost, field_contributions = self._field_cost(
                parent_type, response_key, field_nodes
            )
            total += field_cost
            contributions.extend(field_contributions)

        result = (total, contributions)
        self._memo[memo_key] = result
        return result

    def _collect_fields(
        self,
        parent_type: GraphQLObjectType,
        selection_sets: tuple[SelectionSetNode, ...],
    ) -> dict[str, list[FieldNode]]:
        """Group field selections by response key, following fragments.

        Fields sharing a response key (alias or name) are merged and therefore
        only charged once, mirroring how execution merges them.
        """
        groups: dict[str, list[FieldNode]] = {}
        visited_fragments: set[str] = set()
        stack = list(selection_sets)
        while stack:
            selection_set = stack.pop()
            for selection in selection_set.selections:
                if isinstance(selection, FieldNode):
                    if self._should_include(selection):
                        key = (
                            selection.alias.value
                            if selection.alias
                            else selection.name.value
                        )
                        groups.setdefault(key, []).append(selection)
                elif isinstance(selection, InlineFragmentNode):
                    if self._should_include(selection) and self._applies_to(
                        parent_type, selection.type_condition
                    ):
                        stack.append(selection.selection_set)
                elif isinstance(selection, FragmentSpreadNode):
                    fragment_name = selection.name.value
                    if fragment_name in visited_fragments:
                        continue
                    fragment = self.fragments.get(fragment_name)
                    if fragment is None or not self._should_include(selection):
                        continue
                    visited_fragments.add(fragment_name)
                    if self._applies_to(parent_type, fragment.type_condition):
                        stack.append(fragment.selection_set)
        return groups

    def _applies_to(
        self, parent_type: GraphQLObjectType, type_condition: NamedTypeNode | None
    ) -> bool:
        if type_condition is None:
            return True
        condition_type = self.schema.get_type(type_condition.name.value)
        if isinstance(condition_type, GraphQLObjectType):
            return condition_type == parent_type
        if isinstance(condition_type, (GraphQLInterfaceType, GraphQLUnionType)):
            return parent_type in self.schema.get_possible_types(condition_type)
        return False

    def _should_include(
        self, node: FieldNode | FragmentSpreadNode | InlineFragmentNode
    ) -> bool:
        skip = get_directive_values(GraphQLSkipDirective, node, self.variables)
        if skip and skip.get("if") is True:
            return False
        include = get_directive_values(GraphQLIncludeDirective, node, self.variables)
        return not (include and include.get("if") is False)

    def _field_cost(
        self,
        parent_type: GraphQLObjectType,
        response_key: str,
        field_nodes: list[FieldNode],
    ) -> tuple[Cost, Contributions]:
        node = field_nodes[0]
        field_def = self._get_field_def(parent_type, node.name.value)
        if field_def is None:
            # Unreachable for validated documents; charge the default cost.
            return DEFAULT_FIELD_COST, [((response_key,), DEFAULT_FIELD_COST)]

        base_cost, multiplier_names = self._get_cost_config(field_def)
        multiplier: Cost = 1
        for name in multiplier_names:
            multiplier *= self._argument_multiplier(field_def, node, name)

        child_cost: Cost = 0
        child_contributions: Contributions = []
        child_selection_sets = tuple(
            field_node.selection_set
            for field_node in field_nodes
            if field_node.selection_set
        )
        if child_selection_sets:
            child_type = get_named_type(field_def.type)
            if isinstance(
                child_type,
                (GraphQLObjectType, GraphQLInterfaceType, GraphQLUnionType),
            ):
                child_cost, child_contributions = self._selection_set_cost(
                    child_type, child_selection_sets
                )

        cost = base_cost + multiplier * child_cost
        contributions: Contributions = [((response_key,), cost)]
        contributions.extend(
            ((response_key, *path), child) for path, child in child_contributions
        )
        return cost, contributions

    def _get_field_def(
        self, parent_type: GraphQLObjectType, field_name: str
    ) -> GraphQLField | None:
        if field_name == "__typename":
            return TypeNameMetaFieldDef
        if parent_type == self.schema.query_type:
            if field_name == "__schema":
                return SchemaMetaFieldDef
            if field_name == "__type":
                return TypeMetaFieldDef
        return parent_type.fields.get(field_name)

    def _get_cost_config(self, field_def: GraphQLField) -> tuple[Cost, tuple[str, ...]]:
        cache_key = id(field_def)
        cached = self._cost_configs.get(cache_key)
        if cached is not None:
            return cached

        config: tuple[Cost, tuple[str, ...]] = (DEFAULT_FIELD_COST, ())
        strawberry_field = _get_strawberry_field(field_def)
        if strawberry_field is not None:
            for extension in getattr(strawberry_field, "extensions", ()):
                if isinstance(extension, FieldCost):
                    config = (extension.cost, tuple(extension.multipliers))
                    break

        self._cost_configs[cache_key] = config
        return config

    def _argument_multiplier(
        self, field_def: GraphQLField, node: FieldNode, name: str
    ) -> Cost:
        found = self._find_argument(field_def, name)
        if found is None:
            return 1
        argument_name, argument = found

        value: Any = Undefined
        for argument_node in node.arguments or ():
            if argument_node.name.value == argument_name:
                value = value_from_ast(
                    argument_node.value, argument.type, self.variables
                )
                break
        if value is Undefined:
            # Fall back to the argument's default value, if it declares one.
            default = argument.default_value
            value = default if default is not Undefined else Undefined

        return _sanitize_multiplier(value)

    @staticmethod
    def _find_argument(
        field_def: GraphQLField, name: str
    ) -> tuple[str, GraphQLArgument] | None:
        argument = field_def.args.get(name)
        if argument is not None:
            return name, argument

        # Also accept Python argument names (e.g. `page_size` for `pageSize`).
        strawberry_field = _get_strawberry_field(field_def)
        if strawberry_field is not None:
            for strawberry_argument in getattr(strawberry_field, "arguments", ()):
                candidates = {
                    strawberry_argument.python_name,
                    strawberry_argument.graphql_name,
                    to_camel_case(strawberry_argument.python_name),
                }
                if name not in candidates:
                    continue
                for candidate in candidates:
                    if candidate and candidate in field_def.args:
                        return candidate, field_def.args[candidate]
        return None


class QueryCostLimiter(SchemaExtension):
    """Reject operations whose estimated cost exceeds a maximum, before execution.

    Fields cost `1` by default and can declare a different base cost and
    multiplier arguments with `FieldCost`. The estimate uses the validated
    variable values and argument defaults, understands fragments, aliases,
    interfaces, unions and `@skip`/`@include`, and never lets invalid
    multiplier values reduce the cost.

    Example:

    ```python
    import strawberry
    from strawberry.extensions import QueryCostLimiter

    schema = strawberry.Schema(
        Query,
        extensions=[QueryCostLimiter(max_cost=1000)],
    )
    ```
    """

    def __init__(self, max_cost: int) -> None:
        """Initialize the QueryCostLimiter.

        Args:
            max_cost: The maximum allowed cost for any operation. Operations
                estimated to cost more are rejected before any resolver runs.
        """
        self.max_cost = max_cost

    def on_execute(self) -> Iterator[None]:
        execution_context = self.execution_context
        # Another extension might have already produced a result, in which
        # case execution is skipped and there is nothing to check.
        if execution_context.result is None:
            error = self._check_cost(execution_context)
            if error is not None:
                execution_context.result = PreExecutionError(data=None, errors=[error])
        yield

    def _check_cost(self, execution_context: ExecutionContext) -> GraphQLError | None:
        document = execution_context.graphql_document
        if document is None:
            return None

        operation = get_operation_ast(document, execution_context.operation_name)
        if operation is None:
            # Let execution report the unknown or ambiguous operation.
            return None

        schema = execution_context.schema._schema
        variable_values = get_variable_values(
            schema,
            operation.variable_definitions or (),
            execution_context.variables or {},
        )
        if isinstance(variable_values, list):
            # Invalid variable values: let execution report the coercion
            # errors instead of estimating a cost from them.
            return None

        fragments = {
            definition.name.value: definition
            for definition in document.definitions
            if isinstance(definition, FragmentDefinitionNode)
        }
        computer = _QueryCostComputer(schema, fragments, variable_values)
        total_cost, contributions = computer.compute(operation)
        if total_cost <= self.max_cost:
            return None

        top_contributors = sorted(
            contributions, key=lambda item: item[1], reverse=True
        )[:TOP_CONTRIBUTORS_COUNT]
        contributors_message = ", ".join(
            f"{'.'.join(path)} ({_format_cost(cost)})"
            for path, cost in top_contributors
        )
        return GraphQLError(
            f"Query cost {_format_cost(total_cost)} exceeds the maximum allowed "
            f"cost of {_format_cost(self.max_cost)}. "
            f"Top cost contributors: {contributors_message}.",
            extensions={
                "cost": total_cost,
                "maxCost": self.max_cost,
                "topContributors": [
                    {"path": ".".join(path), "cost": cost}
                    for path, cost in top_contributors
                ],
            },
        )


__all__ = ["FieldCost", "QueryCostLimiter"]
