from typing import Annotated

import pytest

import strawberry
from strawberry.extensions import FieldCost, QueryCostLimiter


@strawberry.interface
class Node:
    id: strawberry.ID


@strawberry.type
class Photo(Node):
    url: str


@strawberry.type
class Video(Node):
    duration: int
    premium_url: str = strawberry.field(extensions=[FieldCost(cost=10)])


Media = Annotated[Photo | Video, strawberry.union("Media")]


@strawberry.type
class User:
    name: str

    @strawberry.field(extensions=[FieldCost(cost=1, multipliers=["first"])])
    def friends(self, first: int | None = None) -> list["User"]:
        return []


users_resolver_calls: list[int] = []


@strawberry.type
class Query:
    @strawberry.field
    def version(self) -> str:
        return "1.0"

    @strawberry.field
    def node(self) -> Node | None:
        return None

    @strawberry.field
    def media(self) -> Media | None:
        return None

    @strawberry.field(extensions=[FieldCost(cost=1, multipliers=["first", "last"])])
    def users(self, first: int | None = None, last: int | None = None) -> list[User]:
        users_resolver_calls.append(1)
        return []

    @strawberry.field(extensions=[FieldCost(cost=1, multipliers=["limit"])])
    def items(self, limit: int = 5) -> list[User]:
        return []

    @strawberry.field(extensions=[FieldCost(cost=1, multipliers=["term"])])
    def search(self, term: str | None = None) -> list[str]:
        return []

    @strawberry.field(extensions=[FieldCost(cost=1, multipliers=["page_size"])])
    def page(self, page_size: int | None = None) -> list[User]:
        return []

    @strawberry.field
    def me(self) -> User:
        return User(name="n")


def make_schema(max_cost: int) -> strawberry.Schema:
    return strawberry.Schema(
        Query,
        types=[Photo, Video],
        extensions=[lambda: QueryCostLimiter(max_cost=max_cost)],
    )


def test_simple_query_under_budget():
    result = make_schema(max_cost=10).execute_sync("{ version }")

    assert not result.errors
    assert result.data == {"version": "1.0"}


def test_cost_exactly_at_budget_passes():
    result = make_schema(max_cost=1).execute_sync("{ version }")

    assert not result.errors


def test_rejects_over_budget_before_calling_resolvers():
    users_resolver_calls.clear()

    result = make_schema(max_cost=5).execute_sync("{ users(first: 10) { name } }")

    assert result.data is None
    assert result.errors is not None
    assert len(result.errors) == 1
    assert users_resolver_calls == []


def test_field_base_cost():
    result = make_schema(max_cost=10).execute_sync(
        "{ media { ... on Video { premiumUrl } } }"
    )

    assert result.errors is not None
    assert "Query cost 11 exceeds the maximum allowed cost of 10" in str(
        result.errors[0]
    )


def test_multiplier_with_literal_argument():
    result = make_schema(max_cost=10).execute_sync("{ users(first: 10) { name } }")

    assert result.errors is not None
    assert "Query cost 11 exceeds the maximum allowed cost of 10" in str(
        result.errors[0]
    )


def test_multiple_multipliers_are_combined():
    result = make_schema(max_cost=12).execute_sync(
        "{ users(first: 3, last: 4) { name } }"
    )

    assert result.errors is not None
    assert "Query cost 13 exceeds the maximum allowed cost of 12" in str(
        result.errors[0]
    )


def test_multiplier_with_variable():
    schema = make_schema(max_cost=5)
    query = "query ($first: Int!) { users(first: $first) { name } }"

    result = schema.execute_sync(query, variable_values={"first": 3})
    assert not result.errors

    result = schema.execute_sync(query, variable_values={"first": 5})
    assert result.errors is not None
    assert "Query cost 6 exceeds the maximum allowed cost of 5" in str(result.errors[0])


def test_multiplier_uses_variable_default():
    query = "query ($first: Int = 20) { users(first: $first) { name } }"

    result = make_schema(max_cost=10).execute_sync(query)

    assert result.errors is not None
    assert "Query cost 21 exceeds the maximum allowed cost of 10" in str(
        result.errors[0]
    )


def test_multiplier_uses_argument_default():
    result = make_schema(max_cost=5).execute_sync("{ items { name } }")

    assert result.errors is not None
    assert "Query cost 6 exceeds the maximum allowed cost of 5" in str(result.errors[0])


def test_missing_multiplier_argument_does_not_reduce_cost():
    result = make_schema(max_cost=1).execute_sync("{ users { name } }")

    assert result.errors is not None
    assert "Query cost 2 exceeds the maximum allowed cost of 1" in str(result.errors[0])


@pytest.mark.parametrize("first", [-100, 0])
def test_non_positive_multiplier_does_not_reduce_cost(first: int):
    result = make_schema(max_cost=1).execute_sync(
        f"{{ users(first: {first}) {{ name }} }}"
    )

    assert result.errors is not None
    assert "Query cost 2 exceeds the maximum allowed cost of 1" in str(result.errors[0])


def test_non_numeric_multiplier_does_not_reduce_cost():
    result = make_schema(max_cost=1).execute_sync('{ search(term: "abc") }')

    assert not result.errors


def test_multiplier_accepts_python_argument_names():
    # The multiplier is declared with the Python name `page_size` while the
    # GraphQL argument is `pageSize`.
    result = make_schema(max_cost=10).execute_sync("{ page(pageSize: 10) { name } }")

    assert result.errors is not None
    assert "Query cost 11 exceeds the maximum allowed cost of 10" in str(
        result.errors[0]
    )


def test_nested_multipliers():
    result = make_schema(max_cost=11).execute_sync(
        "{ me { friends(first: 10) { name } } }"
    )

    assert result.errors is not None
    assert "Query cost 12 exceeds the maximum allowed cost of 11" in str(
        result.errors[0]
    )


def test_aliases_are_charged_separately():
    result = make_schema(max_cost=1).execute_sync("{ a: version, b: version }")

    assert result.errors is not None
    assert "Query cost 2 exceeds the maximum allowed cost of 1" in str(result.errors[0])


def test_merged_fields_are_charged_once():
    query = """
        {
            version
            ... on Query { version }
            ...MoreVersion
        }
        fragment MoreVersion on Query { version }
    """

    result = make_schema(max_cost=1).execute_sync(query)

    assert not result.errors


def test_merged_sub_selections_are_charged_once():
    query = """
        {
            me { name }
            ... on Query { me { name } }
        }
    """

    result = make_schema(max_cost=2).execute_sync(query)

    assert not result.errors


def test_named_fragment_spread_twice_is_charged_once():
    query = """
        { ...F ...F }
        fragment F on Query { version }
    """

    result = make_schema(max_cost=1).execute_sync(query)

    assert not result.errors


@pytest.mark.parametrize(
    "query",
    [
        "{ version @skip(if: true) }",
        "{ version @include(if: false) }",
    ],
)
def test_skip_and_include_literals(query: str):
    result = make_schema(max_cost=0).execute_sync(query)

    assert not result.errors


def test_skip_and_include_with_variables():
    schema = make_schema(max_cost=0)
    query = "query ($skip: Boolean!) { version @skip(if: $skip) }"

    result = schema.execute_sync(query, variable_values={"skip": True})
    assert not result.errors

    result = schema.execute_sync(query, variable_values={"skip": False})
    assert result.errors is not None
    assert "Query cost 1 exceeds the maximum allowed cost of 0" in str(result.errors[0])


def test_interface_uses_most_expensive_concrete_type():
    query = "{ node { id ... on Photo { url } ... on Video { premiumUrl } } }"

    result = make_schema(max_cost=12).execute_sync(query)
    assert not result.errors

    result = make_schema(max_cost=11).execute_sync(query)
    assert result.errors is not None
    assert "Query cost 12 exceeds the maximum allowed cost of 11" in str(
        result.errors[0]
    )


def test_union_uses_most_expensive_concrete_type():
    query = "{ media { ... on Photo { url } ... on Video { premiumUrl } } }"

    result = make_schema(max_cost=10).execute_sync(query)

    assert result.errors is not None
    assert "Query cost 11 exceeds the maximum allowed cost of 10" in str(
        result.errors[0]
    )


def test_error_contains_cost_budget_and_top_contributors():
    result = make_schema(max_cost=5).execute_sync("{ users(first: 10) { name } }")

    assert result.errors is not None
    error = result.errors[0]
    assert error.message == (
        "Query cost 11 exceeds the maximum allowed cost of 5. "
        "Top cost contributors: users (11), users.name (1)."
    )
    assert error.extensions == {
        "cost": 11,
        "maxCost": 5,
        "topContributors": [
            {"path": "users", "cost": 11},
            {"path": "users.name", "cost": 1},
        ],
    }


def test_only_the_executed_operation_is_charged():
    query = """
        query A { version }
        query B { users(first: 100) { name } }
    """

    result = make_schema(max_cost=5).execute_sync(query, operation_name="A")

    assert not result.errors


def test_invalid_variables_are_reported_by_execution():
    query = "query ($first: Int!) { users(first: $first) { name } }"

    result = make_schema(max_cost=1000).execute_sync(
        query, variable_values={"first": "not-an-int"}
    )

    assert result.errors is not None
    assert "Query cost" not in result.errors[0].message


def test_introspection_queries_are_supported():
    result = make_schema(max_cost=100).execute_sync(
        "{ __schema { types { name } } __typename }"
    )

    assert not result.errors


async def test_async_execution_is_rejected_before_resolvers():
    users_resolver_calls.clear()

    result = await make_schema(max_cost=5).execute("{ users(first: 10) { name } }")

    assert result.data is None
    assert result.errors is not None
    assert users_resolver_calls == []


def test_negative_field_cost_is_rejected():
    with pytest.raises(ValueError, match="Field cost cannot be negative"):
        FieldCost(cost=-1)
