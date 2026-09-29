import pytest

import strawberry
from strawberry.extensions import QueryCostLimiter
from strawberry.extensions.query_cost_limiter import (
    COST_METADATA_KEY,
    FieldCost,
    QueryCostReport,
)
from tests.conftest import skip_if_gql_32


@strawberry.type
class User:
    name: str
    email: str

    @strawberry.field(
        metadata={COST_METADATA_KEY: FieldCost(cost=1, multipliers=("first",))}
    )
    def friends(self, first: int = 1) -> list["User"]:
        return []


@strawberry.interface
class Character:
    name: str


@strawberry.type
class Human(Character):
    height: float
    mass: float


@strawberry.type
class Droid(Character):
    primary_function: str


@strawberry.type
class Query:
    @strawberry.field(
        metadata={COST_METADATA_KEY: FieldCost(cost=2, multipliers=("first",))}
    )
    def users(self, first: int = 1) -> list[User]:
        return []

    @strawberry.field(metadata={COST_METADATA_KEY: 5})
    def user(self) -> User:
        return User(name="Jane", email="jane@example.com")

    @strawberry.field
    def hero(self) -> Character:
        return Human(name="Jane", height=1.8, mass=70)

    @strawberry.field
    def version(self) -> str:
        return "1.0"


@strawberry.type
class Mutation:
    @strawberry.mutation(
        metadata={COST_METADATA_KEY: FieldCost(cost=10, multipliers=("count",))}
    )
    def create_users(self, count: int = 1) -> list[User]:
        return []


def make_schema(max_cost: float, reports: list[QueryCostReport] | None = None):
    callback = reports.append if reports is not None else None
    return strawberry.Schema(
        Query,
        mutation=Mutation,
        types=[Human, Droid],
        extensions=[lambda: QueryCostLimiter(max_cost=max_cost, callback=callback)],
    )


def test_simple_query_cost():
    reports: list[QueryCostReport] = []
    schema = make_schema(max_cost=100, reports=reports)

    result = schema.execute_sync("{ users(first: 3) { name email } }")

    assert result.errors is None
    assert len(reports) == 1
    report = reports[0]
    assert report.operation_name == "anonymous"
    # users: 2 + 3 * (name: 1 + email: 1)
    assert report.cost == 8


def test_named_operation_cost():
    reports: list[QueryCostReport] = []
    schema = make_schema(max_cost=100, reports=reports)

    result = schema.execute_sync("query GetUsers { users { name } }")

    assert result.errors is None
    assert reports[0].operation_name == "GetUsers"
    # users: 2 + 1 * (name: 1)
    assert reports[0].cost == 3


def test_over_budget_rejects_before_resolvers():
    called = False

    @strawberry.type
    class TrackedQuery:
        @strawberry.field(
            metadata={COST_METADATA_KEY: FieldCost(cost=1, multipliers=("first",))}
        )
        def users(self, first: int = 1) -> list[User]:
            nonlocal called
            called = True
            return []

    schema = strawberry.Schema(
        TrackedQuery, extensions=[lambda: QueryCostLimiter(max_cost=10)]
    )

    result = schema.execute_sync("{ users(first: 100) { name } }")

    assert called is False
    assert result.data is None
    assert len(result.errors) == 1
    message = result.errors[0].message
    assert "exceeds the maximum operation cost of 10" in message
    assert "actual cost: 101" in message
    assert '"users" (cost 101)' in message
    assert result.errors[0].extensions == {
        "code": "QUERY_COST_EXCEEDED",
        "cost": 101,
        "maxCost": 10,
    }


def test_field_base_cost():
    reports: list[QueryCostReport] = []
    schema = make_schema(max_cost=100, reports=reports)

    result = schema.execute_sync("{ user { name } }")

    assert result.errors is None
    # user: 5 + (name: 1)
    assert reports[0].cost == 6


def test_multiplier_uses_default_argument_value():
    reports: list[QueryCostReport] = []
    schema = make_schema(max_cost=100, reports=reports)

    result = schema.execute_sync("{ users { friends { name } } }")

    assert result.errors is None
    # users: 2 + 1 * (friends: 1 + 1 * (name: 1))
    assert reports[0].cost == 4


def test_multiplier_uses_variable_value():
    reports: list[QueryCostReport] = []
    schema = make_schema(max_cost=100, reports=reports)

    result = schema.execute_sync(
        "query GetUsers($n: Int!) { users(first: $n) { name } }",
        variable_values={"n": 4},
    )

    assert result.errors is None
    # users: 2 + 4 * (name: 1)
    assert reports[0].cost == 6


def test_multiplier_uses_variable_default_value():
    reports: list[QueryCostReport] = []
    schema = make_schema(max_cost=100, reports=reports)

    result = schema.execute_sync(
        "query GetUsers($n: Int = 5) { users(first: $n) { name } }"
    )

    assert result.errors is None
    # users: 2 + 5 * (name: 1)
    assert reports[0].cost == 7


@pytest.mark.parametrize("first", [-10, 0, 0.5])
def test_non_amplifying_multipliers_never_reduce_cost(first):
    @strawberry.type
    class FloatQuery:
        @strawberry.field(
            metadata={COST_METADATA_KEY: FieldCost(cost=2, multipliers=("first",))}
        )
        def users(self, first: float = 1) -> list[User]:
            return []

    reports: list[QueryCostReport] = []
    schema = strawberry.Schema(
        FloatQuery,
        extensions=[lambda: QueryCostLimiter(max_cost=100, callback=reports.append)],
    )

    result = schema.execute_sync(f"{{ users(first: {first}) {{ name }} }}")

    assert result.errors is None
    # Negative, zero and fractional multipliers behave as 1: 2 + 1 * (name: 1)
    assert reports[0].cost == 3


def test_missing_multiplier_argument_does_not_reduce_cost():
    reports: list[QueryCostReport] = []
    schema = make_schema(max_cost=100, reports=reports)

    result = schema.execute_sync("{ users { name } }")

    assert result.errors is None
    # Missing `first` behaves as 1: 2 + 1 * (name: 1)
    assert reports[0].cost == 3


def test_non_numeric_multiplier_argument_does_not_reduce_cost():
    @strawberry.type
    class SearchQuery:
        @strawberry.field(
            metadata={COST_METADATA_KEY: FieldCost(cost=2, multipliers=("term",))}
        )
        def search(self, term: str = "") -> list[User]:
            return []

    reports: list[QueryCostReport] = []
    schema = strawberry.Schema(
        SearchQuery,
        extensions=[lambda: QueryCostLimiter(max_cost=100, callback=reports.append)],
    )

    result = schema.execute_sync('{ search(term: "abc") { name } }')

    assert result.errors is None
    # A string multiplier behaves as 1: 2 + 1 * (name: 1)
    assert reports[0].cost == 3


def test_nested_multipliers_multiply():
    reports: list[QueryCostReport] = []
    schema = make_schema(max_cost=100, reports=reports)

    result = schema.execute_sync("{ users(first: 2) { friends(first: 3) { name } } }")

    assert result.errors is None
    # users: 2 + 2 * (friends: 1 + 3 * (name: 1)) = 2 + 2 * 4
    assert reports[0].cost == 10


def test_merged_fields_are_charged_once():
    reports: list[QueryCostReport] = []
    schema = make_schema(max_cost=100, reports=reports)

    query = """
    {
      users {
        name
        ...UserFields
        ... on User {
          email
        }
      }
    }
    fragment UserFields on User {
      name
      email
    }
    """
    result = schema.execute_sync(query)

    assert result.errors is None
    # users: 2 + 1 * (name: 1 + email: 1); the duplicated selections merge
    assert reports[0].cost == 4


def test_different_aliases_are_charged_separately():
    reports: list[QueryCostReport] = []
    schema = make_schema(max_cost=100, reports=reports)

    result = schema.execute_sync(
        "{ firstUsers: users { name } secondUsers: users { name } }"
    )

    assert result.errors is None
    # 2 * (users: 2 + 1 * (name: 1))
    assert reports[0].cost == 6


def test_same_alias_merges_across_selections():
    reports: list[QueryCostReport] = []
    schema = make_schema(max_cost=100, reports=reports)

    result = schema.execute_sync("{ u: user { name } u: user { email } }")

    assert result.errors is None
    # user: 5 + (name: 1 + email: 1)
    assert reports[0].cost == 7


def test_skip_and_include_directives():
    reports: list[QueryCostReport] = []
    schema = make_schema(max_cost=100, reports=reports)

    query = """
    query GetUsers($withEmail: Boolean!) {
      users {
        name
        email @include(if: $withEmail)
        friends @skip(if: true) {
          name
        }
      }
    }
    """
    result = schema.execute_sync(query, variable_values={"withEmail": False})

    assert result.errors is None
    # users: 2 + 1 * (name: 1); email is excluded and friends is skipped
    assert reports[0].cost == 3

    result = schema.execute_sync(query, variable_values={"withEmail": True})

    assert result.errors is None
    # users: 2 + 1 * (name: 1 + email: 1)
    assert reports[1].cost == 4


def test_interface_uses_most_expensive_concrete_type():
    reports: list[QueryCostReport] = []
    schema = make_schema(max_cost=100, reports=reports)

    query = """
    {
      hero {
        name
        ... on Human {
          height
          mass
        }
        ... on Droid {
          primaryFunction
        }
      }
    }
    """
    result = schema.execute_sync(query)

    assert result.errors is None
    # hero: 1 + max(Human: name + height + mass = 3, Droid: name + primaryFunction = 2)
    assert reports[0].cost == 4


def test_interface_fields_merge_with_concrete_type_fields():
    reports: list[QueryCostReport] = []
    schema = make_schema(max_cost=100, reports=reports)

    query = """
    {
      hero {
        name
        ... on Human {
          name
        }
      }
    }
    """
    result = schema.execute_sync(query)

    assert result.errors is None
    # hero: 1 + (name: 1); name is only charged once per concrete type
    assert reports[0].cost == 2


def test_union_uses_most_expensive_concrete_type():
    @strawberry.type
    class Cat:
        name: str
        lives: int

    @strawberry.type
    class Dog:
        name: str

    @strawberry.type
    class PetQuery:
        @strawberry.field
        def pet(self) -> Cat | Dog:
            return Cat(name="Tom", lives=9)

    reports: list[QueryCostReport] = []
    schema = strawberry.Schema(
        PetQuery,
        extensions=[lambda: QueryCostLimiter(max_cost=100, callback=reports.append)],
    )

    query = """
    {
      pet {
        ... on Cat {
          name
          lives
        }
        ... on Dog {
          name
        }
      }
    }
    """
    result = schema.execute_sync(query)

    assert result.errors is None
    # pet: 1 + max(Cat: name + lives = 2, Dog: name = 1)
    assert reports[0].cost == 3


def test_mutation_is_checked():
    reports: list[QueryCostReport] = []
    schema = make_schema(max_cost=100, reports=reports)

    result = schema.execute_sync("mutation { createUsers(count: 3) { name } }")

    assert result.errors is None
    # createUsers: 10 + 3 * (name: 1)
    assert reports[0].cost == 13


def test_mutation_over_budget_is_rejected():
    schema = make_schema(max_cost=10)

    result = schema.execute_sync("mutation { createUsers(count: 3) { name } }")

    assert result.data is None
    assert len(result.errors) == 1
    assert "exceeds the maximum operation cost of 10" in result.errors[0].message


def test_only_the_executed_operation_is_charged():
    reports: list[QueryCostReport] = []
    schema = make_schema(max_cost=10, reports=reports)

    query = """
    query Cheap { version }
    query Expensive { users(first: 100) { name } }
    """
    result = schema.execute_sync(query, operation_name="Cheap")

    assert result.errors is None
    assert reports[0].cost == 1

    result = schema.execute_sync(query, operation_name="Expensive")

    assert result.data is None
    assert len(result.errors) == 1


def test_typename_is_charged_the_default_cost():
    reports: list[QueryCostReport] = []
    schema = make_schema(max_cost=100, reports=reports)

    result = schema.execute_sync("{ __typename users { __typename } }")

    assert result.errors is None
    # __typename: 1 + users: 2 + 1 * (__typename: 1)
    assert reports[0].cost == 4


def test_report_contains_top_contributors():
    reports: list[QueryCostReport] = []
    schema = make_schema(max_cost=100, reports=reports)

    result = schema.execute_sync("{ users(first: 2) { friends(first: 3) { name } } }")

    assert result.errors is None
    report = reports[0]
    assert report.top_contributors[0].path == "users"
    assert report.top_contributors[0].cost == 10
    assert report.top_contributors[1].path == "users.friends"
    assert report.top_contributors[1].cost == 4


def test_invalid_variable_values_skip_analysis():
    schema = make_schema(max_cost=1)

    result = schema.execute_sync(
        "query GetUsers($n: Int!) { users(first: $n) { name } }"
    )

    # The cost check stays out of the way and the variable coercion error
    # from execution is reported instead.
    assert result.data is None
    assert len(result.errors) == 1
    assert "$n" in result.errors[0].message


def test_invalid_cost_metadata_raises_a_clear_error():
    @strawberry.type
    class BadQuery:
        some_field: str = strawberry.field(metadata={COST_METADATA_KEY: "expensive"})

    schema = strawberry.Schema(
        BadQuery, extensions=[lambda: QueryCostLimiter(max_cost=100)]
    )

    result = schema.execute_sync("{ someField }")

    assert result.data is None
    assert len(result.errors) == 1
    assert "Invalid 'cost' metadata" in result.errors[0].message


def test_field_cost_validates_configuration():
    with pytest.raises(ValueError, match="must not be negative"):
        FieldCost(cost=-1)

    with pytest.raises(TypeError, match="must be a number"):
        FieldCost(cost="a lot")  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="must be argument names"):
        FieldCost(multipliers=(10,))  # type: ignore[arg-type]


def test_field_cost_accepts_single_multiplier_string():
    assert FieldCost(multipliers="first").multipliers == ("first",)  # type: ignore[arg-type]


def test_plain_number_metadata():
    reports: list[QueryCostReport] = []
    schema = make_schema(max_cost=100, reports=reports)

    result = schema.execute_sync("{ user { name } version }")

    assert result.errors is None
    # user: 5 + (name: 1) + version: 1
    assert reports[0].cost == 7


def test_non_callable_callback_raises():
    with pytest.raises(TypeError, match="must be a callable"):
        QueryCostLimiter(max_cost=10, callback="nope")  # type: ignore[arg-type]


async def test_async_execution_is_checked():
    schema = make_schema(max_cost=10)

    result = await schema.execute("{ users(first: 100) { name } }")

    assert result.data is None
    assert len(result.errors) == 1
    assert "exceeds the maximum operation cost of 10" in result.errors[0].message

    result = await schema.execute("{ users(first: 2) { name } }")

    assert result.errors is None
    assert result.data == {"users": []}
