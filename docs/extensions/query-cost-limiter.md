---
title: Query Cost Limiter
summary: Reject operations whose estimated cost exceeds a budget, before execution.
tags: security
---

# `QueryCostLimiter`

This extension estimates the cost of an operation and rejects it before any
resolver runs when the cost exceeds a budget. Unlike
[`QueryDepthLimiter`](./query-depth-limiter.md), which only looks at nesting,
the cost limiter also accounts for wide list queries: fields can declare a
base cost and arguments that multiply the cost of their sub-selections.

## Usage example:

```python
import strawberry
from strawberry.extensions import QueryCostLimiter
from strawberry.extensions.query_cost_limiter import COST_METADATA_KEY, FieldCost


@strawberry.type
class User:
    name: str

    @strawberry.field(
        metadata={COST_METADATA_KEY: FieldCost(cost=1, multipliers=("first",))}
    )
    def friends(self, first: int = 1) -> list["User"]:
        ...


@strawberry.type
class Query:
    @strawberry.field(
        metadata={COST_METADATA_KEY: FieldCost(cost=2, multipliers=("first",))}
    )
    def users(self, first: int = 1) -> list[User]:
        ...


schema = strawberry.Schema(
    Query,
    extensions=[
        lambda: QueryCostLimiter(max_cost=100),
    ],
)
```

With this schema, `{ users(first: 10) { friends(first: 5) { name } } }`
costs `2 + 10 * (1 + 5 * 1) = 62`: each field contributes its base cost,
and the `first` argument multiplies the cost of the field's sub-selection.

## How the cost is computed

- Every field costs its declared base cost, or 1 when no cost is declared.
- A field's total cost is its base cost plus the cost of its sub-selection,
  multiplied by every declared multiplier argument.
- Multipliers use the coerced argument values of the executed operation, so
  variables, variable defaults and argument defaults are all taken into
  account. A multiplier argument that is missing, negative, a fraction below
  1 or not numeric behaves as a multiplier of 1 and never lowers the cost.
- Fields merged at the same response position (same alias or name, including
  fields merged through fragments) are only charged once, while different
  aliases are charged separately.
- For interface and union types the cost of each possible concrete type is
  computed and the largest one is used, so the estimate never underestimates
  the worst case for a response position.
- Fields skipped via `@skip`/`@include` are not charged.

When an operation exceeds the budget, it is rejected before execution with an
error that reports the total cost, the budget and the most expensive paths,
for example:

```text
'GetUsers' exceeds the maximum operation cost of 100 (actual cost: 152).
Top contributors: "users" (cost 152), "users.friends" (cost 75).
```

## Declaring costs

Costs are declared through field metadata. `FieldCost` takes a base `cost`
(default 1) and `multipliers`, the names of arguments whose values multiply
the cost of the field's sub-selection:

```python
@strawberry.field(
    metadata={COST_METADATA_KEY: FieldCost(cost=2, multipliers=("first", "last"))}
)
def users(self, first: int = 1, last: int = 1) -> list[User]: ...
```

When only a base cost is needed, a plain number can be used instead:

```python
@strawberry.field(metadata={COST_METADATA_KEY: 5})
def user(self) -> User: ...
```

## API reference:

```python
class QueryCostLimiter(max_cost, callback=None): ...
```

#### `max_cost: float`

The maximum allowed cost for an operation. Operations that exceed it are
rejected before any resolver runs.

#### `callback: Optional[Callable[[QueryCostReport], None]]`

Called for every executed operation with its cost report, whether or not the
budget was exceeded. The report contains the operation name, the total cost
and the top contributing paths. Useful for logging and monitoring.

