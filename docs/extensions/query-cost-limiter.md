---
title: Query Cost Limiter
summary: Reject operations whose estimated cost exceeds a maximum, before execution.
tags: security
---

# `QueryCostLimiter`

This extension estimates the cost of an operation and rejects it before any
resolver runs when the estimate exceeds a maximum. Depth limiting alone cannot
stop cheap-looking but extremely wide queries (e.g. a list field with
`first: 10000`); cost limiting can, because fields can declare which
arguments multiply the cost of their sub-selections.

Fields cost `1` by default. Use `FieldCost` to declare a different base
cost and the arguments that multiply the cost of the field's sub-selections:

## Usage example:

```python
import strawberry
from strawberry.extensions import FieldCost, QueryCostLimiter


@strawberry.type
class User:
    name: str


@strawberry.type
class Query:
    users: list[User] = strawberry.field(
        extensions=[FieldCost(cost=1, multipliers=["first", "last"])]
    )


schema = strawberry.Schema(
    Query,
    extensions=[
        lambda: QueryCostLimiter(max_cost=1000),
    ],
)
```

With this schema, `users(first: 100) { name }` costs
`1 + 100 * 1 = 101`: the base cost of `users` plus `first` times the
cost of its sub-selections.

The estimate:

- uses the validated variable values and the default values of arguments and
  variables;
- understands fragments, aliases, interfaces, unions and
  `@skip`/`@include`;
- charges fields merged at the same response position only once, while
  different aliases are charged separately;
- uses a conservative rule for interfaces and unions: the cost of an abstract
  position is the cost of its most expensive possible concrete type;
- clamps multiplier values to a minimum of `1`, so negative, missing or
  non-numeric values never make the estimate smaller.

When an operation exceeds the budget, it is rejected before any resolver runs
and the error reports the total cost, the budget and the top cost-contributing
paths, so clients can fix their queries:

```text
Query cost 10101 exceeds the maximum allowed cost of 1000. Top cost
contributors: users (10101), users.friends (101), users.friends.name (1).
```

## API reference:

```python
class QueryCostLimiter(max_cost): ...
```

#### `max_cost: int`

The maximum allowed cost for any operation. Operations estimated to cost more
are rejected before execution.

```python
class FieldCost(cost=1, multipliers=None): ...
```

#### `cost: int = 1`

The base cost of the field, charged once per position in the operation.

#### `multipliers: Optional[list[str]] = None`

Names of arguments whose values multiply the cost of the field's
sub-selections, for example pagination arguments such as `first`. Both
GraphQL (`pageSize`) and Python (`page_size`) argument names are accepted.
Values are resolved from the query, the validated variables or the argument
defaults, and are clamped to a minimum of `1`.

