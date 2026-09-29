---
release type: minor
social_messages:
  x: >-
    {project_name} {version} is out! This release adds a query cost limiter
    extension that rejects expensive operations before any resolver runs. 🍓
    https://strawberry.rocks/release/{version}
  linkedin: >-
    {project_name} {version} is out. This release adds a QueryCostLimiter
    extension: fields can declare a base cost and multiplier arguments, and
    operations over budget are rejected before execution, with an error that
    reports the total cost, the budget and the top cost contributors.
---

This release adds a new `QueryCostLimiter` extension that rejects operations
whose estimated cost exceeds a maximum, before any resolver runs.

Fields cost `1` by default and can declare a base cost and multiplier
arguments with the new `FieldCost` field extension:

```python
import strawberry
from strawberry.extensions import FieldCost, QueryCostLimiter


@strawberry.type
class Query:
    users: list[User] = strawberry.field(
        extensions=[FieldCost(cost=1, multipliers=["first", "last"])]
    )


schema = strawberry.Schema(
    Query,
    extensions=[lambda: QueryCostLimiter(max_cost=1000)],
)
```

The estimate uses validated variable values and argument defaults, understands
fragments, aliases, interfaces, unions and `@skip`/`@include`, charges
fields merged at the same response position only once, uses a conservative
most-expensive-concrete-type rule for abstract types, and never lets negative,
missing or non-numeric multiplier values reduce the cost. Rejected operations
return an error reporting the total cost, the budget and the top
cost-contributing paths.

