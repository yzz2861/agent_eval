---
release type: minor
social_messages:
  x: >-
    {project_name} {version} is out! This release adds a query cost limiter
    extension that rejects expensive operations before they run. 🍓
    https://strawberry.rocks/release/{version}
  linkedin: >-
    {project_name} {version} is out. This release adds a query cost limiter
    extension: fields can declare a base cost and multiplier arguments, and
    operations over budget are rejected before any resolver runs.
---

This release adds a `QueryCostLimiter` extension that estimates the cost of an
operation and rejects it before any resolver runs when the cost exceeds a
budget.

Fields can declare a base cost and arguments that multiply the cost of their
sub-selections via field metadata:

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

The cost is computed with the coerced variable values and argument defaults of
the executed operation. Fields merged at the same response position are only
charged once, different aliases are charged separately, interface and union
types use the most expensive possible concrete type, and `@skip`/`@include`
are respected. Multiplier arguments that are missing, negative or not numeric
never lower the cost. When an operation exceeds the budget, the error reports
the total cost, the budget and the most expensive paths.

