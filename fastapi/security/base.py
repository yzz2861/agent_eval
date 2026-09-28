from dataclasses import dataclass
from typing import Any

from fastapi.openapi.models import SecurityBase as SecurityBaseModel


class SecurityBase:
    model: SecurityBaseModel
    scheme_name: str


@dataclass(frozen=True)
class SecurityResult:
    """
    The result of a successful Security(any_of=[...]) group.

    group_index is the index (in declaration order) of the group that
    succeeded, values holds the value produced by each requirement of that
    group, in declaration order.
    """

    group_index: int
    values: tuple[Any, ...]
