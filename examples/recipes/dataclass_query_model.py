from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Optional

import falcon


@dataclass
class PriceRange:
    min: Optional[int] = None
    max: Optional[int] = None


@dataclass
class SearchFilter:
    price: Optional[PriceRange] = None


@dataclass
class SearchQuery:
    created_on: Optional[date] = falcon.query_field(
        alias='created-on', converter=date.fromisoformat, default=None
    )
    q: str = ''
    page: int = 1
    active: Optional[bool] = None
    tags: list[str] = falcon.query_field(default_factory=list)
    filter: Optional[SearchFilter] = None


def serialize_search(query: SearchQuery) -> dict[str, object]:
    filter = (
        None
        if query.filter is None
        else {
            'price': {
                'min': query.filter.price.min if query.filter.price else None,
                'max': query.filter.price.max if query.filter.price else None,
            }
        }
    )
    return {
        'q': query.q,
        'page': query.page,
        'active': query.active,
        'tags': query.tags,
        'created_on': None
        if query.created_on is None
        else query.created_on.isoformat(),
        'filter': filter,
    }
