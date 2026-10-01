from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from datetime import date
from typing import Optional, Union

import pytest

import falcon
from falcon import query as query_module


@dataclass
class PriceRange:
    min: Optional[int] = None
    max: Optional[int] = None


@dataclass
class SearchFilter:
    price: Optional[PriceRange] = None


@dataclass
class RequiredFilter:
    price: PriceRange


@dataclass
class RequiredRange:
    min: int


@dataclass
class RequiredRangeFilter:
    price: RequiredRange


@dataclass
class SearchQuery:
    created_on: Optional[date] = falcon.query_field(
        alias='created-on', converter=date.fromisoformat, default=None
    )
    q: str = ''
    page: int = 1
    active: Optional[bool] = None
    tags: list[str] = falcon.query_field(default_factory=list)
    sort: list[str] = falcon.query_field(default_factory=list)
    filter: Optional[SearchFilter] = None


def test_bind_scalars_optional_lists_and_nested_dataclass():
    query = falcon.bind_query_model(
        'q=falcon&page=3&active=true&tags=web&tags=http&sort=-name'
        '&filter[price][min]=10&filter[price][max]=20',
        SearchQuery,
    )

    assert query == SearchQuery(
        q='falcon',
        page=3,
        active=True,
        tags=['web', 'http'],
        sort=['-name'],
        filter=SearchFilter(price=PriceRange(min=10, max=20)),
    )


@pytest.mark.parametrize(
    'query_string,expected',
    [('tags=', ['']), ('tags=&tags=', ['', ''])],
)
def test_blank_value_is_one_empty_string(query_string, expected):
    assert falcon.bind_query_model(query_string, SearchQuery).tags == expected


def test_empty_bracket_marker_binds_empty_list():
    assert falcon.bind_query_model('tags[]=', SearchQuery).tags == []
    assert falcon.bind_query_model('tags[]', SearchQuery).tags == []


@pytest.mark.parametrize(
    'query_string',
    [
        'tags=&tags[]=',
        'tags[]=&tags=',
        'tags[]=&tags[]=x',
        'a=1&a[b]=2',
        'a[b]=2&a=1',
        'a[b]=2&a[]=',
        'a[]=1&a[b]=2',
        'a=1&a[]=',
    ],
)
def test_conflicting_shape_rejected(query_string):
    @dataclass
    class Shape:
        a: Optional[str] = None
        tags: list[str] = falcon.query_field(default_factory=list)

    with pytest.raises(falcon.QueryBindingError):
        falcon.bind_query_model(query_string, Shape)


@pytest.mark.parametrize(
    'query_string',
    [
        'a[b',
        'a]',
        'a[]b=1',
        'a[]',
        'a[',
        'a[b][',
        '[a]=1',
        'a[[]=1',
        'a[b]c=1',
        '=1',
    ],
)
def test_malformed_paths_rejected(query_string):
    @dataclass
    class Model:
        a: Optional[str] = None

    with pytest.raises(falcon.QueryBindingError) as exc_info:
        falcon.bind_query_model(query_string, Model)
    assert len(exc_info.value.errors) == 1


@pytest.mark.parametrize(
    'query_string,expected',
    [('tags[]=x', ['x']), ('tags[]=x&tags[]=y', ['x', 'y'])],
)
def test_explicit_list_syntax_with_values(query_string, expected):
    assert falcon.bind_query_model(query_string, SearchQuery).tags == expected


def test_nested_shape_and_bool_conversion():
    query = falcon.bind_query_model('active=false&tags[]=1', SearchQuery)
    assert query.active is False

    with pytest.raises(falcon.QueryBindingError) as exc_info:
        falcon.bind_query_model('active=maybe', SearchQuery)
    assert exc_info.value.errors[0].description == 'Value must be a boolean.'


def test_scalar_list_and_object_shape_errors():
    @dataclass
    class Model:
        scalar: Optional[str] = None
        values: list[str] = falcon.query_field(default_factory=list)
        nested: Optional[SearchFilter] = None

    cases = {
        'scalar[]=': 'scalar',
        'scalar=1&scalar=2': 'scalar',
        'values[value]=1': 'values',
        'nested=1': 'nested',
    }
    for query_string, path in cases.items():
        with pytest.raises(falcon.QueryBindingError) as exc_info:
            falcon.bind_query_model(query_string, Model)
        assert exc_info.value.errors[0].path == path


def test_required_and_empty_conversion_error():
    @dataclass
    class Required:
        page: int

    with pytest.raises(falcon.QueryBindingError) as exc_info:
        falcon.bind_query_model('page=', Required)
    assert exc_info.value.errors[0].path == 'page'

    class EmptyConverter:
        def __call__(self, value):
            if value == '':
                raise ValueError('')
            return value

    @dataclass
    class EmptyMessage:
        value: str = falcon.query_field(converter=EmptyConverter())

    with pytest.raises(falcon.QueryBindingError) as exc_info:
        falcon.bind_query_model('value=', EmptyMessage)
    assert exc_info.value.errors[0].description == 'Invalid value.'


def test_nested_object_defaults_and_unknown_ignored():
    @dataclass
    class RequiredNested:
        price: PriceRange

    query = falcon.bind_query_model('unknown=1', RequiredNested, unknown='ignore')
    assert query == RequiredNested(PriceRange(None, None))


def test_query_binding_error_to_dict():
    error = falcon.QueryBindingError([falcon.QueryErrorDetail('page', 'bad')])
    assert error.to_dict()['errors'] == [{'path': 'page', 'description': 'bad'}]


def test_alias_default_and_custom_converter():
    def parse_date(value: str) -> date:
        return date.fromisoformat(value)

    @dataclass
    class Model:
        search_text: str = falcon.query_field(alias='q', default='')
        created_on: Optional[date] = falcon.query_field(
            alias='created-on', converter=parse_date, default=None
        )

    result = falcon.bind_query_model('q=hello&created-on=2026-10-01', Model)
    assert result == Model('hello', date(2026, 10, 1))


def test_optional_list_uses_custom_converter():
    @dataclass
    class Model:
        dates: Optional[list[date]] = falcon.query_field(
            converter=date.fromisoformat, default=None
        )

    assert falcon.bind_query_model('dates=2026-10-01', Model).dates == [
        date(2026, 10, 1)
    ]


def test_default_factory_is_used_when_absent():
    first = falcon.bind_query_model('', SearchQuery)
    second = falcon.bind_query_model('', SearchQuery)
    assert first.tags == []
    assert first.tags is not second.tags


def test_invalid_model_definition_rejected():
    with pytest.raises(TypeError, match='must be dataclass'):
        falcon.bind_query_model('', object)

    @dataclass
    class Invalid:
        created: complex

    with pytest.raises(TypeError, match='unsupported query type'):
        falcon.bind_query_model('', Invalid)

    @dataclass
    class InvalidAlias:
        created: str = falcon.query_field(alias='', default='')

    with pytest.raises(TypeError, match='invalid alias'):
        falcon.bind_query_model('', InvalidAlias)

    @dataclass
    class BracketAlias:
        nested: str = falcon.query_field(alias='a[b]', default='')

    with pytest.raises(TypeError, match='must not contain brackets'):
        falcon.bind_query_model('', BracketAlias)

    @dataclass
    class InvalidConverter:
        created: str = falcon.query_field(converter='date')

    with pytest.raises(TypeError, match='must be callable'):
        falcon.bind_query_model('', InvalidConverter)

    @dataclass
    class DuplicateAlias:
        first: str = falcon.query_field(alias='same', default='')
        second: str = falcon.query_field(alias='same', default='')

    with pytest.raises(TypeError, match='more than one field'):
        falcon.bind_query_model('', DuplicateAlias)

    @dataclass
    class NestedWithConverter:
        nested: SearchFilter = falcon.query_field(
            converter=lambda value: value,
            default_factory=SearchFilter,
        )

    with pytest.raises(TypeError, match='cannot use a converter'):
        falcon.bind_query_model('', NestedWithConverter)

    @dataclass
    class InvalidUnion:
        value: Optional[Union[int, str]] = None

    with pytest.raises(TypeError, match='optional or use one'):
        falcon.bind_query_model('', InvalidUnion)

    @dataclass
    class InvalidList:
        value: list[SearchFilter]

    with pytest.raises(TypeError, match='one scalar type'):
        falcon.bind_query_model('', InvalidList)


def test_invalid_binding_options_rejected():
    with pytest.raises(ValueError, match='unknown'):
        falcon.bind_query_model('', SearchQuery, unknown='nope')
    with pytest.raises(ValueError, match='max_depth'):
        falcon.bind_query_model('', SearchQuery, max_depth=0)
    with pytest.raises(ValueError, match='max_errors'):
        falcon.bind_query_model('', SearchQuery, max_errors=0)
    with pytest.raises(ValueError, match='max_params'):
        falcon.bind_query_model('', SearchQuery, max_params=0)


def test_conversion_errors_are_limited_and_contain_paths():
    with pytest.raises(falcon.QueryBindingError) as exc_info:
        falcon.bind_query_model(
            'page=bad&filter[price][min]=low&filter[price][max]=high',
            SearchQuery,
            max_errors=2,
        )

    assert [error.path for error in exc_info.value.errors] == [
        'page',
        'filter[price][min]',
    ]


def test_unknown_strict_and_ignore():
    with pytest.raises(falcon.QueryBindingError) as exc_info:
        falcon.bind_query_model('unknown=1&filter[unknown]=2', SearchQuery)
    assert [error.path for error in exc_info.value.errors] == [
        'filter[unknown]',
        'unknown',
    ]

    query = falcon.bind_query_model('q=ok&unknown=1', SearchQuery, unknown='ignore')
    assert query.q == 'ok'


def test_depth_and_parameter_limits():
    with pytest.raises(falcon.QueryBindingError) as exc_info:
        falcon.bind_query_model('filter[price][min]=1', SearchQuery, max_depth=2)
    assert exc_info.value.errors[0].path == 'filter[price][min]'

    with pytest.raises(falcon.QueryBindingError):
        falcon.bind_query_model('a=1&b=2', SearchQuery, max_params=1)


def test_encoded_aliases_and_paths():
    query = falcon.bind_query_model(
        'created%2Don=2026-10-01&filter%5Bprice%5D%5Bmin%5D=7',
        SearchQuery,
    )
    assert query.created_on == date(2026, 10, 1)
    assert query.filter == SearchFilter(PriceRange(min=7))


def test_request_params_are_not_modified(asgi, util):
    req = util.create_req(
        asgi, query_string='q=hello&tags=one&tags=&filter[price][min]=5'
    )
    before = dict(req.params)

    falcon.bind_query_model(req.query_string, SearchQuery)

    assert dict(req.params) == before


def test_query_binding_error_response_paths(asgi, util):
    class Resource:
        @falcon.bind_query(SearchQuery)
        def on_get(self, req, resp, query):
            resp.media = {}

    app = util.create_app(asgi)
    app.add_route('/search', Resource())
    client = falcon.testing.TestClient(app)

    response = client.simulate_get('/search', query_string='page=bad')
    assert response.status == falcon.HTTP_400
    assert [error['path'] for error in response.json['errors']] == ['page']


def test_decorator_requires_matching_keyword_parameter():
    def responder(req, resp):
        return None

    with pytest.raises(TypeError, match='query'):
        falcon.bind_query(SearchQuery)(responder)


def test_decorator_does_not_override_route_parameter(asgi, util):
    class Resource:
        @falcon.bind_query(SearchQuery, param_name='item_id')
        def on_get(self, req, resp, item_id, query):
            raise AssertionError('unreachable')

    class AsyncResource:
        @falcon.bind_query(SearchQuery, param_name='item_id')
        async def on_get(self, req, resp, item_id, query):
            raise AssertionError('unreachable')

    app = util.create_app(asgi)
    app.add_route('/items/{item_id}', AsyncResource() if asgi else Resource())
    client = falcon.testing.TestClient(app)

    response = client.simulate_get('/items/42')
    assert response.status == falcon.HTTP_500


@pytest.mark.parametrize('asgi', [False, True])
def test_decorator_wsgi_and_asgi(asgi, util):
    class Resource:
        @falcon.bind_query(SearchQuery)
        def on_get(self, req, resp, query):
            resp.media = dataclasses_asdict(query)

    class AsyncResource:
        @falcon.bind_query(SearchQuery)
        async def on_get(self, req, resp, query):
            resp.media = dataclasses_asdict(query)

    app = util.create_app(asgi)
    app.add_route('/search', AsyncResource() if asgi else Resource())
    client = falcon.testing.TestClient(app)

    response = client.simulate_get(
        '/search',
        query_string='q=hello&tags=py&tags=&filter[price][min]=5',
    )
    assert response.status == falcon.HTTP_200
    assert response.json == {
        'created_on': None,
        'q': 'hello',
        'page': 1,
        'active': None,
        'tags': ['py', ''],
        'sort': [],
        'filter': {'price': {'min': 5, 'max': None}},
    }


def dataclasses_asdict(value):
    from dataclasses import is_dataclass

    if is_dataclass(value):
        return {key: dataclasses_asdict(item) for key, item in vars(value).items()}
    return value


def test_parser_helpers_cover_empty_root_and_repeated_marker():
    root = query_module._parse_query_tree('', 5, 100)
    assert root.children == {}

    root = query_module._parse_query_tree('&&', 5, 100)
    assert root.children == {}

    root = query_module._parse_query_tree('tags[]=&tags[]=', 5, 100)
    node = root.children['tags']
    assert node.kind == query_module._LIST
    assert node.explicit_empty_list is True

    for malformed in ('a[', 'a[b]['):
        with pytest.raises(falcon.QueryBindingError):
            query_module._parse_query_tree(malformed, 5, 100)


def test_field_default_helper_reports_missing_required_scalar():
    @dataclass
    class Required:
        value: int

    compiled = query_module._compile_model(Required)
    field = compiled.fields_by_alias['value']
    errors = []
    result = query_module._field_default(
        field, compiled, 'value', [], 'strict', 10, errors
    )
    assert result is None
    assert errors[0].path == 'value'


def test_non_init_fields_are_ignored():
    @dataclass
    class Model:
        value: int
        derived: int = dataclasses.field(init=False)

    query = falcon.bind_query_model('value=1', Model)
    assert query.value == 1


def test_empty_list_marker_can_repeat():
    assert falcon.bind_query_model('tags[]=&tags[]=', SearchQuery).tags == []


def test_nested_list_of_lists_rejected():
    @dataclass
    class Model:
        values: list[list[str]]

    with pytest.raises(TypeError, match='must contain scalar'):
        falcon.bind_query_model('', Model)

    @dataclass
    class BareList:
        values: list

    with pytest.raises(TypeError, match='unsupported query type'):
        falcon.bind_query_model('', BareList)


def test_optional_nested_object_defaults_to_none():
    query = falcon.bind_query_model('', SearchQuery)
    assert query.filter is None
    assert query == SearchQuery()


def test_optional_scalar_without_default():
    @dataclass
    class Model:
        value: Optional[int]

    assert falcon.bind_query_model('', Model).value is None


def test_required_nested_object_uses_nested_defaults():
    @dataclass
    class Root:
        price: PriceRange

    assert falcon.bind_query_model('', Root).price == PriceRange()


def test_required_nested_object_can_report_required_scalar():
    with pytest.raises(falcon.QueryBindingError) as exc_info:
        falcon.bind_query_model('', RequiredRangeFilter, max_errors=1)
    assert exc_info.value.errors[0].path == 'price[min]'


def test_scalar_required_error():
    @dataclass
    class Model:
        value: int

    with pytest.raises(falcon.QueryBindingError) as exc_info:
        falcon.bind_query_model('', Model)
    assert exc_info.value.errors[0].path == 'value'


def test_unknown_error_limit_reached():
    with pytest.raises(falcon.QueryBindingError) as exc_info:
        falcon.bind_query_model('a=1&b=2', SearchQuery, max_errors=1)
    assert len(exc_info.value.errors) == 1


def test_list_conversion_error_stops_after_limit():
    @dataclass
    class Model:
        values: list[int]

    with pytest.raises(falcon.QueryBindingError) as exc_info:
        falcon.bind_query_model('values=a&values=b', Model, max_errors=1)
    assert len(exc_info.value.errors) == 1
