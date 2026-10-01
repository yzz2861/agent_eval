# ruff: noqa: UP007, UP045
# NOTE: The models below intentionally use typing.Optional and typing.Union
#   (rather than the "X | None" syntax) so that the annotations can also be
#   evaluated at runtime on Python 3.9.
from __future__ import annotations

import dataclasses
from datetime import date
from typing import Any, Optional, Union

import pytest

import falcon
import falcon.testing as testing


@dataclasses.dataclass
class PriceFilter:
    min: Optional[float] = None
    max: Optional[float] = None


@dataclasses.dataclass
class SearchQuery:
    q: str
    page: int = 1
    per_page: int = falcon.query_field(default=20, alias='page_size')
    tags: list[str] = falcon.query_field(default_factory=list)
    verbose: bool = False
    updated_since: Optional[date] = falcon.query_field(
        default=None, converter=date.fromisoformat
    )
    filter: Optional[PriceFilter] = None


@dataclasses.dataclass
class StrictQuery:
    a: int
    b: Optional[str] = None


@dataclasses.dataclass
class SearchFilters:
    price: Optional[PriceFilter] = None


@dataclasses.dataclass
class DeepSearch:
    filter: Optional[SearchFilters] = None


class CapturingResource:
    def __init__(self, model, **options):
        self.captured = None
        self.captured_params = None
        self.options = options
        self.model = model

    def make_responder(self):
        resource = self

        @falcon.bind_query(self.model, **self.options)
        def on_get(self_, req, resp, query):
            resource.captured = query
            resource.captured_params = dict(req.params)
            resp.media = {'ok': True}

        return on_get


@pytest.fixture
def resource():
    return CapturingResource(SearchQuery)


@pytest.fixture
def client(asgi, util, resource):
    app = util.create_app(asgi)
    app.add_route('/bound', type('R', (), {'on_get': resource.make_responder()})())
    return testing.TestClient(app)


class TestScalarsAndDefaults:
    def test_scalars_and_types(self, client, resource):
        result = client.simulate_get(
            '/bound',
            query_string='q=hello&page=3&page_size=50&verbose=on&'
            'updated_since=2024-01-31',
        )
        assert result.status_code == 200
        query = resource.captured
        assert query.q == 'hello'
        assert query.page == 3
        assert query.per_page == 50
        assert query.verbose is True
        assert query.updated_since == date(2024, 1, 31)

    def test_defaults_and_missing_optional(self, client, resource):
        result = client.simulate_get('/bound', query_string='q=hello')
        assert result.status_code == 200
        query = resource.captured
        assert query.page == 1
        assert query.per_page == 20
        assert query.tags == []
        assert query.verbose is False
        assert query.updated_since is None
        assert query.filter is None

    def test_empty_string_scalar(self, client, resource):
        result = client.simulate_get('/bound', query_string='q=')
        assert result.status_code == 200
        assert resource.captured.q == ''

    def test_missing_required(self, client):
        result = client.simulate_get('/bound', query_string='page=1')
        assert result.status_code == 400
        assert 'q: missing required parameter' in result.json['description']

    def test_scalar_repeated_is_an_error(self, client):
        result = client.simulate_get('/bound', query_string='q=a&q=b')
        assert result.status_code == 400
        assert 'q: expected a single value, got 2' in result.json['description']

    def test_invalid_bool(self, client):
        result = client.simulate_get('/bound', query_string='q=x&verbose=maybe')
        assert result.status_code == 400
        assert "verbose: could not convert 'maybe'" in result.json['description']


class TestLists:
    def test_repeated_params(self, client, resource):
        result = client.simulate_get('/bound', query_string='q=x&tags=a&tags=b')
        assert result.status_code == 200
        assert resource.captured.tags == ['a', 'b']

    def test_single_empty_value_is_one_empty_string(self, client, resource):
        result = client.simulate_get('/bound', query_string='q=x&tags=')
        assert result.status_code == 200
        assert resource.captured.tags == ['']

    def test_empty_list_marker(self, client, resource):
        result = client.simulate_get('/bound', query_string='q=x&tags[]=')
        assert result.status_code == 200
        assert resource.captured.tags == []

    def test_mixed_marker_and_value_is_an_error(self, client):
        for qs in ('q=x&tags=&tags[]=', 'q=x&tags[]=&tags=a'):
            result = client.simulate_get('/bound', query_string=qs)
            assert result.status_code == 400
            assert 'cannot mix the empty-list marker' in result.json['description']

    def test_marker_with_value_is_an_error(self, client):
        result = client.simulate_get('/bound', query_string='q=x&tags[]=a')
        assert result.status_code == 400
        assert 'must have an empty value' in result.json['description']

    def test_list_element_conversion_error(self, client):
        result = client.simulate_get('/bound', query_string='q=x&page=1')
        assert result.status_code == 200

        result = client.simulate_get('/bound', query_string='q=x&page=abc')
        assert result.status_code == 400
        assert "page: could not convert 'abc'" in result.json['description']


class TestNested:
    def test_nested_dataclass(self, client, resource):
        result = client.simulate_get(
            '/bound', query_string='q=x&filter[min]=1.5&filter[max]=9'
        )
        assert result.status_code == 200
        assert resource.captured.filter == PriceFilter(min=1.5, max=9.0)

    def test_nested_partial(self, client, resource):
        result = client.simulate_get('/bound', query_string='q=x&filter[max]=2')
        assert result.status_code == 200
        assert resource.captured.filter == PriceFilter(min=None, max=2.0)

    def test_nested_conversion_error_path(self, client):
        result = client.simulate_get('/bound', query_string='q=x&filter[min]=abc')
        assert result.status_code == 400
        assert "filter[min]: could not convert 'abc'" in result.json['description']

    def test_nested_unknown_param(self, client):
        result = client.simulate_get('/bound', query_string='q=x&filter[bogus]=1')
        assert result.status_code == 400
        assert 'filter[bogus]: unknown parameter' in result.json['description']

    def test_object_given_scalar_is_an_error(self, client):
        result = client.simulate_get('/bound', query_string='q=x&filter=1')
        assert result.status_code == 400
        assert 'filter: expected an object' in result.json['description']

    def test_scalar_given_object_is_an_error(self, client):
        result = client.simulate_get('/bound', query_string='q[x]=1')
        assert result.status_code == 400
        assert 'q: expected a single value' in result.json['description']

    def test_list_given_object_is_an_error(self, client):
        result = client.simulate_get('/bound', query_string='q=x&tags[a]=1')
        assert result.status_code == 400
        assert 'tags: expected a list of values' in result.json['description']

    def test_two_level_nesting(self, asgi, util):
        resource = CapturingResource(DeepSearch)
        app = util.create_app(asgi)
        app.add_route('/bound', type('R', (), {'on_get': resource.make_responder()})())
        client = testing.TestClient(app)
        result = client.simulate_get(
            '/bound', query_string='filter[price][min]=10&filter[price][max]=99'
        )
        assert result.status_code == 200
        assert resource.captured.filter.price == PriceFilter(min=10.0, max=99.0)

        result = client.simulate_get('/bound', query_string='filter[price][min]=oops')
        assert result.status_code == 400
        assert (
            "filter[price][min]: could not convert 'oops'" in result.json['description']
        )


class TestConflicts:
    @pytest.mark.parametrize(
        'qs',
        [
            'q=x&page=1&page[size]=2',
            'q=x&page[size]=2&page=1',
            'q=x&filter=1&filter[min]=2',
        ],
    )
    def test_conflicting_shapes(self, client, qs):
        result = client.simulate_get('/bound', query_string=qs)
        assert result.status_code == 400
        assert 'conflicts with' in result.json['description']

    def test_malformed_names(self, client):
        for qs in ('q=x&page[=1', 'q=x&page]a[=1', 'q=x&[]=1'):
            result = client.simulate_get('/bound', query_string=qs)
            assert result.status_code == 400
            assert 'malformed parameter name' in result.json['description']


class TestConverter:
    def test_custom_converter_failure(self, client):
        result = client.simulate_get(
            '/bound', query_string='q=x&updated_since=not-a-date'
        )
        assert result.status_code == 400
        description = result.json['description']
        assert 'updated_since: could not convert' in description
        assert 'not-a-date' in description


class TestUnknownParams:
    def test_strict_by_default(self, client):
        result = client.simulate_get('/bound', query_string='q=x&bogus=1')
        assert result.status_code == 400
        assert result.json['title'] == 'Invalid query parameter'
        assert 'bogus: unknown parameter' in result.json['description']

    def test_ignore_mode(self, asgi, util):
        resource = CapturingResource(StrictQuery, strict=False)
        app = util.create_app(asgi)
        app.add_route('/bound', type('R', (), {'on_get': resource.make_responder()})())
        client = testing.TestClient(app)
        result = client.simulate_get('/bound', query_string='a=1&bogus=2')
        assert result.status_code == 200
        assert resource.captured == StrictQuery(a=1, b=None)


class TestLimits:
    def test_max_params(self, asgi, util):
        resource = CapturingResource(StrictQuery, strict=False, max_params=3)
        app = util.create_app(asgi)
        app.add_route('/bound', type('R', (), {'on_get': resource.make_responder()})())
        client = testing.TestClient(app)
        result = client.simulate_get('/bound', query_string='a=1&b=x&c=1&d=2')
        assert result.status_code == 400
        assert 'too many parameters' in result.json['description']

    def test_max_depth(self, asgi, util):
        resource = CapturingResource(SearchQuery, strict=False, max_depth=1)
        app = util.create_app(asgi)
        app.add_route('/bound', type('R', (), {'on_get': resource.make_responder()})())
        client = testing.TestClient(app)
        result = client.simulate_get('/bound', query_string='q=x&filter[min]=1')
        assert result.status_code == 400
        assert 'depth limit' in result.json['description']

    def test_max_errors_truncation(self, asgi, util):
        @dataclasses.dataclass
        class ManyInts:
            a: int = 0
            b: int = 0
            c: int = 0
            d: int = 0

        resource = CapturingResource(ManyInts, max_errors=2)
        app = util.create_app(asgi)
        app.add_route('/bound', type('R', (), {'on_get': resource.make_responder()})())
        client = testing.TestClient(app)
        result = client.simulate_get('/bound', query_string='a=x&b=x&c=x&d=x')
        assert result.status_code == 400
        description = result.json['description']
        assert description.count('could not convert') == 2
        assert 'further errors omitted' in description


class TestRequestParamsUntouched:
    def test_params_not_modified(self, client, resource):
        result = client.simulate_get('/bound', query_string='q=x&tags=&filter[min]=2')
        assert result.status_code == 200
        # NOTE: The request's own params use the default parsing options
        #   (bracketed keys kept verbatim, values left as strings), and
        #   must not be affected by binding.
        assert resource.captured_params == {
            'q': 'x',
            'tags': '',
            'filter[min]': '2',
        }


class TestErrorObject:
    def test_errors_attribute(self):
        errors = [falcon.QueryParamError(path='a', message='bad')]
        error = falcon.QueryBindingError(errors, truncated=True)
        assert error.errors == tuple(errors)
        assert error.status == falcon.HTTP_400
        assert 'a: bad' in error.description
        assert 'further errors omitted' in error.description

    def test_model_must_be_a_dataclass(self):
        with pytest.raises(TypeError):
            falcon.bind_query(dict)

    def test_missing_request_argument(self):
        @falcon.bind_query(StrictQuery)
        def responder(req, resp):
            pass

        with pytest.raises(TypeError):
            responder(object(), object())


class TestAsgi:
    @pytest.mark.parametrize(
        'qs,expected_tags',
        [
            ('a=1&b=x', []),
            ('a=1&b=x&extra=1', []),
        ],
    )
    def test_async_responder(self, util, qs, expected_tags):
        @dataclasses.dataclass
        class Model:
            a: int
            b: Optional[str] = None
            tags: list[str] = falcon.query_field(default_factory=list)

        captured = {}

        class Resource:
            @falcon.bind_query(Model, strict=False)
            async def on_get(self, req, resp, query):
                captured['query'] = query
                resp.media = {'ok': True}

        app = util.create_app(asgi=True)
        app.add_route('/bound', Resource())
        client = testing.TestClient(app)
        result = client.simulate_get('/bound', query_string=qs)
        assert result.status_code == 200
        assert captured['query'].tags == expected_tags

    def test_wsgi_and_asgi_agree(self, util):
        samples = [
            'q=hello&page=2&tags=a&tags=b&filter[min]=1.5',
            'q=hello&tags[]=',
            'q=hello&tags=',
            'q=hello',
        ]
        outcomes = {}
        for asgi in (False, True):
            resource = CapturingResource(SearchQuery)
            app = util.create_app(asgi)
            app.add_route(
                '/bound', type('R', (), {'on_get': resource.make_responder()})()
            )
            client = testing.TestClient(app)
            outcomes[asgi] = []
            for qs in samples:
                result = client.simulate_get('/bound', query_string=qs)
                outcomes[asgi].append(
                    (result.status_code, dataclasses.asdict(resource.captured))
                )
        assert outcomes[False] == outcomes[True]


class TestAnyType:
    def test_any_passes_through(self, asgi, util):
        @dataclasses.dataclass
        class Model:
            q: Any

        resource = CapturingResource(Model)
        app = util.create_app(asgi)
        app.add_route('/bound', type('R', (), {'on_get': resource.make_responder()})())
        client = testing.TestClient(app)
        result = client.simulate_get('/bound', query_string='q=whatever')
        assert result.status_code == 200
        assert resource.captured.q == 'whatever'


class TestEdgeCases:
    def test_bool_false(self, asgi, util):
        resource = CapturingResource(SearchQuery)
        app = util.create_app(asgi)
        app.add_route('/bound', type('R', (), {'on_get': resource.make_responder()})())
        client = testing.TestClient(app)
        result = client.simulate_get('/bound', query_string='q=x&verbose=off')
        assert result.status_code == 200
        assert resource.captured.verbose is False

    def test_optional_without_default(self, asgi, util):
        @dataclasses.dataclass
        class Model:
            a: int
            b: Optional[str]

        resource = CapturingResource(Model)
        app = util.create_app(asgi)
        app.add_route('/bound', type('R', (), {'on_get': resource.make_responder()})())
        client = testing.TestClient(app)
        result = client.simulate_get('/bound', query_string='a=1')
        assert result.status_code == 200
        assert resource.captured.b is None

        result = client.simulate_get('/bound', query_string='a=1&b=x')
        assert result.status_code == 200
        assert resource.captured.b == 'x'

    def test_list_element_conversion_failure(self, asgi, util):
        @dataclasses.dataclass
        class Model:
            nums: list[int] = falcon.query_field(default_factory=list)

        resource = CapturingResource(Model)
        app = util.create_app(asgi)
        app.add_route('/bound', type('R', (), {'on_get': resource.make_responder()})())
        client = testing.TestClient(app)
        result = client.simulate_get('/bound', query_string='nums=1&nums=oops')
        assert result.status_code == 400
        assert "nums: could not convert 'oops'" in result.json['description']

    def test_non_optional_union_is_unsupported(self, asgi, util):
        @dataclasses.dataclass
        class Model:
            v: Union[int, str]

        resource = CapturingResource(Model)
        app = util.create_app(asgi)
        app.add_route('/bound', type('R', (), {'on_get': resource.make_responder()})())
        client = testing.TestClient(app)
        result = client.simulate_get('/bound', query_string='v=1')
        assert result.status_code == 400
        assert 'v: could not convert' in result.json['description']

    def test_model_from_dynamically_loaded_module(self, asgi, util):
        # NOTE: Simulate a model whose module cannot be found in
        #   sys.modules (e.g. loaded dynamically by a plugin system).
        Model = dataclasses.make_dataclass('Model', [('a', int)])
        Model.__module__ = 'no_such_module_4a3f9c2e'

        resource = CapturingResource(Model)
        app = util.create_app(asgi)
        app.add_route('/bound', type('R', (), {'on_get': resource.make_responder()})())
        client = testing.TestClient(app)
        result = client.simulate_get('/bound', query_string='a=42')
        assert result.status_code == 200
        assert resource.captured.a == 42

    def test_bare_list_annotation(self, asgi, util):
        @dataclasses.dataclass
        class Model:
            tags: list = falcon.query_field(default_factory=list)

        resource = CapturingResource(Model)
        app = util.create_app(asgi)
        app.add_route('/bound', type('R', (), {'on_get': resource.make_responder()})())
        client = testing.TestClient(app)
        result = client.simulate_get('/bound', query_string='tags=a&tags=b')
        assert result.status_code == 200
        assert resource.captured.tags == ['a', 'b']
