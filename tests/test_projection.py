import copy

import pytest

import falcon
from falcon.projection import FieldProjection
import falcon.testing as testing

TREE = {
    'name': True,
    'active': True,
    'orders': {
        'id': True,
        'total': True,
    },
    'meta': {
        'tags': True,
        'audit': {
            'created_by': True,
        },
    },
}

DOC = {
    'name': 'thing',
    'active': True,
    'secret': 'classified',
    'orders': [
        {'id': 1, 'total': 9.5, 'internal': 'x'},
        {'id': 2, 'total': 3.0, 'internal': 'y'},
    ],
    'meta': {
        'tags': ['a', 'b'],
        'note': 'internal',
        'audit': {'created_by': 'alice', 'token': 'hidden'},
    },
}


@pytest.fixture
def projection():
    return FieldProjection(TREE)


@pytest.fixture
def doc():
    return copy.deepcopy(DOC)


class TestInit:
    def test_fields_must_be_a_mapping(self):
        with pytest.raises(TypeError):
            FieldProjection(['name'])

    def test_field_names_must_be_strings(self):
        with pytest.raises(TypeError):
            FieldProjection({1: True})

    def test_max_depth_must_be_positive(self):
        with pytest.raises(ValueError):
            FieldProjection(TREE, max_depth=0)

    def test_empty_mapping_marks_a_leaf(self):
        projection = FieldProjection({'empty': {}})
        assert projection.parse('empty') == {'empty': None}

    def test_properties(self):
        projection = FieldProjection(TREE, max_depth=4, param='only')
        assert projection.max_depth == 4
        assert projection.param == 'only'


class TestParse:
    def test_simple(self, projection):
        assert projection.parse('name') == {'name': None}

    def test_nested(self, projection):
        selection = projection.parse('name,orders(id,total)')
        assert selection == {'name': None, 'orders': {'id': None, 'total': None}}

    def test_bare_parent_expands_to_allowed_children(self, projection):
        assert projection.parse('orders') == {'orders': {'id': None, 'total': None}}

    def test_bare_parent_expands_recursively(self, projection):
        assert projection.parse('meta') == {
            'meta': {'tags': None, 'audit': {'created_by': None}}
        }

    def test_duplicate_selections_merge(self, projection):
        selection = projection.parse('orders(id),name,orders(total)')
        assert selection == {'orders': {'id': None, 'total': None}, 'name': None}

    def test_duplicate_leaf_selection_merges(self, projection):
        assert projection.parse('name,name') == {'name': None}

    def test_whitespace_is_tolerated(self, projection):
        selection = projection.parse('  name ,\torders( id ) ')
        assert selection == {'name': None, 'orders': {'id': None}}

    @pytest.mark.parametrize(
        'expression,description',
        [
            ('nope', "Unknown field: 'nope'."),
            ('orders(nope)', "Unknown field: 'orders.nope'."),
            ('meta(audit(token))', "Unknown field: 'meta.audit.token'."),
        ],
    )
    def test_unknown_field(self, projection, expression, description):
        with pytest.raises(falcon.HTTPBadRequest) as excinfo:
            projection.parse(expression)

        assert excinfo.value.description == description

    def test_subselection_on_leaf(self, projection):
        with pytest.raises(falcon.HTTPBadRequest) as excinfo:
            projection.parse('name(first)')

        assert excinfo.value.description == (
            "Field 'name' does not support a sub-selection."
        )

    @pytest.mark.parametrize(
        'expression,description',
        [
            ('orders,orders(id)', "Conflicting selections for field: 'orders'."),
            ('orders(id),orders', "Conflicting selections for field: 'orders'."),
            (
                'meta(audit),meta(audit(created_by))',
                "Conflicting selections for field: 'meta.audit'.",
            ),
        ],
    )
    def test_conflicting_selections(self, projection, expression, description):
        with pytest.raises(falcon.HTTPBadRequest) as excinfo:
            projection.parse(expression)

        assert excinfo.value.description == description

    def test_max_depth(self):
        projection = FieldProjection(TREE, max_depth=2)
        projection.parse('meta(audit)')

        with pytest.raises(falcon.HTTPBadRequest) as excinfo:
            projection.parse('meta(audit(created_by))')

        assert 'maximum nesting depth of 2' in excinfo.value.description

    def test_max_depth_one_allows_top_level_only(self):
        projection = FieldProjection(TREE, max_depth=1)
        projection.parse('name,orders')

        with pytest.raises(falcon.HTTPBadRequest):
            projection.parse('orders(id)')

    @pytest.mark.parametrize(
        'expression',
        [
            '',
            ' ',
            '()',
            '(name)',
            'name(',
            'name(id',
            'name)',
            'name()',
            'name,,orders',
            'name,',
            ',name',
            '9lives',
            'name;orders',
        ],
    )
    def test_malformed_expression(self, projection, expression):
        with pytest.raises(falcon.HTTPBadRequest) as excinfo:
            projection.parse(expression)

        assert excinfo.value.title == 'Invalid fields expression'

    def test_expression_must_be_a_string(self, projection):
        with pytest.raises(TypeError):
            projection.parse(None)


class TestProject:
    def test_leaf(self, projection, doc):
        result = projection.project(doc, projection.parse('name,active'))
        assert result == {'name': 'thing', 'active': True}

    def test_nested_objects(self, projection, doc):
        result = projection.project(doc, projection.parse('meta(audit)'))
        assert result == {'meta': {'audit': {'created_by': 'alice'}}}

    def test_list_of_objects(self, projection, doc):
        result = projection.project(doc, projection.parse('orders(id)'))
        assert result == {'orders': [{'id': 1}, {'id': 2}]}

    def test_tuple_of_objects(self, projection):
        data = {'orders': ({'id': 1, 'total': 9.5}, {'id': 2, 'total': 3.0})}
        result = projection.project(data, projection.parse('orders(total)'))
        assert result == {'orders': [{'total': 9.5}, {'total': 3.0}]}

    def test_missing_fields_are_skipped(self, projection):
        result = projection.project({'name': 'thing'}, projection.parse('name,orders'))
        assert result == {'name': 'thing'}

    def test_scalar_data_passes_through(self, projection):
        selection = projection.parse('name')
        assert projection.project(42, selection) == 42
        assert projection.project('thing', selection) == 'thing'

    def test_none_selection_returns_data_as_is(self, projection, doc):
        assert projection.project(doc, None) is doc

    def test_leaf_value_is_returned_as_is(self, projection, doc):
        result = projection.project(doc, {'meta': None})
        assert result['meta'] is doc['meta']

    def test_does_not_mutate_source(self, projection, doc):
        result = projection.project(doc, projection.parse('name,orders(id),meta'))

        assert result is not doc
        assert result['orders'] is not doc['orders']
        assert result['meta'] is not doc['meta']
        assert doc == DOC

    def test_shared_object_supports_consecutive_projections(self, projection, doc):
        first = projection.project(doc, projection.parse('name'))
        second = projection.project(doc, projection.parse('orders(total)'))

        assert first == {'name': 'thing'}
        assert second == {'orders': [{'total': 9.5}, {'total': 3.0}]}
        assert doc == DOC

    def test_select_combines_parse_and_project(self, projection, doc):
        result = projection.select('orders(id)', doc)
        assert result == {'orders': [{'id': 1}, {'id': 2}]}
        assert doc == DOC


class TestParseRequest:
    def test_missing_param(self, projection):
        req = testing.create_req()
        assert projection.parse_request(req) is None

    @pytest.mark.parametrize('query_string', ['fields=', 'fields=%20'])
    def test_empty_param(self, projection, query_string):
        req = testing.create_req(query_string=query_string)
        assert projection.parse_request(req) is None

    def test_valid_expression(self, projection):
        req = testing.create_req(query_string='fields=name,orders(id)')
        assert projection.parse_request(req) == {
            'name': None,
            'orders': {'id': None},
        }

    def test_custom_param_from_init(self):
        projection = FieldProjection(TREE, param='only')
        req = testing.create_req(query_string='only=name')
        assert projection.parse_request(req) == {'name': None}

    def test_custom_param_override(self, projection):
        req = testing.create_req(query_string='only=name')
        assert projection.parse_request(req, param='only') == {'name': None}

    def test_invalid_expression(self, projection):
        req = testing.create_req(query_string='fields=nope')
        with pytest.raises(falcon.HTTPBadRequest):
            projection.parse_request(req)


def _make_resource(projection, doc, asgi, calls):
    if asgi:

        class AsyncResource:
            @projection
            async def on_get(self, req, resp):
                calls.append('called')
                resp.media = doc

        return AsyncResource()

    class SyncResource:
        @projection
        def on_get(self, req, resp):
            calls.append('called')
            resp.media = doc

    return SyncResource()


@pytest.fixture
def client(asgi, util, projection, doc):
    app = util.create_app(asgi)
    app.add_route('/doc', _make_resource(projection, doc, asgi, []))
    return testing.TestClient(app)


class TestDecoratedResponder:
    def test_projects_media(self, client, doc):
        resp = client.simulate_get('/doc', params={'fields': 'name,orders(id)'})

        assert resp.status == falcon.HTTP_200
        assert resp.json == {'name': 'thing', 'orders': [{'id': 1}, {'id': 2}]}
        assert resp.headers['Content-Length'] == str(len(resp.content))
        assert doc == DOC

    def test_no_fields_param_returns_everything(self, client, doc):
        resp = client.simulate_get('/doc')

        assert resp.status == falcon.HTTP_200
        assert resp.json == DOC
        assert resp.headers['Content-Length'] == str(len(resp.content))

    def test_empty_fields_param_returns_everything(self, client, doc):
        resp = client.simulate_get('/doc', params={'fields': ''})

        assert resp.status == falcon.HTTP_200
        assert resp.json == DOC

    def test_shared_object_consecutive_projections(self, client, doc):
        first = client.simulate_get('/doc', params={'fields': 'name'})
        second = client.simulate_get(
            '/doc', params={'fields': 'orders(total),meta(audit)'}
        )
        third = client.simulate_get('/doc')

        assert first.json == {'name': 'thing'}
        assert second.json == {
            'orders': [{'total': 9.5}, {'total': 3.0}],
            'meta': {'audit': {'created_by': 'alice'}},
        }
        assert third.json == DOC
        assert doc == DOC

    @pytest.mark.parametrize(
        'expression,fragment',
        [
            ('secret', "Unknown field: 'secret'."),
            ('orders(internal)', "Unknown field: 'orders.internal'."),
            ('orders,orders(id)', "Conflicting selections for field: 'orders'."),
            ('name(', 'Expected a field name'),
        ],
    )
    def test_invalid_expression_rejected_before_business_logic(
        self, asgi, util, projection, doc, expression, fragment
    ):
        calls = []
        app = util.create_app(asgi)
        app.add_route('/doc', _make_resource(projection, doc, asgi, calls))
        client = testing.TestClient(app)

        resp = client.simulate_get('/doc', params={'fields': expression})

        assert resp.status == falcon.HTTP_400
        assert resp.json['title'] == 'Invalid fields expression'
        assert fragment in resp.json['description']
        assert calls == []
        assert doc == DOC

    def test_too_deep_expression_rejected(self, asgi, util, doc):
        projection = FieldProjection(TREE, max_depth=2)
        calls = []
        app = util.create_app(asgi)
        app.add_route('/doc', _make_resource(projection, doc, asgi, calls))
        client = testing.TestClient(app)

        resp = client.simulate_get('/doc', params={'fields': 'meta(audit(created_by))'})

        assert resp.status == falcon.HTTP_400
        assert 'maximum nesting depth of 2' in resp.json['description']
        assert calls == []

    def test_no_media(self, asgi, util, projection):
        calls = []

        if asgi:

            class AsyncEmptyResource:
                @projection
                async def on_get(self, req, resp):
                    calls.append('called')

            resource = AsyncEmptyResource()
        else:

            class SyncEmptyResource:
                @projection
                def on_get(self, req, resp):
                    calls.append('called')

            resource = SyncEmptyResource()

        app = util.create_app(asgi)
        app.add_route('/empty', resource)
        client = testing.TestClient(app)

        resp = client.simulate_get('/empty', params={'fields': 'name'})

        assert resp.status == falcon.HTTP_200
        assert resp.content == b''
        assert calls == ['called']

    def test_manual_parse_and_project(self, asgi, util, projection, doc):
        class ManualResource:
            def on_get(self, req, resp):
                selection = projection.parse_request(req)
                if selection is not None:
                    resp.media = projection.project(doc, selection)
                else:
                    resp.media = doc

        app = util.create_app(asgi)
        app.add_route('/doc', ManualResource())
        client = testing.TestClient(app)

        resp = client.simulate_get('/doc', params={'fields': 'orders(id)'})
        assert resp.json == {'orders': [{'id': 1}, {'id': 2}]}
        assert resp.headers['Content-Length'] == str(len(resp.content))

        resp = client.simulate_get('/doc')
        assert resp.json == DOC
        assert doc == DOC
