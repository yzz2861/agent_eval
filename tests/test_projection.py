import copy
import json

import pytest

import falcon
from falcon import testing
import falcon.asgi
from falcon.util.projection import FieldSelector

FIELDS = {
    'name': None,
    'customer': {'name': None},
    'orders': {'id': None, 'total': None},
    'meta': {'created': None, 'audit': {'by': None}},
}

SHARED_DOCUMENT = {
    'name': 'falcon',
    'internal_notes': 'do not expose',
    'customer': {'name': 'Kumar', 'loyalty': 42},
    'orders': [
        {'id': 1, 'total': 10, 'pin': '0000'},
        {'id': 2, 'total': 20, 'pin': '1111'},
    ],
    'meta': {'created': '2026-09-29', 'audit': {'by': 'system', 'at': 'now'}},
}


@pytest.fixture
def selector():
    return FieldSelector(FIELDS)


class TestParse:
    def test_none_expression(self, selector):
        assert selector.parse(None) is None

    @pytest.mark.parametrize('expression', ['', '   ', '\t'])
    def test_blank_expression(self, selector, expression):
        assert selector.parse(expression) is None

    def test_single_field(self, selector):
        assert selector.parse('name') == {'name': None}

    def test_multiple_fields(self, selector):
        assert selector.parse('name,customer(name)') == {
            'name': None,
            'customer': {'name': None},
        }

    def test_bare_parent_selects_all_allowed_descendants(self, selector):
        assert selector.parse('meta') == {
            'meta': {'created': None, 'audit': {'by': None}},
        }

    def test_whitespace_is_ignored(self, selector):
        assert selector.parse(' name , orders ( id , total ) ') == {
            'name': None,
            'orders': {'id': None, 'total': None},
        }

    @pytest.mark.parametrize(
        'expression',
        ['name,name', 'orders,orders', 'orders(id),orders(id)'],
    )
    def test_duplicate_selections_merge(self, selector, expression):
        tree = selector.parse(expression)
        assert tree == selector.parse(expression.split(',')[0])

    def test_duplicate_nested_selections_merge(self, selector):
        assert selector.parse('orders(id),orders(total)') == {
            'orders': {'id': None, 'total': None},
        }

    @pytest.mark.parametrize(
        'expression',
        [
            'unknown',
            'orders(unknown)',
            'customer(name,unknown)',
        ],
    )
    def test_unknown_field(self, selector, expression):
        with pytest.raises(falcon.HTTPInvalidParam) as excinfo:
            selector.parse(expression)

        assert 'unknown field' in excinfo.value.description
        assert 'unknown' in excinfo.value.description

    def test_nested_selection_of_leaf_field(self, selector):
        with pytest.raises(falcon.HTTPInvalidParam) as excinfo:
            selector.parse('name(first)')

        assert 'does not support nested selection' in excinfo.value.description

    @pytest.mark.parametrize(
        'expression',
        [
            'orders,orders(id)',
            'orders(id),orders',
            'meta(audit),meta(audit(by))',
        ],
    )
    def test_conflicting_selections(self, selector, expression):
        with pytest.raises(falcon.HTTPInvalidParam) as excinfo:
            selector.parse(expression)

        assert 'conflicting selections' in excinfo.value.description

    def test_expression_too_deep(self):
        selector = FieldSelector(FIELDS, max_depth=2)

        with pytest.raises(falcon.HTTPInvalidParam) as excinfo:
            selector.parse('meta(audit(by))')

        assert 'maximum nesting depth' in excinfo.value.description

    @pytest.mark.parametrize(
        'expression',
        [
            'name,',
            ',name',
            'name,,orders',
            '()',
            'orders()',
            'orders(id',
            'orders(id x)',
            'name)',
            'name other',
        ],
    )
    def test_malformed_expression(self, selector, expression):
        with pytest.raises(falcon.HTTPInvalidParam):
            selector.parse(expression)

    def test_error_mentions_param_name(self):
        selector = FieldSelector(FIELDS, param_name='only')

        with pytest.raises(falcon.HTTPInvalidParam) as excinfo:
            selector.parse('unknown')

        assert excinfo.value.description.startswith('The "only" parameter')


class TestProject:
    def test_none_selection_returns_data_unchanged(self, selector):
        document = copy.deepcopy(SHARED_DOCUMENT)

        assert selector.project(document, None) is document

    def test_unselected_and_unknown_keys_are_dropped(self, selector):
        document = copy.deepcopy(SHARED_DOCUMENT)
        selection = selector.parse('name,customer(name)')

        projected = selector.project(document, selection)

        assert projected == {'name': 'falcon', 'customer': {'name': 'Kumar'}}

    def test_missing_keys_are_skipped(self, selector):
        selection = selector.parse('name,orders(id)')

        assert selector.project({'name': 'falcon'}, selection) == {
            'name': 'falcon',
        }

    def test_object_arrays_use_the_same_subtree(self, selector):
        document = copy.deepcopy(SHARED_DOCUMENT)
        selection = selector.parse('orders(id)')

        projected = selector.project(document, selection)

        assert projected == {'orders': [{'id': 1}, {'id': 2}]}

    def test_tuples_are_projected_as_lists(self, selector):
        selection = selector.parse('orders(id)')
        document = {'orders': ({'id': 1, 'total': 10},)}

        assert selector.project(document, selection) == {'orders': [{'id': 1}]}

    def test_scalar_value_with_subtree_is_returned_as_is(self, selector):
        selection = selector.parse('orders(id)')

        assert selector.project({'orders': 'n/a'}, selection) == {
            'orders': 'n/a',
        }

    def test_none_value_with_subtree_is_preserved(self, selector):
        selection = selector.parse('customer(name)')

        assert selector.project({'customer': None}, selection) == {
            'customer': None,
        }

    def test_projection_does_not_mutate_source(self, selector):
        document = copy.deepcopy(SHARED_DOCUMENT)
        original = copy.deepcopy(document)
        selection = selector.parse('name,orders(id)')

        projected = selector.project(document, selection)

        assert document == original
        assert projected is not document
        assert projected['orders'] is not document['orders']
        assert projected['orders'][0] is not document['orders'][0]

    def test_repeated_projections_of_shared_object(self, selector):
        document = copy.deepcopy(SHARED_DOCUMENT)

        first = selector.project(document, selector.parse('name'))
        second = selector.project(document, selector.parse('orders(total)'))

        assert first == {'name': 'falcon'}
        assert second == {'orders': [{'total': 10}, {'total': 20}]}
        assert document == SHARED_DOCUMENT


class TestFieldSelectorInit:
    def test_fields_must_be_a_mapping(self):
        with pytest.raises(TypeError):
            FieldSelector(['name'])

    def test_field_spec_must_be_none_or_mapping(self):
        with pytest.raises(ValueError):
            FieldSelector({'name': 'leaf'})


class ProjectedResource:
    def __init__(self, document):
        self._document = document
        self._selector = FieldSelector(FIELDS)
        self.business_calls = 0

    def on_get(self, req, resp):
        selection = self._selector.parse(req.get_param('fields'))

        self.business_calls += 1
        resp.media = self._selector.project(self._document, selection)


@pytest.fixture(
    params=[falcon.App, falcon.asgi.App],
    ids=['wsgi', 'asgi'],
)
def client(request):
    app = request.param()
    resource = ProjectedResource(SHARED_DOCUMENT)
    app.add_route('/document', resource)

    client = testing.TestClient(app)
    client.resource = resource
    return client


class TestProjectionIntegration:
    def test_no_projection_returns_full_document(self, client):
        resp = client.simulate_get('/document')

        assert resp.status == falcon.HTTP_OK
        assert resp.json == SHARED_DOCUMENT
        assert resp.headers['Content-Length'] == str(len(resp.content))

    def test_projection_is_applied(self, client):
        resp = client.simulate_get(
            '/document', params={'fields': 'name,customer(name)'}
        )

        assert resp.status == falcon.HTTP_OK
        assert resp.json == {'name': 'falcon', 'customer': {'name': 'Kumar'}}
        assert resp.headers['Content-Length'] == str(len(resp.content))

    def test_bare_parent_does_not_expose_undeclared_children(self, client):
        resp = client.simulate_get('/document', params={'fields': 'orders'})

        assert resp.status == falcon.HTTP_OK
        assert resp.json == {
            'orders': [
                {'id': 1, 'total': 10},
                {'id': 2, 'total': 20},
            ]
        }

    def test_shared_document_survives_different_projections(self, client):
        first = client.simulate_get('/document', params={'fields': 'name'})
        second = client.simulate_get(
            '/document', params={'fields': 'orders(total),meta(created)'}
        )

        assert first.json == {'name': 'falcon'}
        assert second.json == {
            'orders': [{'total': 10}, {'total': 20}],
            'meta': {'created': '2026-09-29'},
        }
        assert SHARED_DOCUMENT['orders'][0] == {
            'id': 1,
            'total': 10,
            'pin': '0000',
        }
        assert SHARED_DOCUMENT == {
            'name': 'falcon',
            'internal_notes': 'do not expose',
            'customer': {'name': 'Kumar', 'loyalty': 42},
            'orders': [
                {'id': 1, 'total': 10, 'pin': '0000'},
                {'id': 2, 'total': 20, 'pin': '1111'},
            ],
            'meta': {
                'created': '2026-09-29',
                'audit': {'by': 'system', 'at': 'now'},
            },
        }

    @pytest.mark.parametrize(
        'expression',
        ['unknown', 'orders,orders(id)', 'meta(audit(by)))'],
    )
    def test_invalid_expression_fails_before_business_logic(self, client, expression):
        resp = client.simulate_get('/document', params={'fields': expression})

        assert resp.status == falcon.HTTP_BAD_REQUEST
        assert 'Invalid fields expression' in resp.json['description']
        assert client.resource.business_calls == 0

    def test_content_length_matches_projected_body(self, client):
        resp = client.simulate_get('/document', params={'fields': 'name'})

        body = json.dumps({'name': 'falcon'}).encode()
        assert resp.content == body
        assert resp.headers['Content-Length'] == str(len(body))
