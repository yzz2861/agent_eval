import pytest

import falcon
from falcon import media
from falcon import testing


class CountingHandler(media.BaseHandler):
    """Media handler that counts (de)serialization invocations."""

    def __init__(self, serialized):
        self._serialized = serialized
        self.serialize_count = 0
        self.deserialize_count = 0

    def serialize(self, media, content_type):
        self.serialize_count += 1
        return self._serialized

    def deserialize(self, stream, content_type, content_length):
        self.deserialize_count += 1
        return None


class ResponderLevelResource:
    @falcon.produces('application/json', 'application/msgpack')
    def on_get(self, req, resp):
        resp.media = {'example': True}


@falcon.produces('application/json', 'application/msgpack')
class ResourceLevelResource:
    def on_get(self, req, resp):
        resp.media = {'example': True}


@falcon.produces('application/json')
class MixedLevelResource:
    @falcon.produces('application/msgpack')
    def on_get(self, req, resp):
        resp.media = {'example': True}

    def on_post(self, req, resp):
        resp.media = {'example': True}


class ExplicitContentTypeResource:
    @falcon.produces('application/json', 'application/msgpack')
    def on_get(self, req, resp):
        resp.content_type = 'application/msgpack'
        resp.media = {'example': True}


class VaryResource:
    @falcon.produces('application/json', 'application/msgpack')
    def on_get(self, req, resp):
        resp.set_header('Vary', req.get_header('X-Vary', required=True))
        resp.media = {'example': True}


class TextResource:
    @falcon.produces('application/json', 'application/msgpack')
    def on_get(self, req, resp):
        resp.text = 'Hello, world!'


class PlainResource:
    def on_get(self, req, resp):
        resp.media = {'example': True}


class MediaSettingMiddleware:
    def process_response(self, req, resp, resource, req_succeeded):
        resp.media = {'middleware': True}


@pytest.fixture()
def json_handler():
    return CountingHandler(b'json')


@pytest.fixture()
def msgpack_handler():
    return CountingHandler(b'msgpack')


@pytest.fixture()
def app(asgi, util, json_handler, msgpack_handler):
    app = util.create_app(asgi)
    app.resp_options.media_handlers['application/json'] = json_handler
    app.resp_options.media_handlers['application/msgpack'] = msgpack_handler
    return app


@pytest.fixture()
def client(app):
    app.add_route('/responder', ResponderLevelResource())
    app.add_route('/resource', ResourceLevelResource())
    app.add_route('/mixed', MixedLevelResource())
    app.add_route('/explicit', ExplicitContentTypeResource())
    app.add_route('/vary', VaryResource())
    app.add_route('/text', TextResource())
    app.add_route('/plain', PlainResource())
    return testing.TestClient(app)


class TestProducesValidation:
    def test_no_media_types(self):
        with pytest.raises(ValueError):
            falcon.produces()

    @pytest.mark.parametrize(
        'media_type',
        ['', '   ', None, 123, b'application/json'],
    )
    def test_invalid_media_type(self, media_type):
        with pytest.raises(ValueError):
            falcon.produces(media_type)


class TestNegotiation:
    @pytest.mark.parametrize(
        'accept, expected_type, expected_body',
        [
            ('application/json', 'application/json', b'json'),
            ('application/msgpack', 'application/msgpack', b'msgpack'),
            (
                'application/json;q=0.1, application/msgpack;q=0.9',
                'application/msgpack',
                b'msgpack',
            ),
            (
                'application/msgpack;q=0.2, application/json;q=0.8',
                'application/json',
                b'json',
            ),
            ('application/*', 'application/json', b'json'),
            ('*/*', 'application/json', b'json'),
            ('application/json, application/msgpack', 'application/json', b'json'),
        ],
    )
    def test_accept_selection(self, client, accept, expected_type, expected_body):
        res = client.simulate_get('/responder', headers={'Accept': accept})

        assert res.status_code == 200
        assert res.headers['Content-Type'] == expected_type
        assert res.content == expected_body
        assert res.headers['Vary'] == 'Accept'

    def test_missing_accept_header(self, client):
        res = client.simulate_get('/responder')

        assert res.status_code == 200
        assert res.headers['Content-Type'] == 'application/json'
        assert res.headers['Vary'] == 'Accept'

    @pytest.mark.parametrize(
        'accept',
        [
            'application/json;q=0, application/*;q=0.5',
            'application/json;q=0, */*;q=0.5',
        ],
    )
    def test_q_zero_excludes(self, client, accept):
        res = client.simulate_get('/responder', headers={'Accept': accept})

        assert res.status_code == 200
        assert res.headers['Content-Type'] == 'application/msgpack'
        assert res.content == b'msgpack'

    def test_tie_follows_declaration_order(self, app, client):
        class ReversedResource:
            @falcon.produces('application/msgpack', 'application/json')
            def on_get(self, req, resp):
                resp.media = {'example': True}

        app.add_route('/reversed', ReversedResource())
        res = client.simulate_get(
            '/reversed', headers={'Accept': 'application/json, application/msgpack'}
        )

        assert res.status_code == 200
        assert res.headers['Content-Type'] == 'application/msgpack'

    def test_media_type_params(self, app, util, asgi):
        versioned_handler = CountingHandler(b'versioned')
        app.resp_options.media_handlers['application/json; version=2'] = (
            versioned_handler
        )

        class VersionedResource:
            @falcon.produces('application/json', 'application/json; version=2')
            def on_get(self, req, resp):
                resp.media = {'example': True}

        app.add_route('/versioned', VersionedResource())
        client = testing.TestClient(app)

        res = client.simulate_get(
            '/versioned',
            headers={
                'Accept': 'application/json; version=2;q=0.9, application/json;q=0.5'
            },
        )
        assert res.status_code == 200
        assert res.headers['Content-Type'] == 'application/json; version=2'
        assert res.content == b'versioned'

        res = client.simulate_get(
            '/versioned',
            headers={
                'Accept': 'application/json; version=2;q=0.5, application/json;q=0.9'
            },
        )
        assert res.status_code == 200
        assert res.headers['Content-Type'] == 'application/json'
        assert res.content == b'json'

    def test_resource_level_declaration(self, client):
        res = client.simulate_get(
            '/resource', headers={'Accept': 'application/msgpack'}
        )

        assert res.status_code == 200
        assert res.headers['Content-Type'] == 'application/msgpack'
        assert res.content == b'msgpack'

    def test_responder_level_overrides_resource_level(self, client):
        res = client.simulate_get('/mixed', headers={'Accept': 'application/json'})
        assert res.status_code == 406

        res = client.simulate_get('/mixed', headers={'Accept': 'application/msgpack'})
        assert res.status_code == 200
        assert res.headers['Content-Type'] == 'application/msgpack'

        res = client.simulate_post('/mixed', headers={'Accept': 'application/json'})
        assert res.status_code == 200
        assert res.headers['Content-Type'] == 'application/json'

    def test_only_selected_handler_serializes(
        self, client, json_handler, msgpack_handler
    ):
        res = client.simulate_get('/responder', headers={'Accept': 'application/json'})

        assert res.status_code == 200
        assert json_handler.serialize_count == 1
        assert msgpack_handler.serialize_count == 0

    def test_unregistered_declared_type_is_skipped(self, app):
        class YAMLResource:
            @falcon.produces('application/yaml', 'application/json')
            def on_get(self, req, resp):
                resp.media = {'example': True}

        app.add_route('/yaml', YAMLResource())
        client = testing.TestClient(app)

        res = client.simulate_get('/yaml', headers={'Accept': 'application/yaml'})
        assert res.status_code == 406

        res = client.simulate_get(
            '/yaml', headers={'Accept': 'application/yaml, application/json;q=0.5'}
        )
        assert res.status_code == 200
        assert res.headers['Content-Type'] == 'application/json'

    def test_explicit_content_type_takes_precedence(
        self, client, json_handler, msgpack_handler
    ):
        res = client.simulate_get('/explicit', headers={'Accept': 'application/json'})

        assert res.status_code == 200
        assert res.headers['Content-Type'] == 'application/msgpack'
        assert res.content == b'msgpack'
        assert 'Vary' not in res.headers
        assert msgpack_handler.serialize_count == 1
        assert json_handler.serialize_count == 0

    def test_vary_is_merged(self, client):
        res = client.simulate_get(
            '/vary',
            headers={'Accept': 'application/json', 'X-Vary': 'Authorization'},
        )

        assert res.status_code == 200
        assert res.headers['Vary'] == 'Authorization, Accept'

    def test_vary_is_not_duplicated(self, client):
        res = client.simulate_get(
            '/vary',
            headers={'Accept': 'application/json', 'X-Vary': 'Accept'},
        )

        assert res.status_code == 200
        assert res.headers['Vary'] == 'Accept'

    def test_no_media_no_negotiation(self, client):
        res = client.simulate_get('/text', headers={'Accept': 'application/msgpack'})

        assert res.status_code == 200
        assert 'Vary' not in res.headers

    def test_no_produces_declaration_no_negotiation(self, client):
        res = client.simulate_get('/plain', headers={'Accept': 'application/xml'})

        assert res.status_code == 200
        assert 'Vary' not in res.headers

    def test_middleware_can_still_set_media(self, asgi, util, msgpack_handler):
        app = util.create_app(asgi, middleware=[MediaSettingMiddleware()])
        app.resp_options.media_handlers['application/msgpack'] = msgpack_handler
        app.add_route('/mw', ResourceLevelResource())
        client = testing.TestClient(app)

        res = client.simulate_get('/mw', headers={'Accept': 'application/msgpack'})

        assert res.status_code == 200
        assert res.headers['Content-Type'] == 'application/msgpack'

    def test_malformed_accept_header(self, client):
        res = client.simulate_get(
            '/responder', headers={'Accept': 'application/json; q=notanumber'}
        )

        assert res.status_code == 406

    def test_unknown_route_is_unaffected(self, client):
        res = client.simulate_get('/does-not-exist')

        assert res.status_code == 404


class TestNotAcceptable:
    def test_no_acceptable_representation(self, client, json_handler, msgpack_handler):
        res = client.simulate_get('/responder', headers={'Accept': 'image/png'})

        assert res.status_code == 406
        assert res.headers['Vary'] == 'Accept'
        # NOTE: The error itself cannot be represented in a type the
        #   client accepts either, so it is sent without a body rather
        #   than silently falling back to a JSON representation.
        assert res.content == b''
        assert json_handler.serialize_count == 0
        assert msgpack_handler.serialize_count == 0

    def test_error_serialization_is_not_renegotiated(self, client):
        # NOTE: The 406 error response itself is exempt from produces
        #   negotiation; the default error serializer may still represent
        #   it in a type outside the produces declaration (here, XML).
        res = client.simulate_get('/responder', headers={'Accept': 'application/xml'})

        assert res.status_code == 406
        assert res.headers['Content-Type'] == 'application/xml'
        assert res.content

    def test_error_is_serialized_when_acceptable(self, app, json_handler):
        class MsgpackOnlyResource:
            @falcon.produces('application/msgpack')
            def on_get(self, req, resp):
                resp.media = {'example': True}

        app.add_route('/msgpack-only', MsgpackOnlyResource())
        client = testing.TestClient(app)

        res = client.simulate_get(
            '/msgpack-only',
            headers={'Accept': 'application/msgpack;q=0, application/json;q=0.5'},
        )

        assert res.status_code == 406
        assert res.headers['Content-Type'] == 'application/json'
        assert res.content == b'json'
        assert json_handler.serialize_count == 1
