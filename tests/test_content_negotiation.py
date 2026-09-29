import json

import pytest

import falcon
from falcon import media
from falcon import testing


@pytest.fixture(scope='session')
def msgpack():
    return pytest.importorskip('msgpack')


@pytest.fixture
def unpack(msgpack):
    return lambda data: msgpack.unpackb(data, raw=False)


class CountingJSONHandler(media.JSONHandler):
    def __init__(self):
        super().__init__()
        self.serialize_count = 0

    def serialize(self, media, content_type):
        self.serialize_count += 1
        return super().serialize(media, content_type)


class CountingMessagePackHandler(media.MessagePackHandler):
    def __init__(self):
        super().__init__()
        self.serialize_count = 0

    def serialize(self, media, content_type):
        self.serialize_count += 1
        return super().serialize(media, content_type)

    async def serialize_async(self, media, content_type):
        self.serialize_count += 1
        return await super().serialize_async(media, content_type)


class MultiMediaResource:
    produces = ('application/json', 'application/msgpack')

    def on_get(self, req, resp):
        resp.media = {'message': 'Hello, World!'}


def create_client(resource, handlers=None):
    app = falcon.App()
    app.add_route('/', resource)

    if handlers:
        app.resp_options.media_handlers.update(handlers)

    return testing.TestClient(app)


@pytest.fixture
def client():
    return create_client(MultiMediaResource(), {
        'application/msgpack': media.MessagePackHandler(),
    })


@pytest.mark.parametrize(
    'accept, expected',
    [
        ('application/msgpack', 'application/msgpack'),
        ('application/json', 'application/json'),
        # Ties are broken by the declaration order.
        ('*/*', 'application/json'),
        ('application/*', 'application/json'),
        ('application/json, application/msgpack', 'application/json'),
        # Quality factors take precedence over the declaration order.
        (
            'application/json;q=0.4, application/msgpack;q=0.9',
            'application/msgpack',
        ),
        # A type excluded with q=0 is never selected.
        ('application/json;q=0, application/msgpack', 'application/msgpack'),
    ],
)
def test_negotiates_media_type(client, accept, expected):
    resp = client.simulate_get('/', headers={'Accept': accept})

    assert resp.status == falcon.HTTP_OK
    assert resp.headers['content-type'] == expected
    assert resp.headers['vary'] == 'Accept'


def test_missing_accept_header_selects_first_declared(client):
    resp = client.simulate_get('/')

    assert resp.status == falcon.HTTP_OK
    assert resp.headers['content-type'] == 'application/json'


def test_serializes_with_selected_handler(client, unpack):
    resp = client.simulate_get('/', headers={'Accept': 'application/msgpack'})
    assert unpack(resp.content) == {'message': 'Hello, World!'}

    resp = client.simulate_get('/', headers={'Accept': 'application/json'})
    assert json.loads(resp.content) == {'message': 'Hello, World!'}


def test_tie_uses_declaration_order():
    class ReversedResource:
        produces = ('application/msgpack', 'application/json')

        def on_get(self, req, resp):
            resp.media = {'message': 'Hello, World!'}

    client = create_client(ReversedResource(), {
        'application/msgpack': media.MessagePackHandler(),
    })

    resp = client.simulate_get(
        '/', headers={'Accept': 'application/json, application/msgpack'}
    )

    assert resp.status == falcon.HTTP_OK
    assert resp.headers['content-type'] == 'application/msgpack'


def test_responder_level_overrides_resource_level():
    class MixedResource:
        produces = ('application/json',)

        @falcon.produces('application/msgpack', 'application/json')
        def on_get(self, req, resp):
            resp.media = {'message': 'Hello, World!'}

        def on_post(self, req, resp):
            resp.media = {'message': 'Hello, World!'}

    client = create_client(MixedResource(), {
        'application/msgpack': media.MessagePackHandler(),
    })

    resp = client.simulate_get('/', headers={'Accept': 'application/msgpack'})
    assert resp.status == falcon.HTTP_OK
    assert resp.headers['content-type'] == 'application/msgpack'

    # on_post() falls back to the resource-level declaration.
    resp = client.simulate_post('/', headers={'Accept': 'application/msgpack'})
    assert resp.status == falcon.HTTP_406


def test_produces_decorator_requires_media_type():
    with pytest.raises(ValueError):
        falcon.produces()


def test_resource_level_single_string():
    class SingleStringResource:
        produces = 'application/msgpack'

        def on_get(self, req, resp):
            resp.media = {'message': 'Hello, World!'}

    client = create_client(SingleStringResource(), {
        'application/msgpack': media.MessagePackHandler(),
    })

    resp = client.simulate_get('/', headers={'Accept': 'application/msgpack'})
    assert resp.status == falcon.HTTP_OK
    assert resp.headers['content-type'] == 'application/msgpack'


def test_empty_produces_disables_negotiation():
    class EmptyProducesResource:
        produces = ()

        def on_get(self, req, resp):
            resp.media = {'message': 'Hello, World!'}

    client = create_client(EmptyProducesResource())
    resp = client.simulate_get('/', headers={'Accept': 'image/png'})

    assert resp.status == falcon.HTTP_OK
    assert resp.headers['content-type'] == 'application/json'


def test_empty_produces_entry_is_skipped():
    class EmptyEntryResource:
        produces = ('', 'application/json')

        def on_get(self, req, resp):
            resp.media = {'message': 'Hello, World!'}

    client = create_client(EmptyEntryResource())
    resp = client.simulate_get('/', headers={'Accept': '*/*'})

    assert resp.status == falcon.HTTP_OK
    assert resp.headers['content-type'] == 'application/json'


@pytest.mark.parametrize(
    'accept',
    [
        'image/png',
        'application/json;q=0, application/msgpack;q=0',
        'application/*;q=0',
        # A malformed Accept header matches nothing.
        'not-a-media-type',
    ],
)
def test_not_acceptable(client, accept):
    resp = client.simulate_get('/', headers={'Accept': accept})

    assert resp.status == falcon.HTTP_406


def test_not_acceptable_error_is_serialized_without_recursion():
    # The client only accepts a type the resource does not produce,
    #   but the error serializer can still use it for the 406 response
    #   itself, independently of the produces declaration.
    class JSONOnlyResource:
        produces = ('application/json',)

        def on_get(self, req, resp):
            resp.media = {'message': 'Hello, World!'}

    client = create_client(JSONOnlyResource(), {
        'application/msgpack': media.MessagePackHandler(),
    })

    resp = client.simulate_get('/', headers={'Accept': 'application/msgpack'})

    assert resp.status == falcon.HTTP_406
    assert resp.headers['content-type'] == 'application/msgpack'


def test_not_acceptable_fallback_when_error_not_acceptable_either(client):
    # When the client accepts nothing the error serializer can
    #   produce either, the 406 response is still returned deterministically
    #   (with an empty body) instead of recursing into negotiation.
    resp = client.simulate_get('/', headers={'Accept': 'image/png'})

    assert resp.status == falcon.HTTP_406
    assert resp.content == b''


def test_media_type_parameters():
    class ParameterizedResource:
        produces = ('application/json; version=2', 'application/json')

        def on_get(self, req, resp):
            resp.media = {'message': 'Hello, World!'}

    client = create_client(ParameterizedResource())

    resp = client.simulate_get(
        '/',
        headers={
            'Accept': 'application/json; version=2; q=0.9, application/json; q=0.4'
        },
    )
    assert resp.status == falcon.HTTP_OK
    assert resp.headers['content-type'] == 'application/json; version=2'

    # A mismatched parameter value excludes the parameterized type.
    resp = client.simulate_get(
        '/', headers={'Accept': 'application/json; version=3'}
    )
    assert resp.status == falcon.HTTP_OK
    assert resp.headers['content-type'] == 'application/json'


def test_unregistered_media_type_is_skipped():
    class PartiallyRegisteredResource:
        produces = ('application/x-yaml', 'application/json')

        def on_get(self, req, resp):
            resp.media = {'message': 'Hello, World!'}

    client = create_client(PartiallyRegisteredResource())

    resp = client.simulate_get('/', headers={'Accept': '*/*'})
    assert resp.status == falcon.HTTP_OK
    assert resp.headers['content-type'] == 'application/json'

    # The only acceptable type has no registered handler.
    resp = client.simulate_get('/', headers={'Accept': 'application/x-yaml'})
    assert resp.status == falcon.HTTP_406


def test_all_types_unregistered():
    class UnregisteredResource:
        produces = ('application/x-yaml',)

        def on_get(self, req, resp):
            resp.media = {'message': 'Hello, World!'}

    client = create_client(UnregisteredResource())
    resp = client.simulate_get('/', headers={'Accept': '*/*'})

    assert resp.status == falcon.HTTP_406


def test_explicit_content_type_takes_precedence():
    class ExplicitResource:
        produces = ('application/json',)

        def on_get(self, req, resp):
            resp.content_type = 'application/msgpack'
            resp.media = {'message': 'Hello, World!'}

    client = create_client(ExplicitResource(), {
        'application/msgpack': media.MessagePackHandler(),
    })

    resp = client.simulate_get('/', headers={'Accept': 'application/json'})

    assert resp.status == falcon.HTTP_OK
    assert resp.headers['content-type'] == 'application/msgpack'
    assert 'vary' not in resp.headers


def test_vary_merged_with_existing_value():
    class VaryResource(MultiMediaResource):
        def on_get(self, req, resp):
            resp.vary = ('Accept-Encoding',)
            resp.media = {'message': 'Hello, World!'}

    client = create_client(VaryResource())
    resp = client.simulate_get('/', headers={'Accept': 'application/json'})

    assert resp.status == falcon.HTTP_OK
    assert resp.headers['vary'] == 'Accept-Encoding, Accept'


@pytest.mark.parametrize('vary', [('Accept',), ('*',)])
def test_vary_not_appended_when_redundant(vary):
    class VaryResource(MultiMediaResource):
        def on_get(self, req, resp):
            resp.vary = vary
            resp.media = {'message': 'Hello, World!'}

    client = create_client(VaryResource())
    resp = client.simulate_get('/', headers={'Accept': 'application/json'})

    assert resp.status == falcon.HTTP_OK
    assert resp.headers['vary'] == vary[0]


def test_only_selected_handler_serializes():
    json_handler = CountingJSONHandler()
    msgpack_handler = CountingMessagePackHandler()

    client = create_client(MultiMediaResource(), {
        'application/json': json_handler,
        'application/msgpack': msgpack_handler,
    })

    resp = client.simulate_get('/', headers={'Accept': 'application/msgpack'})

    assert resp.status == falcon.HTTP_OK
    assert msgpack_handler.serialize_count == 1
    assert json_handler.serialize_count == 0


def test_no_produces_no_negotiation():
    class PlainResource:
        def on_get(self, req, resp):
            resp.media = {'message': 'Hello, World!'}

    client = create_client(PlainResource())
    resp = client.simulate_get('/', headers={'Accept': 'image/png'})

    assert resp.status == falcon.HTTP_OK
    assert resp.headers['content-type'] == 'application/json'
    assert 'vary' not in resp.headers


def test_no_media_no_negotiation():
    class NoMediaResource(MultiMediaResource):
        def on_get(self, req, resp):
            resp.status = falcon.HTTP_204

    client = create_client(NoMediaResource())
    resp = client.simulate_get('/', headers={'Accept': 'image/png'})

    assert resp.status == falcon.HTTP_204


def test_text_takes_precedence_over_media():
    class TextResource(MultiMediaResource):
        def on_get(self, req, resp):
            resp.text = 'Hello, World!'
            resp.media = {'message': 'Hello, World!'}

    client = create_client(TextResource())
    resp = client.simulate_get('/', headers={'Accept': 'application/msgpack'})

    assert resp.status == falcon.HTTP_OK
    assert resp.text == 'Hello, World!'


def test_data_takes_precedence_over_media():
    class DataResource(MultiMediaResource):
        def on_get(self, req, resp):
            resp.data = b'Hello, World!'
            resp.media = {'message': 'Hello, World!'}

    client = create_client(DataResource())
    resp = client.simulate_get('/', headers={'Accept': 'application/msgpack'})

    assert resp.status == falcon.HTTP_OK
    assert resp.content == b'Hello, World!'


def test_sink_without_resource():
    def sink(req, resp):
        resp.media = {'message': 'Hello, World!'}

    app = falcon.App()
    app.add_sink(sink, '/sink')
    client = testing.TestClient(app)

    resp = client.simulate_get('/sink/path', headers={'Accept': 'image/png'})

    assert resp.status == falcon.HTTP_OK
    assert resp.headers['content-type'] == 'application/json'


def test_error_response_not_negotiated(client):
    # Errors raised by the responder are rendered by the app's error
    #   serializer; the produces declaration is not applied to them.
    class FailingResource(MultiMediaResource):
        def on_get(self, req, resp):
            raise falcon.HTTPBadRequest()

    client = create_client(FailingResource())
    resp = client.simulate_get('/', headers={'Accept': 'application/msgpack'})

    assert resp.status == falcon.HTTP_400


def test_unhandled_negotiation_error_reraises():
    client = create_client(MultiMediaResource())
    client.app._error_handlers.clear()

    with pytest.raises(falcon.HTTPNotAcceptable):
        client.simulate_get('/', headers={'Accept': 'image/png'})
