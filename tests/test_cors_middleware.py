from pathlib import Path

import pytest

import falcon
from falcon import testing
import falcon.middleware


@pytest.fixture
def client(asgi, util):
    app = util.create_app(asgi)
    return testing.TestClient(app)


@pytest.fixture(scope='function')
def cors_client(asgi, util):
    # NOTE(kgriffs): Disable wrapping to test that built-in middleware does
    #   not require it (since this will be the case for non-test apps).
    with util.disable_asgi_non_coroutine_wrapping():
        app = util.create_app(asgi, cors_enable=True)
    return testing.TestClient(app)


class CORSHeaderResource:
    def on_get(self, req, resp):
        resp.text = "I'm a CORS test response"

    def on_delete(self, req, resp):
        resp.set_header('Access-Control-Allow-Origin', 'example.com')
        resp.text = "I'm a CORS test response"


class CORSOptionsResource:
    def on_options(self, req, resp):
        # No allow header set
        resp.set_header('Content-Length', '0')


class ScopedCORSResource:
    get_calls = 0
    post_calls = 0

    @falcon.CORSPolicy(
        allow_origins='*',
        allow_headers=['X-Public'],
        allow_credentials=None,
        expose_headers=['X-Public-Expose'],
    )
    def on_get(self, req, resp):
        type(self).get_calls += 1
        resp.text = 'public'

    @falcon.CORSPolicy(
        allow_origins=['https://admin.example'],
        allow_credentials='*',
        allow_headers=['X-Admin'],
        expose_headers=['X-Admin-Expose'],
    )
    def on_post(self, req, resp):
        type(self).post_calls += 1
        resp.text = 'admin'

    def on_options(self, req, resp):
        raise AssertionError('preflight must not invoke on_options')


class SuffixedCORSResource:
    get_calls = 0

    @falcon.CORSPolicy(allow_origins='*')
    def on_get_public(self, req, resp):
        type(self).get_calls += 1
        resp.text = 'public suffix'

    @falcon.CORSPolicy(allow_origins=['https://admin.example'])
    def on_get_admin(self, req, resp):
        type(self).get_calls += 1
        resp.text = 'admin suffix'


@falcon.CORSPolicy(allow_origins=['https://resource.example'])
class ResourcePolicyResource:
    def on_get(self, req, resp):
        resp.text = 'resource policy'


class GetOnlyResource:
    def on_get(self, req, resp):
        resp.text = 'get only'


class HeaderIntersectionResource:
    @falcon.CORSPolicy(allow_origins='*', allow_headers=['X-Shared', 'X-Get-Only'])
    def on_get(self, req, resp):
        resp.text = 'get'

    @falcon.CORSPolicy(allow_origins='*', allow_headers=['X-Shared', 'X-Post-Only'])
    def on_post(self, req, resp):
        resp.text = 'post'


class TestCorsMiddleware:
    def test_disabled_cors_should_not_add_any_extra_headers(self, client):
        client.app.add_route('/', CORSHeaderResource())
        result = client.simulate_get(headers={'Origin': 'localhost'})
        h = dict(result.headers.lower_items()).keys()
        assert 'Access-Control-Allow-Origin'.lower() not in h
        assert 'Access-Control-Allow-Credentials'.lower() not in h
        assert 'Access-Control-Expose-Headers'.lower() not in h

    def test_enabled_cors_no_origin(self, client):
        client.app.add_route('/', CORSHeaderResource())
        result = client.simulate_get()
        h = dict(result.headers.lower_items()).keys()
        assert 'Access-Control-Allow-Origin'.lower() not in h
        assert 'Access-Control-Allow-Credentials'.lower() not in h
        assert 'Access-Control-Expose-Headers'.lower() not in h

    def test_enabled_cors_should_add_extra_headers_on_response(self, cors_client):
        cors_client.app.add_route('/', CORSHeaderResource())
        result = cors_client.simulate_get(headers={'Origin': 'localhost'})
        assert (
            'Access-Control-Allow-Origin'.lower()
            in dict(result.headers.lower_items()).keys()
        )

    def test_enabled_cors_should_accept_all_origins_requests(self, cors_client):
        cors_client.app.add_route('/', CORSHeaderResource())

        result = cors_client.simulate_get(headers={'Origin': 'localhost'})
        assert result.headers['Access-Control-Allow-Origin'] == '*'

        result = cors_client.simulate_delete(headers={'Origin': 'localhost'})
        assert result.headers['Access-Control-Allow-Origin'] == 'example.com'

    def test_enabled_cors_handles_preflighting(self, cors_client):
        cors_client.app.add_route('/', CORSHeaderResource())
        result = cors_client.simulate_options(
            headers=(
                ('Origin', 'localhost'),
                ('Access-Control-Request-Method', 'GET'),
                ('Access-Control-Request-Headers', 'X-PINGOTHER, Content-Type'),
            )
        )
        assert result.headers['Access-Control-Allow-Methods'] == 'DELETE, GET'
        assert (
            result.headers['Access-Control-Allow-Headers']
            == 'X-PINGOTHER, Content-Type'
        )
        assert (
            result.headers['Access-Control-Max-Age'] == '86400'
        )  # 24 hours in seconds

    def test_enabled_cors_handles_preflight_custom_option(self, cors_client):
        cors_client.app.add_route('/', CORSOptionsResource())
        result = cors_client.simulate_options(
            headers=(
                ('Origin', 'localhost'),
                ('Access-Control-Request-Method', 'GET'),
                ('Access-Control-Request-Headers', 'X-PINGOTHER, Content-Type'),
            )
        )
        assert 'Access-Control-Allow-Methods' not in result.headers
        assert 'Access-Control-Allow-Headers' not in result.headers
        assert 'Access-Control-Max-Age' not in result.headers
        assert 'Access-Control-Expose-Headers' not in result.headers
        assert 'Access-Control-Allow-Origin' not in result.headers

    def test_enabled_cors_handles_preflighting_no_headers_in_req(self, cors_client):
        cors_client.app.add_route('/', CORSHeaderResource())
        result = cors_client.simulate_options(
            headers=(
                ('Origin', 'localhost'),
                ('Access-Control-Request-Method', 'GET'),
            )
        )
        assert result.headers['Access-Control-Allow-Methods'] == 'DELETE, GET'
        assert result.headers['Access-Control-Allow-Headers'] == '*'
        assert (
            result.headers['Access-Control-Max-Age'] == '86400'
        )  # 24 hours in seconds

    def test_enabled_cors_static_route(self, cors_client):
        cors_client.app.add_static_route('/static', Path(__file__).parent)
        result = cors_client.simulate_options(
            f'/static/{Path(__file__).name}',
            headers=(
                ('Origin', 'localhost'),
                ('Access-Control-Request-Method', 'GET'),
            ),
        )

        assert result.headers['Access-Control-Allow-Methods'] == 'GET'
        assert result.headers['Access-Control-Allow-Headers'] == '*'
        assert result.headers['Access-Control-Max-Age'] == '86400'
        assert result.headers['Access-Control-Allow-Origin'] == '*'

    @pytest.mark.parametrize('support_options', [True, False])
    def test_enabled_cors_sink_route(self, cors_client, support_options):
        def my_sink(req, resp):
            if req.method == 'OPTIONS' and support_options:
                resp.set_header('ALLOW', 'GET')
            else:
                resp.text = 'my sink'

        cors_client.app.add_sink(my_sink, '/sink')
        result = cors_client.simulate_options(
            '/sink/123',
            headers=(
                ('Origin', 'localhost'),
                ('Access-Control-Request-Method', 'GET'),
            ),
        )

        if support_options:
            assert result.headers['Access-Control-Allow-Methods'] == 'GET'
            assert result.headers['Access-Control-Allow-Headers'] == '*'
            assert result.headers['Access-Control-Max-Age'] == '86400'
            assert result.headers['Access-Control-Allow-Origin'] == '*'
        else:
            assert 'Access-Control-Allow-Methods' not in result.headers
            assert 'Access-Control-Allow-Headers' not in result.headers
            assert 'Access-Control-Max-Age' not in result.headers
            assert 'Access-Control-Expose-Headers' not in result.headers
            assert 'Access-Control-Allow-Origin' not in result.headers

    @pytest.mark.parametrize('include_request_private_network', (True, False))
    def test_disabled_cors_private_network(
        self, cors_client, include_request_private_network
    ):
        # default scenario for cors middleware, where
        # allow private network is off by default

        cors_client.app.add_route('/', CORSHeaderResource())

        headers = (
            ('Origin', 'localhost'),
            ('Access-Control-Request-Method', 'GET'),
        )

        if include_request_private_network:
            headers = (
                *headers,
                ('Access-Control-Request-Private-Network', 'true'),
            )

        result = cors_client.simulate_options('/', headers=headers)

        h = result.headers

        assert 'Access-Control-Allow-Private-Network' not in h


@pytest.fixture(scope='function')
def make_cors_client(asgi, util):
    def make(middleware):
        app = util.create_app(asgi, middleware=middleware)
        return testing.TestClient(app)

    return make


class TestCustomCorsMiddleware:
    def test_raises(self):
        with pytest.raises(ValueError, match='passed to allow_origins'):
            falcon.CORSMiddleware(allow_origins=['*'])
        with pytest.raises(ValueError, match='passed to allow_credentials'):
            falcon.CORSMiddleware(allow_credentials=['*'])

    @pytest.mark.parametrize(
        'allow, fail_origins, success_origins',
        (
            ('*', [None], ['foo', 'bar']),
            ('test', ['other', 'Test', 'TEST'], ['test']),
            (
                ['foo', 'bar'],
                ['foo, bar', 'foobar', 'foo,bar', 'Foo', 'BAR'],
                ['foo', 'bar'],
            ),
        ),
    )
    def test_allow_origin(self, make_cors_client, allow, fail_origins, success_origins):
        client = make_cors_client(falcon.CORSMiddleware(allow_origins=allow))
        client.app.add_route('/', CORSHeaderResource())

        for origin in fail_origins:
            h = {'Origin': origin} if origin is not None else {}
            res = client.simulate_get(headers=h)
            h = dict(res.headers.lower_items()).keys()
            assert 'Access-Control-Allow-Origin'.lower() not in h
            assert 'Access-Control-Allow-Credentials'.lower() not in h
            assert 'Access-Control-Expose-Headers'.lower() not in h

        for origin in success_origins:
            res = client.simulate_get(headers={'Origin': origin})
            assert (
                res.headers['Access-Control-Allow-Origin'] == '*'
                if allow == '*'
                else origin
            )
            h = dict(res.headers.lower_items()).keys()
            assert 'Access-Control-Allow-Credentials'.lower() not in h
            assert 'Access-Control-Expose-Headers'.lower() not in h

    def test_allow_credential_wildcard(self, make_cors_client):
        client = make_cors_client(falcon.CORSMiddleware(allow_credentials='*'))
        client.app.add_route('/', CORSHeaderResource())

        res = client.simulate_get(headers={'Origin': 'localhost'})
        assert res.headers['Access-Control-Allow-Origin'] == 'localhost'
        assert res.headers['Access-Control-Allow-Credentials'] == 'true'

    @pytest.mark.parametrize(
        'allow, successOrigin',
        (
            (['foo', 'bar'], ['foo', 'bar']),
            ('foo', ['foo']),
        ),
    )
    def test_allow_credential_list_or_str(self, make_cors_client, allow, successOrigin):
        client = make_cors_client(falcon.CORSMiddleware(allow_credentials=allow))
        client.app.add_route('/', CORSHeaderResource())

        for origin in ('foo, bar', 'foobar', 'foo,bar', 'Foo', 'BAR'):
            res = client.simulate_get(headers={'Origin': origin})
            assert res.headers['Access-Control-Allow-Origin'] == '*'
            h = dict(res.headers.lower_items()).keys()
            assert 'Access-Control-Allow-Credentials'.lower() not in h
            assert 'Access-Control-Expose-Headers'.lower() not in h

        for origin in successOrigin:
            res = client.simulate_get(headers={'Origin': origin})
            assert res.headers['Access-Control-Allow-Origin'] == origin
            assert res.headers['Access-Control-Allow-Credentials'] == 'true'
            h = dict(res.headers.lower_items()).keys()
            assert 'Access-Control-Expose-Headers'.lower() not in h

    def test_allow_credential_existing_origin(self, make_cors_client):
        client = make_cors_client(falcon.CORSMiddleware(allow_credentials='*'))
        client.app.add_route('/', CORSHeaderResource())

        res = client.simulate_delete(headers={'Origin': 'something'})
        assert res.headers['Access-Control-Allow-Origin'] == 'example.com'
        h = dict(res.headers.lower_items()).keys()
        assert 'Access-Control-Allow-Credentials'.lower() not in h

    def test_allow_origin_allow_credential(self, make_cors_client):
        client = make_cors_client(
            falcon.CORSMiddleware(allow_origins='test', allow_credentials='*')
        )
        client.app.add_route('/', CORSHeaderResource())

        for origin in ['foo', 'TEST']:
            res = client.simulate_get(headers={'Origin': origin})
            h = dict(res.headers.lower_items()).keys()
            assert 'Access-Control-Allow-Origin'.lower() not in h
            assert 'Access-Control-Allow-Credentials'.lower() not in h
            assert 'Access-Control-Expose-Headers'.lower() not in h

        res = client.simulate_get(headers={'Origin': 'test'})
        assert res.headers['Access-Control-Allow-Origin'] == 'test'
        assert res.headers['Access-Control-Allow-Credentials'] == 'true'
        h = dict(res.headers.lower_items()).keys()
        assert 'Access-Control-Expose-Headers'.lower() not in h

    @pytest.mark.parametrize(
        'attr, exp',
        (
            ('foo', 'foo'),
            ('foo, bar', 'foo, bar'),
            (['foo', 'bar'], 'foo, bar'),
        ),
    )
    def test_expose_headers(self, make_cors_client, attr, exp):
        client = make_cors_client(
            falcon.CORSMiddleware(expose_headers=attr, allow_credentials=None)
        )
        client.app.add_route('/', CORSHeaderResource())

        res = client.simulate_get(headers={'Origin': 'something'})
        assert res.headers['Access-Control-Allow-Origin'] == '*'
        assert res.headers['Access-Control-Expose-Headers'] == exp
        h = dict(res.headers.lower_items()).keys()
        assert 'Access-Control-Allow-Credentials'.lower() not in h

    def test_enabled_cors_private_network_headers(self, make_cors_client):
        client = make_cors_client(falcon.CORSMiddleware(allow_private_network=True))

        client.app.add_route('/', CORSHeaderResource())

        res = client.simulate_options(
            '/',
            headers=(
                ('Origin', 'localhost'),
                ('Access-Control-Request-Method', 'GET'),
                ('Access-Control-Request-Private-Network', 'true'),
            ),
        )

        assert res.headers['Access-Control-Allow-Private-Network'] == 'true'


@pytest.fixture
def scoped_cors_client(asgi, util):
    class VaryMiddleware:
        def process_request(self, req, resp):
            resp.append_header('Vary', 'Accept-Encoding')

    middleware = falcon.CORSMiddleware(
        allow_origins=['https://admin.example'],
        allow_credentials='https://admin.example',
        allow_headers=['X-Admin'],
        expose_headers=['X-Default-Expose'],
    )
    app = util.create_app(asgi, middleware=[VaryMiddleware(), middleware])
    resource = ScopedCORSResource()
    suffix_resource = SuffixedCORSResource()
    app.add_route('/items', resource)
    app.add_route('/items/public', suffix_resource, suffix='public')
    app.add_route('/items/admin', suffix_resource, suffix='admin')
    ScopedCORSResource.get_calls = 0
    ScopedCORSResource.post_calls = 0
    SuffixedCORSResource.get_calls = 0
    return testing.TestClient(app), resource


class TestScopedCorsPolicy:
    REQUEST_CASES = (
        {
            'name': 'public_get_wildcard_origin',
            'method': 'GET',
            'path': '/items',
            'headers': {'Origin': 'https://public.example'},
            'expected_headers': {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Expose-Headers': 'X-Public-Expose',
            },
            'forbidden_headers': ('Access-Control-Allow-Credentials',),
            'get_calls': 1,
        },
        {
            'name': 'public_get_admin_origin',
            'method': 'GET',
            'path': '/items',
            'headers': {'Origin': 'https://admin.example'},
            'expected_headers': {'Access-Control-Allow-Origin': '*'},
            'forbidden_headers': ('Access-Control-Allow-Credentials',),
            'get_calls': 1,
        },
        {
            'name': 'admin_post_allowed_origin',
            'method': 'POST',
            'path': '/items',
            'headers': {'Origin': 'https://admin.example'},
            'expected_headers': {
                'Access-Control-Allow-Origin': 'https://admin.example',
                'Access-Control-Allow-Credentials': 'true',
                'Access-Control-Expose-Headers': 'X-Admin-Expose',
            },
            'post_calls': 1,
        },
        {
            'name': 'admin_post_public_origin_denied',
            'method': 'POST',
            'path': '/items',
            'headers': {'Origin': 'https://public.example'},
            'forbidden_headers': (
                'Access-Control-Allow-Origin',
                'Access-Control-Allow-Credentials',
            ),
            'post_calls': 1,
        },
        {
            'name': 'preflight_post_allowed',
            'method': 'OPTIONS',
            'path': '/items',
            'headers': {
                'Origin': 'https://admin.example',
                'Access-Control-Request-Method': 'POST',
                'Access-Control-Request-Headers': 'X-ADMIN',
            },
            'expected_headers': {
                'Access-Control-Allow-Origin': 'https://admin.example',
                'Access-Control-Allow-Credentials': 'true',
                'Access-Control-Allow-Methods': 'POST',
                'Access-Control-Allow-Headers': 'X-ADMIN',
                'Access-Control-Max-Age': '86400',
            },
            'forbidden_headers': ('Allow',),
            'vary': {
                'Origin',
                'Access-Control-Request-Method',
                'Access-Control-Request-Headers',
                'Accept-Encoding',
            },
        },
        {
            'name': 'preflight_post_header_case_insensitive',
            'method': 'OPTIONS',
            'path': '/items',
            'headers': {
                'Origin': 'https://admin.example',
                'Access-Control-Request-Method': 'POST',
                'Access-Control-Request-Headers': 'x-admin',
            },
            'expected_headers': {
                'Access-Control-Allow-Headers': 'x-admin',
                'Access-Control-Allow-Methods': 'POST',
            },
        },
        {
            'name': 'preflight_post_disallowed_header',
            'method': 'OPTIONS',
            'path': '/items',
            'headers': {
                'Origin': 'https://admin.example',
                'Access-Control-Request-Method': 'POST',
                'Access-Control-Request-Headers': 'X-Forbidden',
            },
            'forbidden_headers': (
                'Access-Control-Allow-Origin',
                'Access-Control-Allow-Methods',
                'Access-Control-Allow-Headers',
            ),
            'vary': {'Accept-Encoding'},
        },
        {
            'name': 'preflight_get_uses_get_policy',
            'method': 'OPTIONS',
            'path': '/items',
            'headers': {
                'Origin': 'https://public.example',
                'Access-Control-Request-Method': 'GET',
                'Access-Control-Request-Headers': 'X-PUBLIC',
            },
            'expected_headers': {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET',
                'Access-Control-Allow-Headers': 'X-PUBLIC',
            },
            'vary': {
                'Access-Control-Request-Method',
                'Access-Control-Request-Headers',
                'Accept-Encoding',
            },
        },
        {
            'name': 'preflight_unsupported_method',
            'method': 'OPTIONS',
            'path': '/items',
            'headers': {
                'Origin': 'https://public.example',
                'Access-Control-Request-Method': 'DELETE',
            },
            'forbidden_headers': (
                'Access-Control-Allow-Origin',
                'Access-Control-Allow-Methods',
            ),
            'vary': {'Accept-Encoding'},
        },
        {
            'name': 'preflight_route_not_found',
            'method': 'OPTIONS',
            'path': '/missing',
            'headers': {
                'Origin': 'https://public.example',
                'Access-Control-Request-Method': 'GET',
            },
            'forbidden_headers': (
                'Access-Control-Allow-Origin',
                'Access-Control-Allow-Methods',
            ),
            'vary': {'Accept-Encoding', 'Accept'},
        },
        {
            'name': 'preflight_public_suffix',
            'method': 'OPTIONS',
            'path': '/items/public',
            'headers': {
                'Origin': 'https://public.example',
                'Access-Control-Request-Method': 'GET',
            },
            'expected_headers': {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET',
            },
        },
        {
            'name': 'preflight_admin_suffix',
            'method': 'OPTIONS',
            'path': '/items/admin',
            'headers': {
                'Origin': 'https://admin.example',
                'Access-Control-Request-Method': 'GET',
            },
            'expected_headers': {
                'Access-Control-Allow-Origin': 'https://admin.example',
                'Access-Control-Allow-Methods': 'GET',
            },
        },
        {
            'name': 'preflight_admin_suffix_wrong_origin',
            'method': 'OPTIONS',
            'path': '/items/admin',
            'headers': {
                'Origin': 'https://public.example',
                'Access-Control-Request-Method': 'GET',
            },
            'forbidden_headers': (
                'Access-Control-Allow-Origin',
                'Access-Control-Allow-Methods',
            ),
            'vary': {'Accept-Encoding'},
        },
    )

    def test_policy_helpers(self):
        assert falcon.middleware._parse_method_list('') == frozenset()
        assert falcon.middleware._normalize_method_set('get') == frozenset(('GET',))

        response = falcon.Response()
        response.set_header('Vary', 'Accept, Origin')
        falcon.middleware._delete_cors_vary(response)
        assert response.get_header('Vary') == 'accept'

        response.set_header('Vary', 'Origin')
        falcon.middleware._delete_cors_vary(response)
        assert response.get_header('Vary') is None

    @pytest.mark.parametrize(
        'case', REQUEST_CASES, ids=[case['name'] for case in REQUEST_CASES]
    )
    def test_same_request_table_for_wsgi_and_asgi(self, scoped_cors_client, case):
        client, resource = scoped_cors_client
        result = client.simulate_request(
            method=case['method'], path=case['path'], headers=case['headers']
        )

        for name, value in case.get('expected_headers', {}).items():
            assert result.headers[name] == value

        for name in case.get('forbidden_headers', ()):
            assert name not in result.headers

        if 'vary' in case:
            assert {
                value.strip().lower() for value in result.headers['Vary'].split(',')
            } == {value.lower() for value in case['vary']}

        assert resource.get_calls == case.get('get_calls', 0)
        assert resource.post_calls == case.get('post_calls', 0)

    def test_resource_policy_inherits_other_defaults(self, asgi, util):
        middleware = falcon.CORSMiddleware(
            allow_origins='*',
            allow_credentials='*',
            expose_headers=['X-Inherited'],
        )
        client = testing.TestClient(util.create_app(asgi, middleware=middleware))
        client.app.add_route('/', ResourcePolicyResource())

        result = client.simulate_get(headers={'Origin': 'https://resource.example'})

        assert result.headers['Access-Control-Allow-Origin'] == (
            'https://resource.example'
        )
        assert result.headers['Access-Control-Allow-Credentials'] == 'true'
        assert result.headers['Access-Control-Expose-Headers'] == 'X-Inherited'

    def test_resource_instance_policy(self, asgi, util):
        resource = CORSHeaderResource()
        resource.cors_policy = falcon.CORSPolicy(
            allow_origins=['https://instance.example']
        )
        client = testing.TestClient(
            util.create_app(asgi, middleware=falcon.CORSMiddleware())
        )
        client.app.add_route('/', resource)

        result = client.simulate_get(headers={'Origin': 'https://instance.example'})

        assert result.headers['Access-Control-Allow-Origin'] == (
            'https://instance.example'
        )

    def test_wildcard_credentials_echoes_authorization(self, make_cors_client):
        client = make_cors_client(
            falcon.CORSMiddleware(
                allow_credentials='*',
                allow_headers=['Authorization'],
            )
        )
        client.app.add_route('/', CORSHeaderResource())

        result = client.simulate_options(
            headers=(
                ('Origin', 'https://app.example'),
                ('Access-Control-Request-Method', 'GET'),
                ('Access-Control-Request-Headers', 'Authorization'),
            )
        )

        assert result.headers['Access-Control-Allow-Origin'] == ('https://app.example')
        assert result.headers['Access-Control-Allow-Credentials'] == 'true'
        assert result.headers['Access-Control-Allow-Headers'] == 'Authorization'

    def test_preflight_uses_actual_route_capabilities(self, make_cors_client):
        client = make_cors_client(falcon.CORSMiddleware())
        client.app.add_route('/', GetOnlyResource())

        result = client.simulate_options(
            headers=(
                ('Origin', 'https://app.example'),
                ('Access-Control-Request-Method', 'PATCH'),
            )
        )

        assert result.status == falcon.HTTP_200
        assert 'Access-Control-Allow-Origin' not in result.headers
        assert 'Access-Control-Allow-Methods' not in result.headers

    def test_preflight_respects_policy_methods(self, make_cors_client):
        client = make_cors_client(falcon.CORSMiddleware(allow_methods=['GET']))
        client.app.add_route('/', CORSHeaderResource())

        result = client.simulate_options(
            headers=(
                ('Origin', 'https://app.example'),
                ('Access-Control-Request-Method', 'DELETE'),
            )
        )

        assert 'Access-Control-Allow-Origin' not in result.headers
        assert 'Access-Control-Allow-Methods' not in result.headers

    def test_preflight_rejects_authorization_without_credentials(
        self, make_cors_client
    ):
        client = make_cors_client(falcon.CORSMiddleware())
        client.app.add_route('/', CORSHeaderResource())

        result = client.simulate_options(
            headers=(
                ('Origin', 'https://app.example'),
                ('Access-Control-Request-Method', 'GET'),
                ('Access-Control-Request-Headers', 'Authorization'),
            )
        )

        assert 'Access-Control-Allow-Origin' not in result.headers
        assert 'Access-Control-Allow-Headers' not in result.headers

    def test_preflight_publishes_header_intersection(self, make_cors_client):
        client = make_cors_client(falcon.CORSMiddleware())
        client.app.add_route('/', HeaderIntersectionResource())

        result = client.simulate_options(
            headers=(
                ('Origin', 'https://app.example'),
                ('Access-Control-Request-Method', 'GET'),
                ('Access-Control-Request-Headers', 'X-Shared, X-Get-Only'),
            )
        )

        assert result.headers['Access-Control-Allow-Methods'] == 'GET'
        assert result.headers['Access-Control-Allow-Headers'] == (
            'X-Shared, X-Get-Only'
        )

        result = client.simulate_options(
            headers=(
                ('Origin', 'https://app.example'),
                ('Access-Control-Request-Method', 'GET'),
                ('Access-Control-Request-Headers', 'X-Shared'),
            )
        )

        assert result.headers['Access-Control-Allow-Methods'] == 'GET, POST'
        assert result.headers['Access-Control-Allow-Headers'] == 'X-Shared'
