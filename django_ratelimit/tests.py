from functools import partial

from django.core.cache import cache, InvalidCacheBackendError
from django.core.exceptions import ImproperlyConfigured
from django.test import RequestFactory, TestCase
from django.test.utils import override_settings
from django.utils.decorators import method_decorator
from django.views.generic import View

from django_ratelimit import ALL
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited
from django_ratelimit.core import (get_usage, is_ratelimited,
                                   _split_rate, _get_ip, UnavailableClientIP)


rf = RequestFactory()


class MockUser:
    def __init__(self, authenticated=False):
        self.pk = 1
        self.is_authenticated = authenticated


class RateParsingTests(TestCase):
    def test_simple(self):
        tests = (
            ('100/s', (100, 1)),
            ('100/10s', (100, 10)),
            ('100/10', (100, 10)),
            ('100/m', (100, 60)),
            ('400/10m', (400, 600)),
            ('1000/h', (1000, 3600)),
            ('800/d', (800, 24 * 60 * 60)),
        )

        for i, o in tests:
            assert o == _split_rate(i)


def callable_rate(group, request):
    if request.user.is_authenticated:
        return None
    return (0, 1)


def mykey(group, request):
    return request.META['REMOTE_ADDR'][::-1]


class CustomRatelimitedException(Exception):
    pass


class RatelimitTests(TestCase):
    def setUp(self):
        cache.clear()

    def test_no_key(self):
        @ratelimit(rate='1/m')
        def view(request):
            return True

        req = rf.get('/')
        with self.assertRaises(ImproperlyConfigured):
            view(req)

    def test_ip(self):
        @ratelimit(key='ip', rate='1/m', block=False)
        def view(request):
            return request.limited

        assert not view(rf.get('/')), 'First request works.'
        assert view(rf.get('/')), 'Second request is limited'

    def test_block(self):
        @ratelimit(key='ip', rate='1/m')
        def blocked(request):
            return request.limited

        assert not blocked(rf.get('/')), 'First request works.'
        with self.assertRaises(Ratelimited):
            blocked(rf.get('/')), 'Second request is blocked.'

    def test_ratelimit_custom_string_exception_class(self):
        @ratelimit(key='ip', rate='1/m')
        def view(request):
            return request.limited

        with self.settings(
            RATELIMIT_EXCEPTION_CLASS=(
                "django_ratelimit.tests.CustomRatelimitedException"
            )
        ):
            req = rf.get("")
            assert not view(req)
            with self.assertRaises(CustomRatelimitedException):
                view(req)

    def test_ratelimit_custom_exception_class(self):
        @ratelimit(key='ip', rate='1/m')
        def view(request):
            return request.limited

        with self.settings(
            RATELIMIT_EXCEPTION_CLASS=CustomRatelimitedException
        ):
            req = rf.get("")
            assert not view(req)
            with self.assertRaises(CustomRatelimitedException):
                view(req)

    def test_method(self):
        @ratelimit(key='ip', method='POST', rate='1/m', group='a', block=False)
        def limit_post(request):
            return request.limited

        assert not limit_post(rf.post('/')), 'Do not limit first POST.'
        assert limit_post(rf.post('/')), 'Limit second POST.'
        assert not limit_post(rf.get('/')), 'Do not limit GET.'

    def test_unsafe_methods(self):
        @ratelimit(key='ip', method=ratelimit.UNSAFE, rate='0/m', block=False)
        def limit_unsafe(request):
            return request.limited

        assert not limit_unsafe(rf.get('/'))
        assert not limit_unsafe(rf.head('/'))
        assert not limit_unsafe(rf.options('/'))
        assert limit_unsafe(rf.delete('/'))
        assert limit_unsafe(rf.post('/'))
        assert limit_unsafe(rf.put('/'))
        assert limit_unsafe(rf.patch('/'))

    def test_key_get(self):
        @ratelimit(key='get:foo', rate='1/m', method='GET', block=False)
        def view(request):
            return request.limited

        assert not view(rf.get('/', {'foo': 'a'}))
        assert view(rf.get('/', {'foo': 'a'}))
        assert not view(rf.get('/', {'foo': 'b'}))
        assert view(rf.get('/', {'foo': 'b'}))

    def test_key_post(self):
        @ratelimit(key='post:foo', rate='1/m', block=False)
        def view(request):
            return request.limited

        assert not view(rf.post('/', {'foo': 'a'}))
        assert view(rf.post('/', {'foo': 'a'}))
        assert not view(rf.post('/', {'foo': 'b'}))
        assert view(rf.post('/', {'foo': 'b'}))

    def test_key_header(self):
        def _req():
            req = rf.post('/')
            req.META['HTTP_X_REAL_IP'] = '1.2.3.4'
            return req

        @ratelimit(key='header:x-real-ip', rate='1/m', block=False)
        @ratelimit(key='header:x-missing-header', rate='1/m', block=False)
        def view(request):
            return request.limited

        assert not view(_req())
        assert view(_req())

    def test_rate(self):
        @ratelimit(key='ip', rate='2/m', block=False)
        def twice(request):
            return request.limited

        assert not twice(rf.post('/')), 'First request is not limited.'
        assert not twice(rf.post('/')), 'Second request is not limited.'
        assert twice(rf.post('/')), 'Third request is limited.'

    def test_zero_rate(self):
        @ratelimit(key='ip', rate='0/m', block=False)
        def never(request):
            return request.limited

        assert never(rf.post('/'))

    def test_none_rate(self):
        @ratelimit(key='ip', rate=None, block=False)
        def always(request):
            return request.limited

        assert not always(rf.post('/'))
        assert not always(rf.post('/'))
        assert not always(rf.post('/'))
        assert not always(rf.post('/'))
        assert not always(rf.post('/'))
        assert not always(rf.post('/'))
        assert not always(rf.post('/'))

    def test_callable_rate(self):
        def _req(auth):
            req = rf.post('/')
            req.user = MockUser(authenticated=auth)
            return req

        def get_rate(group, request):
            if request.user.is_authenticated:
                return (2, 60)
            return (1, 60)

        @ratelimit(key='user_or_ip', rate=get_rate, block=False)
        def view(request):
            return request.limited

        assert not view(_req(auth=False))
        assert view(_req(auth=False))
        assert not view(_req(auth=True))
        assert not view(_req(auth=True))
        assert view(_req(auth=True))

    def test_callable_rate_none(self):
        def _req(never_limit=False):
            req = rf.post('/')
            req.never_limit = never_limit
            return req

        get_rate = lambda g, r: None if r.never_limit else '1/m'

        @ratelimit(key='ip', rate=get_rate, block=False)
        def view(request):
            return request.limited

        assert not view(_req())
        assert view(_req())
        assert not view(_req(never_limit=True))
        assert not view(_req(never_limit=True))

    def test_callable_rate_zero(self):
        def _req(auth):
            req = rf.post('/')
            req.user = MockUser(authenticated=auth)
            return req

        def get_rate(group, request):
            if request.user.is_authenticated:
                return '1/m'
            return '0/m'

        @ratelimit(key='ip', rate=get_rate, block=False)
        def view(request):
            return request.limited

        assert view(_req(auth=False))
        assert not view(_req(auth=True))
        assert view(_req(auth=True))

    def test_callable_rate_import(self):
        def _req(auth):
            req = rf.post('/')
            req.user = MockUser(authenticated=auth)
            return req

        @ratelimit(key='user_or_ip',
                   rate='django_ratelimit.tests.callable_rate',
                   block=False)
        def view(request):
            return request.limited

        assert view(_req(auth=False))
        assert not view(_req(auth=True))

    def test_user_or_ip(self):
        """Allow custom functions to set cache keys."""

        def _req(auth):
            req = rf.post('/')
            req.user = MockUser(authenticated=auth)
            return req

        @ratelimit(key='user_or_ip', rate='1/m', block=False)
        def view(request):
            return request.limited

        assert not view(_req(auth=False))
        assert view(_req(auth=False))

        auth = rf.post('/')
        auth.user = MockUser(authenticated=True)

        assert not view(_req(auth=True))
        assert view(_req(auth=True))

    def test_callable_key_path(self):
        @ratelimit(key='django_ratelimit.tests.mykey', rate='1/m', block=False)
        def view(request):
            return request.limited

        assert not view(rf.post('/'))
        assert view(rf.post('/'))

    def test_callable_key(self):
        @ratelimit(key=mykey, rate='1/m', block=False)
        def view(request):
            return request.limited

        assert not view(rf.post('/'))
        assert view(rf.post('/'))

    def test_stacked_decorator(self):
        """Allow @ratelimit to be stacked."""
        # Put the shorter one first and make sure the second one doesn't
        # reset request.limited back to False.
        @ratelimit(rate='1/m', block=False, key=lambda x, y: 'min')
        @ratelimit(rate='10/d', block=False, key=lambda x, y: 'day')
        def view(request):
            return request.limited

        assert not view(rf.post('/'))
        assert view(rf.post('/'))

    def test_stacked_methods(self):
        """Different methods should result in different counts."""
        @ratelimit(rate='1/m', key='ip', method='GET', block=False)
        @ratelimit(rate='1/m', key='ip', method='POST', block=False)
        def view(request):
            return request.limited

        assert not view(rf.get('/'))
        assert not view(rf.post('/'))
        assert view(rf.get('/'))
        assert view(rf.post('/'))

    def test_sorted_methods(self):
        """Order of the methods shouldn't matter."""
        @ratelimit(rate='1/m', key='ip', method=['GET', 'POST'],
                   group='a', block=False)
        def get_post(request):
            return request.limited

        @ratelimit(rate='1/m', key='ip', method=['POST', 'GET'],
                   group='a', block=False)
        def post_get(request):
            return request.limited

        assert not get_post(rf.get('/'))
        assert post_get(rf.get('/'))

    def test_ratelimit_full_mask_v4(self):
        @ratelimit(rate='1/m', key='ip', block=False)
        def view(request):
            return request.limited

        with self.settings(RATELIMIT_IPV4_MASK=32):
            req = rf.get('/')
            req.META['REMOTE_ADDR'] = '10.1.1.1'
            assert not view(req)
            assert view(req)

            req = rf.get('/')
            req.META['REMOTE_ADDR'] = '10.1.1.2'
            assert not view(req)

    def test_ratelimit_full_mask_v6(self):
        @ratelimit(rate='1/m', key='ip', block=False)
        def view(request):
            return request.limited

        with self.settings(RATELIMIT_IPV6_MASK=128):
            req = rf.get('/')
            req.META['REMOTE_ADDR'] = '2001:db8::1000'
            assert not view(req)
            assert view(req)

            req = rf.get('/')
            req.META['REMOTE_ADDR'] = '2001:db8::1001'
            assert not view(req)

    def test_ratelimit_mask_v4(self):
        @ratelimit(rate='1/m', key='ip', block=False)
        def view(request):
            return request.limited

        with self.settings(RATELIMIT_IPV4_MASK=16):
            req = rf.get('/')
            req.META['REMOTE_ADDR'] = '10.1.1.1'
            assert not view(req)
            assert view(req)

            req = rf.get('/')
            req.META['REMOTE_ADDR'] = '10.1.0.1'
            assert view(req)

            req = rf.get('/')
            req.META['REMOTE_ADDR'] = '192.168.1.1'
            assert not view(req)

    def test_ratelimit_mask_v6(self):
        @ratelimit(rate='1/m', key='ip', block=False)
        def view(request):
            return request.limited

        with self.settings(RATELIMIT_IPV6_MASK=64):
            req = rf.get('/')
            req.META['REMOTE_ADDR'] = '2001:db8::1000'
            assert not view(req)
            assert view(req)

            req = rf.get('/')
            req.META['REMOTE_ADDR'] = '2001:db8::1001'
            assert view(req)

            req = rf.get('/')
            req.META['REMOTE_ADDR'] = '2001:db9::1000'
            assert not view(req)


class FunctionsTests(TestCase):
    def setUp(self):
        cache.clear()

    def test_is_ratelimited(self):
        not_increment = partial(is_ratelimited, increment=False, rate='1/m',
                                method=is_ratelimited.ALL, key='ip', group='a')

        # Does not increment. Count still 0. Does not rate limit
        # because 0 < 1.
        assert not not_increment(rf.get('/'))

        # Does not increment. Count still 1. Not limited because 1 > 1
        # is false.
        assert not not_increment(rf.get('/'))

    def test_is_ratelimited_increment(self):
        do_increment = partial(is_ratelimited, increment=True, rate='1/m',
                               method=is_ratelimited.ALL, key='ip', group='a')

        # Increments. Does not rate limit because 0 < 1. Count now 1.
        assert not do_increment(rf.get('/'))

        # Count = 2, 2 > 1.
        assert do_increment(rf.get('/'))

    def test_get_usage(self):
        _get_usage = partial(get_usage, method=get_usage.ALL, key='ip',
                             rate='1/m', group='a')
        usage = _get_usage(rf.get('/'))

        self.assertEqual(usage['count'], 0)
        self.assertEqual(usage['limit'], 1)
        self.assertLessEqual(usage['time_left'], 60)
        self.assertFalse(usage['should_limit'])

    def test_get_usage_increment(self):
        _get_usage = partial(get_usage, method=get_usage.ALL, key='ip',
                             rate='1/m', group='a', increment=True)
        _get_usage(rf.get('/'))
        usage = _get_usage(rf.get('/'))

        self.assertEqual(usage['count'], 2)
        self.assertEqual(usage['limit'], 1)
        self.assertLessEqual(usage['time_left'], 60)
        self.assertTrue(usage['should_limit'])

    def test_not_increment_after_increment(self):
        _get_usage = partial(get_usage, method=get_usage.ALL, key='ip',
                             rate='1/m', group='a')
        _get_usage(rf.get('/'), increment=True)
        _get_usage(rf.get('/'), increment=True)
        usage = _get_usage(rf.get('/'))

        self.assertEqual(usage['count'], 2)
        self.assertEqual(usage['limit'], 1)
        self.assertLessEqual(usage['time_left'], 60)
        self.assertTrue(usage['should_limit'])

    def test_get_usage_called_without_group_or_fn(self):
        with self.assertRaises(ImproperlyConfigured):
            get_usage(rf.get('/'), key='ip')


class RatelimitCBVTests(TestCase):
    def setUp(self):
        cache.clear()

    def test_method_decorator(self):
        class TestView(View):
            @method_decorator(ratelimit(key='ip', rate='1/m', block=False))
            def post(self, request):
                return request.limited

        view = TestView.as_view()

        assert not view(rf.post('/'))
        assert view(rf.post('/'))

    def test_class_decorator(self):
        @method_decorator(ratelimit(key='ip', rate='1/m', block=False),
                          name='get')
        class TestView(View):
            def get(self, request):
                return request.limited

        view = TestView.as_view()

        assert not view(rf.get('/'))
        assert view(rf.get('/'))

    def test_wrap_view(self):
        class TestView(View):
            def get(self, request):
                return request.limited

        view = TestView.as_view()
        wrapped = ratelimit(key='ip', rate='1/m', block=False)(view)

        assert not wrapped(rf.get('/'))
        assert wrapped(rf.get('/'))

    def test_methods_counted_separately(self):
        class TestView(View):
            @method_decorator(ratelimit(key='ip', rate='1/m',
                                        method='GET', block=False))
            def get(self, request):
                return request.limited

            @method_decorator(ratelimit(key='ip', rate='1/m',
                                        method='POST', block=False))
            def post(self, request):
                return request.limited

        view = TestView.as_view()

        assert not view(rf.get('/'))
        assert view(rf.get('/'))
        assert not view(rf.post('/'))

    def test_views_counted_separately(self):
        class TestView(View):
            @method_decorator(ratelimit(key='ip', rate='1/m',
                                        method='GET', block=False))
            def get(self, request):
                return request.limited

        class AnotherTestView(View):
            @method_decorator(ratelimit(key='ip', rate='1/m',
                                        method='GET', block=False))
            def get(self, request):
                return request.limited

        test_view = TestView.as_view()
        another_view = AnotherTestView.as_view()

        assert not test_view(rf.get('/'))
        assert test_view(rf.get('/'))
        assert not another_view(rf.get('/'))


class CacheFailTests(TestCase):
    @override_settings(RATELIMIT_USE_CACHE='fake-cache')
    def test_bad_cache(self):
        @ratelimit(key='ip', rate='1/m', block=False)
        def view(request):
            return request.limited

        with self.assertRaises(InvalidCacheBackendError):
            view(rf.post('/'))

    @override_settings(RATELIMIT_USE_CACHE='connection-errors')
    def test_limit_on_cache_connection_error(self):
        @ratelimit(key='ip', rate='10/m', block=False)
        def view(request):
            return request.limited

        assert view(rf.post('/'))

    @override_settings(RATELIMIT_USE_CACHE='connection-errors',
                       RATELIMIT_FAIL_OPEN=True)
    def test_fail_open_setting(self):
        @ratelimit(key='ip', rate='1/m', block=False)
        def view(request):
            return request.limited

        assert not view(rf.get('/'))
        assert not view(rf.get('/'))

    @override_settings(RATELIMIT_USE_CACHE='connection-errors')
    def test_is_ratelimited_cache_connection_error_without_increment(self):
        def not_increment(request):
            return is_ratelimited(request, increment=False,
                                  method=is_ratelimited.ALL, key='ip',
                                  rate='1/m', group='a')

        assert not not_increment(rf.get('/'))
        assert not not_increment(rf.get('/'))

    @override_settings(RATELIMIT_USE_CACHE='connection-errors')
    def test_is_ratelimited_cache_connection_error_with_increment(self):
        def do_increment(request):
            return is_ratelimited(request, increment=True,
                                  method=is_ratelimited.ALL, key='ip',
                                  rate='1/m', group='a')

        assert do_increment(rf.get('/'))
        assert do_increment(rf.get('/'))

    @override_settings(RATELIMIT_USE_CACHE='connection-errors-redis')
    def test_is_ratelimited_cache_connection_error_with_increment_redis(self):
        def do_increment(request):
            return is_ratelimited(request, increment=True,
                                  method=is_ratelimited.ALL, key='ip',
                                  rate='1/m', group='a')

        assert do_increment(rf.get('/'))
        assert do_increment(rf.get('/'))

    @override_settings(RATELIMIT_USE_CACHE='instant-expiration')
    def test_cache_timeout(self):
        @ratelimit(key='ip', rate='1/m')
        def view(request):
            return True

        assert view(rf.get('/'))
        assert view(rf.get('/'))


def my_ip(req):
    return req.META['MY_THING']


class IpMetaTests(TestCase):
    def test_default(self):
        req = rf.get('/')
        req.META['REMOTE_ADDR'] = '1.2.3.4'

        assert '1.2.3.4' == _get_ip(req)

    @override_settings(RATELIMIT_IP_META_KEY='fake')
    def test_bad_config(self):
        req = rf.get('/')
        req.META['REMOTE_ADDR'] = '1.2.3.4'

        with self.assertRaises(ImproperlyConfigured):
            _get_ip(req)

    @override_settings(RATELIMIT_IP_META_KEY='HTTP_X_CLIENT_IP')
    def test_alternate_header(self):
        req = rf.get('/')
        req.META['REMOTE_ADDR'] = '1.2.3.4'
        req.META['HTTP_X_CLIENT_IP'] = '5.6.7.8'

        assert '5.6.7.8' == _get_ip(req)

    @override_settings(RATELIMIT_IP_META_KEY='django_ratelimit.tests.my_ip')
    def test_path_to_ip_key_callable(self):
        req = rf.get('/')
        req.META['REMOTE_ADDR'] = '1.2.3.4'
        req.META['MY_THING'] = '5.6.7.8'

        assert '5.6.7.8' == _get_ip(req)

    @override_settings(RATELIMIT_IP_META_KEY=my_ip)
    def test_callable_ip_key(self):
        req = rf.get('/')
        req.META['REMOTE_ADDR'] = '1.2.3.4'
        req.META['MY_THING'] = '5.6.7.8'

        assert '5.6.7.8' == _get_ip(req)

    def test_empty_ip(self):
        req = rf.get('/')
        req.META['REMOTE_ADDR'] = ''

        with self.assertRaises(ImproperlyConfigured):
            _get_ip(req)


TRUSTED_PROXIES = ["10.0.0.1", "10.0.0.0/24", "2001:db8:1::/48"]
TRUSTED_PEER = "10.0.0.1"
UNTRUSTED_PEER = "203.0.113.9"
REAL_CLIENT = "198.51.100.7"


def _req(remote_addr=TRUSTED_PEER, meta=None):
    request = rf.get("/")
    request.META["REMOTE_ADDR"] = remote_addr
    if meta:
        request.META.update(meta)
    return request


class TrustedProxyClientIPTests(TestCase):
    def setUp(self):
        cache.clear()

    def _assert_fail_closed(self, request, **settings_overrides):
        overrides = dict(
            RATELIMIT_TRUSTED_PROXIES=TRUSTED_PROXIES,
            RATELIMIT_CLIENT_IP_HEADER="HTTP_X_FORWARDED_FOR",
        )
        overrides.update(settings_overrides)
        with self.settings(**overrides):
            with self.assertRaises(UnavailableClientIP):
                _get_ip(request)
            usage = get_usage(
                request, group="proxy", key="ip", rate="10/m",
                method=ALL, increment=True)
            self.assertTrue(usage["should_limit"])
            self.assertEqual(usage["count"], 0)
            self.assertEqual(usage["limit"], 0)

    def test_direct_connection_ignores_spoofed_forwarded_for(self):
        request = _req(
            UNTRUSTED_PEER,
            {"HTTP_X_FORWARDED_FOR": "1.2.3.4, 5.6.7.8"})
        with self.settings(
                RATELIMIT_TRUSTED_PROXIES=TRUSTED_PROXIES,
                RATELIMIT_CLIENT_IP_HEADER="HTTP_X_FORWARDED_FOR"):
            self.assertEqual(_get_ip(request), UNTRUSTED_PEER)

    def test_direct_connection_ignores_spoofed_real_ip(self):
        request = _req(
            UNTRUSTED_PEER,
            {"HTTP_X_REAL_IP": "1.2.3.4"})
        with self.settings(
                RATELIMIT_TRUSTED_PROXIES=TRUSTED_PROXIES,
                RATELIMIT_CLIENT_IP_HEADER="HTTP_X_REAL_IP"):
            self.assertEqual(_get_ip(request), UNTRUSTED_PEER)

    def test_trusted_proxy_single_real_ip(self):
        request = _req(meta={"HTTP_X_REAL_IP": REAL_CLIENT})
        with self.settings(
                RATELIMIT_TRUSTED_PROXIES=TRUSTED_PROXIES,
                RATELIMIT_CLIENT_IP_HEADER="HTTP_X_REAL_IP"):
            self.assertEqual(_get_ip(request), REAL_CLIENT)

    def test_trusted_proxy_multi_hop_walks_right_to_left(self):
        request = _req(meta={
            "HTTP_X_FORWARDED_FOR":
                "198.51.100.7, 10.0.0.5, 10.0.0.1",
        })
        with self.settings(
                RATELIMIT_TRUSTED_PROXIES=TRUSTED_PROXIES,
                RATELIMIT_CLIENT_IP_HEADER="HTTP_X_FORWARDED_FOR"):
            self.assertEqual(_get_ip(request), REAL_CLIENT)

    def test_forwarded_for_does_not_use_leftmost_value(self):
        request = _req(meta={
            "HTTP_X_FORWARDED_FOR":
                "1.2.3.4, 198.51.100.7, 10.0.0.1",
        })
        with self.settings(
                RATELIMIT_TRUSTED_PROXIES=TRUSTED_PROXIES,
                RATELIMIT_CLIENT_IP_HEADER="HTTP_X_FORWARDED_FOR"):
            self.assertEqual(_get_ip(request), REAL_CLIENT)

    def test_untrusted_hop_stops_the_walk(self):
        request = _req(meta={
            "HTTP_X_FORWARDED_FOR":
                "198.51.100.7, 203.0.113.50, 10.0.0.1",
        })
        with self.settings(
                RATELIMIT_TRUSTED_PROXIES=TRUSTED_PROXIES,
                RATELIMIT_CLIENT_IP_HEADER="HTTP_X_FORWARDED_FOR"):
            self.assertEqual(_get_ip(request), "203.0.113.50")

    def test_trusted_peer_without_header_uses_peer(self):
        request = _req()
        with self.settings(
                RATELIMIT_TRUSTED_PROXIES=TRUSTED_PROXIES,
                RATELIMIT_CLIENT_IP_HEADER="HTTP_X_REAL_IP"):
            self.assertEqual(_get_ip(request), TRUSTED_PEER)

    def test_single_value_header_with_comma_is_ambiguous(self):
        request = _req(meta={"HTTP_X_REAL_IP": "1.2.3.4, 5.6.7.8"})
        self._assert_fail_closed(
            request, RATELIMIT_CLIENT_IP_HEADER="HTTP_X_REAL_IP")

    def test_single_value_header_conflicts_with_forwarded_for(self):
        request = _req(meta={
            "HTTP_X_REAL_IP": REAL_CLIENT,
            "HTTP_X_FORWARDED_FOR": REAL_CLIENT,
        })
        self._assert_fail_closed(
            request, RATELIMIT_CLIENT_IP_HEADER="HTTP_X_REAL_IP")

    def test_ipv4_mapped_ipv6_normalizes_to_ipv4_key(self):
        mapped = _req(meta={
            "HTTP_X_REAL_IP": "::ffff:198.51.100.7",
        })
        native = _req(meta={"HTTP_X_REAL_IP": "198.51.100.7"})
        with self.settings(
                RATELIMIT_TRUSTED_PROXIES=TRUSTED_PROXIES,
                RATELIMIT_CLIENT_IP_HEADER="HTTP_X_REAL_IP"):
            self.assertEqual(_get_ip(mapped), _get_ip(native))
            self.assertEqual(_get_ip(mapped), REAL_CLIENT)

    def test_ipv6_case_and_compression_normalize_to_same_key(self):
        upper = _req(meta={
            "HTTP_X_REAL_IP": "2001:DB8:0:0:0:0:0:1",
        })
        compressed = _req(meta={"HTTP_X_REAL_IP": "2001:db8::1"})
        with self.settings(
                RATELIMIT_TRUSTED_PROXIES=TRUSTED_PROXIES,
                RATELIMIT_CLIENT_IP_HEADER="HTTP_X_REAL_IP",
                RATELIMIT_IPV6_MASK=128):
            self.assertEqual(_get_ip(upper), _get_ip(compressed))
            self.assertEqual(_get_ip(upper), "2001:db8::1")

    def test_empty_segment_in_forwarded_for_fails_closed(self):
        request = _req(meta={
            "HTTP_X_FORWARDED_FOR": "198.51.100.7, , 10.0.0.1",
        })
        self._assert_fail_closed(request)

    def test_trailing_empty_segment_fails_closed(self):
        request = _req(meta={
            "HTTP_X_FORWARDED_FOR": "198.51.100.7, 10.0.0.1,",
        })
        self._assert_fail_closed(request)

    def test_port_in_header_fails_closed(self):
        request = _req(meta={
            "HTTP_X_FORWARDED_FOR": "198.51.100.7:443, 10.0.0.1",
        })
        self._assert_fail_closed(request)

    def test_bracketed_ipv6_port_fails_closed(self):
        request = _req(meta={
            "HTTP_X_REAL_IP": "[2001:db8::1]:443",
        })
        self._assert_fail_closed(
            request, RATELIMIT_CLIENT_IP_HEADER="HTTP_X_REAL_IP")

    def test_ipv6_zone_fails_closed(self):
        request = _req(meta={
            "HTTP_X_REAL_IP": "fe80::1%eth0",
        })
        self._assert_fail_closed(
            request, RATELIMIT_CLIENT_IP_HEADER="HTTP_X_REAL_IP")

    def test_control_character_fails_closed(self):
        request = _req(meta={
            "HTTP_X_FORWARDED_FOR": "198.51.100.7\n, 10.0.0.1",
        })
        self._assert_fail_closed(request)

    def test_unparseable_address_fails_closed(self):
        request = _req(meta={
            "HTTP_X_FORWARDED_FOR": "not-an-ip, 10.0.0.1",
        })
        self._assert_fail_closed(request)

    def test_all_trusted_chain_fails_closed(self):
        request = _req(meta={
            "HTTP_X_FORWARDED_FOR": "10.0.0.2, 10.0.0.1",
        })
        self._assert_fail_closed(request)

    def test_chain_length_limit_fails_closed(self):
        hops = ["10.0.0.1"] * 65
        request = _req(meta={
            "HTTP_X_FORWARDED_FOR": ", ".join(hops),
        })
        self._assert_fail_closed(request)

    def test_long_chain_at_limit_is_accepted(self):
        hops = ["10.0.0.1"] * 63 + [REAL_CLIENT]
        request = _req(meta={
            "HTTP_X_FORWARDED_FOR": ", ".join(hops),
        })
        with self.settings(
                RATELIMIT_TRUSTED_PROXIES=TRUSTED_PROXIES,
                RATELIMIT_CLIENT_IP_HEADER="HTTP_X_FORWARDED_FOR"):
            self.assertEqual(_get_ip(request), REAL_CLIENT)

    def test_fail_open_does_not_allow_invalid_chain(self):
        request = _req(meta={
            "HTTP_X_FORWARDED_FOR": "198.51.100.7, , 10.0.0.1",
        })
        self._assert_fail_closed(request, RATELIMIT_FAIL_OPEN=True)

    @override_settings(RATELIMIT_USE_CACHE="connection-errors")
    def test_cache_failure_still_fails_closed_independently(self):
        @ratelimit(key="ip", rate="1/m", block=False)
        def view(request):
            return request.limited

        request = _req(meta={
            "HTTP_X_FORWARDED_FOR": "198.51.100.7, , 10.0.0.1",
        })
        with self.settings(
                RATELIMIT_TRUSTED_PROXIES=TRUSTED_PROXIES,
                RATELIMIT_CLIENT_IP_HEADER="HTTP_X_FORWARDED_FOR",
                RATELIMIT_FAIL_OPEN=True):
            self.assertTrue(view(request))

    def test_invalid_chain_raises_ratelimited_not_500(self):
        @ratelimit(key="ip", rate="10/m", block=True)
        def view(request):
            return True

        request = _req(meta={
            "HTTP_X_FORWARDED_FOR": "198.51.100.7, , 10.0.0.1",
        })
        with self.settings(
                RATELIMIT_TRUSTED_PROXIES=TRUSTED_PROXIES,
                RATELIMIT_CLIENT_IP_HEADER="HTTP_X_FORWARDED_FOR"):
            with self.assertRaises(Ratelimited):
                view(request)

    def test_spoofed_leftmost_values_cannot_escape_bucket(self):
        @ratelimit(key="ip", rate="1/m", block=False)
        def view(request):
            return request.limited

        with self.settings(
                RATELIMIT_TRUSTED_PROXIES=TRUSTED_PROXIES,
                RATELIMIT_CLIENT_IP_HEADER="HTTP_X_FORWARDED_FOR"):
            first = _req(meta={
                "HTTP_X_FORWARDED_FOR":
                    "1.1.1.1, 198.51.100.7, 10.0.0.1",
            })
            second = _req(meta={
                "HTTP_X_FORWARDED_FOR":
                    "2.2.2.2, 198.51.100.7, 10.0.0.1",
            })
            self.assertFalse(view(first))
            self.assertTrue(view(second))

    def test_ipv4_mask_still_applies_to_resolved_client(self):
        first = _req(meta={"HTTP_X_REAL_IP": "10.1.1.1"})
        second = _req(meta={"HTTP_X_REAL_IP": "10.1.2.2"})
        with self.settings(
                RATELIMIT_TRUSTED_PROXIES=TRUSTED_PROXIES,
                RATELIMIT_CLIENT_IP_HEADER="HTTP_X_REAL_IP",
                RATELIMIT_IPV4_MASK=16):
            self.assertEqual(_get_ip(first), _get_ip(second))
            self.assertEqual(_get_ip(first), "10.1.0.0")

    def test_ipv6_mask_still_applies_to_resolved_client(self):
        first = _req(meta={"HTTP_X_REAL_IP": "2001:db8::1000"})
        second = _req(meta={"HTTP_X_REAL_IP": "2001:db8::1001"})
        with self.settings(
                RATELIMIT_TRUSTED_PROXIES=TRUSTED_PROXIES,
                RATELIMIT_CLIENT_IP_HEADER="HTTP_X_REAL_IP",
                RATELIMIT_IPV6_MASK=64):
            self.assertEqual(_get_ip(first), _get_ip(second))

    def test_new_settings_take_precedence_over_meta_key(self):
        request = _req(meta={
            "HTTP_X_REAL_IP": REAL_CLIENT,
            "MY_THING": "5.6.7.8",
        })
        with self.settings(
                RATELIMIT_TRUSTED_PROXIES=TRUSTED_PROXIES,
                RATELIMIT_CLIENT_IP_HEADER="HTTP_X_REAL_IP",
                RATELIMIT_IP_META_KEY="MY_THING"):
            self.assertEqual(_get_ip(request), REAL_CLIENT)

    def test_legacy_meta_key_unchanged_when_new_settings_absent(self):
        request = _req(meta={"MY_THING": "5.6.7.8"})
        with self.settings(RATELIMIT_IP_META_KEY="MY_THING"):
            self.assertEqual(_get_ip(request), "5.6.7.8")

    def test_single_new_setting_does_not_enable_explicit_resolution(self):
        request = _req(
            UNTRUSTED_PEER,
            {"HTTP_X_FORWARDED_FOR": "1.2.3.4"})
        with self.settings(RATELIMIT_TRUSTED_PROXIES=TRUSTED_PROXIES):
            self.assertEqual(_get_ip(request), UNTRUSTED_PEER)

    def test_trusted_proxies_accepts_single_string(self):
        request = _req(meta={"HTTP_X_REAL_IP": REAL_CLIENT})
        with self.settings(
                RATELIMIT_TRUSTED_PROXIES="10.0.0.0/24",
                RATELIMIT_CLIENT_IP_HEADER="HTTP_X_REAL_IP"):
            self.assertEqual(_get_ip(request), REAL_CLIENT)


    def test_ipv6_trusted_proxy_resolves_forwarded_for(self):
        request = _req(
            remote_addr="2001:db8:1::5",
            meta={
                "HTTP_X_FORWARDED_FOR":
                    "198.51.100.7, 2001:db8:1::5",
            })
        with self.settings(
                RATELIMIT_TRUSTED_PROXIES=TRUSTED_PROXIES,
                RATELIMIT_CLIENT_IP_HEADER="HTTP_X_FORWARDED_FOR"):
            self.assertEqual(_get_ip(request), REAL_CLIENT)

    def test_mapped_peer_matches_ipv4_trusted_network(self):
        request = _req(
            remote_addr="::ffff:10.0.0.1",
            meta={"HTTP_X_REAL_IP": REAL_CLIENT})
        with self.settings(
                RATELIMIT_TRUSTED_PROXIES=TRUSTED_PROXIES,
                RATELIMIT_CLIENT_IP_HEADER="HTTP_X_REAL_IP"):
            self.assertEqual(_get_ip(request), REAL_CLIENT)

    def test_invalid_trusted_proxy_configuration(self):
        request = _req()
        with self.settings(
                RATELIMIT_TRUSTED_PROXIES=["not-a-network"],
                RATELIMIT_CLIENT_IP_HEADER="HTTP_X_REAL_IP"):
            with self.assertRaises(ImproperlyConfigured):
                _get_ip(request)
