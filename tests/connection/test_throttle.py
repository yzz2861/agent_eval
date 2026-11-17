import threading
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import patch
from urllib.parse import urlsplit

from lib.connection.requester import AsyncRequester, Requester
from lib.connection.throttle import (
    AdaptiveThrottle,
    is_rate_limit_signal,
    parse_retry_after,
)
from lib.core.option_defaults import default_options
from lib.core.request_config import RequestConfig
from lib.core.settings import RATE_LIMIT_BACKOFF_MAX


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, delay: float) -> None:
        self.sleeps.append(delay)
        self.now += delay

    async def sleep_async(self, delay: float) -> None:
        self.sleep(delay)


class TestParseRetryAfter(TestCase):
    def test_delta_seconds(self):
        self.assertEqual(parse_retry_after("5"), 5.0)

    def test_delta_seconds_with_whitespace(self):
        self.assertEqual(parse_retry_after(" 3 "), 3.0)

    def test_http_date(self):
        delay = parse_retry_after("Wed, 21 Oct 2099 07:28:00 GMT")
        self.assertIsNotNone(delay)
        self.assertGreater(delay, 0)

    def test_past_http_date(self):
        self.assertIsNone(parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT"))

    def test_invalid_value(self):
        self.assertIsNone(parse_retry_after("soon"))

    def test_missing_value(self):
        self.assertIsNone(parse_retry_after(None))
        self.assertIsNone(parse_retry_after(""))

    def test_huge_delta_is_clamped(self):
        self.assertEqual(parse_retry_after("999999"), RATE_LIMIT_BACKOFF_MAX)


class TestRateLimitSignal(TestCase):
    def test_throttling_statuses(self):
        self.assertTrue(is_rate_limit_signal(429, None))
        self.assertTrue(is_rate_limit_signal(503, None))

    def test_retry_after_header_is_a_signal(self):
        self.assertTrue(is_rate_limit_signal(200, "5"))

    def test_normal_response(self):
        self.assertFalse(is_rate_limit_signal(200, None))
        self.assertFalse(is_rate_limit_signal(404, None))


class TestAdaptiveThrottle(TestCase):
    def make_throttle(self, max_concurrency=4):
        clock = FakeClock()
        throttle = AdaptiveThrottle(
            max_concurrency,
            clock=clock,
            sleep=clock.sleep,
            async_sleep=clock.sleep_async,
        )
        return throttle, clock

    def test_initial_state_allows_full_concurrency(self):
        throttle, _ = self.make_throttle()
        self.assertEqual(throttle.limit, 4)
        self.assertEqual(throttle.interval, 0.0)
        self.assertFalse(throttle.throttled)

    def test_rate_limit_response_halves_concurrency_and_backs_off(self):
        throttle, clock = self.make_throttle()

        delay = throttle.record_response(429, None)

        self.assertEqual(delay, 1.0)
        self.assertEqual(throttle.limit, 2)
        self.assertTrue(throttle.throttled)

        throttle.acquire()
        throttle.release()
        # The first start after the signal waits out the backoff window.
        self.assertAlmostEqual(sum(clock.sleeps), 1.0)
        # A second start must also respect the minimum request interval.
        throttle.acquire()
        self.assertAlmostEqual(sum(clock.sleeps), 2.0)

    def test_retry_after_extends_backoff(self):
        throttle, _ = self.make_throttle()

        delay = throttle.record_response(429, "10")

        self.assertEqual(delay, 10.0)

    def test_backoff_grows_exponentially_on_repeated_signals(self):
        throttle, _ = self.make_throttle()

        self.assertEqual(throttle.record_response(429, None), 1.0)
        self.assertEqual(throttle.record_response(503, None), 2.0)
        self.assertEqual(throttle.record_response(429, None), 4.0)
        self.assertEqual(throttle.limit, 1)

    def test_successful_responses_recover_gradually(self):
        throttle, _ = self.make_throttle()
        throttle.record_response(429, None)
        throttle.record_response(429, None)
        self.assertEqual(throttle.limit, 1)

        self.assertIsNone(throttle.record_response(200, None))
        self.assertEqual(throttle.limit, 2)
        throttle.record_response(200, None)
        throttle.record_response(200, None)
        throttle.record_response(200, None)
        self.assertEqual(throttle.limit, 4)
        self.assertFalse(throttle.throttled)

    def test_concurrency_cap_blocks_until_release(self):
        throttle, _ = self.make_throttle(max_concurrency=1)
        throttle.acquire()

        acquired = threading.Event()
        waiter = threading.Thread(
            target=lambda: (throttle.acquire(), acquired.set())
        )
        waiter.start()
        self.assertFalse(acquired.wait(timeout=0.2))

        throttle.release()
        # The waiter polls the clock; let it observe the released slot.
        waiter.join(timeout=1)
        self.assertTrue(acquired.is_set())
        throttle.release()

    def test_reset_restores_initial_state(self):
        throttle, _ = self.make_throttle()
        throttle.record_response(429, "10")

        throttle.reset()

        self.assertEqual(throttle.limit, 4)
        self.assertEqual(throttle.interval, 0.0)
        self.assertFalse(throttle.throttled)


class TestAdaptiveThrottleAsync(IsolatedAsyncioTestCase):
    async def test_async_acquire_waits_out_backoff(self):
        clock = FakeClock()
        throttle = AdaptiveThrottle(
            2,
            clock=clock,
            sleep=clock.sleep,
            async_sleep=clock.sleep_async,
        )
        throttle.record_response(429, None)

        await throttle.acquire_async()
        throttle.release()
        self.assertAlmostEqual(sum(clock.sleeps), 1.0)
        await throttle.acquire_async()
        throttle.release()

        self.assertAlmostEqual(sum(clock.sleeps), 2.0)


class FakeSyncOriginResponse:
    """Scripted origin response for the requests transport."""

    def __init__(self, status, headers=(), body=b"ok"):
        self.status_code = status
        self.headers = dict(headers)
        self.history = []
        self.encoding = "utf-8"
        self.url = "http://target.test/"
        self._body = body
        self.closed = False

    def iter_content(self, chunk_size):
        yield self._body

    def close(self):
        self.closed = True


class FakeAsyncHeaders:
    def __init__(self, items):
        self._items = list(items)

    def multi_items(self):
        return list(self._items)


class FakeAsyncOriginResponse:
    """Scripted origin response for the httpx transport."""

    def __init__(self, status, headers=(), body=b"ok"):
        self.status_code = status
        self.headers = FakeAsyncHeaders(headers)
        self.history = []
        self.encoding = "utf-8"
        self.url = "http://target.test/"
        self._body = body

    async def aiter_bytes(self, chunk_size):
        yield self._body

    async def aclose(self):
        pass


def simulated_target_response(path):
    """Response plan for a target that throttles selected paths."""
    if path.startswith("/limited"):
        return 429, [("retry-after", "2")], b"too many requests"
    if path.startswith("/degraded"):
        return 503, [("retry-after", "1")], b"unavailable"
    if path.startswith("/error"):
        return 503, [], b"backend failure"
    return 200, [], b"ok"


def make_options():
    options = default_options()
    options["proxies"] = []
    options["headers"] = {}
    options["data"] = None
    options["cert_file"] = None
    options["key_file"] = None
    options["network_interface"] = None
    options["random_agents"] = False
    options["auth"] = None
    options["auth_type"] = None
    options["max_retries"] = 0
    options["max_rate"] = 0
    options["thread_count"] = 4
    options["follow_redirects"] = False
    options["http_method"] = "GET"
    options["timeout"] = 5
    options["proxy_auth"] = None
    return options


def install_fake_throttle(requester):
    clock = FakeClock()
    requester._throttle = AdaptiveThrottle(
        requester.config.concurrency,
        clock=clock,
        sleep=clock.sleep,
        async_sleep=clock.sleep_async,
    )
    return clock


class TestRequesterAdaptiveThrottle(TestCase):
    def setUp(self):
        self.requester = Requester(RequestConfig.from_options(make_options()))
        self.clock = install_fake_throttle(self.requester)
        self.requester.set_url("http://target.test/")
        self.addCleanup(self.requester.close)

    def simulated_send(self, prep, **kwargs):
        path = urlsplit(str(prep.url)).path
        status, headers, body = simulated_target_response(path)
        return FakeSyncOriginResponse(status, headers, body)

    def test_429_response_triggers_backoff_and_marks_response(self):
        with patch.object(
            self.requester.session, "send", side_effect=self.simulated_send
        ):
            response = self.requester.request("limited")
            self.assertEqual(response.status, 429)
            self.assertTrue(response.is_rate_limited)
            self.assertLess(self.requester._throttle.limit, 4)

            # The next request waits out the Retry-After delay before starting.
            follow_up = self.requester.request("other")
            self.assertEqual(follow_up.status, 200)
            self.assertFalse(follow_up.is_rate_limited)
            self.assertAlmostEqual(sum(self.clock.sleeps), 2.0)

    def test_throttle_state_resets_when_target_changes(self):
        with patch.object(
            self.requester.session, "send", side_effect=self.simulated_send
        ):
            self.requester.request("limited")
            self.assertTrue(self.requester._throttle.throttled)

        self.requester.set_url("http://other.test/")
        self.assertFalse(self.requester._throttle.throttled)
        self.assertEqual(self.requester._throttle.limit, 4)

    def test_503_without_retry_after_stays_reportable(self):
        with patch.object(
            self.requester.session, "send", side_effect=self.simulated_send
        ):
            response = self.requester.request("error")
            self.assertEqual(response.status, 503)
            self.assertFalse(response.is_rate_limited)
            # The scheduler still slows down on a bare 503.
            self.assertTrue(self.requester._throttle.throttled)


class TestAsyncRequesterAdaptiveThrottle(IsolatedAsyncioTestCase):
    async def test_async_requester_backs_off_on_retry_after(self):
        requester = AsyncRequester(RequestConfig.from_options(make_options()))
        clock = install_fake_throttle(requester)
        requester.set_url("http://target.test/")

        async def simulated_send(request, **kwargs):
            status, headers, body = simulated_target_response(request.url.path)
            return FakeAsyncOriginResponse(status, headers, body)

        try:
            with patch.object(requester.session, "send", side_effect=simulated_send):
                response = await requester.request("degraded")
                self.assertEqual(response.status, 503)
                self.assertTrue(response.is_rate_limited)
                self.assertLess(requester._throttle.limit, 4)

                follow_up = await requester.request("other")
                self.assertEqual(follow_up.status, 200)
                self.assertAlmostEqual(sum(clock.sleeps), 1.0)
        finally:
            await requester.close()
