import time
from unittest import TestCase
from unittest.mock import patch
from urllib.parse import urlsplit

from lib.connection.requester import Requester
from lib.core.dictionary import Dictionary
from lib.core.discovery_config import DiscoveryConfig
from lib.core.execution_config import ExecutionConfig
from lib.core.filter_config import FilterConfig
from lib.core.fuzzer import Fuzzer
from lib.core.option_defaults import default_options
from lib.core.request_config import RequestConfig
from lib.core.wordlist_config import WordlistConfig


class FakeOriginResponse:
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


def simulated_target_send(prep, **kwargs):
    """Simulated target: one throttled path, one real hit, 404 otherwise."""
    path = urlsplit(str(prep.url)).path
    if path.startswith("/limited"):
        return FakeOriginResponse(429, [("retry-after", "1")], b"slow down")
    if path.startswith("/found"):
        return FakeOriginResponse(
            200, [("content-type", "text/html")], b"secret admin panel"
        )
    return FakeOriginResponse(404, [], b"not found")


class TestFuzzerRateLimitFiltering(TestCase):
    def make_options(self):
        options = default_options()
        options.update(
            {
                "proxies": [],
                "headers": {},
                "data": None,
                "cert_file": None,
                "key_file": None,
                "network_interface": None,
                "random_agents": False,
                "auth": None,
                "auth_type": None,
                "max_retries": 0,
                "max_rate": 0,
                "thread_count": 1,
                "follow_redirects": False,
                "http_method": "GET",
                "timeout": 5,
                "proxy_auth": None,
                "delay": 0,
                "exclude_response": None,
                "exclude_status_codes": set(),
                "include_status_codes": set(),
                "exclude_sizes": set(),
                "minimum_response_size": 0,
                "maximum_response_size": 0,
                "exclude_texts": [],
                "exclude_regex": None,
                "exclude_redirect": None,
                "filter_threshold": 0,
                "prefixes": (),
                "suffixes": (),
                "extensions": (),
            }
        )
        return options

    def test_rate_limited_responses_never_become_hits(self):
        options = self.make_options()
        requester = Requester(RequestConfig.from_options(options))
        requester.set_url("http://target.test/")
        dictionary = Dictionary(WordlistConfig.from_options(options))
        dictionary.__setstate__((["limited", "found"], 0, [], 0))
        matches = []
        misses = []
        errors = []
        fuzzer = Fuzzer(
            requester,
            dictionary,
            filter_config=FilterConfig.from_options(options),
            discovery_config=DiscoveryConfig.from_options(options),
            execution_config=ExecutionConfig.from_options(options),
            match_callbacks=(matches.append,),
            not_found_callbacks=(misses.append,),
            error_callbacks=(errors.append,),
        )

        throttle = requester._throttle
        with (
            patch.object(
                requester.session, "send", side_effect=simulated_target_send
            ),
            patch.object(
                throttle, "record_response", wraps=throttle.record_response
            ) as record_spy,
        ):
            fuzzer.start()
            while not fuzzer.is_finished():
                time.sleep(0.05)
        requester.close()

        # The throttled path is excluded from hits and routed to misses.
        self.assertEqual([response.full_path for response in matches], ["found"])
        self.assertIn("limited", [response.full_path for response in misses])
        self.assertEqual(errors, [])
        # The scheduler observed the 429 + Retry-After signal and engaged.
        self.assertIn((429, "1"), [call.args for call in record_spy.call_args_list])
        self.assertTrue(
            any(call.return_value is not None for call in record_spy.mock_calls)
        )
