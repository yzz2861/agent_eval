from datetime import timedelta
from hashlib import sha256
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.test import RequestFactory, override_settings

from axes.apps import AppConfig
from axes.conf import LockoutTier
from axes.helpers import (
    cleanse_parameters,
    get_cache_timeout,
    get_client_cache_keys,
    get_client_ip_address,
    get_client_parameters,
    get_client_str,
    get_client_username,
    get_cool_off,
    get_cool_off_iso8601,
    get_lockout_response,
    get_username_from_data,
    get_lockout_tier,
    is_client_ip_address_blacklisted,
    is_client_ip_address_whitelisted,
    is_client_method_whitelisted,
    is_ip_address_in_blacklist,
    is_ip_address_in_whitelist,
    is_user_attempt_whitelisted,
    set_retry_after_header,
    toggleable,
)
from axes.helpers import (
    UsernameNormalizationError,
    get_raw_client_username,
    get_unresolved_username_bucket,
    get_username_audit_category,
    get_username_audit_fingerprint,
    get_username_normalization_rules,
    normalize_username,
)
from axes.models import AccessAttempt, AccessBase
from tests.base import AxesTestCase


@override_settings(AXES_ENABLED=False)
class AxesDisabledTestCase(AxesTestCase):
    def test_initialize(self):
        AppConfig.logging_initialized = False
        AppConfig.initialize()
        self.assertFalse(AppConfig.logging_initialized)

    def test_toggleable(self):
        def is_true():
            return True

        self.assertTrue(is_true())
        self.assertIsNone(toggleable(is_true)())


class CacheTestCase(AxesTestCase):
    @override_settings(AXES_COOLOFF_TIME=3)  # hours
    def test_get_cache_timeout_integer(self):
        timeout_seconds = float(60 * 60 * 3)
        self.assertEqual(get_cache_timeout(), timeout_seconds)

    @override_settings(AXES_COOLOFF_TIME=timedelta(seconds=420))
    def test_get_cache_timeout_timedelta(self):
        self.assertEqual(get_cache_timeout(), 420)

    @override_settings(AXES_COOLOFF_TIME=None)
    def test_get_cache_timeout_none(self):
        self.assertEqual(get_cache_timeout(), None)

    def test_get_increasing_cache_timeout_by_username(self):
        user_durations = {
            "ben": timedelta(minutes=5),
            "jen": timedelta(minutes=10),
        }

        def _callback(request):
            username = request.POST["username"] if request else object()
            previous_duration = user_durations.get(username, timedelta())
            user_durations[username] = previous_duration + timedelta(minutes=5)
            return user_durations[username]

        rf = RequestFactory()
        ben_req = rf.post("/", data={"username": "ben"})
        jen_req = rf.post("/", data={"username": "jen"})
        james_req = rf.post("/", data={"username": "james"})

        with override_settings(AXES_COOLOFF_TIME=_callback):
            with self.subTest("no username"):
                self.assertEqual(get_cache_timeout(), 300)

            with self.subTest("ben"):
                self.assertEqual(get_cache_timeout(ben_req), 600)
                self.assertEqual(get_cache_timeout(ben_req), 900)
                self.assertEqual(get_cache_timeout(ben_req), 1200)

            with self.subTest("jen"):
                self.assertEqual(get_cache_timeout(jen_req), 900)

            with self.subTest("james"):
                self.assertEqual(get_cache_timeout(james_req), 300)


class TimestampTestCase(AxesTestCase):
    def test_iso8601(self):
        """
        Test get_cool_off_iso8601 correctly translates datetime.timedelta to ISO 8601 formatted duration.
        """

        expected = {
            timedelta(days=1, hours=25, minutes=42, seconds=8): "P2DT1H42M8S",
            timedelta(days=7, seconds=342): "P7DT5M42S",
            timedelta(days=0, hours=2, minutes=42): "PT2H42M",
            timedelta(hours=20, seconds=42): "PT20H42S",
            timedelta(seconds=300): "PT5M",
            timedelta(seconds=9005): "PT2H30M5S",
            timedelta(minutes=9005): "P6DT6H5M",
            timedelta(days=15): "P15D",
        }

        for delta, iso_duration in expected.items():
            with self.subTest(iso_duration):
                self.assertEqual(get_cool_off_iso8601(delta), iso_duration)


@override_settings(AXES_SENSITIVE_PARAMETERS=[])
class ClientStringTestCase(AxesTestCase):
    @staticmethod
    def get_expected_client_str(*args, **kwargs):
        client_str_template = '{{username: "{0}", ip_address: "{1}", user_agent: "{2}", path_info: "{3}"}}'
        return client_str_template.format(*args, **kwargs)

    @override_settings(AXES_VERBOSE=True)
    def test_verbose_ip_only_client_details(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = self.get_expected_client_str(
            username, ip_address, user_agent, path_info, self.request
        )
        actual = get_client_str(
            username, ip_address, user_agent, path_info, self.request
        )

        self.assertEqual(expected, actual)

    @override_settings(AXES_VERBOSE=True)
    def test_imbalanced_quotes(self):
        username = "butterfly.. },,,"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = self.get_expected_client_str(
            username, ip_address, user_agent, path_info, self.request
        )
        actual = get_client_str(
            username, ip_address, user_agent, path_info, self.request
        )

        self.assertEqual(expected, actual)

    @override_settings(AXES_VERBOSE=True)
    def test_verbose_ip_only_client_details_tuple(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = ("admin", "login")

        expected = self.get_expected_client_str(
            username, ip_address, user_agent, path_info[0], self.request
        )
        actual = get_client_str(
            username, ip_address, user_agent, path_info, self.request
        )

        self.assertEqual(expected, actual)

    @override_settings(AXES_VERBOSE=False)
    def test_non_verbose_ip_only_client_details(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = '{ip_address: "127.0.0.1", path_info: "/admin/"}'
        actual = get_client_str(
            username, ip_address, user_agent, path_info, self.request
        )

        self.assertEqual(expected, actual)

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username"])
    @override_settings(AXES_VERBOSE=True)
    def test_verbose_user_only_client_details(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = self.get_expected_client_str(
            username, ip_address, user_agent, path_info, self.request
        )
        actual = get_client_str(
            username, ip_address, user_agent, path_info, self.request
        )

        self.assertEqual(expected, actual)

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username"])
    @override_settings(AXES_VERBOSE=False)
    def test_non_verbose_user_only_client_details(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = '{username: "test@example.com", path_info: "/admin/"}'
        actual = get_client_str(
            username, ip_address, user_agent, path_info, self.request
        )

        self.assertEqual(expected, actual)

    @override_settings(AXES_LOCKOUT_PARAMETERS=[["username", "ip_address"]])
    @override_settings(AXES_VERBOSE=True)
    def test_verbose_user_ip_combo_client_details(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = self.get_expected_client_str(
            username, ip_address, user_agent, path_info, self.request
        )
        actual = get_client_str(
            username, ip_address, user_agent, path_info, self.request
        )

        self.assertEqual(expected, actual)

    @override_settings(AXES_LOCKOUT_PARAMETERS=[["username", "ip_address"]])
    @override_settings(AXES_VERBOSE=False)
    def test_non_verbose_user_ip_combo_client_details(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = '{username: "test@example.com", ip_address: "127.0.0.1", path_info: "/admin/"}'
        actual = get_client_str(
            username, ip_address, user_agent, path_info, self.request
        )

        self.assertEqual(expected, actual)

    @override_settings(AXES_LOCKOUT_PARAMETERS=[["ip_address", "user_agent"]])
    @override_settings(AXES_VERBOSE=True)
    def test_verbose_user_agent_client_details(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = self.get_expected_client_str(
            username, ip_address, user_agent, path_info, self.request
        )
        actual = get_client_str(
            username, ip_address, user_agent, path_info, self.request
        )

        self.assertEqual(expected, actual)

    @override_settings(AXES_LOCKOUT_PARAMETERS=[["ip_address", "user_agent"]])
    @override_settings(AXES_VERBOSE=False)
    def test_non_verbose_user_agent_client_details(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = '{ip_address: "127.0.0.1", user_agent: "Googlebot/2.1 (+http://www.googlebot.com/bot.html)", path_info: "/admin/"}'
        actual = get_client_str(
            username, ip_address, user_agent, path_info, self.request
        )

        self.assertEqual(expected, actual)

    @override_settings(
        AXES_CLIENT_STR_CALLABLE="tests.test_helpers.get_dummy_client_str"
    )
    def test_get_client_str_callable_return_str(self):
        self.assertEqual(
            get_client_str(
                "username", "ip_address", "user_agent", "path_info", self.request
            ),
            "client string",
        )

    @override_settings(
        AXES_CLIENT_STR_CALLABLE="tests.test_helpers.get_dummy_client_str_using_request"
    )
    def test_get_client_str_callable_using_request(self):
        self.request.user = self.user
        self.assertEqual(
            get_client_str(
                "username", "ip_address", "user_agent", "path_info", self.request
            ),
            self.email,
        )

    @override_settings(AXES_SENSITIVE_PARAMETERS=["username"])
    def test_get_client_str_with_sensitive_parameters(self):
        username = "test@example.com"
        ip_address = "127.0.0.1"
        user_agent = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
        path_info = "/admin/"

        expected = self.get_expected_client_str(
            "********************",
            ip_address,
            user_agent,
            path_info,
            self.request
        )
        actual = get_client_str(
            username, ip_address, user_agent, path_info, self.request
        )

        self.assertEqual(expected, actual)


def get_dummy_client_str(username, ip_address, user_agent, path_info, request):
    return "client string"


def get_dummy_client_str_using_request(
    username, ip_address, user_agent, path_info, request
):
    return f"{request.user.email}"


def get_dummy_lockout_parameters(request, credentials=None):
    return ["ip_address", ["username", "user_agent"]]


class ClientParametersTestCase(AxesTestCase):
    @override_settings(AXES_LOCKOUT_PARAMETERS=["username"])
    def test_get_filter_kwargs_user(self):
        self.assertEqual(
            get_client_parameters(self.username, self.ip_address, self.user_agent, self.request, self.credentials),
            [{"username": self.username}],
        )

    def test_get_filter_kwargs_ip(self):
        self.assertEqual(
            get_client_parameters(self.username, self.ip_address, self.user_agent, self.request, self.credentials),
            [{"ip_address": self.ip_address}],
        )

    @override_settings(AXES_LOCKOUT_PARAMETERS=[["username", "ip_address"]])
    def test_get_filter_kwargs_user_and_ip(self):
        self.assertEqual(
            get_client_parameters(self.username, self.ip_address, self.user_agent, self.request, self.credentials),
            [{"username": self.username, "ip_address": self.ip_address}],
        )

    @override_settings(AXES_LOCKOUT_PARAMETERS=[["username", "user_agent"]])
    def test_get_filter_kwargs_user_and_user_agent(self):
        self.assertEqual(
            get_client_parameters(self.username, self.ip_address, self.user_agent, self.request, self.credentials),
            [{"username": self.username, "user_agent": self.user_agent}],
        )

    @override_settings(AXES_LOCKOUT_PARAMETERS=["ip_address", ["username", "user_agent"]])
    def test_get_filter_kwargs_ip_or_user_and_user_agent(self):
        self.assertEqual(
            get_client_parameters(self.username, self.ip_address, self.user_agent, self.request, self.credentials),
            [{"ip_address": self.ip_address}, {"username": self.username, "user_agent": self.user_agent}],
        )

    @override_settings(AXES_LOCKOUT_PARAMETERS=[["ip_address", "user_agent"], ["username", "user_agent"]])
    def test_get_filter_kwargs_ip_and_user_agent_or_user_and_user_agent(self):
        self.assertEqual(
            get_client_parameters(self.username, self.ip_address, self.user_agent, self.request, self.credentials),
            [{"ip_address": self.ip_address, "user_agent": self.user_agent}, {"username": self.username, "user_agent": self.user_agent}],
        )

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username", "ip_address"])
    def test_get_filter_kwargs_user_or_ip(self):
        self.assertEqual(
            get_client_parameters(self.username, self.ip_address, self.user_agent, self.request, self.credentials),
            [{"username": self.username}, {"ip_address": self.ip_address}],
        )

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username", "ip_address", "user_agent"])
    def test_get_filter_kwargs_user_or_ip_or_user_agent(self):
        self.assertEqual(
            get_client_parameters(self.username, self.ip_address, self.user_agent, self.request, self.credentials),
            [{"username": self.username}, {"ip_address": self.ip_address}, {"user_agent": self.user_agent}],
        )

    @override_settings(AXES_LOCKOUT_PARAMETERS=[["ip_address", "user_agent"]])
    def test_get_filter_kwargs_ip_and_agent(self):
        self.assertEqual(
            get_client_parameters(self.username, self.ip_address, self.user_agent, self.request, self.credentials),
            [{"ip_address": self.ip_address, "user_agent": self.user_agent}],
        )

    @override_settings(
        AXES_LOCKOUT_PARAMETERS=[["username", "ip_address", "user_agent"]]
    )
    def test_get_filter_kwargs_user_ip_agent(self):
        self.assertEqual(
            get_client_parameters(self.username, self.ip_address, self.user_agent, self.request, self.credentials),
            [
                {
                    "username": self.username,
                    "ip_address": self.ip_address,
                    "user_agent": self.user_agent,
                },
            ],
        )

    @override_settings(AXES_LOCKOUT_PARAMETERS=["wrong_param"])
    @patch("axes.helpers.log")
    def test_get_filter_kwargs_invalid_parameter(self, log):
        with self.assertRaises(ValueError):
            get_client_parameters(
                self.username,
                self.ip_address,
                self.user_agent,
                self.request,
                self.credentials,
            )
            log.exception.assert_called_with(
                (
                    "wrong_param lockout parameter is not allowed. "
                    "Allowed lockout parameters: username, ip_address, user_agent"
                )
            )

    @override_settings(AXES_LOCKOUT_PARAMETERS=[["ip_address", "wrong_param"]])
    @patch("axes.helpers.log")
    def test_get_filter_kwargs_invalid_combined_parameter(self, log):
        with self.assertRaises(ValueError):
            get_client_parameters(
                self.username,
                self.ip_address,
                self.user_agent,
                self.request,
                self.credentials,
            )
            log.exception.assert_called_with(
                (
                    "wrong_param lockout parameter is not allowed. "
                    "Allowed lockout parameters: username, ip_address, user_agent"
                )
            )

    @override_settings(AXES_LOCKOUT_PARAMETERS=get_dummy_lockout_parameters)
    def test_get_filter_kwargs_callable_lockout_parameters(self):
        self.assertEqual(
            get_client_parameters(
                self.username,
                self.ip_address,
                self.user_agent,
                self.request,
                self.credentials,
            ),
            [
                {
                    "ip_address": self.ip_address,
                },
                {
                    "username": self.username,
                    "user_agent": self.user_agent,
                },
            ],
        )

    @override_settings(
        AXES_LOCKOUT_PARAMETERS="tests.test_helpers.get_dummy_lockout_parameters"
    )
    def test_get_filter_kwargs_callable_str_lockout_parameters(self):
        self.assertEqual(
            get_client_parameters(
                self.username,
                self.ip_address,
                self.user_agent,
                self.request,
                self.credentials,
            ),
            [
                {
                    "ip_address": self.ip_address,
                },
                {
                    "username": self.username,
                    "user_agent": self.user_agent,
                },
            ],
        )

    @override_settings(
        AXES_LOCKOUT_PARAMETERS=lambda request, credentials: ["username"]
    )
    def test_get_filter_kwargs_callable_lambda_lockout_parameters(self):
        self.assertEqual(
            get_client_parameters(
                self.username,
                self.ip_address,
                self.user_agent,
                self.request,
                self.credentials,
            ),
            [
                {
                    "username": self.username,
                },
            ],
        )

    @override_settings(AXES_LOCKOUT_PARAMETERS=True)
    def test_get_filter_kwargs_not_list_or_callable(self):
        with self.assertRaises(TypeError):
            get_client_parameters(
                self.username,
                self.ip_address,
                self.user_agent,
                self.request,
                self.credentials,
            )

    @override_settings(AXES_LOCKOUT_PARAMETERS=lambda: None)
    def test_get_filter_kwargs_invalid_callable_too_few_arguments(self):
        with self.assertRaises(TypeError):
            get_client_parameters(
                self.username,
                self.ip_address,
                self.user_agent,
                self.request,
                self.credentials,
            )

    @override_settings(AXES_LOCKOUT_PARAMETERS=lambda request, credentials, extra: None)
    def test_get_filter_kwargs_invalid_callable_too_many_arguments(self):
        with self.assertRaises(TypeError):
            get_client_parameters(
                self.username,
                self.ip_address,
                self.user_agent,
                self.request,
                self.credentials,
            )

    @override_settings(
        AXES_LOCKOUT_PARAMETERS=lambda request, credentials: ["wrong_param"]
    )
    @patch("axes.helpers.log")
    def test_get_filter_kwargs_callable_invalid_lockout_param(self, log):
        with self.assertRaises(ValueError):
            get_client_parameters(
                self.username,
                self.ip_address,
                self.user_agent,
                self.request,
                self.credentials,
            )
            log.exception.assert_called_with(
                (
                    "wrong_param lockout parameter is not allowed. "
                    "Allowed lockout parameters: username, ip_address, user_agent"
                )
            )

    @override_settings(
        AXES_LOCKOUT_PARAMETERS=lambda request, credentials: [
            ["ip_address", "wrong_param"]
        ]
    )
    @patch("axes.helpers.log")
    def test_get_filter_kwargs_callable_invalid_combined_lockout_param(self, log):
        with self.assertRaises(ValueError):
            get_client_parameters(
                self.username,
                self.ip_address,
                self.user_agent,
                self.request,
                self.credentials,
            )
            log.exception.assert_called_with(
                (
                    "wrong_param lockout parameter is not allowed. "
                    "Allowed lockout parameters: username, ip_address, user_agent"
                )
            )


class ClientCacheKeyTestCase(AxesTestCase):
    def test_get_cache_keys(self):
        """
        Test the cache key format.
        """

        cache_hash_digest = sha256(self.ip_address.encode()).hexdigest()
        cache_hash_key = f"axes-{cache_hash_digest}"

        # Getting cache key from request
        request_factory = RequestFactory()
        request = request_factory.post(
            "/admin/login/", data={"username": self.username, "password": "test"}
        )

        self.assertEqual([cache_hash_key], get_client_cache_keys(request))

        # Getting cache key from AccessAttempt Object
        attempt = AccessAttempt(
            user_agent="<unknown>",
            ip_address=self.ip_address,
            username=self.username,
            get_data="",
            post_data="",
            http_accept=request.META.get("HTTP_ACCEPT", "<unknown>"),
            path_info=request.META.get("PATH_INFO", "<unknown>"),
            failures_since_start=0,
        )

        self.assertEqual([cache_hash_key], get_client_cache_keys(attempt))

    def test_get_cache_key_empty_ip_address(self):
        """
        Simulate an empty IP address in the request.
        """

        empty_ip_address = ""

        cache_hash_digest = sha256(empty_ip_address.encode()).hexdigest()
        cache_hash_key = f"axes-{cache_hash_digest}"

        # Getting cache key from request
        request_factory = RequestFactory()
        request = request_factory.post(
            "/admin/login/",
            data={"username": self.username, "password": "test"},
            REMOTE_ADDR=empty_ip_address,
        )

        self.assertEqual([cache_hash_key], get_client_cache_keys(request))

        # Getting cache key from AccessAttempt Object
        attempt = AccessAttempt(
            user_agent="<unknown>",
            ip_address=empty_ip_address,
            username=self.username,
            get_data="",
            post_data="",
            http_accept=request.META.get("HTTP_ACCEPT", "<unknown>"),
            path_info=request.META.get("PATH_INFO", "<unknown>"),
            failures_since_start=0,
        )

        self.assertEqual([cache_hash_key], get_client_cache_keys(attempt))

    def test_get_cache_key_credentials(self):
        """
        Test the cache key format.
        """

        ip_address = self.ip_address
        cache_hash_digest = sha256(ip_address.encode()).hexdigest()
        cache_hash_key = f"axes-{cache_hash_digest}"

        # Getting cache key from request
        request_factory = RequestFactory()
        request = request_factory.post(
            "/admin/login/", data={"username": self.username, "password": "test"}
        )

        # Difference between the upper test: new call signature with credentials
        credentials = {"username": self.username}

        self.assertEqual([cache_hash_key], get_client_cache_keys(request, credentials))

        # Getting cache key from AccessAttempt Object
        attempt = AccessAttempt(
            user_agent="<unknown>",
            ip_address=ip_address,
            username=self.username,
            get_data="",
            post_data="",
            http_accept=request.META.get("HTTP_ACCEPT", "<unknown>"),
            path_info=request.META.get("PATH_INFO", "<unknown>"),
            failures_since_start=0,
        )
        self.assertEqual([cache_hash_key], get_client_cache_keys(attempt))


class UsernameTestCase(AxesTestCase):
    def test_get_client_username_respects_field_length_for_all_sources(self):
        max_length = AccessBase._meta.get_field("username").max_length
        for source in ("post", "data", "credentials", "callable", "import_string"):
            for username in (
                None,
                "",
                "short",
                "x" * max_length,
                "é" * (max_length + 1),
            ):
                with self.subTest(source=source, username=username):
                    request = HttpRequest()
                    credentials = None
                    username_callable = None
                    if source == "post":
                        request.POST["username"] = username
                    elif source == "data":
                        request.data = {"username": username}
                    elif source == "credentials":
                        request.POST["username"] = "ignored"
                        credentials = {"username": username}
                    elif source == "callable":
                        username_callable = lambda request, credentials: username
                    else:
                        username_callable = "tests.test_helpers.get_username"

                    expected = username[:max_length] if username else username
                    with (
                        override_settings(AXES_USERNAME_CALLABLE=username_callable),
                        patch("tests.test_helpers.get_username", return_value=username),
                        patch("axes.helpers.log.warning") as warning,
                    ):
                        self.assertEqual(
                            expected, get_client_username(request, credentials)
                        )
                    if username and len(username) > max_length:
                        warning.assert_called_once_with(
                            "AXES: Truncating username of length %s to %s characters to fit the database field.",
                            len(username),
                            max_length,
                        )
                    else:
                        warning.assert_not_called()

    def test_get_client_username_uses_dynamic_field_length(self):
        field = AccessBase._meta.get_field("username")
        with patch.object(field, "max_length", 8):
            self.assertEqual(
                "long-use",
                get_client_username(HttpRequest(), {"username": "long-username"}),
            )

    @override_settings(AXES_USERNAME_FORM_FIELD="auth-username")
    def test_get_client_username_truncates_fallback_field(self):
        max_length = AccessBase._meta.get_field("username").max_length
        self.assertEqual(
            "x" * max_length,
            get_client_username(HttpRequest(), {"username": "x" * (max_length + 1)}),
        )

    @override_settings(AXES_USERNAME_FORM_FIELD="username")
    def test_default_get_client_username(self):
        expected = "test-username"

        request = HttpRequest()
        request.POST["username"] = expected

        actual = get_client_username(request)

        self.assertEqual(expected, actual)

    def test_default_get_client_username_drf(self):
        class DRFRequest:
            def __init__(self):
                self.data = {}
                self.POST = {}

        expected = "test-username"

        request = DRFRequest()
        request.data["username"] = expected

        actual = get_client_username(request)

        self.assertEqual(expected, actual)

    @override_settings(AXES_USERNAME_FORM_FIELD="username")
    def test_default_get_client_username_credentials(self):
        expected = "test-username"
        expected_in_credentials = "test-credentials-username"

        request = HttpRequest()
        request.POST["username"] = expected
        credentials = {"username": expected_in_credentials}

        actual = get_client_username(request, credentials)

        self.assertEqual(expected_in_credentials, actual)

    def sample_customize_username(request, credentials):
        return "prefixed-" + request.POST.get("username")

    @override_settings(AXES_USERNAME_FORM_FIELD="username")
    @override_settings(AXES_USERNAME_CALLABLE=sample_customize_username)
    def test_custom_get_client_username_from_request(self):
        provided = "test-username"
        expected = "prefixed-" + provided
        provided_in_credentials = "test-credentials-username"

        request = HttpRequest()
        request.POST["username"] = provided
        credentials = {"username": provided_in_credentials}

        actual = get_client_username(request, credentials)

        self.assertEqual(expected, actual)

    def sample_customize_username_credentials(request, credentials):
        return "prefixed-" + credentials.get("username")

    @override_settings(AXES_USERNAME_FORM_FIELD="username")
    @override_settings(AXES_USERNAME_CALLABLE=sample_customize_username_credentials)
    def test_custom_get_client_username_from_credentials(self):
        provided = "test-username"
        provided_in_credentials = "test-credentials-username"
        expected_in_credentials = "prefixed-" + provided_in_credentials

        request = HttpRequest()
        request.POST["username"] = provided
        credentials = {"username": provided_in_credentials}

        actual = get_client_username(request, credentials)

        self.assertEqual(expected_in_credentials, actual)

    @override_settings(
        AXES_USERNAME_CALLABLE=lambda request, credentials: "example"
    )  # pragma: no cover
    def test_get_client_username(self):
        self.assertEqual(get_client_username(HttpRequest(), {}), "example")

    @override_settings(AXES_USERNAME_CALLABLE=lambda request: None)  # pragma: no cover
    def test_get_client_username_invalid_callable_too_few_arguments(self):
        with self.assertRaises(TypeError):
            get_client_username(HttpRequest(), {})

    @override_settings(
        AXES_USERNAME_CALLABLE=lambda request, credentials, extra: None
    )  # pragma: no cover
    def test_get_client_username_invalid_callable_too_many_arguments(self):
        with self.assertRaises(TypeError):
            get_client_username(HttpRequest(), {})

    @override_settings(AXES_USERNAME_CALLABLE=True)
    def test_get_client_username_not_callable(self):
        with self.assertRaises(TypeError):
            get_client_username(HttpRequest(), {})

    @override_settings(AXES_USERNAME_CALLABLE="tests.test_helpers.get_username")
    def test_get_client_username_str(self):
        self.assertEqual(get_client_username(HttpRequest(), {}), "username")

    @override_settings(AXES_USERNAME_FORM_FIELD="auth-username")
    def test_get_client_username_fallback_to_username_field_from_credentials(self):
        """
        Test that when AXES_USERNAME_FORM_FIELD is set to a custom value that
        doesn't exist in credentials, we fallback to Django's USERNAME_FIELD.

        This fixes https://github.com/jazzband/django-axes/issues/1159
        """
        expected = "test-username"

        request = HttpRequest()
        # Credentials from Django's user_login_failed signal use USERNAME_FIELD (e.g., "username")
        # not the custom AXES_USERNAME_FORM_FIELD value
        credentials = {"username": expected}

        actual = get_client_username(request, credentials)

        self.assertEqual(expected, actual)

    @override_settings(AXES_USERNAME_FORM_FIELD="auth-username")
    def test_get_client_username_fallback_to_username_field_from_request(self):
        """
        Test that when AXES_USERNAME_FORM_FIELD is set to a custom value that
        doesn't exist in request.POST, we fallback to Django's USERNAME_FIELD.

        This fixes https://github.com/jazzband/django-axes/issues/1159
        """
        expected = "test-username"

        request = HttpRequest()
        # POST data might use Django's USERNAME_FIELD instead of custom form field
        request.POST["username"] = expected

        actual = get_client_username(request)

        self.assertEqual(expected, actual)

    @override_settings(AXES_USERNAME_FORM_FIELD="auth-username")
    def test_get_client_username_custom_field_takes_priority(self):
        """
        Test that AXES_USERNAME_FORM_FIELD takes priority when it exists in credentials.
        """
        expected = "custom-field-username"
        fallback = "username-field-value"

        request = HttpRequest()
        credentials = {
            "auth-username": expected,  # Custom field - should be used
            "username": fallback,  # Django's USERNAME_FIELD - should be ignored
        }

        actual = get_client_username(request, credentials)

        self.assertEqual(expected, actual)


class GetUsernameFromDataTestCase(AxesTestCase):
    """Unit tests for the get_username_from_data helper function."""

    @override_settings(AXES_USERNAME_FORM_FIELD="username")
    def test_get_username_from_data_with_matching_field(self):
        """Test that username is returned when AXES_USERNAME_FORM_FIELD matches."""
        data = {"username": "test-user"}
        self.assertEqual(get_username_from_data(data), "test-user")

    @override_settings(AXES_USERNAME_FORM_FIELD="custom-field")
    def test_get_username_from_data_fallback_to_username_field(self):
        """
        Test that when AXES_USERNAME_FORM_FIELD doesn't exist in data,
        we fallback to Django's USERNAME_FIELD.
        """
        # Django's default USERNAME_FIELD is "username"
        data = {"username": "fallback-user"}
        self.assertEqual(get_username_from_data(data), "fallback-user")

    @override_settings(AXES_USERNAME_FORM_FIELD="custom-field")
    def test_get_username_from_data_custom_field_takes_priority(self):
        """Test that AXES_USERNAME_FORM_FIELD takes priority over USERNAME_FIELD."""
        data = {
            "custom-field": "custom-user",
            "username": "fallback-user",
        }
        self.assertEqual(get_username_from_data(data), "custom-user")

    @override_settings(AXES_USERNAME_FORM_FIELD="nonexistent")
    def test_get_username_from_data_returns_none_when_not_found(self):
        """Test that None is returned when username is not found in any field."""
        data = {"other-field": "some-value"}
        self.assertIsNone(get_username_from_data(data))

    @override_settings(AXES_USERNAME_FORM_FIELD="username")
    def test_get_username_from_data_with_empty_dict(self):
        """Test that None is returned for empty dict."""
        self.assertIsNone(get_username_from_data({}))


def get_username(request, credentials: dict) -> str:
    return "username"


def get_username_normalization_overrides(request, credentials) -> dict:
    return {"casefold": False}


class DummyAuthBackend:
    """Module-level stand-in for an authentication backend declaring its own rules."""


class UsernameNormalizationTestCase(AxesTestCase):
    """Unit tests for the username identity normalization pipeline."""

    def test_normalize_username_none_and_empty(self):
        self.assertIsNone(normalize_username(None))
        self.assertEqual("", normalize_username(""))

    def test_normalize_username_fullwidth(self):
        # full-width letters, digits and at-sign fold to ASCII under NFKC
        self.assertEqual(
            "user1@example.com", normalize_username("\uff55\uff53\uff45\uff52\uff11\uff20example.com")
        )
        self.assertEqual("user@example.com", normalize_username("user\uff20example.com"))

    def test_normalize_username_combining_characters(self):
        combining = "cafe\u0301@example.com"  # e + combining acute accent
        composed = "caf\u00e9@example.com"  # precomposed e-acute
        self.assertEqual(composed, normalize_username(combining))
        self.assertEqual(normalize_username(composed), normalize_username(combining))

    def test_normalize_username_zero_width_and_invisible(self):
        self.assertEqual(
            "user@example.com", normalize_username("u\u200bser@\u200bexample.com")
        )
        self.assertEqual(
            "user@example.com", normalize_username("\ufeffuser@example.com\u2060")
        )
        self.assertEqual("user@example.com", normalize_username("user\u00ad@example.com"))

    def test_normalize_username_casefold(self):
        self.assertEqual("user@example.com", normalize_username("USER@Example.COM"))
        self.assertEqual(normalize_username("User@Example.com"), normalize_username("user@example.COM"))

    def test_normalize_username_whitespace(self):
        self.assertEqual("user@example.com", normalize_username("  user@example.com\t\n"))
        self.assertEqual("user name", normalize_username("user \t\n  name"))

    def test_normalize_username_not_a_string_stable_reason(self):
        for raw in (b"bytes", 123, ["list"]):
            with self.subTest(raw=raw):
                with self.assertRaises(UsernameNormalizationError) as ctx:
                    normalize_username(raw)
                self.assertEqual("not-a-string", ctx.exception.reason)
                self.assertIs(ctx.exception.raw, raw)

    def test_normalize_username_empty_after_normalization_stable_reason(self):
        with self.assertRaises(UsernameNormalizationError) as ctx:
            normalize_username("\u200b\u200b")
        self.assertEqual("empty-after-normalization", ctx.exception.reason)

    def test_normalize_username_rules_override(self):
        self.assertEqual(
            "USER@example.com",
            normalize_username("USER@example.com", {"casefold": False}),
        )
        self.assertEqual(
            "  x  y  ",
            normalize_username("  x  y  ", {"strip": False, "collapse_whitespace": False}),
        )

    def test_normalize_username_does_not_merge_distinct_identities(self):
        # local parts and tenant suffixes are normalized uniformly, so two
        # legitimate users never collapse into one identity
        self.assertNotEqual(
            normalize_username("user@tenant-a.example.com"),
            normalize_username("user@tenant-b.example.com"),
        )
        self.assertNotEqual(
            normalize_username("alice@example.com"),
            normalize_username("alice@example.org"),
        )
        self.assertNotEqual(
            normalize_username("alice@example.com"),
            normalize_username("alice2@example.com"),
        )

    def test_get_username_normalization_rules_defaults(self):
        rules = get_username_normalization_rules(HttpRequest(), None)
        self.assertEqual("NFKC", rules["form"])
        self.assertTrue(rules["casefold"])
        self.assertTrue(rules["strip"])
        self.assertTrue(rules["collapse_whitespace"])
        self.assertTrue(rules["strip_invisible"])

    @override_settings(AXES_USERNAME_NORMALIZATION={"casefold": False})
    def test_get_username_normalization_rules_global_override(self):
        rules = get_username_normalization_rules(HttpRequest(), None)
        self.assertFalse(rules["casefold"])
        self.assertEqual("NFKC", rules["form"])

    @override_settings(
        AXES_USERNAME_NORMALIZATION=lambda request, credentials: {"strip": False}
    )
    def test_get_username_normalization_rules_callable(self):
        rules = get_username_normalization_rules(HttpRequest(), None)
        self.assertFalse(rules["strip"])

    @override_settings(
        AXES_USERNAME_NORMALIZATION="tests.test_helpers.get_username_normalization_overrides"
    )
    def test_get_username_normalization_rules_import_string(self):
        rules = get_username_normalization_rules(HttpRequest(), None)
        self.assertFalse(rules["casefold"])

    @override_settings(AXES_USERNAME_NORMALIZATION=42)
    def test_get_username_normalization_rules_invalid_type(self):
        with self.assertRaises(TypeError):
            get_username_normalization_rules(HttpRequest(), None)

    @override_settings(
        AXES_USERNAME_BACKEND_NORMALIZATION={"my.auth.Backend": {"casefold": False}}
    )
    def test_backend_specific_rules_from_credentials(self):
        credentials = {"username": "USER@example.com", "backend": "my.auth.Backend"}
        self.assertEqual("USER@example.com", get_client_username(HttpRequest(), credentials))

    @override_settings(
        AXES_USERNAME_BACKEND_NORMALIZATION={"my.auth.Backend": {"casefold": False}}
    )
    def test_backend_specific_rules_from_request_attribute(self):
        request = HttpRequest()
        request.POST["username"] = "USER@example.com"
        request.axes_backend = "my.auth.Backend"
        self.assertEqual("USER@example.com", get_client_username(request))
        # other backends still fall back to the default rules
        request.axes_backend = "my.auth.OtherBackend"
        self.assertEqual("user@example.com", get_client_username(request))

    @override_settings(
        AXES_USERNAME_BACKEND_NORMALIZATION={
            "tests.test_helpers.DummyAuthBackend": {"casefold": False}
        }
    )
    def test_backend_specific_rules_class_and_instance(self):
        credentials = {"username": "USER@example.com", "backend": DummyAuthBackend}
        self.assertEqual("USER@example.com", get_client_username(HttpRequest(), credentials))
        credentials = {"username": "USER@example.com", "backend": DummyAuthBackend()}
        self.assertEqual("USER@example.com", get_client_username(HttpRequest(), credentials))


class ClientUsernameNormalizationTestCase(AxesTestCase):
    """get_client_username applies one shared normalization pipeline to all sources."""

    VARIANTS = [
        "user@example.com",
        "USER@example.com",
        "User@Example.Com",
        "\uff55\uff53\uff45\uff52\uff20\uff45\uff58\uff41\uff4d\uff50\uff4c\uff45\uff0e\uff43\uff4f\uff4d",
        "  user@example.com  ",
        "\tuser@example.com\n",
        "user\u200b@example.com",
        "user@example.com\u2060",
        "user\uff20example.com",
        "user@example\uff0ecom",
    ]

    def test_all_sources_normalize_to_same_identity(self):
        expected = "user@example.com"
        for variant in self.VARIANTS:
            with self.subTest(variant=variant):
                request = HttpRequest()
                request.POST["username"] = variant
                self.assertEqual(expected, get_client_username(request))

                request = HttpRequest()
                request.data = {"username": variant}
                self.assertEqual(expected, get_client_username(request))

                self.assertEqual(
                    expected, get_client_username(HttpRequest(), {"username": variant})
                )

                with override_settings(
                    AXES_USERNAME_CALLABLE=lambda request, credentials: variant
                ):
                    self.assertEqual(expected, get_client_username(HttpRequest()))

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username"])
    def test_lockout_cache_key_shared_across_variants(self):
        keys = set()
        for variant in self.VARIANTS:
            request = HttpRequest()
            request.POST["username"] = variant
            request.META["REMOTE_ADDR"] = "127.0.0.1"
            request.META["HTTP_USER_AGENT"] = "test-browser"
            keys.update(get_client_cache_keys(request))
        self.assertEqual(1, len(keys))

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username"])
    def test_lockout_cache_keys_distinct_for_legitimate_users(self):
        keys = set()
        for username in ("user@tenant-a.example.com", "user@tenant-b.example.com"):
            request = HttpRequest()
            request.POST["username"] = username
            request.META["REMOTE_ADDR"] = "127.0.0.1"
            request.META["HTTP_USER_AGENT"] = "test-browser"
            keys.update(get_client_cache_keys(request))
        self.assertEqual(2, len(keys))

    def test_normalization_failure_uses_isolated_stable_bucket(self):
        bucket1 = get_client_username(HttpRequest(), {"username": 123})
        bucket2 = get_client_username(HttpRequest(), {"username": 123})
        bucket3 = get_client_username(HttpRequest(), {"username": 456})
        self.assertIsNotNone(bucket1)
        self.assertEqual(bucket1, bucket2)
        self.assertNotEqual(bucket1, bucket3)
        self.assertTrue(bucket1.startswith("axes-unresolved-"))

    def test_invisible_only_username_uses_isolated_bucket(self):
        bucket = get_client_username(HttpRequest(), {"username": "\u200b\u200b"})
        self.assertTrue(bucket.startswith("axes-unresolved-"))

    def test_normalization_failure_logs_stable_reason(self):
        with patch("axes.helpers.log.warning") as warning:
            get_client_username(HttpRequest(), {"username": 123})
        warning.assert_called_once_with(
            "AXES: Username normalization failed (%s); using an isolated unresolved bucket.",
            "not-a-string",
        )

    def test_get_unresolved_username_bucket_deterministic(self):
        self.assertEqual(
            get_unresolved_username_bucket("x"), get_unresolved_username_bucket("x")
        )
        self.assertNotEqual(
            get_unresolved_username_bucket("x"), get_unresolved_username_bucket("y")
        )

    def test_truncation_applies_after_normalization(self):
        max_length = AccessBase._meta.get_field("username").max_length
        raw = "\uff38" * (max_length + 1)  # full-width X folds to ASCII "x"
        self.assertEqual(
            "x" * max_length, get_client_username(HttpRequest(), {"username": raw})
        )

    @override_settings(
        AXES_WHITELIST_CALLABLE=lambda request, credentials: get_client_username(
            request, credentials
        ) == "user@example.com"
    )
    def test_whitelist_callable_sees_normalized_username(self):
        request = HttpRequest()
        request.POST["username"] = " USER\uff20example.com "
        self.assertTrue(is_user_attempt_whitelisted(request))

        request = HttpRequest()
        request.POST["username"] = "other@example.com"
        self.assertFalse(is_user_attempt_whitelisted(request))


class UsernameAuditTestCase(AxesTestCase):
    """Audit helpers classify and fingerprint raw usernames without storing them."""

    def test_username_audit_category(self):
        self.assertEqual("missing", get_username_audit_category(None))
        self.assertEqual("invalid-type", get_username_audit_category(123))
        self.assertEqual("empty", get_username_audit_category(""))
        self.assertEqual("email-like", get_username_audit_category("user@example.com"))
        self.assertEqual("phone-like", get_username_audit_category("+1 (555) 010-1234"))
        self.assertEqual("username", get_username_audit_category("plain-user"))

    def test_username_audit_fingerprint(self):
        self.assertEqual("", get_username_audit_fingerprint(None))
        self.assertEqual("", get_username_audit_fingerprint(""))
        fingerprint = get_username_audit_fingerprint("user@example.com")
        self.assertEqual(12, len(fingerprint))
        self.assertEqual(
            fingerprint, get_username_audit_fingerprint("user@example.com")
        )
        self.assertNotEqual(
            fingerprint, get_username_audit_fingerprint("other@example.com")
        )
        self.assertNotIn("user@example.com", fingerprint)


def get_ip(request: HttpRequest) -> str:
    return "127.0.0.1"


class ClientIpAddressTestCase(AxesTestCase):
    @override_settings(AXES_CLIENT_IP_CALLABLE=get_ip)
    def test_get_client_ip_address(self):
        self.assertEqual(get_client_ip_address(HttpRequest()), "127.0.0.1")

    @override_settings(AXES_CLIENT_IP_CALLABLE="tests.test_helpers.get_ip")
    def test_get_client_ip_address_str(self):
        self.assertEqual(get_client_ip_address(HttpRequest()), "127.0.0.1")

    @override_settings(
        AXES_CLIENT_IP_CALLABLE=lambda request: "127.0.0.1"
    )  # pragma: no cover
    def test_get_client_ip_address_lambda(self):
        self.assertEqual(get_client_ip_address(HttpRequest()), "127.0.0.1")

    @override_settings(AXES_CLIENT_IP_CALLABLE=True)
    def test_get_client_ip_address_not_callable(self):
        with self.assertRaises(TypeError):
            get_client_ip_address(HttpRequest())

    @override_settings(AXES_CLIENT_IP_CALLABLE=lambda: None)  # pragma: no cover
    def test_get_client_ip_address_invalid_callable_too_few_arguments(self):
        with self.assertRaises(TypeError):
            get_client_ip_address(HttpRequest())

    @override_settings(
        AXES_CLIENT_IP_CALLABLE=lambda request, extra: None
    )  # pragma: no cover
    def test_get_client_ip_address_invalid_callable_too_many_arguments(self):
        with self.assertRaises(TypeError):
            get_client_ip_address(HttpRequest())

    def test_get_client_ip_address_with_ipware(self):
        request = HttpRequest()
        request.META["REMOTE_ADDR"] = "127.0.0.2"
        self.assertEqual(get_client_ip_address(request, use_ipware=True), "127.0.0.2")

    def test_get_client_ip_address_without_ipware(self):
        request = HttpRequest()
        request.META["REMOTE_ADDR"] = "127.0.0.3"
        self.assertEqual(get_client_ip_address(request, use_ipware=False), "127.0.0.3")


class IPWhitelistTestCase(AxesTestCase):
    def setUp(self):
        self.request = HttpRequest()
        self.request.method = "POST"
        self.request.META["REMOTE_ADDR"] = "127.0.0.1"
        self.request.axes_ip_address = "127.0.0.1"

    @override_settings(AXES_IP_WHITELIST=None)
    def test_ip_in_whitelist_none(self):
        self.assertFalse(is_ip_address_in_whitelist("127.0.0.2"))

    @override_settings(AXES_IP_WHITELIST=["127.0.0.1"])
    def test_ip_in_whitelist(self):
        self.assertTrue(is_ip_address_in_whitelist("127.0.0.1"))
        self.assertFalse(is_ip_address_in_whitelist("127.0.0.2"))

    @override_settings(AXES_IP_BLACKLIST=None)
    def test_ip_in_blacklist_none(self):
        self.assertFalse(is_ip_address_in_blacklist("127.0.0.2"))

    @override_settings(AXES_IP_BLACKLIST=["127.0.0.1"])
    def test_ip_in_blacklist(self):
        self.assertTrue(is_ip_address_in_blacklist("127.0.0.1"))
        self.assertFalse(is_ip_address_in_blacklist("127.0.0.2"))

    @override_settings(AXES_IP_BLACKLIST=["127.0.0.1"])
    def test_is_client_ip_address_blacklisted_ip_in_blacklist(self):
        self.assertTrue(is_client_ip_address_blacklisted(self.request))

    @override_settings(AXES_IP_BLACKLIST=["127.0.0.2"])
    def test_is_is_client_ip_address_blacklisted_ip_not_in_blacklist(self):
        self.assertFalse(is_client_ip_address_blacklisted(self.request))

    @override_settings(AXES_NEVER_LOCKOUT_WHITELIST=True)
    @override_settings(AXES_IP_WHITELIST=["127.0.0.1"])
    def test_is_client_ip_address_blacklisted_ip_in_whitelist(self):
        self.assertFalse(is_client_ip_address_blacklisted(self.request))

    @override_settings(AXES_ONLY_WHITELIST=True)
    @override_settings(AXES_IP_WHITELIST=["127.0.0.2"])
    def test_is_already_locked_ip_not_in_whitelist(self):
        self.assertTrue(is_client_ip_address_blacklisted(self.request))

    @override_settings(AXES_NEVER_LOCKOUT_WHITELIST=True)
    @override_settings(AXES_IP_WHITELIST=["127.0.0.1"])
    def test_is_client_ip_address_whitelisted_never_lockout(self):
        self.assertTrue(is_client_ip_address_whitelisted(self.request))

    @override_settings(AXES_ONLY_WHITELIST=True)
    @override_settings(AXES_IP_WHITELIST=["127.0.0.1"])
    def test_is_client_ip_address_whitelisted_only_allow(self):
        self.assertTrue(is_client_ip_address_whitelisted(self.request))

    @override_settings(AXES_ONLY_WHITELIST=True)
    @override_settings(AXES_IP_WHITELIST=["127.0.0.2"])
    def test_is_client_ip_address_whitelisted_not(self):
        self.assertFalse(is_client_ip_address_whitelisted(self.request))


class MethodWhitelistTestCase(AxesTestCase):
    def setUp(self):
        self.request = HttpRequest()
        self.request.method = "GET"

    @override_settings(AXES_NEVER_LOCKOUT_GET=True)
    def test_is_client_method_whitelisted(self):
        self.assertTrue(is_client_method_whitelisted(self.request))

    @override_settings(AXES_NEVER_LOCKOUT_GET=False)
    def test_is_client_method_whitelisted_not(self):
        self.assertFalse(is_client_method_whitelisted(self.request))


class LockoutResponseTestCase(AxesTestCase):
    def setUp(self):
        self.request = HttpRequest()

    @override_settings(AXES_COOLOFF_TIME=42)
    def test_get_lockout_response_cool_off(self):
        get_lockout_response(request=self.request)

    @override_settings(AXES_LOCKOUT_TEMPLATE="example.html")
    @patch("axes.helpers.render")
    def test_get_lockout_response_lockout_template(self, render):
        self.assertFalse(render.called)
        get_lockout_response(request=self.request)
        self.assertTrue(render.called)

    @override_settings(AXES_LOCKOUT_URL="https://example.com")
    def test_get_lockout_response_lockout_url(self):
        response = get_lockout_response(request=self.request)
        self.assertEqual(type(response), HttpResponseRedirect)

    def test_get_lockout_response_lockout_json(self):
        self.request.META["HTTP_X_REQUESTED_WITH"] = "XMLHttpRequest"
        response = get_lockout_response(request=self.request)
        self.assertEqual(type(response), JsonResponse)

    def test_get_lockout_response_lockout_response(self):
        response = get_lockout_response(request=self.request)
        self.assertEqual(type(response), HttpResponse)

    @override_settings(
        AXES_COOLOFF_TIME=timedelta(seconds=120),
        AXES_ENABLE_RETRY_AFTER_HEADER=True,
    )
    def test_lockout_response_sets_retry_after_header(self):
        response = get_lockout_response(request=self.request)
        self.assertEqual(response["Retry-After"], "120")

    @override_settings(
        AXES_COOLOFF_TIME=timedelta(seconds=120),
        AXES_ENABLE_RETRY_AFTER_HEADER=False,
    )
    def test_lockout_response_omits_retry_after_header_when_disabled(self):
        response = get_lockout_response(request=self.request)
        self.assertFalse(response.has_header("Retry-After"))

    @override_settings(
        AXES_COOLOFF_TIME=None,
        AXES_ENABLE_RETRY_AFTER_HEADER=True,
    )
    def test_lockout_response_omits_retry_after_header_without_cool_off(self):
        response = get_lockout_response(request=self.request)
        self.assertFalse(response.has_header("Retry-After"))

    @override_settings(
        AXES_COOLOFF_TIME=timedelta(seconds=120),
        AXES_ENABLE_RETRY_AFTER_HEADER=True,
        AXES_LOCKOUT_URL="https://example.com",
    )
    def test_retry_after_header_set_on_redirect_lockout_response(self):
        response = get_lockout_response(request=self.request)
        self.assertEqual(response["Retry-After"], "120")

    @override_settings(
        AXES_COOLOFF_TIME=timedelta(seconds=90),
        AXES_ENABLE_RETRY_AFTER_HEADER=True,
    )
    def test_set_retry_after_header_writes_cool_off_seconds(self):
        response = HttpResponse()
        set_retry_after_header(self.request, response)
        self.assertEqual(response["Retry-After"], "90")


def mock_get_cool_off_str(req):
    return timedelta(seconds=30)


class AxesCoolOffTestCase(AxesTestCase):
    @override_settings(AXES_COOLOFF_TIME=None)
    def test_get_cool_off_none(self):
        self.assertIsNone(get_cool_off())

    @override_settings(AXES_COOLOFF_TIME=2)
    def test_get_cool_off_int(self):
        self.assertEqual(get_cool_off(), timedelta(hours=2))

    @override_settings(AXES_COOLOFF_TIME=2.0)
    def test_get_cool_off_float(self):
        self.assertEqual(get_cool_off(), timedelta(minutes=120))

    @override_settings(AXES_COOLOFF_TIME=0.25)
    def test_get_cool_off_float_lt_0(self):
        self.assertEqual(get_cool_off(), timedelta(minutes=15))

    @override_settings(AXES_COOLOFF_TIME=1.7)
    def test_get_cool_off_float_gt_0(self):
        self.assertEqual(get_cool_off(), timedelta(seconds=6120))

    @override_settings(AXES_COOLOFF_TIME=lambda r: timedelta(seconds=30))
    def test_get_cool_off_callable(self):
        self.assertEqual(get_cool_off(), timedelta(seconds=30))

    @override_settings(AXES_COOLOFF_TIME="tests.test_helpers.mock_get_cool_off_str")
    def test_get_cool_off_path(self):
        self.assertEqual(get_cool_off(), timedelta(seconds=30))


def mock_is_whitelisted(request, credentials):
    return True


class AxesWhitelistTestCase(AxesTestCase):
    def setUp(self):
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create(username="jane.doe")
        self.request = HttpRequest()
        self.credentials = dict()

    def test_is_whitelisted(self):
        self.assertFalse(is_user_attempt_whitelisted(self.request, self.credentials))

    @override_settings(AXES_WHITELIST_CALLABLE=mock_is_whitelisted)
    def test_is_whitelisted_override_callable(self):
        self.assertTrue(is_user_attempt_whitelisted(self.request, self.credentials))

    @override_settings(AXES_WHITELIST_CALLABLE="tests.test_helpers.mock_is_whitelisted")
    def test_is_whitelisted_override_path(self):
        self.assertTrue(is_user_attempt_whitelisted(self.request, self.credentials))

    @override_settings(AXES_WHITELIST_CALLABLE=42)
    def test_is_whitelisted_override_invalid(self):
        with self.assertRaises(TypeError):
            is_user_attempt_whitelisted(self.request, self.credentials)


def mock_get_lockout_response(request, credentials):
    return HttpResponse(status=400)


def mock_get_lockout_response_with_original_response_param(
    request, response, credentials
):
    return HttpResponse(status=400)


class AxesLockoutTestCase(AxesTestCase):
    def setUp(self):
        self.request = HttpRequest()
        self.response = HttpResponse()
        self.credentials = dict()

    def test_get_lockout_response(self):
        response = get_lockout_response(self.request, self.credentials)
        self.assertEqual(429, response.status_code)

    @override_settings(AXES_HTTP_RESPONSE_CODE=403)
    def test_get_lockout_response_with_custom_http_response_code(self):
        response = get_lockout_response(self.request, self.credentials)
        self.assertEqual(403, response.status_code)

    @override_settings(AXES_LOCKOUT_CALLABLE=mock_get_lockout_response)
    def test_get_lockout_response_override_callable(self):
        response = get_lockout_response(self.request, self.credentials)
        self.assertEqual(400, response.status_code)

    @override_settings(
        AXES_LOCKOUT_CALLABLE="tests.test_helpers.mock_get_lockout_response"
    )
    def test_get_lockout_response_override_path(self):
        response = get_lockout_response(self.request, self.credentials)
        self.assertEqual(400, response.status_code)

    @override_settings(
        AXES_LOCKOUT_CALLABLE=mock_get_lockout_response_with_original_response_param
    )
    def test_get_lockout_response_override_callable_with_original_response_param(self):
        response = get_lockout_response(self.request, self.response, self.credentials)
        self.assertEqual(400, response.status_code)

    @override_settings(
        AXES_LOCKOUT_CALLABLE="tests.test_helpers.mock_get_lockout_response_with_original_response_param"
    )
    def test_get_lockout_response_override_path_with_original_response_param(self):
        response = get_lockout_response(self.request, self.response, self.credentials)
        self.assertEqual(400, response.status_code)

    @override_settings(AXES_LOCKOUT_CALLABLE=42)
    def test_get_lockout_response_override_invalid(self):
        with self.assertRaises(TypeError):
            get_lockout_response(self.request, self.credentials)


class AxesCleanseParamsTestCase(AxesTestCase):
    def setUp(self):
        self.parameters = {
            "username": "test_user",
            "password": "test_password",
            "other_sensitive_data": "sensitive",
        }

    @override_settings(AXES_SENSITIVE_PARAMETERS=[])
    def test_cleanse_parameters(self):
        cleansed = cleanse_parameters(self.parameters)
        self.assertEqual("test_user", cleansed["username"])
        self.assertEqual("********************", cleansed["password"])
        self.assertEqual("sensitive", cleansed["other_sensitive_data"])

    @override_settings(AXES_SENSITIVE_PARAMETERS=["other_sensitive_data"])
    def test_cleanse_parameters_override_sensitive(self):
        cleansed = cleanse_parameters(self.parameters)
        self.assertEqual("test_user", cleansed["username"])
        self.assertEqual("********************", cleansed["password"])
        self.assertEqual("********************", cleansed["other_sensitive_data"])

    @override_settings(AXES_SENSITIVE_PARAMETERS=["other_sensitive_data"])
    @override_settings(AXES_PASSWORD_FORM_FIELD="username")
    def test_cleanse_parameters_override_both(self):
        cleansed = cleanse_parameters(self.parameters)
        self.assertEqual("********************", cleansed["username"])
        self.assertEqual("********************", cleansed["password"])
        self.assertEqual("********************", cleansed["other_sensitive_data"])

    @override_settings(AXES_SENSITIVE_PARAMETERS=[])
    @override_settings(AXES_PASSWORD_FORM_FIELD=None)
    def test_cleanse_parameters_override_empty(self):
        cleansed = cleanse_parameters(self.parameters)
        self.assertEqual("test_user", cleansed["username"])
        self.assertEqual("********************", cleansed["password"])
        self.assertEqual("sensitive", cleansed["other_sensitive_data"])

    @override_settings(AXES_PASSWORD_FORM_FIELD="pword")
    def test_cleanse_parameters_form_prefix(self):
        # A form initialized with prefix="login" submits its password field
        # as "login-pword", not "pword". This used to be left in cleartext.
        prefixed_parameters = {
            "login-uname": "test_user",
            "login-pword": "test_password",
        }
        cleansed = cleanse_parameters(prefixed_parameters)
        self.assertEqual("test_user", cleansed["login-uname"])
        self.assertEqual("********************", cleansed["login-pword"])

    @override_settings(AXES_SENSITIVE_PARAMETERS=["other_sensitive_data"])
    def test_cleanse_parameters_form_prefix_sensitive_parameters(self):
        prefixed_parameters = {
            "form-username": "test_user",
            "form-other_sensitive_data": "sensitive",
        }
        cleansed = cleanse_parameters(prefixed_parameters)
        self.assertEqual("test_user", cleansed["form-username"])
        self.assertEqual("********************", cleansed["form-other_sensitive_data"])


class AxesLockoutTiersTestCase(AxesTestCase):
    SAMPLE_TIERS = [
        LockoutTier(failures=3, cooloff=timedelta(minutes=15)),
        LockoutTier(failures=6, cooloff=timedelta(hours=2)),
        LockoutTier(failures=10, cooloff=timedelta(days=1)),
    ]

    # -- get_lockout_tier --

    def test_get_lockout_tier_none_when_not_configured(self):
        self.assertIsNone(get_lockout_tier(5))

    @override_settings(AXES_LOCKOUT_TIERS=SAMPLE_TIERS)
    def test_get_lockout_tier_below_threshold(self):
        self.assertIsNone(get_lockout_tier(2))

    @override_settings(AXES_LOCKOUT_TIERS=SAMPLE_TIERS)
    def test_get_lockout_tier_first_tier(self):
        tier = get_lockout_tier(3)
        self.assertEqual(tier, LockoutTier(failures=3, cooloff=timedelta(minutes=15)))

    @override_settings(AXES_LOCKOUT_TIERS=SAMPLE_TIERS)
    def test_get_lockout_tier_between_tiers(self):
        tier = get_lockout_tier(5)
        self.assertEqual(tier, LockoutTier(failures=3, cooloff=timedelta(minutes=15)))

    @override_settings(AXES_LOCKOUT_TIERS=SAMPLE_TIERS)
    def test_get_lockout_tier_second_tier(self):
        tier = get_lockout_tier(6)
        self.assertEqual(tier, LockoutTier(failures=6, cooloff=timedelta(hours=2)))

    @override_settings(AXES_LOCKOUT_TIERS=SAMPLE_TIERS)
    def test_get_lockout_tier_seven_failures(self):
        tier = get_lockout_tier(7)
        self.assertEqual(tier, LockoutTier(failures=6, cooloff=timedelta(hours=2)))

    @override_settings(AXES_LOCKOUT_TIERS=SAMPLE_TIERS)
    def test_get_lockout_tier_highest_tier(self):
        tier = get_lockout_tier(10)
        self.assertEqual(tier, LockoutTier(failures=10, cooloff=timedelta(days=1)))

    @override_settings(AXES_LOCKOUT_TIERS=SAMPLE_TIERS)
    def test_get_lockout_tier_above_highest(self):
        tier = get_lockout_tier(100)
        self.assertEqual(tier, LockoutTier(failures=10, cooloff=timedelta(days=1)))

    # -- get_cool_off with tiers --

    @override_settings(AXES_LOCKOUT_TIERS=SAMPLE_TIERS)
    def test_get_cool_off_with_tiers(self):
        self.request.axes_failures_since_start = 6
        self.assertEqual(get_cool_off(self.request), timedelta(hours=2))

    @override_settings(AXES_LOCKOUT_TIERS=SAMPLE_TIERS)
    def test_get_cool_off_tiers_no_failures_attr(self):
        """When request has no failures attribute, returns None (no tier matched)."""
        request = HttpRequest()
        self.assertIsNone(get_cool_off(request))

    @override_settings(AXES_LOCKOUT_TIERS=SAMPLE_TIERS)
    def test_get_cool_off_tiers_below_first_threshold(self):
        self.request.axes_failures_since_start = 1
        self.assertIsNone(get_cool_off(self.request))

    # -- get_failure_limit with tiers --

    @override_settings(AXES_LOCKOUT_TIERS=SAMPLE_TIERS)
    def test_get_failure_limit_returns_lowest_tier(self):
        from axes.helpers import get_failure_limit

        self.assertEqual(get_failure_limit(self.request, self.credentials), 3)

    @override_settings(
        AXES_LOCKOUT_TIERS=[
            LockoutTier(failures=10, cooloff=timedelta(days=1)),
            LockoutTier(failures=5, cooloff=timedelta(hours=1)),
        ]
    )
    def test_get_failure_limit_sorts_tiers(self):
        from axes.helpers import get_failure_limit

        self.assertEqual(get_failure_limit(self.request, self.credentials), 5)

    # -- get_lockout_message with tiers --

    @override_settings(AXES_LOCKOUT_TIERS=SAMPLE_TIERS, AXES_COOLOFF_TIME=None)
    def test_get_lockout_message_with_tiers(self):
        from axes.conf import settings
        from axes.helpers import get_lockout_message

        self.assertEqual(get_lockout_message(), settings.AXES_COOLOFF_MESSAGE)

    # -- get_lockout_response with tiers --

    @override_settings(AXES_LOCKOUT_TIERS=SAMPLE_TIERS, AXES_COOLOFF_TIME=None)
    def test_get_lockout_response_includes_failure_count(self):
        self.request.axes_failures_since_start = 6
        response = get_lockout_response(request=self.request)
        self.assertEqual(response.status_code, 429)

    @override_settings(AXES_LOCKOUT_TIERS=SAMPLE_TIERS, AXES_COOLOFF_TIME=None)
    def test_get_lockout_response_json_with_tiers(self):
        self.request.axes_failures_since_start = 3
        self.request.META["HTTP_X_REQUESTED_WITH"] = "XMLHttpRequest"
        response = get_lockout_response(request=self.request)
        self.assertEqual(type(response), JsonResponse)
        import json

        data = json.loads(response.content)
        self.assertEqual(data["failure_count"], 3)
        self.assertIn("cooloff_time", data)
