from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone as dt_timezone
from threading import Barrier
from unittest.mock import MagicMock, patch

from django.core.cache import cache
from django.http import HttpRequest
from django.http.multipartparser import MultiPartParserError
from django.test import RequestFactory, TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from axes.conf import settings
from axes.handlers.cache import AxesCacheHandler
from axes.handlers.database import AxesDatabaseHandler
from axes.handlers.proxy import AxesProxyHandler
from axes.helpers import get_client_str, get_cool_off, get_failure_limit
from axes.models import (
    AccessAttempt,
    AccessAttemptExpiration,
    AccessFailureLog,
    AccessLog,
)
from tests.base import AxesTestCase


@override_settings(AXES_HANDLER="axes.handlers.base.AxesHandler")
class AxesHandlerTestCase(AxesTestCase):
    @override_settings(AXES_IP_BLACKLIST=["127.0.0.1"])
    def test_is_allowed_with_blacklisted_ip_address(self):
        self.assertFalse(AxesProxyHandler.is_allowed(self.request))

    @override_settings(
        AXES_NEVER_LOCKOUT_WHITELIST=True, AXES_IP_WHITELIST=["127.0.0.1"]
    )
    def test_is_allowed_with_whitelisted_ip_address(self):
        self.assertTrue(AxesProxyHandler.is_allowed(self.request))

    @override_settings(AXES_NEVER_LOCKOUT_GET=True)
    def test_is_allowed_with_whitelisted_method(self):
        self.request.method = "GET"
        self.assertTrue(AxesProxyHandler.is_allowed(self.request))

    @override_settings(AXES_LOCK_OUT_AT_FAILURE=False)
    def test_is_allowed_no_lock_out(self):
        self.assertTrue(AxesProxyHandler.is_allowed(self.request))

    @override_settings(AXES_ONLY_ADMIN_SITE=True)
    def test_only_admin_site(self):
        request = MagicMock()
        request.path = "/test/"
        self.assertTrue(AxesProxyHandler.is_allowed(self.request))

    def test_is_admin_site(self):
        request = MagicMock()
        tests = (  # (AXES_ONLY_ADMIN_SITE, URL, Expected)
            (True, "/test/", True),
            (True, reverse("admin:index"), False),
            (False, "/test/", False),
            (False, reverse("admin:index"), False),
        )

        for setting_value, url, expected in tests:
            with override_settings(AXES_ONLY_ADMIN_SITE=setting_value):
                request.path = url
                with self.assertWarns(DeprecationWarning):
                    self.assertEqual(AxesProxyHandler().is_admin_site(request), expected)

    def test_is_admin_request(self):
        request = MagicMock()
        tests = (  # (URL, Expected)
            ("/test/", False),
            (reverse("admin:index"), True),
        )

        for url, expected in tests:
            request.path = url
            self.assertEqual(AxesProxyHandler().is_admin_request(request), expected)

    @override_settings(ROOT_URLCONF="tests.urls_empty")
    @override_settings(AXES_ONLY_ADMIN_SITE=True)
    def test_is_admin_site_no_admin_site(self):
        request = MagicMock()
        request.path = "/admin/"
        with self.assertWarns(DeprecationWarning):
            self.assertTrue(AxesProxyHandler().is_admin_site(self.request))

    @override_settings(ROOT_URLCONF="tests.urls_empty")
    def test_is_admin_request_no_admin_site(self):
        request = MagicMock()
        request.path = "/admin/"
        self.assertFalse(AxesProxyHandler().is_admin_request(self.request))

    def test_is_admin_request_no_path(self):
        self.assertFalse(AxesProxyHandler().is_admin_request(self.request))


class AxesProxyHandlerTestCase(AxesTestCase):
    def setUp(self):
        self.sender = MagicMock()
        self.credentials = MagicMock()
        self.request = MagicMock()
        self.user = MagicMock()
        self.instance = MagicMock()

    @patch("axes.handlers.proxy.AxesProxyHandler.implementation", None)
    def test_setting_changed_signal_triggers_handler_reimport(self):
        self.assertIsNone(AxesProxyHandler.implementation)

        with self.settings(AXES_HANDLER="axes.handlers.database.AxesDatabaseHandler"):
            self.assertIsNotNone(AxesProxyHandler.implementation)

    @patch("axes.handlers.proxy.AxesProxyHandler.implementation")
    def test_user_login_failed(self, handler):
        self.assertFalse(handler.user_login_failed.called)
        AxesProxyHandler.user_login_failed(self.sender, self.credentials, self.request)
        self.assertTrue(handler.user_login_failed.called)

    @patch("axes.handlers.proxy.AxesProxyHandler.implementation")
    def test_user_logged_in(self, handler):
        self.assertFalse(handler.user_logged_in.called)
        AxesProxyHandler.user_logged_in(self.sender, self.request, self.user)
        self.assertTrue(handler.user_logged_in.called)

    @patch("axes.handlers.proxy.AxesProxyHandler.implementation")
    def test_user_logged_out(self, handler):
        self.assertFalse(handler.user_logged_out.called)
        AxesProxyHandler.user_logged_out(self.sender, self.request, self.user)
        self.assertTrue(handler.user_logged_out.called)

    @patch("axes.handlers.proxy.AxesProxyHandler.implementation")
    def test_post_save_access_attempt(self, handler):
        self.assertFalse(handler.post_save_access_attempt.called)
        AxesProxyHandler.post_save_access_attempt(self.instance)
        self.assertTrue(handler.post_save_access_attempt.called)

    @patch("axes.handlers.proxy.AxesProxyHandler.implementation")
    def test_post_delete_access_attempt(self, handler):
        self.assertFalse(handler.post_delete_access_attempt.called)
        AxesProxyHandler.post_delete_access_attempt(self.instance)
        self.assertTrue(handler.post_delete_access_attempt.called)


class AxesHandlerBaseTestCase(AxesTestCase):
    def check_whitelist(self, log):
        with override_settings(
            AXES_NEVER_LOCKOUT_WHITELIST=True, AXES_IP_WHITELIST=[self.ip_address]
        ):
            AxesProxyHandler.user_login_failed(
                sender=None, request=self.request, credentials=self.credentials
            )
            client_str = get_client_str(
                self.username,
                self.ip_address,
                self.user_agent,
                self.path_info,
                self.request,
            )
            log.info.assert_called_with(
                "AXES: Login failed from whitelisted client %s.", client_str
            )

    def check_empty_request(self, log, handler):
        AxesProxyHandler.user_login_failed(sender=None, credentials={}, request=None)
        log.error.assert_called_with(
            f"AXES: {handler}.user_login_failed does not function without a request."
        )


@override_settings(AXES_HANDLER="axes.handlers.database.AxesDatabaseHandler")
class ResetAttemptsTestCase(AxesHandlerBaseTestCase):
    """Resetting attempts is currently implemented only for database handler"""

    USERNAME_1 = "foo_username"
    USERNAME_2 = "bar_username"
    IP_1 = "127.1.0.1"
    IP_2 = "127.1.0.2"

    def setUp(self):
        super().setUp()
        self.create_attempt()
        self.create_attempt(username=self.USERNAME_1, ip_address=self.IP_1)
        self.create_attempt(username=self.USERNAME_1, ip_address=self.IP_2)
        self.create_attempt(username=self.USERNAME_2, ip_address=self.IP_1)
        self.create_attempt(username=self.USERNAME_2, ip_address=self.IP_2)

    def test_handler_reset_attempts(self):
        self.assertEqual(5, AxesProxyHandler.reset_attempts())
        self.assertFalse(AccessAttempt.objects.count())

    def test_handler_reset_attempts_username(self):
        self.assertEqual(2, AxesProxyHandler.reset_attempts(username=self.USERNAME_1))
        self.assertEqual(AccessAttempt.objects.count(), 3)
        self.assertEqual(
            AccessAttempt.objects.filter(ip_address=self.USERNAME_1).count(), 0
        )

    def test_handler_reset_attempts_ip(self):
        self.assertEqual(2, AxesProxyHandler.reset_attempts(ip_address=self.IP_1))
        self.assertEqual(AccessAttempt.objects.count(), 3)
        self.assertEqual(AccessAttempt.objects.filter(ip_address=self.IP_1).count(), 0)

    def test_handler_reset_attempts_ip_and_username(self):
        self.assertEqual(
            1,
            AxesProxyHandler.reset_attempts(
                ip_address=self.IP_1, username=self.USERNAME_1
            ),
        )
        self.assertEqual(AccessAttempt.objects.count(), 4)
        self.assertEqual(AccessAttempt.objects.filter(ip_address=self.IP_1).count(), 1)

        self.create_attempt(username=self.USERNAME_1, ip_address=self.IP_1)
        self.assertEqual(
            1,
            AxesProxyHandler.reset_attempts(
                ip_address=self.IP_1, username=self.USERNAME_2
            ),
        )
        self.assertEqual(
            1,
            AxesProxyHandler.reset_attempts(
                ip_address=self.IP_2, username=self.USERNAME_1
            ),
        )

    def test_handler_reset_attempts_ip_or_username(self):
        self.assertEqual(
            3,
            AxesProxyHandler.reset_attempts(
                ip_address=self.IP_1, username=self.USERNAME_1, ip_or_username=True
            ),
        )
        self.assertEqual(AccessAttempt.objects.count(), 2)
        self.assertEqual(AccessAttempt.objects.filter(ip_address=self.IP_1).count(), 0)
        self.assertEqual(
            AccessAttempt.objects.filter(ip_address=self.USERNAME_1).count(), 0
        )


@override_settings(
    AXES_HANDLER="axes.handlers.database.AxesDatabaseHandler",
    AXES_COOLOFF_TIME=timedelta(seconds=2),
    AXES_RESET_ON_SUCCESS=True,
    AXES_ENABLE_ACCESS_FAILURE_LOG=True,
)
class AxesDatabaseHandlerTestCase(AxesHandlerBaseTestCase):
    def test_user_login_failed_truncates_long_username(self):
        max_length = AccessAttempt._meta.get_field("username").max_length
        username = "x" * (max_length + 1)
        self.request.POST["username"] = username

        for _ in range(2):
            AxesProxyHandler.user_login_failed(
                sender=None, request=self.request, credentials={"username": username}
            )

        attempt = AccessAttempt.objects.get()
        self.assertEqual(username[:max_length], attempt.username)
        self.assertEqual(2, attempt.failures_since_start)
        self.assertEqual(2, AccessFailureLog.objects.count())
        for failure in AccessFailureLog.objects.all():
            self.assertEqual(username[:max_length], failure.username)

    def test_handle_json_post_data(self):
        def _raise():
            raise MultiPartParserError("Invalid boundary in multipart: None")

        class MockHttpRequest(HttpRequest):
            POST = property(lambda self: _raise(), lambda self, value: None)

        request = MockHttpRequest()
        request.method = "POST"
        request.META["REMOTE_ADDR"] = self.ip_address
        request.META["HTTP_USER_AGENT"] = self.user_agent
        request.META["PATH_INFO"] = self.path_info
        request.content_type = "application/json"
        request._body = b"{}"
        sender = MagicMock()
        AxesProxyHandler.user_login_failed(
            sender=sender, request=request, credentials={"token": "dummy"}
        )
        self.assertEqual(1, AccessAttempt.objects.count())
        self.assertIn(
            'Could not access "request.POST"', AccessAttempt.objects.first().post_data
        )

    def test_handler_reset_attempts(self):
        self.create_attempt()
        self.assertEqual(1, AxesProxyHandler.reset_attempts())
        self.assertFalse(AccessAttempt.objects.count())

    def test_handler_reset_logs(self):
        self.create_log()
        self.assertEqual(1, AxesProxyHandler.reset_logs())
        self.assertFalse(AccessLog.objects.count())

    def test_handler_reset_logs_older_than_42_days(self):
        self.create_log()

        then = timezone.now() - timedelta(days=90)
        with patch("django.utils.timezone.now", return_value=then):
            self.create_log()

        self.assertEqual(AccessLog.objects.count(), 2)
        self.assertEqual(1, AxesProxyHandler.reset_logs(age_days=42))
        self.assertEqual(AccessLog.objects.count(), 1)

    def test_handler_reset_failure_logs(self):
        self.create_failure_log()
        self.assertEqual(1, AxesProxyHandler.reset_failure_logs())
        self.assertFalse(AccessFailureLog.objects.count())

    def test_handler_reset_failure_logs_older_than_42_days(self):
        self.create_failure_log()

        then = timezone.now() - timedelta(days=90)
        with patch("django.utils.timezone.now", return_value=then):
            self.create_failure_log()

        self.assertEqual(AccessFailureLog.objects.count(), 2)
        self.assertEqual(1, AxesProxyHandler.reset_failure_logs(age_days=42))
        self.assertEqual(AccessFailureLog.objects.count(), 1)

    def test_handler_remove_out_of_limit_failure_logs(self):
        _more = 10
        for i in range(settings.AXES_ACCESS_FAILURE_LOG_PER_USER_LIMIT + _more):
            self.create_failure_log()
        self.assertEqual(
            _more,
            AxesProxyHandler.remove_out_of_limit_failure_logs(username=self.username),
        )

    @override_settings(AXES_RESET_ON_SUCCESS=True)
    def test_handler(self):
        self.check_handler()

    @override_settings(AXES_RESET_ON_SUCCESS=False)
    def test_handler_without_reset(self):
        self.check_handler()

    @override_settings(AXES_FAILURE_LIMIT=lambda *args: 3)
    def test_handler_callable_failure_limit(self):
        self.check_handler()

    @override_settings(AXES_FAILURE_LIMIT="tests.base.custom_failure_limit")
    def test_handler_str_failure_limit(self):
        self.check_handler()

    @override_settings(AXES_FAILURE_LIMIT=None)
    def test_handler_invalid_failure_limit(self):
        with self.assertRaises(TypeError):
            self.check_handler()

    @override_settings(AXES_LOCK_OUT_AT_FAILURE=False)
    def test_handler_without_lockout(self):
        self.check_handler()

    @patch("axes.handlers.database.log")
    def test_empty_request(self, log):
        self.check_empty_request(log, "AxesDatabaseHandler")

    @patch("axes.handlers.database.log")
    def test_whitelist(self, log):
        self.check_whitelist(log)

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username"])
    @patch("axes.handlers.database.log")
    def test_user_login_failed_only_user_failures_with_none_username(self, log):
        credentials = {"username": None, "password": "test"}
        sender = MagicMock()
        AxesProxyHandler.user_login_failed(sender, credentials, self.request)
        AccessAttempt.objects.all()
        self.assertEqual(0, AccessAttempt.objects.count())
        log.warning.assert_called_with(
            "AXES: Username is None and username is the only one lockout parameter, new record will NOT be created."
        )

    def test_user_login_failed_with_none_username(self):
        credentials = {"username": None, "password": "test"}
        sender = MagicMock()
        AxesProxyHandler.user_login_failed(sender, credentials, self.request)
        AccessAttempt.objects.all()
        self.assertEqual(1, AccessAttempt.objects.filter(username__isnull=True).count())

    def test_user_login_failed_multiple_username(self):
        configurations = (
            (2, 1, {}, ["admin", "admin1"]),
            (
                2,
                1,
                {"AXES_LOCKOUT_PARAMETERS": [["ip_address", "user_agent"]]},
                ["admin", "admin1"],
            ),
            (2, 1, {"AXES_LOCKOUT_PARAMETERS": ["username"]}, ["admin", "admin1"]),
            (
                2,
                1,
                {"AXES_LOCKOUT_PARAMETERS": [["username", "ip_address"]]},
                ["admin", "admin1"],
            ),
            (
                1,
                2,
                {"AXES_LOCKOUT_PARAMETERS": [["username", "ip_address"]]},
                ["admin", "admin"],
            ),
            (
                1,
                2,
                {"AXES_LOCKOUT_PARAMETERS": ["username", "ip_address"]},
                ["admin", "admin"],
            ),
            (
                2,
                1,
                {"AXES_LOCKOUT_PARAMETERS": ["username", "ip_address"]},
                ["admin", "admin1"],
            ),
        )

        for (
            total_attempts_count,
            failures_since_start,
            overrides,
            usernames,
        ) in configurations:
            with self.settings(**overrides):
                with self.subTest(
                    total_attempts_count=total_attempts_count,
                    failures_since_start=failures_since_start,
                    settings=overrides,
                ):
                    self.login(username=usernames[0])
                    attempt = AccessAttempt.objects.get(username=usernames[0])
                    self.assertEqual(1, attempt.failures_since_start)

                    # check the number of failures associated to the attempt
                    self.login(username=usernames[1])
                    attempt = AccessAttempt.objects.get(username=usernames[1])
                    self.assertEqual(failures_since_start, attempt.failures_since_start)

                    # check the number of distinct attempts
                    self.assertEqual(
                        total_attempts_count, AccessAttempt.objects.count()
                    )

            AccessAttempt.objects.all().delete()


@override_settings(AXES_HANDLER="axes.handlers.cache.AxesCacheHandler")
class ResetAttemptsCacheHandlerTestCase(AxesHandlerBaseTestCase):
    """Test reset attempts for the cache handler"""

    USERNAME_1 = "foo_username"
    USERNAME_2 = "bar_username"
    IP_1 = "127.1.0.1"
    IP_2 = "127.1.0.2"

    def set_up_login_attempts(self):
        """Set up the login attempts."""
        self.login(username=self.USERNAME_1, remote_addr=self.IP_1)
        self.login(username=self.USERNAME_1, remote_addr=self.IP_2)
        self.login(username=self.USERNAME_2, remote_addr=self.IP_1)
        self.login(username=self.USERNAME_2, remote_addr=self.IP_2)

    def check_failures(self, failures, username=None, ip_address=None):
        if ip_address is None and username is None:
            raise NotImplementedError("Must supply ip_address or username")
        try:
            prev_ip = self.request.META["REMOTE_ADDR"]
            credentials = {"username": username} if username else {}
            if ip_address is not None:
                self.request.META["REMOTE_ADDR"] = ip_address
            self.assertEqual(
                failures,
                AxesProxyHandler.get_failures(self.request, credentials=credentials),
            )
        finally:
            self.request.META["REMOTE_ADDR"] = prev_ip

    def test_handler_reset_attempts(self):
        with self.assertRaises(NotImplementedError):
            AxesProxyHandler.reset_attempts()

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username"])
    def test_handler_reset_attempts_username(self):
        self.set_up_login_attempts()
        self.assertEqual(
            2,
            AxesProxyHandler.get_failures(
                self.request, credentials={"username": self.USERNAME_1}
            ),
        )
        self.assertEqual(
            2,
            AxesProxyHandler.get_failures(
                self.request, credentials={"username": self.USERNAME_2}
            ),
        )
        self.assertEqual(1, AxesProxyHandler.reset_attempts(username=self.USERNAME_1))
        self.assertEqual(
            0,
            AxesProxyHandler.get_failures(
                self.request, credentials={"username": self.USERNAME_1}
            ),
        )
        self.assertEqual(
            2,
            AxesProxyHandler.get_failures(
                self.request, credentials={"username": self.USERNAME_2}
            ),
        )

    def test_handler_reset_attempts_ip(self):
        self.set_up_login_attempts()
        self.check_failures(2, ip_address=self.IP_1)
        self.assertEqual(1, AxesProxyHandler.reset_attempts(ip_address=self.IP_1))
        self.check_failures(0, ip_address=self.IP_1)
        self.check_failures(2, ip_address=self.IP_2)

    @override_settings(AXES_LOCKOUT_PARAMETERS=[["username", "ip_address"]])
    def test_handler_reset_attempts_ip_and_username(self):
        self.set_up_login_attempts()
        self.check_failures(1, username=self.USERNAME_1, ip_address=self.IP_1)
        self.check_failures(1, username=self.USERNAME_2, ip_address=self.IP_1)
        self.check_failures(1, username=self.USERNAME_1, ip_address=self.IP_2)
        self.assertEqual(
            1,
            AxesProxyHandler.reset_attempts(
                ip_address=self.IP_1, username=self.USERNAME_1
            ),
        )
        self.check_failures(0, username=self.USERNAME_1, ip_address=self.IP_1)
        self.check_failures(1, username=self.USERNAME_2, ip_address=self.IP_1)
        self.check_failures(1, username=self.USERNAME_1, ip_address=self.IP_2)

    def test_handler_reset_attempts_ip_or_username(self):
        with self.assertRaises(NotImplementedError):
            AxesProxyHandler.reset_attempts()


@override_settings(
    AXES_HANDLER="axes.handlers.cache.AxesCacheHandler",
    AXES_COOLOFF_TIME=timedelta(seconds=1),
)
class AxesCacheHandlerTestCase(AxesHandlerBaseTestCase):
    @override_settings(AXES_RESET_ON_SUCCESS=True)
    def test_handler(self):
        self.check_handler()

    @override_settings(AXES_RESET_ON_SUCCESS=False)
    def test_handler_without_reset(self):
        self.check_handler()

    @override_settings(AXES_LOCK_OUT_AT_FAILURE=False)
    def test_handler_without_lockout(self):
        self.check_handler()

    @patch("axes.handlers.cache.log")
    def test_empty_request(self, log):
        self.check_empty_request(log, "AxesCacheHandler")

    @patch("axes.handlers.cache.log")
    def test_whitelist(self, log):
        self.check_whitelist(log)

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username"])
    @patch.object(cache, "set")
    @patch("axes.handlers.cache.log")
    def test_user_login_failed_only_user_failures_with_none_username(
        self, log, cache_set
    ):
        credentials = {"username": None, "password": "test"}
        sender = MagicMock()
        AxesProxyHandler.user_login_failed(sender, credentials, self.request)
        self.assertFalse(cache_set.called)
        log.warning.assert_called_with(
            "AXES: Username is None and username is the only one lockout parameter, new record will NOT be created."
        )

    @patch.object(cache, "add")
    def test_user_login_failed_with_none_username(self, cache_add):
        credentials = {"username": None, "password": "test"}
        sender = MagicMock()
        AxesProxyHandler.user_login_failed(sender, credentials, self.request)
        self.assertTrue(cache_add.called)

    @patch.object(cache, "touch")
    @patch.object(cache, "incr", side_effect=ValueError("Key 'test' not found"))
    @patch.object(cache, "add", side_effect=[False, True])
    def test_user_login_failed_when_key_expires_before_incr(
        self, cache_add, cache_incr, cache_touch
    ):
        """A key expiring between the add and the incr must not raise.

        The cool off window has elapsed by the time incr runs, so the failure
        starts a fresh count rather than propagating the ValueError. See #1144.
        """
        credentials = {"username": "jane.doe", "password": "test"}
        sender = MagicMock()

        AxesProxyHandler.user_login_failed(sender, credentials, self.request)

        self.assertTrue(cache_incr.called)
        self.assertEqual(self.request.axes_failures_since_start, 1)
        # The count is re-seeded with its timeout, so touch is not needed.
        self.assertEqual(cache_add.call_count, 2)
        self.assertFalse(cache_touch.called)


class LockoutScopeHandlerConsistencyTestCase(AxesTestCase):
    HANDLER_CLASSES = (AxesDatabaseHandler, AxesCacheHandler)
    LOCKOUT_PARAMETERS = ["username", ["username", "ip_address"]]

    def failure_request(self):
        request = RequestFactory().post(
            "/admin/login/",
            data={"username": "shared-user", "password": "wrong-password"},
            REMOTE_ADDR="2.3.4.5",
            HTTP_USER_AGENT="test-browser",
        )
        request.axes_locked_out = False
        return request

    def run_failure_sequence(self, handler_class, lockout_parameters):
        results = []

        with override_settings(
            AXES_LOCKOUT_PARAMETERS=lockout_parameters,
            AXES_HANDLER=(
                f"{handler_class.__module__}.{handler_class.__name__}"
            ),
        ):
            for _ in range(get_failure_limit(None, None)):
                request = self.failure_request()
                credentials = {
                    "username": "shared-user",
                    "password": "wrong-password",
                }
                AxesProxyHandler.user_login_failed(
                    sender=None, request=request, credentials=credentials
                )
                results.append(
                    {
                        "failures": AxesProxyHandler.get_failures(
                            request, credentials
                        ),
                        "request_failures": request.axes_failures_since_start,
                        "locked_out": request.axes_locked_out,
                        "failure_limit": get_failure_limit(
                            request, credentials
                        ),
                        "cool_off": get_cool_off(request),
                    }
                )

        return results

    def test_database_and_cache_count_same_failure_sequence(self):
        database_results = self.run_failure_sequence(
            AxesDatabaseHandler, self.LOCKOUT_PARAMETERS
        )
        cache_results = self.run_failure_sequence(
            AxesCacheHandler, self.LOCKOUT_PARAMETERS
        )

        self.assertEqual(database_results, cache_results)
        self.assertEqual(
            [result["failures"] for result in database_results],
            list(range(1, get_failure_limit(None, None) + 1)),
        )
        self.assertTrue(database_results[-1]["locked_out"])
        self.assertEqual(
            database_results[-1]["request_failures"],
            database_results[-1]["failure_limit"],
        )
        failure_limit = get_failure_limit(None, None)
        for failure_number, result in enumerate(database_results, start=1):
            self.assertEqual(result["failure_limit"], failure_limit)
            self.assertEqual(result["locked_out"], failure_number >= failure_limit)

    def test_scope_order_does_not_change_handler_results(self):
        reversed_parameters = [
            list(reversed(parameter)) if isinstance(parameter, list) else parameter
            for parameter in reversed(self.LOCKOUT_PARAMETERS)
        ]

        for handler_class in self.HANDLER_CLASSES:
            with self.subTest(handler=handler_class.__name__):
                self.assertEqual(
                    self.run_failure_sequence(
                        handler_class, self.LOCKOUT_PARAMETERS
                    ),
                    self.run_failure_sequence(handler_class, reversed_parameters),
                )

    def test_value_boundary_collision_does_not_merge_clients(self):
        with override_settings(
            AXES_LOCKOUT_PARAMETERS=[["username", "ip_address"]],
            AXES_HANDLER="axes.handlers.cache.AxesCacheHandler",
        ):
            first_request = RequestFactory().post(
                "/admin/login/",
                data={"username": "foo1", "password": "wrong-password"},
                REMOTE_ADDR="2.3.4.5",
            )
            second_request = RequestFactory().post(
                "/admin/login/",
                data={"username": "foo", "password": "wrong-password"},
                REMOTE_ADDR="12.3.4.5",
            )
            first_request.axes_locked_out = False
            second_request.axes_locked_out = False

            AxesProxyHandler.user_login_failed(
                sender=None,
                request=first_request,
                credentials={"username": "foo1"},
            )
            AxesProxyHandler.user_login_failed(
                sender=None,
                request=second_request,
                credentials={"username": "foo"},
            )

            self.assertEqual(AxesProxyHandler.get_failures(first_request), 1)
            self.assertEqual(AxesProxyHandler.get_failures(second_request), 1)

    def test_legacy_cache_keys_are_not_reused_by_versioned_keys(self):
        legacy_digest = "legacy-cache-digest"
        legacy_key = f"axes-{legacy_digest}"

        with override_settings(
            AXES_LOCKOUT_PARAMETERS=["username"],
            AXES_HANDLER="axes.handlers.cache.AxesCacheHandler",
        ):
            cache.set(legacy_key, get_failure_limit(None, None))
            request = self.failure_request()

            AxesProxyHandler.user_login_failed(
                sender=None,
                request=request,
                credentials={"username": "shared-user"},
            )

            self.assertEqual(
                cache.get(legacy_key), get_failure_limit(None, None)
            )
            self.assertEqual(request.axes_failures_since_start, 1)
            self.assertFalse(request.axes_locked_out)

    def test_empty_and_unknown_scopes_raise_before_counting_failures(self):
        invalid_configurations = (
            [[]],
            ["unknown_parameter"],
            [["username", "username"]],
            [42],
        )

        for handler_class in self.HANDLER_CLASSES:
            for lockout_parameters in invalid_configurations:
                with self.subTest(
                    handler=handler_class.__name__,
                    lockout_parameters=lockout_parameters,
                ):
                    with override_settings(
                        AXES_HANDLER=(
                            f"{handler_class.__module__}."
                            f"{handler_class.__name__}"
                        ),
                        AXES_LOCKOUT_PARAMETERS=lockout_parameters,
                    ):
                        request = self.failure_request()
                        with self.assertRaises((TypeError, ValueError)):
                            AxesProxyHandler.user_login_failed(
                                sender=None,
                                request=request,
                                credentials={"username": "shared-user"},
                            )

                    self.assertEqual(AccessAttempt.objects.count(), 0)
                    self.assertEqual(cache._cache, {})

    def test_duplicate_scopes_are_counted_once_for_each_handler(self):
        lockout_parameters = ["username", "username", ["username", "ip_address"]]

        for handler_class in self.HANDLER_CLASSES:
            with self.subTest(handler=handler_class.__name__):
                results = self.run_failure_sequence(
                    handler_class, lockout_parameters
                )
                self.assertEqual(
                    [result["failures"] for result in results],
                    list(range(1, get_failure_limit(None, None) + 1)),
                )

    def test_lockout_response_cool_off_is_consistent_across_handlers(self):
        lockout_parameters = ["username", ["username", "ip_address"]]
        response_headers = {}

        for handler_class in self.HANDLER_CLASSES:
            with override_settings(
                AXES_HANDLER=(
                    f"{handler_class.__module__}.{handler_class.__name__}"
                ),
                AXES_LOCKOUT_PARAMETERS=lockout_parameters,
                AXES_COOLOFF_TIME=timedelta(seconds=120),
                AXES_ENABLE_RETRY_AFTER_HEADER=True,
            ):
                for _ in range(get_failure_limit(None, None)):
                    response = self.client.post(
                        reverse("admin:login"),
                        {
                            "username": "shared-user",
                            "password": "wrong-password",
                        },
                        REMOTE_ADDR="2.3.4.5",
                        HTTP_USER_AGENT="test-browser",
                    )

                self.assertEqual(response.status_code, 429)
                response_headers[handler_class.__name__] = response["Retry-After"]
                AccessAttempt.objects.all().delete()
                cache.clear()

        self.assertEqual(
            response_headers,
            {
                AxesDatabaseHandler.__name__: "120",
                AxesCacheHandler.__name__: "120",
            },
        )


class ConcurrentFailureCountTestCase(AxesTestCase):
    thread_count = 10

    def request_for_failure(self):
        request = RequestFactory().post(
            "/admin/login/",
            data={"username": "concurrent-user", "password": "wrong-password"},
            REMOTE_ADDR="10.0.0.1",
            HTTP_USER_AGENT="test-browser",
        )
        request.axes_locked_out = False
        return request

    def record_failure(self, handler, barrier):
        barrier.wait()
        request = self.request_for_failure()
        credentials = {"username": "concurrent-user"}
        AxesProxyHandler.user_login_failed(
            sender=None, request=request, credentials=credentials
        )
        return request.axes_failures_since_start

    def test_cache_failures_are_counted_without_lost_updates(self):
        handler = AxesCacheHandler()
        barrier = Barrier(self.thread_count)

        with override_settings(
            AXES_LOCKOUT_PARAMETERS=["username"],
            AXES_HANDLER="axes.handlers.cache.AxesCacheHandler",
            AXES_FAILURE_LIMIT=50,
        ):
            with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
                failure_counts = list(
                    executor.map(
                        lambda _: self.record_failure(handler, barrier),
                        range(self.thread_count),
                    )
                )

            request = self.request_for_failure()
            AxesProxyHandler.update_request(request)
            self.assertEqual(
                handler.get_failures(request, {"username": "concurrent-user"}),
                self.thread_count,
            )
            self.assertEqual(
                sorted(failure_counts),
                list(range(1, self.thread_count + 1)),
            )


@override_settings(AXES_FAILURE_LIMIT=50)
class ConcurrentDatabaseFailureCountTestCase(TransactionTestCase):
    thread_count = 10

    def setUp(self):
        cache.clear()

    def tearDown(self):
        cache.clear()

    def request_for_failure(self):
        request = RequestFactory().post(
            "/admin/login/",
            data={"username": "concurrent-user", "password": "wrong-password"},
            REMOTE_ADDR="10.0.0.1",
            HTTP_USER_AGENT="test-browser",
        )
        request.axes_locked_out = False
        return request

    def record_failure(self, handler, barrier):
        barrier.wait()
        request = self.request_for_failure()
        credentials = {"username": "concurrent-user"}
        AxesProxyHandler.user_login_failed(
            sender=None, request=request, credentials=credentials
        )
        return request.axes_failures_since_start

    def test_database_failures_are_counted_without_lost_updates(self):
        handler = AxesDatabaseHandler()
        barrier = Barrier(self.thread_count)

        with override_settings(
            AXES_LOCKOUT_PARAMETERS=["username"],
            AXES_HANDLER="axes.handlers.database.AxesDatabaseHandler",
        ):
            with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
                failure_counts = list(
                    executor.map(
                        lambda _: self.record_failure(handler, barrier),
                        range(self.thread_count),
                    )
                )

            request = self.request_for_failure()
            AxesProxyHandler.update_request(request)
            self.assertEqual(
                handler.get_failures(request, {"username": "concurrent-user"}),
                self.thread_count,
            )
            self.assertEqual(
                sorted(failure_counts),
                list(range(1, self.thread_count + 1)),
            )


@override_settings(AXES_HANDLER="axes.handlers.dummy.AxesDummyHandler")
class AxesDummyHandlerTestCase(AxesHandlerBaseTestCase):
    def test_handler(self):
        for _ in range(settings.AXES_FAILURE_LIMIT):
            self.login()

        self.check_login()

    def test_handler_is_allowed(self):
        self.assertEqual(True, AxesProxyHandler.is_allowed(self.request, {}))

    def test_handler_get_failures(self):
        self.assertEqual(0, AxesProxyHandler.get_failures(self.request, {}))


@override_settings(AXES_HANDLER="axes.handlers.test.AxesTestHandler")
class AxesTestHandlerTestCase(AxesHandlerBaseTestCase):
    def test_handler_reset_attempts(self):
        self.assertEqual(0, AxesProxyHandler.reset_attempts())

    def test_handler_reset_logs(self):
        self.assertEqual(0, AxesProxyHandler.reset_logs())

    def test_handler_is_allowed(self):
        self.assertEqual(True, AxesProxyHandler.is_allowed(self.request, {}))

    def test_handler_get_failures(self):
        self.assertEqual(0, AxesProxyHandler.get_failures(self.request, {}))


@override_settings(AXES_HANDLER="axes.handlers.database.AxesDatabaseHandler", AXES_COOLOFF_TIME=timedelta(seconds=10))
class AxesDatabaseHandlerExpirationFlagTestCase(AxesTestCase):
    def setUp(self):
        super().setUp()
        self.handler = AxesDatabaseHandler()
        self.mock_request = MagicMock()
        self.mock_credentials = None

    @override_settings(AXES_USE_ATTEMPT_EXPIRATION=True)
    @patch("axes.handlers.database.log")
    @patch("axes.models.AccessAttempt.objects.filter")
    @patch("django.utils.timezone.now")
    def test_clean_expired_user_attempts_expiration_true(self, mock_now, mock_filter, mock_log):
        mock_now.return_value = datetime(2025, 1, 1, tzinfo=dt_timezone.utc)
        mock_qs = MagicMock()
        mock_filter.return_value = mock_qs
        mock_qs.delete.return_value = (3, None)

        count = self.handler.clean_expired_user_attempts(request=None, credentials=None)
        mock_filter.assert_called_once_with(expiration__expires_at__lte=mock_now.return_value)
        mock_qs.delete.assert_called_once()
        mock_log.info.assert_called_with(
            "AXES: Cleaned up %s expired access attempts from database that expiry were older than %s",
            3,
            mock_now.return_value,
        )
        self.assertEqual(count, 3)

    @override_settings(AXES_USE_ATTEMPT_EXPIRATION=True)
    @patch("axes.handlers.database.log")
    def test_clean_expired_user_attempts_expiration_true_with_complete_deletion(self, mock_log):
        AccessAttempt.objects.all().delete()
        dummy_attempt = AccessAttempt.objects.create(
            username="test_user",
            ip_address="192.168.1.1",
            failures_since_start=1,
            user_agent="test_agent",
        )
        dummy_attempt.expiration = AccessAttemptExpiration.objects.create(
            access_attempt=dummy_attempt,
            expires_at=timezone.now() - timedelta(days=1)  # Set to expire in the past
        )

        count = self.handler.clean_expired_user_attempts(request=None, credentials=None)
        mock_log.info.assert_called_once()

        # comparing count=2, as one is the dummy attempt and one is the expiration
        self.assertEqual(count, 2)
        self.assertEqual(
            AccessAttempt.objects.count(), 0
        )
        self.assertEqual(
            AccessAttemptExpiration.objects.count(), 0
        )

    @override_settings(AXES_USE_ATTEMPT_EXPIRATION=True)
    @patch("axes.handlers.database.log")
    def test_clean_expired_user_attempts_expiration_true_with_partial_deletion(self, mock_log):

        attempt_not_expired = AccessAttempt.objects.create(
            username="test_user",
            ip_address="192.168.1.1",
            failures_since_start=1,
            user_agent="test_agent",
        )
        attempt_not_expired.expiration = AccessAttemptExpiration.objects.create(
            access_attempt=attempt_not_expired,
            expires_at=timezone.now() + timedelta(days=1)  # Set to expire in the future
        )

        attempt_expired = AccessAttempt.objects.create(
            username="test_user_2",
            ip_address="192.168.1.2",
            failures_since_start=1,
            user_agent="test_agent",
        )
        attempt_expired.expiration = AccessAttemptExpiration.objects.create(
            access_attempt=attempt_expired,
            expires_at=timezone.now() - timedelta(days=1)  # Set to expire in the past
        )

        access_attempt_count = AccessAttempt.objects.count()
        access_attempt_expiration_count = AccessAttemptExpiration.objects.count()

        count = self.handler.clean_expired_user_attempts(request=None, credentials=None)
        mock_log.info.assert_called_once()

        # comparing count=2, as one is the dummy attempt and one is the expiration
        self.assertEqual(count, 2)
        self.assertEqual(
            AccessAttempt.objects.count(), access_attempt_count - 1
        )
        self.assertEqual(
            AccessAttemptExpiration.objects.count(), access_attempt_expiration_count - 1
        )

    @override_settings(AXES_USE_ATTEMPT_EXPIRATION=True)
    @patch("axes.handlers.database.log")
    def test_clean_expired_user_attempts_expiration_true_with_no_deletion(self, mock_log):

        attempt_not_expired_1 = AccessAttempt.objects.create(
            username="test_user",
            ip_address="192.168.1.1",
            failures_since_start=1,
            user_agent="test_agent",
        )
        attempt_not_expired_1.expiration = AccessAttemptExpiration.objects.create(
            access_attempt=attempt_not_expired_1,
            expires_at=timezone.now() + timedelta(days=1)  # Set to expire in the future
        )

        attempt_not_expired_2 = AccessAttempt.objects.create(
            username="test_user_2",
            ip_address="192.168.1.2",
            failures_since_start=1,
            user_agent="test_agent",
        )
        attempt_not_expired_2.expiration = AccessAttemptExpiration.objects.create(
            access_attempt=attempt_not_expired_2,
            expires_at=timezone.now() + timedelta(days=2)  # Set to expire in the future
        )

        access_attempt_count = AccessAttempt.objects.count()
        access_attempt_expiration_count = AccessAttemptExpiration.objects.count()

        count = self.handler.clean_expired_user_attempts(request=None, credentials=None)
        mock_log.info.assert_called_once()

        # comparing count=2, as one is the dummy attempt and one is the expiration
        self.assertEqual(count, 0)
        self.assertEqual(
            AccessAttempt.objects.count(), access_attempt_count 
        )
        self.assertEqual(
            AccessAttemptExpiration.objects.count(), access_attempt_expiration_count
        )

    @override_settings(AXES_USE_ATTEMPT_EXPIRATION=False)
    @patch("axes.handlers.database.log")
    @patch("axes.handlers.database.get_cool_off_threshold")
    @patch("axes.models.AccessAttempt.objects.filter")
    def test_clean_expired_user_attempts_expiration_false(self, mock_filter, mock_get_threshold, mock_log):
        mock_get_threshold.return_value = "fake-threshold"
        mock_qs = MagicMock()
        mock_filter.return_value = mock_qs
        mock_qs.delete.return_value = (2, None)

        count = self.handler.clean_expired_user_attempts(request=self.mock_request, credentials=None)
        mock_filter.assert_called_once_with(attempt_time__lte="fake-threshold")
        mock_qs.delete.assert_called_once()
        mock_log.info.assert_called_with(
            "AXES: Cleaned up %s expired access attempts from database that were older than %s",
            2,
            "fake-threshold",
        )
        self.assertEqual(count, 2)

    @override_settings(AXES_COOLOFF_TIME=None)
    @patch("axes.handlers.database.log")
    def test_clean_expired_user_attempts_no_cooloff(self, mock_log):
        count = self.handler.clean_expired_user_attempts(request=None, credentials=None)
        mock_log.debug.assert_called_with(
            "AXES: Skipping clean for expired access attempts because no AXES_COOLOFF_TIME is configured"
        )
        self.assertEqual(count, 0)
