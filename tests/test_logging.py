from datetime import timedelta
import json
from io import StringIO
from unittest.mock import patch, Mock

from django.core.management import call_command
from django.test import override_settings
from django.utils import timezone

from axes import __version__
from axes.apps import AppConfig
from axes.handlers.database import AxesDatabaseHandler
from axes.models import AccessAttempt, AccessFailureLog, AccessLog
from tests.base import AxesTestCase

_BEGIN = "AXES: BEGIN version %s, %s"
_VERSION = __version__


@patch("axes.apps.AppConfig.initialized", False)
@patch("axes.apps.log")
class AppsTestCase(AxesTestCase):
    def test_axes_config_log_re_entrant(self, log):
        """
        Test that initialize call count does not increase on repeat calls.
        """

        AppConfig.initialize()
        calls = log.info.call_count

        AppConfig.initialize()
        self.assertTrue(
            calls == log.info.call_count and calls > 0,
            "AxesConfig.initialize needs to be re-entrant",
        )

    @override_settings(AXES_VERBOSE=False)
    def test_axes_config_log_not_verbose(self, log):
        AppConfig.initialize()
        self.assertFalse(log.info.called)

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username"])
    def test_axes_config_log_user_only(self, log):
        AppConfig.initialize()
        log.info.assert_called_with(_BEGIN, _VERSION, "blocking by username")

    def test_axes_config_log_ip_only(self, log):
        AppConfig.initialize()
        log.info.assert_called_with(_BEGIN, _VERSION, "blocking by ip_address")

    @override_settings(AXES_LOCKOUT_PARAMETERS=[["username", "ip_address"]])
    def test_axes_config_log_user_ip(self, log):
        AppConfig.initialize()
        log.info.assert_called_with(
            _BEGIN, _VERSION, "blocking by combination of username and ip_address"
        )

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username", "ip_address"])
    def test_axes_config_log_user_or_ip(self, log):
        AppConfig.initialize()
        log.info.assert_called_with(_BEGIN, _VERSION, "blocking by username or ip_address")


class AccessLogTestCase(AxesTestCase):
    def test_access_log_on_logout(self):
        """
        Test a valid logout and make sure the logout_time is updated only for that.
        """

        self.login(is_valid_username=True, is_valid_password=True)
        latest_log = AccessLog.objects.latest("id")
        self.assertIsNone(latest_log.logout_time)
        other_log = self.create_log(session_hash='not-the-session')
        self.assertIsNone(other_log.logout_time)

        response = self.logout()
        self.assertContains(response, "Logged out")
        other_log.refresh_from_db()
        self.assertIsNone(other_log.logout_time)
        latest_log.refresh_from_db()
        self.assertIsNotNone(latest_log.logout_time)

    @override_settings(DATA_UPLOAD_MAX_NUMBER_FIELDS=1500)
    def test_log_data_truncated(self):
        """
        Test that get_query_str properly truncates data to the max_length (default 1024).
        """

        # An impossibly large post dict
        extra_data = {"too-large-field": "x" * 2 ** 16}
        self.login(**extra_data)
        self.assertEqual(len(AccessAttempt.objects.latest("id").post_data), 1024)

    @override_settings(AXES_DISABLE_ACCESS_LOG=True)
    def test_valid_logout_without_success_log(self):
        AccessLog.objects.all().delete()

        response = self.login(is_valid_username=True, is_valid_password=True)
        response = self.logout()

        self.assertEqual(AccessLog.objects.all().count(), 0)
        self.assertContains(response, "Logged out", html=True)

    @override_settings(AXES_DISABLE_ACCESS_LOG=True)
    def test_valid_login_without_success_log(self):
        """
        Test that a valid login does not generate an AccessLog when DISABLE_SUCCESS_ACCESS_LOG is True.
        """

        AccessLog.objects.all().delete()

        response = self.login(is_valid_username=True, is_valid_password=True)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(AccessLog.objects.all().count(), 0)

    @override_settings(AXES_DISABLE_ACCESS_LOG=True)
    def test_valid_logout_without_log(self):
        AccessLog.objects.all().delete()

        response = self.login(is_valid_username=True, is_valid_password=True)
        response = self.logout()

        self.assertEqual(AccessLog.objects.count(), 0)
        self.assertContains(response, "Logged out", html=True)

    @override_settings(AXES_DISABLE_ACCESS_LOG=True)
    def test_non_valid_login_without_log(self):
        """
        Test that a non-valid login does generate an AccessLog when DISABLE_ACCESS_LOG is True.
        """
        AccessLog.objects.all().delete()

        response = self.login(is_valid_username=True, is_valid_password=False)
        self.assertEqual(response.status_code, 200)

        self.assertEqual(AccessLog.objects.all().count(), 0)


@override_settings(
    AXES_LOG_FIELD_PROJECTION_ENABLED=True,
    AXES_ENABLE_ACCESS_FAILURE_LOG=True,
)
class AccessAttemptProjectionTestCase(AxesTestCase):
    def test_post_secrets_are_masked_in_attempt_payload(self):
        response = self.login(
            password="hunter2",
            token="tok-secret",
            email="victim@example.com",
            cookie="sessionid=abc123",
        )
        self.assertEqual(response.status_code, 200)

        attempt = AccessAttempt.objects.latest("id")
        payload = json.loads(attempt.post_data)
        self.assertEqual(payload["password"], "*" * 20)
        self.assertEqual(payload["token"], "*" * 20)
        self.assertEqual(payload["email"], "*" * 20)
        self.assertEqual(payload["cookie"], "*" * 20)

        rendered = attempt.post_data
        self.assertNotIn("hunter2", rendered)
        self.assertNotIn("tok-secret", rendered)
        self.assertNotIn("victim@example.com", rendered)
        self.assertNotIn("abc123", rendered)
        self.assertIn("username", payload)

    def test_deeply_nested_json_is_bounded_and_valid(self):
        nested = {"leaf": "value"}
        for _ in range(3000):
            nested = {"outer": nested}
        response = self.login(payload=json.dumps(nested))
        self.assertEqual(response.status_code, 200)

        rendered = AccessAttempt.objects.latest("id").post_data
        json.loads(rendered)
        self.assertLessEqual(len(rendered.encode("utf-8")), 4096)
        self.assertIn("[truncated]", rendered)

    def test_repeated_password_fields_are_all_masked(self):
        response = self.client.post(
            self.path_info,
            [
                ("username", "repeat-user"),
                ("password", "first-secret"),
                ("password", "second-secret"),
            ],
            REMOTE_ADDR=self.ip_address,
            headers={"user-agent": self.user_agent},
        )
        self.assertEqual(response.status_code, 200)
        payload = json.loads(AccessAttempt.objects.latest("id").post_data)
        self.assertEqual(payload["password"], ["*" * 20, "*" * 20])

    def test_repeated_failures_keep_single_parseable_bounded_projection(self):
        for index in range(3):
            self.login(username="steady-user", token=f"secret-{index}")

        attempt = AccessAttempt.objects.get(username="steady-user")
        payload = json.loads(attempt.post_data)
        self.assertLessEqual(
            len(attempt.post_data.encode("utf-8")), 4096
        )
        self.assertEqual(payload["token"], "*" * 20)
        self.assertNotIn("---------", attempt.post_data)
        rendered = attempt.post_data
        self.assertNotIn("secret-0", rendered)
        self.assertNotIn("secret-1", rendered)
        self.assertNotIn("secret-2", rendered)

    def test_failure_log_keeps_correlation_fields_only(self):
        response = self.login()
        self.assertEqual(response.status_code, 200)

        failure = AccessFailureLog.objects.latest("id")
        self.assertTrue(failure.user_agent)
        self.assertTrue(failure.ip_address)
        self.assertEqual(failure.http_accept, "")
        self.assertEqual(failure.path_info, "")
        self.assertEqual(failure.http_referer, "")
        self.assertIn(len(failure.session_hash), (0, 64))

    def test_success_log_keeps_correlation_fields_only(self):
        self.login(is_valid_username=True, is_valid_password=True)
        success = AccessLog.objects.latest("id")
        self.assertTrue(success.username)
        self.assertTrue(success.user_agent)
        self.assertIn(len(success.session_hash), (0, 64))
        self.assertEqual(success.http_accept, "")
        self.assertEqual(success.path_info, "")


@override_settings(
    AXES_LOG_FIELD_PROJECTION_ENABLED=True,
    AXES_ENABLE_ACCESS_FAILURE_LOG=True,
)
class LockoutRegressionTestCase(AxesTestCase):
    def test_attempt_still_explains_failures_and_related_logs(self):
        for _ in range(3):
            self.login(username="lockout-user")

        attempt = AccessAttempt.objects.get(username="lockout-user")
        self.assertEqual(attempt.failures_since_start, 3)
        self.assertIn("3 failed login(s)", attempt.get_lockout_explanation())
        self.assertEqual(len(attempt.get_related_failure_logs()), 3)

    @override_settings(AXES_FAILURE_LIMIT=2)
    def test_model_lockout_state_and_failure_log_flag(self):
        self.login(username="limit-user")
        attempt = AccessAttempt.objects.get(username="limit-user")
        self.assertFalse(attempt.is_locked_out())

        self.login(username="limit-user")
        attempt.refresh_from_db()
        self.assertTrue(attempt.is_locked_out())
        self.assertTrue(AccessFailureLog.objects.latest("id").locked_out)


@override_settings(
    AXES_RETENTION_ENABLED=True,
    AXES_RETENTION_DAYS={"failure": 30, "success": 90, "attempt": None},
)
class RetentionPolicyTestCase(AxesTestCase):
    def setUp(self):
        super().setUp()
        self.handler = AxesDatabaseHandler()

    def _create_old(self, model, days, **kwargs):
        with patch(
            "django.utils.timezone.now",
            Mock(return_value=timezone.now() - timedelta(days=days)),
        ):
            return model.objects.create(**kwargs)

    def test_age_based_cleanup_uses_tiered_thresholds(self):
        old_failure = self._create_old(
            AccessFailureLog,
            31,
            username="old-failure",
            ip_address=self.ip_address,
            user_agent=self.user_agent,
            http_accept="",
            path_info="",
        )
        fresh_failure = self.create_failure_log(username="fresh-failure")
        old_success = self._create_old(
            AccessLog,
            91,
            username="old-success",
            ip_address=self.ip_address,
            user_agent=self.user_agent,
            http_accept="",
            path_info="",
        )
        fresh_success = self.create_log(username="fresh-success")
        with patch(
            "django.utils.timezone.now",
            Mock(return_value=timezone.now() - timedelta(days=400)),
        ):
            old_attempt = self.create_attempt(
                username="old-attempt", failures_since_start=1
            )

        audit = self.handler.apply_retention_policy()

        self.assertFalse(
            AccessFailureLog.objects.filter(pk=old_failure.pk).exists()
        )
        self.assertTrue(
            AccessFailureLog.objects.filter(pk=fresh_failure.pk).exists()
        )
        self.assertFalse(AccessLog.objects.filter(pk=old_success.pk).exists())
        self.assertTrue(AccessLog.objects.filter(pk=fresh_success.pk).exists())
        self.assertTrue(AccessAttempt.objects.filter(pk=old_attempt.pk).exists())

        categories = {entry["category"]: entry for entry in audit}
        self.assertEqual(categories["failure"]["reason"], "age_over_30_days")
        self.assertEqual(categories["failure"]["count"], 1)
        self.assertEqual(categories["success"]["reason"], "age_over_90_days")
        self.assertEqual(categories["success"]["count"], 1)
        self.assertNotIn("attempt", categories)
        rendered_audit = json.dumps(audit)
        self.assertNotIn("old-failure", rendered_audit)
        self.assertNotIn("old-success", rendered_audit)

    def test_policy_is_idempotent(self):
        self._create_old(
            AccessFailureLog,
            60,
            username="gone",
            ip_address=self.ip_address,
            user_agent=self.user_agent,
            http_accept="",
            path_info="",
        )
        first = self.handler.apply_retention_policy()
        second = self.handler.apply_retention_policy()

        self.assertEqual(
            next(e for e in first if e["category"] == "failure")["count"], 1
        )
        self.assertEqual(
            next(e for e in second if e["category"] == "failure")["count"], 0
        )
        self.assertEqual(AccessFailureLog.objects.count(), 0)

    def test_delete_failure_does_not_break_login(self):
        with patch.object(
            AccessFailureLog.objects,
            "delete",
            side_effect=RuntimeError("database unavailable"),
        ):
            response = self.login()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(AccessAttempt.objects.exists())

    def test_management_command_reports_audit_without_content(self):
        self._create_old(
            AccessFailureLog,
            60,
            username="secret-user",
            ip_address=self.ip_address,
            user_agent=self.user_agent,
            http_accept="",
            path_info="",
        )
        out = StringIO()
        call_command("axes_apply_retention", stdout=out)
        report = out.getvalue()
        self.assertIn("failure", report)
        self.assertIn("age_over_30_days", report)
        self.assertNotIn("secret-user", report)


class RetentionPolicyDisabledTestCase(AxesTestCase):
    def test_disabled_policy_is_a_noop(self):
        self.create_failure_log(
            username="kept", http_accept="", path_info=""
        )
        audit = AxesDatabaseHandler().apply_retention_policy()
        self.assertEqual(audit, [])
        self.assertTrue(
            AccessFailureLog.objects.filter(username="kept").exists()
        )


class FailureSuccessCorrelationTestCase(AxesTestCase):
    @override_settings(
        AXES_LOG_FIELD_PROJECTION_ENABLED=True,
        AXES_ENABLE_ACCESS_FAILURE_LOG=True,
    )
    def test_failure_log_can_resolve_later_success_log(self):
        self.login()
        failure = AccessFailureLog.objects.latest("id")
        self.login(is_valid_username=True, is_valid_password=True)
        success = AccessLog.objects.latest("id")

        self.assertEqual(failure.get_related_success_log(), success)
