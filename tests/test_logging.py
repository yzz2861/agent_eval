from datetime import timedelta
from unittest.mock import patch

from django.db import transaction
from django.test import override_settings
from django.utils.timezone import now

from axes import __version__
from axes.apps import AppConfig
from axes.conf import settings
from axes.handlers.proxy import AxesProxyHandler
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


@override_settings(AXES_ENABLE_ACCESS_FAILURE_LOG=True)
class AccessFailureLogLimitTestCase(AxesTestCase):
    """
    Tests for the AXES_ACCESS_FAILURE_LOG_PER_USER_LIMIT trimming semantics.
    """

    def create_failure_logs(self, count, **kwargs):
        return [self.create_failure_log(**kwargs) for _ in range(count)]

    def remaining_pks(self):
        return set(
            AccessFailureLog.objects.filter(username=self.username).values_list(
                "pk", flat=True
            )
        )

    @override_settings(AXES_ACCESS_FAILURE_LOG_PER_USER_LIMIT=3)
    def test_failure_log_limit_orders_by_attempt_time_not_pk(self):
        """
        Restored data can have primary keys that do not follow attempt_time order;
        the newest records by attempt_time must be kept regardless of pk order.
        """

        logs = self.create_failure_logs(5)
        base = now()
        for index, failure_log in enumerate(reversed(logs)):
            AccessFailureLog.objects.filter(pk=failure_log.pk).update(
                attempt_time=base + timedelta(seconds=index)
            )

        removed = AxesProxyHandler.remove_out_of_limit_failure_logs(
            username=self.username
        )
        self.assertEqual(removed, 2)
        self.assertEqual(
            self.remaining_pks(), {logs[0].pk, logs[1].pk, logs[2].pk}
        )

    @override_settings(AXES_ACCESS_FAILURE_LOG_PER_USER_LIMIT=2)
    def test_failure_log_limit_same_attempt_time_uses_pk_tiebreak(self):
        logs = self.create_failure_logs(5)
        AccessFailureLog.objects.filter(username=self.username).update(
            attempt_time=now()
        )

        removed = AxesProxyHandler.remove_out_of_limit_failure_logs(
            username=self.username
        )
        self.assertEqual(removed, 3)
        self.assertEqual(self.remaining_pks(), {logs[3].pk, logs[4].pk})

    @override_settings(AXES_ACCESS_FAILURE_LOG_PER_USER_LIMIT=0)
    def test_failure_log_limit_zero_removes_all_user_logs(self):
        self.create_failure_logs(3)
        other = self.create_failure_log(username="axes-other-username")

        removed = AxesProxyHandler.remove_out_of_limit_failure_logs(
            username=self.username
        )
        self.assertEqual(removed, 3)
        self.assertFalse(
            AccessFailureLog.objects.filter(username=self.username).exists()
        )
        self.assertTrue(AccessFailureLog.objects.filter(pk=other.pk).exists())

    @override_settings(AXES_ACCESS_FAILURE_LOG_PER_USER_LIMIT=1)
    def test_failure_log_limit_one_keeps_single_newest(self):
        logs = self.create_failure_logs(4)

        removed = AxesProxyHandler.remove_out_of_limit_failure_logs(
            username=self.username
        )
        self.assertEqual(removed, 3)
        self.assertEqual(self.remaining_pks(), {logs[3].pk})

    @override_settings(AXES_ACCESS_FAILURE_LOG_PER_USER_LIMIT=1000)
    def test_failure_log_limit_explicit_argument_overrides_setting(self):
        self.create_failure_logs(3)

        removed = AxesProxyHandler.remove_out_of_limit_failure_logs(
            username=self.username, limit=1
        )
        self.assertEqual(removed, 2)
        self.assertEqual(
            AccessFailureLog.objects.filter(username=self.username).count(), 1
        )

    @override_settings(AXES_ACCESS_FAILURE_LOG_PER_USER_LIMIT=2)
    def test_failure_log_limit_repeated_calls_are_idempotent(self):
        self.create_failure_logs(5)

        first = AxesProxyHandler.remove_out_of_limit_failure_logs(
            username=self.username
        )
        second = AxesProxyHandler.remove_out_of_limit_failure_logs(
            username=self.username
        )
        self.assertEqual(first, 3)
        self.assertEqual(second, 0)
        self.assertEqual(
            AccessFailureLog.objects.filter(username=self.username).count(), 2
        )

    @override_settings(AXES_ACCESS_FAILURE_LOG_PER_USER_LIMIT=2)
    def test_failure_log_limit_delete_rolls_back_with_transaction(self):
        self.create_failure_logs(4)

        with self.assertRaises(RuntimeError):
            with transaction.atomic():
                removed = AxesProxyHandler.remove_out_of_limit_failure_logs(
                    username=self.username
                )
                self.assertEqual(removed, 2)
                raise RuntimeError("simulated failure after trimming")

        self.assertEqual(
            AccessFailureLog.objects.filter(username=self.username).count(), 4
        )

    @override_settings(AXES_ACCESS_FAILURE_LOG_PER_USER_LIMIT=2)
    def test_failure_log_limit_concurrent_writes_keep_newest(self):
        """
        Simulate two workers interleaving writes and trims for the same user:
        the newest records must survive and repeated trims must be no-ops.
        """

        first = self.create_failure_log()
        second = self.create_failure_log()
        base = now()
        for index, failure_log in enumerate((first, second)):
            AccessFailureLog.objects.filter(pk=failure_log.pk).update(
                attempt_time=base + timedelta(seconds=index)
            )

        # worker A trims while worker B is about to write a newer record
        self.assertEqual(
            AxesProxyHandler.remove_out_of_limit_failure_logs(username=self.username),
            0,
        )
        third = self.create_failure_log()
        AccessFailureLog.objects.filter(pk=third.pk).update(
            attempt_time=base + timedelta(seconds=2)
        )

        # worker B trims after its write; the newest records must survive
        self.assertEqual(
            AxesProxyHandler.remove_out_of_limit_failure_logs(username=self.username),
            1,
        )
        self.assertEqual(self.remaining_pks(), {second.pk, third.pk})

        # a repeated trim from either worker is a no-op
        self.assertEqual(
            AxesProxyHandler.remove_out_of_limit_failure_logs(username=self.username),
            0,
        )
        self.assertEqual(self.remaining_pks(), {second.pk, third.pk})

    @patch("axes.handlers.database.AxesDatabaseHandler.remove_out_of_limit_failure_logs")
    @patch("axes.handlers.database.log")
    def test_failure_log_limit_trim_error_does_not_block_login(
        self, mock_log, mock_trim
    ):
        """
        A trimming failure (e.g. a deadlock with a concurrent trim) must not
        lose the security event nor block the login flow.
        """

        mock_trim.side_effect = Exception("simulated concurrent trim failure")

        response = self.login(is_valid_username=True, is_valid_password=False)
        self.assertEqual(response.status_code, self.STATUS_SUCCESS)
        self.assertEqual(
            AccessFailureLog.objects.filter(username=self.VALID_USERNAME).count(), 1
        )

        mock_log.exception.assert_called_once()
        args = mock_log.exception.call_args[0]
        self.assertIn(self.VALID_USERNAME, args)
        self.assertIn(settings.AXES_ACCESS_FAILURE_LOG_PER_USER_LIMIT, args)

    @override_settings(AXES_ACCESS_FAILURE_LOG_PER_USER_LIMIT=1)
    def test_failure_log_limit_enforced_on_login_failure(self):
        self.login(is_valid_username=True, is_valid_password=False)
        self.login(is_valid_username=True, is_valid_password=False)

        failure_logs = AccessFailureLog.objects.filter(username=self.VALID_USERNAME)
        self.assertEqual(failure_logs.count(), 1)
        self.assertEqual(
            failure_logs.get().pk, AccessFailureLog.objects.latest("pk").pk
        )

    @override_settings(AXES_ACCESS_FAILURE_LOG_PER_USER_LIMIT=1)
    def test_valid_login_not_affected_by_failure_log_limit(self):
        response = self.login(is_valid_username=True, is_valid_password=True)
        self.assertEqual(response.status_code, self.ALLOWED)
        self.assertEqual(
            AccessLog.objects.filter(username=self.VALID_USERNAME).count(), 1
        )
        self.assertEqual(AccessFailureLog.objects.count(), 0)
