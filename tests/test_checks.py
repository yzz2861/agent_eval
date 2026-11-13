from django.core.checks import run_checks, Warning  # pylint: disable=redefined-builtin
from django.test import override_settings, modify_settings
from datetime import timedelta

from axes.backends import AxesStandaloneBackend
from axes.checks import Messages, Hints, Codes
from axes.conf import LockoutTier
from tests.base import AxesTestCase


class CacheCheckTestCase(AxesTestCase):
    @override_settings(
        AXES_HANDLER="axes.handlers.cache.AxesCacheHandler",
        CACHES={
            "default": {
                "BACKEND": "django.core.cache.backends.db.DatabaseCache",
                "LOCATION": "axes_cache",
            }
        },
    )
    def test_cache_check(self):
        warnings = run_checks()
        self.assertEqual(warnings, [])

    @override_settings(
        AXES_HANDLER="axes.handlers.cache.AxesCacheHandler",
        CACHES={
            "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
        },
    )
    def test_cache_check_warnings(self):
        warnings = run_checks()
        warning = Warning(
            msg=Messages.CACHE_INVALID, hint=Hints.CACHE_INVALID, id=Codes.CACHE_INVALID
        )

        self.assertEqual(warnings, [warning])

    @override_settings(
        AXES_HANDLER="axes.handlers.database.AxesDatabaseHandler",
        CACHES={
            "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
        },
    )
    def test_cache_check_does_not_produce_check_warnings_with_database_handler(self):
        warnings = run_checks()
        self.assertEqual(warnings, [])


class MiddlewareCheckTestCase(AxesTestCase):
    @modify_settings(MIDDLEWARE={"remove": ["axes.middleware.AxesMiddleware"]})
    def test_cache_check_warnings(self):
        warnings = run_checks()
        warning = Warning(
            msg=Messages.MIDDLEWARE_INVALID,
            hint=Hints.MIDDLEWARE_INVALID,
            id=Codes.MIDDLEWARE_INVALID,
        )

        self.assertEqual(warnings, [warning])


class AxesSpecializedBackend(AxesStandaloneBackend):
    pass


class BackendCheckTestCase(AxesTestCase):
    @modify_settings(
        AUTHENTICATION_BACKENDS={"remove": ["axes.backends.AxesStandaloneBackend"]}
    )
    def test_backend_missing(self):
        warnings = run_checks()
        warning = Warning(
            msg=Messages.BACKEND_INVALID,
            hint=Hints.BACKEND_INVALID,
            id=Codes.BACKEND_INVALID,
        )

        self.assertEqual(warnings, [warning])

    @override_settings(
        AUTHENTICATION_BACKENDS=["tests.test_checks.AxesSpecializedBackend"]
    )
    def test_specialized_backend(self):
        warnings = run_checks()
        self.assertEqual(warnings, [])

    @override_settings(
        AUTHENTICATION_BACKENDS=["tests.test_checks.AxesNotDefinedBackend"]
    )
    def test_import_error(self):
        with self.assertRaises(ImportError):
            run_checks()

    @override_settings(AUTHENTICATION_BACKENDS=["module.not_defined"])
    def test_module_not_found_error(self):
        with self.assertRaises(ModuleNotFoundError):
            run_checks()


class DeprecatedSettingsTestCase(AxesTestCase):
    def setUp(self):
        self.disable_success_access_log_warning = Warning(
            msg=Messages.SETTING_DEPRECATED.format(
                deprecated_setting="AXES_DISABLE_SUCCESS_ACCESS_LOG"
            ),
            hint=Hints.SETTING_DEPRECATED,
            id=Codes.SETTING_DEPRECATED,
        )

    @override_settings(AXES_DISABLE_SUCCESS_ACCESS_LOG=True)
    def test_deprecated_success_access_log_flag(self):
        warnings = run_checks()
        self.assertEqual(warnings, [self.disable_success_access_log_warning])


class ConfCheckTestCase(AxesTestCase):
    @override_settings(AXES_USERNAME_CALLABLE="module.not_defined")
    def test_invalid_import_path(self):
        warnings = run_checks()
        warning = Warning(
            msg=Messages.CALLABLE_INVALID.format(
                callable_setting="AXES_USERNAME_CALLABLE"
            ),
            hint=Hints.CALLABLE_INVALID,
            id=Codes.CALLABLE_INVALID,
        )
        self.assertEqual(warnings, [warning])

    @override_settings(AXES_COOLOFF_TIME=lambda: 1)
    def test_valid_callable(self):
        warnings = run_checks()
        self.assertEqual(warnings, [])

    def test_missing_settings_no_error(self):
        warnings = run_checks()
        self.assertEqual(warnings, [])


class LockoutParametersCheckTestCase(AxesTestCase):
    @override_settings(AXES_LOCKOUT_PARAMETERS=["ip_address", "username"])
    def test_valid_configuration(self):
        warnings = run_checks()
        self.assertEqual(warnings, [])

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username", "user_agent"])
    def test_invalid_configuration(self):
        warnings = run_checks()
        warning = Warning(
            msg=Messages.LOCKOUT_PARAMETERS_INVALID,
            hint=Hints.LOCKOUT_PARAMETERS_INVALID,
            id=Codes.LOCKOUT_PARAMETERS_INVALID,
        )
        self.assertEqual(warnings, [warning])


class IPListCheckTestCase(AxesTestCase):
    @override_settings(
        AXES_IP_WHITELIST=["10.20.0.0/16", "2001:db8::/32", "127.0.0.1"],
        AXES_IP_BLACKLIST=["192.0.2.0/24"],
        AXES_IPWARE_PROXY_TRUSTED_IPS=["10.0.0.0/8"],
    )
    def test_valid_ip_lists_no_warnings(self):
        warnings = run_checks()
        self.assertEqual(warnings, [])

    def test_missing_ip_lists_no_warnings(self):
        warnings = run_checks()
        self.assertEqual(warnings, [])

    @override_settings(AXES_IP_WHITELIST=["not-an-ip", "10.20.0.0/33"])
    def test_invalid_whitelist_entries_warn(self):
        warnings = run_checks()
        expected = [
            Warning(
                msg=Messages.IP_LIST_INVALID.format(location="AXES_IP_WHITELIST[0]"),
                hint=Hints.IP_LIST_INVALID,
                id=Codes.IP_LIST_INVALID,
            ),
            Warning(
                msg=Messages.IP_LIST_INVALID.format(location="AXES_IP_WHITELIST[1]"),
                hint=Hints.IP_LIST_INVALID,
                id=Codes.IP_LIST_INVALID,
            ),
        ]
        self.assertEqual(warnings, expected)

    @override_settings(AXES_IP_BLACKLIST=["010.20.0.0/16"])
    def test_invalid_blacklist_entry_warns(self):
        warnings = run_checks()
        warning = Warning(
            msg=Messages.IP_LIST_INVALID.format(location="AXES_IP_BLACKLIST[0]"),
            hint=Hints.IP_LIST_INVALID,
            id=Codes.IP_LIST_INVALID,
        )
        self.assertEqual(warnings, [warning])

    @override_settings(AXES_IPWARE_PROXY_TRUSTED_IPS=["10.0.0.0/8", "bad"])
    def test_invalid_proxy_trusted_ip_entry_warns(self):
        warnings = run_checks()
        warning = Warning(
            msg=Messages.IP_LIST_INVALID.format(
                location="AXES_IPWARE_PROXY_TRUSTED_IPS[1]"
            ),
            hint=Hints.IP_LIST_INVALID,
            id=Codes.IP_LIST_INVALID,
        )
        self.assertEqual(warnings, [warning])

    @override_settings(AXES_IP_WHITELIST=["10.0.0.1, 10.0.0.2, forged-chain"])
    def test_warning_message_only_carries_location_and_category(self):
        warnings = run_checks()
        self.assertEqual(len(warnings), 1)
        self.assertIn("AXES_IP_WHITELIST[0]", warnings[0].msg)
        self.assertNotIn("forged-chain", warnings[0].msg)
        self.assertNotIn("10.0.0.1", warnings[0].msg)


class LockoutTiersCheckTestCase(AxesTestCase):
    SAMPLE_TIERS = [
        LockoutTier(failures=3, cooloff=timedelta(minutes=15)),
        LockoutTier(failures=6, cooloff=timedelta(hours=2)),
    ]

    @override_settings(AXES_LOCKOUT_TIERS=SAMPLE_TIERS, AXES_COOLOFF_TIME=None)
    def test_tiers_alone_no_warning(self):
        warnings = run_checks()
        self.assertEqual(warnings, [])

    @override_settings(AXES_LOCKOUT_TIERS=SAMPLE_TIERS, AXES_COOLOFF_TIME=1)
    def test_tiers_with_cooloff_time_warns(self):
        warnings = run_checks()
        warning = Warning(
            msg=Messages.LOCKOUT_TIERS_CONFLICT,
            hint=Hints.LOCKOUT_TIERS_CONFLICT,
            id=Codes.LOCKOUT_TIERS_CONFLICT,
        )
        self.assertIn(warning, warnings)

    @override_settings(AXES_LOCKOUT_TIERS="not a list")
    def test_tiers_invalid_format_warns(self):
        warnings = run_checks()
        warning = Warning(
            msg=Messages.LOCKOUT_TIERS_INVALID,
            hint=Hints.LOCKOUT_TIERS_INVALID,
            id=Codes.LOCKOUT_TIERS_INVALID,
        )
        self.assertIn(warning, warnings)

    @override_settings(AXES_LOCKOUT_TIERS=[(3, timedelta(minutes=15))])
    def test_tiers_plain_tuples_warns(self):
        warnings = run_checks()
        warning = Warning(
            msg=Messages.LOCKOUT_TIERS_INVALID,
            hint=Hints.LOCKOUT_TIERS_INVALID,
            id=Codes.LOCKOUT_TIERS_INVALID,
        )
        self.assertIn(warning, warnings)
