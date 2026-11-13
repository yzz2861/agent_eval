from datetime import datetime, timedelta, timezone
from time import time
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from django.contrib.admin.sites import AdminSite
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.db import IntegrityError
from django.test import RequestFactory, SimpleTestCase
from django.test.utils import override_settings
from django.urls import reverse

from django_otp.oath import (
    TOTP,
    TOTPConfigurationError,
    TOTPConsumedError,
    TOTPOutOfWindowError,
    TOTPRollbackError,
    hotp,
)
from django_otp.test_utils import TestCase, ThrottlingTestMixin, TimestampTestMixin

from .admin import TOTPDeviceAdmin
from .models import TOTPDevice


class TOTPDeviceMixin:
    """
    A TestCase helper that gives us a TOTPDevice to work with.
    """

    # The next ten tokens
    tokens = [
        179225,
        656163,
        839400,
        154567,
        346912,
        471576,
        45675,
        101397,
        491039,
        784503,
    ]

    def setUp(self):
        """
        Create a device at the fourth time step. The current token is 154567.
        """
        try:
            self.alice = self.create_user(
                'alice', 'password', email='alice@example.com'
            )
        except IntegrityError:
            self.skipTest("Unable to create the test user.")
        else:
            self.device = self.alice.totpdevice_set.create(
                key='2a2bbba1092ffdd25a328ad1a0a5f5d61d7aacc4',
                step=30,
                t0=int(time() - (30 * 3)),
                digits=6,
                tolerance=0,
                drift=0,
            )


@override_settings(
    OTP_TOTP_SYNC=False,
    OTP_TOTP_THROTTLE_FACTOR=0,
)
class TOTPTest(TOTPDeviceMixin, TestCase):
    def test_default_key(self):
        device = self.alice.totpdevice_set.create()

        # Make sure we can decode the key.
        device.bin_key

    def test_single(self):
        results = [self.device.verify_token(token) for token in self.tokens]

        self.assertEqual(results, [False] * 3 + [True] + [False] * 6)

    def test_tolerance(self):
        self.device.tolerance = 1
        results = [self.device.verify_token(token) for token in self.tokens]

        self.assertEqual(results, [False] * 2 + [True] * 3 + [False] * 5)

    def test_drift(self):
        self.device.tolerance = 1
        self.device.drift = -1
        results = [self.device.verify_token(token) for token in self.tokens]

        self.assertEqual(results, [False] * 1 + [True] * 3 + [False] * 6)

    def test_sync_drift(self):
        self.device.tolerance = 2
        with self.settings(OTP_TOTP_SYNC=True):
            ok = self.device.verify_token(self.tokens[5])

        self.assertTrue(ok)
        self.assertEqual(self.device.drift, 2)

    def test_no_reuse(self):
        verified1 = self.device.verify_token(self.tokens[3])
        verified2 = self.device.verify_token(self.tokens[3])

        self.assertEqual(self.device.last_t, 3)
        self.assertTrue(verified1)
        self.assertFalse(verified2)

    def test_slow_clock_at_tolerance_boundary(self):
        now = 1_700_000_000
        self.device.t0 = now - 30 * 10
        self.device.tolerance = 4

        with self.settings(OTP_TOTP_SYNC=True):
            with mock.patch(
                'django_otp.plugins.otp_totp.models.time.time', return_value=now
            ):
                token = hotp(self.device.bin_key, 10 - 4, digits=self.device.digits)
                verified = self.device.verify_token(token)

        self.assertTrue(verified)
        self.assertEqual(self.device.drift, -4)
        self.assertEqual(self.device.last_t, 6)

    def test_far_future_clock_jump_is_not_absorbed(self):
        now = 1_700_000_000
        self.device.t0 = now - 30 * 10
        self.device.tolerance = 120

        with mock.patch(
            'django_otp.plugins.otp_totp.models.time.time', return_value=now
        ):
            token = hotp(self.device.bin_key, 10 + 120, digits=self.device.digits)
            verified = self.device.verify_token(token)

        self.assertFalse(verified)
        self.assertEqual(self.device.drift, 0)
        self.assertEqual(self.device.last_t, -1)
        self.assertEqual(self.device.last_verify_error.code, 'out_of_window')

    def test_rollback_does_not_replay_consumed_step(self):
        now = 1_700_000_000
        self.device.t0 = now - 30 * 3
        self.device.tolerance = 0
        token = hotp(self.device.bin_key, 3, digits=self.device.digits)

        with mock.patch(
            'django_otp.plugins.otp_totp.models.time.time', return_value=now
        ):
            self.assertTrue(self.device.verify_token(token))

        with mock.patch(
            'django_otp.plugins.otp_totp.models.time.time',
            return_value=now - 30,
        ):
            self.assertFalse(self.device.verify_token(token))

        self.assertEqual(self.device.last_t, 3)
        self.assertEqual(self.device.drift, 0)
        self.assertEqual(self.device.last_verify_error.code, 'rollback')

        # Repeating the step after the clock catches up is still a replay.
        with mock.patch(
            'django_otp.plugins.otp_totp.models.time.time', return_value=now
        ):
            self.assertFalse(self.device.verify_token(token))

        self.assertEqual(self.device.last_t, 3)
        self.assertEqual(self.device.last_verify_error.code, 'consumed')

    def test_failure_does_not_advance_last_t(self):
        now = 1_700_000_000
        self.device.t0 = now - 30 * 3
        self.device.tolerance = 0
        token = hotp(self.device.bin_key, 3, digits=self.device.digits)
        invalid_token = (token + 1) % 1_000_000

        with mock.patch(
            'django_otp.plugins.otp_totp.models.time.time', return_value=now
        ):
            self.assertFalse(self.device.verify_token(invalid_token))

        self.assertEqual(self.device.last_t, -1)
        self.assertEqual(self.device.drift, 0)
        self.assertEqual(self.device.last_verify_error.code, 'out_of_window')

    def test_configuration_error_does_not_advance_last_t(self):
        now = 1_700_000_000
        self.device.t0 = now - 30 * 3
        self.device.step = 0
        token = hotp(self.device.bin_key, 3, digits=self.device.digits)

        with mock.patch(
            'django_otp.plugins.otp_totp.models.time.time', return_value=now
        ):
            self.assertFalse(self.device.verify_token(token))

        self.assertEqual(self.device.last_t, -1)
        self.assertEqual(self.device.drift, 0)
        self.assertEqual(self.device.last_verify_error.code, 'configuration_error')

    def test_config_url(self):
        with override_settings(OTP_TOTP_ISSUER=None):
            url = self.device.config_url

        parsed = urlsplit(url)
        params = parse_qs(parsed.query)

        self.assertEqual(parsed.scheme, 'otpauth')
        self.assertEqual(parsed.netloc, 'totp')
        self.assertEqual(parsed.path, '/alice')
        self.assertIn('secret', params)
        self.assertNotIn('issuer', params)

    def test_config_url_issuer(self):
        with override_settings(OTP_TOTP_ISSUER='example.com'):
            url = self.device.config_url

        parsed = urlsplit(url)
        params = parse_qs(parsed.query)

        self.assertEqual(parsed.scheme, 'otpauth')
        self.assertEqual(parsed.netloc, 'totp')
        self.assertEqual(parsed.path, '/example.com%3Aalice')
        self.assertIn('secret', params)
        self.assertIn('issuer', params)
        self.assertEqual(params['issuer'][0], 'example.com')

    def test_config_url_issuer_spaces(self):
        with override_settings(OTP_TOTP_ISSUER='Very Trustworthy Source'):
            url = self.device.config_url

        parsed = urlsplit(url)
        params = parse_qs(parsed.query)

        self.assertEqual(parsed.scheme, 'otpauth')
        self.assertEqual(parsed.netloc, 'totp')
        self.assertEqual(parsed.path, '/Very%20Trustworthy%20Source%3Aalice')
        self.assertIn('secret', params)
        self.assertIn('issuer', params)
        self.assertEqual(params['issuer'][0], 'Very Trustworthy Source')

    def test_config_url_issuer_method(self):
        with override_settings(OTP_TOTP_ISSUER=lambda d: d.user.email):
            url = self.device.config_url

        parsed = urlsplit(url)
        params = parse_qs(parsed.query)

        self.assertEqual(parsed.scheme, 'otpauth')
        self.assertEqual(parsed.netloc, 'totp')
        self.assertEqual(parsed.path, '/alice%40example.com%3Aalice')
        self.assertIn('secret', params)
        self.assertIn('issuer', params)
        self.assertEqual(params['issuer'][0], 'alice@example.com')

    def test_config_url_image(self):
        image_url = "https://test.invalid/square.png"

        with override_settings(OTP_TOTP_ISSUER=None, OTP_TOTP_IMAGE=image_url):
            url = self.device.config_url

        parsed = urlsplit(url)
        params = parse_qs(parsed.query)

        self.assertEqual(parsed.scheme, 'otpauth')
        self.assertEqual(parsed.netloc, 'totp')
        self.assertEqual(parsed.path, '/alice')
        self.assertIn('secret', params)
        self.assertEqual(params['image'][0], image_url)


class TOTPClockPolicyTest(SimpleTestCase):
    key = b'12345678901234567890'

    def make_totp(self, **kwargs):
        totp = TOTP(self.key, **kwargs)
        totp.time = 0
        return totp

    def test_tolerance_is_inclusive_in_both_directions(self):
        for offset in (-2, -1, 0, 1, 2):
            with self.subTest(offset=offset):
                totp = self.make_totp()
                token = hotp(self.key, offset)
                self.assertTrue(totp.verify(token, tolerance=2))
                self.assertEqual(totp.drift, offset)

        for offset in (-3, 3):
            with self.subTest(offset=offset):
                totp = self.make_totp()
                token = hotp(self.key, offset)
                self.assertFalse(totp.verify(token, tolerance=2))
                self.assertEqual(totp.drift, 0)

    def test_negative_tolerance_is_a_configuration_error(self):
        totp = self.make_totp()
        with self.assertRaises(TOTPConfigurationError):
            totp.verify(0, tolerance=-1, raise_errors=True)

    def test_time_step_uses_floor_not_truncation(self):
        totp = self.make_totp()

        for value, expected in [
            (0, 0),
            (0.1, 0),
            (29.999, 0),
            (30, 1),
            (-0.1, -1),
            (-30, -1),
            (-30.1, -2),
        ]:
            with self.subTest(value=value):
                totp.time = value
                self.assertEqual(totp.t(), expected)

    def test_time_step_is_independent_of_utc_offset(self):
        instant = datetime(2020, 1, 1, tzinfo=timezone.utc)
        same_instant = instant.astimezone(timezone(timedelta(hours=8)))
        naive = instant.replace(tzinfo=None)

        utc_totp = self.make_totp()
        utc_totp.time = instant
        offset_totp = self.make_totp()
        offset_totp.time = same_instant
        naive_totp = self.make_totp()
        naive_totp.time = naive

        self.assertEqual(utc_totp.t(), offset_totp.t())
        self.assertEqual(utc_totp.t(), naive_totp.t())
        self.assertEqual(utc_totp.token(), offset_totp.token())
        self.assertEqual(utc_totp.token(), naive_totp.token())

    def test_strict_drift_adjustment_is_limited(self):
        totp = self.make_totp(strict=True, max_drift_step=1)

        token = hotp(self.key, 2)
        self.assertFalse(totp.verify(token, tolerance=2))
        self.assertEqual(totp.drift, 0)

        token = hotp(self.key, 1)
        self.assertTrue(totp.verify(token, tolerance=2))
        self.assertEqual(totp.drift, 1)

    def test_far_future_drift_is_rejected(self):
        totp = self.make_totp(strict=True, max_future_drift=2)
        token = hotp(self.key, 3)

        self.assertFalse(totp.verify(token, tolerance=3))
        self.assertEqual(totp.drift, 0)
        self.assertEqual(totp.last_error.code, 'out_of_window')

    def test_min_t_is_a_consumed_step_watermark(self):
        totp = self.make_totp(strict=True)
        token = hotp(self.key, 1)

        self.assertFalse(totp.verify(token, tolerance=1, min_t=2))
        self.assertIsNone(totp.consumed_t)

        totp.time = 30
        self.assertTrue(totp.verify(token))
        self.assertEqual(totp.consumed_t, 2)

        self.assertFalse(totp.verify(token))
        self.assertEqual(totp.consumed_t, 2)
        self.assertEqual(totp.last_error.code, 'consumed')

    def test_failure_and_out_of_window_do_not_advance_watermark(self):
        totp = self.make_totp(strict=True)
        self.assertTrue(totp.verify(hotp(self.key, 0)))
        consumed_t = totp.consumed_t

        invalid_token = (hotp(self.key, 0) + 1) % 1_000_000
        self.assertFalse(totp.verify(invalid_token))
        self.assertEqual(totp.consumed_t, consumed_t)

        self.assertFalse(totp.verify(hotp(self.key, 5), tolerance=1))
        self.assertEqual(totp.consumed_t, consumed_t)

    def test_replay_after_rollback_is_blocked(self):
        totp = self.make_totp(strict=True)
        totp.time = 100

        token = hotp(self.key, 3)
        self.assertTrue(totp.verify(token))
        self.assertEqual(totp.consumed_t, 4)

        totp.time = 70
        self.assertFalse(totp.verify(token, tolerance=3))
        self.assertEqual(totp.consumed_t, 4)
        self.assertEqual(totp.last_error.code, 'rollback')

        totp.time = 100
        self.assertFalse(totp.verify(token))
        self.assertEqual(totp.consumed_t, 4)
        self.assertEqual(totp.last_error.code, 'consumed')

        totp.time = 130
        self.assertTrue(totp.verify(hotp(self.key, 4)))

    def test_errors_do_not_expose_key_or_token(self):
        totp = self.make_totp(strict=True)
        token = hotp(self.key, 0)
        self.assertTrue(totp.verify(token))

        with self.assertRaises(TOTPConsumedError) as context:
            totp.verify(token, raise_errors=True)
        message = str(context.exception)
        self.assertNotIn(str(token), message)
        self.assertNotIn(self.key.hex(), message)

        with self.assertRaises(TOTPOutOfWindowError):
            self.make_totp().verify(1, raise_errors=True)

        with self.assertRaises(TOTPConfigurationError):
            self.make_totp(step=0).verify(token, raise_errors=True)

    def test_rollback_error_is_safe(self):
        totp = self.make_totp()
        totp.time = 100
        token = hotp(self.key, 3)
        self.assertTrue(totp.verify(token))

        totp.time = 70
        with self.assertRaises(TOTPRollbackError) as context:
            totp.verify(token, raise_errors=True)
        message = str(context.exception)
        self.assertNotIn(str(token), message)
        self.assertNotIn(self.key.hex(), message)


class TOTPAdminTest(TestCase):
    def setUp(self):
        """
        Create a device at the fourth time step. The current token is 154567.
        """
        try:
            self.admin = self.create_user(
                'admin', 'password', email='admin@example.com', is_staff=True
            )
        except IntegrityError:
            self.skipTest("Unable to create the test user.")
        else:
            self.device = self.admin.totpdevice_set.create(
                key='2a2bbba1092ffdd25a328ad1a0a5f5d61d7aacc4',
                step=30,
                t0=int(time() - (30 * 3)),
                digits=6,
                tolerance=0,
                drift=0,
            )
        self.device_admin = TOTPDeviceAdmin(TOTPDevice, AdminSite())
        self.get_request = RequestFactory().get('/')
        self.get_request.user = self.admin

    def test_anonymous(self):
        for suffix in ['config', 'qrcode']:
            with self.subTest(view=suffix):
                url = reverse(
                    'admin:otp_totp_totpdevice_' + suffix, kwargs={'pk': self.device.pk}
                )
                response = self.client.get(url)
                self.assertEqual(response.status_code, 302)

    def test_unauthorized(self):
        self.client.login(username='admin', password='password')

        for suffix in ['config', 'qrcode']:
            with self.subTest(view=suffix):
                url = reverse(
                    'admin:otp_totp_totpdevice_' + suffix, kwargs={'pk': self.device.pk}
                )
                response = self.client.get(url)
                self.assertEqual(response.status_code, 403)

    def test_view_perm(self):
        self._add_device_perms('view_totpdevice')
        self.client.login(username='admin', password='password')

        for suffix in ['config', 'qrcode']:
            with self.subTest(view=suffix):
                url = reverse(
                    'admin:otp_totp_totpdevice_' + suffix, kwargs={'pk': self.device.pk}
                )
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)

    def test_change_perm(self):
        self._add_device_perms('change_totpdevice')
        self.client.login(username='admin', password='password')

        for suffix in ['config', 'qrcode']:
            with self.subTest(view=suffix):
                url = reverse(
                    'admin:otp_totp_totpdevice_' + suffix, kwargs={'pk': self.device.pk}
                )
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)

    def test_config_page_has_no_inline_style_or_script(self):
        """
        The QR code config page shouldn't rely on inline style attributes,
        <style> blocks, or event handler attributes (e.g. onerror), since
        those are blocked by a strict Content-Security-Policy.

        https://github.com/django-otp/django-otp/issues/143
        """
        self._add_device_perms('view_totpdevice')
        self.client.login(username='admin', password='password')

        url = reverse('admin:otp_totp_totpdevice_config', kwargs={'pk': self.device.pk})
        response = self.client.get(url)
        content = response.content.decode()

        self.assertNotIn('style="', content)
        self.assertNotIn('<style', content)
        self.assertNotIn('onerror=', content)
        self.assertIn('otp_totp/css/qrcode.css', content)
        self.assertIn('otp_totp/js/qrcode.js', content)

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=True)
    def test_sensitive_information_hidden_while_adding_device(self):
        fields = self._get_fields(device=None)
        self.assertIn('key', fields)
        self.assertNotIn('qrcode_link', fields)

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=True)
    def test_sensitive_information_hidden_while_changing_device(self):
        fields = self._get_fields(device=self.device)
        self.assertNotIn('key', fields)
        self.assertNotIn('qrcode_link', fields)

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=False)
    def test_sensitive_information_shown_while_adding_device(self):
        fields = self._get_fields(device=None)
        self.assertIn('key', fields)
        self.assertNotIn('qrcode_link', fields)

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=False)
    def test_sensitive_information_shown_while_changing_device(self):
        fields = self._get_fields(device=self.device)
        self.assertIn('key', fields)
        self.assertIn('qrcode_link', fields)

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=True)
    def test_list_display_when_sensitive_information_hidden(self):
        self.assertEqual(
            self.device_admin.get_list_display(self.get_request),
            ['user', 'name', 'created_at', 'last_used_at', 'confirmed'],
        )

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=False)
    def test_list_display_when_sensitive_information_shown(self):
        self.assertEqual(
            self.device_admin.get_list_display(self.get_request),
            ['user', 'name', 'created_at', 'last_used_at', 'confirmed', 'qrcode_link'],
        )

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=True)
    def test_config_view_when_sensitive_information_hidden(self):
        self._add_device_perms('change_totpdevice')
        with self.assertRaises(PermissionDenied):
            self.device_admin.config_view(self.get_request, self.device.id)

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=False)
    def test_config_view_when_sensitive_information_shown(self):
        self._add_device_perms('change_totpdevice')
        response = self.device_admin.config_view(self.get_request, self.device.id)
        self.assertEqual(response.status_code, 200)

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=True)
    def test_qrcode_view_when_sensitive_information_hidden(self):
        self._add_device_perms('change_totpdevice')
        with self.assertRaises(PermissionDenied):
            self.device_admin.qrcode_view(self.get_request, self.device.id)

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=False)
    def test_qrcode_view_when_sensitive_information_shown(self):
        self._add_device_perms('change_totpdevice')
        response = self.device_admin.qrcode_view(self.get_request, self.device.id)
        self.assertEqual(response.status_code, 200)

    #
    # Helpers
    #

    def _add_device_perms(self, *codenames):
        ct = ContentType.objects.get_for_model(TOTPDevice)

        perms = [
            Permission.objects.get(content_type=ct, codename=codename)
            for codename in codenames
        ]

        self.admin.user_permissions.add(*perms)

    def _get_fields(self, device):
        return {
            field
            for fieldset in self.device_admin.get_fieldsets(
                self.get_request, obj=device
            )
            for field in fieldset[1]['fields']
        }


@override_settings(
    OTP_TOTP_THROTTLE_FACTOR=1,
)
class ThrottlingTestCase(TOTPDeviceMixin, ThrottlingTestMixin, TestCase):
    def valid_token(self):
        return self.tokens[3]

    def invalid_token(self):
        return -1


class TimetstampTestCase(TOTPDeviceMixin, TimestampTestMixin, TestCase):
    def valid_token(self):
        return self.tokens[3]

    def invalid_token(self):
        return -1
