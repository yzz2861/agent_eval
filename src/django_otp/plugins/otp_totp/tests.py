from binascii import unhexlify
from datetime import timedelta
from threading import Barrier, Thread
from time import time
from urllib.parse import parse_qs, urlsplit

from django.contrib.admin.sites import AdminSite
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.db import IntegrityError, connection
from django.test import RequestFactory
from django.test.utils import override_settings
from django.urls import reverse
from django.utils import timezone

from django_otp.oath import hotp
from django_otp.test_utils import (
    ConcurrencyTestCase,
    TestCase,
    ThrottlingTestMixin,
    TimestampTestMixin,
)

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


class VerifyThread(Thread):
    """
    Runs a verification on its own database connection.

    Django test connections are thread-local, so each thread gets an
    independent connection; it has to be closed again when we're done.
    """

    def __init__(self, device_pk, token, barrier=None):
        super().__init__()

        self.device_pk = device_pk
        self.token = token
        self.barrier = barrier
        self.verified = None
        self.error = None

    def run(self):
        try:
            if self.barrier is not None:
                self.barrier.wait()
            device = TOTPDevice.objects.get(pk=self.device_pk)
            self.verified = device.verify_token(self.token)
        except Exception as error:
            self.error = error
        finally:
            connection.close()


@override_settings(OTP_TOTP_THROTTLE_FACTOR=1)
class TOTPConcurrencyTestCase(ConcurrencyTestCase):
    """
    Deterministic concurrency checks using independent database connections.

    Each pair of requests must always produce exactly one acceptance,
    regardless of how the threads are scheduled.
    """

    def setUp(self):
        try:
            self.alice = self.create_user(
                'alice', 'password', email='alice@example.com'
            )
        except IntegrityError:
            self.skipTest("Unable to create the test user.")
            return

        # A device parked at time step 3 with a 30-second step and t0 chosen
        # so that the live clock keeps reporting t == 3 for the whole test.
        self.device = self.alice.totpdevice_set.create(
            key='2a2bbba1092ffdd25a328ad1a0a5f5d61d7aacc4',
            step=30,
            t0=int(time() - (30 * 3)),
            digits=6,
            tolerance=1,
            drift=0,
            last_t=-1,
        )

    def _run_pair(self, first_token, second_token):
        barrier = Barrier(2)
        threads = [
            VerifyThread(self.device.pk, first_token, barrier),
            VerifyThread(self.device.pk, second_token, barrier),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
            if thread.error is not None:
                raise thread.error

        return [thread.verified for thread in threads]

    def test_same_token_accepted_once(self):
        # Both requests present the same valid token for time step 3.
        results = self._run_pair(self.totp_token(3), self.totp_token(3))

        self.assertEqual(sorted(results), [False, True])
        self.device.refresh_from_db()
        self.assertEqual(self.device.last_t, 3)
        # The rejected request lost a consumption race, it is not a failure.
        self.assertEqual(self.device.throttling_failure_count, 0)
        self.assertIsNone(self.device.throttling_failure_timestamp)

    def test_different_time_steps_accepted_once(self):
        # Tokens for two distinct time steps are presented simultaneously;
        # only one of them may be consumed.
        results = self._run_pair(self.totp_token(3), self.totp_token(4))

        self.assertEqual(sorted(results), [False, True])
        self.device.refresh_from_db()
        self.assertIn(self.device.last_t, (3, 4))
        self.assertEqual(self.device.throttling_failure_count, 0)

    def test_invalid_tokens_increment_throttle(self):
        # Genuinely wrong tokens still count as failed attempts, even when
        # they arrive concurrently.
        results = self._run_pair(-1, -2)

        self.assertEqual(results, [False, False])
        self.device.refresh_from_db()
        self.assertEqual(self.device.throttling_failure_count, 2)
        self.assertEqual(self.device.last_t, -1)

    def test_locked_device_rejects_without_throttle_change(self):
        # Put the device into an active throttle lockout.
        self.device.throttling_failure_count = 1
        self.device.throttling_failure_timestamp = timezone.now()
        self.device.save()

        results = self._run_pair(self.totp_token(3), self.totp_token(3))

        self.assertEqual(results, [False, False])
        self.device.refresh_from_db()
        self.assertEqual(self.device.throttling_failure_count, 1)
        self.assertEqual(self.device.last_t, -1)

    def test_success_resets_throttle(self):
        # An existing failure history is cleared by the successful request,
        # while the racing duplicate stays a non-counting rejection.
        self.device.throttling_failure_count = 3
        self.device.throttling_failure_timestamp = timezone.now() - timedelta(
            seconds=100
        )
        self.device.save()

        results = self._run_pair(self.totp_token(3), self.totp_token(3))

        self.assertEqual(sorted(results), [False, True])
        self.device.refresh_from_db()
        self.assertEqual(self.device.throttling_failure_count, 0)
        self.assertIsNone(self.device.throttling_failure_timestamp)
        self.assertIsNotNone(self.device.last_used_at)

    def totp_token(self, time_step):
        return hotp(unhexlify(self.device.key.encode()), time_step)
