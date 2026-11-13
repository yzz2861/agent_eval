import random
import uuid
from io import StringIO
from pathlib import Path
from threading import Barrier, Thread

from django.contrib.admin import AdminSite
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.db import IntegrityError, connection
from django.test import RequestFactory
from django.test.utils import override_settings

from django_otp.forms import OTPAuthenticationForm
from django_otp.test_utils import (
    TestCase,
    ThrottlingTestMixin,
    TimestampTestMixin,
    TransactionTestCase,
)

from .admin import StaticDeviceAdmin, StaticTokenInline
from .lib import (
    add_static_token,
    create_static_token_batch,
    import_static_tokens,
    revoke_static_token_batch,
)
from .models import (
    StaticDevice,
    StaticToken,
    StaticTokenBatch,
    StaticTokenError,
    StaticTokenErrorReason,
    normalize_static_token,
)


class DeviceTest(TestCase):
    """A few generic tests to get us started."""

    def setUp(self):
        try:
            self.user = self.create_user('alice', 'password')
        except Exception:
            self.skipTest("Unable to create the test user.")

    def test_str(self):
        device = StaticDevice.objects.create(user=self.user, name="Device")

        str(device)

    def test_str_unpopulated(self):
        device = StaticDevice()

        str(device)


class LibTest(TestCase):
    """
    Test miscellaneous library functions.
    """

    def setUp(self):
        try:
            self.user = self.create_user('alice', 'password')
        except Exception:
            self.skipTest("Unable to create the test user.")

    def test_add_static_token(self):
        statictoken = add_static_token('alice')

        self.assertEqual(statictoken.device.user, self.user)
        self.assertEqual(self.user.staticdevice_set.count(), 1)

    def test_add_static_token_existing_device(self):
        self.user.staticdevice_set.create(name='Test')
        statictoken = add_static_token('alice')

        self.assertEqual(statictoken.device.user, self.user)
        self.assertEqual(self.user.staticdevice_set.count(), 1)
        self.assertEqual(statictoken.device.name, 'Test')

    def test_add_static_token_no_user(self):
        with self.assertRaises(self.User.DoesNotExist):
            add_static_token('bogus')

    def test_add_static_token_specific(self):
        statictoken = add_static_token('alice', 'token')

        self.assertEqual(statictoken.token, 'token')


class BatchIssuanceTest(TestCase):
    def setUp(self):
        try:
            self.user = self.create_user('alice', 'password')
        except Exception:
            self.skipTest("Unable to create the test user.")

    def test_bulk_issue_uses_uniform_policy(self):
        alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ234567'
        random_source = random.Random(42).choice

        batch = create_static_token_batch(
            'alice',
            10,
            length=10,
            alphabet=alphabet,
            random_source=random_source,
            reference='ops-recovery',
        )
        tokens = list(batch.tokens.values_list('token', flat=True))

        self.assertEqual(batch.status, StaticTokenBatch.Status.ACTIVE)
        self.assertEqual(batch.total_count, 10)
        self.assertEqual(batch.consumed_count, 0)
        self.assertEqual(batch.alphabet, alphabet)
        self.assertEqual(batch.token_length, 10)
        self.assertTrue(batch.random_source.endswith('choice'))
        self.assertEqual(len(tokens), 10)
        self.assertEqual(len(set(tokens)), 10)
        self.assertEqual(len(batch.issued_tokens), 10)
        for token in tokens:
            self.assertEqual(len(token), 10)
            self.assertTrue(set(token) <= set(alphabet))

    def test_bulk_issue_with_same_batch_id_is_idempotent(self):
        batch_id = uuid.uuid4()

        first = create_static_token_batch('alice', 5, batch_id=batch_id)
        second = create_static_token_batch('alice', 5, batch_id=batch_id)

        self.assertEqual(first.pk, second.pk)
        self.assertEqual(first.tokens.count(), 5)
        self.assertEqual(second.tokens.count(), 5)

    def test_bulk_issue_rejects_impossible_alphabet(self):
        with self.assertRaises(StaticTokenError) as caught:
            create_static_token_batch(
                'alice', 5, length=1, alphabet='AB'
            )

        self.assertEqual(
            caught.exception.reason,
            StaticTokenErrorReason.RANDOM_SPACE_EXHAUSTED,
        )
        self.assertEqual(caught.exception.code, 'random_space_exhausted')

    def test_bulk_issue_rejects_invalid_configuration(self):
        for kwargs in (
            {'count': 0},
            {'length': 0},
            {'alphabet': ''},
            {'alphabet': 'A-B'},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(StaticTokenError) as caught:
                    create_static_token_batch('alice', **kwargs)
                self.assertEqual(
                    caught.exception.reason,
                    StaticTokenErrorReason.INVALID_BATCH_CONFIG,
                )


class BatchImportTest(TestCase):
    def setUp(self):
        try:
            self.user = self.create_user('alice', 'password')
        except Exception:
            self.skipTest("Unable to create the test user.")
        self.device = self.user.staticdevice_set.create(name='Backup Code')

    def test_import_normalizes_case_and_separators(self):
        csv_data = '\n'.join(
            [
                'token',
                'A1B2-C3D4',
                'a1 b2 c3 d4',
                'E5F6G7H8',
                ' E5F6-G7-H8 ',
            ]
        )

        batch = import_static_tokens('alice', csv_data)
        tokens = sorted(batch.tokens.values_list('token', flat=True))

        self.assertEqual(tokens, ['A1B2C3D4', 'E5F6G7H8'])
        self.assertEqual(batch.total_count, 2)
        self.assertEqual(batch.status, StaticTokenBatch.Status.ACTIVE)
        self.assertEqual(batch.imported_count, 2)
        self.assertEqual(batch.duplicate_count, 0)

    def test_duplicate_import_is_idempotent(self):
        csv_data = 'a1b2-c3d4,e5f6-g7h8\nA1B2C3D4\n'

        first = import_static_tokens('alice', csv_data)
        second = import_static_tokens('alice', csv_data)

        self.assertEqual(first.batch_id, second.batch_id)
        self.assertEqual(StaticTokenBatch.objects.count(), 1)
        self.assertEqual(StaticToken.objects.count(), 2)
        self.assertEqual(second.total_count, 2)
        self.assertEqual(second.imported_count, 0)
        self.assertEqual(second.duplicate_count, 2)

    def test_import_does_not_duplicate_legacy_or_consumed_codes(self):
        self.device.token_set.create(token='A1B2-C3D4')

        batch = import_static_tokens('alice', 'a1b2c3d4\ne5f6g7h8')

        self.assertEqual(batch.total_count, 1)
        self.assertEqual(batch.tokens.get().token, 'E5F6G7H8')
        self.assertEqual(self.device.token_set.count(), 2)

    def test_imported_code_verifies_with_other_formatting(self):
        batch = import_static_tokens('alice', 'a1b2-c3d4')
        token = batch.tokens.get().token

        self.assertTrue(self.device.verify_token('a1 b2 c3 d4'))
        self.assertFalse(self.device.verify_token(token))

    def test_empty_import_has_stable_reason(self):
        with self.assertRaises(StaticTokenError) as caught:
            import_static_tokens('alice', ' , \n ')

        self.assertEqual(
            caught.exception.reason, StaticTokenErrorReason.EMPTY_IMPORT
        )
        self.assertEqual(caught.exception.code, 'empty_import')


@override_settings(OTP_STATIC_THROTTLE_FACTOR=0)
class BatchLifecycleTest(TestCase):
    def setUp(self):
        try:
            self.user = self.create_user('alice', 'password')
        except Exception:
            self.skipTest("Unable to create the test user.")
        self.device = self.user.staticdevice_set.create(name='Backup Code')

    def test_revoking_batch_invalidates_all_unused_codes(self):
        batch = create_static_token_batch('alice', 3, batch_id=uuid.uuid4())
        tokens = list(batch.tokens.values_list('token', flat=True))

        self.assertTrue(self.device.verify_token(tokens[0]))
        batch.revoke(reason='key leaked')
        batch.refresh_from_db()

        self.assertEqual(batch.status, StaticTokenBatch.Status.REVOKED)
        self.assertIsNotNone(batch.revoked_at)
        self.assertEqual(batch.revocation_reason, 'key leaked')
        self.assertEqual(batch.unused_count, 0)
        self.assertFalse(self.device.verify_token(tokens[1]))
        self.assertFalse(self.device.verify_token(tokens[2]))

    def test_revoke_by_identifier_is_idempotent(self):
        batch = create_static_token_batch('alice', 2)

        first = revoke_static_token_batch(batch.batch_id, reason='rotation')
        second = revoke_static_token_batch(str(batch.batch_id), reason='rotation')

        self.assertEqual(first.pk, second.pk)
        self.assertEqual(second.status, StaticTokenBatch.Status.REVOKED)
        self.assertEqual(
            second.tokens.filter(invalidated_at__isnull=True).count(), 0
        )

    def test_reimport_does_not_reactivate_revoked_batch(self):
        batch = import_static_tokens('alice', 'A1B2-C3D4\nE5F6G7H8')
        tokens = list(batch.tokens.values_list('token', flat=True))
        batch.revoke(reason='rotation')

        reimported = import_static_tokens('alice', 'a1b2c3d4\ne5 f6 g7 h8')

        self.assertEqual(reimported.batch_id, batch.batch_id)
        self.assertEqual(reimported.status, StaticTokenBatch.Status.REVOKED)
        self.assertEqual(reimported.tokens.count(), 2)
        self.assertEqual(reimported.imported_count, 0)
        self.assertFalse(self.device.verify_token(tokens[0]))
        self.assertFalse(self.device.verify_token(tokens[1]))

    def test_batch_becomes_exhausted_after_last_code(self):
        batch = create_static_token_batch('alice', 2)
        tokens = list(batch.tokens.values_list('token', flat=True))

        self.assertTrue(self.device.verify_token(tokens[0]))
        self.assertTrue(self.device.verify_token(tokens[1]))

        batch.refresh_from_db()
        self.assertEqual(batch.status, StaticTokenBatch.Status.EXHAUSTED)
        self.assertEqual(batch.consumed_count, 2)
        self.assertEqual(batch.remaining_count, 0)
        self.assertFalse(self.device.verify_token(tokens[0]))

    def test_revocations_use_only_stable_reasons(self):
        with self.assertRaises(StaticTokenError) as caught:
            revoke_static_token_batch(uuid.uuid4())

        self.assertEqual(
            caught.exception.reason, StaticTokenErrorReason.BATCH_NOT_FOUND
        )
        self.assertEqual(caught.exception.code, 'batch_not_found')
        self.assertNotIn('remaining', str(caught.exception).lower())

    def test_verification_failure_does_not_reveal_batch_state(self):
        batch = create_static_token_batch('alice', 1)
        tokens = list(batch.tokens.values_list('token', flat=True))
        batch.revoke()

        verified, reason = self.device.verify_token_with_reason(tokens[0])
        self.assertFalse(verified)
        self.assertEqual(reason, StaticTokenErrorReason.INVALID_TOKEN)
        self.assertNotIn('remaining', str(reason).lower())


class LegacyStaticTokenTest(TestCase):
    def setUp(self):
        try:
            self.user = self.create_user('alice', 'password')
        except Exception:
            self.skipTest("Unable to create the test user.")
        self.device = self.user.staticdevice_set.create(name='Backup Code')

    def test_legacy_token_verifies_and_is_still_deleted(self):
        token = self.device.token_set.create(token='Legacy-Token')

        self.assertEqual(token.normalized_token, 'LEGACYTOKEN')
        self.assertTrue(self.device.verify_token('legacy token'))
        self.assertFalse(StaticToken.objects.filter(pk=token.pk).exists())

    def test_existing_duplicate_legacy_tokens_remain_compatible(self):
        first = self.device.token_set.create(token='same-token')
        self.device.token_set.create(token='SAME TOKEN')

        self.assertTrue(self.device.verify_token('same token'))
        self.assertEqual(StaticToken.objects.filter(device=self.device).count(), 1)
        self.assertFalse(StaticToken.objects.filter(pk=first.pk).exists())

    def test_normalize_helper(self):
        self.assertEqual(normalize_static_token(' ab-cd_12 '), 'ABCD12')
        self.assertEqual(normalize_static_token(None), '')


@override_settings(OTP_STATIC_THROTTLE_FACTOR=1)
class BatchThrottlingTest(TestCase):
    def setUp(self):
        try:
            self.user = self.create_user('alice', 'password')
        except Exception:
            self.skipTest("Unable to create the test user.")
        self.device = self.user.staticdevice_set.create(name='Backup Code')

    def test_revoked_code_failure_increments_throttle(self):
        batch = create_static_token_batch('alice', 1)
        token = batch.tokens.get().token
        batch.revoke()

        self.assertFalse(self.device.verify_token(token))
        self.device.refresh_from_db()
        self.assertEqual(self.device.throttling_failure_count, 1)


class BatchManagementCommandTest(TestCase):
    def setUp(self):
        try:
            self.user = self.create_user('alice', 'password')
        except Exception:
            self.skipTest("Unable to create the test user.")

    def test_addstatictoken_count_creates_batch(self):
        out = StringIO()
        call_command(
            'addstatictoken',
            'alice',
            '--count',
            '5',
            '--reference',
            'ops-recovery',
            stdout=out,
        )
        tokens = [line for line in out.getvalue().splitlines() if line]

        self.assertEqual(len(tokens), 5)
        batch = StaticTokenBatch.objects.get()
        self.assertEqual(batch.reference, 'ops-recovery')
        self.assertEqual(batch.total_count, 5)
        self.assertEqual(
            set(tokens),
            set(batch.tokens.values_list('token', flat=True)),
        )

    def test_importstatictokens_command(self):
        path = Path('otp-static-import-test.csv')
        path.write_text('A1B2-C3D4\nE5F6G7H8\n', encoding='utf-8')
        self.addCleanup(path.unlink)

        out = StringIO()
        call_command(
            'importstatictokens',
            'alice',
            str(path),
            stdout=out,
        )

        batch = StaticTokenBatch.objects.get(source='imported')
        self.assertEqual(batch.total_count, 2)
        self.assertEqual(batch.tokens.count(), 2)
        self.assertIn(str(batch.batch_id), out.getvalue())

    def test_revokestaticbatch_command(self):
        batch = create_static_token_batch('alice', 2)

        out = StringIO()
        call_command(
            'revokestaticbatch',
            str(batch.batch_id),
            '--reason',
            'rotation',
            stdout=out,
        )

        batch.refresh_from_db()
        self.assertEqual(batch.status, StaticTokenBatch.Status.REVOKED)
        self.assertIn('revoked', out.getvalue())


class AuthFormTest(TestCase):
    """
    Test the auth form with static tokens.

    We try to honor custom user models, but if we can't create users, we'll
    skip the tests.
    """

    def setUp(self):
        for device_id, username in enumerate(['alice', 'bob']):
            try:
                user = self.create_user(username, 'password')
            except IntegrityError:
                self.skipTest("Unable to create a test user.")
            else:
                device = user.staticdevice_set.create(id=device_id + 1)
                device.token_set.create(token=username + '1')
                device.token_set.create(token=username + '1')
                device.token_set.create(token=username + '2')

    def test_empty(self):
        data = {}
        form = OTPAuthenticationForm(None, data)

        self.assertFalse(form.is_valid())
        self.assertEqual(form.get_user(), None)

    def test_bad_password(self):
        data = {
            'username': 'alice',
            'password': 'bogus',
        }
        form = OTPAuthenticationForm(None, data)

        self.assertFalse(form.is_valid())
        self.assertEqual(list(form.errors.keys()), ['__all__'])

    def test_no_token(self):
        data = {
            'username': 'alice',
            'password': 'password',
        }
        form = OTPAuthenticationForm(None, data)

        self.assertFalse(form.is_valid())
        self.assertEqual(form.get_user().get_username(), 'alice')

    def test_omitted_device(self):
        data = {
            'username': 'alice',
            'password': 'password',
            'otp_token': 'alice1',
        }
        form = OTPAuthenticationForm(None, data)

        # A device must be selected explicitly; we no longer guess by
        # trying the token against each of the user's devices in turn.
        self.assertFalse(form.is_valid())
        alice = form.get_user()
        self.assertEqual(alice.get_username(), 'alice')
        self.assertIsNone(alice.otp_device)

    def test_spoofed_device(self):
        data = {
            'username': 'alice',
            'password': 'password',
            'otp_device': 'otp_static.staticdevice/2',
            'otp_token': 'bob1',
        }
        form = OTPAuthenticationForm(None, data)

        self.assertFalse(form.is_valid())
        alice = form.get_user()
        self.assertEqual(alice.get_username(), 'alice')
        self.assertIsNone(alice.otp_device)

    def test_specific_device_fail(self):
        data = {
            'username': 'alice',
            'password': 'password',
            'otp_device': 'otp_email.staticdevice/1',
            'otp_token': 'bogus',
        }
        form = OTPAuthenticationForm(None, data)

        self.assertFalse(form.is_valid())
        alice = form.get_user()
        self.assertEqual(alice.get_username(), 'alice')
        self.assertIsNone(alice.otp_device)

    def test_specific_device(self):
        data = {
            'username': 'alice',
            'password': 'password',
            'otp_device': 'otp_static.staticdevice/1',
            'otp_token': 'alice1',
        }
        form = OTPAuthenticationForm(None, data)

        self.assertTrue(form.is_valid())
        alice = form.get_user()
        self.assertEqual(alice.get_username(), 'alice')
        self.assertIsNotNone(alice.otp_device)


@override_settings(
    OTP_STATIC_THROTTLE_FACTOR=1,
)
class ThrottlingTestCase(ThrottlingTestMixin, TestCase):
    def setUp(self):
        try:
            user = self.create_user('alice', 'password')
        except IntegrityError:
            self.skipTest("Unable to create a test user.")
        else:
            self.device = user.staticdevice_set.create()
            self.device.token_set.create(token='valid1')
            self.device.token_set.create(token='valid2')
            self.device.token_set.create(token='valid3')

    def valid_token(self):
        return self.device.token_set.first().token

    def invalid_token(self):
        return 'bogus'


@override_settings(OTP_STATIC_THROTTLE_FACTOR=0)
class BatchConcurrencyTestCase(TransactionTestCase):
    def setUp(self):
        try:
            self.user = self.create_user('alice', 'password')
        except IntegrityError:
            self.skipTest("Unable to create a test user.")
        self.device = self.user.staticdevice_set.create(name='Backup Code')

    def test_only_one_concurrent_consumption_succeeds(self):
        batch = create_static_token_batch('alice', 1)
        token = batch.tokens.get().token
        device_id = self.device.pk
        thread_count = 8
        barrier = Barrier(thread_count)
        results = []

        def consume():
            try:
                device = StaticDevice.objects.get(pk=device_id)
                barrier.wait()
                results.append(device.verify_token(token))
            finally:
                connection.close()

        threads = [Thread(target=consume) for _ in range(thread_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(len(results), thread_count)
        self.assertEqual(sum(1 for result in results if result), 1)
        batch.refresh_from_db()
        self.assertEqual(batch.consumed_count, 1)

    def test_concurrent_duplicate_import_creates_one_batch(self):
        csv_data = '\n'.join(
            'CODE-{0:02d}'.format(index) for index in range(10)
        )
        thread_count = 4
        barrier = Barrier(thread_count)
        batch_ids = []
        errors = []

        def import_codes():
            try:
                barrier.wait()
                batch = import_static_tokens('alice', csv_data)
                batch_ids.append(batch.batch_id)
            except Exception as error:
                errors.append(error)
            finally:
                connection.close()

        threads = [Thread(target=import_codes) for _ in range(thread_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        self.assertEqual(StaticTokenBatch.objects.count(), 1)
        self.assertEqual(StaticToken.objects.filter(device=self.device).count(), 10)
        self.assertEqual(set(batch_ids), {StaticTokenBatch.objects.get().batch_id})


class TimestampTestCase(TimestampTestMixin, TestCase):
    def setUp(self):
        try:
            user = self.create_user('alice', 'password')
        except IntegrityError:
            self.skipTest("Unable to create a test user.")
        else:
            self.device = user.staticdevice_set.create()
            self.device.token_set.create(token='valid1')
            self.device.token_set.create(token='valid2')
            self.device.token_set.create(token='valid3')

    def valid_token(self):
        return self.device.token_set.first().token

    def invalid_token(self):
        return 'bogus'


class StaticDeviceAdminTest(TestCase):
    def setUp(self):
        try:
            self.admin = self.create_user(
                'admin',
                'password',
                email='admin@example.com',
                is_staff=True,
            )
        except IntegrityError:
            self.skipTest("Unable to create test user.")
        else:
            self.device = self.admin.staticdevice_set.create()
        self.device_admin = StaticDeviceAdmin(StaticDevice, AdminSite())
        self.get_request = RequestFactory().get('/')
        self.get_request.user = self.admin

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=True)
    def test_inline_instances_when_sensitive_information_hidden(self):
        self._add_device_perms('change_statictoken')
        instances = self.device_admin.get_inline_instances(self.get_request, obj=None)
        self.assertIsInstance(instances, list)
        self.assertEqual(len(instances), 1)
        self.assertIsInstance(instances[0], StaticTokenInline)
        instances = self.device_admin.get_inline_instances(
            self.get_request, obj=self.device
        )
        self.assertEqual(instances, [])

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=False)
    def test_inline_instances_when_sensitive_information_shown(self):
        self._add_device_perms('change_statictoken')
        for obj in (None, self.device):
            instances = self.device_admin.get_inline_instances(
                self.get_request, obj=obj
            )
            self.assertIsInstance(instances, list)
            self.assertEqual(len(instances), 1)

    #
    # Helpers
    #

    def _add_device_perms(self, *codenames):
        ct = ContentType.objects.get_for_models(StaticDevice, StaticToken)

        perms = [
            Permission.objects.get(content_type__in=ct.values(), codename=codename)
            for codename in codenames
        ]

        self.admin.user_permissions.add(*perms)
