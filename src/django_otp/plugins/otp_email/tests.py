from datetime import timedelta
import smtplib
from unittest import mock

from freezegun import freeze_time

from django.core import mail
from django.db import DatabaseError
from django.db import IntegrityError
from django.test.utils import override_settings
from django.utils import timezone

from django_otp.forms import OTPAuthenticationForm
from django_otp.models import GenerateNotAllowed
from django_otp.test_utils import (
    CooldownTestMixin,
    TestCase,
    ThrottlingTestMixin,
    TimestampTestMixin,
)

from .models import (
    GENERIC_CHALLENGE_FAILURE_MESSAGE,
    ChallengeFailureReason,
    EmailDevice,
)


class EmailDeviceMixin:
    def setUp(self):
        try:
            alice = self.create_user('alice', 'password')
        except IntegrityError:
            self.skipTest("Failed to create user.")
        else:
            self.device = alice.emaildevice_set.create()

        if hasattr(alice, 'email'):
            alice.email = 'alice@example.com'
            alice.save()
        else:
            self.skipTest("User model has no email.")


class AuthFormTest(EmailDeviceMixin, TestCase):
    @override_settings(OTP_EMAIL_SENDER='test@example.com')
    def test_email_interaction(self):
        data = {
            'username': 'alice',
            'password': 'password',
            'otp_device': self.device.persistent_id,
            'otp_token': '',
            'otp_challenge': '1',
        }
        form = OTPAuthenticationForm(None, data)

        self.assertFalse(form.is_valid())
        alice = form.get_user()
        self.assertEqual(alice.get_username(), 'alice')
        self.assertIsNone(alice.otp_device)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ['alice@example.com'])

        self.device.refresh_from_db()
        data['otp_token'] = self.device.token
        del data['otp_challenge']
        form = OTPAuthenticationForm(None, data)

        self.assertTrue(form.is_valid())
        self.assertIsInstance(form.get_user().otp_device, EmailDevice)


@override_settings(
    DEFAULT_FROM_EMAIL="root@localhost",
    OTP_EMAIL_THROTTLE_FACTOR=0,
)
class EmailTest(EmailDeviceMixin, TestCase):
    def test_token_generator(self):
        self.device.generate_token()
        self.device.token.isnumeric()

    def test_invalid_token(self):
        self.device.generate_token()
        self.assertFalse(self.device.verify_token(0))

    def test_no_reuse(self):
        self.device.generate_token()
        token = self.device.token
        self.assertTrue(self.device.verify_token(token))
        self.assertFalse(self.device.verify_token(token))

    def test_token_expiry(self):
        self.device.generate_token()
        token = self.device.token
        with freeze_time() as frozen_time:
            frozen_time.tick(delta=timedelta(seconds=301))
            self.assertFalse(self.device.verify_token(token))

    def test_defaults(self):
        self.device.generate_challenge()

        self.assertEqual(len(mail.outbox), 1)

        msg = mail.outbox[0]

        with self.subTest(field='from_email'):
            self.assertEqual(msg.from_email, "root@localhost")
        with self.subTest(field='body'):
            self.assertEqual(
                msg.body, "Test template 1: {}\n".format(self.device.token)
            )

    @override_settings(
        OTP_EMAIL_SENDER="webmaster@example.com",
        OTP_EMAIL_SUBJECT="Test Subject with token: {token}",
        OTP_EMAIL_BODY_TEMPLATE="Test template: {{token}}",
    )
    def test_settings_with_token_in_subject(self):
        self.device.generate_challenge()

        self.assertEqual(len(mail.outbox), 1)

        msg = mail.outbox[0]

        with self.subTest(field='from_email'):
            self.assertEqual(msg.from_email, "webmaster@example.com")
        with self.subTest(field='subject'):
            self.assertEqual(
                msg.subject, "Test Subject with token: {}".format(self.device.token)
            )
        with self.subTest(field='body'):
            self.assertEqual(msg.body, "Test template: {}".format(self.device.token))

    @override_settings(
        OTP_EMAIL_SENDER="webmaster@example.com",
        OTP_EMAIL_SUBJECT="Test subject",
        OTP_EMAIL_BODY_TEMPLATE="Test template 2: {{token}}",
    )
    def test_settings(self):
        self.device.generate_challenge()

        self.assertEqual(len(mail.outbox), 1)

        msg = mail.outbox[0]

        with self.subTest(field='from_email'):
            self.assertEqual(msg.from_email, "webmaster@example.com")
        with self.subTest(field='subject'):
            self.assertEqual(msg.subject, "Test subject")
        with self.subTest(field='body'):
            self.assertEqual(msg.body, "Test template 2: {}".format(self.device.token))

    @override_settings(
        OTP_EMAIL_SENDER="webmaster@example.com",
        OTP_EMAIL_SUBJECT="Test subject",
        OTP_EMAIL_BODY_HTML_TEMPLATE="<div>{{token}}</div>",
    )
    def test_settings_html_template(self):
        self.device.generate_challenge()

        self.assertEqual(len(mail.outbox), 1)

        msg = mail.outbox[0]

        with self.subTest(field='from_email'):
            self.assertEqual(msg.from_email, "webmaster@example.com")
        with self.subTest(field='subject'):
            self.assertEqual(msg.subject, "Test subject")
        with self.subTest(field='body'):
            self.assertEqual(
                msg.body, 'Test template 1: {}\n'.format(self.device.token)
            )
        with self.subTest(field='alternatives'):
            self.assertEqual(
                msg.alternatives[0],
                ('<div>{}</div>'.format(self.device.token), 'text/html'),
            )

    @override_settings(
        OTP_EMAIL_SENDER="webmaster@example.com",
        OTP_EMAIL_SUBJECT="Test subject",
        OTP_EMAIL_BODY_TEMPLATE_PATH="otp/email/custom.txt",
    )
    def test_settings_template_path(self):
        self.device.generate_challenge()

        self.assertEqual(len(mail.outbox), 1)

        msg = mail.outbox[0]

        with self.subTest(field='from_email'):
            self.assertEqual(msg.from_email, "webmaster@example.com")
        with self.subTest(field='subject'):
            self.assertEqual(msg.subject, "Test subject")
        with self.subTest(field='body'):
            self.assertEqual(
                msg.body, "Test template 3: {}\n".format(self.device.token)
            )

    @override_settings(
        OTP_EMAIL_SENDER="webmaster@example.com",
        OTP_EMAIL_SUBJECT="Test subject",
        OTP_EMAIL_BODY_HTML_TEMPLATE_PATH="otp/email/custom_html.html",
    )
    def test_settings_html_template_path(self):
        self.device.generate_challenge()

        self.assertEqual(len(mail.outbox), 1)

        msg = mail.outbox[0]

        with self.subTest(field='from_email'):
            self.assertEqual(msg.from_email, "webmaster@example.com")
        with self.subTest(field='subject'):
            self.assertEqual(msg.subject, "Test subject")
        with self.subTest(field='body'):
            self.assertEqual(
                msg.body, 'Test template 1: {}\n'.format(self.device.token)
            )
        with self.subTest(field='alternatives'):
            self.assertEqual(
                msg.alternatives[0],
                ('<p>{}</p>'.format(self.device.token), 'text/html'),
            )

    @override_settings(
        OTP_EMAIL_SENDER="webmaster@example.com",
        OTP_EMAIL_SUBJECT="Test subject",
        OTP_EMAIL_BODY_TEMPLATE="Test template 4: {{token}} {{foo}} {{bar}}",
    )
    def test_settings_extra_template_options(self):
        extra_context = {"foo": "extra 1", "bar": "extra 2"}
        self.device.generate_challenge(extra_context)

        self.assertEqual(len(mail.outbox), 1)

        msg = mail.outbox[0]

        with self.subTest(field='from_email'):
            self.assertEqual(msg.from_email, "webmaster@example.com")
        with self.subTest(field='subject'):
            self.assertEqual(msg.subject, "Test subject")
        with self.subTest(field='body'):
            self.assertEqual(
                msg.body,
                "Test template 4: {} {} {}".format(
                    self.device.token, extra_context["foo"], extra_context["bar"]
                ),
            )

    def test_alternative_email(self):
        self.device.email = 'alice2@example.com'
        self.device.save()

        self.device.generate_challenge()

        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ['alice2@example.com'])


@override_settings(
    OTP_EMAIL_THROTTLE_FACTOR=1,
)
class ThrottlingTestCase(EmailDeviceMixin, ThrottlingTestMixin, TestCase):
    def valid_token(self):
        if self.device.token is None:
            self.device.generate_token()

        return self.device.token

    def invalid_token(self):
        return -1


@override_settings(
    OTP_EMAIL_COOLDOWN_DURATION=10,
)
class CooldownTestCase(EmailDeviceMixin, CooldownTestMixin, TestCase):
    def valid_token(self):
        if self.device.token is None:
            self.device.generate_token()

        return self.device.token

    def invalid_token(self):
        return -1

    def test_cooldown_imposed_message(self):
        with freeze_time():
            message = self.device.generate_challenge()
            self.device.refresh_from_db()
            message = self.device.generate_challenge()
            self.assertTrue(
                message.startswith(
                    'Token generation cooldown period has not expired yet. Next generation allowed'
                )
            )

    def test_cooldown_imposed_expiration_message(self):
        with freeze_time() as frozen_time:
            self.device.generate_challenge()
            frozen_time.tick(delta=timedelta(seconds=5))
            self.device.refresh_from_db()
            message = self.device.generate_challenge()
            self.assertIn("Next generation allowed 5\xa0seconds from now.", message)


class TimestampTestCase(EmailDeviceMixin, TimestampTestMixin, TestCase):
    def valid_token(self):
        if self.device.token is None:
            self.device.generate_token()

        return self.device.token

    def invalid_token(self):
        return -1


@override_settings(
    OTP_EMAIL_THROTTLE_FACTOR=0,
    OTP_EMAIL_COOLDOWN_DURATION=10,
    OTP_EMAIL_FAILURE_WINDOW=300,
    OTP_EMAIL_FAILURE_LIMIT=3,
)
class EmailDeliveryFailureTest(EmailDeviceMixin, TestCase):
    """
    Covers the transactional delivery guarantees: failed delivery rolls the
    cooldown and new token back, old tokens stay valid, failures are capped
    within a retry window, and all public failures are indistinguishable.
    """

    def test_smtp_failure_rolls_back_cooldown_and_token(self):
        with self.assertLogs('django_otp.plugins.otp_email', level='WARNING') as logs:
            with mock.patch.object(
                EmailDevice,
                'send_mail',
                side_effect=smtplib.SMTPException('smtp timeout'),
            ):
                message = self.device.generate_challenge()

        self.assertEqual(message, GENERIC_CHALLENGE_FAILURE_MESSAGE)
        self.assertEqual(len(mail.outbox), 0)

        self.device.refresh_from_db()
        self.assertIsNone(self.device.last_generated_timestamp)
        self.assertIsNone(self.device.token)
        self.assertEqual(self.device.generation_failure_count, 1)
        self.assertIsNotNone(self.device.generation_failure_timestamp)
        self.assertTrue(
            any(
                ChallengeFailureReason.DELIVERY_FAILED.value in entry
                for entry in logs.output
            )
        )

        # The failed attempt must not lock the user into a cooldown: an
        # immediate retry is still permitted.
        allowed, _ = self.device.generate_is_allowed()
        self.assertTrue(allowed)

    def test_failed_request_neither_waits_nor_gets_locked_out(self):
        # The support-ticket regression: after a failed send the user must
        # be able to retry immediately and actually receive a code.
        with mock.patch.object(
            EmailDevice,
            'send_mail',
            side_effect=smtplib.SMTPException('smtp timeout'),
        ):
            first_message = self.device.generate_challenge()

        self.assertEqual(first_message, GENERIC_CHALLENGE_FAILURE_MESSAGE)
        self.device.refresh_from_db()
        self.assertIsNone(self.device.last_generated_timestamp)

        second_message = self.device.generate_challenge()
        self.assertEqual(second_message, "sent by email")
        self.assertEqual(len(mail.outbox), 1)

        self.device.refresh_from_db()
        sent_token = mail.outbox[0].body.strip().split()[-1]
        self.assertTrue(self.device.verify_token(sent_token))

    def test_smtp_failure_keeps_old_token_valid(self):
        self.device.generate_token()
        old_token = self.device.token
        self.device.cooldown_reset()

        with mock.patch.object(
            EmailDevice,
            'send_mail',
            side_effect=smtplib.SMTPServerDisconnected('rejected'),
        ):
            message = self.device.generate_challenge()

        self.assertEqual(message, GENERIC_CHALLENGE_FAILURE_MESSAGE)
        self.device.refresh_from_db()
        self.assertEqual(self.device.token, old_token)
        self.assertTrue(self.device.verify_token(old_token))

    def test_socket_error_is_treated_as_delivery_failure(self):
        with self.assertLogs('django_otp.plugins.otp_email', level='WARNING') as logs:
            with mock.patch.object(
                EmailDevice,
                'send_mail',
                side_effect=TimeoutError('connection timed out'),
            ):
                message = self.device.generate_challenge()

        self.assertEqual(message, GENERIC_CHALLENGE_FAILURE_MESSAGE)
        self.device.refresh_from_db()
        self.assertIsNone(self.device.last_generated_timestamp)
        self.assertEqual(self.device.generation_failure_count, 1)
        self.assertTrue(
            any(
                ChallengeFailureReason.DELIVERY_FAILED.value in entry
                for entry in logs.output
            )
        )

    def test_database_error_before_send_rolls_back_without_email(self):
        with self.assertLogs('django_otp.plugins.otp_email', level='ERROR') as logs:
            with mock.patch.object(
                EmailDevice,
                'cooldown_set',
                autospec=True,
                side_effect=DatabaseError('disk full'),
            ):
                message = self.device.generate_challenge()

        self.assertEqual(message, GENERIC_CHALLENGE_FAILURE_MESSAGE)
        self.assertEqual(len(mail.outbox), 0)

        self.device.refresh_from_db()
        self.assertIsNone(self.device.last_generated_timestamp)
        self.assertIsNone(self.device.token)
        # Failure bookkeeping still succeeds via the real save path.
        self.assertEqual(self.device.generation_failure_count, 1)
        self.assertTrue(
            any(
                ChallengeFailureReason.DATABASE_ERROR.value in entry
                for entry in logs.output
            )
        )

    def test_database_error_after_send_leaves_no_usable_phantom_token(self):
        # The final save (after the message was accepted) fails, so the
        # whole generation transaction rolls back. The subsequent
        # failure-bookkeeping save must still succeed.
        real_save = EmailDevice.save
        save_calls = {'count': 0}

        def flaky_save(self_device, *args, **kwargs):
            save_calls['count'] += 1
            if save_calls['count'] == 1:
                raise DatabaseError('commit failed')
            return real_save(self_device, *args, **kwargs)

        with self.assertLogs('django_otp.plugins.otp_email', level='ERROR') as logs:
            with mock.patch.object(
                EmailDevice, 'save', autospec=True, side_effect=flaky_save
            ):
                message = self.device.generate_challenge()

        self.assertEqual(message, GENERIC_CHALLENGE_FAILURE_MESSAGE)
        self.device.refresh_from_db()
        # Nothing from the rolled-back generation transaction is visible.
        self.assertIsNone(self.device.token)
        self.assertIsNone(self.device.last_generated_timestamp)
        self.assertEqual(self.device.generation_failure_count, 1)
        self.assertTrue(
            any(
                ChallengeFailureReason.DATABASE_ERROR.value in entry
                for entry in logs.output
            )
        )

    def test_phantom_token_from_failed_commit_is_never_usable(self):
        # A message may have been accepted before the commit failed, but
        # the rolled-back token must not verify against the device.
        real_save = EmailDevice.save
        save_calls = {'count': 0}

        def flaky_save(self_device, *args, **kwargs):
            save_calls['count'] += 1
            if save_calls['count'] == 1:
                raise DatabaseError('commit failed')
            return real_save(self_device, *args, **kwargs)

        with mock.patch.object(
            EmailDevice, 'save', autospec=True, side_effect=flaky_save
        ):
            self.device.generate_challenge()

        # The outbox carries the token that was rendered into the message.
        self.assertEqual(len(mail.outbox), 1)
        phantom_token = mail.outbox[0].body.strip().split()[-1]

        self.device.refresh_from_db()
        self.assertIsNone(self.device.token)
        self.assertFalse(self.device.verify_token(phantom_token))

    def test_successful_delivery_commits_token_and_clears_failures(self):
        self.device.generation_failure_record()
        self.device.refresh_from_db()
        self.assertEqual(self.device.generation_failure_count, 1)

        message = self.device.generate_challenge()

        self.assertEqual(message, "sent by email")
        self.assertEqual(len(mail.outbox), 1)

        self.device.refresh_from_db()
        self.assertIsNotNone(self.device.token)
        self.assertIsNotNone(self.device.last_generated_timestamp)
        self.assertEqual(self.device.generation_failure_count, 0)
        self.assertIsNone(self.device.generation_failure_timestamp)
        self.assertEqual(mail.outbox[0].to, ['alice@example.com'])

    def test_retry_limit_blocks_generation_within_window(self):
        for _ in range(3):
            with mock.patch.object(
                EmailDevice,
                'send_mail',
                side_effect=smtplib.SMTPException('smtp timeout'),
            ):
                message = self.device.generate_challenge()
            self.assertEqual(message, GENERIC_CHALLENGE_FAILURE_MESSAGE)

        self.device.refresh_from_db()
        self.assertEqual(self.device.generation_failure_count, 3)
        self.assertEqual(len(mail.outbox), 0)

        with self.assertLogs('django_otp.plugins.otp_email', level='WARNING') as logs:
            message = self.device.generate_challenge()

        # Even with the mail backend healthy again, no further send is
        # attempted until the failure window expires.
        self.assertEqual(message, GENERIC_CHALLENGE_FAILURE_MESSAGE)
        self.assertEqual(len(mail.outbox), 0)
        self.device.refresh_from_db()
        self.assertEqual(self.device.generation_failure_count, 3)
        self.assertTrue(
            any(
                ChallengeFailureReason.RETRY_LIMIT_EXCEEDED.value in entry
                for entry in logs.output
            )
        )

        allowed, details = self.device.generate_is_allowed()
        self.assertFalse(allowed)
        self.assertEqual(
            details['reason'],
            GenerateNotAllowed.GENERATION_RETRY_LIMIT_PENDING,
        )
        self.assertEqual(details['failure_count'], 3)

    def test_retry_limit_resets_after_window_expires(self):
        with freeze_time() as frozen_time:
            for _ in range(3):
                with mock.patch.object(
                    EmailDevice,
                    'send_mail',
                    side_effect=smtplib.SMTPException('smtp timeout'),
                ):
                    self.device.generate_challenge()

            frozen_time.tick(delta=timedelta(seconds=301))

            message = self.device.generate_challenge()

        self.assertEqual(message, "sent by email")
        self.assertEqual(len(mail.outbox), 1)
        self.device.refresh_from_db()
        self.assertEqual(self.device.generation_failure_count, 0)

    def test_failures_outside_window_restart_the_count(self):
        with freeze_time() as frozen_time:
            with mock.patch.object(
                EmailDevice,
                'send_mail',
                side_effect=smtplib.SMTPException('smtp timeout'),
            ):
                self.device.generate_challenge()
            self.device.refresh_from_db()
            self.assertEqual(self.device.generation_failure_count, 1)

            frozen_time.tick(delta=timedelta(seconds=301))
            with mock.patch.object(
                EmailDevice,
                'send_mail',
                side_effect=smtplib.SMTPException('smtp timeout'),
            ):
                self.device.generate_challenge()

        self.device.refresh_from_db()
        self.assertEqual(self.device.generation_failure_count, 1)


@override_settings(
    OTP_EMAIL_THROTTLE_FACTOR=0,
    OTP_EMAIL_COOLDOWN_DURATION=10,
)
class EmailEnumerationTest(EmailDeviceMixin, TestCase):
    """
    Unconfirmed devices, missing recipients and server-side delivery
    failures must all produce the same public response; the distinction
    only exists in audit log reason codes.
    """

    def test_unconfirmed_device_returns_generic_message(self):
        self.device.confirmed = False
        self.device.save()

        with self.assertLogs('django_otp.plugins.otp_email', level='WARNING') as logs:
            message = self.device.generate_challenge()

        self.assertEqual(message, GENERIC_CHALLENGE_FAILURE_MESSAGE)
        self.assertEqual(len(mail.outbox), 0)
        self.device.refresh_from_db()
        self.assertIsNone(self.device.last_generated_timestamp)
        self.assertTrue(
            any(
                ChallengeFailureReason.DEVICE_UNCONFIRMED.value in entry
                for entry in logs.output
            )
        )

    def test_missing_recipient_returns_generic_message(self):
        self.device.email = None
        self.device.save()
        alice = self.device.user
        alice.email = ''
        alice.save()

        with self.assertLogs('django_otp.plugins.otp_email', level='WARNING') as logs:
            message = self.device.generate_challenge()

        self.assertEqual(message, GENERIC_CHALLENGE_FAILURE_MESSAGE)
        self.assertEqual(len(mail.outbox), 0)
        self.assertTrue(
            any(
                ChallengeFailureReason.RECIPIENT_MISSING.value in entry
                for entry in logs.output
            )
        )

    def test_all_failure_responses_are_indistinguishable(self):
        responses = []

        self.device.confirmed = False
        self.device.save()
        responses.append(self.device.generate_challenge())
        self.device.confirmed = True
        self.device.save()

        self.device.email = None
        self.device.save()
        alice = self.device.user
        alice.email = ''
        alice.save()
        responses.append(self.device.generate_challenge())
        alice.email = 'alice@example.com'
        alice.save()

        with mock.patch.object(
            EmailDevice,
            'send_mail',
            side_effect=smtplib.SMTPException('smtp timeout'),
        ):
            responses.append(self.device.generate_challenge())

        self.assertEqual(
            responses,
            [GENERIC_CHALLENGE_FAILURE_MESSAGE] * 3,
        )


@override_settings(
    OTP_EMAIL_THROTTLE_FACTOR=0,
    OTP_EMAIL_COOLDOWN_DURATION=10,
)
class EmailConcurrencyTest(EmailDeviceMixin, TestCase):
    """
    Concurrent challenges must serialize on a row lock and the re-read
    cooldown check guarantees that only one contender can claim a send.
    """

    def test_locked_queryset_uses_select_for_update(self):
        queryset = self.device._locked_queryset()
        self.assertTrue(queryset.query.select_for_update)

    def test_second_concurrent_request_loses_the_send(self):
        # Simulate a contender that won the row lock and committed a claim
        # first: the outer pre-check passes, but the re-read row inside the
        # transaction reports a pending cooldown.
        cooldown_verdict = (
            False,
            {
                'reason': GenerateNotAllowed.COOLDOWN_DURATION_PENDING,
                'next_generation_at': timezone.now() + timedelta(seconds=10),
            },
        )

        with self.assertLogs('django_otp.plugins.otp_email', level='INFO') as logs:
            with mock.patch.object(
                EmailDevice,
                'generate_is_allowed',
                autospec=True,
                side_effect=[(True, None), cooldown_verdict],
            ):
                message = self.device.generate_challenge()

        self.assertTrue(message.startswith('Token generation cooldown'))
        self.assertEqual(len(mail.outbox), 0)
        self.device.refresh_from_db()
        self.assertIsNone(self.device.token)
        self.assertIsNone(self.device.last_generated_timestamp)
        self.assertTrue(
            any(
                ChallengeFailureReason.COOLDOWN_PENDING.value in entry
                for entry in logs.output
            )
        )

    def test_concurrent_claim_does_not_send_or_overwrite_existing_token(self):
        self.device.generate_token()
        old_token = self.device.token
        self.device.cooldown_reset()
        self.device.refresh_from_db()

        cooldown_verdict = (
            False,
            {
                'reason': GenerateNotAllowed.COOLDOWN_DURATION_PENDING,
                'next_generation_at': timezone.now() + timedelta(seconds=10),
            },
        )

        with mock.patch.object(
            EmailDevice,
            'generate_is_allowed',
            autospec=True,
            side_effect=[(True, None), cooldown_verdict],
        ):
            message = self.device.generate_challenge()

        self.assertTrue(message.startswith('Token generation cooldown'))
        self.assertEqual(len(mail.outbox), 0)
        self.device.refresh_from_db()
        self.assertEqual(self.device.token, old_token)

    def test_only_one_email_sent_for_sequential_claims_under_cooldown(self):
        first_message = self.device.generate_challenge()
        self.assertEqual(first_message, "sent by email")

        # The immediate second request is refused by the cooldown and never
        # reaches the mail backend.
        with mock.patch.object(EmailDevice, 'send_mail') as send_mail:
            second_message = self.device.generate_challenge()

        self.assertNotEqual(second_message, "sent by email")
        send_mail.assert_not_called()
        self.assertEqual(len(mail.outbox), 1)
