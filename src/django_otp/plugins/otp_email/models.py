import enum
import logging
import smtplib
import socket

from django.contrib.humanize.templatetags.humanize import naturaltime
from django.core.mail import send_mail
from django.db import DatabaseError, transaction
from django.db import models
from django.template import Context, Template
from django.template.loader import get_template
from django.utils.translation import gettext

from django_otp.models import (
    CooldownMixin,
    GenerateNotAllowed,
    SideChannelDevice,
    ThrottlingMixin,
    TimestampMixin,
)
from django_otp.util import hex_validator, random_hex

from .conf import settings

logger = logging.getLogger('django_otp.plugins.otp_email')

# Returned (and logged) for every externally visible challenge failure, so
# that unconfirmed devices, unusable addresses and delivery errors never
# produce distinguishable responses.
GENERIC_CHALLENGE_FAILURE_MESSAGE = gettext(
    "We couldn't send your verification code. Please try again later."
)


def default_key():  # pragma: no cover
    """Obsolete code here for migrations."""
    return random_hex(20)


def key_validator(value):  # pragma: no cover
    """Obsolete code here for migrations."""
    return hex_validator()(value)


class ChallengeFailureReason(enum.Enum):
    """
    Stable reason codes recorded in audit log entries when a challenge
    cannot be delivered.

    These are never exposed to users; the public response is always
    :data:`GENERIC_CHALLENGE_FAILURE_MESSAGE`.
    """

    DEVICE_UNCONFIRMED = 'DEVICE_UNCONFIRMED'
    RECIPIENT_MISSING = 'RECIPIENT_MISSING'
    RETRY_LIMIT_EXCEEDED = 'RETRY_LIMIT_EXCEEDED'
    COOLDOWN_PENDING = 'COOLDOWN_PENDING'
    DELIVERY_FAILED = 'DELIVERY_FAILED'
    DATABASE_ERROR = 'DATABASE_ERROR'
    INTERNAL_ERROR = 'INTERNAL_ERROR'


class EmailDevice(TimestampMixin, CooldownMixin, ThrottlingMixin, SideChannelDevice):
    """
    A :class:`~django_otp.models.SideChannelDevice` that delivers a token to
    the email address saved in this object or alternatively to the user's
    registered email address (``user.email``).

    The tokens are valid for :setting:`OTP_EMAIL_TOKEN_VALIDITY` seconds. Once
    a token has been accepted, it is no longer valid.

    Note that if you allow users to reset their passwords by email, this may
    provide little additional account security. It may still be useful for,
    e.g., requiring the user to re-verify their email address on new devices.

    .. attribute:: email

        *EmailField*: An alternative email address to send the tokens to.

    """

    email = models.EmailField(
        max_length=254,
        blank=True,
        null=True,
        help_text='Optional alternative email address to send tokens to',
    )

    def generate_challenge(self, extra_context=None):
        """
        Generates a random token and emails it to the user.

        The cooldown claim, token generation and delivery share a single
        transaction. A delivery failure rolls the cooldown and token back,
        leaving any previously issued token intact; the new token is only
        committed once the message has been accepted for delivery.

        Failures are counted within a sliding window
        (:setting:`OTP_EMAIL_FAILURE_WINDOW`) up to
        :setting:`OTP_EMAIL_FAILURE_LIMIT`, after which further attempts are
        refused until the window expires, so broken delivery cannot consume
        the mail quota indefinitely.

        Every externally visible failure returns the same generic message;
        the precise, stable reason code is only written to the audit log.

        :param extra_context: Additional context variables for rendering the
            email template.
        :type extra_context: dict

        """
        generate_allowed, data_dict = self.generate_is_allowed()
        if not generate_allowed:
            if data_dict['reason'] == GenerateNotAllowed.COOLDOWN_DURATION_PENDING:
                return self._cooldown_pending_response(data_dict)
            else:
                self._audit(
                    ChallengeFailureReason.RETRY_LIMIT_EXCEEDED,
                    logging.WARNING,
                    failure_count=data_dict.get('failure_count'),
                )
                return GENERIC_CHALLENGE_FAILURE_MESSAGE

        if not self.confirmed:
            self._audit(ChallengeFailureReason.DEVICE_UNCONFIRMED, logging.WARNING)
            return GENERIC_CHALLENGE_FAILURE_MESSAGE

        recipient = self.email or getattr(self.user, 'email', None)
        if not recipient:
            self._audit(ChallengeFailureReason.RECIPIENT_MISSING, logging.WARNING)
            return GENERIC_CHALLENGE_FAILURE_MESSAGE

        try:
            # The whole claim/generate/deliver sequence is one transaction.
            # select_for_update() serializes concurrent requests on backends
            # that support row locks (it is a no-op where unsupported, e.g.
            # SQLite), and the re-read cooldown check makes the second
            # contender lose even without real row locks.
            with transaction.atomic():
                locked_device = self._locked_queryset().get(pk=self.pk)
                allowed, details = locked_device.generate_is_allowed()
                if not allowed:
                    # Another request won the send while we were waiting.
                    self.refresh_from_db()
                    return self._cooldown_pending_response(details)

                locked_device._deliver_token(extra_context)

                # The message has been accepted for delivery; only now do we
                # persist the new cooldown, token and clear failure state.
                locked_device.generation_failure_reset(commit=False)
                locked_device.save()
        except DatabaseError:
            logger.exception(
                "OTP email challenge failed: reason=%s device_pk=%s",
                ChallengeFailureReason.DATABASE_ERROR.value,
                self.pk,
            )
            self._handle_delivery_failure()
            return GENERIC_CHALLENGE_FAILURE_MESSAGE
        except (smtplib.SMTPException, socket.error) as exc:
            logger.warning(
                "OTP email challenge failed: reason=%s device_pk=%s error=%s",
                ChallengeFailureReason.DELIVERY_FAILED.value,
                self.pk,
                exc,
            )
            self._handle_delivery_failure()
            return GENERIC_CHALLENGE_FAILURE_MESSAGE
        except Exception:  # pragma: no cover - defensive catch-all
            logger.exception(
                "OTP email challenge failed: reason=%s device_pk=%s",
                ChallengeFailureReason.INTERNAL_ERROR.value,
                self.pk,
            )
            self._handle_delivery_failure()
            return GENERIC_CHALLENGE_FAILURE_MESSAGE

        self.refresh_from_db()
        return gettext("sent by email")

    def _locked_queryset(self):
        """
        Returns the queryset used to re-read this device under a row lock
        inside the generation transaction.

        Backends without ``select_for_update`` support (such as SQLite)
        simply ignore the locking clause.
        """
        return type(self).objects.select_for_update().filter(pk=self.pk)

    def _cooldown_pending_response(self, data_dict):
        """
        Builds the user-facing response for a pending cooldown and writes
        the corresponding audit entry.

        Cooldown timing guidance is harmless rate-limit information rather
        than an account-state signal, so it remains specific; the audit
        entry still carries the stable reason code.
        """
        next_generation_naturaltime = naturaltime(data_dict['next_generation_at'])
        message = (
            gettext(
                "Token generation cooldown period has not expired yet. Next"
                " generation allowed %s."
            )
            % next_generation_naturaltime
        )
        self._audit(ChallengeFailureReason.COOLDOWN_PENDING, logging.INFO)

        return message

    def _handle_delivery_failure(self):
        """
        Records a failed generation after the generation transaction has
        rolled back.

        The cooldown and token were part of that transaction, so the old
        token (if any) remains valid and the user is not locked out by the
        failed attempt. The failure bookkeeping is committed separately so
        the retry window still works.
        """
        self.refresh_from_db()
        try:
            with transaction.atomic():
                self.generation_failure_record(commit=False)
                self.save()
        except DatabaseError:  # pragma: no cover - nothing else we can do
            logger.exception(
                "OTP email failure bookkeeping failed: reason=%s device_pk=%s",
                ChallengeFailureReason.DATABASE_ERROR.value,
                self.pk,
            )

    def _audit(self, reason, level, **extra):
        """
        Emits an audit log entry with a stable reason code.
        """
        logger.log(
            level,
            "OTP email challenge audit: reason=%s device_pk=%s%s",
            reason.value,
            self.pk,
            ''.join(' %s=%r' % (key, value) for key, value in extra.items()),
        )

    def _deliver_token(self, extra_context):
        """
        Claims the cooldown, generates a token and sends the email, all
        without committing: the caller owns the surrounding transaction.

        Any exception from the database or the mail backend propagates to
        the caller so the entire transaction is rolled back.
        """
        self.cooldown_set(commit=False)
        self.generate_token(valid_secs=settings.OTP_EMAIL_TOKEN_VALIDITY, commit=False)

        context = {'token': self.token, **(extra_context or {})}
        if settings.OTP_EMAIL_BODY_TEMPLATE:
            body = Template(settings.OTP_EMAIL_BODY_TEMPLATE).render(Context(context))
        else:
            body = get_template(settings.OTP_EMAIL_BODY_TEMPLATE_PATH).render(context)

        if settings.OTP_EMAIL_BODY_HTML_TEMPLATE:
            body_html = Template(settings.OTP_EMAIL_BODY_HTML_TEMPLATE).render(
                Context(context)
            )
        elif settings.OTP_EMAIL_BODY_HTML_TEMPLATE_PATH:
            body_html = get_template(settings.OTP_EMAIL_BODY_HTML_TEMPLATE_PATH).render(
                context
            )
        else:
            body_html = None

        self.send_mail(body, html_message=body_html)

    def get_subject(self):
        """
        Returns a formatted email subject.

        This renders :setting:`OTP_EMAIL_SUBJECT` with the optional `token`
        placeholder. Subclasses may customize this.

        """
        return str(settings.OTP_EMAIL_SUBJECT).format(token=self.token)

    def send_mail(self, body, **kwargs):
        """
        A simple wrapper for :func:`django.core.mail.send_mail`.

        Subclasses (e.g. proxy models) may override this to customize delivery.

        """
        send_mail(
            self.get_subject(),
            body,
            settings.OTP_EMAIL_SENDER,
            [self.email or self.user.email],
            **kwargs,
        )

    def verify_token(self, token):
        """"""
        verify_allowed, _ = self.verify_is_allowed()
        if verify_allowed:
            verified = super().verify_token(token)

            if verified:
                self.throttle_reset(commit=False)
                self.set_last_used_timestamp(commit=False)
                self.save()
            else:
                self.throttle_increment()
        else:
            verified = False

        return verified

    def get_cooldown_duration(self):
        """
        Returns :setting:`OTP_EMAIL_COOLDOWN_DURATION`.
        """
        return settings.OTP_EMAIL_COOLDOWN_DURATION

    def get_generation_failure_window(self):
        """
        Returns :setting:`OTP_EMAIL_FAILURE_WINDOW`.
        """
        return settings.OTP_EMAIL_FAILURE_WINDOW

    def get_generation_failure_limit(self):
        """
        Returns :setting:`OTP_EMAIL_FAILURE_LIMIT`.
        """
        return settings.OTP_EMAIL_FAILURE_LIMIT

    def get_throttle_factor(self):
        """
        Returns :setting:`OTP_EMAIL_THROTTLE_FACTOR`.
        """
        return settings.OTP_EMAIL_THROTTLE_FACTOR
