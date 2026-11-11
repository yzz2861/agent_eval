from base64 import b32encode
from binascii import unhexlify
import time
from urllib.parse import quote, urlencode

from django.conf import settings
from django.db import models, transaction
from django.utils import timezone

from django_otp.models import Device, ThrottlingMixin, TimestampMixin
from django_otp.oath import TOTP
from django_otp.util import hex_validator, random_hex


def default_key():
    return random_hex(20)


def key_validator(value):
    return hex_validator()(value)


class TOTPDevice(TimestampMixin, ThrottlingMixin, Device):
    """
    A generic TOTP :class:`~django_otp.models.Device`. The model fields mostly
    correspond to the arguments to :func:`django_otp.oath.totp`. They all have
    sensible defaults, including the key, which is randomly generated.

    .. attribute:: key

        *CharField*: A hex-encoded secret key of up to 40 bytes. (Default: 20
        random bytes)

    .. attribute:: step

        *PositiveSmallIntegerField*: The time step in seconds. (Default: 30)

    .. attribute:: t0

        *BigIntegerField*: The Unix time at which to begin counting steps.
        (Default: 0)

    .. attribute:: digits

        *PositiveSmallIntegerField*: The number of digits to expect in a token
        (6 or 8).  (Default: 6)

    .. attribute:: tolerance

        *PositiveSmallIntegerField*: The number of time steps in the past or
        future to allow. For example, if this is 1, we'll accept any of three
        tokens: the current one, the previous one, and the next one. (Default:
        1)

    .. attribute:: drift

        *SmallIntegerField*: The number of time steps the prover is known to
        deviate from our clock.  If :setting:`OTP_TOTP_SYNC` is ``True``, we'll
        update this any time we match a token that is not the current one.
        (Default: 0)

    .. attribute:: last_t

        *BigIntegerField*: The time step of the last verified token. To avoid
        verifying the same token twice, this will be updated on each successful
        verification. Only tokens at a higher time step will be verified
        subsequently. (Default: -1)

    """

    key = models.CharField(
        max_length=80,
        validators=[key_validator],
        default=default_key,
        help_text="A hex-encoded secret key of up to 40 bytes.",
    )
    step = models.PositiveSmallIntegerField(
        default=30, help_text="The time step in seconds."
    )
    t0 = models.BigIntegerField(
        default=0, help_text="The Unix time at which to begin counting steps."
    )
    digits = models.PositiveSmallIntegerField(
        choices=[(6, 6), (8, 8)],
        default=6,
        help_text="The number of digits to expect in a token.",
    )
    tolerance = models.PositiveSmallIntegerField(
        default=1, help_text="The number of time steps in the past or future to allow."
    )
    drift = models.SmallIntegerField(
        default=0,
        help_text="The number of time steps the prover is known to deviate from our clock.",
    )
    last_t = models.BigIntegerField(
        default=-1,
        help_text="The t value of the latest verified token. The next token must be at a higher time step.",
    )

    class Meta(Device.Meta):
        verbose_name = "TOTP device"

    @property
    def bin_key(self):
        """
        The secret key as a binary string.
        """
        return unhexlify(self.key.encode())

    def verify_token(self, token):
        try:
            token = int(token)
        except Exception:
            # A token that can't even be parsed is a genuine failure.
            with transaction.atomic():
                verify_allowed, _ = self.verify_is_allowed()
                if verify_allowed:
                    self.throttle_increment_atomic()
            return False

        # The allowed-check, the last_t guard and the state update all happen
        # in a single transaction with a conditional UPDATE, so a concurrent
        # verification can never consume the same token twice.
        with transaction.atomic():
            verify_allowed, _ = self.verify_is_allowed()
            if not verify_allowed:
                return False

            key = self.bin_key

            totp = TOTP(key, self.step, self.t0, self.digits, self.drift)
            totp.time = time.time()

            current_last_t = self.last_t
            verified = totp.verify(token, self.tolerance, current_last_t + 1)
            if not verified:
                # A genuinely wrong token still counts as a failure.
                self.throttle_increment_atomic()
                return False

            update_fields = {
                'last_t': totp.t(),
                'last_used_at': timezone.now(),
                'throttling_failure_timestamp': None,
                'throttling_failure_count': 0,
            }
            if getattr(settings, 'OTP_TOTP_SYNC', True):
                update_fields['drift'] = totp.drift

            # Only commit while last_t still holds the value we read. If a
            # concurrent request already consumed any token (advancing
            # last_t), this matches zero rows and exactly one request wins;
            # the strict time-step rule itself is enforced by totp.verify().
            updated = (
                type(self)
                .objects.filter(pk=self.pk, last_t=current_last_t)
                .update(**update_fields)
            )
            if updated == 0:
                # The token was already consumed by a concurrent request;
                # that is not a failed attempt and must not count toward
                # throttling.
                return False

            for name, value in update_fields.items():
                setattr(self, name, value)
            return True

    def get_throttle_factor(self):
        return getattr(settings, 'OTP_TOTP_THROTTLE_FACTOR', 1)

    @property
    def config_url(self):
        """
        A URL for configuring Google Authenticator or similar.

        See https://github.com/google/google-authenticator/wiki/Key-Uri-Format.
        The issuer is taken from :setting:`OTP_TOTP_ISSUER`, if available.
        The image (for e.g. FreeOTP) is taken from :setting:`OTP_TOTP_IMAGE`, if available.

        """
        label = str(self.user.get_username())
        params = {
            'secret': b32encode(self.bin_key),
            'algorithm': 'SHA1',
            'digits': self.digits,
            'period': self.step,
        }
        urlencoded_params = urlencode(params)

        issuer = self._read_str_from_settings('OTP_TOTP_ISSUER')
        if issuer:
            issuer = issuer.replace(':', '')
            label = '{}:{}'.format(issuer, label)
            urlencoded_params += '&issuer={}'.format(
                quote(issuer)
            )  # encode issuer as per RFC 3986, not quote_plus

        image = self._read_str_from_settings('OTP_TOTP_IMAGE')
        if image:
            urlencoded_params += "&image={}".format(quote(image, safe=':/'))

        url = 'otpauth://totp/{}?{}'.format(quote(label), urlencoded_params)

        return url

    def _read_str_from_settings(self, key):
        val = getattr(settings, key, None)
        if callable(val):
            val = val(self)
        if isinstance(val, str) and (val != ''):
            return val
        return None
