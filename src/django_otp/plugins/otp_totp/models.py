from base64 import b32encode
from binascii import unhexlify
import time
from urllib.parse import quote, urlencode

from django.conf import settings
from django.db import models

from django_otp.models import Device, ThrottlingMixin, TimestampMixin
from django_otp.oath import (
    DEFAULT_MAX_DRIFT_STEP,
    DEFAULT_MAX_FUTURE_DRIFT,
    DEFAULT_MAX_PAST_DRIFT,
    TOTP,
    TOTPConfigurationError,
    TOTPError,
    TOTPOutOfWindowError,
)
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

    # The device opts into the strict clock policy by default.  This prevents
    # a manually changed prover clock from persisting an arbitrarily large
    # drift.  It can be disabled explicitly for callers that need the legacy
    # unbounded behaviour.
    strict_clock = True
    max_drift_step = DEFAULT_MAX_DRIFT_STEP
    max_future_drift = DEFAULT_MAX_FUTURE_DRIFT
    max_past_drift = DEFAULT_MAX_PAST_DRIFT

    @property
    def bin_key(self):
        """
        The secret key as a binary string.
        """
        return unhexlify(self.key.encode())

    def verify_token(self, token):
        OTP_TOTP_SYNC = getattr(settings, 'OTP_TOTP_SYNC', True)
        self.last_verify_error = None

        verify_allowed, _ = self.verify_is_allowed()
        if not verify_allowed:
            return False

        try:
            token = int(token)
        except Exception:
            verified = False
            self.last_verify_error = TOTPOutOfWindowError()
        else:
            strict = self._clock_option(
                ('OTP_TOTP_STRICT_CLOCK', 'OTP_TOTP_STRICT'),
                ('strict_clock', 'clock_strict', 'enforce_clock'),
                True,
            )
            max_drift_step = self._clock_option(
                (
                    'OTP_TOTP_MAX_DRIFT_STEP',
                    'OTP_TOTP_MAX_DRIFT_PER_STEP',
                ),
                (
                    'max_drift_step',
                    'max_drift_per_step',
                    'max_step_adjustment',
                ),
                DEFAULT_MAX_DRIFT_STEP,
            )
            max_future_drift = self._clock_option(
                (
                    'OTP_TOTP_MAX_FUTURE_DRIFT',
                    'OTP_TOTP_FUTURE_DRIFT_LIMIT',
                ),
                (
                    'max_future_drift',
                    'future_drift_limit',
                    'max_future_steps',
                ),
                DEFAULT_MAX_FUTURE_DRIFT,
            )
            max_past_drift = self._clock_option(
                (
                    'OTP_TOTP_MAX_PAST_DRIFT',
                    'OTP_TOTP_PAST_DRIFT_LIMIT',
                ),
                (
                    'max_past_drift',
                    'past_drift_limit',
                    'max_past_steps',
                ),
                DEFAULT_MAX_PAST_DRIFT,
            )

            # On the last successful verification, last_t was the absolute
            # (drift-adjusted) step and drift was the offset used to reach it.
            # Their difference is therefore the server-side base step at that
            # moment.  Keeping it as a floor lets us recognize a rollback
            # without adding another persisted field.
            min_base_t = None
            if self.last_t >= 0:
                min_base_t = self.last_t - self.drift

            totp = None
            try:
                totp = TOTP(
                    self.bin_key,
                    self.step,
                    self.t0,
                    self.digits,
                    self.drift,
                    strict=strict,
                    max_drift_step=max_drift_step,
                    max_future_drift=max_future_drift,
                    max_past_drift=max_past_drift,
                )
                totp.time = time.time()

                verified = totp.verify(
                    token,
                    self.tolerance,
                    self.last_t + 1,
                    min_base_t=min_base_t,
                )
            except TOTPError as error:
                verified = False
                self.last_verify_error = error
            except Exception:
                # Configuration and decoding failures are reported as a safe
                # category; neither the key nor the token is included.
                verified = False
                self.last_verify_error = TOTPConfigurationError()

            if verified:
                self.last_t = totp.t()
                if OTP_TOTP_SYNC:
                    self.drift = totp.drift
                self.throttle_reset(commit=False)
                self.set_last_used_timestamp(commit=False)
                self.save()
            else:
                self.last_verify_error = self.last_verify_error or getattr(
                    totp, 'last_error', None
                )

        if not verified:
            self.throttle_increment(commit=True)

        return verified

    def _clock_option(self, setting_names, attribute_names, default):
        for name in setting_names:
            if hasattr(settings, name):
                return getattr(settings, name)
        for name in attribute_names:
            if hasattr(self, name):
                return getattr(self, name)
        return default

    def get_throttle_factor(self):
        return getattr(settings, 'OTP_TOTP_THROTTLE_FACTOR', 1)

    @property
    def last_verify_error_code(self):
        """
        The safe category of the most recent failed verification, if any.

        Possible values are ``out_of_window``, ``rollback``,
        ``configuration_error`` and ``consumed``.
        """
        return getattr(getattr(self, 'last_verify_error', None), 'code', None)

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
