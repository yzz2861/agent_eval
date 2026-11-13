from datetime import datetime, timezone
from hashlib import sha1
import hmac
import math
from struct import pack
from time import time


# Limits used by the opt-in strict clock policy.  These are deliberately
# small: a clock that is more than a few steps away is evidence that the
# prover's clock was changed rather than ordinary drift.  The values can be
# overridden by the caller or by a device that has a larger legitimate skew.
DEFAULT_MAX_DRIFT_STEP = 8
DEFAULT_MAX_FUTURE_DRIFT = 8
DEFAULT_MAX_PAST_DRIFT = 8


class TOTPError(Exception):
    """
    Base class for safe TOTP verification errors.

    The exception text intentionally never contains the shared key or the
    submitted token.
    """

    code = 'totp_error'
    default_message = 'TOTP verification failed'

    def __init__(self, message=None):
        super().__init__(message if message is not None else self.default_message)


class TOTPConfigurationError(TOTPError):
    """The device or caller supplied an unusable TOTP configuration."""

    code = 'configuration_error'
    default_message = 'invalid TOTP configuration'


class TOTPOutOfWindowError(TOTPError):
    """The token did not match any step in the permitted window."""

    code = 'out_of_window'
    default_message = 'token is outside of the permitted window'


class TOTPRollbackError(TOTPError):
    """A backwards clock change was detected."""

    code = 'rollback'
    default_message = 'clock rollback detected'


class TOTPConsumedError(TOTPError):
    """The matching time step has already been consumed."""

    code = 'consumed'
    default_message = 'time step has already been consumed'


# Convenient aliases for callers that prefer shorter names.
TOTPConfigError = TOTPConfigurationError
OutOfWindowError = TOTPOutOfWindowError
RollbackError = TOTPRollbackError
ConsumedError = TOTPConsumedError
TOTPVerificationError = TOTPError
VerifyError = TOTPError
TOTPWindowError = TOTPOutOfWindowError
ClockRollbackError = TOTPRollbackError
TokenConsumedError = TOTPConsumedError


def _seconds(value):
    """
    Normalize a Unix timestamp without depending on the local timezone.

    Naive datetimes are interpreted as UTC.  Aware datetimes are converted
    to their absolute instant, so changing the UTC offset alone does not
    change the resulting time step.
    """
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.timestamp()
    if isinstance(value, bool):
        raise TOTPConfigurationError()
    return value


def hotp(key, counter, digits=6):
    """
    Implementation of the HOTP algorithm from `RFC 4226
    <http://tools.ietf.org/html/rfc4226#section-5>`_.

    :param bytes key: The shared secret. A 20-byte string is recommended.
    :param int counter: The password counter.
    :param int digits: The number of decimal digits to generate.

    :returns: The HOTP token.
    :rtype: int

    >>> key = b'12345678901234567890'
    >>> for c in range(10):
    ...     hotp(key, c)
    755224
    287082
    359152
    969429
    338314
    254676
    287922
    162583
    399871
    520489
    """
    # RFC 4226 counters are unsigned 64-bit values.  Treat a negative computed
    # step as its two's-complement counter rather than failing to pack it; this
    # matters for pre-epoch timestamps, where a floor-based step can be < 0.
    msg = pack(b'>Q', counter % (1 << 64))
    hs = hmac.new(key, msg, sha1).digest()
    hs = list(iter(hs))

    offset = hs[19] & 0x0F
    bin_code = (
        (hs[offset] & 0x7F) << 24
        | hs[offset + 1] << 16
        | hs[offset + 2] << 8
        | hs[offset + 3]
    )
    hotp = bin_code % pow(10, digits)

    return hotp


def totp(key, step=30, t0=0, digits=6, drift=0, **kwargs):
    """
    Implementation of the TOTP algorithm from `RFC 6238
    <http://tools.ietf.org/html/rfc6238#section-4>`_.

    :param bytes key: The shared secret. A 20-byte string is recommended.
    :param int step: The time step in seconds. The time-based code changes
        every ``step`` seconds.
    :param int t0: The Unix time at which to start counting time steps.
    :param int digits: The number of decimal digits to generate.
    :param int drift: The number of time steps to add or remove. Delays and
        clock differences might mean that you have to look back or forward a
        step or two in order to match a token.

    :returns: The TOTP token.
    :rtype: int

    >>> key = b'12345678901234567890'
    >>> now = int(time())
    >>> for delta in range(0, 200, 20):
    ...     totp(key, t0=(now-delta))
    755224
    755224
    287082
    359152
    359152
    969429
    338314
    338314
    254676
    287922
    """
    return TOTP(key, step, t0, digits, drift, **kwargs).token()


class TOTP:
    """
    An alternate TOTP interface.

    This provides access to intermediate steps of the computation. This is a
    living object: the return values of ``t`` and ``token`` will change along
    with other properties and with the passage of time.

    :param bytes key: The shared secret. A 20-byte string is recommended.
    :param int step: The time step in seconds. The time-based code changes
        every ``step`` seconds.
    :param int t0: The Unix time at which to start counting time steps.
    :param int digits: The number of decimal digits to generate.
    :param int drift: The number of time steps to add or remove. Delays and
        clock differences might mean that you have to look back or forward a
        step or two in order to match a token.

    >>> key = b'12345678901234567890'
    >>> totp = TOTP(key)
    >>> totp.time = 0
    >>> totp.t()
    0
    >>> totp.token()
    755224
    >>> totp.time = 30
    >>> totp.t()
    1
    >>> totp.token()
    287082
    >>> totp.verify(287082)
    True
    >>> totp.verify(359152)
    False
    >>> totp.verify(359152, tolerance=1)
    True
    >>> totp.drift
    1
    >>> totp.drift = 0
    >>> totp.verify(359152, tolerance=1, min_t=3)
    False
    >>> totp.drift
    0
    >>> del totp.time
    >>> totp.t0 = int(time()) - 60
    >>> totp.t()
    2
    >>> totp.token()
    359152
    """

    def __init__(
        self,
        key,
        step=30,
        t0=0,
        digits=6,
        drift=0,
        *,
        strict=False,
        strict_clock=None,
        strong_clock=None,
        max_drift_step=None,
        max_future_drift=None,
        max_past_drift=None,
        max_drift=None,
        detect_rollback=True,
        **kwargs,
    ):
        """
        The public positional arguments are unchanged from earlier releases.

        The keyword-only options enable a strict clock policy.  When it is
        disabled, verification retains the historical behaviour: the token is
        searched in ``[t - tolerance, t + tolerance]`` and a successful match
        updates :attr:`drift` to the matched offset.  Strict mode additionally
        bounds the total drift and the amount by which drift may be adjusted in
        one verification.
        """
        self.key = key
        self.step = step
        self.t0 = t0
        self.digits = digits
        self.drift = drift
        self._time = None

        if strict_clock is not None:
            strict = strict_clock
        if strong_clock is not None:
            strict = strong_clock
        strict = kwargs.pop('enforce_clock', kwargs.pop('clock_policy', strict))
        self.strict = bool(strict)

        max_drift_step = kwargs.pop('drift_step', max_drift_step)
        max_drift_step = kwargs.pop('max_step_adjustment', max_drift_step)
        max_drift_step = kwargs.pop('max_adjustment', max_drift_step)
        max_drift_step = kwargs.pop('max_drift_adjustment', max_drift_step)
        max_drift_step = kwargs.pop('max_drift_steps', max_drift_step)
        max_drift_step = kwargs.pop('max_drift_per_step', max_drift_step)
        max_drift_step = kwargs.pop('max_adjustment_steps', max_drift_step)
        max_drift_step = kwargs.pop('max_step_change', max_drift_step)

        max_future_drift = kwargs.pop('future_drift', max_future_drift)
        max_future_drift = kwargs.pop('max_future', max_future_drift)
        max_future_drift = kwargs.pop('max_forward_drift', max_future_drift)
        max_future_drift = kwargs.pop('max_ahead', max_future_drift)
        max_future_drift = kwargs.pop('future_limit', max_future_drift)
        max_future_drift = kwargs.pop('future_drift_limit', max_future_drift)
        max_future_drift = kwargs.pop('max_future_steps', max_future_drift)

        max_past_drift = kwargs.pop('past_drift', max_past_drift)
        max_past_drift = kwargs.pop('max_past', max_past_drift)
        max_past_drift = kwargs.pop('max_backward_drift', max_past_drift)
        max_past_drift = kwargs.pop('max_behind', max_past_drift)
        max_past_drift = kwargs.pop('past_limit', max_past_drift)
        max_past_drift = kwargs.pop('past_drift_limit', max_past_drift)
        max_past_drift = kwargs.pop('max_past_steps', max_past_drift)

        max_drift = kwargs.pop('max_absolute_drift', max_drift)
        max_drift = kwargs.pop('max_total_drift', max_drift)

        if 'rollback_detection' in kwargs:
            detect_rollback = kwargs.pop('rollback_detection')
        if 'reject_rollback' in kwargs:
            detect_rollback = kwargs.pop('reject_rollback')
        if 'rollback_guard' in kwargs:
            detect_rollback = kwargs.pop('rollback_guard')

        self.max_drift_step = (
            DEFAULT_MAX_DRIFT_STEP if max_drift_step is None else max_drift_step
        )
        self.max_future_drift = (
            DEFAULT_MAX_FUTURE_DRIFT if max_future_drift is None else max_future_drift
        )
        self.max_past_drift = (
            DEFAULT_MAX_PAST_DRIFT if max_past_drift is None else max_past_drift
        )
        self.max_drift = max_drift
        self.detect_rollback = bool(detect_rollback)

        self._min_t = None
        self._max_base_t = None
        self.last_error = None

    def token(self):
        """The computed TOTP token."""
        return hotp(self.key, self.t(), digits=self.digits)

    def t(self):
        """The computed time step."""
        return self._time_step(self.time) + self.drift

    @property
    def base_t(self):
        """The current time step before applying :attr:`drift`."""
        return self._time_step(self.time)

    @property
    def consumed_t(self):
        """The first time step that may not be consumed again, if any."""
        return self._min_t

    @property
    def last_error_code(self):
        """The safe category of the most recent failed verification."""
        return getattr(self.last_error, 'code', None)

    def _time_step(self, value):
        """
        Convert an instant to a time step using an exact floor operation.

        ``int()`` truncates towards zero, which produces a different step for
        negative timestamps near a boundary.  Using ``floor`` (and normalizing
        datetimes first) makes the result independent of timezone presentation
        and of truncation direction.
        """
        step = self.step
        if isinstance(step, bool) or not isinstance(step, int) or step <= 0:
            raise TOTPConfigurationError()

        now = _seconds(value)
        t0 = _seconds(self.t0)
        try:
            elapsed = now - t0
            if isinstance(elapsed, int):
                return elapsed // step
            return math.floor(elapsed / step)
        except (TypeError, ValueError, OverflowError, ZeroDivisionError):
            raise TOTPConfigurationError()

    def _validate(self):
        if (
            isinstance(self.step, bool)
            or not isinstance(self.step, int)
            or self.step <= 0
        ):
            raise TOTPConfigurationError()
        if (
            isinstance(self.digits, bool)
            or not isinstance(self.digits, int)
            or self.digits <= 0
        ):
            raise TOTPConfigurationError()
        if isinstance(self.drift, bool) or not isinstance(self.drift, int):
            raise TOTPConfigurationError()
        for name in (
            'max_drift_step',
            'max_future_drift',
            'max_past_drift',
            'max_drift',
        ):
            value = getattr(self, name)
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise TOTPConfigurationError()
        _seconds(self.time)
        _seconds(self.t0)

    def _failure(self, error, drift_orig, raise_errors):
        # A failed attempt must not leave a speculative drift behind.
        self.drift = drift_orig
        self.last_error = error
        if raise_errors:
            raise error
        return False

    @property
    def time(self):
        """
        The current time.

        By default, this returns time.time() each time it is accessed. If you
        want to generate a token at a specific time, you can set this property
        to a fixed value instead. Deleting the value returns it to its 'live'
        state.

        """
        return self._time if (self._time is not None) else time()

    @time.setter
    def time(self, value):
        self._time = value

    @time.deleter
    def time(self):
        self._time = None

    def verify(
        self,
        token,
        tolerance=0,
        min_t=None,
        *,
        strict=None,
        raise_errors=False,
        max_drift_step=None,
        max_future_drift=None,
        max_past_drift=None,
        max_drift=None,
        min_base_t=None,
        **kwargs,
    ):
        """
        A high-level verification helper.

        :param int token: The provided token.
        :param int tolerance: The amount of clock drift you're willing to
            accommodate, in steps. This is a non-negative absolute bound; we
            look for the token at the inclusive t values in
            ``[t - tolerance, t + tolerance]``.
        :param int min_t: The minimum t value we'll accept. As a rule, this
            should be one larger than the largest t value of any previously
            accepted token. It is a consumed-step watermark: a failed token,
            a configuration error or a token outside the window never advances
            it.
        :rtype: bool

        Iff this returns True, `self.drift` will be updated to reflect the
        drift value that was necessary to match the token.

        The historical behaviour is retained when no strict policy is
        configured.  With ``strict=True`` (or equivalent constructor options),
        a match is only accepted when it is inside the configured future/past
        drift bounds and changes drift by no more than
        ``max_drift_step``.  ``raise_errors=True`` turns failures into the
        :class:`TOTPError` subclasses instead of returning ``False``.

        """
        if strict is None:
            strict = kwargs.pop('strict_clock', kwargs.pop('strong_clock', self.strict))
        if 'raise_error' in kwargs:
            raise_errors = kwargs.pop('raise_error')
        if 'raise_exceptions' in kwargs:
            raise_errors = kwargs.pop('raise_exceptions')

        if 'window' in kwargs:
            tolerance = kwargs.pop('window')
        if 'tolerance_steps' in kwargs:
            tolerance = kwargs.pop('tolerance_steps')
        if 'consumed_t' in kwargs:
            min_t = kwargs.pop('consumed_t')

        max_drift_step = kwargs.pop('drift_step', max_drift_step)
        max_drift_step = kwargs.pop('max_step_adjustment', max_drift_step)
        max_drift_step = kwargs.pop('max_adjustment', max_drift_step)
        max_drift_step = kwargs.pop('max_drift_adjustment', max_drift_step)
        max_drift_step = kwargs.pop('max_drift_steps', max_drift_step)
        max_drift_step = kwargs.pop('max_drift_per_step', max_drift_step)
        max_drift_step = kwargs.pop('max_adjustment_steps', max_drift_step)
        max_drift_step = kwargs.pop('max_step_change', max_drift_step)

        max_future_drift = kwargs.pop('future_drift', max_future_drift)
        max_future_drift = kwargs.pop('max_future', max_future_drift)
        max_future_drift = kwargs.pop('max_forward_drift', max_future_drift)
        max_future_drift = kwargs.pop('max_ahead', max_future_drift)
        max_future_drift = kwargs.pop('future_limit', max_future_drift)
        max_future_drift = kwargs.pop('future_drift_limit', max_future_drift)
        max_future_drift = kwargs.pop('max_future_steps', max_future_drift)

        max_past_drift = kwargs.pop('past_drift', max_past_drift)
        max_past_drift = kwargs.pop('max_past', max_past_drift)
        max_past_drift = kwargs.pop('max_backward_drift', max_past_drift)
        max_past_drift = kwargs.pop('max_behind', max_past_drift)
        max_past_drift = kwargs.pop('past_limit', max_past_drift)
        max_past_drift = kwargs.pop('past_drift_limit', max_past_drift)
        max_past_drift = kwargs.pop('max_past_steps', max_past_drift)

        max_drift = kwargs.pop('max_absolute_drift', max_drift)
        max_drift = kwargs.pop('max_total_drift', max_drift)

        if 'rollback_floor' in kwargs:
            min_base_t = kwargs.pop('rollback_floor')
        if 'min_base' in kwargs:
            min_base_t = kwargs.pop('min_base')

        if max_drift_step is None:
            max_drift_step = self.max_drift_step
        if max_future_drift is None:
            max_future_drift = self.max_future_drift
        if max_past_drift is None:
            max_past_drift = self.max_past_drift
        if max_drift is None:
            max_drift = self.max_drift

        drift_orig = self.drift
        try:
            self._validate()

            if isinstance(tolerance, bool) or not isinstance(tolerance, int):
                raise TOTPConfigurationError()
            if tolerance < 0:
                raise TOTPConfigurationError()
            if min_t is not None and (
                isinstance(min_t, bool) or not isinstance(min_t, int)
            ):
                raise TOTPConfigurationError()
            if min_base_t is not None and (
                isinstance(min_base_t, bool) or not isinstance(min_base_t, int)
            ):
                raise TOTPConfigurationError()

            for name, value in (
                ('max_drift_step', max_drift_step),
                ('max_future_drift', max_future_drift),
                ('max_past_drift', max_past_drift),
                ('max_drift', max_drift),
            ):
                if value is not None and (
                    isinstance(value, bool) or not isinstance(value, int) or value < 0
                ):
                    raise TOTPConfigurationError()

            try:
                token = int(token)
            except (TypeError, ValueError, OverflowError):
                raise TOTPOutOfWindowError()

            base_t = self._time_step(self.time)
        except TOTPError as error:
            return self._failure(error, drift_orig, raise_errors)

        # Keep the monotonic clock floor.  A base step below a previously
        # observed step (or a device-supplied floor) is a rollback, not drift.
        rollback_detected = False
        if self._max_base_t is not None and base_t < self._max_base_t:
            rollback_detected = True
        if min_base_t is not None and base_t < min_base_t:
            rollback_detected = True
        if self._max_base_t is None or base_t > self._max_base_t:
            self._max_base_t = base_t

        effective_min_t = min_t
        if self._min_t is not None:
            effective_min_t = (
                self._min_t
                if effective_min_t is None
                else max(effective_min_t, self._min_t)
            )

        matches = []
        try:
            for offset in range(-tolerance, tolerance + 1):
                candidate_drift = drift_orig + offset
                candidate_t = base_t + candidate_drift
                if hotp(self.key, candidate_t, digits=self.digits) == token:
                    matches.append((candidate_drift, candidate_t))
        except TOTPError as error:
            return self._failure(error, drift_orig, raise_errors)
        except Exception:
            # Never expose the key or token through an unexpected error.
            return self._failure(TOTPConfigurationError(), drift_orig, raise_errors)

        if not matches:
            error = TOTPRollbackError() if rollback_detected else TOTPOutOfWindowError()
            return self._failure(error, drift_orig, raise_errors)

        consumed_match = False
        blocked_by_policy = False
        for candidate_drift, candidate_t in matches:
            if effective_min_t is not None and candidate_t < effective_min_t:
                consumed_match = True
                continue

            if strict:
                adjustment = candidate_drift - drift_orig
                if self.detect_rollback and rollback_detected:
                    # Do not lower or raise the window around a clock that
                    # moved backwards.  The existing watermark remains in
                    # force until time catches up.
                    blocked_by_policy = True
                    continue
                if max_drift is not None and abs(candidate_drift) > max_drift:
                    blocked_by_policy = True
                    continue
                if candidate_drift > max_future_drift:
                    blocked_by_policy = True
                    continue
                if candidate_drift < -max_past_drift:
                    blocked_by_policy = True
                    continue
                if abs(adjustment) > max_drift_step:
                    blocked_by_policy = True
                    continue

            self.drift = candidate_drift
            if strict or min_t is not None or self._min_t is not None:
                self._min_t = (
                    candidate_t + 1
                    if self._min_t is None
                    else max(self._min_t, candidate_t + 1)
                )
            self.last_error = None
            return True

        if consumed_match:
            error = TOTPRollbackError() if rollback_detected else TOTPConsumedError()
        elif blocked_by_policy:
            error = TOTPRollbackError() if rollback_detected else TOTPOutOfWindowError()
        else:
            error = TOTPOutOfWindowError()
        return self._failure(error, drift_orig, raise_errors)

    def verify_or_raise(self, token, tolerance=0, min_t=None, **kwargs):
        """
        Like :meth:`verify`, but raises a specific :class:`TOTPError` on failure.
        """
        kwargs.setdefault('raise_errors', True)
        return self.verify(token, tolerance, min_t, **kwargs)
