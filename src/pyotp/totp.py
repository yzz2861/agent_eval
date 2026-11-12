import calendar
import datetime
import hashlib
import time
from enum import Enum
from typing import Any, Literal, Optional, Union

from . import utils
from .otp import OTP


class TimePolicy(str, Enum):
    """
    Strategy used to interpret time inputs that do not carry their own UTC
    offset (naive datetimes and numeric timestamps).

    ``LOCAL`` (the default) keeps the historical behavior: naive datetimes are
    interpreted in the process local timezone via ``time.mktime()`` and numeric
    timestamps are converted with ``datetime.fromtimestamp()``. Results depend
    on the machine timezone and, for daylight-saving-time gaps and repeated
    times, on the platform C library.

    ``UTC`` is the strict, timezone-independent policy. Naive datetimes are
    rejected unless a timezone is declared (via the ``default_tz`` argument of
    :class:`TOTP` or the ``tzinfo`` argument of the individual call), aware
    datetimes are always converted to UTC, and numeric timestamps are treated
    directly as UTC epoch seconds without any local-time conversion.
    """

    LOCAL = "local"
    UTC = "utc"

    @staticmethod
    def coerce(time_policy: Union["TimePolicy", str]) -> "TimePolicy":
        if isinstance(time_policy, TimePolicy):
            return time_policy
        if isinstance(time_policy, str):
            try:
                return TimePolicy(time_policy)
            except ValueError:
                pass
        raise ValueError("time_policy must be TimePolicy.LOCAL or TimePolicy.UTC (or the strings 'local' / 'utc')")


class TOTP(OTP):
    """
    Handler for time-based OTP counters.
    """

    def __init__(
        self,
        s: str,
        digits: int = 6,
        digest: Any = None,
        name: Optional[str] = None,
        issuer: Optional[str] = None,
        interval: int = 30,
        time_policy: Union[TimePolicy, str] = TimePolicy.LOCAL,
        default_tz: Optional[datetime.tzinfo] = None,
    ) -> None:
        """
        :param s: secret in base32 format
        :param digits: number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
        :param digest: digest function to use in the HMAC (expected to be SHA1)
        :param name: account name
        :param issuer: issuer
        :param interval: the time interval in seconds for OTP. This defaults to 30.
        :param time_policy: how times without a UTC offset are interpreted.
            ``TimePolicy.LOCAL`` (default) preserves the legacy local-time
            behavior; ``TimePolicy.UTC`` enforces strict UTC handling, in
            which naive datetimes are rejected unless ``default_tz`` or a
            per-call ``tzinfo`` declares their timezone.
        :param default_tz: optional timezone applied to naive datetime inputs
            in strict UTC mode (and available in every mode). When set, naive
            datetimes are interpreted in this timezone instead of being
            rejected or mapped through the machine local timezone.
        """
        if digest is None:
            digest = hashlib.sha1
        elif digest in [hashlib.md5, hashlib.shake_128]:
            raise ValueError("selected digest function must generate digest size greater than or equals to 18 bytes")

        self.interval = interval
        self.time_policy = TimePolicy.coerce(time_policy)
        if default_tz is not None and not isinstance(default_tz, datetime.tzinfo):
            raise TypeError("default_tz must be a datetime.tzinfo instance")
        self.default_tz = default_tz
        super().__init__(s=s, digits=digits, digest=digest, name=name, issuer=issuer)

    def at(
        self,
        for_time: Union[int, float, datetime.datetime],
        counter_offset: int = 0,
        tzinfo: Optional[datetime.tzinfo] = None,
    ) -> str:
        """
        Accepts a Unix timestamp or a datetime object and returns the OTP for
        its timecode.

        Time interpretation:

        * Integer inputs are Unix timestamps in whole seconds. Float inputs are
          timestamps in seconds truncated toward zero (the fractional second is
          dropped). Millisecond or nanosecond timestamps must be scaled by the
          caller; out-of-range numeric values raise ``ValueError``.
        * Aware datetimes are always converted to UTC.
        * Naive datetimes follow the configured :class:`TimePolicy`: in
          ``LOCAL`` mode (default) they are interpreted in the machine local
          timezone; in ``UTC`` mode they are rejected unless ``tzinfo`` or the
          instance ``default_tz`` declares the timezone to assume.
        * In strict UTC mode, daylight-saving-time gaps and repeated local
          times are resolved deterministically via the standard library
          timezone database; the datetime ``fold`` flag selects which side of a
          repeated time (or how a nonexistent time) is resolved.

        To get the time until the next timecode change (seconds until the current OTP expires), use this instead:

        .. code:: python

            totp = pyotp.TOTP(...)
            time_remaining = totp.interval - datetime.datetime.now().timestamp() % totp.interval

        :param for_time: the time to generate an OTP for
        :param counter_offset: the amount of ticks to add to the time counter
        :param tzinfo: timezone to assume when ``for_time`` is a naive
            datetime; takes precedence over the instance ``default_tz``
        :returns: OTP value
        """
        return self.generate_otp(self.timecode(for_time, tzinfo) + counter_offset)

    def now(self) -> str:
        """
        Generate the current time OTP. The current instant is read as an
        aware UTC datetime, so the result is independent of the process
        timezone and of the configured :class:`TimePolicy`.

        :returns: OTP value
        """
        return self.generate_otp(self.timecode(datetime.datetime.now(tz=datetime.timezone.utc)))

    def verify(
        self,
        otp: str,
        for_time: Optional[Union[int, float, datetime.datetime]] = None,
        valid_window: int = 0,
        tzinfo: Optional[datetime.tzinfo] = None,
    ) -> bool:
        """
        Verifies the OTP passed in against the current time OTP.

        :param otp: the OTP to check against
        :param for_time: Time to check OTP at (defaults to now); accepts a
            datetime or a numeric Unix timestamp, interpreted with the same
            rules as :meth:`at`
        :param valid_window: extends the validity to this many counter ticks
            before and after the current one; the same base timecode is used
            for generation and verification, so local timezone offsets cannot
            add or remove an interval from the window
        :param tzinfo: timezone to assume for a naive ``for_time`` datetime
        :returns: True if verification succeeded, False otherwise
        """
        if valid_window < 0:
            raise ValueError("valid_window cannot be negative")

        if for_time is None:
            for_time = datetime.datetime.now(tz=datetime.timezone.utc)

        base_timecode = self.timecode(for_time, tzinfo)
        for i in range(-valid_window, valid_window + 1):
            if utils.strings_equal(str(otp), str(self.generate_otp(base_timecode + i))):
                return True
        return False

    def verify_and_get_timecode(
        self,
        otp: str,
        for_time: Optional[Union[int, float, datetime.datetime]] = None,
        valid_window: int = 0,
        tzinfo: Optional[datetime.tzinfo] = None,
    ) -> int | Literal[False]:
        """
        Verifies the OTP passed in against the current time OTP and returns the matching timecode.

        This is useful when callers need to prevent TOTP reuse. An
        application can store the timecode from the last successful
        authentication and reject future OTPs whose matching timecode
        is not greater than the stored one.

        :param otp: the OTP to check against
        :param for_time: Time to check OTP at (defaults to now); accepts a
            datetime or a numeric Unix timestamp, interpreted with the same
            rules as :meth:`at`
        :param valid_window: extends the validity to this many counter ticks
            before and after the current one
        :param tzinfo: timezone to assume for a naive ``for_time`` datetime
        :returns: matching timecode if verification succeeded, False otherwise
        """
        if valid_window < 0:
            raise ValueError("valid_window cannot be negative")

        if for_time is None:
            for_time = datetime.datetime.now(tz=datetime.timezone.utc)

        base_timecode = self.timecode(for_time, tzinfo)

        for i in range(-valid_window, valid_window + 1):
            if utils.strings_equal(str(otp), str(self.generate_otp(base_timecode + i))):
                return base_timecode + i
        return False

    def provisioning_uri(self, name: Optional[str] = None, issuer_name: Optional[str] = None, **kwargs) -> str:
        """
        Returns the provisioning URI for the OTP.  This can then be
        encoded in a QR Code and used to provision an OTP app like
        Google Authenticator.

        See also:
            https://github.com/google/google-authenticator/wiki/Key-Uri-Format

        """
        return utils.build_uri(
            self.secret,
            name if name else self.name,
            issuer=issuer_name if issuer_name else self.issuer,
            algorithm=self.digest().name,
            digits=self.digits,
            period=self.interval,
            **kwargs,
        )

    def timecode(self, for_time: Union[int, float, datetime.datetime], tzinfo: Optional[datetime.tzinfo] = None) -> int:
        """
        Returns the counter value (timecode) for the given time.

        Aware datetimes are converted to UTC. Naive datetimes and numeric
        timestamps follow the configured :class:`TimePolicy`; see :meth:`at`
        for the full interpretation rules.
        """
        epoch_seconds = self._to_epoch_seconds(for_time, tzinfo)
        return int(epoch_seconds / self.interval)

    def _resolve_tz(self, tzinfo: Optional[datetime.tzinfo]) -> Optional[datetime.tzinfo]:
        if tzinfo is not None:
            if not isinstance(tzinfo, datetime.tzinfo):
                raise TypeError("tzinfo must be a datetime.tzinfo instance")
            return tzinfo
        return self.default_tz

    def _to_epoch_seconds(
        self, for_time: Union[int, float, datetime.datetime], tzinfo: Optional[datetime.tzinfo]
    ) -> int:
        if isinstance(for_time, bool):
            raise TypeError(
                "for_time must be a datetime.datetime, an integer epoch-second timestamp, or a float epoch-second timestamp"
            )
        if isinstance(for_time, (int, float)):
            truncated_seconds = utils.normalize_timestamp(for_time)
            if self.time_policy is TimePolicy.UTC:
                return truncated_seconds
            # Legacy behavior: numeric timestamps are truncated to whole
            # seconds first and then mapped through the machine local timezone.
            local_datetime = datetime.datetime.fromtimestamp(truncated_seconds)
            return int(time.mktime(local_datetime.timetuple()))

        if not isinstance(for_time, datetime.datetime):
            raise TypeError(
                "for_time must be a datetime.datetime, an integer epoch-second timestamp, or a float epoch-second timestamp"
            )

        if for_time.tzinfo is not None:
            utc_datetime = for_time.astimezone(datetime.timezone.utc)
            return int(calendar.timegm(utc_datetime.utctimetuple()))

        assumed_tz = self._resolve_tz(tzinfo)
        if assumed_tz is not None:
            utc_datetime = for_time.replace(tzinfo=assumed_tz).astimezone(datetime.timezone.utc)
            return int(calendar.timegm(utc_datetime.utctimetuple()))

        if self.time_policy is TimePolicy.UTC:
            raise ValueError(
                "naive datetime cannot be interpreted in strict UTC mode: pass an aware datetime, declare its "
                "timezone via the tzinfo argument or the TOTP default_tz, or use TimePolicy.LOCAL"
            )

        # Legacy behavior: naive datetimes are interpreted in the machine local timezone.
        return int(time.mktime(for_time.timetuple()))
