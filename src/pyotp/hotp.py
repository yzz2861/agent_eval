import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional

from . import utils
from .otp import OTP

#: RFC 4226 feeds an 8-byte (unsigned 64-bit) counter into the HMAC, so this
#: is the largest counter value for which an OTP can be generated.
MAX_COUNTER = (1 << 64) - 1

#: Upper bound accepted for a resync window. The scan is a sequential HMAC
#: computation per candidate, so unbounded windows would be a denial-of-service
#: vector. Callers needing a larger policy must implement it explicitly.
MAX_RESYNC_WINDOW = 100_000


class ResyncStatus(Enum):
    """
    Outcome of an :meth:`HOTP.resync` call.

    Failure members intentionally carry no information about the server-side
    counter; surfacing such details (e.g. in error messages) would let an
    attacker probe the current counter value.
    """

    #: The token matched a counter inside the window and the consume callback
    #: committed the new counter.
    MATCH = "match"

    #: No counter inside the window produced the submitted token. The caller
    #: must keep its stored counter unchanged.
    NOT_FOUND = "not_found"

    #: The token matched, but the caller's consume callback reported that the
    #: counter moved concurrently (a lost CAS race). The token was not
    #: accepted a second time.
    ALREADY_CONSUMED = "already_consumed"

    #: The submitted token is empty, non-numeric, or has the wrong length.
    INVALID_TOKEN = "invalid_token"

    #: One of the scalar arguments (counter, window, callback) is malformed.
    INVALID_ARGUMENT = "invalid_argument"

    #: The committed counter is already at or beyond the 64-bit counter space.
    OVERFLOW = "overflow"


@dataclass(frozen=True)
class ResyncResult:
    """
    Result of an :meth:`HOTP.resync` call.

    Counter-bearing fields are populated only on :attr:`ResyncStatus.MATCH`
    so that failure handling paths cannot accidentally leak the server-side
    counter. The library never persists the counter itself; ``next_count`` is
    merely the value it recommends the caller commit via its own storage.
    """

    status: ResyncStatus
    #: Counter value whose OTP matched the token, relative to ``initial_count``.
    matched_count: Optional[int] = None
    #: Recommended new committed counter (``matched_count + 1``).
    next_count: Optional[int] = None
    #: Number of candidate counters actually compared, in scan order.
    candidates_checked: Optional[int] = None

    @property
    def success(self) -> bool:
        return self.status is ResyncStatus.MATCH


class HOTP(OTP):
    """
    Handler for HMAC-based OTP counters.
    """

    def __init__(
        self,
        s: str,
        digits: int = 6,
        digest: Any = None,
        name: Optional[str] = None,
        issuer: Optional[str] = None,
        initial_count: int = 0,
    ) -> None:
        """
        :param s: secret in base32 format
        :param initial_count: starting HMAC counter value, defaults to 0
        :param digits: number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
        :param digest: digest function to use in the HMAC (expected to be SHA1)
        :param name: account name
        :param issuer: issuer
        """
        if digest is None:
            digest = hashlib.sha1
        elif digest in [hashlib.md5, hashlib.shake_128]:
            raise ValueError("selected digest function must generate digest size greater than or equals to 18 bytes")

        self.initial_count = initial_count
        super().__init__(s=s, digits=digits, digest=digest, name=name, issuer=issuer)

    def at(self, count: int) -> str:
        """
        Generates the OTP for the given count.

        :param count: the OTP HMAC counter
        :returns: OTP
        """
        return self.generate_otp(self.initial_count + count)

    def verify(self, otp: str, counter: int) -> bool:
        """
        Verifies the OTP passed in against the current counter OTP.

        :param otp: the OTP to check against
        :param counter: the OTP HMAC counter
        """
        return utils.strings_equal(str(otp), str(self.at(counter)))

    def resync(
        self,
        otp: str,
        current_count: int,
        max_window: int,
        consume: Callable[[int, int], bool],
    ) -> ResyncResult:
        """
        Resynchronizes a drifted HOTP token against a bounded counter window.

        Counters are compared in a fixed, deterministic order (the committed
        counter first, then each successive counter up to ``max_window``
        steps ahead) until a candidate matches or the window is exhausted.
        The scan is iterative and bounded by :data:`MAX_RESYNC_WINDOW`; it
        never materializes a large ``range`` and never logs candidate codes.

        This method does not persist anything. When a candidate matches, the
        caller-supplied ``consume`` callback is invoked exactly once with the
        previously committed counter and the recommended new counter
        (``matched_count + 1``). The callback is expected to perform an
        atomic compare-and-swap: return ``True`` when it commits the new
        counter and ``False`` when the stored counter no longer equals the
        previously committed counter (a concurrent request won the race).
        Exceptions raised by the callback are propagated to the caller.

        :param otp: the token submitted by the user
        :param current_count: the counter currently committed by the caller,
            relative to ``initial_count`` (same convention as :meth:`verify`)
        :param max_window: maximum number of forward steps to scan; ``0``
            restricts the check to ``current_count`` only
        :param consume: one-time consumption callback
            ``consume(committed_count, new_count) -> bool``
        :returns: a :class:`ResyncResult`; on success it carries the matched
            counter and the recommended counter to commit, on failure only a
            status that reveals nothing about the stored counter
        """
        if not isinstance(otp, str) or len(otp) != self.digits or not all("0" <= char <= "9" for char in otp):
            return ResyncResult(ResyncStatus.INVALID_TOKEN)

        if not callable(consume):
            return ResyncResult(ResyncStatus.INVALID_ARGUMENT)

        if isinstance(current_count, bool) or not isinstance(current_count, int) or current_count < 0:
            return ResyncResult(ResyncStatus.INVALID_ARGUMENT)

        if (
            isinstance(max_window, bool)
            or not isinstance(max_window, int)
            or max_window < 0
            or max_window > MAX_RESYNC_WINDOW
        ):
            return ResyncResult(ResyncStatus.INVALID_ARGUMENT)

        if current_count > MAX_COUNTER:
            return ResyncResult(ResyncStatus.OVERFLOW)

        last_candidate = min(current_count + max_window, MAX_COUNTER)
        candidate = current_count
        while candidate <= last_candidate:
            if utils.strings_equal(otp, self.at(candidate)):
                next_count = candidate + 1
                if consume(current_count, next_count):
                    return ResyncResult(
                        ResyncStatus.MATCH,
                        matched_count=candidate,
                        next_count=next_count,
                        candidates_checked=candidate - current_count + 1,
                    )
                return ResyncResult(ResyncStatus.ALREADY_CONSUMED)
            candidate += 1

        return ResyncResult(
            ResyncStatus.NOT_FOUND,
            candidates_checked=last_candidate - current_count + 1,
        )

    def provisioning_uri(
        self,
        name: Optional[str] = None,
        initial_count: Optional[int] = None,
        issuer_name: Optional[str] = None,
        **kwargs,
    ) -> str:
        """
        Returns the provisioning URI for the OTP.  This can then be
        encoded in a QR Code and used to provision an OTP app like
        Google Authenticator.

        See also:
            https://github.com/google/google-authenticator/wiki/Key-Uri-Format

        :param name: name of the user account
        :param initial_count: starting HMAC counter value, defaults to 0
        :param issuer_name: the name of the OTP issuer; this will be the
            organization title of the OTP entry in Authenticator
        :returns: provisioning URI
        """
        return utils.build_uri(
            self.secret,
            name=name if name else self.name,
            initial_count=initial_count if initial_count is not None else self.initial_count,
            issuer=issuer_name if issuer_name else self.issuer,
            algorithm=self.digest().name,
            digits=self.digits,
            **kwargs,
        )
