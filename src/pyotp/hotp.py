import hashlib
import json
import threading
from collections.abc import Mapping as MappingABC
from typing import Any, Dict, Mapping, Optional

from . import utils
from .otp import OTP


class HOTPState:
    """
    Persistable anti-replay state for :class:`HOTP` verification.

    The state records the highest counter for which an OTP was successfully
    verified. It also owns a reentrant lock so that the check-and-update of
    that counter is atomic when the same state object is shared by multiple
    threads.

    Use :meth:`to_dict`/:meth:`from_dict` or :meth:`to_json`/:meth:`from_json`
    to persist the state between verification requests.
    """

    def __init__(self, last_counter: int = -1) -> None:
        """
        :param last_counter: the last successfully verified counter, or -1 if
            no OTP has been verified yet
        """
        self._lock = threading.RLock()
        self._last_counter = self._validate_last_counter(last_counter)

    @staticmethod
    def _validate_last_counter(value: int) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("last_counter must be an integer")
        if value < -1:
            raise ValueError("last_counter must be greater than or equal to -1")
        return value

    @property
    def last_counter(self) -> int:
        """The last successfully verified counter."""
        with self._lock:
            return self._last_counter

    @last_counter.setter
    def last_counter(self, value: int) -> None:
        value = self._validate_last_counter(value)
        with self._lock:
            self._last_counter = value

    @property
    def last_verified_counter(self) -> int:
        """Alias for :attr:`last_counter`."""
        return self.last_counter

    @last_verified_counter.setter
    def last_verified_counter(self, value: int) -> None:
        self.last_counter = value

    @property
    def counter(self) -> int:
        """Alias for :attr:`last_counter`."""
        return self.last_counter

    @counter.setter
    def counter(self, value: int) -> None:
        self.last_counter = value

    def to_dict(self) -> Dict[str, int]:
        """Serialize the state to a JSON-compatible dictionary."""
        return {"last_counter": self.last_counter}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "HOTPState":
        """
        Restore state from a dictionary produced by :meth:`to_dict`.

        ``last_verified_counter`` and ``counter`` are also accepted as keys for
        compatibility with state persisted by other implementations.
        """
        if not isinstance(data, MappingABC):
            raise TypeError("state data must be a mapping")
        for key in ("last_counter", "last_verified_counter", "counter"):
            if key in data:
                return cls(data[key])
        raise KeyError("state data must contain last_counter")

    def to_json(self) -> str:
        """Serialize the state to JSON."""
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_json(cls, data: str) -> "HOTPState":
        """Restore state from JSON produced by :meth:`to_json`."""
        return cls.from_dict(json.loads(data))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, HOTPState):
            return NotImplemented
        return self.last_counter == other.last_counter

    def __repr__(self) -> str:
        return "{}(last_counter={!r})".format(type(self).__name__, self.last_counter)

    def __getstate__(self) -> Dict[str, int]:
        return self.to_dict()

    def __setstate__(self, state: Mapping[str, Any]) -> None:
        self._lock = threading.RLock()
        restored = HOTPState.from_dict(state)
        self._last_counter = restored._last_counter


HOTPVerificationState = HOTPState


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
        look_ahead: int = 0,
        state: Optional[HOTPState] = None,
    ) -> None:
        """
        :param s: secret in base32 format
        :param initial_count: starting HMAC counter value, defaults to 0
        :param digits: number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
        :param digest: digest function to use in the HMAC (expected to be SHA1)
        :param name: account name
        :param issuer: issuer
        :param look_ahead: number of counters ahead of the supplied counter to
            check during stateful verification. Defaults to 0 (exact match).
        :param state: optional :class:`HOTPState` used for stateful
            verification. If omitted, an internal state is created and used
            only when ``look_ahead`` is nonzero or state is passed to
            :meth:`verify`.
        """
        if digest is None:
            digest = hashlib.sha1
        elif digest in [hashlib.md5, hashlib.shake_128]:
            raise ValueError("selected digest function must generate digest size greater than or equals to 18 bytes")

        if isinstance(look_ahead, bool) or not isinstance(look_ahead, int):
            raise TypeError("look_ahead must be an integer")
        if look_ahead < 0:
            raise ValueError("look_ahead must be greater than or equal to 0")
        if state is not None and not isinstance(state, HOTPState):
            if isinstance(state, MappingABC):
                state = HOTPState.from_dict(state)
            else:
                raise TypeError("state must be a HOTPState instance")

        self.initial_count = initial_count
        self.look_ahead = look_ahead
        self.state = state if state is not None else HOTPState()
        self._stateful = state is not None or look_ahead != 0
        super().__init__(s=s, digits=digits, digest=digest, name=name, issuer=issuer)

    def at(self, count: int) -> str:
        """
        Generates the OTP for the given count.

        :param count: the OTP HMAC counter
        :returns: OTP
        """
        return self.generate_otp(self.initial_count + count)

    def verify(
        self,
        otp: str,
        counter: Optional[int] = None,
        look_ahead: Optional[int] = None,
        state: Optional[HOTPState] = None,
    ) -> bool:
        """
        Verifies the OTP passed in against the current counter OTP.

        With no ``look_ahead`` and no ``state`` (and no stateful configuration
        on the instance), this retains the original exact-counter, stateless
        behavior. When a look-ahead window or state is supplied, verification
        is stateful: counters are checked from ``counter`` through
        ``counter + look_ahead`` (inclusive), counters less than or equal to
        the last successful counter are ignored, and the matched counter is
        recorded atomically.

        :param otp: the OTP to check against
        :param counter: the expected OTP HMAC counter. If omitted in stateful
            mode, verification starts at the last successful counter plus one.
        :param look_ahead: number of counter values ahead of ``counter`` to
            accept. Defaults to the instance's configured value.
        :param state: state object to use for anti-replay tracking. Defaults to
            the instance's state.
        :returns: True if verification succeeded, False otherwise
        """
        if look_ahead is None and state is None and not self._stateful:
            if counter is None:
                raise TypeError("counter is required for stateless verification")
            return utils.strings_equal(str(otp), str(self.at(counter)))
        return self.verify_resync(otp, counter, look_ahead=look_ahead, state=state)

    def verify_resync(
        self,
        otp: str,
        counter: Optional[int] = None,
        look_ahead: Optional[int] = None,
        state: Optional[HOTPState] = None,
    ) -> bool:
        """
        Verify an OTP while tolerating counter drift and preventing replay.

        The window is checked forward from ``counter`` (inclusive). Within the
        window only counters greater than the state's last successful counter
        are eligible. The comparison and state update happen while holding the
        state's lock, so concurrent verifications cannot both consume the same
        OTP.

        :param otp: the OTP to check against
        :param counter: the expected OTP HMAC counter. Defaults to the last
            successful counter plus one.
        :param look_ahead: number of counter values ahead of ``counter`` to
            accept. Defaults to the instance's configured value.
        :param state: state object to use for anti-replay tracking. Defaults to
            the instance's state.
        :returns: True if verification succeeded, False otherwise
        """
        target_state = self.state if state is None else state
        if not isinstance(target_state, HOTPState):
            raise TypeError("state must be a HOTPState instance")

        target_look_ahead = self.look_ahead if look_ahead is None else look_ahead
        if isinstance(target_look_ahead, bool) or not isinstance(target_look_ahead, int):
            raise TypeError("look_ahead must be an integer")
        if target_look_ahead < 0:
            raise ValueError("look_ahead must be greater than or equal to 0")

        if counter is not None:
            if isinstance(counter, bool) or not isinstance(counter, int):
                raise TypeError("counter must be an integer")
            if counter < 0:
                raise ValueError("counter must be greater than or equal to 0")

        with target_state._lock:
            if counter is None:
                counter = target_state._last_counter + 1

            first_counter = max(counter, target_state._last_counter + 1)
            last_counter = counter + target_look_ahead
            for candidate in range(first_counter, last_counter + 1):
                if utils.strings_equal(str(otp), str(self.at(candidate))):
                    target_state._last_counter = candidate
                    return True
        return False

    def verify_with_resync(
        self,
        otp: str,
        counter: Optional[int] = None,
        look_ahead: Optional[int] = None,
        state: Optional[HOTPState] = None,
    ) -> bool:
        """Alias for :meth:`verify_resync`."""
        return self.verify_resync(otp, counter, look_ahead=look_ahead, state=state)

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
