from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import threading
import time
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, MutableMapping, Protocol

from ..ctap import CtapError


class PinUvState(IntEnum):
    """State of the PIN/UV verification flow.

    The values are intentionally stable: they may be persisted and compared
    across process restarts.
    """

    READY = 0
    PIN_INVALID = 1
    PIN_BLOCKED = 2
    UV_REQUIRED = 3
    UV_BLOCKED = 4
    UNSUPPORTED = 5
    PIN_REQUIRED = 6
    UV_INVALID = 7

    # Common aliases. These intentionally share values with the canonical
    # states above.
    OK = READY
    PIN_ERROR = PIN_INVALID
    PIN_LOCKED = PIN_BLOCKED
    UV_NEEDED = UV_REQUIRED
    UV_LOCKED = UV_BLOCKED
    PROTOCOL_UNSUPPORTED = UNSUPPORTED

    @classmethod
    def from_code(cls, code: int | CtapError.ERR | None) -> PinUvState | None:
        """Map a CTAP status code to a PIN/UV state.

        UV_INVALID deliberately maps to UV_INVALID rather than PIN_INVALID.
        Callers that know whether the failed operation was a PIN or UV
        operation must pass that context to the state machine, as some
        authenticators incorrectly use PIN_INVALID for a failed UV check.
        """
        if code is None:
            return None
        try:
            err = CtapError.ERR(int(code))
        except ValueError:
            return None
        if err in (CtapError.ERR.PIN_INVALID, CtapError.ERR.PIN_AUTH_INVALID):
            return cls.PIN_INVALID
        if err in (CtapError.ERR.PIN_BLOCKED, CtapError.ERR.PIN_AUTH_BLOCKED):
            return cls.PIN_BLOCKED
        if err == CtapError.ERR.UV_INVALID:
            return cls.UV_REQUIRED
        if err == CtapError.ERR.UV_BLOCKED:
            return cls.UV_BLOCKED
        if err in (CtapError.ERR.PUAT_REQUIRED, CtapError.ERR.PIN_NOT_SET):
            return cls.PIN_REQUIRED
        if err in (
            CtapError.ERR.INVALID_COMMAND,
            CtapError.ERR.INVALID_SUBCOMMAND,
            CtapError.ERR.UNSUPPORTED_OPTION,
            CtapError.ERR.INVALID_OPTION,
        ):
            return cls.UNSUPPORTED
        return None

    def __str__(self) -> str:
        return self.name

    @property
    def protocol_unsupported(self) -> bool:
        return self == PinUvState.UNSUPPORTED

    @property
    def locked(self) -> bool:
        return self in (PinUvState.PIN_BLOCKED, PinUvState.UV_BLOCKED)


# Aliases used by callers that prefer different terminology.
PinState = PinUvState
PINState = PinUvState
PinUvStatusEnum = PinUvState


@dataclass(frozen=True)
class PinUvStatus:
    """A point-in-time PIN/UV status for a credential/authenticator."""

    state: PinUvState = PinUvState.READY
    retries: int | None = None
    uv_retries: int | None = None
    retry_after: float = 0.0
    locked_until: float | None = None
    device_id: str | None = None
    credential_id: str | None = None
    protocol_version: int | None = None
    pin_set: bool = True
    uv_supported: bool = False
    uv_required: bool = False
    pin_hard_blocked: bool = False
    uv_hard_blocked: bool = False
    error: CtapError | None = None

    @property
    def pin_retries(self) -> int | None:
        return self.retries

    @property
    def uv_attempts_remaining(self) -> int | None:
        return self.uv_retries

    @property
    def remaining_retries(self) -> int | None:
        return self.retries

    @property
    def remaining(self) -> int | None:
        return self.retries

    @property
    def attempts_remaining(self) -> int | None:
        return self.retries

    @property
    def locked(self) -> bool:
        return self.state.locked or self.retry_after > 0

    @property
    def is_locked(self) -> bool:
        return self.locked

    @property
    def lockout(self) -> float:
        return self.retry_after

    @property
    def lockout_seconds(self) -> float:
        return self.retry_after

    @property
    def protocol_supported(self) -> bool:
        return not self.protocol_unsupported

    @property
    def is_uv_required(self) -> bool:
        return self.state == PinUvState.UV_REQUIRED

    @property
    def state_name(self) -> str:
        return self.state.name

    @property
    def protocol_unsupported(self) -> bool:
        return self.state.protocol_unsupported

    @property
    def pin_retryable(self) -> bool:
        if self.state in (PinUvState.PIN_BLOCKED, PinUvState.UNSUPPORTED):
            return False
        if self.locked:
            return False
        if self.retries is not None and self.retries <= 0:
            return False
        return self.state in (PinUvState.READY, PinUvState.PIN_INVALID)

    @property
    def uv_retryable(self) -> bool:
        if self.state in (PinUvState.UV_BLOCKED, PinUvState.UNSUPPORTED):
            return False
        if self.locked:
            return False
        if self.uv_retries is not None and self.uv_retries <= 0:
            return False
        return self.state in (
            PinUvState.READY,
            PinUvState.UV_INVALID,
            PinUvState.UV_REQUIRED,
        )

    @property
    def retryable(self) -> bool:
        if self.state in (PinUvState.UV_REQUIRED, PinUvState.PIN_REQUIRED):
            return False
        return self.pin_retryable or self.uv_retryable

    @property
    def can_retry(self) -> bool:
        return self.retryable

    def to_dict(self) -> dict[str, Any]:
        """Serialize the status using stable, non-secret fields."""
        return {
            "state": int(self.state),
            "state_name": self.state.name,
            "retries": self.retries,
            "remaining_retries": self.retries,
            "uv_retries": self.uv_retries,
            "retry_after": self.retry_after,
            "lockout": self.retry_after,
            "locked_until": self.locked_until,
            "locked": self.locked,
            "protocol_supported": self.protocol_supported,
            "protocol_unsupported": self.protocol_unsupported,
            "pin_retryable": self.pin_retryable,
            "uv_retryable": self.uv_retryable,
        }

    @classmethod
    def from_response(
        cls,
        response: Mapping[Any, Any] | bytes | bytearray | int | None,
        *,
        state: PinUvState | None = None,
        device_id: str | None = None,
        credential_id: str | None = None,
    ) -> PinUvStatus:
        """Build a status from an extended CTAP response mapping."""
        metadata = error_metadata_from_response(response)
        return cls(
            state=state or metadata.get("state", PinUvState.READY),
            retries=metadata.get("retries"),
            uv_retries=metadata.get("uv_retries"),
            retry_after=metadata.get("retry_after", 0.0),
            locked_until=metadata.get("locked_until"),
            device_id=device_id,
            credential_id=credential_id,
        )

    @classmethod
    def from_mapping(
        cls,
        response: Mapping[Any, Any],
        **kwargs: Any,
    ) -> PinUvStatus:
        return cls.from_response(response, **kwargs)

    @classmethod
    def from_error(
        cls,
        code: int | CtapError.ERR,
        *,
        operation: str = "pin",
        retries: int | None = None,
        uv_retries: int | None = None,
        retry_after: float | None = None,
        locked_until: float | None = None,
    ) -> PinUvStatus:
        """Map an error code to a status without touching a store."""
        if isinstance(code, CtapError):
            retries = retries if retries is not None else getattr(code, "retries", None)
            uv_retries = (
                uv_retries
                if uv_retries is not None
                else getattr(code, "uv_retries", None)
            )
            retry_after = (
                retry_after
                if retry_after is not None
                else getattr(code, "retry_after", None)
            )
            locked_until = (
                locked_until
                if locked_until is not None
                else getattr(code, "locked_until", None)
            )
            state = getattr(code, "state", None) or PinUvState.from_code(code.code)
            code = code.code
        else:
            state = PinUvState.from_code(code) or PinUvState.READY
        if operation == "uv" and code in (
            CtapError.ERR.PIN_INVALID,
            CtapError.ERR.PIN_AUTH_INVALID,
        ):
            state = PinUvState.UV_REQUIRED
        return cls(
            state=state,
            retries=retries,
            uv_retries=uv_retries,
            retry_after=retry_after or 0.0,
            locked_until=locked_until,
        )

    def to_ctap_error_response(self) -> dict[int, Any]:
        """Numeric CTAP-style error response with retry/lockout fields."""
        response: dict[int, Any] = {8: int(self.state)}
        if self.retries is not None:
            response[3] = self.retries
        if self.uv_retries is not None:
            response[5] = self.uv_retries
        if self.retry_after:
            response[6] = self.retry_after
        if self.locked_until is not None:
            response[7] = self.locked_until
        return response

    @property
    def error_response(self) -> dict[int, Any]:
        return self.to_ctap_error_response()

    def to_ctap_error(self) -> CtapError:
        """Build an error carrying the current retry/lockout information."""
        code = CtapError.ERR.OTHER
        if self.state == PinUvState.PIN_INVALID:
            code = CtapError.ERR.PIN_INVALID
        elif self.state == PinUvState.PIN_BLOCKED:
            code = (
                CtapError.ERR.PIN_BLOCKED
                if self.pin_hard_blocked
                else CtapError.ERR.PIN_AUTH_BLOCKED
            )
        elif self.state == PinUvState.UV_INVALID:
            code = CtapError.ERR.UV_INVALID
        elif self.state == PinUvState.UV_BLOCKED:
            code = (
                CtapError.ERR.UV_BLOCKED
                if self.uv_hard_blocked
                else CtapError.ERR.UV_BLOCKED
            )
        elif self.state == PinUvState.UNSUPPORTED:
            code = CtapError.ERR.INVALID_SUBCOMMAND
        elif self.state == PinUvState.PIN_REQUIRED:
            code = CtapError.ERR.PIN_NOT_SET
        return PinUvError(
            code,
            state=self.state,
            retries=self.retries,
            uv_retries=self.uv_retries,
            retry_after=self.retry_after,
            locked_until=self.locked_until,
        )


class PinUvError(CtapError):
    """CtapError subclass with explicit PIN/UV state information."""

    def __init__(self, code: int = CtapError.ERR.OTHER, *args: Any, **kwargs: Any):
        super().__init__(code, *args, **kwargs)


PinRetryError = PinUvError
PinUvStateError = PinUvError


class PinUvStore(Protocol):
    """Storage interface for PIN/UV state.

    Implementations must be atomic with respect to concurrent updates of the
    same key. PIN state must never be placed in a client-controlled cookie.
    """

    def load(self, key: str) -> dict[str, Any] | None: ...

    def save(self, key: str, value: Mapping[str, Any]) -> None: ...


class InMemoryPinUvStore:
    """Thread-safe process-local PIN/UV store."""

    def __init__(self) -> None:
        self._data: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()

    @contextmanager
    def transaction(self, key: str) -> Iterator[dict[str, Any] | None]:
        with self._lock:
            yield self._data.get(key)

    def load(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            value = self._data.get(key)
            return dict(value) if value is not None else None

    def save(self, key: str, value: Mapping[str, Any]) -> None:
        with self._lock:
            self._data[key] = dict(value)

    def transaction_lock(self) -> Any:
        return self._lock

    def delete(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    def __getstate__(self) -> dict[str, Any]:
        state = self.__dict__.copy()
        state.pop("_lock", None)
        return state

    def __setstate__(self, state: Mapping[str, Any]) -> None:
        self.__dict__.update(state)
        self._lock = threading.RLock()


MemoryPinUvStore = InMemoryPinUvStore


class DictPinUvStore(InMemoryPinUvStore):
    """In-memory store backed by a caller-supplied mapping."""

    def __init__(self, data: MutableMapping[str, Any] | None = None) -> None:
        super().__init__()
        if data is not None:
            self._data = data  # type: ignore[assignment]


class JsonFilePinUvStore:
    """Durable, atomic JSON-backed PIN/UV store.

    The file contains state for all credentials and is replaced atomically on
    every update. A process lock is used when available so concurrent
    processes cannot interleave read-modify-write cycles.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._lock_path = self.path.with_name(self.path.name + ".lock")
        self._txn_lock_path = self.path.with_name(self.path.name + ".txn.lock")

    @contextmanager
    def _file_lock(self) -> Iterator[None]:
        with self._lock:
            with open(self._lock_path, "a+b") as lock_file:
                try:
                    import fcntl
                except ImportError:  # pragma: no cover - Windows
                    yield
                else:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                    try:
                        yield
                    finally:
                        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    @contextmanager
    def transaction_lock(self) -> Iterator[None]:
        with self._lock:
            with open(self._txn_lock_path, "a+b") as lock_file:
                try:
                    import fcntl
                except ImportError:  # pragma: no cover - Windows
                    yield
                else:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                    try:
                        yield
                    finally:
                        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def _read(self) -> dict[str, dict[str, Any]]:
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return {}
        if not isinstance(data, dict):
            return {}
        return {
            str(key): value for key, value in data.items() if isinstance(value, dict)
        }

    def _write(self, data: Mapping[str, Mapping[str, Any]]) -> None:
        fd, tmp_name = tempfile.mkstemp(
            prefix=self.path.name + ".",
            suffix=".tmp",
            dir=self.path.parent,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, sort_keys=True, separators=(",", ":"))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_name, self.path)
        finally:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass

    def load(self, key: str) -> dict[str, Any] | None:
        with self._file_lock():
            value = self._read().get(key)
            return dict(value) if value is not None else None

    def save(self, key: str, value: Mapping[str, Any]) -> None:
        with self._file_lock():
            data = self._read()
            data[key] = dict(value)
            self._write(data)

    @contextmanager
    def transaction(self, key: str) -> Iterator[dict[str, Any] | None]:
        with self._file_lock():
            data = self._read()
            value = data.get(key)
            yield dict(value) if value is not None else None

    def update(self, key: str, value: Mapping[str, Any]) -> None:
        with self._file_lock():
            data = self._read()
            data[key] = dict(value)
            self._write(data)

    def __getstate__(self) -> dict[str, Any]:
        state = self.__dict__.copy()
        state.pop("_lock", None)
        return state

    def __setstate__(self, state: Mapping[str, Any]) -> None:
        self.__dict__.update(state)
        self._lock = threading.RLock()


FilePinUvStore = JsonFilePinUvStore


_DEFAULT_STORE = InMemoryPinUvStore()
_DEVICE_LOCKS: dict[str, threading.RLock] = {}
_DEVICE_LOCKS_LOCK = threading.Lock()


def _device_lock(key: str) -> threading.RLock:
    with _DEVICE_LOCKS_LOCK:
        lock = _DEVICE_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _DEVICE_LOCKS[key] = lock
        return lock


def device_identity(info: Any) -> str:
    """Build a stable authenticator identity from GetInfo data."""
    if info is None:
        return "default"
    parts = []
    aaguid = getattr(info, "aaguid", None)
    if isinstance(aaguid, (bytes, bytearray, memoryview)):
        parts.append(bytes(aaguid).hex())
    enc_identifier = getattr(info, "enc_identifier", None)
    if isinstance(enc_identifier, (bytes, bytearray, memoryview)):
        parts.append(bytes(enc_identifier).hex())
    if parts:
        return "|".join(parts)
    versions = getattr(info, "versions", None)
    if isinstance(versions, (list, tuple)):
        parts.append(",".join(str(v) for v in versions))
    options = getattr(info, "options", None)
    if isinstance(options, Mapping):
        stable_options = {
            key: value
            for key, value in options.items()
            if key not in ("clientPin", "uv")
        }
        parts.append(
            "options="
            + ",".join(f"{key}:{stable_options[key]}" for key in sorted(stable_options))
        )
    protocols = getattr(info, "pin_uv_protocols", None)
    if isinstance(protocols, (list, tuple)):
        parts.append("protocols=" + ",".join(str(v) for v in protocols))
    max_msg_size = getattr(info, "max_msg_size", None)
    if isinstance(max_msg_size, int):
        parts.append(f"max_msg_size={max_msg_size}")
    return "|".join(parts) or f"ctap-{id(info):x}"


def _as_key(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.hex()
    return str(value)


def _clamp(value: int, maximum: int) -> int:
    return max(0, min(int(value), maximum))


def _first(mapping: Mapping[Any, Any], names: tuple[Any, ...]) -> Any:
    for name in names:
        if name in mapping:
            return mapping[name]
    return None


def _coerce_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _coerce_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class PinUvStateMachine:
    """Per-credential PIN/UV state machine.

    Counter updates are monotonic: a failed verification can only lower the
    remaining attempts. Counters are restored only by a successful
    verification or by an explicit administrative reset.

    :param credential_id: Stable credential identifier, if state is kept per
        credential.
    :param device_id: Stable authenticator identifier. Use a value that
        survives re-enumeration (for example an AAGUID plus a persistent
        identifier), not a USB path.
    :param store: Optional :class:`PinUvStore`. A process-local store is used
        by default. Pass a :class:`JsonFilePinUvStore` for state that must
        survive a process restart.
    :param clock: Wall clock returning seconds. It is used for lockout
        deadlines. Clock rollback is detected using a persisted high-water
        mark.
    """

    VERSION = 1

    def __init__(
        self,
        credential_id: Any = None,
        *,
        device_id: Any = None,
        max_pin_retries: int = 8,
        max_uv_retries: int = 3,
        pin_supported: bool | None = None,
        pin_set: bool | None = None,
        uv_supported: bool = False,
        protocol_version: int | None = None,
        store: PinUvStore | str | os.PathLike[str] | None = None,
        clock: Callable[[], float] = time.time,
        lockout_seconds: float = 60.0,
        soft_lock_after: int = 3,
        uv_soft_lock_after: int | None = None,
        expected_pin: str | None = None,
        enforce_locks: bool = False,
        **kwargs: Any,
    ) -> None:
        if credential_id is None:
            credential_id = kwargs.pop("key", kwargs.pop("id", None))
        if device_id is None:
            device_id = kwargs.pop("authenticator_id", kwargs.pop("device", None))
        if "max_retries" in kwargs:
            max_pin_retries = kwargs.pop("max_retries")
        if "max_attempts" in kwargs:
            max_pin_retries = kwargs.pop("max_attempts")
        if "initial_retries" in kwargs:
            kwargs.setdefault("initial_pin_retries", kwargs.pop("initial_retries"))
        if "pin" in kwargs and expected_pin is None:
            expected_pin = kwargs.pop("pin")
        if "protocol" in kwargs and protocol_version is None:
            protocol_version = kwargs.pop("protocol")
        if "lockout" in kwargs:
            lockout_seconds = kwargs.pop("lockout")
        if "lock_period" in kwargs:
            lockout_seconds = kwargs.pop("lock_period")
        if "lockout_period" in kwargs:
            lockout_seconds = kwargs.pop("lockout_period")
        initial_pin_retries = _coerce_int(
            kwargs.pop("initial_pin_retries", kwargs.pop("pin_retries", None))
        )
        initial_uv_retries = _coerce_int(
            kwargs.pop("initial_uv_retries", kwargs.pop("uv_retries", None))
        )
        if store is None:
            store = kwargs.pop(
                "state_path", kwargs.pop("store_path", kwargs.pop("path", None))
            )
        if kwargs:
            unknown = ", ".join(sorted(kwargs))
            raise TypeError(f"Unexpected arguments: {unknown}")
        if isinstance(store, MutableMapping):
            store = DictPinUvStore(store)
        elif isinstance(store, (str, os.PathLike)):
            store = JsonFilePinUvStore(store)
        self.store: PinUvStore = store if store is not None else _DEFAULT_STORE
        self.device_id = _as_key(device_id)
        self.credential_id = _as_key(credential_id)
        self.max_pin_retries = max(1, int(max_pin_retries))
        self.max_uv_retries = max(1, int(max_uv_retries))
        self.clock = clock
        self.lockout_seconds = max(0.0, float(lockout_seconds))
        self.soft_lock_after = max(1, int(soft_lock_after))
        self.uv_soft_lock_after = max(
            1,
            int(
                uv_soft_lock_after
                if uv_soft_lock_after is not None
                else soft_lock_after
            ),
        )
        self.enforce_locks = enforce_locks
        self._expected_pin = self._pin_hash(expected_pin)
        self.key = self._state_key()
        self._lock = _device_lock(self.key)

        with self._lock:
            now = self._wall_now()
            data = self._load(now)
            data["max_pin_retries"] = self.max_pin_retries
            data["max_uv_retries"] = self.max_uv_retries
            data["lockout_seconds"] = self.lockout_seconds
            if initial_pin_retries is not None:
                data["pin_retries"] = _clamp(initial_pin_retries, self.max_pin_retries)
            if initial_uv_retries is not None:
                data["uv_retries"] = _clamp(initial_uv_retries, self.max_uv_retries)
            if protocol_version is not None:
                data["protocol_version"] = int(protocol_version)
            elif data.get("protocol_version") is None:
                data["protocol_version"] = None
            if pin_supported is not None:
                data["protocol_supported"] = bool(pin_supported)
            if pin_set is not None:
                data["pin_set"] = bool(pin_set)
            if uv_supported:
                data["uv_supported"] = True
            elif "uv_supported" not in data:
                data["uv_supported"] = False
            self._refresh(data, now)
            self._save(data)

    def __getstate__(self) -> dict[str, Any]:
        state = self.__dict__.copy()
        state.pop("_lock", None)
        return state

    def __setstate__(self, state: Mapping[str, Any]) -> None:
        self.__dict__.update(state)
        self._lock = _device_lock(self.key)

    @staticmethod
    def _pin_hash(pin: str | None) -> bytes | None:
        return hashlib.sha256(pin.encode()).digest() if pin is not None else None

    def _state_key(self) -> str:
        # Credential IDs are stable across device paths/re-enumeration, while
        # a USB path is not. Use the credential identifier when available.
        if self.credential_id:
            return self.credential_id
        if self.device_id:
            return self.device_id
        return "default"

    @property
    def state(self) -> PinUvStatus:
        return self.status()

    @property
    def retries(self) -> int:
        return self.status().retries or 0

    @property
    def retry_count(self) -> int:
        return self.retries

    @property
    def remaining(self) -> int:
        return self.retries

    @property
    def remaining_retries(self) -> int:
        return self.retries

    @property
    def pin_attempts_remaining(self) -> int:
        return self.retries

    @property
    def uv_attempts_remaining(self) -> int:
        return self.uv_retries

    @property
    def is_uv_blocked(self) -> bool:
        return self.status().state == PinUvState.UV_BLOCKED

    @property
    def pin_retries(self) -> int:
        return self.retries

    @property
    def uv_retries(self) -> int:
        return self.status().uv_retries or 0

    @property
    def locked(self) -> bool:
        return self.status().locked

    @property
    def is_locked(self) -> bool:
        return self.locked

    @property
    def remaining_attempts(self) -> int:
        return self.retries

    @property
    def status_dict(self) -> dict[str, Any]:
        return self.status().to_dict()

    def get_status(self) -> PinUvStatus:
        return self.status()

    def get_pin_retries(self) -> int:
        return self.retries

    def get_uv_retries(self) -> int:
        return self.uv_retries

    def _wall_now(self) -> float:
        return float(self.clock())

    @staticmethod
    def _effective_now(data: Mapping[str, Any]) -> float:
        return max(float(data.get("last_seen") or 0.0), float(data.get("_now") or 0.0))

    def _empty(self, now: float) -> dict[str, Any]:
        return {
            "version": self.VERSION,
            "pin_retries": self.max_pin_retries,
            "uv_retries": self.max_uv_retries,
            "max_pin_retries": self.max_pin_retries,
            "max_uv_retries": self.max_uv_retries,
            "pin_failures": 0,
            "uv_failures": 0,
            "pin_locked_until": 0.0,
            "uv_locked_until": 0.0,
            "pin_hard_blocked": False,
            "uv_hard_blocked": False,
            "protocol_supported": True,
            "uv_supported": False,
            "uv_required": False,
            "pin_set": True,
            "last_error": None,
            "last_seen": now,
            "last_updated": now,
            "generation": 0,
        }

    def _load(self, now: float) -> dict[str, Any]:
        stored = self.store.load(self.key)
        data = self._empty(now)
        if stored:
            data.update(stored)
        data["version"] = self.VERSION
        if self.device_id is not None:
            data["device_id"] = self.device_id
        if self.credential_id is not None:
            data["credential_id"] = self.credential_id
        data["pin_retries"] = _clamp(
            _coerce_int(data.get("pin_retries")) or 0,
            self.max_pin_retries,
        )
        data["uv_retries"] = _clamp(
            _coerce_int(data.get("uv_retries")) or 0,
            self.max_uv_retries,
        )
        # A stored high-water mark prevents a wall-clock rollback from
        # shortening an existing lockout or reviving attempts.
        data["last_seen"] = max(
            float(data.get("last_seen") or 0.0),
            now,
        )
        return data

    def _save(self, data: MutableMapping[str, Any]) -> None:
        data["last_updated"] = data["last_seen"]
        data["generation"] = int(data.get("generation") or 0) + 1
        self.store.save(self.key, data)

    def _refresh(self, data: MutableMapping[str, Any], now: float) -> None:
        if now > float(data.get("last_seen") or 0.0):
            data["last_seen"] = now
        if data.get("pin_retries", 0) <= 0:
            data["pin_hard_blocked"] = True
        if data.get("uv_retries", 0) <= 0 and data.get("uv_required"):
            data["uv_hard_blocked"] = True

        pin_until = float(data.get("pin_locked_until") or 0.0)
        if pin_until and now >= pin_until:
            data["pin_locked_until"] = 0.0
            data["pin_failures"] = 0

        uv_until = float(data.get("uv_locked_until") or 0.0)
        if uv_until and now >= uv_until:
            data["uv_locked_until"] = 0.0
            data["uv_failures"] = 0

    def _status(self, data: Mapping[str, Any], now: float) -> PinUvStatus:
        effective_now = max(now, float(data.get("last_seen") or 0.0))
        pin_until = float(data.get("pin_locked_until") or 0.0)
        uv_until = float(data.get("uv_locked_until") or 0.0)
        retry_after = max(pin_until - effective_now, uv_until - effective_now, 0.0)
        locked_until = max(pin_until, uv_until) or None

        if not data.get("protocol_supported", True):
            state = PinUvState.UNSUPPORTED
        elif data.get("pin_hard_blocked"):
            state = PinUvState.PIN_BLOCKED
        elif pin_until > effective_now:
            state = PinUvState.PIN_BLOCKED
        elif data.get("uv_hard_blocked") or uv_until > effective_now:
            state = PinUvState.UV_BLOCKED
        elif not data.get("pin_set", True):
            state = PinUvState.PIN_REQUIRED
        elif data.get("uv_required"):
            state = PinUvState.UV_REQUIRED
        elif data.get("last_error") == "uv":
            state = (
                PinUvState.UV_INVALID
                if int(data.get("uv_retries") or 0) > 0
                else PinUvState.UV_BLOCKED
            )
        elif data.get("last_error") == "pin":
            state = (
                PinUvState.PIN_INVALID
                if int(data.get("pin_retries") or 0) > 0
                else PinUvState.PIN_BLOCKED
            )
        else:
            state = PinUvState.READY

        return PinUvStatus(
            state=state,
            retries=_coerce_int(data.get("pin_retries")),
            uv_retries=_coerce_int(data.get("uv_retries")),
            retry_after=retry_after,
            locked_until=locked_until,
            device_id=self.device_id,
            credential_id=self.credential_id,
            protocol_version=_coerce_int(data.get("protocol_version")),
            pin_set=bool(data.get("pin_set", True)),
            uv_supported=bool(data.get("uv_supported", False)),
            uv_required=bool(data.get("uv_required", False)),
            pin_hard_blocked=bool(data.get("pin_hard_blocked", False)),
            uv_hard_blocked=bool(data.get("uv_hard_blocked", False)),
        )

    @contextmanager
    def _transaction(self) -> Iterator[dict[str, Any]]:
        store_lock = getattr(self.store, "transaction_lock", None)
        store_context = store_lock() if store_lock is not None else nullcontext()
        with self._lock, store_context:
            now = self._wall_now()
            data = self._load(now)
            effective_now = max(now, float(data.get("last_seen") or 0.0))
            data["_now"] = effective_now
            # Keep configured maxima/policy authoritative even if an older
            # serialized record is read.
            data["max_pin_retries"] = self.max_pin_retries
            data["max_uv_retries"] = self.max_uv_retries
            data["lockout_seconds"] = self.lockout_seconds
            self._refresh(data, effective_now)
            yield data
            data["_now"] = max(
                float(data.get("_now") or 0.0),
                float(data.get("last_seen") or 0.0),
                self._wall_now(),
            )
            self._refresh(data, float(data["_now"]))
            data.pop("_now", None)
            self._save(data)

    def status(self, *, refresh: bool = True) -> PinUvStatus:
        """Return the current status, expiring a completed soft lockout."""
        if refresh:
            with self._transaction():
                pass
        with self._lock:
            now = self._wall_now()
            data = self._load(now)
            effective_now = max(now, float(data.get("last_seen") or 0.0))
            self._refresh(data, effective_now)
            return self._status(data, effective_now)

    snapshot = status

    def can_retry(self) -> bool:
        return self.status().retryable

    def is_retryable(self) -> bool:
        return self.can_retry()

    def can_retry_pin(self) -> bool:
        return self.status().pin_retryable

    def can_retry_uv(self) -> bool:
        return self.status().uv_retryable

    def check_lockout(self) -> PinUvStatus:
        return self.status()

    expire_lockouts = check_lockout

    def ensure_available(self, *, uv: bool = False) -> None:
        """Raise a stateful error if verification cannot currently be attempted."""
        status = self.status()
        if status.protocol_unsupported:
            raise PinUvError(
                CtapError.ERR.INVALID_SUBCOMMAND,
                state=status.state,
                retries=status.retries,
                uv_retries=status.uv_retries,
                retry_after=status.retry_after,
                locked_until=status.locked_until,
            )
        if status.locked or (uv and status.uv_retries == 0):
            err = status.to_ctap_error()
            raise err

    def _maybe_enforce(self) -> None:
        if self.enforce_locks:
            self.ensure_available()

    def record_pin_failure(
        self,
        retries: int | None = None,
        *,
        reported_retries: int | None = None,
        retry_after: float | None = None,
        locked_until: float | None = None,
    ) -> PinUvStatus:
        """Record a failed PIN attempt and decrease the retry counter."""
        self._maybe_enforce()
        reported = retries if retries is not None else reported_retries
        with self._transaction() as data:
            if data.get("pin_hard_blocked") or float(
                data.get("pin_locked_until") or 0.0
            ) > self._effective_now(data):
                self._merge_lockout(data, "pin", retry_after, locked_until)
                data["last_error"] = "pin"
                return self._status(data, self._effective_now(data))

            current = int(data.get("pin_retries") or 0)
            # A failed attempt must consume at least one attempt even if a
            # device (or a stale response) reports an unchanged count.
            decremented = max(0, current - 1)
            if reported is not None:
                updated = min(
                    decremented,
                    _clamp(_coerce_int(reported) or 0, self.max_pin_retries),
                )
            else:
                updated = decremented
            data["pin_retries"] = updated
            data["pin_failures"] = int(data.get("pin_failures") or 0) + 1
            data["last_error"] = "pin"
            if updated <= 0:
                data["pin_hard_blocked"] = True
            elif (
                int(data["pin_failures"]) >= self.soft_lock_after
                or retry_after is not None
                or locked_until is not None
            ):
                self._merge_lockout(
                    data,
                    "pin",
                    retry_after,
                    locked_until,
                    default=self.lockout_seconds,
                )
            return self._status(data, self._effective_now(data))

    on_pin_failure = record_pin_failure
    on_pin_invalid = record_pin_failure
    pin_failed = record_pin_failure

    def record_pin_success(self) -> PinUvStatus:
        """A correct PIN restores the retry counter and clears PIN locks."""
        with self._transaction() as data:
            data["pin_retries"] = self.max_pin_retries
            data["pin_failures"] = 0
            data["pin_locked_until"] = 0.0
            data["pin_hard_blocked"] = False
            data["pin_set"] = True
            if data.get("last_error") == "pin":
                data["last_error"] = None
            return self._status(data, self._effective_now(data))

    on_pin_success = record_pin_success
    pin_succeeded = record_pin_success

    def record_uv_failure(
        self,
        retries: int | None = None,
        *,
        reported_retries: int | None = None,
        retry_after: float | None = None,
        locked_until: float | None = None,
    ) -> PinUvStatus:
        """Record a failed UV attempt without consuming a PIN attempt."""
        self._maybe_enforce()
        reported = retries if retries is not None else reported_retries
        with self._transaction() as data:
            if data.get("uv_hard_blocked") or float(
                data.get("uv_locked_until") or 0.0
            ) > self._effective_now(data):
                self._merge_lockout(data, "uv", retry_after, locked_until)
                data["last_error"] = "uv"
                return self._status(data, self._effective_now(data))

            current = int(data.get("uv_retries") or 0)
            decremented = max(0, current - 1)
            if reported is not None:
                updated = min(
                    decremented,
                    _clamp(_coerce_int(reported) or 0, self.max_uv_retries),
                )
            else:
                updated = decremented
            data["uv_retries"] = updated
            data["uv_failures"] = int(data.get("uv_failures") or 0) + 1
            data["uv_required"] = True
            data["last_error"] = "uv"
            if updated <= 0:
                data["uv_hard_blocked"] = True
            elif (
                int(data["uv_failures"]) >= self.uv_soft_lock_after
                or retry_after is not None
                or locked_until is not None
            ):
                self._merge_lockout(
                    data,
                    "uv",
                    retry_after,
                    locked_until,
                    default=self.lockout_seconds,
                )
            return self._status(data, self._effective_now(data))

    on_uv_failure = record_uv_failure
    on_uv_invalid = record_uv_failure
    uv_failed = record_uv_failure

    def record_failure(self, kind: str = "pin", **kwargs: Any) -> PinUvStatus:
        return (
            self.record_uv_failure(**kwargs)
            if kind.lower().startswith("uv")
            else self.record_pin_failure(**kwargs)
        )

    on_failure = record_failure

    def record_success(self, kind: str = "pin") -> PinUvStatus:
        return (
            self.record_uv_success()
            if kind.lower().startswith("uv")
            else self.record_pin_success()
        )

    on_success = record_success

    def record_pin_attempt(self, success: bool, **kwargs: Any) -> PinUvStatus:
        return (
            self.record_pin_success() if success else self.record_pin_failure(**kwargs)
        )

    def record_uv_attempt(self, success: bool, **kwargs: Any) -> PinUvStatus:
        return self.record_uv_success() if success else self.record_uv_failure(**kwargs)

    def record_uv_success(self) -> PinUvStatus:
        """Successful UV restores UV attempts but never PIN attempts."""
        with self._transaction() as data:
            data["uv_retries"] = self.max_uv_retries
            data["uv_failures"] = 0
            data["uv_locked_until"] = 0.0
            data["uv_hard_blocked"] = False
            data["uv_required"] = False
            if data.get("last_error") == "uv":
                data["last_error"] = None
            return self._status(data, self._effective_now(data))

    on_uv_success = record_uv_success
    uv_succeeded = record_uv_success

    def set_uv_required(self, required: bool = True) -> PinUvStatus:
        with self._transaction() as data:
            data["uv_required"] = bool(required)
            return self._status(data, self._effective_now(data))

    def mark_unsupported(self) -> PinUvStatus:
        with self._transaction() as data:
            data["protocol_supported"] = False
            return self._status(data, self._effective_now(data))

    def admin_reset(self, *, pin: bool = True, uv: bool = True) -> PinUvStatus:
        """Explicit administrative reset of PIN and/or UV state."""
        with self._transaction() as data:
            if pin:
                data["pin_retries"] = self.max_pin_retries
                data["pin_failures"] = 0
                data["pin_locked_until"] = 0.0
                data["pin_hard_blocked"] = False
                data["pin_set"] = True
                data["protocol_supported"] = True
            if uv:
                data["uv_retries"] = self.max_uv_retries
                data["uv_failures"] = 0
                data["uv_locked_until"] = 0.0
                data["uv_hard_blocked"] = False
                data["uv_required"] = False
            data["last_error"] = None
            return self._status(data, self._effective_now(data))

    reset = admin_reset
    reset_state = admin_reset
    reset_retries = admin_reset

    def unlock(self, *, pin: bool = True, uv: bool = True) -> PinUvStatus:
        """Clear a soft lockout without restoring consumed attempts."""
        with self._transaction() as data:
            if pin:
                data["pin_locked_until"] = 0.0
                data["pin_failures"] = 0
            if uv:
                data["uv_locked_until"] = 0.0
                data["uv_failures"] = 0
            return self._status(data, self._effective_now(data))

    clear_lockout = unlock
    unlock_pin = unlock

    def sync_pin_retries(
        self,
        retries: int,
        *,
        retry_after: float | None = None,
        locked_until: float | None = None,
        success: bool = False,
    ) -> PinUvStatus:
        """Synchronize with an authoritative device retry count.

        Without ``success`` (or an explicit administrative reset) the
        counter is only allowed to decrease.
        """
        if success:
            return self.record_pin_success()
        with self._transaction() as data:
            current = int(data.get("pin_retries") or 0)
            updated = min(current, _clamp(int(retries), self.max_pin_retries))
            data["pin_retries"] = updated
            data["pin_set"] = True
            data["protocol_supported"] = True
            if updated <= 0:
                data["pin_hard_blocked"] = True
            self._merge_lockout(data, "pin", retry_after, locked_until)
            return self._status(data, self._effective_now(data))

    def sync_uv_retries(
        self,
        retries: int,
        *,
        retry_after: float | None = None,
        locked_until: float | None = None,
        success: bool = False,
    ) -> PinUvStatus:
        if success:
            return self.record_uv_success()
        with self._transaction() as data:
            current = int(data.get("uv_retries") or 0)
            updated = min(current, _clamp(int(retries), self.max_uv_retries))
            data["uv_retries"] = updated
            if updated <= 0:
                data["uv_hard_blocked"] = True
            self._merge_lockout(data, "uv", retry_after, locked_until)
            return self._status(data, self._effective_now(data))

    def set_pin(self, pin: str) -> PinUvStatus:
        """Set the expected PIN for :meth:`verify_pin` (hashed at rest)."""
        self._expected_pin = self._pin_hash(pin)
        return self.admin_reset(pin=True, uv=False)

    def verify_pin(
        self,
        pin: str | bool,
        *,
        expected_pin: str | None = None,
    ) -> PinUvStatus:
        """Verify a PIN and update the state machine.

        If ``pin`` is a boolean it is interpreted as the verification result.
        A string is compared against ``expected_pin`` if supplied, otherwise
        against the PIN configured through :meth:`set_pin`.
        """
        if isinstance(pin, bool):
            valid = pin
        else:
            expected = (
                self._pin_hash(expected_pin)
                if expected_pin is not None
                else self._expected_pin
            )
            if expected is None:
                raise ValueError("No expected PIN configured")
            valid = hmac.compare_digest(self._pin_hash(pin) or b"", expected)
        return self.record_pin_success() if valid else self.record_pin_failure()

    def verify_uv(self, success: bool = True) -> PinUvStatus:
        return self.record_uv_success() if success else self.record_uv_failure()

    check_pin = verify_pin
    attempt_pin = verify_pin
    check_uv = verify_uv
    attempt_uv = verify_uv

    def apply_error(
        self,
        code: int | CtapError.ERR,
        *,
        operation: str = "pin",
        retries: int | None = None,
        uv_retries: int | None = None,
        retry_after: float | None = None,
        locked_until: float | None = None,
    ) -> PinUvStatus:
        """Apply an authenticator error to the correct PIN or UV counter."""
        if isinstance(code, CtapError):
            retries = retries if retries is not None else getattr(code, "retries", None)
            uv_retries = (
                uv_retries
                if uv_retries is not None
                else getattr(code, "uv_retries", None)
            )
            retry_after = (
                retry_after
                if retry_after is not None
                else getattr(code, "retry_after", None)
            )
            locked_until = (
                locked_until
                if locked_until is not None
                else getattr(code, "locked_until", None)
            )
            code = code.code
        try:
            err = CtapError.ERR(int(code))
        except ValueError:
            return self.status()

        if err in (
            CtapError.ERR.INVALID_COMMAND,
            CtapError.ERR.INVALID_SUBCOMMAND,
            CtapError.ERR.UNSUPPORTED_OPTION,
            CtapError.ERR.INVALID_OPTION,
        ):
            return self.mark_unsupported()

        if err == CtapError.ERR.PIN_NOT_SET:
            with self._transaction() as data:
                data["pin_set"] = False
                data["protocol_supported"] = True
                data["pin_retries"] = self.max_pin_retries
                data["pin_failures"] = 0
                data["pin_locked_until"] = 0.0
                data["pin_hard_blocked"] = False
                data["last_error"] = None
                return self._status(data, self._effective_now(data))

        if operation == "uv":
            if err in (
                CtapError.ERR.PIN_INVALID,
                CtapError.ERR.PIN_AUTH_INVALID,
                CtapError.ERR.UV_INVALID,
            ):
                return self.record_uv_failure(
                    reported_retries=uv_retries,
                    retry_after=retry_after,
                    locked_until=locked_until,
                )
            if err == CtapError.ERR.PIN_NOT_SET:
                return self.mark_unsupported()
            if err in (CtapError.ERR.UV_BLOCKED, CtapError.ERR.PIN_AUTH_BLOCKED):
                with self._transaction() as data:
                    data["uv_required"] = True
                    if int(data.get("uv_retries") or 0) <= 0:
                        data["uv_hard_blocked"] = True
                    self._merge_lockout(
                        data,
                        "uv",
                        retry_after,
                        locked_until,
                        default=self.lockout_seconds,
                    )
                    data["last_error"] = "uv"
                    return self._status(data, self._effective_now(data))
            if err == CtapError.ERR.PUAT_REQUIRED:
                return self.set_uv_required(True)
            return self.status()

        if err in (CtapError.ERR.PIN_INVALID, CtapError.ERR.PIN_AUTH_INVALID):
            return self.record_pin_failure(
                reported_retries=retries,
                retry_after=retry_after,
                locked_until=locked_until,
            )
        if err == CtapError.ERR.PIN_BLOCKED:
            with self._transaction() as data:
                data["pin_hard_blocked"] = True
                data["pin_retries"] = 0
                data["last_error"] = "pin"
                self._merge_lockout(data, "pin", retry_after, locked_until)
                return self._status(data, self._effective_now(data))
        if err == CtapError.ERR.PIN_AUTH_BLOCKED:
            with self._transaction() as data:
                self._merge_lockout(
                    data,
                    "pin",
                    retry_after,
                    locked_until,
                    default=self.lockout_seconds,
                )
                data["last_error"] = "pin"
                return self._status(data, self._effective_now(data))
        if err == CtapError.ERR.UV_BLOCKED:
            with self._transaction() as data:
                data["uv_required"] = True
                if int(data.get("uv_retries") or 0) <= 0:
                    data["uv_hard_blocked"] = True
                data["last_error"] = "uv"
                self._merge_lockout(
                    data,
                    "uv",
                    retry_after,
                    locked_until,
                    default=self.lockout_seconds,
                )
                return self._status(data, self._effective_now(data))
        if err == CtapError.ERR.UV_INVALID:
            return self.record_uv_failure(
                reported_retries=uv_retries,
                retry_after=retry_after,
                locked_until=locked_until,
            )
        if err == CtapError.ERR.PUAT_REQUIRED:
            with self._transaction() as data:
                data["uv_required"] = True
                return self._status(data, self._effective_now(data))
        return self.status()

    on_error = apply_error
    handle_error = apply_error

    def apply_status(
        self,
        code: int | CtapError.ERR,
        *,
        operation: str = "pin",
        retries: int | None = None,
        uv_retries: int | None = None,
        retry_after: float | None = None,
        locked_until: float | None = None,
    ) -> PinUvStatus:
        return self.apply_error(
            code,
            operation=operation,
            retries=retries,
            uv_retries=uv_retries,
            retry_after=retry_after,
            locked_until=locked_until,
        )

    def apply_ctap_error(self, error: CtapError, *, operation: str = "pin"):
        return self.apply_error(
            error.code,
            operation=operation,
            retries=getattr(error, "retries", None),
            uv_retries=getattr(error, "uv_retries", None),
            retry_after=getattr(error, "retry_after", None),
            locked_until=getattr(error, "locked_until", None),
        )

    def _merge_lockout(
        self,
        data: MutableMapping[str, Any],
        kind: str,
        retry_after: float | None,
        locked_until: float | None,
        *,
        default: float = 0.0,
    ) -> None:
        now = max(
            float(data.get("_now") or 0.0),
            float(data.get("last_seen") or 0.0),
            self._wall_now(),
        )
        deadline = 0.0
        if locked_until is not None:
            # Normalize absolute monotonic-style values to wall time where
            # possible. Some authenticators report a relative duration in this
            # field instead of an absolute deadline.
            deadline = float(locked_until)
            if deadline < now:
                if retry_after is not None:
                    deadline = now + max(0.0, float(retry_after))
                elif 0 < deadline < 365 * 24 * 60 * 60:
                    deadline = now + deadline
                else:
                    deadline = now
        elif retry_after is not None:
            deadline = now + max(0.0, float(retry_after))
        elif default:
            deadline = now + default
        if deadline:
            key = f"{kind}_locked_until"
            data[key] = max(float(data.get(key) or 0.0), deadline)
        data["last_seen"] = max(float(data.get("last_seen") or 0.0), now)


PinStateMachine = PinUvStateMachine
PinUvTracker = PinUvStateMachine
CredentialPinUvState = PinUvStateMachine


def error_metadata_from_response(
    response: Mapping[Any, Any] | bytes | bytearray | int | None,
) -> dict[str, Any]:
    """Extract retry/lockout metadata from an extended CTAP error response."""
    if isinstance(response, (bytes, bytearray)):
        try:
            from .. import cbor

            response = cbor.decode(bytes(response))
        except Exception:
            return {}
    if isinstance(response, int) and not isinstance(response, bool):
        return {"retries": response}
    if not isinstance(response, Mapping):
        return {}
    retries = _coerce_int(
        _first(
            response,
            (
                0x03,
                3,
                "pinRetries",
                "pin_retries",
                "retries",
                "remainingRetries",
                "remaining_retries",
                "remainingAttempts",
                "remaining_attempts",
            ),
        )
    )
    uv_retries = _coerce_int(
        _first(
            response,
            (
                0x05,
                5,
                "uvRetries",
                "uv_retries",
                "uvAttempts",
                "uv_attempts",
            ),
        )
    )
    retry_after = _coerce_float(
        _first(
            response,
            (
                0x06,
                6,
                "retryAfter",
                "retry_after",
                "lockout",
                "lockoutSeconds",
                "lockout_seconds",
                "lockPeriod",
                "lock_period",
                "lockoutPeriod",
                "lockout_period",
            ),
        )
    )
    locked_until = _coerce_float(
        _first(
            response,
            (
                0x07,
                7,
                "lockedUntil",
                "locked_until",
                "lockoutUntil",
                "lockout_until",
            ),
        )
    )
    state = _first(
        response,
        (
            0x08,
            8,
            "state",
            "pinUvState",
            "pin_uv_state",
        ),
    )
    if retries is None and 1 in response:
        retries = _coerce_int(response[1])
    if retry_after is None and 2 in response:
        retry_after = _coerce_float(response[2])
    if retry_after is None and 4 in response:
        candidate = _coerce_float(response[4])
        if candidate is not None and candidate > 1:
            retry_after = candidate
    result: dict[str, Any] = {}
    if retries is not None:
        result["retries"] = retries
    if uv_retries is not None:
        result["uv_retries"] = uv_retries
    if retry_after is not None:
        result["retry_after"] = retry_after
    if locked_until is not None:
        result["locked_until"] = locked_until
    if state is not None:
        try:
            result["state"] = PinUvState(int(state))
        except (TypeError, ValueError):
            if isinstance(state, str):
                try:
                    result["state"] = PinUvState[state]
                except KeyError:
                    pass
    return result
