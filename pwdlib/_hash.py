import collections.abc
import enum
import threading
import time
import typing
from typing import TYPE_CHECKING

from . import exceptions
from .hashers import HasherProtocol
from .hashers.base import validate_str_or_bytes

if TYPE_CHECKING:
    import sys

    if sys.version_info >= (3, 11):
        from typing import Self
    else:
        from typing_extensions import Self


class MigrationStatus(str, enum.Enum):
    """
    Outcome of a single password migration transaction.
    """

    #: The password was verified successfully and no hash upgrade was needed.
    SUCCESS = "success"
    #: The password was verified successfully and the hash was upgraded.
    UPGRADED = "upgraded"
    #: Another transaction already committed the upgraded hash.
    ALREADY_MIGRATED = "already_migrated"
    #: The password did not match the stored hash.
    INVALID_PASSWORD = "invalid_password"
    #: The hash has a recognized algorithm prefix but a corrupted content.
    CORRUPTED_HASH = "corrupted_hash"
    #: Authentication succeeded but the updated hash could not be stored.
    STORAGE_ERROR = "storage_error"


class MigrationFailureReason(str, enum.Enum):
    """
    Machine-readable reason why a migration transaction did not fully succeed.
    """

    NONE = "none"
    INVALID_PASSWORD = "invalid_password"
    CORRUPTED_HASH = "corrupted_hash"
    STORAGE_ERROR = "storage_error"


class CorruptedHashHandling(str, enum.Enum):
    """
    How a corrupted hash (recognized prefix, unreadable content) is handled.
    """

    #: Return a result object describing the corruption instead of raising.
    RETURN_RESULT = "return_result"
    #: Raise :class:`pwdlib.exceptions.CorruptedHashError`.
    RAISE = "raise"


class MigrationResult:
    """
    Explicit result of a password verification/migration transaction.

    Callers never have to parse hashes or guess the meaning of a boolean:
    the status, failure reason, algorithm and final hash are always exposed
    as structured attributes.
    """

    __slots__ = (
        "authenticated",
        "upgraded",
        "status",
        "failure_reason",
        "algorithm",
        "final_hash",
        "error",
    )

    def __init__(
        self,
        *,
        authenticated: bool,
        upgraded: bool,
        status: MigrationStatus,
        failure_reason: MigrationFailureReason,
        algorithm: str | None,
        final_hash: str | None,
        error: BaseException | None = None,
    ) -> None:
        self.authenticated = authenticated
        self.upgraded = upgraded
        self.status = status
        self.failure_reason = failure_reason
        self.algorithm = algorithm
        self.final_hash = final_hash
        self.error = error

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return (
            "MigrationResult("
            f"authenticated={self.authenticated!r}, upgraded={self.upgraded!r}, "
            f"status={self.status!r}, failure_reason={self.failure_reason!r}, "
            f"algorithm={self.algorithm!r}, final_hash={self.final_hash!r})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MigrationResult):
            return NotImplemented
        return (
            self.authenticated == other.authenticated
            and self.upgraded == other.upgraded
            and self.status == other.status
            and self.failure_reason == other.failure_reason
            and self.algorithm == other.algorithm
            and self.final_hash == other.final_hash
        )


class PasswordHashStore(typing.Protocol):
    """
    Optional storage abstraction used by :class:`PasswordMigrationPolicy`.

    Only ``update_hash`` is required. ``load_hash`` enables safe resolution of
    lost concurrent updates: when another transaction won the race, the policy
    can return the already committed hash instead of producing a second one.
    """

    def load_hash(self, old_hash: str) -> str | None: ...

    def update_hash(self, old_hash: str, new_hash: str) -> None: ...


#: Callable persisting ``new_hash`` in place of ``old_hash``.
UpdateHashCallable = collections.abc.Callable[[str, str], None]
#: Callable returning the hash currently stored for the user behind ``old_hash``.
LoadHashCallable = collections.abc.Callable[[str], str | None]


def _resolve_hasher(
    hashers: collections.abc.Sequence[HasherProtocol], hash: str | bytes
) -> tuple[HasherProtocol | None, HasherProtocol | None]:
    """
    Resolve which hasher a hash belongs to.

    Returns a ``(hasher, prefix_hasher)`` tuple where:

    - ``hasher`` is the hasher whose full structure matches the hash;
    - ``prefix_hasher`` is a hasher matching only the algorithm prefix, meaning
      the hash is recognized but corrupted.

    When both are ``None``, the hash is completely unknown.
    """
    prefix_hasher: HasherProtocol | None = None
    for hasher in hashers:
        if hasher.identify(hash) and hasher.is_valid(hash):
            return hasher, None
        if prefix_hasher is None and hasher.identify_prefix(hash):
            prefix_hasher = hasher
    return None, prefix_hasher


class PasswordHash:
    """
    Represents a password hashing utility.
    """

    def __init__(self, hashers: collections.abc.Sequence[HasherProtocol]) -> None:
        """
        Args:
            hashers: A sequence of hashers to be used for password hashing.

        Raises:
            AssertionError: If no hashers are specified.
        """
        assert len(hashers) > 0, "You must specify at least one hasher."
        self.hashers = hashers
        self.current_hasher = hashers[0]

    @classmethod
    def recommended(cls) -> "Self":
        """
        Returns a PasswordHash instance with recommended hashers.

        Currently, the hasher is Argon2 with default parameters.

        Examples:
            >>> password_hash = PasswordHash.recommended()
            >>> hash = password_hash.hash("herminetincture")
            >>> password_hash.verify(hash, "herminetincture")
            True
        """
        from .hashers.argon2 import Argon2Hasher

        return cls((Argon2Hasher(),))

    def hash(self, password: str | bytes, *, salt: bytes | None = None) -> str:
        """
        Hashes a password using the current hasher.

        Args:
            password: The password to be hashed.
            salt: The salt to be used for hashing. Defaults to None.

        Returns:
            The hashed password.

        Examples:
            >>> hash = password_hash.hash("herminetincture")
        """
        validate_str_or_bytes(password, "password")
        return self.current_hasher.hash(password, salt=salt)

    def verify(self, password: str | bytes, hash: str | bytes) -> bool:
        """
        Verifies if a password matches a given hash.

        Args:
            password: The password to be checked.
            hash: The hash to be verified.

        Returns:
            True if the password matches the hash, False otherwise.

        Raises:
            exceptions.UnknownHashError: If the hash is not recognized by any of the hashers.

        Examples:
            >>> password_hash.verify("herminetincture", hash)
            True

            >>> password_hash.verify("INVALID_PASSWORD", hash)
            False
        """
        validate_str_or_bytes(password, "password")
        validate_str_or_bytes(hash, "hash")
        hasher, _ = _resolve_hasher(self.hashers, hash)
        if hasher is not None:
            return hasher.verify(password, hash)
        raise exceptions.UnknownHashError(hash)

    def verify_and_update(
        self, password: str | bytes, hash: str | bytes
    ) -> tuple[bool, str | None]:
        """
        Verifies if a password matches a given hash and updates the hash if necessary.

        Args:
            password: The password to be checked.
            hash: The hash to be verified.

        Returns:
            A tuple containing a boolean indicating if the password matches the hash,
                and an updated hash if the current hasher or the hash itself needs to be updated.

        Raises:
            exceptions.UnknownHashError: If the hash is not recognized by any of the hashers.

        Examples:
            >>> valid, updated_hash = password_hash.verify_and_update("herminetincture", hash)
        """
        validate_str_or_bytes(password, "password")
        validate_str_or_bytes(hash, "hash")
        hasher, _ = _resolve_hasher(self.hashers, hash)
        if hasher is not None:
            if not hasher.verify(password, hash):
                return False, None
            else:
                updated_hash: str | None = None
                if hasher != self.current_hasher or hasher.check_needs_rehash(hash):
                    updated_hash = self.current_hasher.hash(password)
                return True, updated_hash
        raise exceptions.UnknownHashError(hash)


class PasswordMigrationPolicy:
    """
    Reusable, concurrency-safe password hash migration transaction.

    A policy wraps a :class:`PasswordHash` instance and turns verification
    into an explicit transaction: it distinguishes unknown hashes, corrupted
    hashes and wrong passwords, optionally upgrades legacy/obsolete hashes
    after a successful login and makes sure two concurrent logins using the
    same legacy hash can't overwrite each other's upgrade.

    The classic :meth:`PasswordHash.verify` and
    :meth:`PasswordHash.verify_and_update` methods are left untouched: this
    policy is an opt-in, explicitly instantiated component.
    """

    def __init__(
        self,
        password_hash: PasswordHash,
        *,
        legacy_hashers: collections.abc.Sequence[HasherProtocol] | None = None,
        corrupted_hash_handling: CorruptedHashHandling = (
            CorruptedHashHandling.RETURN_RESULT
        ),
        upgrade_on_success: bool = True,
        min_verification_time: float = 0.0,
    ) -> None:
        """
        Args:
            password_hash: The :class:`PasswordHash` instance used to verify
                and generate hashes. Its current (first) hasher is the target
                of every upgrade.
            legacy_hashers: Hashers allowed for verification but eligible for
                an upgrade. Defaults to every hasher except the current one.
            corrupted_hash_handling: Whether to raise
                :class:`pwdlib.exceptions.CorruptedHashError` or to return an
                explicit corrupted-hash result when a hash prefix is known but
                its content is invalid.
            upgrade_on_success: When ``False``, successful logins are never
                upgraded, even if the hash is legacy or needs rehashing.
            min_verification_time: Minimum wall-clock duration, in seconds, of
                a verification transaction. Useful to mitigate user
                enumeration through timing differences. ``0`` disables it.

        Raises:
            TypeError: If a parameter has an invalid type.
            ValueError: If a parameter has an invalid value.
        """
        if min_verification_time < 0:
            raise ValueError("min_verification_time")
        if not isinstance(corrupted_hash_handling, CorruptedHashHandling):
            raise TypeError("corrupted_hash_handling")

        self.password_hash = password_hash
        self.target_hasher: HasherProtocol = password_hash.current_hasher
        if legacy_hashers is None:
            self.legacy_hashers: tuple[HasherProtocol, ...] = tuple(
                hasher
                for hasher in password_hash.hashers
                if not self._is_target_hasher(hasher)
            )
        else:
            unknown = [
                hasher
                for hasher in legacy_hashers
                if hasher not in password_hash.hashers
            ]
            if unknown:
                raise ValueError("legacy_hashers")
            self.legacy_hashers = tuple(legacy_hashers)
        self.corrupted_hash_handling = corrupted_hash_handling
        self.upgrade_on_success = upgrade_on_success
        self.min_verification_time = min_verification_time
        self._registry_lock = threading.Lock()
        self._hash_locks: dict[str, threading.Lock] = {}

    def _is_target_hasher(self, hasher: HasherProtocol) -> bool:
        if hasher is self.target_hasher:
            return True
        try:
            return hasher == self.target_hasher
        except Exception:  # noqa: BLE001 - defensive, hasher is user code
            return False

    def _get_hash_lock(self, hash: str) -> threading.Lock:
        # The registry lock is only held for dict bookkeeping, never while
        # verifying or hashing, so distinct hashes don't serialize each other.
        with self._registry_lock:
            lock = self._hash_locks.get(hash)
            if lock is None:
                lock = threading.Lock()
                self._hash_locks[hash] = lock
            return lock

    def _corrupted_result(self, hash: str | bytes, algorithm: str) -> MigrationResult:
        if self.corrupted_hash_handling is CorruptedHashHandling.RAISE:
            raise exceptions.CorruptedHashError(hash, algorithm)
        return MigrationResult(
            authenticated=False,
            upgraded=False,
            status=MigrationStatus.CORRUPTED_HASH,
            failure_reason=MigrationFailureReason.CORRUPTED_HASH,
            algorithm=algorithm,
            final_hash=hash if isinstance(hash, str) else None,
        )

    def verify_and_migrate(
        self,
        password: str | bytes,
        hash: str | bytes,
        update: UpdateHashCallable | PasswordHashStore,
        *,
        load: LoadHashCallable | None = None,
    ) -> MigrationResult:
        """
        Verify a password and run the hash upgrade as a single transaction.

        Args:
            password: The password provided by the user.
            hash: The currently stored hash.
            update: Either a callable ``(old_hash, new_hash) -> None``
                persisting the upgrade, or a :class:`PasswordHashStore`.
            load: Optional callable returning the hash currently stored for
                the user, used to resolve lost concurrent upgrades. Ignored
                when ``update`` is a full :class:`PasswordHashStore`.

        Returns:
            A :class:`MigrationResult` describing authentication, upgrade and
            storage outcomes. A storage failure never turns a successful
            authentication into a failure.

        Raises:
            exceptions.UnknownHashError: If no configured hasher recognizes
                even the hash prefix.
            exceptions.CorruptedHashError: If the hash content is corrupted
                and the policy is configured to raise.
        """
        started_at = time.perf_counter()
        validate_str_or_bytes(password, "password")
        validate_str_or_bytes(hash, "hash")

        if hasattr(update, "load_hash") and hasattr(update, "update_hash"):
            store = typing.cast(PasswordHashStore, update)
            update_hash: UpdateHashCallable = store.update_hash
            load_hash: LoadHashCallable | None = store.load_hash
        else:
            update_hash = typing.cast(UpdateHashCallable, update)
            load_hash = load

        try:
            result = self._run_transaction(password, hash, update_hash, load_hash)
        finally:
            self._enforce_min_time(started_at)
        return result

    def _enforce_min_time(self, started_at: float) -> None:
        if self.min_verification_time <= 0:
            return
        elapsed = time.perf_counter() - started_at
        remaining = self.min_verification_time - elapsed
        if remaining > 0:
            time.sleep(remaining)

    def _run_transaction(
        self,
        password: str | bytes,
        hash: str | bytes,
        update_hash: UpdateHashCallable,
        load_hash: LoadHashCallable | None,
    ) -> MigrationResult:
        hasher, prefix_hasher = _resolve_hasher(self.password_hash.hashers, hash)
        if hasher is None:
            if prefix_hasher is not None:
                return self._corrupted_result(hash, prefix_hasher.algorithm)
            raise exceptions.UnknownHashError(hash)

        algorithm = hasher.algorithm
        hash_str = hash.decode("utf-8") if isinstance(hash, bytes) else hash

        # Serialize concurrent transactions on the same stored hash. Different
        # hashes use different locks and keep running concurrently.
        lock = self._get_hash_lock(hash_str)
        with lock:
            stored_hash = self._load_committed_hash(hash_str, load_hash)
            if stored_hash is not None and stored_hash != hash_str:
                committed_hasher, committed_prefix = _resolve_hasher(
                    self.password_hash.hashers, stored_hash
                )
                committed_algorithm = (
                    committed_hasher.algorithm
                    if committed_hasher is not None
                    else (
                        committed_prefix.algorithm
                        if committed_prefix is not None
                        else None
                    )
                )
                return MigrationResult(
                    authenticated=True,
                    upgraded=False,
                    status=MigrationStatus.ALREADY_MIGRATED,
                    failure_reason=MigrationFailureReason.NONE,
                    algorithm=committed_algorithm,
                    final_hash=stored_hash,
                )

            try:
                is_valid = hasher.verify(password, hash)
            except Exception as exc:  # noqa: BLE001 - backend-specific errors
                # A structurally valid hash that blows up the backend is still
                # a corrupted record, never a wrong password.
                result = self._corrupted_result(hash, algorithm)
                result.error = exc
                return result

            if not is_valid:
                return MigrationResult(
                    authenticated=False,
                    upgraded=False,
                    status=MigrationStatus.INVALID_PASSWORD,
                    failure_reason=MigrationFailureReason.INVALID_PASSWORD,
                    algorithm=algorithm,
                    final_hash=hash_str,
                )

            needs_upgrade = self.upgrade_on_success and (
                not self._is_target_hasher(hasher) or hasher.check_needs_rehash(hash)
            )
            if not needs_upgrade:
                return MigrationResult(
                    authenticated=True,
                    upgraded=False,
                    status=MigrationStatus.SUCCESS,
                    failure_reason=MigrationFailureReason.NONE,
                    algorithm=algorithm,
                    final_hash=hash_str,
                )

            new_hash = self.target_hasher.hash(password)
            try:
                update_hash(hash_str, new_hash)
            except Exception as exc:  # noqa: BLE001 - storage backend errors
                # Authentication already succeeded: a storage failure must not
                # lock the user out, and the generated hash is returned so
                # the caller can retry the commit.
                return MigrationResult(
                    authenticated=True,
                    upgraded=False,
                    status=MigrationStatus.STORAGE_ERROR,
                    failure_reason=MigrationFailureReason.STORAGE_ERROR,
                    algorithm=algorithm,
                    final_hash=new_hash,
                    error=exc,
                )

            return MigrationResult(
                authenticated=True,
                upgraded=True,
                status=MigrationStatus.UPGRADED,
                failure_reason=MigrationFailureReason.NONE,
                algorithm=self.target_hasher.algorithm,
                final_hash=new_hash,
            )

    def _load_committed_hash(
        self, old_hash: str, load_hash: LoadHashCallable | None
    ) -> str | None:
        if load_hash is None:
            return None
        try:
            stored_hash = load_hash(old_hash)
        except Exception:  # noqa: BLE001 - storage is best-effort here
            return None
        if not stored_hash or stored_hash == old_hash:
            return None
        # Only a recognizable hash counts as a committed upgrade. An empty or
        # unreadable value must not masquerade as a successful migration.
        hasher, prefix_hasher = _resolve_hasher(self.password_hash.hashers, stored_hash)
        if hasher is None and prefix_hasher is None:
            return None
        return stored_hash
