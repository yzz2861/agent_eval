import dataclasses
import re

try:
    import argon2.exceptions
    from argon2 import PasswordHasher
except ImportError as e:  # pragma: no cover
    from ..exceptions import HasherNotAvailable

    raise HasherNotAvailable("argon2") from e

from ..exceptions import HashVerificationPolicyError
from .base import HasherProtocol, ensure_str, validate_str_or_bytes

# Pattern for identifying and validating an Argon2 encoded hash, covering all currently
# supported type variants (i.e., `id`, `i`, `d`). Pattern uses deterministic matching,
# explicit anchors, and a non-greedy terminal quantifier to ensure linear run time
# relative to input hash length and resilience against catastrophic backtracking attacks.
ARGON2_ENCODED_HASH_REGEX: re.Pattern = re.compile(
    r"^\$(?P<variant>argon2(id|i|d))\$(?:v=(?P<version>\d+)\$)?"
    r"m=(?P<memory_cost>\d+),t=(?P<time_cost>\d+),p=(?P<parallelism>\d+)"
    r"(?:\$(?P<salt>[^$]+)(?:\$(?P<digest>.+?))?)?$"
)

# Default upper bound for the full encoded hash size. Regular Argon2 hashes
# are well below this limit; it exists as a last resort guard against
# oversized payloads stored in the hash column.
DEFAULT_MAX_ENCODED_SIZE: int = 1024


class PolicyViolationReason:
    """Stable, machine readable reasons for a policy violation.

    The order below is also the order in which the checks are evaluated,
    guaranteeing a deterministic ``first reason`` when several parameters
    exceed their budget at the same time.
    """

    UNRECOGNIZED_HASH = "unrecognized_hash"
    MISSING_COMPONENTS = "missing_components"
    ENCODED_SIZE = "encoded_size_exceeded"
    MEMORY_COST = "memory_cost_exceeded"
    TIME_COST = "time_cost_exceeded"
    PARALLELISM = "parallelism_exceeded"
    SALT_LEN = "salt_len_exceeded"
    HASH_LEN = "hash_len_exceeded"


def _decoded_str_len(length: int) -> int:
    """Compute how many bytes an unpadded Base64 string of ``length`` decodes to."""
    rem = length % 4
    if rem == 3:
        last_group_len = 2
    elif rem == 2:
        last_group_len = 1
    else:
        last_group_len = 0
    return length // 4 * 3 + last_group_len


@dataclasses.dataclass(frozen=True)
class Argon2VerificationPolicy:
    """Explicit verification budget enforced before calling the Argon2 backend.

    Every limit is an **upper bound** parsed directly from the encoded hash
    with a regular expression. No memory is allocated by the Argon2 backend
    while the policy is evaluated, so a tampered hash can never trigger a
    large allocation.

    Args:
        max_memory_cost: Maximum allowed ``m`` parameter, in kibibytes.
        max_time_cost: Maximum allowed ``t`` parameter (iterations).
        max_parallelism: Maximum allowed ``p`` parameter (threads).
        max_salt_len: Maximum allowed decoded salt length, in bytes.
        max_hash_len: Maximum allowed decoded digest length, in bytes.
        max_encoded_size: Maximum allowed size of the whole encoded hash,
            in characters.

    A hash exceeding one of these limits raises
    :class:`pwdlib.exceptions.HashVerificationPolicyError` with a stable
    :attr:`~pwdlib.exceptions.HashVerificationPolicyError.reason`. Callers
    can catch it and treat the hash as needing migration instead of an
    incorrect password. Checks run in a fixed order (encoded size, memory
    cost, time cost, parallelism, salt length, hash length), so the first
    reported reason is deterministic.
    """

    max_memory_cost: int = argon2.DEFAULT_MEMORY_COST
    max_time_cost: int = argon2.DEFAULT_TIME_COST
    max_parallelism: int = argon2.DEFAULT_PARALLELISM
    max_salt_len: int = argon2.DEFAULT_RANDOM_SALT_LENGTH
    max_hash_len: int = argon2.DEFAULT_HASH_LENGTH
    max_encoded_size: int = DEFAULT_MAX_ENCODED_SIZE

    def __post_init__(self) -> None:
        for field in dataclasses.fields(self):
            value = getattr(self, field.name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{field.name} must be an integer")  # noqa: TRY003
            if value <= 0:
                raise ValueError(f"{field.name} must be strictly positive")  # noqa: TRY003

    def check(self, hash: str) -> None:
        """Validate an encoded Argon2 hash against the budget.

        Args:
            hash: An encoded Argon2 hash.

        Raises:
            pwdlib.exceptions.HashVerificationPolicyError: If the hash does
                not comply with the configured budget. The raw hash is never
                included in the error.
        """
        match = ARGON2_ENCODED_HASH_REGEX.fullmatch(hash)
        if match is None:
            raise HashVerificationPolicyError(
                PolicyViolationReason.UNRECOGNIZED_HASH,
                "The hash is not a recognizable Argon2 encoded hash.",
            )

        if len(hash) > self.max_encoded_size:
            raise HashVerificationPolicyError(
                PolicyViolationReason.ENCODED_SIZE,
                f"The encoded hash size exceeds the maximum allowed size "
                f"of {self.max_encoded_size} characters.",
            )

        memory_cost = int(match.group("memory_cost"))
        if memory_cost > self.max_memory_cost:
            raise HashVerificationPolicyError(
                PolicyViolationReason.MEMORY_COST,
                f"The Argon2 memory cost ({memory_cost} KiB) exceeds the "
                f"maximum allowed value of {self.max_memory_cost} KiB.",
            )

        time_cost = int(match.group("time_cost"))
        if time_cost > self.max_time_cost:
            raise HashVerificationPolicyError(
                PolicyViolationReason.TIME_COST,
                f"The Argon2 time cost ({time_cost}) exceeds the maximum "
                f"allowed value of {self.max_time_cost}.",
            )

        parallelism = int(match.group("parallelism"))
        if parallelism > self.max_parallelism:
            raise HashVerificationPolicyError(
                PolicyViolationReason.PARALLELISM,
                f"The Argon2 parallelism ({parallelism}) exceeds the maximum "
                f"allowed value of {self.max_parallelism}.",
            )

        salt = match.group("salt")
        digest = match.group("digest")
        if salt is None or digest is None:
            raise HashVerificationPolicyError(
                PolicyViolationReason.MISSING_COMPONENTS,
                "The Argon2 hash is missing its salt or digest component.",
            )

        salt_len = _decoded_str_len(len(salt))
        if salt_len > self.max_salt_len:
            raise HashVerificationPolicyError(
                PolicyViolationReason.SALT_LEN,
                f"The Argon2 salt length ({salt_len} bytes) exceeds the "
                f"maximum allowed value of {self.max_salt_len} bytes.",
            )

        hash_len = _decoded_str_len(len(digest))
        if hash_len > self.max_hash_len:
            raise HashVerificationPolicyError(
                PolicyViolationReason.HASH_LEN,
                f"The Argon2 digest length ({hash_len} bytes) exceeds the "
                f"maximum allowed value of {self.max_hash_len} bytes.",
            )


class Argon2Hasher(HasherProtocol):
    def __init__(
        self,
        time_cost: int = argon2.DEFAULT_TIME_COST,
        memory_cost: int = argon2.DEFAULT_MEMORY_COST,
        parallelism: int = argon2.DEFAULT_PARALLELISM,
        hash_len: int = argon2.DEFAULT_HASH_LENGTH,
        salt_len: int = argon2.DEFAULT_RANDOM_SALT_LENGTH,
        type: argon2.Type = argon2.Type.ID,
        *,
        verification_policy: Argon2VerificationPolicy | None = None,
    ) -> None:
        """

        Args:
            time_cost: Defines the amount of computation realized and
                therefore the execution time, given in number of iterations.
            memory_cost: Defines the memory usage, given in kibibytes.
            parallelism: Defines the number of parallel threads (*changes*
                the resulting hash value).
            hash_len: Length of the hash in bytes.
            salt_len: Length of random salt to be generated for each
                password.
            type: Argon2 type to use.  Only change for interoperability
                with legacy systems.
            verification_policy: Optional explicit verification budget. When
                set, every hash is validated against it *before* the Argon2
                backend is invoked. When ``None`` (default), verification
                behaves exactly like the underlying library and no policy is
                enforced.

        """
        self._hasher = PasswordHasher(
            time_cost, memory_cost, parallelism, hash_len, salt_len, "utf-8", type
        )
        self._time_cost = time_cost
        self._memory_cost = memory_cost
        self._parallelism = parallelism
        self._hash_len = hash_len
        self._salt_len = salt_len
        self._type = type
        self._verification_policy = verification_policy

    @property
    def verification_policy(self) -> Argon2VerificationPolicy | None:
        """The verification policy enforced by this hasher, if any."""
        return self._verification_policy

    def with_verification_policy(
        self, verification_policy: Argon2VerificationPolicy
    ) -> "Argon2Hasher":
        """Return a copy of this hasher enforcing the given verification policy."""
        return Argon2Hasher(
            time_cost=self._time_cost,
            memory_cost=self._memory_cost,
            parallelism=self._parallelism,
            hash_len=self._hash_len,
            salt_len=self._salt_len,
            type=self._type,
            verification_policy=verification_policy,
        )

    @classmethod
    def identify(cls, hash: str | bytes) -> bool:
        validate_str_or_bytes(hash, "hash")
        try:
            hash_str = ensure_str(hash)
        except UnicodeDecodeError:
            return False
        match = ARGON2_ENCODED_HASH_REGEX.fullmatch(hash_str)
        if match is None:
            return False
        variant: str = match.group("variant")
        return variant in {"argon2id", "argon2i", "argon2d"}

    def hash(self, password: str | bytes, *, salt: bytes | None = None) -> str:
        validate_str_or_bytes(password, "password")
        return self._hasher.hash(password, salt=salt)

    def verify(self, password: str | bytes, hash: str | bytes) -> bool:
        validate_str_or_bytes(password, "password")
        validate_str_or_bytes(hash, "hash")
        if self._verification_policy is not None:
            try:
                hash_str = ensure_str(hash)
            except UnicodeDecodeError:
                return False
            if not self.identify(hash_str):
                return False
            self._verification_policy.check(hash_str)
        try:
            return self._hasher.verify(hash, password)
        except (
            argon2.exceptions.VerificationError,
            argon2.exceptions.InvalidHashError,
        ):
            return False

    def check_needs_rehash(self, hash: str | bytes) -> bool:
        validate_str_or_bytes(hash, "hash")
        return self._hasher.check_needs_rehash(ensure_str(hash))
