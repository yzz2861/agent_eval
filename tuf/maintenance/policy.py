"""Visibility policies for scoped maintenance diff reviews."""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable, Mapping  # noqa: TC003
from dataclasses import dataclass, field
from types import MappingProxyType

from tuf.maintenance._errors import PolicyChangedError


@dataclass(frozen=True)
class ScopePolicy:
    """Immutable mapping of target paths to maintenance scopes.

    A maintenance group may only view target paths that are explicitly owned
    by its scope. Targets that are not listed in ``owners`` are assigned to
    ``reviewer_scope`` so that new or unrecognized paths fail closed instead
    of being exposed to every maintenance group.

    Args:
        version: Monotonically increasing policy version.
        owners: Mapping of target path to maintenance scope name. It should
            cover both previous and updated paths so that removals remain
            attributable to the correct group.
        reviewer_scope: Scope allowed to see the complete, unfiltered review.
    """

    version: int
    owners: Mapping[str, str]
    reviewer_scope: str = "security-operations"
    _fingerprint: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.version < 1:
            raise ValueError("policy version must be positive")
        if not self.reviewer_scope:
            raise ValueError("reviewer_scope must not be empty")

        copied = dict(self.owners)
        for path, scope in copied.items():
            if not path:
                raise ValueError("target path must not be empty")
            if not scope:
                raise ValueError("scope name must not be empty")

        object.__setattr__(self, "owners", MappingProxyType(copied))
        object.__setattr__(self, "_fingerprint", self._compute_fingerprint())

    def _compute_fingerprint(self) -> str:
        canonical = json.dumps(
            {
                "version": self.version,
                "reviewer_scope": self.reviewer_scope,
                "owners": sorted(self.owners.items()),
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @property
    def fingerprint(self) -> str:
        """Content hash covering the version, reviewer scope, and owners."""
        return self._fingerprint

    def scope_of(self, target_path: str) -> str:
        """Return the scope that owns ``target_path``.

        Unknown paths belong to the reviewer scope. This makes the fallback
        fail closed: maintenance scopes cannot see paths that security
        operations has not explicitly assigned.
        """
        return self.owners.get(target_path, self.reviewer_scope)

    def is_reviewer(self, scope: str) -> bool:
        """Return whether ``scope`` is the security operations scope."""
        return scope == self.reviewer_scope

    def maintenance_scopes(self) -> frozenset[str]:
        """Return the explicitly assigned, non-reviewer scope names."""
        return frozenset(
            scope
            for scope in self.owners.values()
            if scope != self.reviewer_scope
        )


class PolicyControl:
    """Owns the current :class:`ScopePolicy` and detects policy changes.

    A policy change is a versioned, observable event. In-flight notification
    batches register a callback and are abandoned immediately when a new
    policy version is installed. This prevents a batch from mixing
    notifications built under different visibility rules.
    """

    def __init__(self, policy: ScopePolicy) -> None:
        self._policy = policy
        self._callbacks: dict[int, Callable[[int, int], None]] = {}
        self._next_callback_id = 0
        self._lock = threading.RLock()

    @property
    def policy(self) -> ScopePolicy:
        """Return the current policy snapshot."""
        with self._lock:
            return self._policy

    @property
    def version(self) -> int:
        """Return the current policy version."""
        return self.policy.version

    def register(
        self, callback: Callable[[int, int], None]
    ) -> Callable[[], None]:
        """Register ``callback`` for policy changes.

        The callback receives the previous and the new policy version. The
        returned function unregisters the callback and is safe to call more
        than once.
        """
        with self._lock:
            callback_id = self._next_callback_id
            self._next_callback_id += 1
            self._callbacks[callback_id] = callback

        def unregister() -> None:
            with self._lock:
                self._callbacks.pop(callback_id, None)

        return unregister

    def replace(self, policy: ScopePolicy) -> int:
        """Install ``policy`` and notify every registered observer.

        Returns:
            The installed policy version.

        Raises:
            ValueError: If the new version does not increase.
        """
        with self._lock:
            old_version = self._policy.version
            if policy.version <= old_version:
                raise ValueError(
                    "new policy version must be greater than "
                    f"{old_version}, got {policy.version}"
                )
            self._policy = policy
            callbacks = tuple(self._callbacks.values())

        for callback in callbacks:
            callback(old_version, policy.version)

        return policy.version

    def assert_current(self, version: int) -> None:
        """Raise :class:`PolicyChangedError` if ``version`` is not current."""
        current = self.version
        if current != version:
            raise PolicyChangedError(version, current)
