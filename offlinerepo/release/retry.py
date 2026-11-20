# SPDX-License-Identifier: MIT OR Apache-2.0
"""Deterministic in-memory retry policy for the execution layer."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable

from .objectstore import TransientStorageError

T = TypeVar("T")


@dataclass
class RetryPolicy:
    """Retry transient storage failures with a fixed, injectable clock."""

    max_attempts: int = 3
    delay: float = 0.0
    sleep: Callable[[float], None] = time.sleep
    attempts: list[str] = field(default_factory=list)

    def run(self, label: str, op: Callable[[], T]) -> T:
        """Run ``op`` with retries; raise the last error if all fail."""
        last_error: TransientStorageError | None = None
        for attempt in range(1, self.max_attempts + 1):
            self.attempts.append(f"{label}#attempt{attempt}")
            try:
                return op()
            except TransientStorageError as exc:
                last_error = exc
                if attempt < self.max_attempts:
                    self.sleep(self.delay)
        if last_error is None:  # pragma: no cover - defensive guard
            msg = "retry loop exited without a result or error"
            raise RuntimeError(msg)
        raise last_error
