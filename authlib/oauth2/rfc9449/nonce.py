from __future__ import annotations

from typing import Any
from typing import Protocol


class DPoPNoncePolicy(Protocol):
    def get_nonce(self, request: Any) -> str:
        """Return the nonce that the client must send in its next proof."""

    def issue(self, request: Any) -> str:
        """Compatibility alias for :meth:`get_nonce`."""
        return self.get_nonce(request)

    def validate(self, nonce: str | None, request: Any) -> bool:
        """Return whether the proof nonce satisfies server policy."""
