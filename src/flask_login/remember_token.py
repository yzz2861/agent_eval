"""Pluggable storage for rotating "remember me" tokens.

When remember-cookie rotation is enabled with the
``REMEMBER_COOKIE_ROTATION`` configuration, each remember cookie carries a
single-use token. Applications provide a :class:`RememberTokenStore`
implementation (backed by Redis, a database, or anything else) so the server
can keep track of which tokens have already been consumed.
"""

from dataclasses import dataclass
from datetime import datetime
from datetime import timezone
from enum import Enum
from threading import RLock
from typing import Optional


class TokenConsumeResult(Enum):
    """The result of :meth:`RememberTokenStore.consume_token`."""

    #: The token existed and had not been used before. It is now marked used.
    CONSUMED = "consumed"

    #: The token had already been consumed: this is a replay attempt.
    ALREADY_USED = "already_used"

    #: No record exists for the token (the family was revoked or the token
    #: was never issued).
    UNKNOWN = "unknown"


@dataclass
class RememberToken:
    """The server-side state of a single rotating remember token."""

    #: The id of the user the token authenticates.
    user_id: str

    #: Identifier shared by every token issued in the same login chain.
    family_id: str

    #: Unique, single-use identifier of this token.
    token_id: str

    #: Browser/session binding value carried by the cookie.
    identifier: str

    #: When the token was issued.
    created_at: datetime

    #: When the token expires.
    expires_at: datetime

    #: When the token was consumed, or ``None`` while it is still usable.
    consumed_at: Optional[datetime] = None


class RememberTokenStore:
    """Interface for storing rotating remember tokens.

    Implementations must be safe to share between requests. In particular
    :meth:`consume_token` has to perform the "consume once and mark used"
    transition atomically so that two concurrent requests presenting the same
    token cannot both succeed.
    """

    def save_token(self, token):
        """Persist a newly issued token.

        :param token: The :class:`RememberToken` to store.
        :type token: RememberToken
        """
        raise NotImplementedError

    def consume_token(self, family_id, token_id):
        """Atomically consume a single-use token.

        :param family_id: The token family id.
        :type family_id: str
        :param token_id: The single-use token id.
        :type token_id: str
        :rtype: TokenConsumeResult
        """
        raise NotImplementedError

    def get_token(self, family_id, token_id):
        """Return the stored token, or ``None`` if it does not exist."""
        raise NotImplementedError

    def revoke_family(self, family_id):
        """Invalidate every token belonging to the given family."""
        raise NotImplementedError

    def revoke_user_tokens(self, user_id):
        """Invalidate every remember token belonging to the given user."""
        raise NotImplementedError


class InMemoryRememberTokenStore(RememberTokenStore):
    """A process-local :class:`RememberTokenStore`.

    This is intended as a reference implementation and for testing; real
    applications should provide a durable, shared backend.
    """

    def __init__(self):
        self._lock = RLock()
        self._tokens = {}
        self._families = {}
        self._users = {}

    def save_token(self, token):
        key = (token.family_id, token.token_id)
        with self._lock:
            self._tokens[key] = token
            self._families.setdefault(token.family_id, set()).add(key)
            self._users.setdefault(str(token.user_id), set()).add(token.family_id)

    def consume_token(self, family_id, token_id):
        key = (family_id, token_id)
        with self._lock:
            token = self._tokens.get(key)
            if token is None:
                return TokenConsumeResult.UNKNOWN
            if token.consumed_at is not None:
                return TokenConsumeResult.ALREADY_USED
            token.consumed_at = datetime.now(timezone.utc)
            return TokenConsumeResult.CONSUMED

    def get_token(self, family_id, token_id):
        with self._lock:
            return self._tokens.get((family_id, token_id))

    def revoke_family(self, family_id):
        with self._lock:
            for key in self._families.pop(family_id, ()):  # type: ignore[arg-type]
                token = self._tokens.pop(key, None)
                if token is not None:
                    user_families = self._users.get(str(token.user_id))
                    if user_families is not None:
                        user_families.discard(family_id)

    def revoke_user_tokens(self, user_id):
        with self._lock:
            for family_id in list(self._users.pop(str(user_id), ())):
                for key in self._families.pop(family_id, ()):  # type: ignore[arg-type]
                    self._tokens.pop(key, None)
