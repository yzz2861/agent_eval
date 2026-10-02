import time
from typing import Any, Optional, Union

from .api_jwk import PyJWKSet, PyJWTSetWithTimestamp
from .exceptions import PyJWKSetError
from .jwk_import_policy import JWKImportPolicy


class JWKSetCache:
    def __init__(
        self,
        lifespan: float,
        import_policy: JWKImportPolicy | None = None,
    ) -> None:
        self.jwk_set_with_timestamp: Optional[PyJWTSetWithTimestamp] = None
        self.lifespan = lifespan
        self.import_policy = import_policy

    def put(self, jwk_set: Optional[Union[PyJWKSet, dict[str, Any]]]) -> None:
        """Cache *jwk_set*, or clear the cache when it is ``None``.

        Accepts either an already-parsed ``PyJWKSet`` or the raw JWKS
        payload it is parsed from, and always stores it parsed so that
        reads never have to parse the keys again. Raw payloads are parsed
        with the cache's import policy, if one was configured, so a cache
        hit can never serve keys the policy would have rejected.

        :raises PyJWKSetError: If *jwk_set* is neither a ``PyJWKSet`` nor a
            JWKS payload containing usable keys.
        """
        if jwk_set is None:
            # clear cache
            self.jwk_set_with_timestamp = None
            return

        if not isinstance(jwk_set, PyJWKSet):
            if not isinstance(jwk_set, dict):
                raise PyJWKSetError("Invalid JWK Set value")
            jwk_set = PyJWKSet.from_dict(jwk_set, import_policy=self.import_policy)

        self.jwk_set_with_timestamp = PyJWTSetWithTimestamp(jwk_set)

    def get(self) -> Optional[PyJWKSet]:
        if self.jwk_set_with_timestamp is None or self.is_expired():
            return None

        return self.jwk_set_with_timestamp.get_jwk_set()

    def is_expired(self) -> bool:
        return (
            self.jwk_set_with_timestamp is not None
            and self.lifespan > -1
            and time.monotonic()
            > self.jwk_set_with_timestamp.get_timestamp() + self.lifespan
        )
