"""Content-based identity for a secret finding.

The upstream ``PotentialSecret`` identity includes the file name, so moving a
file silently drops any prior audit decision, while replacing the secret value
keeps the stale ``is_secret`` marker because the baseline entry is keyed by
location.  This module derives an identity from *what the secret is* instead
of *where it lives*:

* the identity changes whenever the secret content (or its type) changes, so a
  rotated key never inherits an existing exception;
* the identity ignores the file path and line number, so a move preserves it.

Only a one-way hash is ever retained.  Plaintext is consumed by the hashing
function and never written back to a record or serialized anywhere.
"""
from dataclasses import dataclass
from typing import Any
from typing import Dict

from ..core.potential_secret import PotentialSecret


def _hash(value: str) -> str:
    """Reuse the upstream hashing primitive so baseline hashes stay compatible."""
    return PotentialSecret.hash_secret(value)


@dataclass(frozen=True)
class SecretIdentity:
    """Stable, content-derived identifier for a secret.

    :param secret_type: plugin / rule that produced the finding (e.g.
        ``"AWSKeyDetector"``).  Included so two different rule families can
        never share an identity even on a hash collision.
    :param content_hash: SHA-1 hex digest of the secret value, optionally
        namespaced by the secret type to avoid cross-type collisions.
    """

    secret_type: str
    content_hash: str

    @staticmethod
    def from_plaintext(secret_type: str, secret_value: str) -> 'SecretIdentity':
        if not isinstance(secret_value, str) or secret_value == '':
            raise ValueError('secret_value must be a non-empty string')
        if not isinstance(secret_type, str) or secret_type == '':
            raise ValueError('secret_type must be a non-empty string')

        # Namespacing by type makes the hash collision-resistant across rules.
        return SecretIdentity(
            secret_type=secret_type,
            content_hash=_hash(f'{secret_type}\x00{secret_value}'),
        )

    @staticmethod
    def from_hashed_secret(secret_type: str, hashed_secret: str) -> 'SecretIdentity':
        """Build an identity from an already-hashed baseline secret.

        Baselines only persist ``hashed_secret`` (a bare SHA-1 of the value).
        We cannot re-apply the type namespacing without the plaintext, so this
        constructor accepts the upstream hash directly.  Identities built from
        plaintext and from hashes therefore use distinct hash spaces; use the
        same constructor for every finding in a given pipeline.
        """
        if not isinstance(hashed_secret, str) or hashed_secret == '':
            raise ValueError('hashed_secret must be a non-empty string')
        if not isinstance(secret_type, str) or secret_type == '':
            raise ValueError('secret_type must be a non-empty string')

        return SecretIdentity(secret_type=secret_type, content_hash=hashed_secret)

    @staticmethod
    def from_potential_secret(secret: PotentialSecret) -> 'SecretIdentity':
        """Derive the identity without reading plaintext from a baseline entry."""
        return SecretIdentity.from_hashed_secret(
            secret_type=secret.type,
            hashed_secret=secret.secret_hash,
        )

    def to_dict(self) -> Dict[str, str]:
        return {
            'secret_type': self.secret_type,
            'content_hash': self.content_hash,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'SecretIdentity':
        try:
            return SecretIdentity(
                secret_type=str(data['secret_type']),
                content_hash=str(data['content_hash']),
            )
        except KeyError as error:
            raise ValueError(f'missing identity field: {error.args[0]}') from error

    def __str__(self) -> str:
        # Never render the full hash in logs by default; a short prefix suffices.
        return f'{self.secret_type}:{self.content_hash[:12]}'
