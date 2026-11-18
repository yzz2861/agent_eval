"""Domain-separated, irreversible identities used by derivation analysis.

Nothing in this module is reversible, and nothing here is shared across
domains: every digest is keyed with a per-domain HMAC key, so an identity
computed for one purpose (e.g. an observed candidate) can never be confused
with one computed for another (e.g. a derived group). Plaintext secrets are
only ever accepted as function arguments and are never stored.
"""
import hashlib
import hmac
from typing import List


# Fixed, non-secret module key. HMAC here provides *domain separation*, not
# confidentiality of the key: digesting the same value under different domains
# yields unrelated identifiers, while the one-way property keeps the plaintext
# unrecoverable from any persisted artifact.
_MODULE_KEY = b"detect-secrets.derivation.v1"

DOMAIN_OCCURRENCE = "occurrence.v1"
DOMAIN_VALUE = "intermediate-value.v1"
DOMAIN_GROUP = "derived-group.v1"
DOMAIN_RELATIONSHIP = "unverified-relationship.v1"

# Bump if the digest input format ever changes in a non-compatible way.
IDENTITY_SCHEMA_VERSION = 1
SCHEMA_VERSION = IDENTITY_SCHEMA_VERSION


def _digest(domain: str, message: bytes) -> str:
    domain_key = hmac.new(_MODULE_KEY, domain.encode("utf-8"), hashlib.sha256).digest()
    return hmac.new(domain_key, message, hashlib.sha256).hexdigest()


def occurrence_identity(
    tenant: str,
    secret_type: str,
    filename: str,
    line_number: int,
    secret: str,
) -> str:
    """Stable identifier for one observed candidate location."""
    message = b"\x1f".join(
        [
            tenant.encode("utf-8"),
            secret_type.encode("utf-8"),
            filename.encode("utf-8"),
            str(int(line_number)).encode("ascii"),
            secret.encode("utf-8"),
        ],
    )
    return _digest(DOMAIN_OCCURRENCE, message)


def value_identity(value: str) -> str:
    """Stable identifier for a decoded (intermediate or canonical) value.

    Deliberately tenant-agnostic: identical decoded plaintext maps to the
    same intermediate identity, which is what lets two encoded observations
    prove they decode to the same underlying secret. The occurrence and
    group identities (which carry the tenant label) remain tenant-scoped
    and provide the cross-tenant isolation boundary.
    """
    return _digest(DOMAIN_VALUE, value.encode("utf-8"))


def group_identity(root_value_id: str, member_occurrence_ids: List[str]) -> str:
    """Order-independent identifier for a group of merged occurrences."""
    message = b"\x1f".join(
        [
            root_value_id.encode("ascii"),
            b"\x1e".join(
                sorted(item.encode("ascii") for item in member_occurrence_ids),
            ),
        ],
    )
    return _digest(DOMAIN_GROUP, message)


def relationship_identity(
    tenant: str,
    left_occurrence_id: str,
    right_occurrence_id: str,
) -> str:
    """Order-independent identifier for an unverifiable candidate pair."""
    ordered = sorted([left_occurrence_id, right_occurrence_id])
    message = b"\x1f".join(
        [
            tenant.encode("utf-8"),
            ordered[0].encode("ascii"),
            ordered[1].encode("ascii"),
        ],
    )
    return _digest(DOMAIN_RELATIONSHIP, message)


def mask_secret(secret: str) -> str:
    """Return a non-reversible, human-triage-friendly rendering of a secret.

    Masks (and only masks) are allowed into reports for unverifiable pairs.
    Matching must never be performed on this output.
    """
    if not secret:
        return ""

    if len(secret) <= 8:
        return "*" * len(secret)

    return f"{secret[:2]}{chr(42) * (len(secret) - 6)}{secret[-4:]}"


# Canonical public names used by the analysis engine.
compute_occurrence_identity = occurrence_identity
compute_value_identity = value_identity
compute_group_identity = group_identity
compute_relationship_identity = relationship_identity
