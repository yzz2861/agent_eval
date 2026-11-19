# Adapters between detect-secrets scan results and the exception policy model.
#
# These helpers translate :class:`PotentialSecret` objects (or baseline dict
# entries, which only carry a hash) into policy :class:`Finding` objects. They
# never persist plaintext: the finding identity always reuses the one-way
# ``secret_hash`` that detect-secrets already computes, so a freshly scanned
# secret and a replayed baseline entry resolve to the same identity without any
# secret material being stored.
from typing import Any
from typing import Dict

from ..core.potential_secret import PotentialSecret
from .engine import Finding
from .identity import SecretIdentity
from .rules import RuleVersion
from .scope import Scope


def finding_from_potential_secret(
    secret: PotentialSecret,
    project: str,
    rule_version: str,
) -> Finding:
    # Identity is content/type based and ignores location, so moving the file
    # keeps the same identity while rotating the secret changes it.
    identity = SecretIdentity.from_potential_secret(secret)
    return Finding(
        secret_identity=identity,
        scope=Scope.from_string(project, secret.filename),
        rule=RuleVersion.parse(secret.type, rule_version),
        filename=secret.filename,
        line_number=secret.line_number,
    )


def finding_from_baseline_entry(
    filename: str,
    entry: Dict[str, Any],
    project: str,
    rule_versions: Dict[str, str],
) -> Finding:
    # Baseline entries contain only the hashed secret. The identity reuses the
    # baseline hash directly, keeping the replay path free of plaintext.
    secret_type = str(entry["type"])
    version = rule_versions.get(secret_type)
    if version is None:
        raise KeyError(
            f"no rule version supplied for secret type {secret_type!r}",
        )
    identity = SecretIdentity.from_hashed_secret(
        secret_type=secret_type,
        hashed_secret=str(entry["hashed_secret"]),
    )
    return Finding(
        secret_identity=identity,
        scope=Scope.from_string(project, filename),
        rule=RuleVersion.parse(secret_type, version),
        filename=filename,
        line_number=int(entry.get("line_number", 0)),
    )
