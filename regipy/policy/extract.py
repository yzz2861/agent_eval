"""Extraction of policy records from registry hives.

Extraction is intentionally separate from interpretation: this module only
turns registry values into :class:`~regipy.policy.models.PolicyRecord`
observations with a precise evidence reference.  Whether a record belongs to a
role, and what it means for that role, is decided later by the engine.
"""

import hashlib
import logging
import os
from collections.abc import Iterable
from typing import Optional

from regipy.exceptions import RegistryKeyNotFoundException, RegistryParsingException
from regipy.hive_types import (
    AMCACHE_HIVE_TYPE,
    BCD_HIVE_TYPE,
    NTUSER_HIVE_TYPE,
    SAM_HIVE_TYPE,
    SECURITY_HIVE_TYPE,
    SOFTWARE_HIVE_TYPE,
    SYSTEM_HIVE_TYPE,
    USRCLASS_HIVE_TYPE,
)
from regipy.policy.models import (
    MACHINE_SCOPE,
    USER_SCOPE,
    Evidence,
    PolicyContextException,
    PolicyRecord,
    normalize_path,
)
from regipy.registry import RegistryHive

logger = logging.getLogger(__name__)

MACHINE_POLICY_ROOTS = [
    r"\Policies",
    r"\Microsoft\Windows\CurrentVersion\Policies",
    r"\Wow6432Node\Policies",
    r"\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies",
]

USER_POLICY_ROOTS = [
    r"\Software\Policies",
    r"\Software\Microsoft\Windows\CurrentVersion\Policies",
    r"\Software\Wow6432Node\Policies",
    r"\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies",
]

USRCLASS_POLICY_ROOTS = [
    r"\Local Settings\Software\Microsoft\Windows\CurrentVersion\Policies",
    r"\Software\Microsoft\Windows\CurrentVersion\Policies",
    r"\Software\Policies",
]

MACHINE_HIVE_TYPES = {
    SOFTWARE_HIVE_TYPE,
    SYSTEM_HIVE_TYPE,
    SAM_HIVE_TYPE,
    SECURITY_HIVE_TYPE,
    AMCACHE_HIVE_TYPE,
    BCD_HIVE_TYPE,
}

USER_HIVE_TYPES = {NTUSER_HIVE_TYPE, USRCLASS_HIVE_TYPE}


def infer_scope(hive_type: Optional[str] = None, hive_name: Optional[str] = None) -> Optional[str]:
    """Infer the policy scope from a hive type, falling back to the hive name."""
    normalized_type = (hive_type or "").lower()
    if normalized_type in USER_HIVE_TYPES:
        return USER_SCOPE
    if normalized_type in MACHINE_HIVE_TYPES:
        return MACHINE_SCOPE

    normalized_name = (hive_name or "").lower()
    if "ntuser" in normalized_name or "usrclass" in normalized_name:
        return USER_SCOPE
    return None


def default_policy_roots(scope: str, hive_type: Optional[str] = None) -> list[str]:
    """Return the well-known policy roots for a scope."""
    if (hive_type or "").lower() == USRCLASS_HIVE_TYPE:
        return list(USRCLASS_POLICY_ROOTS)
    if scope == USER_SCOPE:
        return list(USER_POLICY_ROOTS)
    return list(MACHINE_POLICY_ROOTS)


def hash_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def evidence_for_hive(
    hive: RegistryHive,
    hive_path: str,
    evidence_id: Optional[str] = None,
    scope: Optional[str] = None,
    description: Optional[str] = None,
    compute_sha256: bool = True,
) -> Evidence:
    """Build an evidence descriptor for an already loaded hive."""
    resolved_scope = scope or infer_scope(hive.hive_type, hive.name or hive_path)
    resolved_id = evidence_id or f"{resolved_scope or 'unknown'}:{os.path.basename(hive_path)}"
    return Evidence(
        evidence_id=resolved_id,
        hive_path=hive_path,
        hive_type=hive.hive_type,
        scope=resolved_scope,
        sha256=hash_file(hive_path) if compute_sha256 else None,
        description=description,
    )


def evidence_for_hive_path(
    hive_path: str,
    evidence_id: Optional[str] = None,
    scope: Optional[str] = None,
    description: Optional[str] = None,
    compute_sha256: bool = True,
) -> Evidence:
    """Load a hive just far enough to describe it as evidence."""
    hive = RegistryHive(hive_path)
    return evidence_for_hive(
        hive,
        hive_path,
        evidence_id=evidence_id,
        scope=scope,
        description=description,
        compute_sha256=compute_sha256,
    )


def extract_policy_records(
    hive: RegistryHive,
    evidence_id: str,
    scope: Optional[str] = None,
    key_roots: Optional[Iterable[str]] = None,
    value_names: Optional[Iterable[str]] = None,
    max_records: Optional[int] = None,
) -> list[PolicyRecord]:
    """Extract policy values from a hive without interpreting them.

    Args:
        hive: A loaded :class:`~regipy.registry.RegistryHive`.
        evidence_id: The evidence id that will be cited by every record.
        scope: ``machine`` or ``user``.  If omitted it is inferred from the hive.
        key_roots: Optional registry roots to walk.  Defaults to the known
            machine/user policy roots.
        value_names: Optional case-insensitive value-name filter.
        max_records: Optional safety limit for very large hives.
    """
    resolved_scope = scope or infer_scope(hive.hive_type, hive.name)
    if resolved_scope not in (MACHINE_SCOPE, USER_SCOPE):
        raise PolicyContextException(
            f"cannot infer machine/user policy scope for hive type {hive.hive_type!r}; pass scope explicitly"
        )

    roots = list(key_roots) if key_roots is not None else default_policy_roots(resolved_scope, hive.hive_type)
    wanted_names = {name.lower() for name in value_names} if value_names is not None else None
    records: list[PolicyRecord] = []
    seen = set()

    for root in roots:
        normalized_root = normalize_path(root)
        try:
            root_key = hive.get_key(normalized_root)
        except RegistryKeyNotFoundException:
            logger.debug("Policy root %s does not exist in %s", normalized_root, evidence_id)
            continue
        except (RegistryParsingException, OSError) as exc:
            logger.warning("Could not open policy root %s in %s: %s", normalized_root, evidence_id, exc)
            continue

        try:
            subkeys = hive.recurse_subkeys(
                root_key,
                path_root=normalized_root,
                as_json=True,
                fetch_values=True,
            )
            for subkey in subkeys:
                values = subkey.values or []
                for value in values:
                    value_name = value.get("name") or "(default)"
                    if wanted_names is not None and value_name.lower() not in wanted_names:
                        continue
                    dedupe_key = (subkey.path.lower(), value_name.lower())
                    if dedupe_key in seen:
                        continue
                    seen.add(dedupe_key)
                    records.append(
                        PolicyRecord(
                            evidence_id=evidence_id,
                            scope=resolved_scope,
                            key_path=subkey.path,
                            value_name=value_name,
                            value=value.get("value"),
                            value_type=value.get("value_type"),
                            last_write=subkey.timestamp,
                            source=f"hive:{hive.hive_type or 'unknown'}",
                            metadata={
                                "subkey_name": subkey.subkey_name,
                                "is_corrupted": bool(value.get("is_corrupted")),
                            },
                        )
                    )
                    if max_records is not None and len(records) >= max_records:
                        return records
        except RegistryParsingException as exc:
            logger.warning("Could not fully parse policy root %s in %s: %s", normalized_root, evidence_id, exc)

    logger.debug("Extracted %d policy records from %s", len(records), evidence_id)
    return records


def extract_from_hive_path(
    hive_path: str,
    evidence_id: Optional[str] = None,
    scope: Optional[str] = None,
    key_roots: Optional[Iterable[str]] = None,
    value_names: Optional[Iterable[str]] = None,
    max_records: Optional[int] = None,
    compute_sha256: bool = True,
) -> tuple[Evidence, list[PolicyRecord]]:
    """Convenience wrapper: load a hive, describe it, and extract its policies."""
    hive = RegistryHive(hive_path)
    evidence = evidence_for_hive(
        hive,
        hive_path,
        evidence_id=evidence_id,
        scope=scope,
        compute_sha256=compute_sha256,
    )
    records = extract_policy_records(
        hive,
        evidence.evidence_id,
        scope=evidence.scope,
        key_roots=key_roots,
        value_names=value_names,
        max_records=max_records,
    )
    return evidence, records
