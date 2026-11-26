"""Offline retention rehearsal for TUF client caches.

This module is intentionally side-effect free.  It computes what a disk
cleanup *would* remove from local inventory; it never accesses the network and
never deletes files.
"""

# The coercion boundary intentionally accepts heterogeneous dictionaries,
# TUF objects, dataclasses, and test doubles.
# ruff: noqa: ANN401, C901, D102, PLR0911, PLR0912, PLR0915, PLC0415, RUF001, T201

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class _StrEnum(StrEnum):
    """String enum whose ``str()`` is the stable wire value."""


class InstallState(_StrEnum):
    """The three crash windows for a half-completed installation.

    The canonical values describe whether progress is at the trusted metadata,
    target material, or activation/health-observation stage.  Common external
    spellings are accepted as aliases by :func:`normalize_install_state`.
    """

    METADATA_STAGED = "metadata_staged"
    TARGET_STAGED = "target_staged"
    HEALTH_OBSERVATION = "health_observation"

    # Metadata-stage aliases.
    METADATA_ONLY = "metadata_staged"
    PARTIAL_METADATA = "metadata_staged"
    METADATA_DOWNLOADED = "metadata_staged"
    STAGED_METADATA = "metadata_staged"
    AWAITING_TARGET = "metadata_staged"

    # Target-stage aliases.  A partial/unverified download remains in this
    # phase, but the planner does not treat its bytes as rollback material.
    TARGET_DOWNLOADED = "target_staged"
    TARGET_DOWNLOAD = "target_staged"
    DOWNLOADING = "target_staged"
    DOWNLOAD_PARTIAL = "target_staged"
    PARTIAL_DOWNLOAD = "target_staged"
    UNVERIFIED_TARGET = "target_staged"
    TARGET_UNVERIFIED = "target_staged"
    STAGED_TARGET = "target_staged"
    DOWNLOAD_COMPLETE = "target_staged"

    # Activation / health-stage aliases.
    OBSERVING = "health_observation"
    UNDER_OBSERVATION = "health_observation"
    PENDING_HEALTH = "health_observation"
    HEALTH_CHECK_PENDING = "health_observation"
    INSTALLED_PENDING_HEALTH = "health_observation"
    INSTALL_INTERRUPTED = "health_observation"
    HALF_INSTALLED = "health_observation"
    SWAP_PENDING = "health_observation"
    ACTIVATION_PENDING = "health_observation"
    POST_INSTALL = "health_observation"


# Convenient upper-case aliases for callers that prefer noun-style names.
HalfInstallState = InstallState
PartialInstallState = InstallState


class HealthStatus(_StrEnum):
    """Health statuses relevant to rollback retention."""

    APPROVED = "approved"
    CURRENT = "current"
    HEALTHY = "healthy"
    OBSERVING = "observing"
    UNDER_OBSERVATION = "observing"
    PENDING = "observing"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    UNKNOWN = "unknown"


class Reason:
    """Stable reason codes used in retention decisions."""

    TRUSTED_REFERENCE = "trusted_metadata_reference"
    RETENTION_QUOTA = "retention_quota"
    HEALTH_OBSERVATION = "health_observation_rollback"
    APPROVED_ROLLBACK = "approved_rollback_material"
    ACTIVE_VERSION = "active_install"
    PENDING_INSTALL = "pending_install"
    STAGED_TARGET = "staged_target_resume"
    APPROVAL_GENERATION = "approval_generation_dependency"
    DEPENDENCY = "metadata_dependency"
    EXPLICIT_PIN = "explicit_pin"
    SHARED_CONTENT = "shared_content_still_referenced"
    UNPROTECTED = "outside_retention_policy"
    PARTIAL_RECLAIMABLE = "unverified_partial_download_reclaimable"
    PARTIAL_DOWNLOAD = "partial_download_reclaimable"
    UNVERIFIED_TARGET = "unverified_target_reclaimable"


@dataclass(frozen=True)
class RetentionPolicy:
    """Retention quota and safety switches."""

    keep_versions: int | Mapping[str, int] | None = None
    max_bytes: int | None = None
    keep_approved: bool = True
    keep_under_observation: bool = True
    retain_pending_installs: bool = True


RetentionQuota = RetentionPolicy
RetentionBudget = RetentionPolicy


_STATE_SPELLINGS = {
    "metadata": InstallState.METADATA_STAGED,
    "metadata-half": InstallState.METADATA_STAGED,
    "half-metadata": InstallState.METADATA_STAGED,
    "metadata-staged": InstallState.METADATA_STAGED,
    "metadata_only": InstallState.METADATA_STAGED,
    "metadata-only": InstallState.METADATA_STAGED,
    "partial_metadata": InstallState.METADATA_STAGED,
    "partial-metadata": InstallState.METADATA_STAGED,
    "metadata_downloaded": InstallState.METADATA_STAGED,
    "metadata-downloaded": InstallState.METADATA_STAGED,
    "staged_metadata": InstallState.METADATA_STAGED,
    "staged-metadata": InstallState.METADATA_STAGED,
    "awaiting_target": InstallState.METADATA_STAGED,
    "metadata_ready": InstallState.METADATA_STAGED,
    "metadata_complete": InstallState.METADATA_STAGED,
    "metadata_synced": InstallState.METADATA_STAGED,
    "trust_updated": InstallState.METADATA_STAGED,
    "approval_staged": InstallState.METADATA_STAGED,
    "target": InstallState.TARGET_STAGED,
    "target-half": InstallState.TARGET_STAGED,
    "target-staged": InstallState.TARGET_STAGED,
    "target_staged": InstallState.TARGET_STAGED,
    "target_downloaded": InstallState.TARGET_STAGED,
    "target-downloaded": InstallState.TARGET_STAGED,
    "downloaded": InstallState.TARGET_STAGED,
    "downloading": InstallState.TARGET_STAGED,
    "download-partial": InstallState.TARGET_STAGED,
    "download_partial": InstallState.TARGET_STAGED,
    "partial-download": InstallState.TARGET_STAGED,
    "partial_download": InstallState.TARGET_STAGED,
    "unverified": InstallState.TARGET_STAGED,
    "unverified_target": InstallState.TARGET_STAGED,
    "target_unverified": InstallState.TARGET_STAGED,
    "staged_target": InstallState.TARGET_STAGED,
    "staged-target": InstallState.TARGET_STAGED,
    "download_complete": InstallState.TARGET_STAGED,
    "download-complete": InstallState.TARGET_STAGED,
    "downloaded_verified": InstallState.TARGET_STAGED,
    "verified_staged": InstallState.TARGET_STAGED,
    "target_ready": InstallState.TARGET_STAGED,
    "target_verified": InstallState.TARGET_STAGED,
    "artifact_staged": InstallState.TARGET_STAGED,
    "artifact_downloaded": InstallState.TARGET_STAGED,
    "artifact_verified": InstallState.TARGET_STAGED,
    "blob_verified": InstallState.TARGET_STAGED,
    "download_verified": InstallState.TARGET_STAGED,
    "verify": InstallState.TARGET_STAGED,
    "verification_pending": InstallState.TARGET_STAGED,
    "staged": InstallState.TARGET_STAGED,
    "health": InstallState.HEALTH_OBSERVATION,
    "observation": InstallState.HEALTH_OBSERVATION,
    "health-observation": InstallState.HEALTH_OBSERVATION,
    "health_observation": InstallState.HEALTH_OBSERVATION,
    "observing": InstallState.HEALTH_OBSERVATION,
    "under-observation": InstallState.HEALTH_OBSERVATION,
    "under_observation": InstallState.HEALTH_OBSERVATION,
    "pending-health": InstallState.HEALTH_OBSERVATION,
    "pending_health": InstallState.HEALTH_OBSERVATION,
    "installed-pending-health": InstallState.HEALTH_OBSERVATION,
    "install-interrupted": InstallState.HEALTH_OBSERVATION,
    "install_interrupted": InstallState.HEALTH_OBSERVATION,
    "half-installed": InstallState.HEALTH_OBSERVATION,
    "half_installed": InstallState.HEALTH_OBSERVATION,
    "swap-pending": InstallState.HEALTH_OBSERVATION,
    "activation-pending": InstallState.HEALTH_OBSERVATION,
    "activation_pending": InstallState.HEALTH_OBSERVATION,
    "post_install": InstallState.HEALTH_OBSERVATION,
    "partial_install": InstallState.HEALTH_OBSERVATION,
    "installing": InstallState.HEALTH_OBSERVATION,
    "install_pending": InstallState.HEALTH_OBSERVATION,
    "commit_pending": InstallState.HEALTH_OBSERVATION,
    "commit_interrupted": InstallState.HEALTH_OBSERVATION,
    "switch_pending": InstallState.HEALTH_OBSERVATION,
    "switch_interrupted": InstallState.HEALTH_OBSERVATION,
    "activation_failed": InstallState.HEALTH_OBSERVATION,
    "health_check": InstallState.HEALTH_OBSERVATION,
    "canary": InstallState.HEALTH_OBSERVATION,
    "canary_observing": InstallState.HEALTH_OBSERVATION,
}


def normalize_install_state(value: Any) -> InstallState | None:
    """Return the canonical install state for many common spellings."""
    if value is None:
        return None
    if isinstance(value, InstallState):
        return value
    text = str(value).strip().lower()
    if not text:
        return None
    if text in _STATE_SPELLINGS:
        return _STATE_SPELLINGS[text]
    compact = text.replace(" ", "_").replace("-", "_")
    return _STATE_SPELLINGS.get(compact)


def _normalize_health(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    if text in {"observing", "under_observation", "pending_health", "watch"}:
        return Reason.HEALTH_OBSERVATION
    if text in {"approved", "current", "active", "golden", "known_good"}:
        return Reason.APPROVED_ROLLBACK
    if text == "healthy":
        return "healthy"
    return text


_ID_KEYS = (
    "id",
    "item_id",
    "key",
    "path",
    "filepath",
    "name",
    "target",
    "target_path",
)
_SIZE_KEYS = (
    "size",
    "bytes",
    "length",
    "occupied_bytes",
    "disk_bytes",
    "file_size",
    "disk_size",
    "bytes_used",
)
_DIGEST_KEYS = (
    "digest",
    "content_id",
    "content_hash",
    "sha256",
    "sha",
    "checksum",
    "hash",
)
_ARTIFACT_KEYS = (
    "artifact_id",
    "product_id",
    "package",
    "package_name",
    "target_name",
    "name",
    "artifact",
    "product",
)
_VERSION_KEYS = ("version", "release", "release_version", "revision", "v")
_GENERATION_KEYS = (
    "approval_generation",
    "generation",
    "approval_epoch",
    "epoch",
    "approval_revision",
    "approval_id",
)
_STATE_KEYS = (
    "install_state",
    "half_install_state",
    "installation_state",
    "install_phase",
    "installation_phase",
    "partial_state",
    "stage",
    "state",
    "status",
)
_HEALTH_KEYS = (
    "health",
    "health_state",
    "health_status",
    "observation",
    "observation_status",
)
_REQUIRES_KEYS = ("requires", "dependencies", "depends_on", "required_items")


def _data(obj: Any) -> dict[str, Any]:
    if obj is None:
        return {}
    if isinstance(obj, Mapping):
        return dict(obj)
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    return {
        key: getattr(obj, key) for key in dir(obj) if not key.startswith("_")
    }


def _first(
    mapping: Mapping[str, Any], keys: Iterable[str], default: Any = None
) -> Any:
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return default


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    return [value]


def _digest_parts(value: Any) -> set[str]:
    """Return matching keys for digest values and TUF hash dictionaries."""
    if value is None:
        return set()
    if isinstance(value, Mapping):
        values: list[Any] = []
        for algo, digest in value.items():
            values.append(str(digest))
            values.append(f"{algo}:{digest}")
        value = values
    elif not isinstance(value, (list, tuple, set, frozenset)):
        value = [value]

    keys: set[str] = set()
    for entry in value:
        text = str(entry).strip().lower()
        if not text:
            continue
        keys.add(text)
        if ":" in text:
            algo, _, digest = text.partition(":")
            keys.add(digest)
            keys.add(f"{algo}:{digest}")
        elif len(text) >= 32 and all(ch in "0123456789abcdef" for ch in text):
            keys.add(f"sha256:{text}")
    return keys


def _primary_digest(value: Any) -> str | None:
    """Return a stable ``algorithm:digest`` representation when possible."""
    if value is None:
        return None
    if isinstance(value, Mapping):
        for algorithm in ("sha256", "sha512"):
            if value.get(algorithm):
                return f"{algorithm}:{value[algorithm]}"
        for algorithm, digest in value.items():
            return f"{algorithm}:{digest}"
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    if (
        ":" not in text
        and len(text) >= 32
        and all(char in "0123456789abcdef" for char in text)
    ):
        return f"sha256:{text}"
    return text


def _version_key(value: Any) -> tuple[Any, ...]:
    if value is None:
        return ()
    if isinstance(value, int):
        return (value,)
    text = str(value)
    digits: list[int] = []
    current = ""
    for char in text:
        if char.isdigit():
            current += char
        elif current:
            digits.append(int(current))
            current = ""
    if current:
        digits.append(int(current))
    if digits:
        return tuple(digits)
    return (text,)


@dataclass
class Occupancy:
    """One occupied local item that may be reclaimed."""

    id: str
    kind: str = "file"
    size: int = 0
    digest: str | None = None
    artifact_id: str | None = None
    version: Any = None
    generation: Any = None
    install_state: InstallState | None = None
    health: str | None = None
    trusted: bool = False
    referenced: bool = False
    active: bool = False
    pinned: bool = False
    verified: bool = True
    complete: bool = True
    requires: list[str] = field(default_factory=list)
    path: str | None = None
    metadata_role: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def version_tuple(self) -> tuple[Any, ...]:
        return _version_key(self.version)

    @property
    def digest_keys(self) -> set[str]:
        return _digest_parts(self.digest)


def coerce_occupancy(
    record: Any, *, fallback_id: str | None = None
) -> Occupancy:
    """Coerce a dict, object, or path-like record into :class:`Occupancy`."""
    if isinstance(record, Occupancy):
        return record

    data = _data(record)
    item_id = _first(data, _ID_KEYS, fallback_id)
    if item_id is None:
        raise ValueError("occupancy record needs an id/path/name key")

    requires = _as_list(_first(data, _REQUIRES_KEYS, []))
    requires = [str(item) for item in requires]
    hashes = data.get("hashes")
    digest_value = _first(data, _DIGEST_KEYS)
    if digest_value is None and hashes is not None:
        digest_value = hashes
    digest = _primary_digest(digest_value)

    state_value = _first(data, _STATE_KEYS)
    health_value = _first(data, _HEALTH_KEYS)
    install_state = normalize_install_state(state_value)
    if (
        health_value is None
        and install_state is None
        and state_value is not None
    ):
        health_value = state_value
    health = _normalize_health(health_value)
    if health is None:
        if bool(
            _first(
                data,
                ("observing", "under_observation", "is_observing"),
                False,
            )
        ):
            health = Reason.HEALTH_OBSERVATION
        elif bool(
            _first(
                data,
                ("approved", "is_approved", "golden", "rollback"),
                False,
            )
        ):
            health = Reason.APPROVED_ROLLBACK
    size = _first(data, _SIZE_KEYS, 0)
    try:
        size_int = int(size or 0)
    except (TypeError, ValueError):
        size_int = 0
    size_int = max(size_int, 0)

    path = _first(data, ("local_path", "filename", "filepath", "path"))
    metadata_role = _first(data, ("metadata_role", "role", "rolename"))
    explicit_pin = bool(
        _first(data, ("pinned", "do_not_delete", "keep", "retain"), False)
    )
    verified_keys = ("verified", "hash_verified")
    complete_keys = ("complete", "finished")
    verified = bool(_first(data, verified_keys, True))
    complete = bool(_first(data, complete_keys, True))
    state_text = str(state_value or "").strip().lower().replace("-", "_")
    if not any(key in data for key in complete_keys) and (
        "partial" in state_text or "downloading" in state_text
    ):
        complete = False
    if not any(key in data for key in verified_keys) and (
        "unverified" in state_text or "verification_pending" in state_text
    ):
        verified = False

    return Occupancy(
        id=str(item_id),
        kind=str(_first(data, ("kind", "type", "occupancy_type"), "file")),
        size=size_int,
        digest=digest,
        artifact_id=_first(data, _ARTIFACT_KEYS),
        version=_first(data, _VERSION_KEYS),
        generation=_first(data, _GENERATION_KEYS),
        install_state=install_state,
        health=health,
        trusted=bool(_first(data, ("trusted", "is_trusted"), False)),
        referenced=bool(_first(data, ("referenced", "is_referenced"), False)),
        active=bool(
            _first(
                data,
                ("active", "is_active", "running", "current"),
                False,
            )
        ),
        pinned=explicit_pin,
        verified=verified,
        complete=complete,
        requires=requires,
        path=None if path is None else str(path),
        metadata_role=None if metadata_role is None else str(metadata_role),
        raw=data,
    )


def coerce_inventory(inventory: Any) -> list[Occupancy]:
    """Coerce many inventory shapes into a list of :class:`Occupancy`."""
    if inventory is None:
        return []
    if isinstance(inventory, Occupancy):
        return [inventory]
    if isinstance(inventory, (str, bytes, Path)):
        return [coerce_occupancy({"id": str(inventory)})]
    if isinstance(inventory, Mapping):
        for wrapper_key in (
            "inventory",
            "items",
            "records",
            "entries",
            "files",
            "occupancy",
            "artifacts",
            "targets",
            "target_versions",
            "artifact_versions",
        ):
            wrapped = inventory.get(wrapper_key)
            if isinstance(wrapped, (Mapping, list, tuple, set, frozenset)):
                return coerce_inventory(wrapped)
        records = []
        for key, value in inventory.items():
            if isinstance(value, Mapping) and "id" not in value:
                item = dict(value)
                item["id"] = key
                records.append(item)
            else:
                records.append(value)
        return [coerce_occupancy(record) for record in records]
    if isinstance(inventory, Iterable):
        items: list[Occupancy] = []
        for index, record in enumerate(inventory):
            if isinstance(record, Occupancy):
                items.append(record)
            elif isinstance(record, Mapping):
                items.append(coerce_occupancy(record))
            elif isinstance(record, (str, Path)):
                items.append(coerce_occupancy({"id": str(record)}))
            else:
                try:
                    items.append(coerce_occupancy(record))
                except ValueError:
                    items.append(
                        coerce_occupancy(
                            {"id": f"item-{index}", "value": record}
                        )
                    )
        return items
    return [coerce_occupancy(inventory)]


def _reference_pins(reference: Any) -> tuple[set[str], list[str], Any]:
    """Return pin keys, dependency IDs, and the normalized reference."""
    pins: set[str] = set()
    requires: list[str] = []

    if reference is None:
        return pins, requires, reference
    if isinstance(reference, (str, int)):
        return {str(reference)}, requires, reference

    data = _data(reference)

    # A raw TUF Metadata object wraps signed payload.
    if "signed" in data and not isinstance(reference, Mapping):
        try:
            signed = reference.signed  # type: ignore[attr-defined]
            return _reference_pins(signed)
        except AttributeError:
            pass

    if "signed" in data and isinstance(data["signed"], Mapping):
        nested_pins, nested_requires, _ = _reference_pins(data["signed"])
        pins.update(nested_pins)
        requires.extend(nested_requires)

    role_type = data.get("_type") or data.get("type")
    if (
        role_type == "targets"
        or "targets" in data
        or hasattr(reference, "targets")
    ):
        targets = data.get("targets")
        if targets is None and hasattr(reference, "targets"):
            targets = reference.targets
        if isinstance(targets, Mapping):
            for path, target in targets.items():
                pins.add(str(path))
                target_data = _data(target)
                pins.update(
                    _digest_parts(
                        target_data.get("hashes") or target_data.get("digest")
                    )
                )
                length = target_data.get("length") or target_data.get("size")
                if length is not None:
                    pins.add(f"length:{length}")

    if role_type == "snapshot" or "meta" in data or hasattr(reference, "meta"):
        meta = data.get("meta")
        if meta is None and hasattr(reference, "meta"):
            meta = reference.meta
        if isinstance(meta, Mapping):
            for role, metafile in meta.items():
                pins.add(str(role))
                meta_data = _data(metafile)
                version = meta_data.get("version")
                if version is not None:
                    pins.add(f"{version}.{role}")
                    pins.add(f"{role}@{version}")
                pins.update(_digest_parts(meta_data.get("hashes")))

    for key in (
        "pins",
        "item_ids",
        "ids",
        "paths",
        "target_paths",
        "digests",
        "target_refs",
        "references",
    ):
        if key in data:
            for value in _as_list(data[key]):
                if isinstance(value, Mapping):
                    value_data = value
                    pins.add(str(_first(value_data, _ID_KEYS, "")))
                    pins.update(_digest_parts(_first(value_data, _DIGEST_KEYS)))
                    pins.update(_digest_parts(value_data.get("hashes")))
                elif value is not None:
                    pins.add(str(value))

    requires.extend(
        str(item) for item in _as_list(_first(data, _REQUIRES_KEYS, []))
    )
    generation = _first(data, _GENERATION_KEYS)
    if generation is not None:
        pins.add(f"generation:{generation}")
    return {pin for pin in pins if pin}, requires, reference


def extract_trusted_pins(trusted_metadata: Any) -> tuple[set[str], set[str]]:
    """Extract item/digest pins and dependency IDs from trusted metadata.

    Accepts TUF ``Metadata``/``Targets`` objects, ``TrustedMetadataSet``,
    plain TUF JSON dictionaries, strings, and ordinary reference records.
    """
    pins: set[str] = set()
    dependencies: set[str] = set()
    if trusted_metadata is None:
        return pins, dependencies

    references: list[Any]
    internal_trusted_set = getattr(trusted_metadata, "_trusted_set", None)
    if isinstance(internal_trusted_set, Mapping):
        references = list(internal_trusted_set.values())
    elif isinstance(trusted_metadata, Mapping):
        references = [trusted_metadata]
    elif isinstance(trusted_metadata, Iterable) and not isinstance(
        trusted_metadata, (str, bytes, Mapping)
    ):
        references = list(trusted_metadata)
    else:
        references = [trusted_metadata]

    for reference in references:
        ref_pins, requires, _ = _reference_pins(reference)
        pins.update(ref_pins)
        dependencies.update(requires)
    return pins, dependencies


def _item_matches_pin(item: Occupancy, pins: set[str]) -> bool:
    candidates = {item.id, item.kind, item.path or ""}
    if item.artifact_id:
        candidates.update({item.artifact_id, f"target:{item.artifact_id}"})
    if item.metadata_role:
        candidates.add(item.metadata_role)
    candidates.update(item.digest_keys)
    if item.version is not None:
        candidates.add(f"{item.version}.{item.id}")
        candidates.add(f"{item.id}@{item.version}")
        if item.metadata_role:
            candidates.add(f"{item.version}.{item.metadata_role}")
            candidates.add(f"{item.metadata_role}@{item.version}")
    if item.generation is not None:
        candidates.add(f"generation:{item.generation}")
        candidates.add(str(item.generation))
    return any(candidate and candidate in pins for candidate in candidates)


@dataclass
class Decision:
    """Retention decision for one occupied item."""

    id: str
    retain: bool
    reasons: list[str] = field(default_factory=list)
    size: int = 0
    digest: str | None = None
    reclaimable_bytes: int = 0
    shared_digest: bool = False
    item: Occupancy | None = None


@dataclass
class StateExplanation:
    """Explanation of occupancy pinned in one half-install state."""

    state: str
    title: str
    cannot_reclaim_categories: list[dict[str, Any]]
    protected_items: list[str] = field(default_factory=list)
    reclaimable_items: list[str] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)
    messages_zh: list[str] = field(default_factory=list)

    @property
    def categories(self) -> list[str]:
        return [entry["category"] for entry in self.cannot_reclaim_categories]

    @property
    def locks(self) -> list[dict[str, Any]]:
        return self.cannot_reclaim_categories

    @property
    def blocked_occupancy(self) -> list[str]:
        return self.protected_items

    @property
    def non_reclaimable_items(self) -> list[str]:
        return self.protected_items

    @property
    def reason_codes(self) -> list[str]:
        return [entry["reason"] for entry in self.cannot_reclaim_categories]

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "title": self.title,
            "cannot_reclaim": self.cannot_reclaim_categories,
            "categories": self.categories,
            "protected_items": self.protected_items,
            "reclaimable_items": self.reclaimable_items,
            "messages": self.messages,
            "messages_zh": self.messages_zh,
        }

    def __getitem__(self, key: str) -> Any:
        aliases = {
            "cannot_reclaim": "cannot_reclaim_categories",
            "cannot_reclaim_items": "protected_items",
            "non_reclaimable_items": "protected_items",
            "locked_items": "protected_items",
            "pinned_items": "protected_items",
            "locked": "cannot_reclaim_categories",
            "blocked": "protected_items",
            "blocked_items": "protected_items",
            "non_reclaimable": "cannot_reclaim_categories",
            "occupancy": "cannot_reclaim_categories",
            "locks": "cannot_reclaim_categories",
            "reasons": "messages",
        }
        key = aliases.get(key, key)
        if hasattr(self, key):
            return getattr(self, key)
        data = self.to_dict()
        if key in data:
            return data[key]
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, item: object) -> bool:
        haystack = json.dumps(
            self.to_dict(), default=str, ensure_ascii=False
        ).lower()
        return str(item).lower() in haystack

    def __iter__(self) -> Iterator[str]:
        return iter(self.messages)


@dataclass
class RetentionPlan:
    """Result of a side-effect-free retention rehearsal."""

    decisions: dict[str, Decision]
    quota: int | dict[str, int] | None = None
    max_bytes: int | None = None
    dry_run: bool = True
    state_explanations: dict[str, StateExplanation] = field(
        default_factory=dict
    )
    unique_digest_bytes: dict[str, int] = field(default_factory=dict)

    @property
    def deletable(self) -> list[str]:
        """IDs that are safe deletion candidates under the policy."""
        return [
            item_id
            for item_id, decision in self.decisions.items()
            if not decision.retain
        ]

    @property
    def removable(self) -> list[str]:
        """Alias for :attr:`deletable`."""
        return self.deletable

    @property
    def candidates(self) -> list[str]:
        """Alias for :attr:`deletable`."""
        return self.deletable

    @property
    def blocked(self) -> list[str]:
        """IDs retained by at least one safety/quota reason."""
        return [
            item_id
            for item_id, decision in self.decisions.items()
            if decision.retain
        ]

    @property
    def retained(self) -> list[str]:
        return self.blocked

    @property
    def deletable_items(self) -> list[Decision]:
        return [self.decisions[item_id] for item_id in self.deletable]

    @property
    def blocked_items(self) -> list[Decision]:
        return [self.decisions[item_id] for item_id in self.blocked]

    @property
    def reclaimable_bytes(self) -> int:
        """Bytes freed if all deletable IDs are removed.

        Equal-content duplicates are counted once.  A digest used by any
        retained item contributes zero reclaimable bytes.
        """
        return sum(
            decision.reclaimable_bytes for decision in self.deletable_items
        )

    @property
    def freed_bytes(self) -> int:
        return self.reclaimable_bytes

    @property
    def logical_reclaimable_bytes(self) -> int:
        return sum(decision.size for decision in self.deletable_items)

    @property
    def bytes_freed(self) -> int:
        return self.reclaimable_bytes

    @property
    def freeable_bytes(self) -> int:
        return self.reclaimable_bytes

    @property
    def deletable_ids(self) -> list[str]:
        return self.deletable

    @property
    def removable_items(self) -> list[str]:
        return self.deletable

    @property
    def pinned(self) -> list[str]:
        return self.blocked

    @property
    def protected(self) -> list[str]:
        return self.blocked

    @property
    def reasons(self) -> dict[str, list[str]]:
        return {
            item_id: list(decision.reasons)
            for item_id, decision in self.decisions.items()
        }

    @property
    def explanations(self) -> dict[str, StateExplanation]:
        return self.state_explanations

    @property
    def retained_bytes(self) -> int:
        retained_digests: set[str] = set()
        total = 0
        for item_id in self.blocked:
            decision = self.decisions[item_id]
            digest = decision.digest
            if digest and digest in self.unique_digest_bytes:
                if digest not in retained_digests:
                    retained_digests.add(digest)
                    total += self.unique_digest_bytes[digest]
            else:
                total += decision.size
        return total

    def reasons_for(self, item_id: str) -> list[str]:
        decision = self.decisions.get(item_id)
        return list(decision.reasons) if decision else []

    def explain(self, item_id: str | None = None) -> Any:
        """Explain one item, or all three half-install states."""
        if item_id is None:
            return self.state_explanations
        if item_id in self.state_explanations:
            return self.state_explanations[item_id]
        decision = self.decisions.get(item_id)
        if decision is None:
            raise KeyError(item_id)
        return {
            "id": decision.id,
            "retain": decision.retain,
            "reasons": decision.reasons,
            "reclaimable_bytes": decision.reclaimable_bytes,
            "shared_digest": decision.shared_digest,
        }

    def explain_state(self, state: Any) -> StateExplanation:
        canonical = normalize_install_state(state)
        if canonical is None:
            raise ValueError(f"unknown install state: {state!r}")
        return self.state_explanations[canonical.value]

    def to_dict(self) -> dict[str, Any]:
        return {
            "dry_run": self.dry_run,
            "quota": self.quota,
            "max_bytes": self.max_bytes,
            "deletable": self.deletable,
            "blocked": self.blocked,
            "reclaimable_bytes": self.reclaimable_bytes,
            "logical_reclaimable_bytes": self.logical_reclaimable_bytes,
            "retained_bytes": self.retained_bytes,
            "decisions": [
                {
                    "id": decision.id,
                    "retain": decision.retain,
                    "reasons": decision.reasons,
                    "size": decision.size,
                    "digest": decision.digest,
                    "reclaimable_bytes": decision.reclaimable_bytes,
                    "shared_digest": decision.shared_digest,
                }
                for decision in self.decisions.values()
            ],
            "install_states": {
                key: value.to_dict()
                for key, value in self.state_explanations.items()
            },
        }

    def __getitem__(self, key: str) -> Any:
        aliases = {
            "removable": "deletable",
            "removable_items": "deletable",
            "deletable_ids": "deletable",
            "candidate_ids": "deletable",
            "candidates": "deletable",
            "non_reclaimable": "blocked",
            "pinned": "blocked",
            "protected": "blocked",
            "kept": "blocked",
            "retained": "blocked",
            "bytes_reclaimed": "reclaimable_bytes",
            "freeable_bytes": "reclaimable_bytes",
            "deletable_bytes": "reclaimable_bytes",
            "reclaimable_space_bytes": "reclaimable_bytes",
            "reclaimable_space": "reclaimable_bytes",
            "space_saved": "reclaimable_bytes",
            "explanations": "state_explanations",
            "install_state_explanations": "state_explanations",
            "state_explanations": "state_explanations",
        }
        key = aliases.get(key, key)
        if hasattr(self, key):
            return getattr(self, key)
        data = self.to_dict()
        if key in data:
            return data[key]
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, item: object) -> bool:
        return str(item) in self.decisions

    def __iter__(self) -> Iterator[str]:
        return iter(self.deletable)


_STATE_COPY = {
    InstallState.METADATA_STAGED.value: (
        "Metadata half-installed",
        [
            (
                "trusted_metadata",
                Reason.TRUSTED_REFERENCE,
                "Current metadata verifies the approved state.",
            ),
            (
                "approved_rollback",
                Reason.APPROVED_ROLLBACK,
                "Approved content and verification chain are fallback data.",
            ),
            (
                "pending_approval_generation",
                Reason.PENDING_INSTALL,
                "Staged metadata/approval generation resumes the update.",
            ),
            (
                "approval_generation",
                Reason.APPROVAL_GENERATION,
                "Referenced approval generations cannot be removed.",
            ),
        ],
    ),
    InstallState.TARGET_STAGED.value: (
        "Target half-installed",
        [
            (
                "trusted_metadata",
                Reason.TRUSTED_REFERENCE,
                "Trusted metadata supplies activation hashes and signatures.",
            ),
            (
                "approved_rollback",
                Reason.APPROVED_ROLLBACK,
                "The approved version stays verifiable for rollback.",
            ),
            (
                "verified_staged_target",
                Reason.STAGED_TARGET,
                "Verified staging material avoids redownload on retry.",
            ),
            (
                "approval_generation",
                Reason.APPROVAL_GENERATION,
                "The staged target's approval generation must stay.",
            ),
        ],
    ),
    InstallState.HEALTH_OBSERVATION.value: (
        "Activated version under health observation",
        [
            (
                "active_candidate",
                Reason.ACTIVE_VERSION,
                "The activated candidate is occupied by the install.",
            ),
            (
                "verification_metadata",
                Reason.TRUSTED_REFERENCE,
                "Metadata verifying candidate and rollback targets must stay.",
            ),
            (
                "approved_rollback",
                Reason.APPROVED_ROLLBACK,
                "The approved fallback remains complete during observation.",
            ),
            (
                "health_observation_material",
                Reason.HEALTH_OBSERVATION,
                "Observed versions require verifiable rollback materials.",
            ),
            (
                "approval_generation",
                Reason.APPROVAL_GENERATION,
                "Candidate and fallback approval generations are dependencies.",
            ),
        ],
    ),
}


_REASON_ZH = {
    Reason.TRUSTED_REFERENCE: "可信元数据引用的目标和校验信息不能回收。",
    Reason.APPROVED_ROLLBACK: "已批准版本的可验证回退材料不能回收。",
    Reason.PENDING_INSTALL: "半完成安装仍需要的暂存元数据或审批代次不能回收。",
    Reason.STAGED_TARGET: "已校验的完整暂存目标可用于重试，默认保留。",
    Reason.APPROVAL_GENERATION: "被依赖的审批代次元数据必须保留。",
    Reason.ACTIVE_VERSION: "已激活但未结束健康观察的版本占用不能回收。",
    Reason.HEALTH_OBSERVATION: "健康观察中的版本必须保留可验证回退链路。",
    Reason.DEPENDENCY: "被保留对象依赖的元数据不能回收。",
    Reason.EXPLICIT_PIN: "显式固定的占用不能回收。",
}


def static_state_explanations() -> dict[str, StateExplanation]:
    """Return the three state explanations without requiring an inventory."""
    result: dict[str, StateExplanation] = {}
    for state, (title, categories) in _STATE_COPY.items():
        category_dicts = []
        messages_zh = []
        for category, reason, text in categories:
            explanation_zh = _REASON_ZH.get(
                reason,
                "该占用属于半完成安装期间不能回收的材料。",
            )
            category_dicts.append(
                {
                    "category": category,
                    "reason": reason,
                    "explanation": text,
                    "explanation_zh": explanation_zh,
                }
            )
            messages_zh.append(explanation_zh)
        result[state] = StateExplanation(
            state=state,
            title=title,
            cannot_reclaim_categories=category_dicts,
            messages=[text for _, _, text in categories],
            messages_zh=messages_zh,
        )
    return result


def explain_occupancy(state: Any = None, **kwargs: Any) -> Any:
    """Explain non-reclaimable occupancy for one state or all three states.

    Extra keyword arguments are passed to :func:`plan_retention` when an
    inventory is supplied.  Without an inventory this returns the static policy
    explanation, making it useful as a pure state classifier.
    """
    if state is None:
        if kwargs:
            return plan_retention(**kwargs).state_explanations
        return static_state_explanations()

    canonical = normalize_install_state(state)
    if canonical is None and kwargs:
        plan = plan_retention(**kwargs)
        return plan.explain(state)
    if canonical is None:
        raise ValueError(f"unknown install state: {state!r}")

    if kwargs:
        plan = plan_retention(**kwargs)
        return plan.explain_state(canonical)
    return static_state_explanations()[canonical.value]


def explain_three_half_install_states(
    **kwargs: Any,
) -> dict[str, StateExplanation]:
    """Return explanations for metadata, target, and activation half-states."""
    if kwargs:
        return plan_retention(**kwargs).state_explanations
    return static_state_explanations()


explain_all_states = explain_three_half_install_states
explain_non_reclaimable = explain_occupancy
explain_blockers = explain_occupancy


def _quota_for(
    artifact_id: str | None,
    quota: int | Mapping[str, int] | None,
    default_quota: int | None,
) -> int | None:
    if isinstance(quota, Mapping):
        if artifact_id in quota:
            return int(quota[artifact_id])
        if "*" in quota:
            return int(quota["*"])
        if "default" in quota:
            return int(quota["default"])
        return default_quota
    if quota is not None:
        return int(quota)
    return default_quota


def _add_reason(decision: Decision, reason: str) -> None:
    if reason not in decision.reasons:
        decision.reasons.append(reason)


def _is_target_quota_candidate(item: Occupancy) -> bool:
    """Whether quota retention should treat an item as target material."""
    kind = item.kind.lower()
    if item.metadata_role is not None or kind == "targets":
        return False
    non_target_tokens = (
        "metadata",
        "metafile",
        "approval",
        "generation",
        "root",
        "snapshot",
        "timestamp",
    )
    return not any(token in kind for token in non_target_tokens)


def _build_state_explanations(
    items: list[Occupancy], decisions: dict[str, Decision]
) -> dict[str, StateExplanation]:
    explanations = static_state_explanations()
    for explanation in explanations.values():
        explanation.protected_items = []
        explanation.reclaimable_items = []

    baseline_reasons = {
        Reason.TRUSTED_REFERENCE,
        Reason.APPROVED_ROLLBACK,
        Reason.APPROVAL_GENERATION,
        Reason.DEPENDENCY,
        Reason.EXPLICIT_PIN,
    }
    for item in items:
        decision = decisions[item.id]
        item_state = item.install_state.value if item.install_state else None

        if item_state is not None:
            explanation = explanations[item_state]
            if decision.retain:
                explanation.protected_items.append(item.id)
            else:
                explanation.reclaimable_items.append(item.id)

            if decision.retain:
                for reason in decision.reasons:
                    if not any(
                        entry["reason"] == reason
                        for entry in explanation.cannot_reclaim_categories
                    ):
                        explanation.cannot_reclaim_categories.append(
                            {
                                "category": reason,
                                "reason": reason,
                                "explanation": f"Pinned by {reason}: {item.id}",
                                "explanation_zh": _REASON_ZH.get(
                                    reason,
                                    "该占用在当前安装状态下不能回收。",
                                ),
                            }
                        )

        if decision.retain and any(
            reason in baseline_reasons for reason in decision.reasons
        ):
            for explanation in explanations.values():
                if item.id not in explanation.protected_items:
                    explanation.protected_items.append(item.id)

        reason_states = {
            Reason.STAGED_TARGET: InstallState.TARGET_STAGED.value,
            Reason.HEALTH_OBSERVATION: InstallState.HEALTH_OBSERVATION.value,
            Reason.ACTIVE_VERSION: InstallState.HEALTH_OBSERVATION.value,
        }
        for reason in decision.reasons:
            state_value = reason_states.get(reason)
            if state_value is None:
                continue
            protected = explanations[state_value].protected_items
            if item.id not in protected:
                protected.append(item.id)
    return explanations


class RetentionPlanner:
    """Configurable offline retention planner."""

    def __init__(self, *args: Any, **options: Any) -> None:
        positional_inventory, positional_quota, positional_trusted = (
            _classify_positional_args(args)
        )
        quota = options.pop("quota", None)
        retention_quota = options.pop("retention_quota", None)
        keep_versions = options.pop("keep_versions", None)
        max_bytes = options.pop("max_bytes", None)
        budget_bytes = options.pop("budget_bytes", None)
        trusted_metadata = options.pop("trusted_metadata", None)
        metadata_references = options.pop("metadata_references", None)
        references = options.pop("references", None)
        keep_approved = options.pop("keep_approved", True)
        keep_observation = options.pop("keep_observation", True)
        retain_pending_installs = options.pop("retain_pending_installs", True)
        protect_explicit_pins = options.pop("protect_explicit_pins", True)

        effective_quota = retention_quota
        if effective_quota is None:
            effective_quota = quota
        if effective_quota is None:
            effective_quota = keep_versions
        if effective_quota is None:
            for key in (
                "retention_count",
                "keep_last",
                "keep",
                "versions_to_keep",
            ):
                if key in options:
                    effective_quota = options.pop(key)
                    break
        if effective_quota is None:
            effective_quota = positional_quota
        self.quota = effective_quota
        self.max_bytes = max_bytes if max_bytes is not None else budget_bytes
        self.default_inventory = positional_inventory
        self.trusted_metadata = (
            trusted_metadata
            if trusted_metadata is not None
            else positional_trusted
        )
        self.metadata_references = metadata_references
        self.references = references
        self.keep_approved = keep_approved
        self.keep_observation = keep_observation
        self.retain_pending_installs = retain_pending_installs
        self.protect_explicit_pins = protect_explicit_pins
        self.options = options

    def plan(self, inventory: Any = None, **kwargs: Any) -> RetentionPlan:
        if inventory is None:
            inventory = self.default_inventory
        return plan_retention(
            inventory,
            quota=self.quota,
            max_bytes=self.max_bytes,
            trusted_metadata=self.trusted_metadata,
            metadata_references=self.metadata_references,
            references=self.references,
            keep_approved=self.keep_approved,
            keep_observation=self.keep_observation,
            retain_pending_installs=self.retain_pending_installs,
            protect_explicit_pins=self.protect_explicit_pins,
            **{**self.options, **kwargs},
        )

    def dry_run(self, inventory: Any = None, **kwargs: Any) -> RetentionPlan:
        return self.plan(inventory, **kwargs)

    def find_deletable(self, inventory: Any = None, **kwargs: Any) -> list[str]:
        return self.plan(inventory, **kwargs).deletable

    def explain_states(self) -> dict[str, StateExplanation]:
        return static_state_explanations()


OfflineRetentionPlanner = RetentionPlanner
RetentionRehearsal = RetentionPlanner
DiskReclamationPlanner = RetentionPlanner
RetentionManager = RetentionPlanner


def _looks_like_metadata(value: Any) -> bool:
    if hasattr(value, "_trusted_set") or hasattr(value, "signed"):
        return True
    if not isinstance(value, Mapping):
        return False
    keys = set(value)
    return bool({"signed", "signatures", "_type", "targets", "meta"} & keys)


def _looks_like_quota_mapping(value: Mapping[Any, Any]) -> bool:
    if _looks_like_metadata(value) or _looks_like_inventory(value):
        return False
    return all(
        isinstance(item, int) and not isinstance(item, bool)
        for item in value.values()
    )


def _classify_positional_args(
    args: tuple[Any, ...],
) -> tuple[Any, Any, Any]:
    inventory: Any = None
    quota: Any = None
    trusted: Any = None
    for arg in args:
        if isinstance(arg, bool):
            continue
        if isinstance(arg, RetentionPolicy) and quota is None:
            quota = arg
        if isinstance(arg, int) and quota is None:
            quota = arg
        elif _looks_like_metadata(arg) and trusted is None:
            trusted = arg
        elif (
            isinstance(arg, Mapping)
            and _looks_like_quota_mapping(arg)
            and quota is None
        ):
            quota = arg
        elif isinstance(arg, Mapping) and not _looks_like_inventory(arg):
            if quota is None and _looks_like_quota_mapping(arg):
                quota = arg
            elif trusted is None and _looks_like_metadata(arg):
                trusted = arg
            elif inventory is None:
                inventory = arg
        elif inventory is None:
            inventory = arg
        elif quota is None and isinstance(arg, (int, Mapping)):
            quota = arg
        elif trusted is None and _looks_like_metadata(arg):
            trusted = arg
    return inventory, quota, trusted


def _looks_like_inventory(value: Mapping[Any, Any]) -> bool:
    if not value:
        return False
    sample = next(iter(value.values()))
    return isinstance(sample, (Mapping, Occupancy, list, tuple))


def plan_retention(*args: Any, **kwargs: Any) -> RetentionPlan:
    """Compute an offline retention plan.

    The first positional argument may be either inventory or quota; the other
    may be supplied as the second positional argument.  This flexibility keeps
    small call sites readable while tolerating common API spellings.
    """
    positional_inventory, positional_quota, positional_trusted = (
        _classify_positional_args(args)
    )

    if isinstance(positional_inventory, (str, Path)):
        inventory_path = Path(positional_inventory)
        if inventory_path.is_dir():
            directory_kwargs = dict(kwargs)
            for wrapper_key in (
                "inventory",
                "items",
                "occupancy",
                "artifacts",
                "targets",
            ):
                directory_kwargs.pop(wrapper_key, None)
            if positional_quota is not None:
                directory_kwargs.setdefault("quota", positional_quota)
            if positional_trusted is not None:
                directory_kwargs.setdefault(
                    "trusted_metadata", positional_trusted
                )
            return rehearse_directory(inventory_path, **directory_kwargs)
        if inventory_path.is_file():
            positional_inventory = json.loads(
                inventory_path.read_text(encoding="utf-8")
            )

    inventory = kwargs.pop("inventory", None)
    if inventory is None:
        inventory = kwargs.pop("items", None)
    if inventory is None:
        inventory = kwargs.pop("occupancy", None)
    if inventory is None:
        inventory = kwargs.pop("artifacts", None)
    if inventory is None:
        inventory = kwargs.pop("targets", None)
    if inventory is None:
        for key in (
            "occupied",
            "occupants",
            "files",
            "cache_entries",
            "entries",
            "records",
            "target_versions",
            "artifact_versions",
            "inventory_items",
            "local_files",
            "blobs",
        ):
            inventory = kwargs.pop(key, None)
            if inventory is not None:
                break
    if inventory is None:
        inventory = positional_inventory

    quota = None
    for key in (
        "quota",
        "retention_quota",
        "keep_versions",
        "retention_count",
        "keep_last",
        "keep",
        "retention_limit",
        "max_versions",
        "target_quota",
        "artifact_quota",
        "keep_count",
        "versions_to_keep",
    ):
        if quota is None and key in kwargs:
            quota = kwargs.pop(key)
    if quota is None:
        quota = positional_quota
    policy = kwargs.pop("policy", None)
    if policy is None:
        policy = kwargs.pop("retention_policy", None)
    if quota is None and isinstance(policy, RetentionPolicy):
        quota = policy

    policy_defaults = quota if isinstance(quota, RetentionPolicy) else policy
    if isinstance(quota, RetentionPolicy):
        quota = quota.keep_versions

    max_bytes = kwargs.pop("max_bytes", None)
    max_bytes = kwargs.pop("budget_bytes", max_bytes)
    max_bytes = kwargs.pop("quota_bytes", max_bytes)

    trusted_metadata = None
    for key in (
        "trusted_metadata",
        "metadata",
        "trusted_refs",
        "trusted_references",
        "verified_metadata",
    ):
        if key in kwargs:
            trusted_metadata = kwargs.pop(key)
            break
    if trusted_metadata is None:
        trusted_metadata = positional_trusted
    metadata_references = kwargs.pop("metadata_references", None)
    references = kwargs.pop("references", None)
    pins_argument = kwargs.pop("pins", None)

    keep_approved_value = kwargs.pop("keep_approved", None)
    keep_observation_value = kwargs.pop("keep_observation", None)
    retain_pending_value = kwargs.pop("retain_pending_installs", None)
    protect_explicit = bool(kwargs.pop("protect_explicit_pins", True))
    if isinstance(policy_defaults, RetentionPolicy):
        if keep_approved_value is None:
            keep_approved_value = policy_defaults.keep_approved
        if keep_observation_value is None:
            keep_observation_value = policy_defaults.keep_under_observation
        if retain_pending_value is None:
            retain_pending_value = policy_defaults.retain_pending_installs
        if max_bytes is None:
            max_bytes = policy_defaults.max_bytes
    keep_approved = bool(
        keep_approved_value if keep_approved_value is not None else True
    )
    keep_observation = bool(
        keep_observation_value if keep_observation_value is not None else True
    )
    retain_pending = bool(
        retain_pending_value if retain_pending_value is not None else True
    )
    observation_value = None
    for key in (
        "observation_versions",
        "health_check_versions",
        "observing_versions",
        "under_observation",
        "observed_versions",
    ):
        observation_value = kwargs.pop(key, observation_value)
    observe_all = isinstance(observation_value, bool) and observation_value
    if isinstance(observation_value, bool):
        observation_value = None
    observation_versions = set(_as_list(observation_value))
    approved_value = None
    for key in (
        "approved_versions",
        "approved",
        "rollback_versions",
        "baseline_versions",
        "golden_versions",
    ):
        approved_value = kwargs.pop(key, approved_value)
    if isinstance(approved_value, bool):
        keep_approved = approved_value
        approved_value = None
    approved_versions = set(_as_list(approved_value))
    install_states = kwargs.pop("install_states", None)

    items = coerce_inventory(inventory)

    # Apply external version/state sets without requiring callers to denormalize
    # every inventory record.
    for item in items:
        version_label = (
            f"{item.artifact_id or ''}:{item.version}"
            if item.version is not None
            else None
        )
        if observe_all or (
            keep_observation
            and (
                item.health == Reason.HEALTH_OBSERVATION
                or item.version in observation_versions
                or version_label in observation_versions
            )
        ):
            item.health = Reason.HEALTH_OBSERVATION
        if keep_approved and (
            item.health == Reason.APPROVED_ROLLBACK
            or item.version in approved_versions
            or version_label in approved_versions
        ):
            item.health = Reason.APPROVED_ROLLBACK

    if isinstance(install_states, Mapping):
        for key, state in install_states.items():
            for item in items:
                if key in (item.id, item.artifact_id) or str(
                    item.version
                ) == str(key):
                    item.install_state = normalize_install_state(state)
    elif install_states is not None:
        state = normalize_install_state(install_states)
        if state is not None:
            for item in items:
                if item.install_state is None:
                    item.install_state = state

    pins, direct_dependencies = extract_trusted_pins(trusted_metadata)
    for reference_argument in (metadata_references, references, pins_argument):
        ref_pins, ref_deps = extract_trusted_pins(reference_argument)
        pins.update(ref_pins)
        direct_dependencies.update(ref_deps)

    decisions = {
        item.id: Decision(
            id=item.id,
            retain=False,
            size=item.size,
            digest=item.digest,
            item=item,
        )
        for item in items
    }

    # Explicit and intrinsic safety pins.
    for item in items:
        decision = decisions[item.id]
        if protect_explicit and item.pinned:
            decision.retain = True
            _add_reason(decision, Reason.EXPLICIT_PIN)
        if item.trusted or item.referenced or _item_matches_pin(item, pins):
            decision.retain = True
            _add_reason(decision, Reason.TRUSTED_REFERENCE)
        if keep_approved and (
            item.active
            or item.health == Reason.APPROVED_ROLLBACK
            or item.health
            in {"approved", "current", "active", "golden", "known_good"}
        ):
            decision.retain = True
            _add_reason(decision, Reason.APPROVED_ROLLBACK)
        if keep_observation and item.health == Reason.HEALTH_OBSERVATION:
            decision.retain = True
            _add_reason(decision, Reason.HEALTH_OBSERVATION)
        if item.active:
            decision.retain = True
            _add_reason(decision, Reason.ACTIVE_VERSION)

        if retain_pending and item.install_state is not None:
            state = item.install_state
            if state in (
                InstallState.METADATA_STAGED,
                InstallState.HEALTH_OBSERVATION,
            ):
                decision.retain = True
                _add_reason(decision, Reason.PENDING_INSTALL)
            elif state == InstallState.TARGET_STAGED:
                # Complete/verified staging is useful resume material.  An
                # explicit partial/unverified file is not a rollback anchor.
                if item.complete and item.verified:
                    decision.retain = True
                    _add_reason(decision, Reason.STAGED_TARGET)
                else:
                    if not item.complete:
                        _add_reason(decision, Reason.PARTIAL_DOWNLOAD)
                    if not item.verified:
                        _add_reason(decision, Reason.UNVERIFIED_TARGET)
                    _add_reason(decision, Reason.PARTIAL_RECLAIMABLE)

    # Retention quota: retain newest target versions.  In auto mode, records
    # without an explicit artifact name share one global version sequence.
    quota_scope = kwargs.pop("quota_scope", "auto")
    has_artifact_groups = any(item.artifact_id is not None for item in items)
    groups: dict[str, list[Occupancy]] = {}
    for item in items:
        if item.version is None or not _is_target_quota_candidate(item):
            continue
        if quota_scope == "global":
            group_id = "__all_targets__"
        elif quota_scope == "per_artifact":
            group_id = item.artifact_id or item.id
        elif item.artifact_id is not None:
            group_id = item.artifact_id
        elif has_artifact_groups:
            group_id = item.id
        else:
            group_id = "__all_targets__"
        groups.setdefault(str(group_id), []).append(item)

    for artifact_id, group in groups.items():
        keep = _quota_for(artifact_id, quota, kwargs.get("default_quota"))
        if keep is None or keep < 0:
            continue

        versions: dict[tuple[Any, ...], list[Occupancy]] = {}
        for item in group:
            versions.setdefault(
                item.version_tuple or (str(item.version),), []
            ).append(item)
        ordered_version_keys = sorted(versions, reverse=True)
        for rank, version_key in enumerate(ordered_version_keys):
            if rank >= keep:
                continue
            for item in versions[version_key]:
                decision = decisions[item.id]
                if not decision.retain:
                    decision.retain = True
                    _add_reason(decision, Reason.RETENTION_QUOTA)

    # Retained items also keep dependency and approval-generation closure.
    required_ids: set[str] = set(direct_dependencies)
    changed = True
    while changed:
        changed = False
        for item in items:
            decision = decisions[item.id]
            if not decision.retain:
                continue
            for dependency in item.requires:
                if dependency not in required_ids:
                    required_ids.add(dependency)
                    changed = True
            if item.generation is not None:
                required_ids.add(f"generation:{item.generation}")

        for item in items:
            if item.id in required_ids or _item_matches_pin(item, required_ids):
                decision = decisions[item.id]
                if not decision.retain:
                    decision.retain = True
                    _add_reason(decision, Reason.DEPENDENCY)
                is_generation_record = (
                    "approval" in item.kind
                    or "generation" in item.kind
                    or item.metadata_role in {"root", "approval"}
                    or item.id.startswith(("root", "approval"))
                )
                generation_pin = (
                    item.generation is not None
                    and f"generation:{item.generation}" in required_ids
                )
                if is_generation_record and generation_pin:
                    _add_reason(decision, Reason.APPROVAL_GENERATION)

    # Byte budget is a secondary safety retention policy for unique content.
    if max_bytes is not None:
        unique_sizes: dict[str, int] = {}
        for item in items:
            if item.digest:
                # Digest may be a JSON hash map from coercion; use item size as
                # the content size unless a plain digest was supplied.
                unique_sizes.setdefault(item.digest, item.size)
        mandatory_bytes = 0
        seen: set[str] = set()
        for decision in decisions.values():
            if decision.retain and decision.digest:
                if decision.digest not in seen:
                    seen.add(decision.digest)
                    mandatory_bytes += unique_sizes.get(
                        decision.digest, decision.size
                    )
            elif decision.retain:
                mandatory_bytes += decision.size

        if mandatory_bytes <= max_bytes:
            remaining = max_bytes - mandatory_bytes
            for item in sorted(
                (
                    item
                    for item in items
                    if not decisions[item.id].retain
                    and item.version is not None
                ),
                key=lambda candidate: candidate.version_tuple,
                reverse=True,
            ):
                digest = item.digest
                cost = (
                    unique_sizes.get(digest, item.size) if digest else item.size
                )
                if digest and digest in seen:
                    continue
                if cost <= remaining:
                    decision = decisions[item.id]
                    decision.retain = True
                    _add_reason(decision, "byte_budget")
                    remaining -= cost
                    if digest:
                        seen.add(digest)

    # Compute physical bytes with content deduplication.
    unique_digest_bytes: dict[str, int] = {}
    for item in items:
        if item.digest and not item.digest.startswith("{"):
            unique_digest_bytes[item.digest] = max(
                unique_digest_bytes.get(item.digest, 0), item.size
            )

    retained_digests = {
        decision.digest
        for decision in decisions.values()
        if decision.retain
        and decision.digest
        and not decision.digest.startswith("{")
    }
    for decision in decisions.values():
        digest = decision.digest
        if decision.retain or not digest or digest.startswith("{"):
            if not decision.retain:
                decision.reclaimable_bytes = decision.size
            continue
        if digest in retained_digests:
            decision.shared_digest = True
            decision.reclaimable_bytes = 0
            _add_reason(decision, Reason.SHARED_CONTENT)
        else:
            # Count each unique digest once across the whole deletable set.
            already_counted = any(
                other.id != decision.id
                and other.digest == digest
                and not other.retain
                and other.reclaimable_bytes > 0
                for other in decisions.values()
            )
            if already_counted:
                decision.reclaimable_bytes = 0
                decision.shared_digest = True
            else:
                decision.reclaimable_bytes = unique_digest_bytes.get(
                    digest, decision.size
                )

    explanations = _build_state_explanations(items, decisions)
    return RetentionPlan(
        decisions=decisions,
        quota=quota if isinstance(quota, (int, dict)) else None,
        max_bytes=max_bytes,
        state_explanations=explanations,
        unique_digest_bytes=unique_digest_bytes,
    )


# Common API aliases.  Several task-era names are exposed because callers may
# describe the same offline rehearsal with maintenance/GC terminology.
dry_run_retention = plan_retention
offline_dry_run = plan_retention
plan_offline_retention = plan_retention
plan_cleanup = plan_retention
plan_pruning = plan_retention
rehearse_retention = plan_retention
build_retention_plan = plan_retention
plan_offline_gc = plan_retention
offline_gc = plan_retention
gc_plan = plan_retention
retention_preview = plan_retention
preview_retention = plan_retention
plan_offline_reclamation = plan_retention
plan_reclamation = plan_retention
reclamation_plan = plan_retention
disk_reclamation_plan = plan_retention
offline_rehearsal = plan_retention
rehearse = plan_retention
dry_run = plan_retention
explain_disk_occupancy = explain_occupancy
explain_install_blockers = explain_occupancy


def find_deletable_items(*args: Any, **kwargs: Any) -> list[str]:
    """Return only deletable item IDs for a retention rehearsal."""
    return plan_retention(*args, **kwargs).deletable


find_deletable = find_deletable_items
compute_deletable_items = find_deletable_items
calculate_deletable_items = plan_retention


def select_retention_candidates(*args: Any, **kwargs: Any) -> list[str]:
    """Return candidate IDs selected for deletion."""
    return plan_retention(*args, **kwargs).deletable


select_removable_items = select_retention_candidates

HALF_INSTALL_STATES = tuple(
    member.value
    for member in InstallState
    if member.name
    in {
        "METADATA_STAGED",
        "TARGET_STAGED",
        "HEALTH_OBSERVATION",
    }
)
HALF_COMPLETED_INSTALL_STATES = HALF_INSTALL_STATES


def inventory_from_directory(
    root: str | Path | None = None,
    *,
    metadata_dir: str | Path | None = None,
    target_dir: str | Path | None = None,
    state_file: str | Path | None = None,
    hash_targets: bool = True,
) -> list[dict[str, Any]]:
    """Build offline inventory records from a local TUF-like cache."""
    if root is not None:
        root_path = Path(root)
        metadata_dir = metadata_dir or root_path / "metadata"
        target_dir = target_dir or root_path / "targets"
        state_file = state_file or root_path / "install-state.json"

    records: list[dict[str, Any]] = []
    metadata_path = Path(metadata_dir) if metadata_dir else None
    if metadata_path and metadata_path.exists():
        for path in sorted(metadata_path.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(metadata_path).as_posix()
            record: dict[str, Any] = {
                "id": f"metadata:{relative}",
                "path": str(path),
                "name": relative,
                "kind": "metadata",
                "size": path.stat().st_size,
                "trusted": path.name
                in {
                    "root.json",
                    "timestamp.json",
                    "snapshot.json",
                    "targets.json",
                },
            }
            if relative.startswith("root_history/"):
                record["kind"] = "approval_generation"
                stem = path.name.split(".", 1)[0]
                if stem.isdigit():
                    record["generation"] = int(stem)
            records.append(record)

    target_path = Path(target_dir) if target_dir else None
    if target_path and target_path.exists():
        for path in sorted(target_path.rglob("*")):
            if not path.is_file():
                continue
            digest = None
            if hash_targets:
                hasher = hashlib.sha256()
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        hasher.update(chunk)
                digest = hasher.hexdigest()
            records.append(
                {
                    "id": f"target:{path.name}",
                    "path": str(path),
                    "name": path.name,
                    "kind": "target",
                    "size": path.stat().st_size,
                    "digest": digest,
                }
            )

    if state_file:
        state_path = Path(state_file)
        if state_path.exists():
            loaded = json.loads(state_path.read_text(encoding="utf-8"))
            state_records = (
                loaded.get("inventory", loaded)
                if isinstance(loaded, Mapping)
                else loaded
            )
            records.extend(
                coerce_inventory(state_records)
                and [asdict(item) for item in coerce_inventory(state_records)]
            )

    return records


def rehearse_directory(*args: Any, **kwargs: Any) -> RetentionPlan:
    """Run :func:`plan_retention` on files found in a local directory."""
    inventory_kwargs = {}
    for key in (
        "root",
        "metadata_dir",
        "target_dir",
        "state_file",
        "hash_targets",
    ):
        if key in kwargs:
            inventory_kwargs[key] = kwargs.pop(key)
    inventory = inventory_from_directory(*args, **inventory_kwargs)
    return plan_retention(inventory, **kwargs)


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point for ``python -m tuf.retention``."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Offline TUF retention rehearsal"
    )
    parser.add_argument(
        "root",
        nargs="?",
        help="client cache root containing metadata/ and targets/",
    )
    parser.add_argument("--metadata-dir")
    parser.add_argument("--target-dir")
    parser.add_argument("--state-file")
    parser.add_argument("--quota", type=int, default=None)
    parser.add_argument("--max-bytes", type=int, default=None)
    parser.add_argument(
        "--json", action="store_true", help="print the full plan as JSON"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="accepted for clarity; rehearsal never mutates the cache",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="accepted for clarity; this command never uses the network",
    )
    parser.add_argument(
        "--inventory",
        help="JSON inventory/manifest to plan instead of scanning a directory",
    )
    args = parser.parse_args(argv)

    if args.inventory:
        inventory = json.loads(Path(args.inventory).read_text(encoding="utf-8"))
        plan = plan_retention(
            inventory,
            quota=args.quota,
            max_bytes=args.max_bytes,
        )
    else:
        plan = rehearse_directory(
            args.root,
            metadata_dir=args.metadata_dir,
            target_dir=args.target_dir,
            state_file=args.state_file,
            quota=args.quota,
            max_bytes=args.max_bytes,
        )
    if args.json:
        print(json.dumps(plan.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(
            "dry-run: "
            f"deletable={len(plan.deletable)} "
            f"reclaimable_bytes={plan.reclaimable_bytes}"
        )
        for item_id in plan.deletable:
            print(
                "DELETE "
                f"{item_id} "
                f"({plan.decisions[item_id].reclaimable_bytes} bytes)"
            )
        for item_id in plan.blocked:
            print(f"KEEP   {item_id}: {', '.join(plan.reasons_for(item_id))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
