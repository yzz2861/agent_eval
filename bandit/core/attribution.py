#
# SPDX-License-Identifier: Apache-2.0
"""Deterministic attribution of Bandit findings to maintained code.

This module consumes an existing Bandit JSON report and one or more release
manifests.  A release manifest is a finite, reviewable statement about which
source components are present in a build artifact and who maintained them.
Handovers are only applied when they carry proof and are effective at the
``as_of`` timestamp supplied with the evidence.

The output deliberately keeps three things separate:

* the current risk burden, which is counted once per owner and finding;
* legacy attribution, which remains reportable even after a handover; and
* review candidates, which are based only on filename similarity and never
  contribute to the burden.

All ordering and digests are derived from the input.  No wall-clock value is
used, so the same report and manifest bytes produce the same attribution.
"""

from __future__ import annotations

import datetime
import difflib
import fnmatch
import hashlib
import json
import os
import posixpath
import re
import sys
from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Iterable
from typing import Mapping
from typing import Optional
from typing import Sequence
from typing import Union

SCHEMA_VERSION = 1
POLICY_VERSION = "bandit-attribution-v1"
DEFAULT_NEAR_MATCH_THRESHOLD = 0.80

_ACTIVE_STATUSES = {
    "active",
    "beta",
    "ga",
    "in-service",
    "in_service",
    "legacy",
    "maintained",
    "old",
    "preview",
    "rc",
    "released",
    "shipping",
    "supported",
}
_RETIRED_STATUSES = {
    "archived",
    "decommissioned",
    "end-of-life",
    "end_of_life",
    "eol",
    "retired",
    "stopped",
    "stop-shipped",
    "stop_shipped",
    "sunset",
    "unsupported",
}

_ARTIFACT_KEYS = (
    "artifacts",
    "build_artifacts",
    "builds",
    "releases",
    "release_artifacts",
)
_COMPONENT_KEYS = (
    "components",
    "source_components",
    "code_components",
    "packages",
)
_HANDOVER_KEYS = (
    "handovers",
    "handover",
    "team_handovers",
    "handover_records",
    "ownership_transfers",
    "transfers",
)
_LEGACY_KEYS = (
    "legacy_attribution",
    "legacy_attributions",
    "legacy",
    "legacy_owners",
    "previous_attribution",
    "historical_attribution",
)
_OWNER_KEYS = (
    "owner",
    "maintainer",
    "maintainers",
    "maintained_by",
    "owning_team",
    "owned_by",
    "responsible_team",
    "maintaining_team",
    "team",
)
_LEGACY_OWNER_KEYS = (
    "legacy_owner",
    "original_owner",
    "previous_owner",
    "old_owner",
    "former_owner",
)
_PATH_KEYS = (
    "source_paths",
    "source_path",
    "source_files",
    "source_file",
    "paths",
    "path",
    "files",
    "file",
    "filenames",
    "filename",
    "sources",
    "source",
)

PathLike = Union[str, bytes, os.PathLike]
JSONSource = Union[
    PathLike,
    Mapping[str, Any],
    Sequence[Any],
]


class AttributionError(ValueError):
    """Raised when attribution evidence cannot be interpreted."""


def _normalise_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).lower()).strip("_")


def _first(mapping: Any, *names: str, default: Any = None) -> Any:
    """Return the first present value, accepting common key spellings."""
    if not isinstance(mapping, Mapping):
        return default
    normalised = {_normalise_key(key): value for key, value in mapping.items()}
    for name in names:
        if name in mapping and mapping[name] is not None:
            return mapping[name]
        value = normalised.get(_normalise_key(name))
        if value is not None:
            return value
    return default


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _as_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalised = value.strip().lower()
        if normalised in {"1", "true", "yes", "y", "on"}:
            return True
        if normalised in {"0", "false", "no", "n", "off"}:
            return False
    return bool(value)


def _owner_name(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        return value or None
    if isinstance(value, Mapping):
        candidate = _first(
            value,
            "id",
            "name",
            "team",
            "owner",
            "maintainer",
            "email",
        )
        return _owner_name(candidate)
    if isinstance(value, (list, tuple)):
        for item in value:
            candidate = _owner_name(item)
            if candidate:
                return candidate
    return str(value).strip() or None


def _normalise_path(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, Mapping):
        value = _first(value, *_PATH_KEYS)
        if value is None:
            return ""
    text = str(value).strip().replace("\\", "/")
    if text.startswith("file://"):
        text = text[7:]
    if not text:
        return ""
    text = re.sub(r"/+", "/", text)
    text = posixpath.normpath(text)
    while text.startswith("./"):
        text = text[2:]
    return "" if text == "." else text


def _paths_from(value: Any) -> list[str]:
    paths = []
    if value is None:
        return paths
    if isinstance(value, str):
        normalised = _normalise_path(value)
        return [normalised] if normalised else []
    if isinstance(value, Mapping):
        path_value = _first(value, *_PATH_KEYS)
        if path_value is not None and path_value is not value:
            return _paths_from(path_value)
        path_keys = [
            _normalise_path(key) for key in value if _looks_like_path(str(key))
        ]
        if path_keys:
            return path_keys
        return paths
    if isinstance(value, (list, tuple, set)):
        for item in value:
            paths.extend(_paths_from(item))
        return paths
    normalised = _normalise_path(value)
    return [normalised] if normalised else []


def _looks_like_path(value: str) -> bool:
    return (
        "/" in value
        or "\\" in value
        or value.endswith((".py", ".pyw", ".pyi"))
        or bool(re.search(r"[*?[]", value))
    )


def _parse_datetime(value: Any) -> Optional[datetime.datetime]:
    if value is None or value == "":
        return None
    if isinstance(value, datetime.datetime):
        parsed = value
    elif isinstance(value, datetime.date):
        parsed = datetime.datetime(
            value.year, value.month, value.day, tzinfo=datetime.timezone.utc
        )
    else:
        text = str(value).strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.datetime.fromisoformat(text)
        except ValueError:
            parsed = None
            for fmt in (
                "%Y-%m-%d",
                "%Y/%m/%d",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
            ):
                try:
                    parsed = datetime.datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue
            if parsed is None:
                return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.astimezone(datetime.timezone.utc)


def _format_datetime(value: Optional[datetime.datetime]) -> Optional[str]:
    if value is None:
        return None
    value = value.astimezone(datetime.timezone.utc)
    if value.microsecond:
        return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _json_default(value: Any) -> Any:
    if isinstance(value, (datetime.datetime, datetime.date)):
        return _format_datetime(_parse_datetime(value))
    if isinstance(value, os.PathLike):
        return os.fspath(value)
    if isinstance(value, (set, frozenset)):
        return sorted(value, key=str)
    return repr(value)


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_json_default,
    )


def _digest_value(value: Any) -> str:
    return (
        "sha256:"
        + hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()
    )


def _digest_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _read_json_or_yaml(text: str, name: str) -> Any:
    try:
        return json.loads(text)
    except ValueError as json_error:
        try:
            import yaml
        except ImportError:
            raise AttributionError(
                f"Unable to parse manifest/report {name!r} as JSON"
            ) from json_error
        try:
            return yaml.safe_load(text)
        except yaml.YAMLError as yaml_error:
            raise AttributionError(
                f"Unable to parse manifest/report {name!r}: {yaml_error}"
            ) from yaml_error


def _load_source(source: JSONSource, kind: str) -> tuple[Any, str]:
    if isinstance(source, Mapping) or isinstance(source, (list, tuple)):
        data = source
        return data, _digest_value(data)
    if hasattr(source, "read"):
        read = source.read()
        if isinstance(read, bytes):
            read = read.decode("utf-8")
        return _read_json_or_yaml(read, kind), _digest_text(read)
    if isinstance(source, bytes):
        text = source.decode("utf-8")
        return _read_json_or_yaml(text, kind), _digest_text(text)
    text = os.fspath(source)
    if text == "-":
        raw = sys.stdin.read()
        return _read_json_or_yaml(raw, kind), _digest_text(raw)
    if os.path.exists(text):
        with open(text, encoding="utf-8") as source_file:
            raw = source_file.read()
        return _read_json_or_yaml(raw, text), _digest_text(raw)
    stripped = text.lstrip()
    if stripped.startswith(("{", "[", "---")) or "\n" in text:
        return _read_json_or_yaml(text, kind), _digest_text(text)
    raise AttributionError(f"Unable to open {kind}: {text!r}")


@dataclass
class Component:
    id: str
    owner: Optional[str] = None
    legacy_owner: Optional[str] = None
    paths: list[str] = field(default_factory=list)
    revision: Optional[str] = None
    phase: Optional[str] = None
    source: Optional[str] = None

    def merge(self, other: "Component") -> None:
        if other.owner:
            self.owner = other.owner
        if other.legacy_owner:
            self.legacy_owner = other.legacy_owner
        if other.revision:
            self.revision = other.revision
        if other.phase:
            self.phase = other.phase
        if other.source:
            self.source = other.source
        for path in other.paths:
            if path not in self.paths:
                self.paths.append(path)


@dataclass
class Artifact:
    id: str
    name: Optional[str] = None
    digest: Optional[str] = None
    status: Optional[str] = None
    stop_ship_at: Optional[datetime.datetime] = None
    accepts_tickets: Optional[bool] = None
    owner: Optional[str] = None
    component_ids: list[str] = field(default_factory=list)
    phase: Optional[str] = None
    source: Optional[str] = None

    def merge(self, other: "Artifact") -> None:
        for attribute in (
            "name",
            "digest",
            "status",
            "stop_ship_at",
            "accepts_tickets",
            "owner",
            "phase",
            "source",
        ):
            value = getattr(other, attribute)
            if value is not None:
                setattr(self, attribute, value)
        for component_id in other.component_ids:
            if component_id not in self.component_ids:
                self.component_ids.append(component_id)


@dataclass
class Handover:
    component_id: str
    to_owner: str
    from_owner: Optional[str] = None
    effective_at: Optional[datetime.datetime] = None
    proof: Any = None
    verified: bool = False
    order: int = 0
    phase: Optional[str] = None
    source: Optional[str] = None

    @property
    def proven(self) -> bool:
        return bool(self.verified or self.proof)


@dataclass
class LegacyRecord:
    filename: Optional[str]
    owner: str
    artifact_id: Optional[str] = None
    component_id: Optional[str] = None
    phase: Optional[str] = None
    source: Optional[str] = None
    proof: Any = None


@dataclass
class Manifest:
    name: str
    digest: str
    phase: Optional[str] = None
    as_of: Optional[datetime.datetime] = None
    artifacts: dict[str, Artifact] = field(default_factory=dict)
    components: dict[str, Component] = field(default_factory=dict)
    handovers: list[Handover] = field(default_factory=list)
    legacy: list[LegacyRecord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    raw: Any = field(default=None, repr=False)


@dataclass
class Evidence:
    manifests: list[Manifest]
    artifacts: dict[str, Artifact]
    components: dict[str, Component]
    handovers: list[Handover]
    legacy: list[LegacyRecord]
    warnings: list[str]
    as_of: Optional[datetime.datetime]
    digest: str


@dataclass
class Finding:
    fingerprint: str
    filename: str
    result: Mapping[str, Any]
    candidate_for: Optional[str] = None


@dataclass
class _Claim:
    component: Optional[Component]
    artifact_ids: list[str]
    relation: str
    owner_override: Optional[str] = None
    owner_source_override: Optional[str] = None
    legacy_owner: Optional[str] = None
    legacy_source: Optional[str] = None
    matched_path: Optional[str] = None


class AttributionReport(dict):
    """Attribution result with both mapping and attribute-style access."""

    def __init__(
        self,
        attributions: list[dict[str, Any]],
        legacy_attribution: list[dict[str, Any]],
        review_candidates: list[dict[str, Any]],
        double_counting: list[dict[str, Any]],
        risk_burden: list[dict[str, Any]],
        component_burden: list[dict[str, Any]],
        unattributed: list[dict[str, Any]],
        summary: dict[str, Any],
        evidence: dict[str, Any],
    ):
        self.attributions = attributions
        self.legacy_attribution = legacy_attribution
        self.review_candidates = review_candidates
        self.double_counting = double_counting
        self.risk_burden = risk_burden
        self.component_burden = component_burden
        self.unattributed = unattributed
        self.summary = summary
        self.evidence = evidence
        super().__init__(self.as_dict())

    @property
    def schema_version(self) -> int:
        return SCHEMA_VERSION

    @property
    def policy_version(self) -> str:
        return POLICY_VERSION

    @property
    def legacy(self) -> list[dict[str, Any]]:
        return self.legacy_attribution

    @property
    def candidates(self) -> list[dict[str, Any]]:
        return self.review_candidates

    @property
    def duplicates(self) -> list[dict[str, Any]]:
        return self.double_counting

    @property
    def burden(self) -> list[dict[str, Any]]:
        return self.risk_burden

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "policy_version": POLICY_VERSION,
            "evidence": self.evidence,
            "summary": self.summary,
            "attributions": self.attributions,
            "legacy_attribution": self.legacy_attribution,
            "review_candidates": self.review_candidates,
            "double_counting": self.double_counting,
            "risk_burden": self.risk_burden,
            "component_burden": self.component_burden,
            "unattributed": self.unattributed,
        }

    def to_dict(self) -> dict[str, Any]:
        return self.as_dict()

    def to_json(self, **kwargs: Any) -> str:
        options = {
            "sort_keys": True,
            "indent": 2,
            "separators": (",", ": "),
        }
        options.update(kwargs)
        return json.dumps(self.as_dict(), **options)

    def __getitem__(self, key: str) -> Any:
        aliases = {
            "legacy": "legacy_attribution",
            "candidates": "review_candidates",
            "duplicates": "double_counting",
            "burden": "risk_burden",
        }
        return super().__getitem__(aliases.get(key, key))

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default


def _entry_items(value: Any) -> list[tuple[Optional[str], Any]]:
    if isinstance(value, Mapping):
        return list(value.items())
    return [(None, item) for item in _as_list(value)]


def _parse_component(
    entry: Any,
    key: Optional[str],
    phase: Optional[str],
    source: str,
) -> Optional[Component]:
    owner = _first(entry, *_OWNER_KEYS)
    legacy_owner = _first(entry, *_LEGACY_OWNER_KEYS)
    paths = _paths_from(entry)
    revision = _first(
        entry,
        "revision",
        "commit",
        "version",
        "digest",
        "checksum",
        "hash",
    )

    if isinstance(entry, str):
        component_id = key if key else entry
        if key and _looks_like_path(key):
            paths = [_normalise_path(key)]
            component_id = "path:" + paths[0]
            if not _looks_like_path(entry):
                owner = entry
        elif not key and _looks_like_path(entry):
            component_id = "path:" + _normalise_path(entry)
            paths = [_normalise_path(entry)]
        elif key and not _looks_like_path(entry):
            owner = entry
            paths = []
        return Component(
            id=str(component_id),
            owner=_owner_name(owner),
            paths=paths,
            phase=phase,
            source=source,
        )

    if isinstance(entry, (list, tuple)):
        paths = _paths_from(entry)
        component_id = key or ("path:" + paths[0] if paths else None)
        if not component_id:
            return None
        return Component(
            id=str(component_id),
            paths=paths,
            phase=phase,
            source=source,
        )

    if not isinstance(entry, Mapping):
        return None

    if owner is None:
        file_owners = _first(entry, "files", "source_files")
        if isinstance(file_owners, Mapping):
            candidate_owners = sorted(
                {
                    _owner_name(value)
                    for value in file_owners.values()
                    if _owner_name(value)
                }
            )
            if len(candidate_owners) == 1:
                owner = candidate_owners[0]

    explicit_id = _first(
        entry,
        "id",
        "component_id",
        "component",
        "name",
        "bom_ref",
        "bom-ref",
        "ref",
    )
    component_id = key or explicit_id
    if not component_id:
        component_id = "path:" + paths[0] if paths else None
    if not component_id:
        return None
    explicit_text = str(component_id)
    if key and _looks_like_path(key) and not paths:
        paths = [_normalise_path(key)]
        component_id = "path:" + paths[0]
    if not key and _looks_like_path(explicit_text) and not paths:
        paths = [_normalise_path(explicit_text)]
        component_id = "path:" + paths[0]
    return Component(
        id=str(component_id),
        owner=_owner_name(owner),
        legacy_owner=_owner_name(legacy_owner),
        paths=paths,
        revision=str(revision) if revision is not None else None,
        phase=_first(entry, "phase", "stage", default=phase),
        source=source,
    )


def _find_component(
    components: Mapping[str, Component], reference: str
) -> Optional[Component]:
    if reference in components:
        return components[reference]
    normalised = _normalise_path(reference)
    for component in components.values():
        for path in component.paths:
            if _path_matches(normalised, path):
                return component
    return None


def _component_from_reference(
    reference: Any,
    components: dict[str, Component],
    artifact: Artifact,
    phase: Optional[str],
    source: str,
) -> Optional[Component]:
    if isinstance(reference, str):
        existing = _find_component(components, reference)
        if existing:
            return existing
        if _looks_like_path(reference):
            component_id = "path:" + _normalise_path(reference)
            component = components.get(component_id)
            if component is None:
                component = Component(
                    id=component_id,
                    owner=artifact.owner,
                    paths=[_normalise_path(reference)],
                    phase=phase,
                    source=source,
                )
                components[component_id] = component
            return component
        component = Component(
            id=reference,
            owner=artifact.owner,
            phase=phase,
            source=source,
        )
        components[reference] = component
        return component

    if isinstance(reference, Mapping):
        parsed = _parse_component(reference, None, phase, source)
        if parsed is None:
            return None
        existing = _find_component(components, parsed.id)
        if existing is None:
            for path in parsed.paths:
                existing = _find_component(components, path)
                if existing:
                    break
        if existing:
            existing.merge(parsed)
            if not existing.owner:
                existing.owner = artifact.owner
            return existing
        if not parsed.owner:
            parsed.owner = artifact.owner
        components[parsed.id] = parsed
        return parsed

    if isinstance(reference, (list, tuple)):
        parsed = _parse_component(reference, None, phase, source)
        if parsed:
            components.setdefault(parsed.id, parsed)
            return components[parsed.id]
    return None


def _artifact_entries(data: Any) -> list[tuple[Optional[str], Any]]:
    if isinstance(data, list):
        return [(None, item) for item in data]
    if not isinstance(data, Mapping):
        return []
    for key in _ARTIFACT_KEYS:
        value = _first(data, key)
        if value is not None:
            return _entry_items(value)
    for key in ("artifact", "build", "release"):
        value = _first(data, key)
        if isinstance(value, Mapping):
            return [(None, value)]
        if isinstance(value, str):
            return [(None, {"id": value})]
    return []


def _component_entries(data: Any) -> list[tuple[Optional[str], Any]]:
    if isinstance(data, list):
        return [(None, item) for item in data]
    if not isinstance(data, Mapping):
        return []
    for key in _COMPONENT_KEYS:
        value = _first(data, key)
        if value is not None:
            return _entry_items(value)
    for key in ("component", "source_component"):
        value = _first(data, key)
        if value is not None:
            return _entry_items(value)
    return []


def _parse_artifacts(
    data: Any,
    components: dict[str, Component],
    phase: Optional[str],
    source: str,
    warnings: list[str],
) -> dict[str, Artifact]:
    artifacts: dict[str, Artifact] = {}
    for key, entry in _artifact_entries(data):
        if isinstance(entry, str):
            if key and re.match(r"^(sha\d+:|[0-9a-fA-F]{32,})", entry):
                entry = {"id": key, "digest": entry}
            elif key:
                entry = {"id": key, "components": [entry]}
            else:
                entry = {"id": entry}
        elif isinstance(entry, (list, tuple)):
            entry = {"id": key, "components": list(entry)}
        if not isinstance(entry, Mapping):
            warnings.append(f"{source}: ignored artifact entry {entry!r}")
            continue

        artifact_id = _first(
            entry,
            "id",
            "artifact_id",
            "artifact",
            "release",
            "build",
            "name",
            default=key,
        )
        if artifact_id is None:
            warnings.append(f"{source}: artifact without an id was ignored")
            continue

        status = _first(entry, "status", "lifecycle", "state")
        if status is None and _as_bool(
            _first(entry, "eol", "retired", "end_of_life", default=None)
        ):
            status = "eol"
        artifact = Artifact(
            id=str(artifact_id),
            name=_first(entry, "name", "label", "product"),
            digest=_first(
                entry,
                "digest",
                "sha256",
                "checksum",
                "hash",
                "artifact_digest",
            ),
            status=status,
            stop_ship_at=_parse_datetime(
                _first(
                    entry,
                    "stop_ship_at",
                    "stop_ship",
                    "stop_ship_date",
                    "end_of_sale",
                    "end_of_sale_at",
                    "end_of_sale_date",
                    "eol_at",
                    "eol_date",
                    "end_of_life_at",
                    "retire_at",
                    "retirement_date",
                    "sunset_at",
                )
            ),
            accepts_tickets=_as_bool(
                _first(
                    entry,
                    "accepts_tickets",
                    "accepting_tickets",
                    "accepts_work",
                    "maintained",
                    "active",
                    "shipping",
                    "in_service",
                    default=None,
                )
            ),
            owner=_owner_name(_first(entry, *_OWNER_KEYS)),
            phase=_first(entry, "phase", "stage", default=phase),
            source=source,
        )
        if artifact.name is not None:
            artifact.name = str(artifact.name)
        if artifact.digest is not None:
            artifact.digest = str(artifact.digest)
        if artifact.status is not None:
            artifact.status = str(artifact.status)
        if artifact.digest is None:
            warnings.append(
                f"{source}: artifact {artifact.id!r} has no pinned digest"
            )

        references = _first(
            entry,
            "components",
            "component_ids",
            "source_components",
            "source_component_refs",
            "component_refs",
            "contents",
            default=[],
        )
        direct_paths = _paths_from(
            _first(
                entry,
                "source_paths",
                "source_path",
                "paths",
                "path",
                "files",
                "file",
                "filenames",
                "filename",
                "sources",
                "source",
                default=[],
            )
        )
        if isinstance(references, Mapping):
            component_fields = {
                "id",
                "component",
                "component_id",
                "name",
                "path",
                "paths",
                "file",
                "files",
                "source_path",
                "source_paths",
                "owner",
                "maintainer",
                "bom_ref",
            }
            if any(
                _normalise_key(key) in component_fields for key in references
            ):
                references = [references]
            else:
                references = [
                    (
                        {"id": key, "owner": value}
                        if isinstance(value, str)
                        and not _looks_like_path(value)
                        else (
                            {"id": key, "paths": value}
                            if isinstance(value, (str, list, tuple))
                            else (
                                dict(value, id=key)
                                if isinstance(value, Mapping)
                                else {"id": key}
                            )
                        )
                    )
                    for key, value in references.items()
                ]
        for reference in _as_list(references):
            component = _component_from_reference(
                reference, components, artifact, artifact.phase, source
            )
            if component and component.id not in artifact.component_ids:
                artifact.component_ids.append(component.id)

        if artifact.owner:
            for component_id in artifact.component_ids:
                component = components.get(component_id)
                if component and not component.owner:
                    component.owner = artifact.owner

        for path in direct_paths:
            component = _find_component(components, path)
            if component is None and len(artifact.component_ids) == 1:
                component = components.get(artifact.component_ids[0])
                if component:
                    if path not in component.paths:
                        component.paths.append(path)
                    if not component.owner:
                        component.owner = artifact.owner
            if component is None:
                component_id = "path:" + path
                component = components.get(component_id)
                if component is None:
                    component = Component(
                        id=component_id,
                        owner=artifact.owner,
                        paths=[path],
                        phase=artifact.phase,
                        source=source,
                    )
                    components[component_id] = component
            if component.id not in artifact.component_ids:
                artifact.component_ids.append(component.id)

        artifact_owners = _first(
            entry,
            "owners",
            "component_owners",
            "owner_by_component",
            "file_owners",
        )
        source_entries = _first(
            entry, "sources", "source_paths", "files", "source_files"
        )
        if isinstance(source_entries, (list, tuple)):
            artifact_owners = (
                dict(artifact_owners)
                if isinstance(artifact_owners, Mapping)
                else {}
            )
            for source_entry in source_entries:
                if not isinstance(source_entry, Mapping):
                    continue
                path = _normalise_path(_first(source_entry, *_PATH_KEYS))
                owner = _owner_name(_first(source_entry, *_OWNER_KEYS))
                if path and owner:
                    artifact_owners.setdefault(path, owner)
        file_owners = _first(entry, "files", "source_files")
        if isinstance(file_owners, Mapping):
            artifact_owners = (
                dict(artifact_owners)
                if isinstance(artifact_owners, Mapping)
                else {}
            )
            for reference, value in file_owners.items():
                if isinstance(value, str) and _looks_like_path(str(reference)):
                    artifact_owners.setdefault(reference, value)
        if isinstance(artifact_owners, Mapping):
            for reference, owner in artifact_owners.items():
                component = _find_component(components, str(reference))
                if component is None:
                    continue
                component.owner = _owner_name(owner) or component.owner

        if artifact.id in artifacts:
            artifacts[artifact.id].merge(artifact)
        else:
            artifacts[artifact.id] = artifact
    return artifacts


def _parse_handovers(
    data: Any,
    components: dict[str, Component],
    phase: Optional[str],
    source: str,
    warnings: list[str],
    start_order: int,
) -> list[Handover]:
    if not isinstance(data, Mapping):
        return []

    value = None
    for key in _HANDOVER_KEYS:
        value = _first(data, key)
        if value is not None:
            break
    if value is None:
        return []

    handovers = []
    order = start_order
    if isinstance(value, Mapping) and any(
        _normalise_key(key)
        in {
            "component",
            "component_id",
            "component_path",
            "path",
            "file",
            "filename",
            "artifact",
            "to",
            "to_owner",
            "new_owner",
            "owner",
        }
        for key in value
    ):
        entries = [(None, value)]
    else:
        entries = _entry_items(value)
    for key, entry in entries:
        if isinstance(entry, str) and key:
            items = [
                {
                    "component": key,
                    "to": entry,
                }
            ]
        else:
            items = _as_list(entry)

        for item in items:
            order += 1
            if isinstance(item, str) and key:
                item = {"component": key, "to": item}
            if not isinstance(item, Mapping):
                warnings.append(f"{source}: ignored handover {item!r}")
                continue

            reference = _first(
                item,
                "component",
                "component_id",
                "component_path",
                "path",
                "file",
                "filename",
                "artifact",
            )
            if isinstance(reference, Mapping):
                reference = _first(
                    reference,
                    "id",
                    "component",
                    "component_id",
                    "path",
                    "file",
                    "filename",
                )
            to_owner = _owner_name(
                _first(
                    item,
                    "to",
                    "to_owner",
                    "new_owner",
                    "new_maintainer",
                    "new_team",
                    "assigned_to",
                    "owner",
                    "maintainer",
                    "team",
                )
            )
            if reference is None:
                warnings.append(f"{source}: handover without a component")
                continue
            if not to_owner:
                warnings.append(f"{source}: handover without a target owner")
                continue

            component = _find_component(components, str(reference))
            if component is None:
                path = _normalise_path(reference)
                if _looks_like_path(path):
                    component_id = "path:" + path
                    component = Component(
                        id=component_id,
                        paths=[path],
                        phase=phase,
                        source=source,
                    )
                else:
                    component_id = str(reference)
                    component = Component(
                        id=component_id, phase=phase, source=source
                    )
                components[component.id] = component

            proof = _first(
                item,
                "proof",
                "evidence",
                "handover_proof",
                "handover_evidence",
                "proof_ref",
                "evidence_ref",
                "approval",
                "ticket",
                "handover_ticket",
                "document",
                "reference",
            )
            verified = bool(
                _as_bool(
                    _first(
                        item,
                        "verified",
                        "approved",
                        "signed",
                        "confirmed",
                        default=False,
                    )
                )
            )
            if not (proof or verified):
                warnings.append(
                    f"{source}: handover for {component.id!r} has no proof"
                )

            handovers.append(
                Handover(
                    component_id=component.id,
                    from_owner=_owner_name(
                        _first(
                            item,
                            "from",
                            "from_owner",
                            "previous_owner",
                            "old_owner",
                        )
                    ),
                    to_owner=to_owner,
                    effective_at=_parse_datetime(
                        _first(
                            item,
                            "effective_at",
                            "effective",
                            "effective_date",
                            "effective_on",
                            "from_date",
                            "start",
                            "since",
                            "date",
                            "timestamp",
                        )
                    ),
                    proof=proof,
                    verified=verified,
                    order=order,
                    phase=_first(item, "phase", "stage", default=phase),
                    source=source,
                )
            )
    return handovers


def _legacy_records_from_item(
    key: Optional[str],
    entry: Any,
    phase: Optional[str],
    source: str,
) -> list[LegacyRecord]:
    if isinstance(entry, str):
        if key is None:
            return []
        filename = _normalise_path(key)
        if not filename:
            return []
        return [
            LegacyRecord(
                filename=filename,
                owner=_owner_name(entry) or entry,
                phase=phase,
                source=source,
            )
        ]

    if isinstance(entry, Mapping):
        owner = _owner_name(
            _first(
                entry,
                "owner",
                "team",
                "maintainer",
                "attributed_to",
                "to",
            )
        )
        filenames = _paths_from(_first(entry, *_PATH_KEYS, default=key))
        if not owner or not filenames:
            return []
        return [
            LegacyRecord(
                filename=filename,
                owner=owner,
                artifact_id=_first(
                    entry,
                    "artifact",
                    "artifact_id",
                    "release",
                    "build",
                ),
                component_id=_first(
                    entry, "component", "component_id", "source_component"
                ),
                phase=_first(entry, "phase", "stage", default=phase),
                source=source,
                proof=_first(entry, "proof", "evidence", "ticket"),
            )
            for filename in filenames
        ]

    records = []
    for item in _as_list(entry):
        records.extend(_legacy_records_from_item(key, item, phase, source))
    return records


def _parse_legacy(
    data: Any,
    components: dict[str, Component],
    phase: Optional[str],
    source: str,
) -> list[LegacyRecord]:
    if not isinstance(data, Mapping):
        return []

    records = []
    for key in _LEGACY_KEYS:
        value = _first(data, key)
        if value is None:
            continue
        if isinstance(value, Mapping):
            for filename, entry in value.items():
                if filename in components:
                    owner = _owner_name(entry)
                    if owner:
                        components[filename].legacy_owner = owner
                    continue
                normalised = _normalise_path(filename)
                if _find_component(components, normalised):
                    owner = _owner_name(entry)
                    if owner:
                        component = _find_component(components, normalised)
                        if component:
                            component.legacy_owner = owner
                            continue
                records.extend(
                    _legacy_records_from_item(filename, entry, phase, source)
                )
        else:
            records.extend(
                _legacy_records_from_item(None, value, phase, source)
            )
    return records


def _parse_manifest(
    source: JSONSource, name: Optional[str] = None
) -> Manifest:
    if isinstance(source, Manifest):
        return source
    raw, digest = _load_source(source, "manifest")
    if raw is None:
        raw = {}
    manifest_name = name or (
        os.fspath(source)
        if isinstance(source, (str, bytes, os.PathLike))
        else f"<manifest-{digest[-12:]}>"
    )
    if isinstance(raw, list):
        artifact_like = any(
            isinstance(entry, Mapping)
            and any(
                _normalise_key(key)
                in {
                    "artifact",
                    "artifact_id",
                    "release",
                    "build",
                    "digest",
                    "components",
                    "source_components",
                }
                for key in entry
            )
            for entry in raw
        )
        raw = {"artifacts": raw} if artifact_like else {"components": raw}
    if not isinstance(raw, Mapping):
        raise AttributionError(
            f"Manifest {manifest_name!r} must be a mapping or a list"
        )

    phase = _first(raw, "phase", "stage", "snapshot", "manifest_phase")
    manifest = Manifest(
        name=str(manifest_name),
        digest=digest,
        phase=phase,
        as_of=_parse_datetime(
            _first(
                raw,
                "as_of",
                "effective_at",
                "evidence_at",
                "generated_at",
            )
        ),
        raw=raw,
    )

    for key, entry in _component_entries(raw):
        component = _parse_component(entry, key, manifest.phase, manifest.name)
        if component is None:
            manifest.warnings.append(
                f"{manifest.name}: ignored component entry {entry!r}"
            )
            continue
        if component.id in manifest.components:
            manifest.components[component.id].merge(component)
        else:
            manifest.components[component.id] = component

    for owner_map_name in ("component_owners", "component_owner"):
        owner_map = _first(raw, owner_map_name)
        if isinstance(owner_map, Mapping):
            for component_id, owner in owner_map.items():
                component = _find_component(
                    manifest.components, str(component_id)
                )
                if component is None:
                    component = Component(
                        id=str(component_id),
                        phase=manifest.phase,
                        source=manifest.name,
                    )
                    manifest.components[component.id] = component
                component.owner = _owner_name(owner)

    owners_map = _first(raw, "owners", "teams")
    if isinstance(owners_map, Mapping):
        for owner, references in owners_map.items():
            for reference in _as_list(references):
                component = _find_component(
                    manifest.components, str(reference)
                )
                if component is None:
                    component = Component(
                        id=str(reference),
                        phase=manifest.phase,
                        source=manifest.name,
                    )
                    manifest.components[component.id] = component
                component.owner = _owner_name(owner)

    manifest.artifacts = _parse_artifacts(
        raw,
        manifest.components,
        manifest.phase,
        manifest.name,
        manifest.warnings,
    )

    singular_release = any(
        isinstance(_first(raw, key), str)
        for key in ("release", "artifact", "build")
    )
    if (
        singular_release
        and len(manifest.artifacts) == 1
        and manifest.components
    ):
        only_artifact = next(iter(manifest.artifacts.values()))
        if not only_artifact.component_ids:
            only_artifact.component_ids = sorted(manifest.components)

    relation_map = _first(
        raw,
        "artifact_to_components",
        "artifact_to_component",
        "artifact_components",
        "artifacts_to_components",
        "artifact_component_map",
        "artifact_component_edges",
    )
    if isinstance(relation_map, Mapping):
        for artifact_id, references in relation_map.items():
            artifact = manifest.artifacts.get(str(artifact_id))
            if artifact is None:
                artifact = Artifact(
                    id=str(artifact_id),
                    phase=manifest.phase,
                    source=manifest.name,
                )
                manifest.artifacts[artifact.id] = artifact
                manifest.warnings.append(
                    f"{manifest.name}: artifact {artifact.id!r} was "
                    "defined only by its component relation"
                )
            for reference in _as_list(references):
                component = _component_from_reference(
                    reference,
                    manifest.components,
                    artifact,
                    artifact.phase,
                    manifest.name,
                )
                if component and component.id not in artifact.component_ids:
                    artifact.component_ids.append(component.id)
    relation_entries = _first(
        raw,
        "artifact_component_relations",
        "artifact_relations",
        "ownership_relations",
        "component_relations",
        "relations",
    )
    for relation in _as_list(relation_entries):
        if not isinstance(relation, Mapping):
            continue
        artifact_id = _first(
            relation,
            "artifact",
            "artifact_id",
            "build_artifact",
            "release",
            "build",
        )
        references = _first(
            relation,
            "components",
            "component",
            "component_id",
            "source_component",
            "source_components",
        )
        if artifact_id is None or references is None:
            continue
        artifact = manifest.artifacts.get(str(artifact_id))
        if artifact is None:
            artifact = Artifact(
                id=str(artifact_id),
                phase=manifest.phase,
                source=manifest.name,
            )
            manifest.artifacts[artifact.id] = artifact
        for reference in _as_list(references):
            component = _component_from_reference(
                reference,
                manifest.components,
                artifact,
                artifact.phase,
                manifest.name,
            )
            if component and component.id not in artifact.component_ids:
                artifact.component_ids.append(component.id)

    manifest.handovers = _parse_handovers(
        raw,
        manifest.components,
        manifest.phase,
        manifest.name,
        manifest.warnings,
        0,
    )
    manifest.legacy = _parse_legacy(
        raw, manifest.components, manifest.phase, manifest.name
    )

    for component in manifest.components.values():
        if not component.paths:
            manifest.warnings.append(
                f"{manifest.name}: component {component.id!r} has no paths"
            )
        if not component.revision:
            manifest.warnings.append(
                f"{manifest.name}: component {component.id!r} has no revision"
            )
    return manifest


def _merge_manifests(manifests: Sequence[Manifest]) -> Evidence:
    artifacts: dict[str, Artifact] = {}
    components: dict[str, Component] = {}
    handovers: list[Handover] = []
    legacy: list[LegacyRecord] = []
    warnings: list[str] = []

    for manifest in manifests:
        for artifact_id, artifact in manifest.artifacts.items():
            if artifact_id in artifacts:
                artifacts[artifact_id].merge(artifact)
            else:
                artifacts[artifact_id] = artifact
        for component_id, component in manifest.components.items():
            if component_id in components:
                components[component_id].merge(component)
            else:
                components[component_id] = component
        for handover in manifest.handovers:
            handover.order = len(handovers)
            handovers.append(handover)
        legacy.extend(manifest.legacy)
        warnings.extend(manifest.warnings)

    as_of_values = [
        manifest.as_of for manifest in manifests if manifest.as_of is not None
    ]
    as_of = max(as_of_values) if as_of_values else None
    if len(set(as_of_values)) > 1:
        warnings.append(
            "manifests declare different as_of values; the latest was used"
        )

    digest = _digest_value(
        {
            "policy": POLICY_VERSION,
            "manifests": [
                {"digest": manifest.digest} for manifest in manifests
            ],
            "as_of": _format_datetime(as_of),
        }
    )
    return Evidence(
        manifests=list(manifests),
        artifacts=artifacts,
        components=components,
        handovers=handovers,
        legacy=legacy,
        warnings=sorted(set(warnings)),
        as_of=as_of,
        digest=digest,
    )


def load_manifest(source: JSONSource, name: Optional[str] = None) -> Manifest:
    """Load one release manifest from a path, file object or mapping."""
    return _parse_manifest(source, name=name)


def _sequence_is_single_manifest(entries: Sequence[Any]) -> bool:
    if not entries or not all(isinstance(item, Mapping) for item in entries):
        return False
    artifact_like = 0
    component_like = 0
    for entry in entries:
        keys = {_normalise_key(key) for key in entry}
        if ("id" in keys or "artifact" in keys or "release" in keys) and (
            "components" in keys
            or "source_components" in keys
            or "files" in keys
            or "paths" in keys
        ):
            artifact_like += 1
        elif "path" in keys or "source_paths" in keys or "file" in keys:
            component_like += 1
    return artifact_like == len(entries) or component_like == len(entries)


def load_manifests(
    manifests: Union[JSONSource, Sequence[JSONSource]],
) -> Evidence:
    """Load and merge release manifests in the order supplied."""
    if isinstance(manifests, Evidence):
        return manifests
    if isinstance(manifests, Mapping):
        nested = _first(manifests, "manifests", "release_manifests")
        if nested is not None and not any(
            _first(manifests, key) is not None
            for key in _ARTIFACT_KEYS + _COMPONENT_KEYS + _HANDOVER_KEYS
        ):
            return load_manifests(nested)
    if isinstance(manifests, (str, bytes, os.PathLike, Mapping)):
        sources = [manifests]
    elif _sequence_is_single_manifest(manifests):
        sources = [list(manifests)]
    else:
        sources = list(manifests)
    if not sources:
        raise AttributionError("At least one release manifest is required")
    if all(isinstance(source, str) for source in sources) and len(sources) > 1:
        # A list of strings is treated as a list of manifest paths.
        sources = [source for source in sources]
    parsed = [_parse_manifest(source) for source in sources]
    return _merge_manifests(parsed)


def _path_matches(filename: str, pattern: str) -> bool:
    filename = _normalise_path(filename)
    pattern = _normalise_path(pattern)
    if not filename or not pattern:
        return False
    if filename == pattern:
        return True

    if re.search(r"[*?[]", pattern):
        parts = filename.split("/")
        for index in range(len(parts)):
            suffix = "/".join(parts[index:])
            if fnmatch.fnmatchcase(suffix, pattern):
                return True
        return fnmatch.fnmatchcase(filename, pattern)

    if "/" not in pattern or "/" not in filename:
        # A lone basename is a review clue, never an exact path relation.
        return False
    if filename.endswith("/" + pattern):
        return True
    if pattern.endswith("/" + filename):
        return True
    return False


def _near_match(
    filename: str, pattern: str, threshold: float
) -> Optional[tuple[float, str]]:
    filename = _normalise_path(filename)
    pattern = _normalise_path(pattern)
    if not filename or not pattern or _path_matches(filename, pattern):
        return None
    filename_base = posixpath.basename(filename)
    pattern_base = posixpath.basename(pattern)
    if filename_base and filename_base == pattern_base:
        return 1.0, "same_basename_different_path"

    base_score = difflib.SequenceMatcher(
        None, filename_base, pattern_base
    ).ratio()
    path_score = difflib.SequenceMatcher(None, filename, pattern).ratio()
    score = max(base_score, path_score)
    if score >= threshold:
        return score, "similar_filename"
    return None


def _fingerprint(result: Mapping[str, Any]) -> str:
    supplied = _first(result, "fingerprint", "issue_fingerprint", "id")
    if supplied:
        return str(supplied)
    identity = {
        "filename": _normalise_path(result.get("filename")),
        "test_id": result.get("test_id"),
        "test_name": result.get("test_name"),
        "line_number": result.get("line_number"),
        "issue_text": result.get("issue_text"),
    }
    return _digest_value(identity)


def _iter_report_results(report: Mapping[str, Any]) -> list[Finding]:
    findings = []
    report_results = report.get("results") or []
    if isinstance(report_results, Mapping):
        report_results = report_results.values()
    for result in report_results:
        if not isinstance(result, Mapping):
            continue
        findings.append(
            Finding(
                fingerprint=_fingerprint(result),
                filename=_normalise_path(result.get("filename")),
                result=result,
            )
        )
        for candidate in result.get("candidates") or []:
            if not isinstance(candidate, Mapping):
                continue
            findings.append(
                Finding(
                    fingerprint=_fingerprint(candidate),
                    filename=_normalise_path(candidate.get("filename")),
                    result=candidate,
                    candidate_for=findings[-1].fingerprint,
                )
            )
    return findings


def _status_accepts_tickets(
    artifact: Artifact, as_of: Optional[datetime.datetime]
) -> bool:
    if artifact.accepts_tickets is not None:
        return artifact.accepts_tickets

    status = (
        _normalise_key(artifact.status)
        if artifact.status is not None
        else None
    )
    if artifact.stop_ship_at is not None and as_of is not None:
        return as_of < artifact.stop_ship_at
    if status in _RETIRED_STATUSES:
        return False
    # Unknown statuses, and old products without a stop-ship date, may still
    # receive tickets. A dated stop-ship is the authoritative boundary.
    return True


class Attributor:
    """Resolve findings against a fixed set of manifests and handovers."""

    def __init__(
        self,
        evidence: Union[Evidence, JSONSource, Sequence[JSONSource]],
        as_of: Optional[Union[str, datetime.datetime]] = None,
        near_match_threshold: float = DEFAULT_NEAR_MATCH_THRESHOLD,
    ):
        if not isinstance(evidence, Evidence):
            evidence = load_manifests(evidence)
        self.evidence = evidence
        explicit_as_of = _parse_datetime(as_of)
        if as_of is not None and explicit_as_of is None:
            raise AttributionError(f"Invalid as_of timestamp: {as_of!r}")
        self._base_as_of = explicit_as_of or evidence.as_of
        self.as_of = self._base_as_of
        self.near_match_threshold = float(near_match_threshold)
        if not 0.0 <= self.near_match_threshold <= 1.0:
            raise AttributionError(
                "near_match_threshold must be between 0 and 1"
            )
        self._path_index = self._build_path_index()
        self._artifacts_by_component = self._build_artifact_index()
        self._handovers_by_component = self._build_handover_index()
        self._handover_warnings: set[str] = set()

    def _build_path_index(self) -> list[tuple[str, Component]]:
        index = []
        for component in sorted(
            self.evidence.components.values(), key=lambda item: item.id
        ):
            for path in sorted(set(component.paths)):
                index.append((path, component))
        return index

    def _build_artifact_index(self) -> dict[str, list[str]]:
        index: dict[str, list[str]] = {}
        for artifact in sorted(
            self.evidence.artifacts.values(), key=lambda item: item.id
        ):
            for component_id in sorted(set(artifact.component_ids)):
                index.setdefault(component_id, []).append(artifact.id)
        return index

    def _build_handover_index(self) -> dict[str, list[Handover]]:
        index: dict[str, list[Handover]] = {}
        for handover in self.evidence.handovers:
            index.setdefault(handover.component_id, []).append(handover)
        return index

    def _current_owner(
        self, component: Component
    ) -> tuple[Optional[str], Optional[str], Optional[Handover]]:
        owner = component.owner
        source = "component" if owner else None
        handovers = [
            handover
            for handover in self._handovers_by_component.get(component.id, [])
            if handover.proven
            and (
                self.as_of is None
                or handover.effective_at is None
                or handover.effective_at <= self.as_of
            )
        ]
        applied = None
        for handover in sorted(
            handovers,
            key=lambda item: (
                item.effective_at
                or datetime.datetime.min.replace(tzinfo=datetime.timezone.utc),
                item.order,
            ),
        ):
            if (
                handover.from_owner is None
                or owner is None
                or handover.from_owner == owner
                or handover.to_owner == owner
            ):
                owner = handover.to_owner
                source = "handover"
                applied = handover
            else:
                self._handover_warnings.add(
                    "ignored stale handover for "
                    f"{component.id!r}: {handover.from_owner!r} -> "
                    f"{handover.to_owner!r}"
                )
        if applied is not None:
            return owner, source, applied
        return owner, source, None

    def _legacy_records_for(
        self, component: Optional[Component], filename: str
    ) -> list[LegacyRecord]:
        records = []
        for record in self._legacy_records_for_filename(filename):
            records.append(record)
        if component and component.legacy_owner:
            records.append(
                LegacyRecord(
                    filename=filename,
                    owner=component.legacy_owner,
                    component_id=component.id,
                    phase=component.phase,
                    source=component.source,
                )
            )
        deduplicated = {}
        for record in records:
            key = (
                record.owner,
                record.artifact_id,
                record.component_id,
                record.phase,
                record.source,
            )
            deduplicated[key] = record
        return [deduplicated[key] for key in sorted(deduplicated)]

    def _legacy_records_for_filename(
        self, filename: str
    ) -> list[LegacyRecord]:
        return [
            record
            for record in self.evidence.legacy
            if record.filename and _path_matches(filename, record.filename)
        ]

    def _artifact_accepts(self, artifact_ids: Iterable[str]) -> bool:
        artifacts = [
            self.evidence.artifacts[artifact_id]
            for artifact_id in artifact_ids
            if artifact_id in self.evidence.artifacts
        ]
        if not artifacts:
            return True
        return any(
            _status_accepts_tickets(artifact, self.as_of)
            for artifact in artifacts
        )

    def _matched_component_path(
        self, component: Component, filename: str
    ) -> Optional[str]:
        matches = [
            path for path in component.paths if _path_matches(filename, path)
        ]
        if not matches:
            return None
        return max(matches, key=lambda path: (len(path), path))

    def _claims_for(self, finding: Finding) -> list[_Claim]:
        claims = []
        exact_components: dict[str, Component] = {}
        for pattern, component in self._path_index:
            if _path_matches(finding.filename, pattern):
                exact_components[component.id] = component

        for component in sorted(
            exact_components.values(), key=lambda item: item.id
        ):
            artifact_ids = list(
                self._artifacts_by_component.get(component.id, [])
            )
            if not artifact_ids:
                artifact_ids = sorted(
                    {
                        record.artifact_id
                        for record in self._legacy_records_for_filename(
                            finding.filename
                        )
                        if record.artifact_id
                        and record.artifact_id in self.evidence.artifacts
                    }
                )
            claims.append(
                _Claim(
                    component=component,
                    artifact_ids=sorted(set(artifact_ids)),
                    relation=(
                        "artifact_component"
                        if artifact_ids
                        else "component_only"
                    ),
                    matched_path=self._matched_component_path(
                        component, finding.filename
                    ),
                )
            )

        if claims:
            return claims

        for record in self._legacy_records_for_filename(finding.filename):
            component = (
                self.evidence.components.get(record.component_id)
                if record.component_id
                else None
            )
            artifact_ids = [record.artifact_id] if record.artifact_id else []
            claims.append(
                _Claim(
                    component=component,
                    artifact_ids=artifact_ids,
                    relation="legacy",
                    owner_override=record.owner,
                    owner_source_override="legacy",
                    legacy_owner=record.owner,
                    legacy_source=record.source,
                    matched_path=record.filename or finding.filename,
                )
            )
        return claims

    def _review_candidates(
        self, finding: Finding, exact_components: set[str]
    ) -> list[dict[str, Any]]:
        candidates: dict[str, dict[str, Any]] = {}
        for pattern, component in self._path_index:
            if component.id in exact_components:
                continue
            match = _near_match(
                finding.filename, pattern, self.near_match_threshold
            )
            if match is None:
                continue
            score, reason = match
            artifact_ids = self._artifacts_by_component.get(component.id, [])
            owner, owner_source, _ = self._current_owner(component)
            candidate = {
                "component": component.id,
                "candidate_component": component.id,
                "path": pattern,
                "candidate_path": pattern,
                "artifacts": sorted(set(artifact_ids)),
                "owner": owner,
                "maintainer": owner,
                "legacy_owner": component.legacy_owner,
                "owner_source": owner_source,
                "score": round(score, 4),
                "reason": reason,
                "status": "needs_review",
                "counted": False,
            }
            previous = candidates.get(component.id)
            if previous is None or (candidate["score"], candidate["path"]) > (
                previous["score"],
                previous["path"],
            ):
                candidates[component.id] = candidate
        return sorted(
            candidates.values(),
            key=lambda item: (
                -item["score"],
                item["component"],
                item["path"],
            ),
        )

    def _evidence_for_claim(self, claim: _Claim, owner: Optional[str]) -> dict:
        component = claim.component
        artifacts = [
            self.evidence.artifacts[artifact_id]
            for artifact_id in claim.artifact_ids
            if artifact_id in self.evidence.artifacts
        ]
        return {
            "relation": claim.relation,
            "source_path": claim.matched_path,
            "phase": (
                component.phase
                if component and component.phase
                else (artifacts[0].phase if artifacts else None)
            ),
            "component_revision": component.revision if component else None,
            "artifacts": [
                {
                    "id": artifact.id,
                    "digest": artifact.digest,
                    "phase": artifact.phase,
                    "accepts_tickets": _status_accepts_tickets(
                        artifact, self.as_of
                    ),
                    "stop_ship_at": _format_datetime(artifact.stop_ship_at),
                }
                for artifact in sorted(artifacts, key=lambda item: item.id)
            ],
            "owner_source": owner,
        }

    def attribute(self, report: JSONSource) -> AttributionReport:
        report_data, report_digest = _load_source(report, "Bandit report")
        if not isinstance(report_data, Mapping):
            raise AttributionError("Bandit report must be a JSON object")

        self._handover_warnings.clear()
        self.as_of = self._base_as_of
        findings = _iter_report_results(report_data)
        warnings = list(self.evidence.warnings)
        if self.as_of is None:
            report_as_of = _parse_datetime(
                _first(
                    report_data,
                    "as_of",
                    "generated_at",
                    "evidence_at",
                )
            )
            if report_as_of is not None:
                self.as_of = report_as_of
        attributions = []
        legacy_attribution = []
        review_candidates = []
        double_counting = []
        unattributed = []
        counted_for_burden = []
        seen_fingerprints: dict[str, Finding] = {}
        burden_identity: dict[tuple[Any, ...], dict[str, Any]] = {}
        warned_unproven = set()

        for handover in self.evidence.handovers:
            if (
                not handover.proven
                and handover.component_id not in warned_unproven
            ):
                warnings.append(
                    "ignored unproven handover for "
                    f"{handover.component_id!r} to {handover.to_owner!r}"
                )
                warned_unproven.add(handover.component_id)

        for finding in findings:
            if finding.fingerprint in seen_fingerprints:
                double_counting.append(
                    {
                        "fingerprint": finding.fingerprint,
                        "reason": "duplicate_report_entry",
                        "resolution": "counted_once",
                        "filename": finding.filename,
                        "test_id": finding.result.get("test_id"),
                        "line_number": finding.result.get("line_number"),
                    }
                )
                continue
            seen_fingerprints[finding.fingerprint] = finding

            claims = self._claims_for(finding)
            exact_components = {
                claim.component.id
                for claim in claims
                if claim.component is not None and claim.relation != "legacy"
            }
            candidates = self._review_candidates(finding, exact_components)
            if candidates:
                review_candidates.extend(
                    {
                        "fingerprint": finding.fingerprint,
                        "filename": finding.filename,
                        "test_id": finding.result.get("test_id"),
                        **candidate,
                    }
                    for candidate in candidates
                )

            claims_by_owner: dict[str, list[_Claim]] = {}
            claim_details = []
            for claim in claims:
                component = claim.component
                if claim.owner_override:
                    owner = claim.owner_override
                    owner_source = claim.owner_source_override
                    handover = None
                elif component is not None:
                    owner, owner_source, handover = self._current_owner(
                        component
                    )
                    if not owner:
                        legacy_records = self._legacy_records_for(
                            component, finding.filename
                        )
                        if legacy_records:
                            owner = legacy_records[0].owner
                            owner_source = "legacy"
                else:
                    owner = None
                    owner_source = None
                    handover = None

                active = self._artifact_accepts(claim.artifact_ids)
                claim_details.append(
                    {
                        "claim": claim,
                        "owner": owner,
                        "owner_source": owner_source,
                        "handover": handover,
                        "active": active,
                    }
                )
                if owner:
                    claims_by_owner.setdefault(owner, []).append(claim)

            for claim_detail in claim_details:
                component = claim_detail["claim"].component
                records = self._legacy_records_for(component, finding.filename)
                if not records and claim_detail["claim"].legacy_owner:
                    records = [
                        LegacyRecord(
                            filename=finding.filename,
                            owner=claim_detail["claim"].legacy_owner,
                            component_id=component.id if component else None,
                            source=claim_detail["claim"].legacy_source,
                        )
                    ]
                for record in records:
                    component_artifacts = (
                        self._artifacts_by_component.get(component.id, [])
                        if component
                        else []
                    )
                    artifact_ids = (
                        [record.artifact_id]
                        if record.artifact_id
                        else sorted(component_artifacts)
                    )
                    legacy_attribution.append(
                        {
                            "fingerprint": finding.fingerprint,
                            "filename": finding.filename,
                            "test_id": finding.result.get("test_id"),
                            "owner": record.owner,
                            "legacy_owner": record.owner,
                            "artifact": (
                                artifact_ids[0] if artifact_ids else None
                            ),
                            "artifacts": artifact_ids,
                            "component": record.component_id
                            or (component.id if component else None),
                            "phase": record.phase,
                            "source": record.source,
                            "status": "reported",
                        }
                    )

            if not claims:
                status = "needs_review" if candidates else "unattributed"
                record = {
                    "fingerprint": finding.fingerprint,
                    "filename": finding.filename,
                    "test_id": finding.result.get("test_id"),
                    "test_name": finding.result.get("test_name"),
                    "line_number": finding.result.get("line_number"),
                    "line_range": finding.result.get("line_range"),
                    "severity": finding.result.get("issue_severity"),
                    "confidence": finding.result.get("issue_confidence"),
                    "issue_text": finding.result.get("issue_text"),
                    "issue_cwe": finding.result.get("issue_cwe"),
                    "candidate_for": finding.candidate_for,
                    "source_path": None,
                    "status": status,
                    "counted": False,
                    "burden_counted": False,
                    "owner": None,
                    "owner_source": None,
                    "legacy_owner": None,
                    "component": None,
                    "components": [],
                    "artifact": None,
                    "artifacts": [],
                    "candidates": candidates,
                    "reason": (
                        "near_filename_match_only"
                        if candidates
                        else "no_source_component"
                    ),
                    "evidence": {},
                }
                attributions.append(record)
                unattributed.append(record)
                continue

            owners = sorted(claims_by_owner)
            all_components = sorted(
                {
                    claim.component.id
                    for claim in claims
                    if claim.component is not None
                }
            )
            all_artifacts = sorted(
                {
                    artifact_id
                    for claim in claims
                    for artifact_id in claim.artifact_ids
                }
            )
            active = any(
                detail["active"] for detail in claim_details if detail["owner"]
            )

            duplicate_reasons = []
            for component_id in all_components:
                artifact_ids = [
                    claim.artifact_ids
                    for claim in claims
                    if claim.component is not None
                    and claim.component.id == component_id
                ]
                total_artifacts = {
                    artifact_id for ids in artifact_ids for artifact_id in ids
                }
                if len(total_artifacts) > 1:
                    duplicate_reasons.append("shared_component")
                    double_counting.append(
                        {
                            "fingerprint": finding.fingerprint,
                            "reason": "shared_component",
                            "resolution": "counted_once",
                            "component": component_id,
                            "artifacts": sorted(total_artifacts),
                            "owners": owners,
                        }
                    )

            if len(owners) > 1:
                duplicate_reasons.append("conflicting_owner_claims")
                double_counting.append(
                    {
                        "fingerprint": finding.fingerprint,
                        "reason": "conflicting_owner_claims",
                        "resolution": "needs_review",
                        "components": all_components,
                        "artifacts": all_artifacts,
                        "owners": owners,
                    }
                )

            if len(set(all_components)) > 1 and len(owners) == 1:
                shared_paths = {}
                for claim in claims:
                    if claim.component is None:
                        continue
                    for path in claim.component.paths:
                        if _path_matches(finding.filename, path):
                            shared_paths.setdefault(path, set()).add(
                                claim.component.id
                            )
                if any(
                    len(component_ids) > 1
                    for component_ids in shared_paths.values()
                ):
                    duplicate_reasons.append("shared_maintained_code")
                    double_counting.append(
                        {
                            "fingerprint": finding.fingerprint,
                            "reason": "shared_maintained_code",
                            "resolution": "counted_once",
                            "components": all_components,
                            "owner": owners[0],
                        }
                    )

            if (
                len(set(all_components)) > 1
                and len(owners) == 1
                and "shared_maintained_code" not in duplicate_reasons
            ):
                duplicate_reasons.append("multiple_component_claims")
                double_counting.append(
                    {
                        "fingerprint": finding.fingerprint,
                        "reason": "multiple_component_claims",
                        "resolution": "counted_once",
                        "components": all_components,
                        "owner": owners[0],
                    }
                )

            legacy_owners = {
                record["owner"]
                for record in legacy_attribution
                if record["fingerprint"] == finding.fingerprint
            }
            if legacy_owners and owners and set(legacy_owners) != set(owners):
                duplicate_reasons.append("legacy_and_current")
                double_counting.append(
                    {
                        "fingerprint": finding.fingerprint,
                        "reason": "legacy_and_current",
                        "resolution": (
                            "legacy_reported_current_counted_once"
                            if active and len(owners) == 1
                            else "needs_review"
                        ),
                        "legacy_owners": sorted(legacy_owners),
                        "current_owners": owners,
                    }
                )

            if len(owners) > 1:
                status = "needs_review"
                counted = False
                owner = None
                owner_source = None
                reason = "conflicting_owner_claims"
            elif owners:
                owner = owners[0]
                owner_source = next(
                    detail["owner_source"]
                    for detail in claim_details
                    if detail["owner"] == owner and detail["owner_source"]
                )
                counted = bool(active)
                if not active:
                    status = "retired"
                    reason = "artifact_stopped_before_as_of"
                elif owner_source == "legacy":
                    status = "legacy"
                    reason = "legacy_attribution_still_active"
                else:
                    status = "attributed"
                    reason = (
                        duplicate_reasons[0]
                        if duplicate_reasons
                        else "exact_artifact_component"
                    )
            else:
                owner = None
                owner_source = None
                counted = False
                if active:
                    status = "unattributed"
                    reason = "no_current_maintainer"
                else:
                    status = "retired"
                    reason = "artifact_stopped_before_as_of"

            primary_component = all_components[0] if all_components else None
            primary_artifact = all_artifacts[0] if all_artifacts else None
            primary_claim = claims[0]
            record = {
                "fingerprint": finding.fingerprint,
                "filename": finding.filename,
                "test_id": finding.result.get("test_id"),
                "test_name": finding.result.get("test_name"),
                "line_number": finding.result.get("line_number"),
                "line_range": finding.result.get("line_range"),
                "severity": finding.result.get("issue_severity"),
                "confidence": finding.result.get("issue_confidence"),
                "issue_text": finding.result.get("issue_text"),
                "issue_cwe": finding.result.get("issue_cwe"),
                "candidate_for": finding.candidate_for,
                "source_path": primary_claim.matched_path,
                "status": status,
                "counted": counted,
                "burden_counted": False,
                "owner": owner,
                "owner_source": owner_source,
                "owners": owners,
                "legacy_owner": (
                    sorted(legacy_owners)[0] if legacy_owners else None
                ),
                "legacy_owners": sorted(legacy_owners),
                "component": primary_component,
                "components": all_components,
                "artifact": primary_artifact,
                "artifacts": all_artifacts,
                "candidates": candidates,
                "reason": reason,
                "duplicate_reason": (
                    duplicate_reasons[0] if duplicate_reasons else None
                ),
                "duplicate_reasons": sorted(set(duplicate_reasons)),
                "double_counted": bool(duplicate_reasons),
                "evidence": self._evidence_for_claim(
                    primary_claim, owner_source
                ),
            }
            attributions.append(record)
            if counted and owner:
                source_identity = (
                    primary_claim.matched_path or finding.filename
                )
                if re.search(r"[*?[]", source_identity):
                    source_identity = posixpath.basename(finding.filename)
                record["source_identity"] = source_identity
                identity = (
                    owner,
                    tuple(all_components),
                    source_identity,
                    record["test_id"],
                    record["test_name"],
                    record["line_number"],
                    record["issue_text"],
                )
                primary_burden = burden_identity.get(identity)
                if primary_burden is None:
                    record["burden_counted"] = True
                    burden_identity[identity] = record
                    counted_for_burden.append(record)
                else:
                    duplicate_reasons = "shared_source_finding"
                    if duplicate_reasons not in record["duplicate_reasons"]:
                        record["duplicate_reasons"].append(duplicate_reasons)
                        record["duplicate_reasons"].sort()
                    record["duplicate_reason"] = record["duplicate_reasons"][0]
                    record["double_counted"] = True
                    record["duplicate_of"] = primary_burden["fingerprint"]
                    primary_burden.setdefault(
                        "related_fingerprints", []
                    ).append(record["fingerprint"])
                    primary_burden["artifacts"] = sorted(
                        set(primary_burden["artifacts"])
                        | set(record["artifacts"])
                    )
                    primary_burden["components"] = sorted(
                        set(primary_burden["components"])
                        | set(record["components"])
                    )
                    double_counting.append(
                        {
                            "fingerprint": record["fingerprint"],
                            "reason": "shared_source_finding",
                            "resolution": "counted_once",
                            "kept_fingerprint": primary_burden["fingerprint"],
                            "owner": owner,
                            "components": all_components,
                            "source_path": primary_claim.matched_path,
                            "artifacts": all_artifacts,
                        }
                    )
            elif status in {"needs_review", "unattributed"}:
                unattributed.append(record)

        # Legacy rows must stay reportable even if a near-name match is the
        # only other clue. Keep one row per finding/owner/artifact tuple.
        legacy_unique = {}
        for row in legacy_attribution:
            key = (
                row["fingerprint"],
                row["owner"],
                row["component"],
            )
            existing = legacy_unique.get(key)
            if existing is None:
                legacy_unique[key] = row
                continue
            existing["artifacts"] = sorted(
                set(existing.get("artifacts") or [])
                | set(row.get("artifacts") or [])
            )
            existing["artifact"] = (
                existing["artifacts"][0]
                if existing["artifacts"]
                else existing.get("artifact")
            )
        legacy_attribution = [
            legacy_unique[key] for key in sorted(legacy_unique, key=str)
        ]
        attribution_by_fingerprint = {
            row["fingerprint"]: row for row in attributions
        }
        for row in legacy_attribution:
            current = attribution_by_fingerprint.get(row["fingerprint"])
            if current and current.get("owner"):
                row["current_owner"] = current["owner"]
                row["superseded_by"] = (
                    current["owner"]
                    if current["owner"] != row["owner"]
                    else None
                )

        severity_weights = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        owner_burden: dict[str, dict[str, Any]] = {}
        component_burden: dict[tuple[str, Optional[str]], dict[str, Any]] = {}
        for record in counted_for_burden:
            owner = record["owner"]
            weight = severity_weights.get(record["severity"], 0)
            owner_row = owner_burden.setdefault(
                owner,
                {
                    "owner": owner,
                    "owner_team": owner,
                    "maintainer": owner,
                    "finding_count": 0,
                    "findings": [],
                    "severity_counts": {},
                    "risk_weight": 0,
                    "risk_score": 0,
                    "components": set(),
                    "artifacts": set(),
                    "phases": set(),
                    "shared_finding_count": 0,
                },
            )
            owner_row["finding_count"] += 1
            owner_row["findings"].append(record["fingerprint"])
            owner_row["severity_counts"][record["severity"]] = (
                owner_row["severity_counts"].get(record["severity"], 0) + 1
            )
            owner_row["risk_weight"] += weight
            owner_row["risk_score"] += weight
            owner_row["components"].update(record["components"])
            owner_row["artifacts"].update(record["artifacts"])
            if record["evidence"].get("phase"):
                owner_row["phases"].add(record["evidence"]["phase"])
            if "shared_component" in record["duplicate_reasons"]:
                owner_row["shared_finding_count"] += 1

            identity_path = record["source_identity"]
            component_key = (owner, identity_path)
            component_row = component_burden.setdefault(
                component_key,
                {
                    "owner": owner,
                    "maintainer": owner,
                    "component": record["component"],
                    "components": set(),
                    "source_path": identity_path,
                    "finding_count": 0,
                    "findings": [],
                    "severity_counts": {},
                    "risk_weight": 0,
                    "risk_score": 0,
                    "artifacts": set(),
                    "shared": False,
                },
            )
            component_row["components"].update(record["components"])
            component_row["finding_count"] += 1
            component_row["findings"].append(record["fingerprint"])
            component_row["severity_counts"][record["severity"]] = (
                component_row["severity_counts"].get(record["severity"], 0) + 1
            )
            component_row["risk_weight"] += weight
            component_row["risk_score"] += weight
            component_row["artifacts"].update(record["artifacts"])
            if "shared_component" in record["duplicate_reasons"]:
                component_row["shared"] = True

        for row in owner_burden.values():
            row["components"] = sorted(row["components"])
            row["artifacts"] = sorted(row["artifacts"])
            row["phases"] = sorted(row["phases"])
            row["findings"] = sorted(set(row["findings"]))
        for row in component_burden.values():
            row["artifacts"] = sorted(row["artifacts"])
            row["components"] = sorted(row["components"])
            row["findings"] = sorted(set(row["findings"]))
        risk_burden = [owner_burden[owner] for owner in sorted(owner_burden)]
        component_rows = [
            component_burden[key] for key in sorted(component_burden, key=str)
        ]

        attributions.sort(
            key=lambda item: (
                item["filename"],
                item["line_number"] or 0,
                item["test_id"] or "",
                item["fingerprint"],
            )
        )
        review_candidates.sort(
            key=lambda item: (
                item["filename"],
                item["fingerprint"],
                -item["score"],
                item["component"],
            )
        )
        double_counting.sort(
            key=lambda item: (
                item["fingerprint"] or "",
                item["reason"],
                item.get("component") or "",
            )
        )
        legacy_attribution.sort(
            key=lambda item: (
                item["filename"],
                item["owner"],
                item["artifact"] or "",
                item["component"] or "",
            )
        )
        unattributed.sort(
            key=lambda item: (
                item["filename"],
                item["line_number"] or 0,
                item["fingerprint"],
            )
        )

        duplicate_fingerprints = {
            item["fingerprint"]
            for item in double_counting
            if item.get("fingerprint")
        }
        warnings = sorted(set(warnings) | self._handover_warnings)
        evidence = {
            "as_of": _format_datetime(self.as_of),
            "near_match_threshold": self.near_match_threshold,
            "report_digest": report_digest,
            "manifest_digests": [
                manifest.digest for manifest in self.evidence.manifests
            ],
            "manifests": [
                {
                    "name": manifest.name,
                    "phase": manifest.phase,
                    "digest": manifest.digest,
                    "as_of": _format_datetime(manifest.as_of),
                }
                for manifest in self.evidence.manifests
            ],
            "evidence_digest": _digest_value(
                {
                    "policy": POLICY_VERSION,
                    "report_digest": report_digest,
                    "manifests": self.evidence.digest,
                    "as_of": _format_datetime(self.as_of),
                    "near_match_threshold": self.near_match_threshold,
                }
            ),
            "warnings": warnings,
        }
        summary = {
            "finding_count": len(seen_fingerprints),
            "attributed_findings": sum(
                1 for item in attributions if item["counted"]
            ),
            "burden_counted_findings": sum(
                1 for item in attributions if item["burden_counted"]
            ),
            "legacy_findings": len(
                {item["fingerprint"] for item in legacy_attribution}
            ),
            "review_candidate_findings": len(
                {item["fingerprint"] for item in review_candidates}
            ),
            "double_counted_findings": len(duplicate_fingerprints),
            "unattributed_findings": sum(
                1
                for item in attributions
                if item["status"] in {"unattributed", "needs_review"}
            ),
            "retired_findings": sum(
                1 for item in attributions if item["status"] == "retired"
            ),
            "burden_owners": len(risk_burden),
            "burden_weight": sum(item["risk_weight"] for item in risk_burden),
        }
        return AttributionReport(
            attributions=attributions,
            legacy_attribution=legacy_attribution,
            review_candidates=review_candidates,
            double_counting=double_counting,
            risk_burden=risk_burden,
            component_burden=component_rows,
            unattributed=unattributed,
            summary=summary,
            evidence=evidence,
        )


def attribute(
    report: JSONSource,
    manifests: Optional[Union[JSONSource, Sequence[JSONSource]]] = None,
    as_of: Optional[Union[str, datetime.datetime]] = None,
    near_match_threshold: float = DEFAULT_NEAR_MATCH_THRESHOLD,
    manifest: Optional[JSONSource] = None,
    release_manifest: Optional[JSONSource] = None,
    ownership_manifest: Optional[JSONSource] = None,
    evidence: Optional[JSONSource] = None,
    artifacts: Optional[Any] = None,
    components: Optional[Any] = None,
    relations: Optional[Any] = None,
    artifact_relations: Optional[Any] = None,
    handovers: Optional[Any] = None,
    legacy_attribution: Optional[Any] = None,
    legacy: Optional[Any] = None,
) -> AttributionReport:
    """Attribute a Bandit JSON report to maintained components.

    ``report`` is a Bandit JSON object/path/file object. ``manifests`` is a
    manifest object/path/file object, or a sequence of them. Later manifests
    refine earlier declarations, which makes phased evidence easy to replay.

    A consumer may also submit the finite evidence directly with
    ``artifacts``, ``components``, ``relations``, ``handovers`` and
    ``legacy_attribution`` instead of preparing a manifest file first.
    """
    sources: list[JSONSource] = []
    if manifests is not None:
        if isinstance(manifests, (list, tuple)) and not (
            _sequence_is_single_manifest(manifests)
        ):
            sources.extend(manifests)
        else:
            sources.append(manifests)
    submitted_manifest = manifest
    if submitted_manifest is None:
        submitted_manifest = release_manifest or ownership_manifest or evidence
    if submitted_manifest is not None:
        sources.append(submitted_manifest)

    inline_manifest = {}
    if artifacts is not None:
        inline_manifest["artifacts"] = artifacts
    if components is not None:
        inline_manifest["components"] = components
    submitted_relations = (
        relations if relations is not None else artifact_relations
    )
    if submitted_relations is not None:
        if isinstance(submitted_relations, Mapping):
            inline_manifest["artifact_to_components"] = submitted_relations
        else:
            inline_manifest["artifact_component_relations"] = (
                submitted_relations
            )
    if handovers is not None:
        inline_manifest["handovers"] = handovers
    submitted_legacy = (
        legacy_attribution if legacy_attribution is not None else legacy
    )
    if submitted_legacy is not None:
        inline_manifest["legacy_attribution"] = submitted_legacy
    if inline_manifest:
        sources.append(inline_manifest)
    if not sources:
        raise AttributionError("At least one release manifest is required")

    evidence = load_manifests(sources)
    return Attributor(
        evidence,
        as_of=as_of,
        near_match_threshold=near_match_threshold,
    ).attribute(report)


attribute_report = attribute
attribute_findings = attribute
attribute_bandit_report = attribute
build_attribution = attribute
compute_attribution = attribute
resolve_attribution = attribute
resolve_ownership = attribute
AttributionEngine = Attributor
load_release_manifest = load_manifest
load_release_manifests = load_manifests


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Command-line entry point for the report consumer."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        prog="bandit-attribution",
        description=(
            "Attribute a Bandit JSON report to maintained source components "
            "using release manifests and proven handovers"
        ),
    )
    parser.add_argument(
        "report_positional",
        nargs="?",
        help="Bandit JSON report path",
    )
    parser.add_argument(
        "manifest_positional",
        nargs="*",
        help="release manifest path(s)",
    )
    parser.add_argument("-r", "--report", "--report-json", dest="report")
    parser.add_argument(
        "-m",
        "--manifest",
        dest="manifests",
        action="append",
        default=[],
    )
    parser.add_argument(
        "--manifests",
        dest="manifest_list",
        help="comma-separated release manifest paths",
    )
    parser.add_argument(
        "--as-of",
        dest="as_of",
        help="fixed evidence timestamp (ISO 8601)",
    )
    parser.add_argument(
        "--near-match-threshold",
        type=float,
        default=DEFAULT_NEAR_MATCH_THRESHOLD,
        help="filename similarity threshold for review candidates only",
    )
    parser.add_argument("-o", "--output", help="output path (default: stdout)")
    parser.add_argument(
        "--fail-on-double-count",
        action="store_true",
        help="exit 1 when a double-counting reason is present",
    )
    args = parser.parse_args(argv)

    report = args.report or args.report_positional
    manifests = list(args.manifests or []) + list(
        args.manifest_positional or []
    )
    if args.manifest_list:
        manifests.extend(
            path.strip()
            for path in args.manifest_list.split(",")
            if path.strip()
        )
    if not report or not manifests:
        parser.error("a Bandit report and at least one manifest are required")

    try:
        result = attribute(
            report,
            manifests,
            as_of=args.as_of,
            near_match_threshold=args.near_match_threshold,
        )
    except (AttributionError, OSError) as error:
        print(f"bandit-attribution: {error}", file=sys.stderr)
        return 2

    output = json.dumps(
        result.as_dict(),
        sort_keys=True,
        indent=2,
        separators=(",", ": "),
    )
    if args.output and args.output != "-":
        try:
            with open(args.output, "w", encoding="utf-8") as output_file:
                output_file.write(output)
                output_file.write("\n")
        except OSError as error:
            print(f"bandit-attribution: {error}", file=sys.stderr)
            return 2
    else:
        print(output)

    if args.fail_on_double_count and result.double_counting:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
