#
# SPDX-License-Identifier: Apache-2.0
"""Manifest driven attribution for Bandit report consumers.

Bandit reports findings against source files.  A risk leaderboard usually
needs a different answer: *which maintained release artifact should carry the
finding?*  Repositories that were split from a shared code base do not always
have that answer, especially when two artifacts still build the same source
component.

This module adds a deliberately small, deterministic attribution layer:

* a release manifest declares artifacts, source components, explicit
  artifact-to-component relations, and team handovers;
* only exact path matches are used for attribution;
* filename similarity is emitted as an investigation lead and never as risk;
* risk is counted once per source component, while every affected artifact is
  still reported;
* legacy ownership is reported separately and remains usable before an old
  artifact reaches end of life.

The public entry points are :func:`load_manifest`, :func:`load_report`, and
:func:`attribute_report`.  The result is JSON serialisable and contains the
manifest and finding digests needed to reproduce the allocation.
"""
import copy
import datetime
import difflib
import hashlib
import json
import os
import posixpath
from collections import defaultdict
from dataclasses import dataclass
from dataclasses import field

from bandit.core import constants

MANIFEST_SCHEMA_VERSION = 1
ATTRIBUTION_SCHEMA_VERSION = 1
ATTRIBUTION_ALGORITHM_VERSION = 1
DEFAULT_FUZZY_MATCH_THRESHOLD = 0.82

ARTIFACT_STATUSES = frozenset(
    {"active", "maintenance", "sunset", "eol", "discontinued"}
)
EOL_STATUSES = frozenset({"eol", "discontinued"})
PRE_EOL_STATUSES = frozenset({"maintenance", "sunset"})
RISK_WEIGHTS = dict(constants.RANKING_VALUES)

_FINDING_FIELDS = (
    "filename",
    "line_number",
    "col_offset",
    "end_col_offset",
    "test_id",
    "test_name",
    "issue_severity",
    "issue_confidence",
    "issue_text",
)


class ManifestError(ValueError):
    """Raised when a release manifest cannot be used safely."""


class ReportError(ValueError):
    """Raised when a Bandit report cannot be interpreted."""


def _text(value):
    if value is None:
        return ""
    return str(value).strip()


def _tuple_of_text(value, field_name, allow_none=True):
    if value is None:
        if allow_none:
            return ()
        raise ManifestError("'%s' is required" % field_name)
    if isinstance(value, str):
        return (value,) if value.strip() else ()
    if isinstance(value, (list, tuple)):
        return tuple(str(item).strip() for item in value if str(item).strip())
    raise ManifestError(
        "'%s' must be a string or a list of strings" % field_name
    )


def _canonical_json(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def _digest(value):
    payload = _canonical_json(value).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _parse_date(value, field_name):
    value = _text(value)
    if not value:
        return ""
    try:
        datetime.date.fromisoformat(value)
    except ValueError:
        raise ManifestError(
            "'%s' must be an ISO date (YYYY-MM-DD), got %r"
            % (field_name, value)
        )
    return value


def normalize_path(value):
    """Return a stable, comparable representation of a source path."""
    path = _text(value).replace("\\", "/")
    if not path:
        return ""
    if path.startswith("./"):
        path = path[2:]
    path = posixpath.normpath(path)
    if path == ".":
        return ""
    return path.rstrip("/")


def _suffix_match(filename, declared):
    """Match a relative manifest path to an absolute report path, or back.

    This is still an exact suffix match.  It only exists because Bandit may
    report absolute paths while a manifest is written relative to a checkout
    root.  It is not the fuzzy filename matching used for investigation leads.
    """
    if not filename or not declared:
        return False
    if filename.startswith("/") == declared.startswith("/"):
        return False
    return filename.endswith("/" + declared) or declared.endswith(
        "/" + filename
    )


def _path_is_within(filename, declared):
    if not filename or not declared:
        return False
    return filename == declared or filename.startswith(declared + "/")


@dataclass(frozen=True)
class Evidence:
    """A minimal reference to immutable build or handover evidence."""

    kind: str = ""
    id: str = ""
    uri: str = ""
    digest: str = ""
    detail: str = ""

    @classmethod
    def from_value(cls, value):
        if value is None or value == "":
            return cls()
        if isinstance(value, dict) and not value:
            return cls()
        if isinstance(value, str):
            return cls(kind="reference", id=value)
        if not isinstance(value, dict):
            raise ManifestError("evidence must be an object or a string")
        return cls(
            kind=_text(value.get("kind")),
            id=_text(value.get("id") or value.get("ticket")),
            uri=_text(value.get("uri")),
            digest=_text(value.get("digest")),
            detail=_text(value.get("detail")),
        )

    @property
    def present(self):
        return bool(self.id or self.uri or self.digest)

    def as_dict(self):
        result = {}
        for key in ("kind", "id", "uri", "digest", "detail"):
            value = getattr(self, key)
            if value:
                result[key] = value
        return result


@dataclass
class Handover:
    """A team handover with proof.

    A handover without a proof reference is parsed but rejected.  This keeps
    an unproven ownership move from silently changing the risk allocation.
    """

    from_owner: str
    to_owner: str
    proof: Evidence
    component_id: str = ""
    artifact_id: str = ""
    effective: str = ""

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict):
            raise ManifestError("each handover must be an object")
        proof = value.get("proof")
        return cls(
            from_owner=_text(
                value.get("from_owner") or value.get("from")
            ),
            to_owner=_text(value.get("to_owner") or value.get("to")),
            proof=Evidence.from_value(proof),
            component_id=_text(
                value.get("component_id") or value.get("component")
            ),
            artifact_id=_text(
                value.get("artifact_id") or value.get("artifact")
            ),
            effective=_parse_date(
                value.get("effective") or value.get("effective_date"),
                "handover.effective",
            ),
        )

    @property
    def valid(self):
        return bool(
            self.from_owner
            and self.to_owner
            and self.proof.present
            and (self.component_id or self.artifact_id)
        )

    def rejection_reason(self):
        if not self.from_owner:
            return "missing_from_owner"
        if not self.to_owner:
            return "missing_to_owner"
        if not self.proof.present:
            return "missing_proof"
        if not self.component_id and not self.artifact_id:
            return "missing_scope"
        return ""

    def applies_to(self, artifact_id, component_id):
        return (
            (not self.artifact_id or self.artifact_id == artifact_id)
            and (
                not self.component_id or self.component_id == component_id
            )
        )

    def as_dict(self):
        result = {
            "from_owner": self.from_owner,
            "to_owner": self.to_owner,
            "proof": self.proof.as_dict(),
        }
        if self.component_id:
            result["component_id"] = self.component_id
        if self.artifact_id:
            result["artifact_id"] = self.artifact_id
        if self.effective:
            result["effective"] = self.effective
        return result


@dataclass
class SourceComponent:
    """A source component that can be related to one or more artifacts."""

    component_id: str
    owner: str = ""
    legacy_owner: str = ""
    paths: tuple = ()
    files: tuple = ()
    status: str = "active"

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict):
            raise ManifestError("each component must be an object")
        component_id = _text(
            value.get("component_id") or value.get("id")
        )
        if not component_id:
            raise ManifestError("each component needs a component_id")
        return cls(
            component_id=component_id,
            owner=_text(value.get("owner") or value.get("maintainer")),
            legacy_owner=_text(value.get("legacy_owner")),
            paths=_tuple_of_text(value.get("paths"), "component.paths"),
            files=_tuple_of_text(value.get("files"), "component.files"),
            status=_text(value.get("status") or "active").lower(),
        )

    def match(self, filename):
        """Return ``(specificity, kind, matched_path)`` for an exact match."""
        filename = normalize_path(filename)
        if not filename:
            return None
        best = None
        for declared in self.files:
            normalized = normalize_path(declared)
            if not normalized:
                continue
            if filename == normalized or _suffix_match(
                filename, normalized
            ):
                best = _better_match(
                    best, (len(normalized), "exact_file", normalized)
                )
        for declared in self.paths:
            normalized = normalize_path(declared)
            if not normalized:
                continue
            if _path_is_within(filename, normalized):
                kind = "exact_path"
            elif _suffix_match(filename, normalized):
                kind = "exact_path_suffix"
            else:
                continue
            best = _better_match(
                best, (len(normalized), kind, normalized)
            )
        return best

    def as_dict(self):
        result = {
            "component_id": self.component_id,
            "status": self.status,
        }
        if self.owner:
            result["owner"] = self.owner
        if self.legacy_owner:
            result["legacy_owner"] = self.legacy_owner
        if self.paths:
            result["paths"] = list(self.paths)
        if self.files:
            result["files"] = list(self.files)
        return result


def _better_match(current, candidate):
    if current is None:
        return candidate
    # Longer paths are more specific.  For equal length prefer file matches
    # because they describe one migrated component rather than a directory.
    current_rank = (current[0], current[1] == "exact_file")
    candidate_rank = (candidate[0], candidate[1] == "exact_file")
    if candidate_rank > current_rank:
        return candidate
    if candidate_rank == current_rank and candidate[2] < current[2]:
        return candidate
    return current


@dataclass
class Artifact:
    """A release artifact and its lifecycle."""

    artifact_id: str
    owner: str = ""
    legacy_owner: str = ""
    status: str = "active"
    accepts_work_orders: bool = True
    eol_date: str = ""

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict):
            raise ManifestError("each artifact must be an object")
        artifact_id = _text(value.get("artifact_id") or value.get("id"))
        if not artifact_id:
            raise ManifestError("each artifact needs an artifact_id")
        status = _text(value.get("status") or "active").lower()
        if status not in ARTIFACT_STATUSES:
            raise ManifestError(
                "artifact %r has unknown status %r; expected one of %s"
                % (artifact_id, status, ", ".join(sorted(ARTIFACT_STATUSES)))
            )
        accepts = value.get("accepts_work_orders", True)
        return cls(
            artifact_id=artifact_id,
            owner=_text(value.get("owner") or value.get("maintainer")),
            legacy_owner=_text(value.get("legacy_owner")),
            status=status,
            accepts_work_orders=bool(accepts),
            eol_date=_parse_date(
                value.get("eol_date"), "artifact.eol_date"
            ),
        )

    def effective_status(self, as_of):
        if self.eol_date and as_of and self.eol_date <= as_of:
            return "eol", "eol_date_reached"
        return self.status, "declared_status"

    def counts_toward_risk(self, as_of):
        status, _ = self.effective_status(as_of)
        if status in EOL_STATUSES:
            return False, "artifact_status_%s" % status
        if not self.accepts_work_orders:
            return False, "artifact_does_not_accept_work_orders"
        if status in PRE_EOL_STATUSES:
            return True, "pre_eol_%s_accepts_work_orders" % status
        return True, "active_artifact_accepts_work_orders"

    def as_dict(self, as_of):
        status, status_reason = self.effective_status(as_of)
        counts, count_reason = self.counts_toward_risk(as_of)
        result = {
            "artifact_id": self.artifact_id,
            "status": status,
            "status_reason": status_reason,
            "accepts_work_orders": counts,
            "count_reason": count_reason,
        }
        if self.owner:
            result["owner"] = self.owner
        if self.legacy_owner:
            result["legacy_owner"] = self.legacy_owner
        if self.eol_date:
            result["eol_date"] = self.eol_date
        return result


@dataclass(frozen=True)
class Relation:
    """An explicit artifact-to-source-component relationship."""

    artifact_id: str
    component_id: str
    evidence: Evidence = field(default_factory=Evidence)

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict):
            raise ManifestError("each relation must be an object")
        artifact_id = _text(value.get("artifact_id"))
        component_id = _text(value.get("component_id"))
        if not artifact_id or not component_id:
            raise ManifestError(
                "each relation needs artifact_id and component_id"
            )
        return cls(
            artifact_id=artifact_id,
            component_id=component_id,
            evidence=Evidence.from_value(value.get("evidence")),
        )

    def as_dict(self):
        result = {
            "artifact_id": self.artifact_id,
            "component_id": self.component_id,
        }
        if self.evidence.present:
            result["evidence"] = self.evidence.as_dict()
        return result


@dataclass
class ReleaseManifest:
    """Validated release manifest used by the attribution engine."""

    schema_version: int
    manifest_id: str
    as_of: str
    components: dict
    artifacts: dict
    relations: tuple
    handovers: tuple
    rejected_handovers: tuple
    fuzzy_match_threshold: float
    notes: tuple
    source_name: str = ""
    raw: dict = field(default_factory=dict, repr=False)

    @property
    def valid_handovers(self):
        return tuple(
            handover for handover in self.handovers if handover.valid
        )

    def related_artifacts(self, component_id):
        artifact_ids = {
            relation.artifact_id
            for relation in self.relations
            if relation.component_id == component_id
        }
        return [
            self.artifacts[artifact_id]
            for artifact_id in sorted(artifact_ids)
        ]

    def relation_evidence(self, artifact_id, component_id):
        evidence = []
        for relation in self.relations:
            if (
                relation.artifact_id == artifact_id
                and relation.component_id == component_id
                and relation.evidence.present
            ):
                evidence.append(relation.evidence)
        return evidence

    def matching_handovers(self, artifact_id, component_id):
        matches = [
            handover
            for handover in self.valid_handovers
            if handover.applies_to(artifact_id, component_id)
        ]
        return sorted(
            matches,
            key=lambda handover: (
                bool(handover.artifact_id),
                handover.effective,
                handover.to_owner,
                handover.from_owner,
            ),
            reverse=True,
        )

    def normalized(self):
        return {
            "schema_version": self.schema_version,
            "manifest_id": self.manifest_id,
            "as_of": self.as_of,
            "components": [
                component.as_dict()
                for component in sorted(
                    self.components.values(),
                    key=lambda item: item.component_id,
                )
            ],
            "artifacts": [
                artifact.as_dict(self.as_of)
                for artifact in sorted(
                    self.artifacts.values(),
                    key=lambda item: item.artifact_id,
                )
            ],
            "relations": [
                relation.as_dict()
                for relation in sorted(
                    self.relations,
                    key=lambda item: (
                        item.artifact_id,
                        item.component_id,
                        _canonical_json(item.evidence.as_dict()),
                    ),
                )
            ],
            "handovers": [
                handover.as_dict()
                for handover in sorted(
                    self.valid_handovers,
                    key=lambda item: (
                        item.component_id,
                        item.artifact_id,
                        item.from_owner,
                        item.to_owner,
                        item.effective,
                    ),
                )
            ],
            "rejected_handovers": sorted(
                (
                    {
                        "handover": entry["handover"],
                        "reason": entry["reason"],
                    }
                    for entry in self.rejected_handovers
                ),
                key=_canonical_json,
            ),
            "notes": sorted(self.notes),
            "fuzzy_match_threshold": self.fuzzy_match_threshold,
        }

    @property
    def digest(self):
        return _digest(self.normalized())


def _load_json_source(source, label):
    if isinstance(source, dict):
        return copy.deepcopy(source), ""
    if hasattr(source, "read"):
        name = getattr(source, "name", "")
        try:
            return json.load(source), name
        except (TypeError, ValueError) as exc:
            raise ManifestError("invalid %s JSON: %s" % (label, exc))
    if isinstance(source, os.PathLike):
        source = os.fspath(source)
    if isinstance(source, str):
        stripped = source.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                return json.loads(source), ""
            except ValueError as exc:
                raise ManifestError("invalid %s JSON: %s" % (label, exc))
        try:
            with open(source, "r", encoding="utf-8") as handle:
                return json.load(handle), source
        except OSError as exc:
            raise ManifestError("cannot read %s: %s" % (label, exc))
        except ValueError as exc:
            raise ManifestError("invalid %s JSON: %s" % (label, exc))
    raise ManifestError(
        "%s must be a mapping, a JSON string, a path, or a file object"
        % label
    )


def _iter_entries(value, label, id_key):
    if value is None:
        return
    if isinstance(value, dict):
        for key, entry in value.items():
            if not isinstance(entry, dict):
                raise ManifestError(
                    "%s[%r] must be an object" % (label, key)
                )
            entry = dict(entry)
            entry.setdefault(id_key, key)
            yield entry
        return
    if isinstance(value, list):
        for entry in value:
            yield entry
        return
    raise ManifestError("%s must be a list or a mapping" % label)


def manifest_from_dict(value, source_name=""):
    """Validate a mapping and build a :class:`ReleaseManifest`."""
    if not isinstance(value, dict):
        raise ManifestError("release manifest must be a JSON object")
    schema_version = value.get("schema_version", MANIFEST_SCHEMA_VERSION)
    try:
        schema_version = int(schema_version)
    except (TypeError, ValueError):
        raise ManifestError("schema_version must be an integer")
    if schema_version != MANIFEST_SCHEMA_VERSION:
        raise ManifestError(
            "unsupported schema_version %s; this Bandit supports %s"
            % (schema_version, MANIFEST_SCHEMA_VERSION)
        )

    as_of = _parse_date(value.get("as_of"), "as_of")
    options = value.get("options") or {}
    if not isinstance(options, dict):
        raise ManifestError("options must be an object")
    threshold = options.get(
        "fuzzy_match_threshold", DEFAULT_FUZZY_MATCH_THRESHOLD
    )
    try:
        threshold = float(threshold)
    except (TypeError, ValueError):
        raise ManifestError("fuzzy_match_threshold must be a number")
    if not 0.0 <= threshold <= 1.0:
        raise ManifestError("fuzzy_match_threshold must be between 0 and 1")

    components = {}
    for entry in _iter_entries(
        value.get("components"), "components", "component_id"
    ):
        component = SourceComponent.from_dict(entry)
        if component.component_id in components:
            raise ManifestError(
                "duplicate component_id %r" % component.component_id
            )
        components[component.component_id] = component

    artifacts = {}
    for entry in _iter_entries(
        value.get("artifacts"), "artifacts", "artifact_id"
    ):
        artifact = Artifact.from_dict(entry)
        if artifact.artifact_id in artifacts:
            raise ManifestError(
                "duplicate artifact_id %r" % artifact.artifact_id
            )
        artifacts[artifact.artifact_id] = artifact

    relations = []
    notes = []
    seen_relations = set()
    for entry in _iter_entries(
        value.get("relations"), "relations", "artifact_id"
    ):
        relation = Relation.from_dict(entry)
        if relation.artifact_id not in artifacts:
            raise ManifestError(
                "relation references unknown artifact_id %r"
                % relation.artifact_id
            )
        if relation.component_id not in components:
            raise ManifestError(
                "relation references unknown component_id %r"
                % relation.component_id
            )
        if not relation.evidence.present:
            notes.append(
                "relation %s -> %s has no evidence reference"
                % (relation.artifact_id, relation.component_id)
            )
        key = (relation.artifact_id, relation.component_id)
        if key in seen_relations:
            notes.append(
                "duplicate relation %s -> %s was collapsed"
                % (relation.artifact_id, relation.component_id)
            )
        seen_relations.add(key)
        relations.append(relation)

    handovers = []
    rejected = []
    for entry in _iter_entries(
        value.get("handovers"), "handovers", "component_id"
    ):
        handover = Handover.from_dict(entry)
        if handover.component_id and (
            handover.component_id not in components
        ):
            raise ManifestError(
                "handover references unknown component_id %r"
                % handover.component_id
            )
        if handover.artifact_id and handover.artifact_id not in artifacts:
            raise ManifestError(
                "handover references unknown artifact_id %r"
                % handover.artifact_id
            )
        reason = handover.rejection_reason()
        if (
            not reason
            and handover.effective
            and as_of
            and handover.effective > as_of
        ):
            reason = "handover_not_yet_effective"
        if reason:
            rejected.append(
                {
                    "handover": handover.as_dict(),
                    "reason": reason,
                }
            )
        else:
            handovers.append(handover)

    for component in components.values():
        if component.status not in ARTIFACT_STATUSES:
            raise ManifestError(
                "component %r has unknown status %r"
                % (component.component_id, component.status)
            )

    return ReleaseManifest(
        schema_version=schema_version,
        manifest_id=_text(value.get("manifest_id")),
        as_of=as_of,
        components=components,
        artifacts=artifacts,
        relations=tuple(relations),
        handovers=tuple(handovers),
        rejected_handovers=tuple(rejected),
        fuzzy_match_threshold=threshold,
        notes=tuple(notes),
        source_name=source_name,
        raw=copy.deepcopy(value),
    )


def load_manifest(source):
    """Load a release manifest from a mapping, path, JSON string, or file."""
    value, source_name = _load_json_source(source, "release manifest")
    return manifest_from_dict(value, source_name=source_name)


def _finding_to_dict(item):
    if hasattr(item, "as_dict"):
        try:
            return item.as_dict(with_code=False)
        except TypeError:
            return item.as_dict()
    if isinstance(item, dict):
        return dict(item)
    raise ReportError("each finding must be an object or an Issue")


def _int_or_none(value):
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalize_finding(item):
    raw = _finding_to_dict(item)
    filename = _text(
        raw.get("filename") or raw.get("fname") or raw.get("path")
    )
    severity = _text(
        raw.get("issue_severity") or raw.get("severity")
    ).upper()
    confidence = _text(
        raw.get("issue_confidence") or raw.get("confidence")
    ).upper()
    if severity not in RISK_WEIGHTS:
        severity = "UNDEFINED"
    if confidence not in RISK_WEIGHTS:
        confidence = "UNDEFINED"
    test_id = _text(raw.get("test_id") or raw.get("test"))
    normalized = {
        "filename": filename,
        "line_number": _int_or_none(
            raw.get("line_number") or raw.get("lineno")
        ),
        "col_offset": _int_or_none(raw.get("col_offset")),
        "end_col_offset": _int_or_none(raw.get("end_col_offset")),
        "test_id": test_id,
        "test_name": _text(raw.get("test_name") or test_id),
        "issue_severity": severity,
        "issue_confidence": confidence,
        "issue_text": _text(raw.get("issue_text") or raw.get("text")),
    }
    normalized["finding_id"] = _digest(
        {key: normalized[key] for key in _FINDING_FIELDS}
    )
    return normalized


def normalize_findings(report):
    """Return a deterministic list of normalized findings.

    ``report`` may be a Bandit JSON mapping, a list of findings, an
    :class:`bandit.core.issue.Issue` list, or a Bandit manager with
    ``get_issue_list``.
    """
    if hasattr(report, "get_issue_list"):
        items = report.get_issue_list()
    elif isinstance(report, dict) and "results" in report:
        items = report["results"]
    elif isinstance(report, dict) and "findings" in report:
        items = report["findings"]
    elif isinstance(report, dict):
        items = [report]
    elif isinstance(report, (list, tuple)):
        items = list(report)
    else:
        raise ReportError(
            "report must be a Bandit report, a finding list, or a manager"
        )
    findings = []
    seen = set()
    duplicates = 0
    for item in items:
        finding = _normalize_finding(item)
        if finding["finding_id"] in seen:
            duplicates += 1
            continue
        seen.add(finding["finding_id"])
        findings.append(finding)
    findings.sort(
        key=lambda item: (
            item["filename"],
            item["line_number"] or 0,
            item["test_id"],
            item["finding_id"],
        )
    )
    return findings, duplicates


def load_report(source):
    """Load a Bandit JSON report from a mapping, path, JSON string, or file."""
    try:
        value, source_name = _load_json_source(source, "Bandit report")
    except ManifestError as exc:
        raise ReportError(str(exc))
    findings, duplicates = normalize_findings(value)
    return findings, duplicates, source_name


def _risk_points(finding):
    return RISK_WEIGHTS.get(
        finding["issue_severity"], RISK_WEIGHTS["UNDEFINED"]
    )


def _rejected_handover_dicts(manifest):
    return [
        {
            "handover": entry["handover"],
            "reason": entry["reason"],
        }
        for entry in manifest.rejected_handovers
    ]


def _component_handovers(manifest, component_id):
    return manifest.matching_handovers("", component_id)


def _component_legacy_handover(manifest, component_id):
    handovers = _component_handovers(manifest, component_id)
    if handovers:
        return handovers[0]
    return None


def _artifact_legacy_owner(manifest, component, artifact):
    handovers = manifest.matching_handovers(
        artifact.artifact_id, component.component_id
    )
    if artifact.legacy_owner:
        return artifact.legacy_owner, "artifact.legacy_owner", None
    if handovers:
        return handovers[0].from_owner, "handover.from_owner", handovers[0]
    if component.legacy_owner:
        return component.legacy_owner, "component.legacy_owner", None
    component_handover = _component_legacy_handover(
        manifest, component.component_id
    )
    if component_handover:
        return (
            component_handover.from_owner,
            "handover.from_owner",
            component_handover,
        )
    return "", "", None


def _artifact_handover(manifest, component, artifact):
    handovers = manifest.matching_handovers(
        artifact.artifact_id, component.component_id
    )
    return handovers[0] if handovers else None


def _resolve_component_owner(manifest, component, artifacts):
    """Resolve one risk owner for a shared source component."""
    handovers = _component_handovers(manifest, component.component_id)
    if handovers:
        handover = handovers[0]
        return handover.to_owner, "handover", handover, ""

    per_artifact = []
    for artifact in artifacts:
        handover = _artifact_handover(manifest, component, artifact)
        if handover:
            per_artifact.append((artifact.artifact_id, handover))
    targets = {handover.to_owner for _, handover in per_artifact}
    if len(targets) == 1:
        _, handover = per_artifact[0]
        note = ""
        if len(per_artifact) != len(artifacts):
            note = (
                "only some artifacts have a proven handover; the shared "
                "component uses the proven target"
            )
        return handover.to_owner, "artifact.handover", handover, note
    if len(targets) > 1:
        _, handover = per_artifact[0]
        return (
            handover.to_owner,
            "artifact.handover_conflict",
            handover,
            "shared component has conflicting artifact handovers; "
            "the first artifact id was used deterministically",
        )

    if component.owner:
        return component.owner, "component.owner", None, ""

    owners = {
        artifact.owner
        for artifact in artifacts
        if artifact.owner
    }
    if len(owners) == 1:
        return owners.pop(), "artifact.owner", None, ""
    if len(owners) > 1:
        owner = sorted(owners)[0]
        return (
            owner,
            "artifact.owner_conflict",
            None,
            "shared component has conflicting artifact owners; "
            "the lexicographically first owner was used",
        )
    return "", "unattributed", None, ""


def _fuzzy_candidates(manifest, finding):
    filename = normalize_path(finding["filename"])
    if not filename:
        return []
    basename = posixpath.basename(filename)
    candidates = {}
    for component in manifest.components.values():
        declared_paths = list(component.paths) + list(component.files)
        for declared in declared_paths:
            declared = normalize_path(declared)
            if not declared:
                continue
            if component.match(filename):
                continue
            score = max(
                difflib.SequenceMatcher(
                    None, filename, declared
                ).ratio(),
                difflib.SequenceMatcher(
                    None,
                    basename,
                    posixpath.basename(declared),
                ).ratio(),
            )
            basename_collision = bool(
                basename
                and basename == posixpath.basename(declared)
            )
            if (
                not basename_collision
                and score < manifest.fuzzy_match_threshold
            ):
                continue
            kind = (
                "basename_collision"
                if basename_collision
                else "approximate_filename"
            )
            candidate = {
                "kind": kind,
                "candidate_component_id": component.component_id,
                "candidate_path": declared,
                "score": round(float(score), 3),
                "reason": (
                    "same file name in a different path; "
                    "not used for attribution"
                    if basename_collision
                    else "approximate filename match; not used for attribution"
                ),
            }
            current = candidates.get(component.component_id)
            if current is None or candidate["score"] > current["score"]:
                candidates[component.component_id] = candidate
    return sorted(
        candidates.values(),
        key=lambda item: (
            -item["score"],
            item["candidate_component_id"],
        ),
    )[:3]


def _match_components(manifest, finding):
    matches = []
    for component in manifest.components.values():
        match = component.match(finding["filename"])
        if match:
            matches.append((component, match))
    if not matches:
        return "none", []
    specificity = max(match[0] for _, match in matches)
    most_specific = [
        (component, match)
        for component, match in matches
        if match[0] == specificity
    ]
    if len(most_specific) > 1:
        return "ambiguous", most_specific
    return "exact", most_specific


def _double_count(component, artifacts, counted):
    if len(artifacts) < 2:
        return None
    artifact_ids = [artifact.artifact_id for artifact in artifacts]
    counted_ids = [artifact.artifact_id for artifact in counted]
    if len(counted) > 1:
        return {
            "detected": True,
            "reason": "shared_component",
            "component_id": component.component_id,
            "artifact_ids": artifact_ids,
            "counted_artifact_ids": counted_ids,
            "detail": (
                "artifacts %s all resolve to source component %r; "
                "the finding is counted once for that component"
            )
            % (", ".join(artifact_ids), component.component_id),
        }
    return {
        "detected": False,
        "reason": "shared_component_single_counted_artifact",
        "component_id": component.component_id,
        "artifact_ids": artifact_ids,
        "counted_artifact_ids": counted_ids,
        "detail": (
            "artifacts %s share source component %r, but only %s "
            "accepts work orders; the finding is counted once"
        )
        % (
            ", ".join(artifact_ids),
            component.component_id,
            ", ".join(counted_ids) or "no artifact",
        ),
    }


def _affected_artifact(
    manifest, component, artifact, legacy_owner, legacy_source, handover
):
    counts, count_reason = artifact.counts_toward_risk(manifest.as_of)
    evidence = [
        item.as_dict()
        for item in manifest.relation_evidence(
            artifact.artifact_id, component.component_id
        )
    ]
    status, status_reason = artifact.effective_status(manifest.as_of)
    result = {
        "artifact_id": artifact.artifact_id,
        "status": status,
        "status_reason": status_reason,
        "artifact_owner": artifact.owner,
        "counts_toward_risk": counts,
        "count_reason": count_reason,
        "relation_evidence": evidence,
    }
    if legacy_owner:
        result["legacy_owner"] = legacy_owner
        result["legacy_owner_source"] = legacy_source
    if handover:
        result["handover"] = handover.as_dict()
    return result


def _owner_bucket():
    return {
        "finding_ids": set(),
        "risk_points": 0,
        "components": set(),
        "artifact_ids": set(),
    }


def _finalize_bucket(bucket):
    return {
        "finding_count": len(bucket["finding_ids"]),
        "risk_points": bucket["risk_points"],
        "components": sorted(bucket["components"]),
        "artifact_ids": sorted(bucket["artifact_ids"]),
    }


def _finding_allocation(
    manifest, finding, component, match, risk_by_owner, risk_by_component
):
    match_kind, matched_path = match[1], match[2]
    artifacts = manifest.related_artifacts(component.component_id)
    if not artifacts:
        return {
            "component_id": component.component_id,
            "component_owner": component.owner,
            "component_legacy_owner": component.legacy_owner,
            "match_kind": match_kind,
            "matched_path": matched_path,
            "counts_toward_risk": False,
            "count_reason": "component_has_no_release_relation",
            "risk_points": 0,
            "affected_artifacts": [],
            "double_count": None,
            "legacy_attribution": [],
        }

    owner, owner_source, owner_handover, owner_note = (
        _resolve_component_owner(manifest, component, artifacts)
    )
    counted = []
    affected = []
    legacy_entries = []
    for artifact in artifacts:
        counts, _ = artifact.counts_toward_risk(manifest.as_of)
        if counts:
            counted.append(artifact)
        legacy_owner, legacy_source, _ = _artifact_legacy_owner(
            manifest, component, artifact
        )
        handover = _artifact_handover(manifest, component, artifact)
        affected.append(
            _affected_artifact(
                manifest,
                component,
                artifact,
                legacy_owner,
                legacy_source,
                handover,
            )
        )
        if legacy_owner:
            legacy_entries.append(
                {
                    "artifact_id": artifact.artifact_id,
                    "owner": legacy_owner,
                    "source": legacy_source,
                    "superseded_by": owner,
                    "counts_toward_risk": counts,
                    "report_only": True,
                }
            )

    double_count = _double_count(component, artifacts, counted)
    points = _risk_points(finding)
    counts_component = bool(owner and counted)
    count_reason = "no_maintainer" if not owner else ""
    if not counted:
        count_reason = "no_artifact_accepts_work_orders"
    elif counts_component:
        if double_count and double_count["detected"]:
            count_reason = "shared_component_counted_once"
        else:
            count_reason = "maintained_component"

    if counts_component:
        finding_id = finding["finding_id"]
        owner_bucket = risk_by_owner[owner]
        owner_bucket["finding_ids"].add(finding_id)
        owner_bucket["risk_points"] += points
        owner_bucket["components"].add(component.component_id)
        owner_bucket["artifact_ids"].update(
            artifact.artifact_id for artifact in counted
        )
        component_bucket = risk_by_component[component.component_id]
        component_bucket["finding_ids"].add(finding_id)
        component_bucket["risk_points"] += points
        component_bucket["owners"].add(owner)
        component_bucket["artifact_ids"].update(
            artifact.artifact_id for artifact in counted
        )

    legacy = []
    for entry in legacy_entries:
        entry = dict(entry)
        entry["finding_id"] = finding["finding_id"]
        entry["component_id"] = component.component_id
        entry["risk_points"] = points if entry["counts_toward_risk"] else 0
        legacy.append(entry)

    result = {
        "component_id": component.component_id,
        "component_owner": component.owner,
        "component_legacy_owner": component.legacy_owner,
        "match_kind": match_kind,
        "matched_path": matched_path,
        "owner": owner,
        "owner_source": owner_source,
        "counts_toward_risk": counts_component,
        "count_reason": count_reason,
        "risk_points": points if counts_component else 0,
        "affected_artifacts": affected,
        "double_count": double_count,
        "legacy_attribution": legacy,
    }
    if owner_handover:
        result["owner_handover"] = owner_handover.as_dict()
    if owner_note:
        result["owner_note"] = owner_note
    return result


def _finding_result(manifest, finding):
    state, matches = _match_components(manifest, finding)
    result = {
        "finding_id": finding["finding_id"],
        "test_id": finding["test_id"],
        "test_name": finding["test_name"],
        "filename": finding["filename"],
        "line_number": finding["line_number"],
        "col_offset": finding["col_offset"],
        "end_col_offset": finding["end_col_offset"],
        "severity": finding["issue_severity"],
        "confidence": finding["issue_confidence"],
        "issue_text": finding["issue_text"],
        "risk_points": 0,
        "attribution_status": "unattributed",
        "reason": "",
        "allocation": [],
        "legacy_attribution": [],
        "double_count": [],
        "needs_investigation": [],
    }
    if state == "ambiguous":
        result["attribution_status"] = "needs_investigation"
        result["reason"] = "ambiguous_exact_component_match"
        result["needs_investigation"] = [
            {
                "finding_id": finding["finding_id"],
                "filename": finding["filename"],
                "kind": "ambiguous_exact_match",
                "candidate_component_id": component.component_id,
                "candidate_path": match[2],
                "score": 1.0,
                "reason": (
                    "multiple components matched at the same specificity"
                ),
            }
            for component, match in matches
        ]
        return result, result["needs_investigation"]
    if state == "none":
        candidates = _fuzzy_candidates(manifest, finding)
        if candidates:
            result["attribution_status"] = "needs_investigation"
            result["reason"] = "no_exact_component_match"
            result["needs_investigation"] = [
                {
                    "finding_id": finding["finding_id"],
                    "filename": finding["filename"],
                    **candidate,
                }
                for candidate in candidates
            ]
        else:
            result["reason"] = "no_component_match"
        return result, result["needs_investigation"]

    return result, None


def attribute_findings(findings, manifest):
    """Attribute normalized findings to manifest owners.

    The returned mapping is deterministic for fixed finding and manifest
    inputs.  Risk is maintained per source component, not per artifact, so two
    artifacts that still share maintained code cannot double count one finding.
    """
    if not isinstance(manifest, ReleaseManifest):
        manifest = load_manifest(manifest)
    if not isinstance(findings, list) or (
        findings and "finding_id" not in findings[0]
    ):
        findings, _ = normalize_findings(findings)

    risk_by_owner = defaultdict(_owner_bucket)
    risk_by_component = defaultdict(
        lambda: {
            "finding_ids": set(),
            "risk_points": 0,
            "owners": set(),
            "artifact_ids": set(),
        }
    )
    legacy_by_owner = defaultdict(_owner_bucket)
    artifact_impact = {}
    for artifact in manifest.artifacts.values():
        status, _ = artifact.effective_status(manifest.as_of)
        counts, _ = artifact.counts_toward_risk(manifest.as_of)
        artifact_impact[artifact.artifact_id] = {
            "status": status,
            "accepts_work_orders": counts,
            "owner": artifact.owner,
            "legacy_owner": artifact.legacy_owner,
            "finding_count": 0,
            "components": set(),
            "shared_components": set(),
        }
    finding_results = []
    investigation_queue = []
    legacy_entries = []
    double_count_events = []
    duplicate_legacy = set()
    legacy_owner_components = set()

    for finding in findings:
        result, leads = _finding_result(manifest, finding)
        if leads:
            investigation_queue.extend(leads)
            finding_results.append(result)
            continue

        state, matches = _match_components(manifest, finding)
        if state != "exact":
            finding_results.append(result)
            continue

        component, match = matches[0]
        allocation = _finding_allocation(
            manifest,
            finding,
            component,
            match,
            risk_by_owner,
            risk_by_component,
        )
        result["allocation"] = [allocation]
        result["legacy_attribution"] = allocation["legacy_attribution"]
        if allocation["double_count"]:
            result["double_count"] = [allocation["double_count"]]
            if allocation["double_count"]["detected"]:
                event = dict(allocation["double_count"])
                event["finding_id"] = finding["finding_id"]
                event["risk_points"] = allocation["risk_points"]
                double_count_events.append(event)

        result["risk_points"] = allocation["risk_points"]
        if allocation["counts_toward_risk"]:
            result["attribution_status"] = "attributed"
            result["reason"] = allocation["count_reason"]
        elif allocation["legacy_attribution"]:
            result["attribution_status"] = "legacy_only"
            result["reason"] = allocation["count_reason"]
        elif allocation["count_reason"] == "component_has_no_release_relation":
            result["reason"] = allocation["count_reason"]
        elif allocation["count_reason"] == "no_artifact_accepts_work_orders":
            result["attribution_status"] = "excluded"
            result["reason"] = allocation["count_reason"]
        else:
            result["reason"] = allocation["count_reason"]

        for legacy in allocation["legacy_attribution"]:
            key = (
                legacy["finding_id"],
                legacy["component_id"],
                legacy["artifact_id"],
                legacy["owner"],
            )
            if key in duplicate_legacy:
                continue
            duplicate_legacy.add(key)
            legacy_entries.append(legacy)
            if legacy["counts_toward_risk"]:
                owner_key = (
                    legacy["finding_id"],
                    legacy["component_id"],
                    legacy["owner"],
                )
                bucket = legacy_by_owner[legacy["owner"]]
                bucket["finding_ids"].add(legacy["finding_id"])
                bucket["components"].add(legacy["component_id"])
                bucket["artifact_ids"].add(legacy["artifact_id"])
                if owner_key in legacy_owner_components:
                    continue
                legacy_owner_components.add(owner_key)
                bucket["risk_points"] += legacy["risk_points"]

        for affected in allocation["affected_artifacts"]:
            artifact = manifest.artifacts[affected["artifact_id"]]
            impact = artifact_impact[artifact.artifact_id]
            status, _ = artifact.effective_status(manifest.as_of)
            impact["status"] = status
            impact["accepts_work_orders"] = affected["counts_toward_risk"]
            impact["finding_count"] += 1
            impact["components"].add(component.component_id)
            if allocation["double_count"]:
                impact["shared_components"].add(component.component_id)

        finding_results.append(result)

    for impact in artifact_impact.values():
        impact["components"] = sorted(impact.pop("components"))
        impact["shared_components"] = sorted(
            impact.pop("shared_components")
        )
        impact["note"] = (
            "informational only; do not total finding_count across "
            "artifacts that share a component"
        )

    risk_owner_output = {
        owner: _finalize_bucket(bucket)
        for owner, bucket in sorted(risk_by_owner.items())
    }
    risk_component_output = {
        component_id: {
            "finding_count": len(bucket["finding_ids"]),
            "risk_points": bucket["risk_points"],
            "owners": sorted(bucket["owners"]),
            "artifact_ids": sorted(bucket["artifact_ids"]),
        }
        for component_id, bucket in sorted(risk_by_component.items())
    }
    legacy_owner_output = {}
    for owner, bucket in sorted(legacy_by_owner.items()):
        entry = _finalize_bucket(bucket)
        entry["report_only"] = True
        legacy_owner_output[owner] = entry
    investigation_queue.sort(
        key=lambda item: (
            -item.get("score", 0.0),
            item.get("candidate_component_id", ""),
            item.get("finding_id", ""),
        )
    )
    legacy_entries.sort(
        key=lambda item: (
            item["finding_id"],
            item["component_id"],
            item["artifact_id"],
            item["owner"],
        )
    )
    double_count_events.sort(
        key=lambda item: (
            item["component_id"],
            item["artifact_ids"],
        )
    )

    status_counts = defaultdict(int)
    for finding in finding_results:
        status_counts[finding["attribution_status"]] += 1

    total_points = sum(
        item["risk_points"] for item in risk_component_output.values()
    )
    avoided_points = 0
    for finding in finding_results:
        for event in finding["double_count"]:
            if event["detected"]:
                extra = len(event["counted_artifact_ids"]) - 1
                avoided_points += extra * finding["risk_points"]

    return {
        "schema_version": ATTRIBUTION_SCHEMA_VERSION,
        "summary": {
            "findings": len(finding_results),
            "attributed": status_counts["attributed"],
            "legacy_only": status_counts["legacy_only"],
            "needs_investigation": status_counts["needs_investigation"],
            "excluded": status_counts["excluded"],
            "unattributed": status_counts["unattributed"],
            "risk_points": total_points,
            "double_count_detected": len(double_count_events),
            "double_count_avoided_points": avoided_points,
            "legacy_entries": len(legacy_entries),
        },
        "risk_by_owner": risk_owner_output,
        "risk_by_component": risk_component_output,
        "legacy_risk_by_owner": legacy_owner_output,
        "legacy_attribution": legacy_entries,
        "investigation_queue": investigation_queue,
        "double_count": {
            "detected": len(double_count_events),
            "reason": (
                "multiple artifacts share a maintained source component"
                if double_count_events
                else ""
            ),
            "events": double_count_events,
        },
        "artifact_impact": artifact_impact,
        "findings": finding_results,
        "manifest": {
            "schema_version": manifest.schema_version,
            "manifest_id": manifest.manifest_id,
            "as_of": manifest.as_of,
            "source": manifest.source_name,
            "sha256": manifest.digest,
            "components": len(manifest.components),
            "artifacts": len(manifest.artifacts),
            "relations": len(manifest.relations),
            "handovers_accepted": len(manifest.valid_handovers),
            "handovers_rejected": _rejected_handover_dicts(manifest),
            "notes": list(manifest.notes),
        },
        "reproducibility": {
            "algorithm": "bandit-attribution",
            "algorithm_version": ATTRIBUTION_ALGORITHM_VERSION,
            "manifest_sha256": manifest.digest,
            "findings_sha256": _digest(findings),
            "risk_weights": RISK_WEIGHTS,
            "fuzzy_match_threshold": manifest.fuzzy_match_threshold,
            "double_count_policy": "one finding per source component",
            "legacy_policy": (
                "legacy owners are always reported; legacy risk is counted "
                "only for artifacts that still accept work orders"
            ),
        },
    }


def attribute_report(report, manifest, view="both"):
    """Attribute a Bandit report to owners declared in ``manifest``.

    :param report: Bandit JSON mapping, finding list, or manager object
    :param manifest: release manifest mapping, path, or loaded manifest
    :param view: ``both`` (default), ``current``, or ``legacy``
    """
    if not isinstance(manifest, ReleaseManifest):
        manifest = load_manifest(manifest)
    if hasattr(report, "get_issue_list") or isinstance(
        report, (dict, list, tuple)
    ):
        findings, duplicates = normalize_findings(report)
    else:
        raise ReportError(
            "report must be a Bandit report mapping, finding list, or manager"
        )

    result = attribute_findings(findings, manifest)
    result["summary"]["duplicate_findings_removed"] = duplicates
    if duplicates:
        result["manifest"]["notes"] = list(result["manifest"]["notes"]) + [
            "%d exact duplicate finding(s) were collapsed" % duplicates
        ]
    return _apply_view(result, view)


def _apply_view(result, view):
    if view not in {"both", "current", "legacy"}:
        raise ValueError("view must be 'both', 'current', or 'legacy'")
    result = copy.deepcopy(result)
    if view == "both":
        return result
    if view == "current":
        result.pop("legacy_attribution", None)
        result.pop("legacy_risk_by_owner", None)
        result["summary"].pop("legacy_entries", None)
        result["summary"].pop("legacy_only", None)
        for finding in result["findings"]:
            finding.pop("legacy_attribution", None)
            for allocation in finding["allocation"]:
                allocation.pop("legacy_attribution", None)
                allocation.pop("component_legacy_owner", None)
                for affected in allocation["affected_artifacts"]:
                    affected.pop("legacy_owner", None)
                    affected.pop("legacy_owner_source", None)
        for impact in result["artifact_impact"].values():
            impact.pop("legacy_owner", None)
        return result

    legacy_findings = []
    for finding in result["findings"]:
        keep = {
            "finding_id": finding["finding_id"],
            "test_id": finding["test_id"],
            "test_name": finding["test_name"],
            "filename": finding["filename"],
            "line_number": finding["line_number"],
            "severity": finding["severity"],
            "confidence": finding["confidence"],
            "legacy_attribution": finding["legacy_attribution"],
        }
        legacy_findings.append(keep)
    return {
        "schema_version": result["schema_version"],
        "summary": {
            "findings": result["summary"]["findings"],
            "legacy_entries": result["summary"]["legacy_entries"],
            "legacy_only": result["summary"]["legacy_only"],
            "legacy_risk_points": sum(
                item["risk_points"]
                for item in result["legacy_risk_by_owner"].values()
            ),
        },
        "legacy_risk_by_owner": result["legacy_risk_by_owner"],
        "legacy_attribution": result["legacy_attribution"],
        "findings": legacy_findings,
        "manifest": result["manifest"],
        "reproducibility": result["reproducibility"],
    }


def dumps(result, indent=2):
    """Return deterministic JSON for an attribution result."""
    return json.dumps(
        result,
        sort_keys=True,
        indent=indent,
        separators=(",", ": "),
        ensure_ascii=False,
    )
