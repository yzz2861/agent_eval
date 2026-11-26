"""
Data model for pip-audit's offline, dual-time review workflow.

The offline review model separates three pieces of information that an
ordinary online audit conflates:

* the *effective* time of an advisory (when the vulnerability bulletin says
  the entry came into force), and the *received* time (when the operating
  team actually obtained a copy of it);
* the *deployment scope*, i.e. which package/version pairs were actually
  installed, including placeholders for packages that were never deployed;
* the *disposition* that was produced for a historical cross-section under
  the rules that were in force at the time.

All datetimes are naive UTC datetimes. They are serialized as RFC 3339
strings ending in ``Z`` so that snapshots remain plain, diff-able JSON.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any

from packaging.version import Version


def utcnow() -> datetime:
    """Return the current time as a naive UTC datetime."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def to_rfc3339(dt: datetime) -> str:
    """Serialize a naive UTC datetime as an RFC 3339 ``Z`` string."""
    return dt.replace(microsecond=0).isoformat() + "Z"


def parse_rfc3339(value: str) -> datetime:
    """
    Parse an RFC 3339 timestamp into a naive UTC datetime.

    Both second and sub-second precisions are accepted, matching the formats
    emitted by the vulnerability services.
    """
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def package_key(name: str) -> str:
    """Canonical, case/separator-insensitive key for a package name."""
    return "-".join(name.lower().replace(".", "-").replace("_", "-").split())


class ReviewView(str, enum.Enum):
    """
    The two historical perspectives supported by a review.
    """

    AsOfKnown = "as-of-known"
    """
    Reproduce what could have been known at the cross-section: only advisories
    that had already been *received* (and not later corrected/withdrawn) at
    the cutoff time contribute findings.
    """

    Today = "today"
    """
    Look back from the newest snapshot: advisories that arrived late, or that
    were corrected after the cutoff, are visible and explicitly attributed.
    """


class AdvisoryStatus(str, enum.Enum):
    """Lifecycle state of an advisory record within a snapshot."""

    Active = "active"
    Corrected = "corrected"
    Withdrawn = "withdrawn"


@dataclass(frozen=True)
class AdvisoryRecord:
    """
    A single advisory (vulnerability bulletin entry) as stored in a snapshot.

    `effective_at` is the bulletin's own effective/published time, while
    `received_at` records when operations actually obtained the entry. An
    advisory whose `received_at` is later than a report's cutoff is a
    *late* advisory and must not appear in the ``as-of-known`` view.
    """

    id: str
    package: str
    affected_range: str
    description: str
    fix_versions: list[Version]
    aliases: set[str]
    effective_at: datetime
    received_at: datetime
    status: AdvisoryStatus = AdvisoryStatus.Active
    corrected_at: datetime | None = None
    withdrawn_at: datetime | None = None

    @property
    def package_key(self) -> str:
        """Canonical lookup key for the advisory's package."""
        return package_key(self.package)

    def is_active(self, at: datetime) -> bool:
        """Whether this record was an authoritative, visible advisory at `at`."""
        if self.status is AdvisoryStatus.Withdrawn and self.withdrawn_at is not None:
            if self.withdrawn_at <= at:
                return False
        if self.status is AdvisoryStatus.Corrected and self.corrected_at is not None:
            if self.corrected_at <= at:
                return False
        return True

    def was_known(self, at: datetime) -> bool:
        """
        Whether the operating team could have known about this record at `at`.

        A record is only knowable once it has actually been received, and it
        must still have been authoritative at that time.
        """
        return self.received_at <= at and self.is_active(at)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the advisory record to plain JSON-compatible data."""
        data: dict[str, Any] = {
            "id": self.id,
            "package": self.package,
            "affected_range": self.affected_range,
            "description": self.description,
            "fix_versions": [str(version) for version in self.fix_versions],
            "aliases": sorted(self.aliases),
            "effective_at": to_rfc3339(self.effective_at),
            "received_at": to_rfc3339(self.received_at),
            "status": self.status.value,
        }
        if self.corrected_at is not None:
            data["corrected_at"] = to_rfc3339(self.corrected_at)
        if self.withdrawn_at is not None:
            data["withdrawn_at"] = to_rfc3339(self.withdrawn_at)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AdvisoryRecord:
        """Rebuild an advisory record from serialized data."""
        return cls(
            id=data["id"],
            package=data["package"],
            affected_range=data["affected_range"],
            description=data.get("description", "N/A"),
            fix_versions=[Version(value) for value in data.get("fix_versions", [])],
            aliases=set(data.get("aliases", [])),
            effective_at=parse_rfc3339(data["effective_at"]),
            received_at=parse_rfc3339(data["received_at"]),
            status=AdvisoryStatus(data.get("status", AdvisoryStatus.Active.value)),
            corrected_at=(
                parse_rfc3339(data["corrected_at"])
                if data.get("corrected_at") is not None
                else None
            ),
            withdrawn_at=(
                parse_rfc3339(data["withdrawn_at"])
                if data.get("withdrawn_at") is not None
                else None
            ),
        )


@dataclass(frozen=True)
class DeploymentRecord:
    """
    A package/version pair in the deployment scope.

    `deployed` is ``False`` for placeholder packages: entries that the team
    tracks but that were never installed in the environment. Placeholder
    packages are preserved in the snapshot but never produce a finding.
    """

    name: str
    version: Version | None
    deployed: bool = True
    scope: str = "default"
    note: str = ""

    @property
    def key(self) -> str:
        """Canonical lookup key for the deployment's package."""
        return package_key(self.name)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the deployment record to plain JSON-compatible data."""
        data: dict[str, Any] = {
            "name": self.name,
            "version": str(self.version) if self.version is not None else None,
            "deployed": self.deployed,
            "scope": self.scope,
        }
        if self.note:
            data["note"] = self.note
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeploymentRecord:
        """Rebuild a deployment record from serialized data."""
        version_value = data.get("version")
        return cls(
            name=data["name"],
            version=Version(version_value) if version_value is not None else None,
            deployed=data.get("deployed", True),
            scope=data.get("scope", "default"),
            note=data.get("note", ""),
        )


class DispositionAction(str, enum.Enum):
    """The handling decision produced for an advisory finding."""

    Upgrade = "upgrade"
    Accept = "accept"
    Suppress = "suppress"
    Monitor = "monitor"
    None_ = "none"


@dataclass(frozen=True)
class DispositionRecord:
    """
    The handling produced for an advisory under a specific rule version.

    Dispositions are captured per snapshot so that recomputation can preserve
    the decision a historical report actually shipped, even when the current
    rules would produce a different one.
    """

    advisory_id: str
    package: str
    action: DispositionAction
    rule_version: str
    reason: str = ""
    target_version: Version | None = None
    decided_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize the disposition record to plain JSON-compatible data."""
        data: dict[str, Any] = {
            "advisory_id": self.advisory_id,
            "package": self.package,
            "action": self.action.value,
            "rule_version": self.rule_version,
            "reason": self.reason,
            "target_version": str(self.target_version) if self.target_version else None,
        }
        if self.decided_at is not None:
            data["decided_at"] = to_rfc3339(self.decided_at)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DispositionRecord:
        """Rebuild a disposition record from serialized data."""
        target = data.get("target_version")
        decided = data.get("decided_at")
        return cls(
            advisory_id=data["advisory_id"],
            package=data["package"],
            action=DispositionAction(data["action"]),
            rule_version=data["rule_version"],
            reason=data.get("reason", ""),
            target_version=Version(target) if target is not None else None,
            decided_at=parse_rfc3339(decided) if decided is not None else None,
        )


@dataclass(frozen=True)
class Snapshot:
    """
    An immutable, offline point-in-time capture of the review inputs.

    A snapshot bundles the advisory feed, the deployment scope and the
    dispositions produced under its `rule_version`, together with enough
    provenance (`id`, `created_at`, `description`) to explain later changes.
    """

    id: str
    created_at: datetime
    rule_version: str
    advisories: list[AdvisoryRecord]
    deployments: list[DeploymentRecord]
    dispositions: list[DispositionRecord] = field(default_factory=list)
    description: str = ""

    def advisory_index(self) -> dict[str, AdvisoryRecord]:
        """Return advisories keyed by their advisory ID."""
        return {advisory.id: advisory for advisory in self.advisories}

    def disposition_index(self) -> dict[tuple[str, str], DispositionRecord]:
        """Return dispositions keyed by ``(package key, advisory ID)``."""
        return {
            (package_key(disposition.package), disposition.advisory_id): disposition
            for disposition in self.dispositions
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize the full snapshot to plain JSON-compatible data."""
        return {
            "schema_version": 1,
            "id": self.id,
            "created_at": to_rfc3339(self.created_at),
            "rule_version": self.rule_version,
            "description": self.description,
            "advisories": [advisory.to_dict() for advisory in self.advisories],
            "deployments": [deployment.to_dict() for deployment in self.deployments],
            "dispositions": [disposition.to_dict() for disposition in self.dispositions],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Snapshot:
        """Rebuild a snapshot from serialized data."""
        if data.get("schema_version") != 1:
            raise ValueError(
                f"unsupported offline snapshot schema version: {data.get('schema_version')!r}"
            )
        return cls(
            id=data["id"],
            created_at=parse_rfc3339(data["created_at"]),
            rule_version=data["rule_version"],
            description=data.get("description", ""),
            advisories=[AdvisoryRecord.from_dict(item) for item in data.get("advisories", [])],
            deployments=[DeploymentRecord.from_dict(item) for item in data.get("deployments", [])],
            dispositions=[
                DispositionRecord.from_dict(item) for item in data.get("dispositions", [])
            ],
        )

    def with_corrections(
        self,
        corrected: list[AdvisoryRecord] | None = None,
        *,
        new_id: str,
        created_at: datetime | None = None,
        description: str = "",
    ) -> Snapshot:
        """
        Return a new snapshot that supersedes this one with corrected advisories.

        Records sharing an ID with a replacement are updated; all other records,
        deployments and dispositions are carried forward unchanged.
        """
        replacements = {record.id: record for record in (corrected or [])}
        advisories: list[AdvisoryRecord] = [
            replacements.pop(advisory.id, advisory) for advisory in self.advisories
        ]
        advisories.extend(replacements.values())
        return replace(
            self,
            id=new_id,
            created_at=created_at or utcnow(),
            description=description,
            advisories=advisories,
        )
