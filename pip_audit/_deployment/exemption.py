"""
Caller-supplied exemptions for deployment-stage review.

Exemptions are scoped along three axes:

1. the package (canonicalized name plus the pinned version),
2. the deployment role the notice was filed against,
3. the advisory identifier (optionally; see below).

An exemption only affects a finding when every axis matches. In particular,
an exemption filed against the ``build-host`` role never cancels a finding
for the same archive in the ``runtime-image`` role.

Roles that the caller did not register are treated as unknown. Entries that
target an unknown role are retained verbatim and never applied
automatically.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from pathlib import Path

import tomli
from packaging.utils import canonicalize_name
from packaging.version import Version


class ExemptionDecision(enum.Enum):
    """
    The outcome of matching a single exemption entry against a finding.
    """

    Applied = "applied"
    RoleNotRegistered = "role-not-registered"
    RoleMismatch = "role-mismatch"
    PackageMismatch = "package-mismatch"


class ExemptionCatalogError(Exception):
    """Raised when an exemption file cannot be parsed or validated."""


@dataclass(frozen=True)
class Exemption:
    """
    A single caller-supplied exemption entry.
    """

    package: str
    version: Version
    role: str
    advisory: str | None
    reason: str

    @property
    def canonical_name(self) -> str:
        return canonicalize_name(self.package)

    def matches_package(self, name: str, version: Version) -> bool:
        return self.canonical_name == canonicalize_name(name) and self.version == version

    def matches_advisory(self, advisory_id: str, aliases: set[str]) -> bool:
        if self.advisory is None:
            return True
        return self.advisory == advisory_id or self.advisory in aliases


@dataclass(frozen=True)
class ExemptionEvaluation:
    """
    The result of evaluating the whole catalog for one finding.
    """

    decision: ExemptionDecision
    exemption: Exemption | None

    @property
    def is_applied(self) -> bool:
        return self.decision is ExemptionDecision.Applied


class ExemptionCatalog:
    """
    A parsed, role-scoped collection of exemption entries.
    """

    def __init__(
        self,
        exemptions: list[Exemption],
        registered_roles: frozenset[str],
    ) -> None:
        self._exemptions = exemptions
        self._registered_roles = registered_roles

    @property
    def registered_roles(self) -> frozenset[str]:
        return self._registered_roles

    @property
    def exemptions(self) -> tuple[Exemption, ...]:
        return tuple(self._exemptions)

    def is_role_registered(self, role: str) -> bool:
        return role in self._registered_roles

    def evaluate(
        self,
        role: str,
        name: str,
        version: Version,
        advisory_id: str,
        aliases: set[str],
    ) -> ExemptionEvaluation:
        """
        Evaluate every entry for one finding and return the decision.

        Precedence, evaluated in order:

        1. An entry matching package, advisory and the current role is
           ``Applied`` (only when the role is registered).
        2. An entry targeting an unregistered role is retained as
           ``RoleNotRegistered``.
        3. An entry matching package/advisory but a different registered
           role is ``RoleMismatch``.
        4. Otherwise the finding has no matching entry
           (``PackageMismatch``).
        """

        package_candidates = [
            entry
            for entry in self._exemptions
            if entry.matches_package(name, version)
            and entry.matches_advisory(advisory_id, aliases)
        ]

        if not package_candidates:
            return ExemptionEvaluation(ExemptionDecision.PackageMismatch, None)

        for entry in package_candidates:
            if entry.role == role and entry.role in self._registered_roles:
                return ExemptionEvaluation(ExemptionDecision.Applied, entry)

        for entry in package_candidates:
            if entry.role not in self._registered_roles:
                return ExemptionEvaluation(ExemptionDecision.RoleNotRegistered, entry)

        mismatch = next(entry for entry in package_candidates if entry.role != role)
        return ExemptionEvaluation(ExemptionDecision.RoleMismatch, mismatch)


def read_exemption_catalog(filename: Path) -> ExemptionCatalog:
    """
    Parse a TOML exemption file into an `ExemptionCatalog`.

    Raises `ExemptionCatalogError` on any parse or validation error.
    """

    try:
        with filename.open(mode="rb") as f:
            raw = tomli.load(f)
    except FileNotFoundError as e:
        raise ExemptionCatalogError(f"{filename}: exemption file not found") from e
    except tomli.TOMLDecodeError as e:
        raise ExemptionCatalogError(f"{filename}: invalid TOML in exemption file") from e

    registered_roles = raw.get("registered_roles")
    if (
        not isinstance(registered_roles, list)
        or not registered_roles
        or not all(isinstance(role, str) for role in registered_roles)
    ):
        raise ExemptionCatalogError(
            f"{filename}: registered_roles must be a non-empty array of strings"
        )

    exemptions: list[Exemption] = []
    for idx, entry in enumerate(raw.get("exemptions", [])):
        try:
            package = entry["package"]
            raw_version = entry["version"]
            entry_role = entry["role"]
            reason = entry.get("reason", "")
        except KeyError as e:
            raise ExemptionCatalogError(
                f"{filename}: exemption #{idx} missing required field {e.args[0]!r}"
            ) from e

        try:
            version = Version(raw_version)
        except Exception as e:  # packaging raises InvalidVersion subclasses
            raise ExemptionCatalogError(
                f"{filename}: exemption #{idx} has invalid version {raw_version!r}"
            ) from e

        exemptions.append(
            Exemption(
                package=package,
                version=version,
                role=entry_role,
                advisory=entry.get("advisory"),
                reason=reason,
            )
        )

    return ExemptionCatalog(exemptions, frozenset(registered_roles))
