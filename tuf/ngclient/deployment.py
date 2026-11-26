# Copyright 2026, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Client-side review of delegated deployment plans."""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tuf.api.metadata import TargetFile
    from tuf.ngclient.updater import Updater


@dataclass(frozen=True)
class DeploymentContract:
    """A regional contract that independently authorizes a delegation."""

    id: str
    region: str
    role_name: str
    package_name: str
    target_patterns: frozenset[str]
    allowed_versions: frozenset[str]

    @classmethod
    def create(
        cls,
        contract_id: str,
        region: str,
        role_name: str,
        package_name: str,
        target_patterns: Iterable[str],
        allowed_versions: Iterable[str],
    ) -> DeploymentContract:
        """Create a contract from mutable iterable inputs."""
        return cls(
            contract_id,
            region,
            role_name,
            package_name,
            frozenset(target_patterns),
            frozenset(allowed_versions),
        )


@dataclass(frozen=True)
class StoreLocalRecord:
    """A store's locally recorded package state."""

    store_id: str
    region: str
    package_name: str
    current_version: str
    target_path: str


@dataclass(frozen=True)
class TargetCandidate:
    """A TUF target candidate and the role that provides it."""

    role_name: str
    target_path: str
    version: str
    target_file: TargetFile


@dataclass(frozen=True)
class ApprovalReason:
    """Minimum evidence required to approve a store update candidate."""

    store_id: str
    region: str
    contract_id: str
    role_name: str
    package_name: str
    target_path: str
    version: str
    current_version: str
    reasons: tuple[str, ...]


class DeploymentPlanReviewer:
    """Intersect TUF delegation, contract, package, and local record state."""

    def __init__(
        self,
        updater: Updater,
        contracts: Iterable[DeploymentContract],
        local_records: Mapping[str, StoreLocalRecord],
    ) -> None:
        self._updater = updater
        self._contracts = tuple(contracts)
        self._local_records = dict(local_records)

    def review(self, store_id: str) -> tuple[ApprovalReason, ...]:
        """Return independently justified update candidates for one store."""
        local_record = self._local_records.get(store_id)
        if local_record is None:
            return ()

        candidates = self._target_candidates()
        approvals = []
        for contract in self._contracts:
            for candidate in candidates:
                reasons = self._approval_reasons(
                    contract, local_record, candidate
                )
                if reasons:
                    approvals.append(
                        ApprovalReason(
                            store_id,
                            local_record.region,
                            contract.id,
                            candidate.role_name,
                            contract.package_name,
                            candidate.target_path,
                            candidate.version,
                            local_record.current_version,
                            tuple(reasons),
                        )
                    )

        return tuple(approvals)

    def review_all(self) -> dict[str, tuple[ApprovalReason, ...]]:
        """Return review results keyed by local store identifier."""
        return {
            store_id: self.review(store_id) for store_id in self._local_records
        }

    def _target_candidates(self) -> tuple[TargetCandidate, ...]:
        candidates = []
        for role_name, target_file in self._updater.get_targetinfos():
            version = self._target_version(target_file)
            if version is not None:
                candidates.append(
                    TargetCandidate(
                        role_name,
                        target_file.path,
                        version,
                        target_file,
                    )
                )
        return tuple(candidates)

    @staticmethod
    def _target_version(target_file: TargetFile) -> str | None:
        custom = target_file.custom
        if not isinstance(custom, Mapping):
            return None
        version = custom.get("version")
        return version if isinstance(version, str) else None

    @staticmethod
    def _target_package(target_file: TargetFile) -> str | None:
        custom = target_file.custom
        if not isinstance(custom, Mapping):
            return None
        package_name = custom.get("package")
        return package_name if isinstance(package_name, str) else None

    def _approval_reasons(
        self,
        contract: DeploymentContract,
        local_record: StoreLocalRecord,
        candidate: TargetCandidate,
    ) -> list[str]:
        target_package = self._target_package(candidate.target_file)
        checks = (
            (
                local_record.region == contract.region,
                f"store region {local_record.region} matches contract region",
            ),
            (
                candidate.role_name == contract.role_name,
                f"delegation {candidate.role_name} is covered by "
                f"contract {contract.id}",
            ),
            (
                any(
                    fnmatch.fnmatchcase(candidate.target_path, pattern)
                    for pattern in contract.target_patterns
                ),
                f"target {candidate.target_path} is inside contract boundary",
            ),
            (
                target_package == contract.package_name
                and local_record.package_name == contract.package_name,
                f"package {contract.package_name} matches contract and record",
            ),
            (
                candidate.version in contract.allowed_versions,
                f"version {candidate.version} is allowed by contract",
            ),
            (
                local_record.target_path == candidate.target_path,
                "client record references the same target path",
            ),
        )

        if local_record.current_version == candidate.version or not all(
            allowed for allowed, _ in checks
        ):
            return []

        return [reason for _, reason in checks]
