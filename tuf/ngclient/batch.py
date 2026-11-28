# Copyright 2026, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Batch verification of target lists.

The batch verifier intentionally does not share an
:class:`~tuf.ngclient.Updater` between targets. Each target is verified
through a fresh updater supplied by a factory so that a repository change
between targets cannot be hidden by cached delegated metadata.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import cast

from tuf.api import exceptions
from tuf.api.metadata import Signed, TargetFile, Targets
from tuf.ngclient._internal.trusted_metadata_set import TrustedMetadataSet
from tuf.ngclient.updater import Updater


class TargetVerificationStatus(Enum):
    """Verification status for a target in a batch."""

    #: Target was found and verified with non-expired TUF metadata.
    VERIFIED = "verified"
    #: Target path was not found in the verified target delegation tree.
    NOT_FOUND = "not_found"
    #: Required metadata is expired or does not meet ``min_validity``.
    EXPIRED = "expired"
    #: Target was verified with a different repository generation.
    TRUST_MATERIAL_MISMATCH = "trust_material_mismatch"
    #: Required metadata could not be downloaded.
    DOWNLOAD_ERROR = "download_error"
    #: Downloaded metadata failed a TUF repository verification check.
    REPOSITORY_ERROR = "repository_error"


@dataclass(frozen=True)
class TrustMaterial:
    """Versions of the metadata that verified a target."""

    #: Version of the trusted root metadata.
    root_version: int
    #: Version of the trusted timestamp metadata.
    timestamp_version: int
    #: Version of the trusted snapshot metadata.
    snapshot_version: int
    #: Version of the top-level targets metadata.
    targets_version: int
    #: Name of the targets role containing the target.
    role: str
    #: Version of the targets role containing the target.
    role_version: int

    def generation(self) -> tuple[int, int, int]:
        """Return the repository generation represented by this material."""

        return (
            self.root_version,
            self.timestamp_version,
            self.snapshot_version,
        )


@dataclass(frozen=True)
class TargetVerificationResult:
    """Verification evidence collected for one target."""

    #: Requested target path.
    target_path: str
    #: Per-target verification status.
    status: TargetVerificationStatus
    #: Trust material for successful target-info verification, if available.
    trust_material: TrustMaterial | None = None
    #: Whether this result is the first result in a new repository generation.
    generation_boundary: bool = False
    #: Error message for non-verified targets, when available.
    error: str | None = None

    @property
    def is_verified(self) -> bool:
        """Return whether this target can be included in a signed-off batch."""

        return self.status is TargetVerificationStatus.VERIFIED


@dataclass(frozen=True)
class TargetBatchResult:
    """Verification result and aggregate sign-off decision for a batch."""

    results: tuple[TargetVerificationResult, ...]
    trust_materials: tuple[TrustMaterial, ...]
    generation_boundary: int | None

    @property
    def can_sign_off(self) -> bool:
        """Return whether every target was verified with one generation."""

        return (
            len(self.results) > 0
            and all(result.is_verified for result in self.results)
            and self.generation_boundary is None
        )

    @property
    def trust_generation(
        self,
    ) -> tuple[int, int, int] | None:
        """Return the common repository generation when one exists."""

        generations = {
            material.generation() for material in self.trust_materials
        }
        if len(generations) != 1:
            return None
        return next(iter(generations))


UpdaterFactory = Callable[[], Updater]


class TargetBatchVerifier:
    """Verify a list of targets while retaining per-target trust evidence.

    A factory is called once for each target. This keeps target verification
    independent and makes metadata changes visible even when the fetcher serves
    repository content from mutable in-memory state.
    """

    def __init__(
        self,
        updater_factory: UpdaterFactory,
        *,
        min_validity: timedelta | None = None,
    ) -> None:
        self._updater_factory = updater_factory
        self._min_validity = min_validity

    def verify(self, target_paths: Sequence[str]) -> TargetBatchResult:
        """Verify all targets and return per-target and batch-level results.

        Args:
            target_paths: Target paths to verify in list order.

        Returns:
            A report containing per-target status, the trust material used
            for each successful verification, the first generation boundary,
            and the aggregate sign-off decision.
        """

        partial_results = [
            self._verify_target(target_path) for target_path in target_paths
        ]
        verified_generations = {
            result.trust_material.generation()
            for result in partial_results
            if result.trust_material is not None
        }
        boundary = self._generation_boundary(partial_results)
        results = []

        for index, result in enumerate(partial_results):
            if boundary is not None and index > boundary:
                results.append(
                    TargetVerificationResult(
                        result.target_path,
                        TargetVerificationStatus.TRUST_MATERIAL_MISMATCH,
                        result.trust_material,
                        True,
                        result.error,
                    )
                )
                continue

            if (
                result.status is TargetVerificationStatus.VERIFIED
                and len(verified_generations) > 1
                and boundary == index
            ):
                results.append(
                    TargetVerificationResult(
                        result.target_path,
                        TargetVerificationStatus.TRUST_MATERIAL_MISMATCH,
                        result.trust_material,
                        True,
                    )
                )
            else:
                results.append(result)

        materials = tuple(
            result.trust_material
            for result in results
            if result.trust_material is not None
        )
        return TargetBatchResult(tuple(results), materials, boundary)

    def _verify_target(self, target_path: str) -> TargetVerificationResult:
        try:
            updater = self._updater_factory()
            target_info = updater.get_targetinfo(target_path)
            trusted_set = updater._trusted_set
        except exceptions.ExpiredMetadataError as exception:
            return TargetVerificationResult(
                target_path,
                TargetVerificationStatus.EXPIRED,
                error=str(exception),
            )
        except exceptions.DownloadError as exception:
            return TargetVerificationResult(
                target_path,
                TargetVerificationStatus.DOWNLOAD_ERROR,
                error=str(exception),
            )
        except exceptions.RepositoryError as exception:
            return TargetVerificationResult(
                target_path,
                TargetVerificationStatus.REPOSITORY_ERROR,
                error=str(exception),
            )

        expired_role = self._expired_role(trusted_set)

        if expired_role is not None:
            return TargetVerificationResult(
                target_path,
                TargetVerificationStatus.EXPIRED,
                error=f"{expired_role} is expired or valid for too little time",
            )

        if target_info is None:
            return TargetVerificationResult(
                target_path, TargetVerificationStatus.NOT_FOUND
            )

        role = self._find_target_role(trusted_set, target_info)

        material = TrustMaterial(
            trusted_set.root.version,
            trusted_set.timestamp.version,
            trusted_set.snapshot.version,
            trusted_set.targets.version,
            role,
            cast(Targets, trusted_set[role]).version,
        )
        return TargetVerificationResult(
            target_path, TargetVerificationStatus.VERIFIED, material
        )

    @staticmethod
    def _find_target_role(
        trusted_set: TrustedMetadataSet, target_info: TargetFile
    ) -> str:
        for role_name, signed in trusted_set._trusted_set.items():
            if (
                isinstance(signed, Targets)
                and target_info.path in signed.targets
            ):
                return role_name

        return Targets.type

    def _is_insufficient_validity(
        self,
        reference_time: datetime,
        metadata: Iterable[Signed],
    ) -> bool:
        if self._min_validity is None:
            return any(signed.is_expired(reference_time) for signed in metadata)

        minimum_expiry = reference_time + self._min_validity
        return any(signed.expires <= minimum_expiry for signed in metadata)

    def _expired_role(self, trusted_set: TrustedMetadataSet) -> str | None:
        for role_name, signed in trusted_set._trusted_set.items():
            if self._is_insufficient_validity(
                trusted_set.reference_time, [signed]
            ):
                return role_name
        return None

    @staticmethod
    def _generation_boundary(
        results: Sequence[TargetVerificationResult],
    ) -> int | None:
        previous_generation = None
        for index, result in enumerate(results):
            if result.trust_material is None:
                continue

            generation = result.trust_material.generation()
            if (
                previous_generation is not None
                and generation != previous_generation
            ):
                return index
            previous_generation = generation

        return None


def verify_targets(
    updater_factory: UpdaterFactory,
    target_paths: Sequence[str],
    *,
    min_validity: timedelta | None = None,
) -> TargetBatchResult:
    """Verify a target batch using a fresh updater for each target.

    Example::

        def updater_factory() -> Updater:
            return Updater(
                metadata_dir,
                metadata_base_url,
                target_dir,
                target_base_url,
                fetcher=fetcher,
                bootstrap=root_bytes,
            )

        report = verify_targets(updater_factory, target_paths)
        if not report.can_sign_off:
            raise RuntimeError("Target list cannot be signed off")
    """

    return TargetBatchVerifier(
        updater_factory, min_validity=min_validity
    ).verify(target_paths)
