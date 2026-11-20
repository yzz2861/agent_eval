# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Read-only root rotation rehearsal for rollout planning.

This module projects whether client batches can rotate their trusted root
to a target version during planned launch windows, without touching any
repository, cache or network resource:

* Input is a chain of already signed candidate roots, each with the time
  range in which it is visible to clients, and the trust root each client
  batch actually holds.
* Projection follows the client workflow rules: root versions advance one
  at a time, every new root must reach the signature threshold of both the
  previous and the new root ("bilateral threshold"), and each batch may
  only spend its per-update rotation budget.
* Distinct blockers are reported separately: missing chain material,
  insufficient signatures and an exhausted update budget.
* ``RotationRehearsal.confirm_with_updater()`` re-runs a projected window
  with the real ``Updater`` to double-check key outcomes.

Nothing in this module mutates its inputs: verification happens in memory
and the optional ``Updater`` cross-check works in a temporary directory.
"""

from __future__ import annotations

import enum
import logging
import tempfile
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from tuf.api import exceptions
from tuf.api.metadata import Metadata, Root
from tuf.ngclient._internal.trusted_metadata_set import TrustedMetadataSet
from tuf.ngclient.config import EnvelopeType, UpdaterConfig
from tuf.ngclient.fetcher import FetcherInterface
from tuf.ngclient.updater import Updater

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Mapping
    from datetime import datetime

logger = logging.getLogger(__name__)


class BlockReason(enum.StrEnum):
    """Why a client batch cannot advance to the next root version."""

    MISSING_MATERIAL = "missing-material"
    NOT_VISIBLE = "not-visible-in-window"
    INSUFFICIENT_SIGNATURES = "insufficient-signatures"
    UPDATE_BUDGET_EXHAUSTED = "update-budget-exhausted"


@dataclass(frozen=True)
class LaunchWindow:
    """A candidate launch window with a label.

    Args:
        label: Human-readable window name used in reports.
        start: First moment clients may update in this window.
        end: Last moment clients may update in this window.
    """

    label: str
    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        if self.end < self.start:
            raise ValueError("window end must not be before window start")


@dataclass(frozen=True)
class CandidateRoot:
    """A signed candidate root and the time range it is visible to clients.

    Args:
        data: Signed root metadata as bytes.
        visible_from: First moment clients can fetch this root.
        visible_until: Last moment clients can fetch this root.
    """

    data: bytes
    visible_from: datetime
    visible_until: datetime

    def is_visible_during(self, window: LaunchWindow) -> bool:
        """Return True if this root is visible at some point of ``window``."""
        return (
            self.visible_from <= window.end
            and self.visible_until >= window.start
        )


@dataclass(frozen=True)
class ClientBatch:
    """A group of clients sharing a trust root and an update budget.

    Args:
        name: Batch identifier used in reports.
        trusted_root: Root metadata this batch currently trusts, as bytes.
        update_budget: Maximum number of root rotations the batch may
            perform in a single update (mirrors
            ``UpdaterConfig.max_root_rotations``).
    """

    name: str
    trusted_root: bytes
    update_budget: int = 256


@dataclass(frozen=True)
class RotationStep:
    """One successful root rotation from one version to the next."""

    from_version: int
    to_version: int


@dataclass
class WindowOutcome:
    """Projected result of one client batch in one launch window.

    Attributes:
        window: The launch window that was evaluated.
        target_version: Root version the batch should reach.
        final_version: Root version the batch ends up trusting.
        steps: Rotations the batch managed to perform, in order.
        block_reason: Why the batch stopped, or None if it reached the
            target version.
        block_detail: Human-readable explanation of the blocker.
        no_path_since: For time-dependent blockers, the moment from which
            no later window offers a path past this point.
    """

    window: LaunchWindow
    target_version: int
    final_version: int
    steps: list[RotationStep] = field(default_factory=list)
    block_reason: BlockReason | None = None
    block_detail: str | None = None
    no_path_since: datetime | None = None

    @property
    def reachable(self) -> bool:
        """True if the batch reaches the target version in this window."""
        return self.final_version >= self.target_version


@dataclass
class BatchReport:
    """Projection summary for one client batch across all launch windows.

    Outcomes are ordered chronologically by window start.
    """

    batch: ClientBatch
    target_version: int
    outcomes: list[WindowOutcome]

    @property
    def reachable_windows(self) -> list[str]:
        """Labels of windows in which the batch reaches the target."""
        return [o.window.label for o in self.outcomes if o.reachable]

    @property
    def stranded_version(self) -> int | None:
        """Root version the batch is left at, or None if never stranded."""
        for outcome in self.outcomes:
            if not outcome.reachable:
                return outcome.final_version
        return None

    @property
    def block_reason(self) -> BlockReason | None:
        """Reason the batch first fails to reach the target, if any."""
        for outcome in self.outcomes:
            if not outcome.reachable:
                return outcome.block_reason
        return None

    @property
    def no_path_since(self) -> datetime | None:
        """Earliest moment from which no launch window offers a path.

        Only time-dependent blockers (a required root leaving visibility)
        produce a moment: for time-independent blockers (missing material,
        insufficient signatures, exhausted budget) the batch never had a
        path and None is returned.
        """
        moments = [
            outcome.no_path_since
            for outcome in self.outcomes
            if not outcome.reachable and outcome.no_path_since is not None
        ]
        return min(moments) if moments else None


@dataclass
class RehearsalResult:
    """Full rehearsal result for all evaluated client batches."""

    target_version: int
    reports: list[BatchReport]

    def summarize(self) -> str:
        """Return a human-readable summary for the on-call scheduler."""
        lines = []
        for report in self.reports:
            name = report.batch.name
            if report.stranded_version is None:
                windows = ", ".join(report.reachable_windows)
                lines.append(
                    f"batch '{name}': reaches root v{self.target_version}"
                    f" in window(s) {windows}"
                )
                continue
            line = (
                f"batch '{name}': stranded at root"
                f" v{report.stranded_version} ({report.block_reason})"
            )
            if report.no_path_since is not None:
                line += f", no path since {report.no_path_since.isoformat()}"
            lines.append(line)
        return "\n".join(lines)


class _StaticFetcher(FetcherInterface):
    """Serves fixed metadata bytes for the Updater cross-check."""

    def __init__(self, files: Mapping[str, bytes]):
        self._files = dict(files)

    def _fetch(self, url: str) -> Iterator[bytes]:
        filename = url.rsplit("/", 1)[-1]
        if filename not in self._files:
            raise exceptions.DownloadHTTPError(f"Unknown path '{url}'", 404)
        yield self._files[filename]


class RotationRehearsal:
    """Projects root rotation outcomes for client batches.

    The rehearsal is read-only: candidate roots and client trust roots are
    only verified in memory and are never modified or persisted.

    Args:
        candidates: The signed candidate root chain with visibility ranges.

    Raises:
        ValueError: A candidate is not valid signed root metadata, or two
            candidates carry the same root version.
    """

    def __init__(self, candidates: Iterable[CandidateRoot]):
        self._candidates: dict[int, CandidateRoot] = {}
        for candidate in candidates:
            md = Metadata.from_bytes(candidate.data)
            if not isinstance(md.signed, Root):
                raise ValueError("Candidate is not root metadata")
            version = md.signed.version
            if version in self._candidates:
                raise ValueError(f"Duplicate candidate root v{version}")
            self._candidates[version] = candidate

    def evaluate_window(
        self,
        batch: ClientBatch,
        window: LaunchWindow,
        target_version: int,
    ) -> WindowOutcome:
        """Project one batch through one launch window.

        Root versions advance one at a time: every candidate must be
        visible during the window, must verify against both the previous
        and the new root thresholds, and each rotation spends one update
        budget.
        """
        trusted = TrustedMetadataSet(batch.trusted_root, EnvelopeType.METADATA)
        outcome = WindowOutcome(
            window=window,
            target_version=target_version,
            final_version=trusted.root.version,
        )
        budget = batch.update_budget
        while outcome.final_version < target_version:
            next_version = outcome.final_version + 1
            candidate = self._candidates.get(next_version)
            if candidate is None:
                outcome.block_reason = BlockReason.MISSING_MATERIAL
                outcome.block_detail = (
                    f"candidate chain has no root v{next_version}"
                )
                break
            if not candidate.is_visible_during(window):
                outcome.block_reason = BlockReason.NOT_VISIBLE
                outcome.block_detail = (
                    f"root v{next_version} is only visible "
                    f"{candidate.visible_from.isoformat()}.."
                    f"{candidate.visible_until.isoformat()}"
                )
                outcome.no_path_since = candidate.visible_until
                break
            if budget <= 0:
                outcome.block_reason = BlockReason.UPDATE_BUDGET_EXHAUSTED
                outcome.block_detail = (
                    f"batch '{batch.name}' may not rotate past "
                    f"v{outcome.final_version} in one update"
                )
                break
            try:
                trusted.update_root(candidate.data)
            except exceptions.UnsignedMetadataError as e:
                outcome.block_reason = BlockReason.INSUFFICIENT_SIGNATURES
                outcome.block_detail = str(e)
                break
            except exceptions.BadVersionNumberError as e:
                outcome.block_reason = BlockReason.MISSING_MATERIAL
                outcome.block_detail = str(e)
                break
            budget -= 1
            outcome.steps.append(
                RotationStep(outcome.final_version, next_version)
            )
            outcome.final_version = next_version

        return outcome

    def evaluate(
        self,
        batch: ClientBatch,
        windows: Iterable[LaunchWindow],
        target_version: int,
    ) -> BatchReport:
        """Project one batch through every launch window, chronologically."""
        ordered = sorted(windows, key=lambda w: (w.start, w.end, w.label))
        outcomes = [
            self.evaluate_window(batch, window, target_version)
            for window in ordered
        ]
        return BatchReport(batch, target_version, outcomes)

    def evaluate_all(
        self,
        batches: Iterable[ClientBatch],
        windows: Iterable[LaunchWindow],
        target_version: int,
    ) -> RehearsalResult:
        """Project every batch through every launch window."""
        window_list = list(windows)
        reports = [
            self.evaluate(batch, window_list, target_version)
            for batch in batches
        ]
        return RehearsalResult(target_version, reports)

    def confirm_with_updater(
        self,
        batch: ClientBatch,
        window: LaunchWindow,
        supporting_metadata: Mapping[str, bytes],
    ) -> int:
        """Re-run a projected window with the real ``Updater``.

        Serves the candidate roots visible during ``window`` (plus the
        given supporting metadata such as timestamp, snapshot and targets)
        to an ``Updater`` bootstrapped with the batch trust root and
        limited to the batch update budget, then returns the trusted root
        version after ``refresh()``. Everything happens in a temporary
        directory: the rehearsal inputs are not modified or persisted.

        Args:
            batch: Client batch to confirm.
            window: Launch window that decides candidate visibility.
            supporting_metadata: Non-root metadata files (``timestamp.json``,
                ``snapshot.json``, ``targets.json``) served to the Updater.

        Raises:
            RepositoryError: The update failed to verify, confirming the
                projected blockage.

        Returns:
            Root version the Updater trusts after refresh.
        """
        trusted_md = Metadata.from_bytes(batch.trusted_root)
        files: dict[str, bytes] = dict(supporting_metadata)
        for version, candidate in self._candidates.items():
            if version > trusted_md.signed.version and (
                candidate.is_visible_during(window)
            ):
                files[f"{version}.root.json"] = candidate.data

        with tempfile.TemporaryDirectory(prefix="tuf-rehearsal-") as md_dir:
            updater = Updater(
                metadata_dir=md_dir,
                metadata_base_url="https://rehearsal.invalid/metadata/",
                fetcher=_StaticFetcher(files),
                config=UpdaterConfig(max_root_rotations=batch.update_budget),
                bootstrap=batch.trusted_root,
            )
            updater.refresh()
            return updater._trusted_set.root.version  # noqa: SLF001
