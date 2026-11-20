from __future__ import annotations

import uuid
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

from ..potential_secret import PotentialSecret
from ..secrets_collection import SecretsCollection
from .manifest import LinkageManifest
from .report import MigrationEntry
from .report import MigrationReport
from .report import MigrationStatus
from .schema import LinkageRecord
from .schema import parse_timestamp
from .timeutil import format_timestamp
from .timeutil import utcnow

# A new-baseline secret is located by rule + pseudonymous identifier; the
# old identifier alone is never a sufficient join key. The filename only
# disambiguates repeated occurrences of the same finding.
TargetKey = Tuple[str, str]


def build_target_index(
    new_baseline: SecretsCollection,
) -> Dict[TargetKey, List[PotentialSecret]]:
    index: Dict[TargetKey, List[PotentialSecret]] = {}
    for _, secret in new_baseline:
        index.setdefault((secret.type, secret.secret_hash), []).append(secret)
    return index


class MigrationProtocol:
    """Carries human review decisions across a desensitization key rotation.

    Inputs are local-only: two baseline objects plus one trusted linkage
    manifest. No secret plaintext is read and nothing is fetched remotely.
    """

    def __init__(
        self,
        old_baseline: SecretsCollection,
        new_baseline: SecretsCollection,
        manifest: LinkageManifest,
        evaluated_at: Optional[str] = None,
        id_generator: Callable[[], str] = lambda: uuid.uuid4().hex[:12],
    ) -> None:
        self.old_baseline = old_baseline
        self.new_baseline = new_baseline
        self.manifest = manifest
        self.evaluated_at = (
            parse_timestamp(evaluated_at) if evaluated_at else utcnow()
        )
        self._id_generator = id_generator
        self._target_index = build_target_index(new_baseline)

    def run(self) -> "MigrationResult":
        window_open = self.manifest.is_window_open(
            format_timestamp(self.evaluated_at),
        )
        entries: List[MigrationEntry] = []
        migrated: List[Tuple[PotentialSecret, PotentialSecret]] = []

        for _, old_secret in self.old_baseline:
            entry, pair = self._classify(old_secret, window_open)
            entries.append(entry)
            if pair is not None:
                migrated.append(pair)

        report = MigrationReport(
            project_id=self.manifest.project_id,
            window_open=window_open,
            evaluated_at=format_timestamp(self.evaluated_at),
            entries=entries,
        )
        return MigrationResult(
            migrated_baseline=self._apply_decisions(migrated),
            report=report,
        )

    def _classify(
        self,
        old_secret: PotentialSecret,
        window_open: bool,
    ) -> Tuple[MigrationEntry, Optional[Tuple[PotentialSecret, PotentialSecret]]]:
        records = self.manifest.records_for(
            rule_id=old_secret.type,
            old_secret_id=old_secret.secret_hash,
        )

        def make_entry(
            status: MigrationStatus,
            reason: str,
            evidence_count: int,
        ) -> MigrationEntry:
            return MigrationEntry(
                record_ref=self._id_generator(),
                project_id=self.manifest.project_id,
                rule_id=old_secret.type,
                filename=old_secret.filename,
                line_number=old_secret.line_number,
                status=status,
                reason=reason,
                decision=old_secret.is_secret,
                evidence_count=evidence_count,
            )

        if not records:
            return (
                make_entry(
                    MigrationStatus.UNMIGRATED,
                    "no linkage evidence for this rule and old identifier",
                    0,
                ),
                None,
            )

        active = [
            record
            for record in records
            if record.is_active_at(self.evaluated_at)
        ]
        if not active:
            return (
                make_entry(
                    MigrationStatus.EXPIRED,
                    "all linkage evidence is outside its validity window",
                    len(records),
                ),
                None,
            )

        if window_open:
            status = self._evidence_status(active)
            if status != MigrationStatus.MIGRATED:
                return (
                    make_entry(status, self._reason_for(status), len(active)),
                    None,
                )

            target = self._find_target(active[0])
            if target is None:
                return (
                    make_entry(
                        MigrationStatus.TARGET_MISSING,
                        "new baseline has no candidate for the linked identifier",
                        len(active),
                    ),
                    None,
                )
            return (
                make_entry(
                    MigrationStatus.MIGRATED,
                    "human decision carried forward through trusted linkage",
                    len(active),
                ),
                (old_secret, target),
            )

        # The transition was ended early (or naturally). Even otherwise
        # valid evidence no longer authorizes a migration; the item stays
        # visible so operators can find everything that never made it across.
        return (
            make_entry(
                MigrationStatus.UNMIGRATED,
                "transition window is closed; evidence can no longer be applied",
                len(active),
            ),
            None,
        )

    def _evidence_status(
        self,
        active: List[LinkageRecord],
    ) -> MigrationStatus:
        new_ids = {record.new_secret_id for record in active}
        if len(active) > 1 and len(new_ids) == 1:
            return MigrationStatus.DUPLICATE
        if len(new_ids) > 1:
            return MigrationStatus.CONFLICT

        target = self._find_target(active[0])
        if target is not None and target.filename != active[0].filename:
            return MigrationStatus.CONFLICT
        return MigrationStatus.MIGRATED

    def _find_target(self, record: LinkageRecord) -> Optional[PotentialSecret]:
        candidates = self._target_index.get(
            (record.rule_id, record.new_secret_id),
        )
        if not candidates:
            return None
        for candidate in candidates:
            if candidate.filename == record.filename:
                return candidate
        return candidates[0]

    @staticmethod
    def _reason_for(status: MigrationStatus) -> str:
        reasons = {
            MigrationStatus.DUPLICATE:
                "repeated linkage evidence for one identifier; manual review required",
            MigrationStatus.CONFLICT:
                "linkage evidence disagrees on the new identifier or its location",
        }
        return reasons[status]

    def _apply_decisions(
        self,
        migrated: List[Tuple[PotentialSecret, PotentialSecret]],
    ) -> SecretsCollection:
        for old_secret, new_secret in migrated:
            if new_secret.is_secret is None:
                new_secret.is_secret = old_secret.is_secret
            if not new_secret.is_verified:
                new_secret.is_verified = old_secret.is_verified
        return self.new_baseline


class MigrationResult:
    def __init__(
        self,
        migrated_baseline: SecretsCollection,
        report: MigrationReport,
    ) -> None:
        self.migrated_baseline = migrated_baseline
        self.report = report

    def pending_record_refs(self) -> List[str]:
        return [entry.record_ref for entry in self.report.pending_entries]


def migrate_baseline(
    old_baseline: SecretsCollection,
    new_baseline: SecretsCollection,
    manifest: LinkageManifest,
    evaluated_at: Optional[str] = None,
) -> MigrationResult:
    """Convenience entry point used before an audit/compare run."""
    return MigrationProtocol(
        old_baseline=old_baseline,
        new_baseline=new_baseline,
        manifest=manifest,
        evaluated_at=evaluated_at,
    ).run()


def prepare_comparison_inputs(
    old_baseline: SecretsCollection,
    new_baseline: SecretsCollection,
    manifest: LinkageManifest,
    project_id: str,
    evaluated_at: Optional[str] = None,
) -> MigrationResult:
    """Migration step to run between baseline loading and audit compare.

    Rejects linkage material scoped to another project, then carries human
    decisions forward so compare/audit sees continuity of review history.
    """
    manifest.require_project(project_id)
    return migrate_baseline(
        old_baseline=old_baseline,
        new_baseline=new_baseline,
        manifest=manifest,
        evaluated_at=evaluated_at,
    )
