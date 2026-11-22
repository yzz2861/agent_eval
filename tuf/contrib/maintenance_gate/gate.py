"""Local admission gate built on the TUF trusted metadata reading model.

The gate is deliberately transport agnostic: maintenance material is handed in
as signed metadata bytes, in any order, possibly incomplete.  Nothing is
trusted until it survives the standard TUF verification chain

    root -> timestamp -> snapshot -> targets -> delegated targets

implemented by TrustedMetadataSet.  That reader enforces signature thresholds,
snapshot-pinned versions and hashes, expiry and rollback protection, which is
exactly what makes the final admission decision independent of the order in
which pause and resume slips arrive on the different maintenance channels.

Three outcomes are possible for a fed document:

* TRUSTED  - verified and incorporated into the current trusted view;
* STAGED   - a half set (for example a delegated slip without the matching
  timestamp/snapshot).  It is retained and retried whenever more material
  arrives;
* REJECTED - failed verification (bad signature, rollback, hash mismatch).
  It can never influence an admission.

Per package the gate returns one of PROCEED, PAUSED or PENDING, always with a
human readable basis that cites the verified statement and its authorization
version, or the missing metadata that forces a fail closed pending verdict.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from tuf.api import exceptions as tuf_exceptions
from tuf.api.metadata import Metadata, TargetFile, Targets, Timestamp

if TYPE_CHECKING:
    from collections.abc import Iterable
from tuf.contrib.maintenance_gate.model import (
    PAUSE,
    AdmissionDecision,
    AdmissionVerdict,
    AuthorizationStatement,
    GateStatus,
    IngestResult,
    statements_from_targets,
    target_action,
)
from tuf.ngclient._internal.trusted_metadata_set import TrustedMetadataSet
from tuf.ngclient.config import EnvelopeType

logger = logging.getLogger(__name__)

#: Filename used by snapshot/timestamp for the top level targets role.
_TOP_TARGETS = "targets"


class MaintenanceGate:
    """Stateful, order independent admission gate for one offline device.

    The gate bootstraps from a trusted root and keeps the highest fully
    verified TUF release.  Documents that cannot yet be verified are staged;
    documents that fail verification are rejected.  Admission for a package is
    recomputed from the trusted view on demand and never from arrival order.
    """

    def __init__(
        self,
        root_bytes: bytes,
        *,
        delegated_roles: Iterable[str] = (),
        reference_time: datetime | None = None,
    ) -> None:
        """Create a gate with an immutable trust anchor.

        Args:
            root_bytes: Trusted root metadata (the offline provisioning anchor).
            delegated_roles: Names of delegated maintenance roles the gate may
                receive, matching the repository delegation graph.
            reference_time: Override the clock for expiry evaluation (tests and
                reproducible offline runs).  Defaults to the current UTC time.
        """
        self._root_bytes = root_bytes
        self._delegated_roles = tuple(dict.fromkeys(delegated_roles))
        self._reference_time = reference_time or datetime.now(UTC)
        # The core chain must always be present before any promotion.
        self._core_roles = ("timestamp", "snapshot", _TOP_TARGETS)
        self._required = {
            *self._core_roles,
            *self._delegated_roles,
        }

        # Bytes of every role in the highest fully verified release.
        self._trusted_bytes: dict[str, bytes] = {}
        # The active trusted set, rebuilt whenever a release is promoted.
        self._trusted: TrustedMetadataSet | None = None
        # Half-set material waiting for the rest of its release.
        self._staging: dict[str, bytes] = {}
        # Rejected bytes kept for the audit trail only, never trusted.
        self._rejected: dict[str, bytes] = {}
        # Monotonic, append-only audit log of ingest outcomes.
        self.audit_log: list[IngestResult] = []

    # ------------------------------------------------------------------
    # Ingestion: feed signed metadata in arbitrary order.
    # ------------------------------------------------------------------
    def ingest(self, role: str, data: bytes) -> IngestResult:
        """Feed one signed authorization document to the gate.

        The document is never trusted on its own: the gate attempts to build a
        complete TUF release from the newly arrived document plus anything held
        in staging and the currently trusted view.  The result classifies the
        document as trusted, staged or rejected.

        Args:
            role: TUF role name (``timestamp``, ``snapshot``, ``targets`` or a
                delegated role).
            data: Signed metadata bytes as received on a maintenance channel.

        Returns:
            An :class:`IngestResult` describing the outcome and reason.
        """
        candidate = dict(self._staging)
        candidate[role] = data

        # Fast rollback precheck for a document that cannot yet form a full
        # chain: an older timestamp is rejected on its own version number.
        standalone_reject = self._standalone_rollback(role, data)
        if standalone_reject is not None:
            self._rejected[role] = data
            result = IngestResult(
                role=role,
                status=GateStatus.REJECTED,
                reason=standalone_reject,
            )
            self.audit_log.append(result)
            return result

        promoted, error = self._try_promote(candidate)
        if promoted is not None:
            # Trusted bytes describe exactly the newly verified release; stale
            # bytes from the previous epoch are never carried over.
            merged = dict(candidate)
            merged.pop("root", None)

            # Delegated roles absent from this release remain unverified for
            # the new epoch, so their targets fail closed until fresh metadata
            # arrives.
            missing_delegated = [
                delegated
                for delegated in self._delegated_roles
                if delegated not in merged
            ]

            self._trusted = promoted
            self._trusted_bytes = merged
            self._trusted_bytes["root"] = self._root_bytes
            # Anything still staged has been consumed by this promotion.
            self._staging = {}
            reason = (
                "verified TUF release "
                f"(timestamp v{promoted.timestamp.version})"
            )
            if missing_delegated:
                reason += "; delegated metadata still missing: " + ", ".join(
                    missing_delegated
                )
            result = IngestResult(
                role=role,
                status=GateStatus.TRUSTED,
                reason=reason,
                promoted_epoch=promoted.timestamp.version,
                detail={"missing_delegated": missing_delegated},
            )
            self.audit_log.append(result)
            return result

        if error is None:
            # Could not complete a release but nothing was invalid: hold it.
            self._staging[role] = data
            result = IngestResult(
                role=role,
                status=GateStatus.STAGED,
                reason=self._stage_reason(candidate),
            )
            self.audit_log.append(result)
            return result

        # A verification failure on a document that does not combine into a
        # valid release is a hard rejection. Identify which supplied document
        # is actually invalid rather than blaming the last arrival.
        invalid_role, invalid_data = self._identify_invalid(
            candidate, role, data
        )
        self._rejected[invalid_role] = invalid_data
        self._staging.pop(invalid_role, None)
        result = IngestResult(
            role=invalid_role,
            status=GateStatus.REJECTED,
            reason=error,
        )
        self.audit_log.append(result)
        return result

    def ingest_many(
        self, documents: dict[str, bytes]
    ) -> dict[str, IngestResult]:
        """Feed a batch of role -> bytes documents and return each outcome."""
        return {
            role: self.ingest(role, data) for role, data in documents.items()
        }

    def _standalone_rollback(self, role: str, data: bytes) -> str | None:
        """Reject an obviously stale document before chain assembly.

        A timestamp that deserializes but carries a version older than the
        trusted one is a rollback attempt even when its snapshot has not
        arrived. Catching it here prevents an old release from being staged and
        later mistaken for new material. Signature verification is still
        enforced when the full chain is assembled; this check only compares
        version numbers of parseable metadata.
        """
        if role != "timestamp" or self._trusted is None:
            return None
        try:
            timestamp = Metadata.from_bytes(data).signed
        except tuf_exceptions.RepositoryError:
            # Unparseable bytes will be rejected through normal verification.
            return None
        if not isinstance(timestamp, Timestamp):
            return None
        offered = timestamp.version
        current = self._trusted.timestamp.version
        if offered < current:
            return (
                f"rollback rejected: timestamp v{offered} is older than "
                f"trusted v{current}"
            )
        return None

    def _try_promote(
        self, candidate: dict[str, bytes]
    ) -> tuple[TrustedMetadataSet | None, str | None]:
        """Attempt to verify a complete release from the candidate documents.

        A release only promotes when every required role is present and the
        whole TUF chain (timestamp, snapshot, targets and all delegated roles)
        verifies as one self-consistent set. This strict all-or-nothing rule is
        what makes the final trusted view independent of arrival order: an
        incomplete release is staged and retried, never partially applied.

        Returns the promoted trusted set on success.  Otherwise returns
        ``(None, None)`` for an incomplete-but-valid half set, or
        ``(None, error)`` for a hard verification failure.
        """
        release = dict(candidate)
        release.pop("root", None)

        missing_core = [
            role for role in self._core_roles if role not in release
        ]
        if missing_core:
            return None, None

        missing_delegated = [
            delegated
            for delegated in self._delegated_roles
            if delegated not in release
        ]
        if missing_delegated:
            return None, None

        trusted, _failing_role, error = self._build_trusted(release)
        if trusted is None:
            return None, error

        if self._trusted is not None:
            current = self._trusted.timestamp.version
            offered = trusted.timestamp.version
            if offered < current:
                return None, (
                    f"rollback rejected: timestamp v{offered} is older than "
                    f"trusted v{current}"
                )
            if offered == current:
                # Re-delivery of the already trusted release: idempotent no-op.
                return None, None

        return trusted, None

    def _build_trusted(
        self, merged: dict[str, bytes]
    ) -> tuple[TrustedMetadataSet | None, str | None, str | None]:
        """Verify roles in TUF chain order and report the failing role.

        Delegated roles that are simply absent are skipped rather than treated
        as failures: their targets fail closed at admission time. A delegated
        role that *is* supplied but cannot be verified is a hard error and is
        reported as the failing role.

        Returns ``(trusted, None, None)`` on success, otherwise
        ``(None, failing_role, error)``.
        """
        try:
            trusted = TrustedMetadataSet(
                self._root_bytes, EnvelopeType.METADATA
            )
            trusted.reference_time = self._reference_time
            try:
                trusted.update_timestamp(merged["timestamp"])
            except tuf_exceptions.RepositoryError as exc:
                return None, "timestamp", self._classify_error(exc)
            try:
                trusted.update_snapshot(merged["snapshot"])
            except tuf_exceptions.RepositoryError as exc:
                return None, "snapshot", self._classify_error(exc)
            try:
                trusted.update_targets(merged[_TOP_TARGETS])
            except tuf_exceptions.RepositoryError as exc:
                return None, _TOP_TARGETS, self._classify_error(exc)
            for delegated in self._delegated_roles:
                if delegated not in merged:
                    # Half set: this delegated role has not arrived yet.
                    continue
                try:
                    trusted.update_delegated_targets(
                        merged[delegated], delegated, _TOP_TARGETS
                    )
                except tuf_exceptions.RepositoryError as exc:
                    return None, delegated, self._classify_error(exc)
        except tuf_exceptions.RepositoryError as exc:
            # Defensive: an unexpected failure before a role is pinned down.
            return None, None, self._classify_error(exc)
        return trusted, None, None

    def _identify_invalid(
        self,
        candidate: dict[str, bytes],
        arrived_role: str,
        arrived_data: bytes,
    ) -> tuple[str, bytes]:
        """Pinpoint the supplied document that breaks verification.

        The combined release failed, but the failure may come from any newly
        supplied document held in staging, not necessarily the one that just
        arrived. Verification walks the TUF chain role by role, so the first
        role that fails is the invalid document.
        """
        merged = dict(self._trusted_bytes)
        merged.update(candidate)
        merged.pop("root", None)
        _, failing_role, _ = self._build_trusted(merged)
        if failing_role is not None and failing_role in candidate:
            return failing_role, candidate[failing_role]
        # Fallback: attribute the failure to the document just received.
        return arrived_role, arrived_data

    @staticmethod
    def _classify_error(exc: tuf_exceptions.RepositoryError) -> str:
        """Turn a TUF verification exception into an audit reason."""
        return f"{type(exc).__name__}: {exc}"

    def _stage_reason(self, candidate: dict[str, bytes]) -> str:
        """Explain which role of the in-flight release is still missing."""
        missing = sorted(self._required - candidate.keys())
        if missing:
            return "half set held, awaiting: " + ", ".join(missing)
        return "half set held pending a newer complete release"

    # ------------------------------------------------------------------
    # Trusted view accessors.
    # ------------------------------------------------------------------
    @property
    def trusted_epoch(self) -> int | None:
        """Return the timestamp version of the trusted release, if any."""
        if self._trusted is None:
            return None
        return self._trusted.timestamp.version

    @property
    def has_trusted_view(self) -> bool:
        """Return whether at least one full release has been verified."""
        return self._trusted is not None

    @property
    def staged_roles(self) -> tuple[str, ...]:
        """Return roles currently held as an unverifiable half set."""
        return tuple(sorted(self._staging))

    @property
    def rejected_roles(self) -> tuple[str, ...]:
        """Return roles whose documents failed verification."""
        return tuple(sorted(self._rejected))

    def statements(self) -> list[AuthorizationStatement]:
        """Return all verified pause/resume statements in the current view."""
        if self._trusted is None:
            return []
        result: list[AuthorizationStatement] = []
        for role in self._delegated_roles:
            if role not in self._trusted:
                continue
            result.extend(statements_from_targets(role, self._trusted[role]))
        return result

    # ------------------------------------------------------------------
    # Admission: order independent per-package decisions.
    # ------------------------------------------------------------------
    def admit(self, target_path: str) -> AdmissionDecision:
        """Decide whether a package may be admitted (updated/installed).

        The delegation graph is walked in TUF delegation order.  The first
        verified role that explicitly lists the target decides it: pause
        statements yield ``PAUSED``, resume statements yield ``PROCEED``.  A
        role that covers the path but could not be verified forces a fail
        closed ``PENDING``.  A terminating role stops the walk; otherwise the
        search continues to the next delegated role.

        Args:
            target_path: Canonical TUF target path of the package.

        Returns:
            An :class:`AdmissionDecision` with verdict and justification.
        """
        if self._trusted is None:
            return AdmissionDecision(
                target=target_path,
                verdict=AdmissionVerdict.PENDING,
                basis=(
                    "no verified release yet; held material for "
                    f"{self.staged_roles or ()}"
                ),
            )

        top: Targets = self._trusted[_TOP_TARGETS]
        if top.delegations is None:
            return self._default_proceed(target_path)

        for role_name, terminating in top.delegations.get_roles_for_target(
            target_path
        ):
            if role_name not in self._trusted:
                return AdmissionDecision(
                    target=target_path,
                    verdict=AdmissionVerdict.PENDING,
                    basis=(
                        f"delegated role {role_name!r} covers the target but "
                        "its metadata is not verified (half set)"
                    ),
                )

            role_targets: Targets = self._trusted[role_name]
            target_file = role_targets.targets.get(target_path)
            if target_file is None or target_action(target_file) is None:
                # The role covers the path pattern but carries no statement for
                # this exact package. A terminating role ends the lookup here.
                if terminating:
                    return self._default_proceed(
                        target_path,
                        f"terminating role {role_name!r} lists no statement",
                    )
                continue

            action = target_action(target_file)
            statement = self._find_statement(role_name, action, target_path)
            verdict = (
                AdmissionVerdict.PAUSED
                if action == PAUSE
                else AdmissionVerdict.PROCEED
            )
            return AdmissionDecision(
                target=target_path,
                verdict=verdict,
                basis=(
                    f"{action} v{role_targets.version} from role "
                    f"{role_name!r} covers the target"
                ),
                statement=statement,
            )

        return self._default_proceed(target_path)

    def admit_many(
        self, target_paths: Iterable[str]
    ) -> dict[str, AdmissionDecision]:
        """Admit several packages; the result does not depend on input order."""
        return {path: self.admit(path) for path in target_paths}

    def admit_cached(
        self,
        target_path: str,
        cached_bytes: bytes | None = None,
    ) -> AdmissionDecision:
        """Re-evaluate a package already cached locally on the device.

        Caching never grants authority: a cached package is gated through
        :meth:`admit` against the current trusted view before it can be used.
        When ``cached_bytes`` is supplied it is additionally checked against the
        length and hashes recorded in the verified targets metadata, so stale
        or tampered cached content is forced into ``PENDING`` instead of being
        admitted.

        Args:
            target_path: Canonical TUF target path of the cached package.
            cached_bytes: Optional on-disk content of the cached package.
        """
        decision = self.admit(target_path)
        if cached_bytes is None or self._trusted is None:
            return decision

        target_file = self._verified_target_file(target_path)
        if target_file is None:
            return AdmissionDecision(
                target=target_path,
                verdict=AdmissionVerdict.PENDING,
                basis=(
                    "cached target has no verified length/hash description; "
                    "operator check required"
                ),
            )

        try:
            target_file.verify_length_and_hashes(cached_bytes)
        except tuf_exceptions.LengthOrHashMismatchError as exc:
            return AdmissionDecision(
                target=target_path,
                verdict=AdmissionVerdict.PENDING,
                basis=f"cached content failed verification: {exc}",
            )
        return decision

    def _verified_target_file(self, target_path: str) -> TargetFile | None:
        """Find the verified TargetFile description for a target, if any."""
        if self._trusted is None:
            return None
        for role in self._delegated_roles:
            if role not in self._trusted:
                continue
            target_file = self._trusted[role].targets.get(target_path)
            if target_file is not None:
                return target_file
        return None

    def _find_statement(
        self, role: str, action: str, target_path: str
    ) -> AuthorizationStatement | None:
        """Locate the verified statement backing an admission decision."""
        for statement in self.statements():
            if (
                statement.role == role
                and statement.action == action
                and statement.covers(target_path)
            ):
                return statement
        return None

    @staticmethod
    def _default_proceed(
        target_path: str, detail: str | None = None
    ) -> AdmissionDecision:
        """Build a proceed verdict for a target with no pause in effect."""
        basis = (
            "no verified pause statement covers the target"
            if detail is None
            else detail
        )
        return AdmissionDecision(
            target=target_path,
            verdict=AdmissionVerdict.PROCEED,
            basis=basis,
        )
