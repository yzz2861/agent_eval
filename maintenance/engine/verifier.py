"""Offline, fixed-clock verification of one copyable release directory.

A release directory is a self-contained TUF repository (``metadata/`` plus
``targets/``) plus a ``release.json`` manifest.  The maintenance station has
no network during the window, so every signature and expiry check is done
locally against the root metadata the devices pinned at inventory time.

The verifier never trusts repository state on its own: it feeds the metadata
through ``TrustedMetadataSet`` with a fixed reference time, which performs the
full TUF client workflow (signature thresholds, rollback protection via
version numbers, and expiry checks).  A release only counts as verified when
the whole chain -- timestamp, snapshot, targets -- verifies at that clock.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from tuf.api import exceptions as tuf_exceptions
from tuf.api.metadata import TargetFile
from tuf.ngclient._internal.trusted_metadata_set import TrustedMetadataSet
from tuf.ngclient.config import EnvelopeType

from maintenance.engine.clock import parse_iso


@dataclass
class ReleaseVerdict:
    """Outcome of verifying one release for one target at a fixed time."""

    release_name: str
    target: str
    target_version: str | None
    metadata_version: int | None
    published_at: datetime
    verified: bool
    status: str
    reason: str
    verifiable_until: datetime | None = None
    install_deadline: datetime | None = None
    has_time_to_install: bool = False

    def to_dict(self) -> dict:
        def stamp(value: datetime | None) -> str | None:
            return value.isoformat() if value is not None else None

        return {
            "release": self.release_name,
            "version": self.target_version,
            "metadata_version": self.metadata_version,
            "published_at": self.published_at.isoformat(),
            "status": self.status,
            "reason": self.reason,
            "verifiable_until": stamp(self.verifiable_until),
            "install_deadline": stamp(self.install_deadline),
            "has_time_to_install": self.has_time_to_install,
        }


class OfflineVerifier:
    """Verify a single offline release directory with a fixed clock."""

    def __init__(
        self,
        root_path: str | Path,
        release_dir: str | Path,
        reference_time: str | datetime,
    ) -> None:
        self.release_dir = Path(release_dir)
        self.metadata_dir = self.release_dir / "metadata"
        self.targets_dir = self.release_dir / "targets"
        self.reference_time = parse_iso(reference_time)
        self.trusted_root = Path(root_path).read_bytes()

        manifest = json.loads(
            (self.release_dir / "release.json").read_text()
        )
        self.release_name = manifest["release"]
        self.firmware_version = manifest["firmware_version"]
        self.published_at = parse_iso(manifest["published_at"])

    def _read(self, name: str) -> bytes:
        return (self.metadata_dir / name).read_bytes()

    def _reject(
        self, version: str | None, status: str, reason: str
    ) -> ReleaseVerdict:
        return ReleaseVerdict(
            release_name=self.release_name,
            target="",
            target_version=version,
            metadata_version=None,
            published_at=self.published_at,
            verified=False,
            status=status,
            reason=reason,
        )

    def verify(
        self, target: str, trusted_metadata_version: int | None = None
    ) -> ReleaseVerdict:
        """Run the full TUF chain check for ``target`` at the fixed clock.

        ``trusted_metadata_version`` is the metadata version the device group
        pinned at inventory time.  A release whose metadata has advanced past
        it cannot replace the trusted inventory state, so it is rejected even
        though its signatures verify.
        """
        try:
            trusted = TrustedMetadataSet(
                self.trusted_root, EnvelopeType.METADATA
            )
        except tuf_exceptions.RepositoryError as err:
            return self._reject(None, "trusted-root-invalid", str(err))

        trusted.reference_time = self.reference_time
        try:
            timestamp = trusted.update_timestamp(
                self._read("timestamp.json")
            )
            snapshot = trusted.update_snapshot(self._read("snapshot.json"))
            targets = trusted.update_targets(self._read("targets.json"))
        except tuf_exceptions.ExpiredMetadataError as err:
            return self._reject(None, "metadata-expired", str(err))
        except tuf_exceptions.RepositoryError as err:
            return self._reject(None, "signature-invalid", str(err))

        if (
            trusted_metadata_version is not None
            and targets.version > trusted_metadata_version
        ):
            return self._reject(
                None,
                "metadata-version-ahead",
                (
                    f"release metadata v{targets.version} is newer than "
                    f"trusted v{trusted_metadata_version}"
                ),
            )

        # Metadata and device versions advance independently: a release
        # whose metadata version is newer than the one the group pinned at
        # inventory time cannot replace the trusted stock state offline.
        if (
            trusted_metadata_version is not None
            and targets.version > trusted_metadata_version
        ):
            return self._reject(
                None,
                "metadata-version-too-new",
                (
                    f"targets metadata v{targets.version} exceeds trusted "
                    f"v{trusted_metadata_version} from inventory"
                ),
            )

        target_file = targets.targets.get(target)
        if target_file is None:
            return self._reject(None, "target-missing", f"{target} absent")

        if not self._payload_matches(target, target_file):
            return self._reject(None, "payload-mismatch", f"{target} hash")

        verifiable_until = min(
            timestamp.expires, snapshot.expires, targets.expires
        )
        return ReleaseVerdict(
            release_name=self.release_name,
            target=target,
            target_version=self.firmware_version,
            metadata_version=targets.version,
            published_at=self.published_at,
            verified=True,
            status="verified",
            reason="full TUF chain verified at fixed clock",
            verifiable_until=verifiable_until,
        )

    def _payload_matches(self, target: str, target_file: TargetFile) -> bool:
        payload_path = self.targets_dir / Path(target).name
        if not payload_path.is_file():
            return False
        try:
            target_file.verify_length_and_hashes(payload_path.read_bytes())
        except tuf_exceptions.LengthOrHashMismatchError:
            return False
        return True

    def install_deadline(
        self, verifiable_until: datetime, install_duration: timedelta
    ) -> datetime:
        """Latest install start that still leaves time to finish."""
        return verifiable_until - install_duration
