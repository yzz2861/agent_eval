"""Regression tests for release-set resolution (tuf.ngclient.release_set).

All tests run against an in-memory repository simulator: no network, no
database and only small in-memory files are used.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from tests.repository_simulator import RepositorySimulator
from tuf.api.metadata import DelegatedRole, Targets
from tuf.ngclient.fetcher import FetcherInterface
from tuf.ngclient.release_set import (
    ReleaseManifest,
    ReleaseSetError,
    ReleaseSetResolver,
    version_satisfies,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

APP_V1 = b"app 1.0 payload\n"
APP_V2 = b"app 2.0 payload\n"
LIB_V15 = b"lib 1.5 payload\n"

MANIFEST_V1 = "manifests/release-1.json"
MANIFEST_V2 = "manifests/release-2.json"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _component(
    name: str,
    path: str,
    data: bytes,
    version: str,
    requires: dict[str, str] | None = None,
) -> dict:
    entry = {
        "name": name,
        "path": path,
        "sha256": _sha256(data),
        "version": version,
    }
    if requires:
        entry["requires"] = requires
    return entry


def _manifest_bytes(name: str, components: list[dict]) -> bytes:
    doc = {"release_set": name, "components": components}
    return json.dumps(doc).encode()


class _MidResolutionPublisher(FetcherInterface):
    """Fetcher that publishes a new snapshot mid-resolution.

    When the delegated "pkgs" metadata is first requested, the repository
    is mutated as if a concurrent publish happened: the delegated role
    version is bumped and a new snapshot/timestamp is published.
    """

    def __init__(self, sim: RepositorySimulator):
        self.sim = sim
        self.fired = False

    def _fetch(self, url: str) -> Iterator[bytes]:
        if not self.fired and "pkgs.json" in url:
            self.fired = True
            self.sim.md_delegates["pkgs"].signed.version += 1
            self.sim.update_snapshot()
        yield from self.sim._fetch(url)


class TestReleaseSet(unittest.TestCase):
    """Test ReleaseSetResolver against an in-memory repository."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(dir=os.getcwd())
        self.metadata_dir = os.path.join(self.temp_dir, "metadata")
        self.targets_dir = os.path.join(self.temp_dir, "targets")
        os.mkdir(self.metadata_dir)
        os.mkdir(self.targets_dir)

        self.sim = RepositorySimulator()
        role = DelegatedRole("pkgs", [], 1, False, ["pkgs/*"])
        self.sim.add_delegation(
            "targets", role, Targets(expires=self.sim.safe_expiry)
        )
        self.sim.add_target("pkgs", APP_V1, "pkgs/app-1.0.tar.gz")
        self.sim.add_target("pkgs", LIB_V15, "pkgs/lib-1.5.tar.gz")
        manifest = _manifest_bytes(
            "demo-1",
            [
                _component(
                    "app",
                    "pkgs/app-1.0.tar.gz",
                    APP_V1,
                    "1.0",
                    {"lib": ">=1.0,<2.0"},
                ),
                _component("lib", "pkgs/lib-1.5.tar.gz", LIB_V15, "1.5"),
            ],
        )
        self.sim.add_target("targets", manifest, MANIFEST_V1)
        self.sim.targets.version += 1
        self.sim.update_snapshot()

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir)

    def _make_resolver(
        self, fetcher: FetcherInterface | None = None
    ) -> ReleaseSetResolver:
        return ReleaseSetResolver(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            fetcher or self.sim,
            bootstrap=self.sim.signed_roots[0],
        )

    def _publish_incompatible_v2(self) -> None:
        """Publish a release-set mixing incompatible component versions."""
        self.sim.add_target("pkgs", APP_V2, "pkgs/app-2.0.tar.gz")
        manifest = _manifest_bytes(
            "demo-2",
            [
                _component(
                    "app",
                    "pkgs/app-2.0.tar.gz",
                    APP_V2,
                    "2.0",
                    {"lib": ">=2.0"},
                ),
                _component("lib", "pkgs/lib-1.5.tar.gz", LIB_V15, "1.5"),
            ],
        )
        self.sim.add_target("targets", manifest, MANIFEST_V2)
        self.sim.targets.version += 1
        self.sim.md_delegates["pkgs"].signed.version += 1
        self.sim.update_snapshot()

    def test_resolve_compatible_release_set(self) -> None:
        resolver = self._make_resolver()
        plan = resolver.resolve(MANIFEST_V1)

        self.assertEqual(plan.release_set, "demo-1")
        self.assertEqual(plan.snapshot_version, self.sim.snapshot.version)
        self.assertEqual({c.spec.name for c in plan.components}, {"app", "lib"})
        self.assertIs(resolver.active_plan, plan)

        paths = resolver.download_all()
        self.assertEqual(set(paths), {"app", "lib"})
        with open(paths["app"], "rb") as f:
            self.assertEqual(f.read(), APP_V1)
        with open(paths["lib"], "rb") as f:
            self.assertEqual(f.read(), LIB_V15)

    def test_mixed_incompatible_release_rejected(self) -> None:
        self._publish_incompatible_v2()
        resolver = self._make_resolver()

        with self.assertRaises(ReleaseSetError):
            resolver.resolve(MANIFEST_V2)
        self.assertIsNone(resolver.active_plan)

    def test_missing_component_rejected(self) -> None:
        manifest = _manifest_bytes(
            "demo-broken",
            [
                _component("app", "pkgs/app-1.0.tar.gz", APP_V1, "1.0"),
                _component("ghost", "pkgs/ghost-1.0.tar.gz", b"ghost", "1.0"),
            ],
        )
        self.sim.add_target("targets", manifest, "manifests/broken.json")
        self.sim.targets.version += 1
        self.sim.update_snapshot()

        resolver = self._make_resolver()
        with self.assertRaises(ReleaseSetError):
            resolver.resolve("manifests/broken.json")
        self.assertIsNone(resolver.active_plan)

    def test_component_digest_mismatch_rejected(self) -> None:
        bad_entry = _component("app", "pkgs/app-1.0.tar.gz", APP_V1, "1.0")
        bad_entry["sha256"] = _sha256(b"not the app payload")
        manifest = _manifest_bytes(
            "demo-baddigest",
            [
                bad_entry,
                _component("lib", "pkgs/lib-1.5.tar.gz", LIB_V15, "1.5"),
            ],
        )
        self.sim.add_target("targets", manifest, "manifests/baddigest.json")
        self.sim.targets.version += 1
        self.sim.update_snapshot()

        resolver = self._make_resolver()
        with self.assertRaises(ReleaseSetError):
            resolver.resolve("manifests/baddigest.json")
        self.assertIsNone(resolver.active_plan)

    def test_manifest_must_be_tuf_authorized(self) -> None:
        resolver = self._make_resolver()

        # A manifest path that is not listed in signed targets metadata
        # cannot be resolved, even if the caller asks for it directly.
        with self.assertRaises(ReleaseSetError):
            resolver.resolve("manifests/unsigned.json")

        # A manifest whose served bytes do not match the digest in signed
        # targets metadata is rejected as well.
        self.sim.target_files[MANIFEST_V1].data = b'{"release_set": "x"}'
        with self.assertRaises(ReleaseSetError):
            resolver.resolve(MANIFEST_V1)
        self.assertIsNone(resolver.active_plan)

    def test_mid_resolution_snapshot_change_aborts(self) -> None:
        fetcher = _MidResolutionPublisher(self.sim)
        resolver = self._make_resolver(fetcher)

        with self.assertRaises(ReleaseSetError):
            resolver.resolve(MANIFEST_V1)
        self.assertTrue(fetcher.fired)
        self.assertIsNone(resolver.active_plan)

    def test_expired_delegation_aborts(self) -> None:
        past = datetime.now(UTC) - timedelta(days=1)
        self.sim.md_delegates["pkgs"].signed.expires = past

        resolver = self._make_resolver()
        with self.assertRaises(ReleaseSetError):
            resolver.resolve(MANIFEST_V1)
        self.assertIsNone(resolver.active_plan)

    def test_failed_resolution_keeps_previous_active_plan(self) -> None:
        resolver = self._make_resolver()
        plan_v1 = resolver.resolve(MANIFEST_V1)
        first_paths = resolver.download_all()

        # Repository publishes an incompatible release-set: resolution
        # must fail without activating a half-valid plan.
        self._publish_incompatible_v2()
        with self.assertRaises(ReleaseSetError):
            resolver.resolve(MANIFEST_V2)
        self.assertIs(resolver.active_plan, plan_v1)

        # The old complete release-set is still readable, even if the
        # repository no longer serves its files.
        del self.sim.target_files["pkgs/app-1.0.tar.gz"]
        del self.sim.target_files["pkgs/lib-1.5.tar.gz"]
        paths = resolver.download_all()
        self.assertEqual(paths, first_paths)
        with open(paths["app"], "rb") as f:
            self.assertEqual(f.read(), APP_V1)
        with open(paths["lib"], "rb") as f:
            self.assertEqual(f.read(), LIB_V15)

    def test_manifest_validation(self) -> None:
        with self.assertRaises(ReleaseSetError):
            ReleaseManifest.from_bytes(b"not json")
        with self.assertRaises(ReleaseSetError):
            ReleaseManifest.from_bytes(b"{}")
        with self.assertRaises(ReleaseSetError):
            ReleaseManifest.from_bytes(
                _manifest_bytes("x", [_component("a", "p", b"d", "1.0")] * 2)
            )
        bad = _component("a", "p", b"d", "1.0")
        bad["sha256"] = "not-hex"
        with self.assertRaises(ReleaseSetError):
            ReleaseManifest.from_bytes(_manifest_bytes("x", [bad]))

        self.assertTrue(version_satisfies("2.0", ">=2.0,<3.0"))
        self.assertTrue(version_satisfies("2.0.0", "==2.0"))
        self.assertFalse(version_satisfies("1.5", ">=2.0"))
        self.assertFalse(version_satisfies("3.0", "!=3.0"))
        with self.assertRaises(ReleaseSetError):
            version_satisfies("1.0", "bogus")


if __name__ == "__main__":
    unittest.main()
