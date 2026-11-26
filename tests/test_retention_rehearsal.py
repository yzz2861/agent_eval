import tempfile
import unittest
from pathlib import Path

from tuf.api.metadata import Metadata, TargetFile, Targets
from tuf.retention import (
    InstallState,
    explain_three_half_install_states,
    plan_offline_retention,
    plan_retention,
    rehearse_directory,
)


def target_version(
    artifact: str,
    version: int,
    *,
    digest: str | None = None,
    size: int = 10,
    generation: int | None = None,
    **kwargs: object,
) -> dict[str, object]:
    digest = digest or f"{version:064x}"
    return {
        "id": f"{artifact}-v{version}",
        "artifact_id": artifact,
        "version": version,
        "generation": generation if generation is not None else 100 + version,
        "digest": digest,
        "size": size,
        **kwargs,
    }


class RetentionRehearsalTests(unittest.TestCase):
    def test_quota_and_trusted_reference_select_deletable_versions(
        self,
    ) -> None:
        items = [
            target_version("sensor", 1),
            target_version("sensor", 2),
            target_version("sensor", 3),
        ]
        trusted = {
            "targets": {
                "sensor-v1": {
                    "hashes": {"sha256": f"{1:064x}"},
                    "length": 10,
                }
            }
        }

        plan = plan_retention(items, quota=1, trusted_metadata=trusted)

        self.assertIn("sensor-v1", plan.blocked)
        self.assertIn(
            "trusted_metadata_reference", plan.reasons_for("sensor-v1")
        )
        self.assertIn("sensor-v3", plan.blocked)
        self.assertIn("retention_quota", plan.reasons_for("sensor-v3"))
        self.assertEqual(["sensor-v2"], plan.deletable)

    def test_observation_keeps_approved_rollback_and_generation(self) -> None:
        items = [
            target_version(
                "agent",
                4,
                health="observing",
                install_state=InstallState.HEALTH_OBSERVATION,
            ),
            target_version(
                "agent",
                3,
                health="approved",
                active=True,
                requires=["root-generation-103"],
            ),
            target_version("agent", 2),
            {
                "id": "root-generation-103",
                "kind": "approval_generation",
                "generation": 103,
                "size": 7,
            },
            {
                "id": "root-generation-102",
                "kind": "approval_generation",
                "generation": 102,
                "size": 7,
            },
        ]

        plan = plan_retention(items, quota=0)

        self.assertIn("agent-v4", plan.blocked)
        self.assertIn(
            "health_observation_rollback", plan.reasons_for("agent-v4")
        )
        self.assertIn("agent-v3", plan.blocked)
        self.assertIn(
            "approved_rollback_material", plan.reasons_for("agent-v3")
        )
        self.assertIn("root-generation-103", plan.blocked)
        self.assertIn(
            "approval_generation_dependency",
            plan.reasons_for("root-generation-103"),
        )
        self.assertIn("agent-v2", plan.deletable)
        self.assertIn("root-generation-102", plan.deletable)

    def test_duplicate_content_is_counted_once(self) -> None:
        digest = "a" * 64
        items = [
            {"id": "target-path-a", "digest": digest, "size": 128},
            {"id": "target-path-b", "digest": digest, "size": 128},
        ]

        plan = plan_retention(items)

        self.assertEqual(["target-path-a", "target-path-b"], plan.deletable)
        self.assertEqual(256, plan.logical_reclaimable_bytes)
        self.assertEqual(128, plan.reclaimable_bytes)

        decisions = sorted(plan.deletable_items, key=lambda item: item.id)
        self.assertEqual(128, decisions[0].reclaimable_bytes)
        self.assertEqual(0, decisions[1].reclaimable_bytes)

    def test_duplicate_blob_is_not_freeable_while_one_reference_is_retained(
        self,
    ) -> None:
        digest = "b" * 64
        items = [
            {
                "id": "approved-copy",
                "digest": digest,
                "size": 64,
                "trusted": True,
            },
            {"id": "cache-copy", "digest": digest, "size": 64},
        ]

        plan = plan_retention(items)

        self.assertEqual(["cache-copy"], plan.deletable)
        self.assertEqual(0, plan.reclaimable_bytes)
        self.assertTrue(plan.decisions["cache-copy"].shared_digest)
        self.assertIn(
            "shared_content_still_referenced",
            plan.reasons_for("cache-copy"),
        )

    def test_tuf_targetfile_metadata_creates_reference_pins(self) -> None:
        target_file = TargetFile(
            12,
            {"sha256": "c" * 64},
            "files/agent.bin",
        )
        metadata = Metadata(Targets(targets={"files/agent.bin": target_file}))
        items = [
            {
                "id": "agent-blob",
                "path": "files/agent.bin",
                "digest": {"sha256": "c" * 64},
                "size": 12,
            },
            {"id": "old-blob", "digest": "d" * 64, "size": 12},
        ]

        plan = plan_offline_retention(items, trusted_metadata=metadata)

        self.assertIn("agent-blob", plan.blocked)
        self.assertIn(
            "trusted_metadata_reference", plan.reasons_for("agent-blob")
        )
        self.assertEqual(["old-blob"], plan.deletable)

    def test_three_half_install_states_have_distinct_explanations(self) -> None:
        explanations = explain_three_half_install_states()

        self.assertEqual(
            {
                "metadata_staged",
                "target_staged",
                "health_observation",
            },
            set(explanations),
        )
        for explanation in explanations.values():
            self.assertTrue(explanation.categories)
            self.assertTrue(explanation.messages)

        metadata_categories = explanations["metadata_staged"].categories
        self.assertIn("pending_approval_generation", metadata_categories)

        target_categories = explanations["target_staged"].categories
        self.assertIn("verified_staged_target", target_categories)

        health_categories = explanations["health_observation"].categories
        self.assertIn("active_candidate", health_categories)
        self.assertIn("approved_rollback", health_categories)

    def test_state_explanations_classify_actual_occupancy(self) -> None:
        items = [
            {
                "id": "new-metadata",
                "kind": "metadata",
                "install_state": "metadata-downloaded",
                "size": 2,
            },
            {
                "id": "approved-blob",
                "health": "approved",
                "size": 20,
            },
            {
                "id": "verified-staged-target",
                "install_state": "download_complete",
                "complete": True,
                "verified": True,
                "size": 30,
            },
            {
                "id": "partial-download",
                "install_state": "downloading",
                "complete": False,
                "verified": False,
                "size": 5,
            },
            {
                "id": "observing-install",
                "install_state": "pending-health",
                "health": "observing",
                "size": 40,
            },
        ]

        plan = plan_retention(items)

        metadata_state = plan.explain_state(InstallState.METADATA_STAGED)
        target_state = plan.explain_state(InstallState.TARGET_STAGED)
        health_state = plan.explain_state(InstallState.HEALTH_OBSERVATION)

        self.assertIn("new-metadata", metadata_state.protected_items)
        self.assertIn("approved-blob", metadata_state.protected_items)

        self.assertIn("verified-staged-target", target_state.protected_items)
        self.assertIn("partial-download", target_state.reclaimable_items)
        self.assertIn("partial-download", plan.deletable)

        self.assertIn("observing-install", health_state.protected_items)
        self.assertIn("approved-blob", health_state.protected_items)

    def test_directory_rehearsal_is_offline_and_dry_run(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            root = Path(tmp)
            metadata_dir = root / "metadata"
            target_dir = root / "targets"
            metadata_dir.mkdir()
            target_dir.mkdir()
            (metadata_dir / "targets.json").write_text("{}", encoding="utf-8")
            blob = target_dir / "blob.bin"
            blob.write_bytes(b"offline")

            plan = rehearse_directory(
                root,
                metadata_dir=metadata_dir,
                target_dir=target_dir,
                quota=0,
            )

            self.assertTrue(plan.dry_run)
            self.assertIn("metadata:targets.json", plan.blocked)
            self.assertIn("target:blob.bin", plan.deletable)
            self.assertEqual(blob.stat().st_size, plan.reclaimable_bytes)
            self.assertTrue(blob.exists())


if __name__ == "__main__":
    unittest.main()
