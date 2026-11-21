"""Tests for scoped maintenance diff review and notifications."""

import json
import unittest
from collections.abc import Mapping

from tuf.api.metadata import TargetFile, Targets
from tuf.maintenance import (
    AbandonedNotificationError,
    BatchClosedError,
    BatchState,
    ChangeKind,
    ComponentIdentity,
    DeliveryChannel,
    DraftState,
    DuplicateNotificationError,
    EvidenceKind,
    NotificationGenerator,
    PolicyControl,
    ScopedDiffReview,
    ScopeNotVisibleError,
    ScopePolicy,
    SharedDigest,
    StaleReviewError,
)


def digest(char: str) -> str:
    return char * 64


def make_target(
    path: str, value: str, component: str | None = None, length: int = 10
) -> TargetFile:
    fields = None
    if component is not None:
        fields = {"custom": {"component_id": component}}
    return TargetFile(length, {"sha256": value}, path, fields)


def build_review(
    old: dict[str, TargetFile],
    new: dict[str, TargetFile],
    owners: dict[str, str],
    version: int = 1,
    rename_evidence: Mapping[str, str] | None = None,
) -> ScopedDiffReview:
    policy = ScopePolicy(version, owners)
    return ScopedDiffReview.build(
        old, new, policy, rename_evidence=rename_evidence
    )


class TestScopedReview(unittest.TestCase):
    def test_update_records_old_artifact_for_replacement(self) -> None:
        old = {"pump/fw": make_target("pump/fw", digest("a"), "pump-fw")}
        new = {"pump/fw": make_target("pump/fw", digest("b"), "pump-fw")}
        review = build_review(old, new, {"pump/fw": "pump"})

        view = review.for_scope("pump")
        self.assertEqual([c.kind for c in view.changes], [ChangeKind.UPDATED])
        self.assertEqual(view.old_artifacts[0].path, "pump/fw")
        self.assertEqual(
            view.old_artifacts[0].digest, f"sha256:{digest(chr(97))}"
        )

    def test_rename_requires_component_identity(self) -> None:
        old = {"pump/a": make_target("pump/a", digest("a"), "pump-fw")}
        new = {"pump/b": make_target("pump/b", digest("a"), "pump-fw")}
        review = build_review(old, new, {"pump/a": "pump", "pump/b": "pump"})

        change = review.for_scope("pump").changes[0]
        self.assertIs(change.kind, ChangeKind.RENAMED)
        self.assertEqual(change.old_path, "pump/a")
        self.assertEqual(change.path, "pump/b")
        self.assertIsInstance(change.evidence[0], ComponentIdentity)
        evidence = change.evidence[0]
        assert isinstance(evidence, ComponentIdentity)
        self.assertEqual(evidence.component_id, "pump-fw")
        self.assertEqual(evidence.source.value, "target-custom")

    def test_equal_digest_with_distinct_component_is_not_rename(self) -> None:
        old = {"pump/a": make_target("pump/a", digest("a"), "comp-a")}
        new = {"pump/b": make_target("pump/b", digest("a"), "comp-b")}
        review = build_review(old, new, {"pump/a": "pump", "pump/b": "pump"})

        changes = review.for_scope("pump").changes
        self.assertEqual(
            {change.kind for change in changes},
            {ChangeKind.REMOVED, ChangeKind.ADDED},
        )
        for change in changes:
            self.assertNotIn(
                EvidenceKind.COMPONENT_IDENTITY, change.evidence_kinds
            )

    def test_explicit_rename_evidence_is_marked(self) -> None:
        old = {"pump/a": make_target("pump/a", digest("a"))}
        new = {"pump/b": make_target("pump/b", digest("a"))}
        review = build_review(
            old,
            new,
            {"pump/a": "pump", "pump/b": "pump"},
            rename_evidence={"pump/a": "pump/b"},
        )

        change = review.for_scope("pump").changes[0]
        self.assertIs(change.kind, ChangeKind.RENAMED)
        evidence = change.evidence[0]
        assert isinstance(evidence, ComponentIdentity)
        self.assertEqual(evidence.source.value, "security-operations")

    def test_ambiguous_identity_is_not_rename_evidence(self) -> None:
        old = {"pump/a": make_target("pump/a", digest("a"), "pump-fw")}
        new = {
            "pump/b": make_target("pump/b", digest("a"), "pump-fw"),
            "pump/c": make_target("pump/c", digest("a"), "pump-fw"),
        }
        review = build_review(
            old,
            new,
            {
                "pump/a": "pump",
                "pump/b": "pump",
                "pump/c": "pump",
            },
        )

        kinds = [change.kind for change in review.for_scope("pump").changes]
        self.assertNotIn(ChangeKind.RENAMED, kinds)
        self.assertIn(ChangeKind.REMOVED, kinds)
        self.assertEqual(kinds.count(ChangeKind.ADDED), 2)

    def test_shared_digest_evidence_is_scoped(self) -> None:
        new = {
            "a/one": make_target("a/one", digest("a"), "comp-one"),
            "a/two": make_target("a/two", digest("a"), "comp-two"),
        }
        review = build_review({}, new, {"a/one": "A", "a/two": "A"})

        for change in review.for_scope("A").changes:
            self.assertIn(EvidenceKind.SHARED_DIGEST, change.evidence_kinds)
            self.assertNotIn(
                EvidenceKind.DELIVERY_CHANNEL, change.evidence_kinds
            )
            shared = next(
                item
                for item in change.evidence
                if isinstance(item, SharedDigest)
            )
            self.assertEqual(len(shared.peers), 1)
            self.assertNotEqual(shared.peers[0], change.path)

    def test_cross_scope_digest_sharing_is_not_disclosed(self) -> None:
        new = {
            "a/one": make_target("a/one", digest("a"), "comp-one"),
            "b/one": make_target("b/one", digest("a"), "comp-two"),
        }
        review = build_review({}, new, {"a/one": "A", "b/one": "B"})

        view_a = review.for_scope("A")
        for change in view_a.changes:
            self.assertNotIn(EvidenceKind.SHARED_DIGEST, change.evidence_kinds)
        self.assertNotIn("b/one", json.dumps(view_a.as_dict()))

    def test_two_channels_have_independent_evidence(self) -> None:
        new = {
            "a/channel-one": make_target(
                "a/channel-one", digest("a"), "pump-fw"
            ),
            "a/channel-two": make_target(
                "a/channel-two", digest("a"), "pump-fw"
            ),
        }
        review = build_review(
            {},
            new,
            {"a/channel-one": "A", "a/channel-two": "A"},
        )

        changes = review.for_scope("A").changes
        self.assertEqual(len(changes), 2)
        by_path = {change.path: change for change in changes}
        first = by_path["a/channel-one"]
        second = by_path["a/channel-two"]

        for change, other_path in (
            (first, "a/channel-two"),
            (second, "a/channel-one"),
        ):
            self.assertNotIn(EvidenceKind.SHARED_DIGEST, change.evidence_kinds)
            channel = next(
                item
                for item in change.evidence
                if isinstance(item, DeliveryChannel)
            )
            self.assertEqual(channel.path, change.path)
            serialized = json.dumps(change.as_dict())
            self.assertNotIn(other_path, serialized)

    def test_same_component_with_distinct_digest_is_not_channel(self) -> None:
        new = {
            "a/one": make_target("a/one", digest("a"), "pump-fw"),
            "a/two": make_target("a/two", digest("b"), "pump-fw"),
        }
        review = build_review({}, new, {"a/one": "A", "a/two": "A"})

        for change in review.for_scope("A").changes:
            self.assertNotIn(
                EvidenceKind.DELIVERY_CHANNEL, change.evidence_kinds
            )

    def test_rename_and_shared_digest_evidence_are_independent(self) -> None:
        old = {"pump/old": make_target("pump/old", digest("a"), "pump-fw")}
        new = {
            "pump/new": make_target("pump/new", digest("b"), "pump-fw"),
            "pump/other": make_target("pump/other", digest("b"), "pump-other"),
        }
        review = build_review(
            old,
            new,
            {
                "pump/old": "pump",
                "pump/new": "pump",
                "pump/other": "pump",
            },
        )
        changes = {c.path: c for c in review.for_scope("pump").changes}
        renamed = changes["pump/new"]
        self.assertIs(renamed.kind, ChangeKind.RENAMED)
        self.assertIn(EvidenceKind.COMPONENT_IDENTITY, renamed.evidence_kinds)
        self.assertIn(EvidenceKind.SHARED_DIGEST, renamed.evidence_kinds)

        identity = next(
            item
            for item in renamed.evidence
            if isinstance(item, ComponentIdentity)
        )
        shared = next(
            item for item in renamed.evidence if isinstance(item, SharedDigest)
        )
        self.assertNotIn("pump/other", json.dumps(identity.as_dict()))
        self.assertNotIn("pump/old", json.dumps(shared.as_dict()))
        self.assertNotIn(
            EvidenceKind.COMPONENT_IDENTITY,
            changes["pump/other"].evidence_kinds,
        )

    def test_cross_scope_channels_are_not_disclosed(self) -> None:
        new = {
            "a/channel": make_target(
                "a/channel", digest("a"), "shared-artifact"
            ),
            "b/channel": make_target(
                "b/channel", digest("a"), "shared-artifact"
            ),
        }
        review = build_review({}, new, {"a/channel": "A", "b/channel": "B"})

        for scope, foreign in (("A", "b/channel"), ("B", "a/channel")):
            view = review.for_scope(scope)
            for change in view.changes:
                self.assertNotIn(
                    EvidenceKind.DELIVERY_CHANNEL, change.evidence_kinds
                )
            self.assertNotIn(foreign, json.dumps(view.as_dict()))

    def test_totals_and_deletions_only_cover_visible_scope(self) -> None:
        old = {
            "pump/old": make_target("pump/old", digest("a"), "pump-old"),
            "valve/old": make_target("valve/old", digest("b"), "valve-old"),
        }
        review = build_review(
            old, {}, {"pump/old": "pump", "valve/old": "valve"}
        )

        pump = review.for_scope("pump")
        reviewer = review.reviewer_view

        self.assertEqual(pump.totals.removed, 1)
        self.assertEqual(pump.totals.total, 1)
        self.assertEqual(reviewer.totals.removed, 2)
        self.assertEqual(len(pump.deletion_notes), 1)
        self.assertIn("pump/old", pump.deletion_notes[0])
        self.assertNotIn("valve/old", " ".join(pump.deletion_notes))
        self.assertNotIn("valve/old", json.dumps(pump.as_dict()))
        self.assertNotIn("valve/old", pump.render_text())
        self.assertNotIn("valve/old", repr(pump))

    def test_other_scope_changes_do_not_change_local_view(self) -> None:
        owners = {"pump/fw": "pump", "valve/fw": "valve"}
        old = {
            "pump/fw": make_target("pump/fw", digest("a"), "pump"),
            "valve/fw": make_target("valve/fw", digest("b"), "valve"),
        }
        first = build_review(
            old,
            {
                "pump/fw": make_target("pump/fw", digest("c"), "pump"),
                "valve/fw": make_target("valve/fw", digest("d"), "valve"),
            },
            owners,
        )
        second = build_review(
            old,
            {
                "pump/fw": make_target("pump/fw", digest("c"), "pump"),
                "valve/fw": make_target("valve/fw", digest("e"), "valve"),
            },
            owners,
        )

        self.assertNotEqual(first.review_id, second.review_id)
        self.assertEqual(
            first.for_scope("pump").view_id,
            second.for_scope("pump").view_id,
        )
        self.assertEqual(
            first.for_scope("pump").as_dict(),
            second.for_scope("pump").as_dict(),
        )

    def test_scope_view_has_no_global_review_digest(self) -> None:
        old = {
            "pump/fw": make_target("pump/fw", digest("a"), "pump"),
            "valve/fw": make_target("valve/fw", digest("b"), "valve"),
        }
        new = {
            "pump/fw": make_target("pump/fw", digest("c"), "pump"),
            "valve/fw": make_target("valve/fw", digest("d"), "valve"),
        }
        review = build_review(
            old, new, {"pump/fw": "pump", "valve/fw": "valve"}
        )

        pump = review.for_scope("pump")
        self.assertNotEqual(pump.view_id, review.review_id)
        self.assertNotIn(review.review_id, json.dumps(pump.as_dict()))

    def test_cross_scope_move_is_split_without_peer_path(self) -> None:
        old = {"pump/fw": make_target("pump/fw", digest("a"), "shared")}
        new = {"valve/fw": make_target("valve/fw", digest("a"), "shared")}
        review = build_review(
            old, new, {"pump/fw": "pump", "valve/fw": "valve"}
        )

        pump = review.for_scope("pump")
        valve = review.for_scope("valve")
        self.assertEqual([c.kind for c in pump.changes], [ChangeKind.REMOVED])
        self.assertEqual([c.kind for c in valve.changes], [ChangeKind.ADDED])
        self.assertNotIn("valve/fw", json.dumps(pump.as_dict()))
        self.assertNotIn("pump/fw", json.dumps(valve.as_dict()))
        self.assertEqual(pump.changes[0].evidence, ())

    def test_unassigned_target_is_only_visible_to_reviewer(self) -> None:
        new = {
            "pump/fw": make_target("pump/fw", digest("a"), "pump"),
            "unassigned/fw": make_target(
                "unassigned/fw", digest("b"), "unknown"
            ),
        }
        review = build_review({}, new, {"pump/fw": "pump"})

        pump = review.for_scope("pump")
        self.assertEqual(len(pump.changes), 1)
        self.assertNotIn("unassigned/fw", json.dumps(pump.as_dict()))
        self.assertIn(
            "unassigned/fw",
            json.dumps(review.reviewer_view.as_dict()),
        )

    def test_unknown_scope_is_rejected(self) -> None:
        review = build_review(
            {},
            {"pump/fw": make_target("pump/fw", digest("a"), "pump")},
            {"pump/fw": "pump"},
        )
        with self.assertRaises(ScopeNotVisibleError):
            review.for_scope("typo")

    def test_targets_metadata_versions_are_captured(self) -> None:
        old = Targets(version=3, targets={"a": make_target("a", digest("a"))})
        new = Targets(version=4, targets={"a": make_target("a", digest("b"))})
        review = ScopedDiffReview.build(old, new, ScopePolicy(1, {"a": "A"}))
        self.assertEqual(review.previous_version, 3)
        self.assertEqual(review.updated_version, 4)

    def test_review_id_is_deterministic(self) -> None:
        args = (
            {"a": make_target("a", digest("a"))},
            {"a": make_target("a", digest("b"))},
            {"a": "A"},
        )
        first = build_review(*args)
        second = build_review(*args)
        self.assertEqual(first.review_id, second.review_id)
        self.assertEqual(
            first.review_id,
            ScopedDiffReview.build(
                args[0], args[1], ScopePolicy(1, args[2])
            ).review_id,
        )


class TestNotificationGeneration(unittest.TestCase):
    def setUp(self) -> None:
        self.owners = {"pump/fw": "pump", "valve/fw": "valve"}
        self.policy = ScopePolicy(1, self.owners)
        self.control = PolicyControl(self.policy)
        self.old = {
            "pump/fw": make_target("pump/fw", digest("a"), "pump-fw"),
            "valve/fw": make_target("valve/fw", digest("b"), "valve-fw"),
        }
        self.new = {
            "pump/fw": make_target("pump/fw", digest("c"), "pump-fw"),
            "valve/fw": make_target("valve/fw", digest("d"), "valve-fw"),
        }
        self.review = ScopedDiffReview.build(self.old, self.new, self.policy)
        self.generator = NotificationGenerator(self.control)

    def test_notifications_require_sealed_review(self) -> None:
        with self.assertRaises(TypeError):
            self.generator.open_batch(self.new)  # type: ignore[arg-type]

    def test_stale_review_is_rejected(self) -> None:
        self.control.replace(ScopePolicy(2, self.owners))
        with self.assertRaises(StaleReviewError):
            self.generator.open_batch(self.review)

    def test_same_version_with_different_owners_is_rejected(self) -> None:
        other = PolicyControl(
            ScopePolicy(1, {"pump/fw": "other", "valve/fw": "valve"})
        )
        with self.assertRaises(StaleReviewError):
            NotificationGenerator(other).open_batch(self.review)

    def test_notification_body_is_scoped(self) -> None:
        batch = self.generator.open_batch(self.review)
        draft = batch.generate("pump")

        self.assertIs(draft.state, DraftState.ACTIVE)
        text = draft.render()
        self.assertIn("pump/fw", text)
        self.assertNotIn("valve/fw", text)
        payload = json.dumps(draft.as_dict())
        self.assertNotIn("valve/fw", payload)
        self.assertEqual(
            [artifact.path for artifact in draft.body.old_artifacts],
            ["pump/fw"],
        )

    def test_policy_change_midway_abandons_everything(self) -> None:
        batch = self.generator.open_batch(self.review)
        draft = batch.generate("pump")
        self.assertEqual(batch.deliverable(), (draft,))

        self.control.replace(ScopePolicy(2, self.owners))

        self.assertIs(draft.state, DraftState.ABANDONED)
        self.assertIs(batch.state, BatchState.ABANDONED)
        self.assertEqual(batch.deliverable(), ())
        boundary = batch.abandonment
        assert boundary is not None
        self.assertEqual(boundary.policy_version, 1)
        self.assertEqual(boundary.draft_ids, (draft.draft_id,))
        with self.assertRaises(AbandonedNotificationError):
            draft.render()
        with self.assertRaises(AbandonedNotificationError):
            draft.as_dict()
        with self.assertRaises(BatchClosedError):
            batch.generate("valve")

    def test_policy_change_after_close_still_abandons_delivery(self) -> None:
        batch = self.generator.open_batch(self.review)
        draft = batch.generate("pump")
        batch.close()
        self.assertIs(batch.state, BatchState.CLOSED)
        self.assertEqual(batch.deliverable(), (draft,))

        self.control.replace(ScopePolicy(2, self.owners))

        self.assertIs(draft.state, DraftState.ABANDONED)
        self.assertEqual(batch.deliverable(), ())
        with self.assertRaises(AbandonedNotificationError):
            batch.deliver()

    def test_delivery_renders_and_closes_batch(self) -> None:
        batch = self.generator.open_batch(self.review)
        batch.generate("pump")
        batch.close()

        rendered = batch.deliver()
        self.assertEqual(len(rendered), 1)
        self.assertIn("pump/fw", rendered[0])
        self.assertNotIn("valve/fw", rendered[0])
        self.assertIs(batch.state, BatchState.DELIVERED)
        self.assertEqual(batch.deliverable(), ())
        with self.assertRaises(BatchClosedError):
            batch.deliver()

    def test_delivery_requires_closed_batch(self) -> None:
        batch = self.generator.open_batch(self.review)
        batch.generate("pump")
        with self.assertRaises(BatchClosedError):
            batch.deliver()

    def test_duplicate_scope_is_rejected(self) -> None:
        batch = self.generator.open_batch(self.review)
        batch.generate("pump")
        with self.assertRaises(DuplicateNotificationError):
            batch.generate("pump")

    def test_draft_ids_are_unique_across_batches(self) -> None:
        first = self.generator.open_batch(self.review)
        first_draft = first.generate("pump")
        first.close()
        first.deliver()

        second = self.generator.open_batch(self.review)
        second_draft = second.generate("pump")
        self.assertNotEqual(first_draft.draft_id, second_draft.draft_id)

    def test_policy_change_before_first_draft_closes_batch(self) -> None:
        batch = self.generator.open_batch(self.review)
        self.control.replace(ScopePolicy(2, self.owners))

        self.assertIs(batch.state, BatchState.ABANDONED)
        boundary = batch.abandonment
        assert boundary is not None
        self.assertEqual(boundary.draft_ids, ())
        with self.assertRaises(BatchClosedError):
            batch.generate("pump")

    def test_unchanged_targets_produce_empty_review(self) -> None:
        review = ScopedDiffReview.build(self.old, self.old, self.policy)
        self.assertEqual(review.changes, ())
        batch = self.generator.open_batch(review)
        draft = batch.generate("pump")
        self.assertEqual(draft.body.totals.total, 0)
        self.assertEqual(
            draft.body.render_text(),
            "maintenance scope: pump\n"
            "totals: added=0 updated=0 removed=0 renamed=0",
        )


if __name__ == "__main__":
    unittest.main()
