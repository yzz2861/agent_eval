"""
Inventory snapshot storage and update-diff explanation.

The store is fully offline: snapshots are JSON files on disk.  When a new
inventory snapshot replaces an old one, the store re-runs the review and
explains which proofs disappeared, appeared or changed, including the
exact evidence item that no longer holds.
"""

import json
import os
from collections import OrderedDict

from .model import (
    Asset,
    AdvisoryEntry,
    Relation,
)
from .review import OfflineReview


class InventoryStore(object):
    """
    Persistent, file-backed inventory of assets and advisories.

    Snapshots are written as JSON so a review run can be repeated without
    any network access and compared against the previous inventory update.
    """

    def __init__(self, path):
        self.path = path

    # ------------------------------------------------------------------
    # Snapshot (de)serialization
    # ------------------------------------------------------------------

    def save_snapshot(self, assets, advisories):
        payload = OrderedDict((
            ("assets", [asset.to_dict() for asset in assets]),
            ("advisories", [entry.to_dict() for entry in advisories]),
        ))
        directory = os.path.dirname(self.path)
        if directory and not os.path.isdir(directory):
            os.makedirs(directory)
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)

    def load_snapshot(self):
        with open(self.path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        assets = [Asset.from_dict(item) for item in payload.get("assets", [])]
        advisories = [AdvisoryEntry.from_dict(item)
                      for item in payload.get("advisories", [])]
        return assets, advisories

    # ------------------------------------------------------------------
    # Review helpers
    # ------------------------------------------------------------------

    def review(self, assets=None, advisories=None):
        if assets is None or advisories is None:
            assets, advisories = self.load_snapshot()
        return OfflineReview(assets, advisories).run()

    # ------------------------------------------------------------------
    # Snapshot comparison
    # ------------------------------------------------------------------

    @staticmethod
    def _relation_index(result):
        """
        Index the relations of a review result.

        The key is ``(asset-independent) relation identity`` built from the
        relation kind, its subject and object CPEs and the containment
        chain, so the same proof in two snapshots compares equal even if
        unrelated ordering changes.
        """
        index = OrderedDict()
        for relation in result.relations:
            key = (
                relation.asset_id,
                relation.kind,
                relation.subject_cpe,
                relation.object_cpe,
                tuple(relation.chain),
            )
            index[key] = relation
        return index

    def diff_reviews(self, old_result, new_result):
        """
        Explain the proof-level difference between two review runs.

        Each change entry names the relation kind, the CPEs involved and,
        for removed proofs, the evidence that disappeared with the
        inventory update.
        """
        old_index = self._relation_index(old_result)
        new_index = self._relation_index(new_result)

        changes = []
        for key, relation in old_index.items():
            if key not in new_index:
                changes.append(OrderedDict((
                    ("change", "proof_removed"),
                    ("kind", relation.kind),
                    ("subject_cpe", relation.subject_cpe),
                    ("object_cpe", relation.object_cpe),
                    ("chain", list(relation.chain)),
                    ("lost_evidence",
                     [item.to_dict() for item in relation.evidence]),
                    ("explanation",
                     self._explain_removal(relation, new_index)),
                )))

        for key, relation in new_index.items():
            if key not in old_index:
                changes.append(OrderedDict((
                    ("change", "proof_added"),
                    ("kind", relation.kind),
                    ("subject_cpe", relation.subject_cpe),
                    ("object_cpe", relation.object_cpe),
                    ("chain", list(relation.chain)),
                    ("evidence",
                     [item.to_dict() for item in relation.evidence]),
                )))

        disposition_changes = self._diff_dispositions(old_result, new_result)
        return OrderedDict((
            ("proof_changes", changes),
            ("disposition_changes", disposition_changes),
        ))

    @staticmethod
    def _explain_removal(relation, new_index):
        """Human-readable explanation of why a proof no longer holds."""
        if relation.kind == "contained":
            return (
                "containment chain {0} is no longer fully backed by "
                "inventory parent links; the containing product can no "
                "longer be proven to include {1}".format(
                    " -> ".join(relation.chain),
                    relation.object_cpe))
        if relation.kind == "same":
            return (
                "the queryable record {0} matching advisory {1} was "
                "removed or changed; identity folding for it is no "
                "longer supported".format(
                    relation.object_cpe,
                    relation.subject_cpe))
        return (
            "supplier declaration for {0} backing advisory {1} is no "
            "longer present in the inventory".format(
                relation.object_cpe,
                relation.subject_cpe))

    @staticmethod
    def _diff_dispositions(old_result, new_result):
        changes = []
        asset_ids = set(old_result.dispositions)
        asset_ids.update(new_result.dispositions)
        for asset_id in sorted(asset_ids):
            old_item = old_result.dispositions.get(asset_id)
            new_item = new_result.dispositions.get(asset_id)
            old_level = old_item.disposition if old_item else None
            new_level = new_item.disposition if new_item else None
            if old_level != new_level:
                changes.append(OrderedDict((
                    ("asset_id", asset_id),
                    ("old_disposition", old_level),
                    ("new_disposition", new_level),
                    ("new_reason",
                     new_item.reason if new_item else
                     "asset removed from inventory"),
                )))
        return changes

    def update_and_diff(self, new_assets, new_advisories):
        """
        Replace the snapshot and return the review plus the proof diff.

        The old review is computed from the snapshot currently on disk;
        after the comparison the new snapshot replaces it, so repeated
        updates always compare against the immediately previous state.
        """
        old_assets, old_advisories = self.load_snapshot()
        old_result = OfflineReview(old_assets, old_advisories).run()
        new_result = OfflineReview(new_assets, new_advisories).run()
        diff = self.diff_reviews(old_result, new_result)
        self.save_snapshot(new_assets, new_advisories)
        return new_result, diff

    @staticmethod
    def render_diff(diff):
        """Render a proof diff as readable plain text for operators."""
        lines = []
        for change in diff["proof_changes"]:
            if change["change"] == "proof_removed":
                lines.append(
                    "- removed {0} proof: {1} -> {2}".format(
                        change["kind"],
                        change["subject_cpe"],
                        change["object_cpe"]))
                lines.append("    reason: {0}".format(
                    change["explanation"]))
            else:
                lines.append(
                    "+ added {0} proof: {1} -> {2}".format(
                        change["kind"],
                        change["subject_cpe"],
                        change["object_cpe"]))
        for change in diff["disposition_changes"]:
            lines.append(
                "~ asset {0}: {1} -> {2}".format(
                    change["asset_id"],
                    change["old_disposition"],
                    change["new_disposition"]))
        return "\n".join(lines) if lines else "no proof changes"
