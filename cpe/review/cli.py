"""
Command line entry point for the offline CPE review layer.

The entry point is fully offline: it only reads the bundled fictional
fixtures and an optional JSON snapshot written under a local directory.
Run it with::

    python -m cpe.review.cli --snapshot-dir ./review-state

It prints the evidence collected for the three relation kinds, the
remediation disposition of every device, the identity folds allowed by
``same`` relations, and (on ``--update``) the proofs that disappeared
with the refreshed inventory.
"""

import argparse
import json
import os
from collections import OrderedDict

from .fixtures.devices import (
    build_assets,
    build_advisories,
    build_updated_assets,
)
from .inventory import InventoryStore
from .model import RELATION_KINDS
from .review import OfflineReview

def _print_header(title):
    print("")
    print("=" * len(title))
    print(title)
    print("=" * len(title))


def _print_relations(result):
    for kind in RELATION_KINDS:
        relations = result.relations_of(kind)
        _print_header("Relation: {0} ({1})".format(kind, len(relations)))
        for relation in relations:
            print("- [{0}] {1}".format(
                relation.asset_id, relation.subject_cpe))
            print("    -> {0}".format(relation.object_cpe))
            if relation.chain:
                print("    chain: {0}".format(" -> ".join(relation.chain)))
            for evidence in relation.evidence:
                print("    evidence: {0} (supports={1})".format(
                    evidence.source, evidence.supports))


def _print_dispositions(result):
    _print_header("Remediation disposition")
    for asset_id, item in result.dispositions.items():
        print("- {0}: {1}".format(asset_id, item.disposition))
        print("    reason: {0}".format(item.reason))
        if item.matched_cpe:
            print("    matched: {0}".format(", ".join(item.matched_cpe)))
        for rejection in item.rejections:
            print("    rejected: {0} [{1}]".format(
                rejection.detail.get("enclosure_cpe"),
                rejection.detail.get("type")))


def _print_folds(review, result):
    folds = review.fold_identities(result)
    _print_header("Identity folds (same relations only)")
    for key, names in folds.items():
        print("- folded {0} names:".format(len(names)))
        for name in names:
            print("    * {0}".format(name))

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Offline CPE evidence review self-test.")
    parser.add_argument(
        "--snapshot-dir", default=os.path.join(".", "review-state"),
        help="directory for the offline inventory JSON snapshot")
    parser.add_argument(
        "--update", action="store_true",
        help="apply the refreshed inventory and explain lost proofs")
    args = parser.parse_args(argv)

    snapshot_path = os.path.join(args.snapshot_dir, "inventory.json")
    store = InventoryStore(snapshot_path)
    assets = build_assets()
    advisories = build_advisories()

    if not os.path.exists(snapshot_path):
        store.save_snapshot(assets, advisories)

    review = OfflineReview(assets, advisories)
    result = review.run()
    _print_relations(result)
    _print_folds(review, result)
    _print_dispositions(result)

    if args.update:
        updated_assets = build_updated_assets()
        _, diff = store.update_and_diff(updated_assets, advisories)
        _print_header("Inventory update: proof changes")
        print(store.render_diff(diff))
        print("")
        print(json.dumps(diff, indent=2, ensure_ascii=False))
    else:
        store.save_snapshot(assets, advisories)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
