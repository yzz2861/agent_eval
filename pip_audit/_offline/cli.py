"""
Command-line entrypoint for pip-audit's offline dual-time review.

This command operates exclusively on local snapshot files and never reaches
the network. It supports four workflows:

* ``snapshot``  -- create an append-only snapshot from advisory/deployment JSON;
* ``review``    -- recompute a historical cross-section in either view;
* ``trace``     -- attribute a report's changing counts to specific snapshots;
* ``list``      -- enumerate the snapshots in a review directory.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn

from pip_audit._offline.model import (
    AdvisoryRecord,
    DeploymentRecord,
    DispositionRecord,
    ReviewView,
    Snapshot,
    parse_rfc3339,
    utcnow,
)
from pip_audit._offline.postmortem import trace_snapshots
from pip_audit._offline.rules import (
    DEFAULT_RULE_VERSION,
    OfflineReviewEngine,
    ReviewFinding,
    default_disposition,
    parse_affected_range,
)
from pip_audit._offline.store import SnapshotStore, SnapshotStoreError


def _fatal(message: str) -> NoReturn:
    """Print an error message and terminate the process."""
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def _parse_cutoff(value: str) -> datetime:
    """Argparse type for RFC 3339 cutoff timestamps."""
    try:
        return parse_rfc3339(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid cutoff timestamp {value!r}, expected RFC 3339 (e.g. 2026-11-20T00:00:00Z)"
        ) from exc


def _load_input(path: Path) -> dict[str, Any]:
    """Load a JSON snapshot-description document from disk."""
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        _fatal(f"failed to read input {path}: {exc}")


def _build_snapshot(payload: dict[str, Any], *, snapshot_id: str | None) -> Snapshot:
    """Construct a snapshot, generating rule-based dispositions when absent."""
    advisories = [AdvisoryRecord.from_dict(item) for item in payload.get("advisories", [])]
    deployments = [DeploymentRecord.from_dict(item) for item in payload.get("deployments", [])]
    dispositions = [DispositionRecord.from_dict(item) for item in payload.get("dispositions", [])]

    rule_version = payload.get("rule_version", DEFAULT_RULE_VERSION)

    # When no dispositions are supplied, reproduce the rule-based handling that
    # would have been produced at the time, so "as produced under the then
    # rules" decisions travel with the snapshot.
    if not dispositions:
        deployments_by_key = {deployment.key: deployment for deployment in deployments}
        for advisory in advisories:
            deployment = deployments_by_key.get(advisory.package_key)
            if deployment is None or not deployment.deployed or deployment.version is None:
                continue
            if deployment.version not in parse_affected_range(advisory.affected_range):
                continue
            dispositions.append(
                default_disposition(
                    advisory,
                    deployment,
                    rule_version=rule_version,
                    decided_at=advisory.received_at,
                )
            )

    return Snapshot(
        id=snapshot_id or payload.get("id") or f"snapshot-{utcnow().strftime('%Y%m%dT%H%M%S')}",
        created_at=(
            parse_rfc3339(payload["created_at"]) if payload.get("created_at") else utcnow()
        ),
        rule_version=rule_version,
        advisories=advisories,
        deployments=deployments,
        dispositions=dispositions,
        description=payload.get("description", ""),
    )


def _finding_to_dict(finding: ReviewFinding) -> dict[str, Any]:
    """Serialize a review finding for JSON output."""
    data: dict[str, Any] = {
        "package": finding.package,
        "version": str(finding.version) if finding.version is not None else None,
        "advisory_id": finding.advisory_id,
        "visible": finding.visible,
        "placeholder": finding.placeholder,
        "late_received": finding.late_received,
        "corrected_after_cutoff": finding.corrected_after_cutoff,
        "effective_at": finding.effective_at.isoformat(),
        "received_at": finding.received_at.isoformat(),
        "fix_versions": [str(version) for version in finding.fix_versions],
        "reasons": sorted(finding.reasons),
    }
    if finding.disposition is not None:
        data["disposition"] = finding.disposition.to_dict()
    return data


def _cmd_snapshot(args: argparse.Namespace) -> int:
    """Handle the ``snapshot`` subcommand."""
    payload = _load_input(args.input)
    snapshot = _build_snapshot(payload, snapshot_id=args.id)
    store = SnapshotStore(args.review_dir)
    try:
        path = store.save(snapshot)
    except SnapshotStoreError as exc:
        _fatal(str(exc))
    print(json.dumps({"saved": str(path), "snapshot_id": snapshot.id}, indent=2))
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    """Handle the ``list`` subcommand."""
    store = SnapshotStore(args.review_dir)
    try:
        snapshots = store.list_snapshots()
    except SnapshotStoreError as exc:
        _fatal(str(exc))
    output = [
        {
            "id": snapshot.id,
            "created_at": snapshot.created_at.isoformat(),
            "rule_version": snapshot.rule_version,
            "advisories": len(snapshot.advisories),
            "deployments": len(snapshot.deployments),
            "dispositions": len(snapshot.dispositions),
            "description": snapshot.description,
        }
        for snapshot in snapshots
    ]
    print(json.dumps(output, indent=2))
    return 0


def _resolve_snapshot(store: SnapshotStore, args: argparse.Namespace) -> Snapshot:
    """Load the requested snapshot, or the newest one when no ID is given."""
    try:
        if args.snapshot_id is not None:
            return store.load(args.snapshot_id)
        latest = store.latest()
    except SnapshotStoreError as exc:
        _fatal(str(exc))
    if latest is None:
        _fatal(f"no snapshots found in {store.directory}")
    return latest


def _cmd_review(args: argparse.Namespace) -> int:
    """Handle the ``review`` subcommand."""
    store = SnapshotStore(args.review_dir)
    snapshot = _resolve_snapshot(store, args)
    report = OfflineReviewEngine(snapshot).review(args.cutoff, args.view)
    output = {
        "summary": report.summary(),
        "findings": [_finding_to_dict(finding) for finding in report.findings],
        "skipped_placeholders": [
            deployment.to_dict() for deployment in report.skipped_placeholders
        ],
    }
    print(json.dumps(output, indent=2))
    return 0


def _cmd_trace(args: argparse.Namespace) -> int:
    """Handle the ``trace`` subcommand."""
    store = SnapshotStore(args.review_dir)
    snapshots = store.list_snapshots()
    if not snapshots:
        _fatal(f"no snapshots found in {store.directory}")
    result = trace_snapshots(snapshots, args.cutoff, args.view)
    output = {
        "cutoff": args.cutoff.isoformat(),
        "view": args.view.value,
        "summaries": [report.summary() for report in result.reports],
        "changes": [
            {
                "previous_snapshot_id": change.previous_snapshot_id,
                "snapshot_id": change.snapshot_id,
                "before_count": change.before_count,
                "after_count": change.after_count,
                "added": [list(item) for item in change.added],
                "removed": [list(item) for item in change.removed],
                "late_attributed": [list(item) for item in change.late_attributed],
                "corrected_attributed": [list(item) for item in change.corrected_attributed],
                "changed": change.changed,
            }
            for change in result.changes
        ],
        "explanation": result.explain(),
    }
    first = result.first_change()
    if first is not None:
        output["first_snapshot_changing_report"] = first.snapshot_id
    print(json.dumps(output, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct the offline-review argument parser."""
    parser = argparse.ArgumentParser(
        prog="pip-audit-review",
        description="offline dual-time review of historical pip-audit snapshots",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--review-dir",
        type=Path,
        default=Path(".pip-audit-review"),
        help="directory holding append-only snapshot files",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshot_parser = subparsers.add_parser(
        "snapshot", help="create a snapshot from advisory/deployment JSON"
    )
    snapshot_parser.add_argument("input", type=Path, help="JSON file describing the snapshot")
    snapshot_parser.add_argument("--id", dest="id", help="explicit snapshot ID")
    snapshot_parser.set_defaults(func=_cmd_snapshot)

    list_parser = subparsers.add_parser("list", help="list stored snapshots")
    list_parser.set_defaults(func=_cmd_list)

    review_parser = subparsers.add_parser(
        "review", help="recompute a historical cross-section in one view"
    )
    review_parser.add_argument(
        "--cutoff", type=_parse_cutoff, required=True, help="historical cutoff (RFC 3339)"
    )
    review_parser.add_argument(
        "--view",
        type=ReviewView,
        choices=list(ReviewView),
        default=ReviewView.AsOfKnown,
        help="historical perspective to reproduce",
    )
    review_parser.add_argument("--snapshot-id", help="snapshot to use (defaults to the newest)")
    review_parser.set_defaults(func=_cmd_review)

    trace_parser = subparsers.add_parser(
        "trace", help="attribute report changes to the snapshots that caused them"
    )
    trace_parser.add_argument(
        "--cutoff", type=_parse_cutoff, required=True, help="historical cutoff (RFC 3339)"
    )
    trace_parser.add_argument(
        "--view",
        type=ReviewView,
        choices=list(ReviewView),
        default=ReviewView.AsOfKnown,
        help="historical perspective to reproduce",
    )
    trace_parser.set_defaults(func=_cmd_trace)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the offline-review CLI, returning a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
