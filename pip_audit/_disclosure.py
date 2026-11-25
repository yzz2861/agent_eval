"""
Offline disclosure review for distributing `pip-audit` results.

This module merges local audit results that were collected per deployment
scope (environment, build line, ...) and produces one redacted report per
external recipient, plus an internal report that retains everything.

Guarantees:

* A recipient only sees dependency records whose scopes intersect the
  scopes they are authorized for. Records shared between multiple
  environments are only counted for a recipient when at least one of
  their authorized scopes covers the record.
* Only a fixed whitelist of fields is disclosed; any other field present
  in the local audit results (private versions annotations, descriptions,
  etc.) never leaves the internal report.
* Each outgoing report carries an omission note (count + digest) that the
  internal reviewer can recompute from the merged data to verify exactly
  which records were withheld, without revealing them.
* Records that no recipient can claim are kept separately in the
  internal-only report.

The entry point is intentionally offline: it consumes `pip-audit --format
json` output files and never talks to a vulnerability service.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name

logger = logging.getLogger(__name__)

# The fixed set of fields that may ever be disclosed to an external
# recipient. Dotted paths address fields nested inside each vulnerability
# object. Anything not listed here is internal-only.
MAX_DISCLOSURE_FIELDS: tuple[str, ...] = (
    "name",
    "version",
    "skip_reason",
    "vulns.id",
    "vulns.fix_versions",
    "vulns.aliases",
    "vulns.description",
)

# The fields disclosed when the configuration does not narrow the set.
DEFAULT_DISCLOSURE_FIELDS: tuple[str, ...] = (
    "name",
    "version",
    "vulns.id",
    "vulns.fix_versions",
)

# Fields kept on fix entries in outgoing reports. Fix entries never carry
# sensitive annotations, so they are filtered by record, not by field.
_FIX_FIELDS: tuple[str, ...] = ("name", "old_version", "new_version", "skip_reason")


class DisclosureError(Exception):
    """Raised when disclosure inputs are malformed or inconsistent."""


@dataclass
class _Record:
    """A merged dependency record and the scopes it was observed in."""

    key: str
    data: dict[str, Any]
    scopes: set[str] = field(default_factory=set)


def _record_key(dep: dict[str, Any]) -> str:
    """Return the identity key for a dependency object."""
    name = canonicalize_name(str(dep.get("name", "")))
    version = dep.get("version")
    return f"{name}=={version}" if version is not None else name


def _digest_keys(keys: list[str] | set[str]) -> str:
    """Return a verifiable digest over a set of record keys."""
    payload = "\n".join(sorted(keys))
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_scoped_audit(
    scope: str,
    path: Path,
    records: dict[str, _Record],
    fixes: list[dict[str, Any]],
) -> None:
    """
    Merge one local audit result file into `records` under `scope`.

    The file must be `pip-audit --format json` output. Dependencies with
    the same name and version observed in several scopes are merged into a
    single record; same-name packages at different versions (e.g. separate
    build lines) stay distinct.
    """
    try:
        audit = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise DisclosureError(f"cannot load audit result {path}: {e}") from e
    if not isinstance(audit, dict) or not isinstance(audit.get("dependencies"), list):
        raise DisclosureError(f"{path} is not a pip-audit JSON audit result")

    for dep in audit["dependencies"]:
        if not isinstance(dep, dict) or "name" not in dep:
            raise DisclosureError(f"{path} contains a malformed dependency entry: {dep!r}")
        key = _record_key(dep)
        record = records.get(key)
        if record is None:
            record = records[key] = _Record(key=key, data=dep)
        record.scopes.add(scope)

    fixes.extend(audit.get("fixes", []))


def load_recipient_config(path: Path) -> tuple[dict[str, set[str]], tuple[str, ...]]:
    """
    Load the recipient configuration from `path`.

    Returns a mapping of recipient name to their authorized deployment
    scopes, plus the (possibly narrowed) disclosure field whitelist.
    """
    try:
        config = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise DisclosureError(f"cannot load recipient config {path}: {e}") from e

    raw_recipients = config.get("recipients")
    if not isinstance(raw_recipients, dict) or not raw_recipients:
        raise DisclosureError(f'{path} must define a non-empty "recipients" object')

    recipients: dict[str, set[str]] = {}
    for name, entry in raw_recipients.items():
        scopes = entry.get("scopes") if isinstance(entry, dict) else None
        if (
            not isinstance(scopes, list)
            or not scopes
            or not all(isinstance(s, str) for s in scopes)
        ):
            raise DisclosureError(f'recipient {name!r} must define a non-empty "scopes" list')
        recipients[name] = set(scopes)

    fields = tuple(config.get("disclosure_fields", DEFAULT_DISCLOSURE_FIELDS))
    unknown = [f for f in fields if f not in MAX_DISCLOSURE_FIELDS]
    if unknown:
        raise DisclosureError(
            f"disclosure fields {unknown!r} are outside the fixed whitelist "
            f"{list(MAX_DISCLOSURE_FIELDS)!r}"
        )
    return recipients, fields


def _filter_dependency(dep: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    """Project a dependency object onto the disclosed field whitelist."""
    out: dict[str, Any] = {}
    for top in ("name", "version", "skip_reason"):
        if top in fields and top in dep:
            out[top] = dep[top]
    vuln_fields = {f.split(".", 1)[1] for f in fields if f.startswith("vulns.")}
    if vuln_fields and isinstance(dep.get("vulns"), list):
        out["vulns"] = [
            {k: v for k, v in vuln.items() if k in vuln_fields}
            for vuln in dep["vulns"]
            if isinstance(vuln, dict)
        ]
    return out


def _fix_key(fix_entry: dict[str, Any]) -> str:
    """Return the record key a fix entry refers to."""
    name = canonicalize_name(str(fix_entry.get("name", "")))
    version = fix_entry.get("old_version", fix_entry.get("version"))
    return f"{name}=={version}" if version is not None else name


@dataclass
class DisclosurePlan:
    """The merged audit data plus recipient configuration."""

    records: dict[str, _Record]
    fixes: list[dict[str, Any]]
    recipients: dict[str, set[str]]
    fields: tuple[str, ...]

    def recipient_report(self, name: str) -> dict[str, Any]:
        """
        Render the outgoing report for one recipient.

        Only records within the recipient's authorized scopes are included,
        and each record's scope labels are reduced to that authorized
        subset so other deployment lines are never revealed. Withheld
        records are summarized as a verifiable omission note.
        """
        if name not in self.recipients:
            raise DisclosureError(f"unknown recipient: {name}")
        allowed = self.recipients[name]

        included: list[dict[str, Any]] = []
        included_keys: set[str] = set()
        omitted_keys: set[str] = set()
        for key, record in sorted(self.records.items()):
            visible_scopes = sorted(record.scopes & allowed)
            if not visible_scopes:
                omitted_keys.add(key)
                continue
            dep = _filter_dependency(record.data, self.fields)
            dep["scopes"] = visible_scopes
            included.append(dep)
            included_keys.add(key)

        fixes = [
            {k: v for k, v in fix_entry.items() if k in _FIX_FIELDS}
            for fix_entry in self.fixes
            if _fix_key(fix_entry) in included_keys
        ]

        return {
            "recipient": name,
            "scopes": sorted(allowed),
            "disclosure_fields": list(self.fields),
            "dependencies": included,
            "fixes": fixes,
            "omissions": {
                "count": len(omitted_keys),
                "digest": _digest_keys(omitted_keys),
            },
        }

    def internal_report(self) -> dict[str, Any]:
        """
        Render the internal-only report.

        Retains every record with its full scope set, lists the records no
        recipient could claim, and reproduces each recipient's inclusion
        and omission digests so the merged conclusions can be recomputed
        and checked against the outgoing reports.
        """
        all_scopes = set().union(*self.recipients.values())
        unclaimed = sorted(
            key for key, record in self.records.items() if not record.scopes & all_scopes
        )

        per_recipient: dict[str, Any] = {}
        for name, allowed in sorted(self.recipients.items()):
            included_keys = {key for key, record in self.records.items() if record.scopes & allowed}
            omitted_keys = set(self.records) - included_keys
            per_recipient[name] = {
                "scopes": sorted(allowed),
                "included": {"count": len(included_keys), "digest": _digest_keys(included_keys)},
                "omitted": {
                    "count": len(omitted_keys),
                    "digest": _digest_keys(omitted_keys),
                    "keys": sorted(omitted_keys),
                },
            }

        return {
            "dependencies": [
                {**record.data, "scopes": sorted(record.scopes)}
                for _, record in sorted(self.records.items())
            ],
            "fixes": self.fixes,
            "unclaimed": unclaimed,
            "recipients": per_recipient,
        }


def build_plan(scoped_audits: list[tuple[str, Path]], config_path: Path) -> DisclosurePlan:
    """Build a `DisclosurePlan` from scoped audit files and a recipient config."""
    records: dict[str, _Record] = {}
    fixes: list[dict[str, Any]] = []
    for scope, path in scoped_audits:
        load_scoped_audit(scope, path, records, fixes)

    recipients, fields = load_recipient_config(config_path)
    return DisclosurePlan(records=records, fixes=fixes, recipients=recipients, fields=fields)


def _parse_scope(value: str) -> tuple[str, Path]:
    """Parse a `SCOPE=PATH` command-line argument."""
    scope, sep, raw_path = value.partition("=")
    if not sep or not scope:
        raise argparse.ArgumentTypeError(f"expected SCOPE=PATH, got {value!r}")
    return scope, Path(raw_path)


def main(argv: list[str] | None = None) -> None:
    """
    Entry point for the offline disclosure review tool.

    Merges the given scoped audit results and writes one redacted report
    per recipient plus an internal-only report into the output directory.
    """
    parser = argparse.ArgumentParser(
        prog="pip-audit-disclose",
        description="Offline review and distribution of local pip-audit results",
    )
    parser.add_argument(
        "--scope",
        metavar="SCOPE=PATH",
        type=_parse_scope,
        action="append",
        required=True,
        help="a local pip-audit JSON result tagged with its deployment scope (repeatable)",
    )
    parser.add_argument(
        "--recipients",
        metavar="PATH",
        type=Path,
        required=True,
        help="JSON config mapping recipients to authorized scopes and "
        "optionally narrowing the fixed disclosure fields",
    )
    parser.add_argument(
        "--out-dir",
        metavar="DIR",
        type=Path,
        required=True,
        help="directory for the per-recipient reports and the internal report",
    )
    args = parser.parse_args(argv)

    try:
        plan = build_plan(args.scope, args.recipients)
    except DisclosureError as e:
        print(f"error: {e}", file=sys.stderr)
        raise SystemExit(2) from e

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for name in sorted(plan.recipients):
        report = plan.recipient_report(name)
        out_path = args.out_dir / f"{name}.json"
        out_path.write_text(json.dumps(report, indent=2) + "\n")
        omissions = report["omissions"]
        print(
            f"{out_path}: {len(report['dependencies'])} dependencies disclosed, "
            f"{omissions['count']} withheld ({omissions['digest']})"
        )

    internal_path = args.out_dir / "internal.json"
    internal_path.write_text(json.dumps(plan.internal_report(), indent=2) + "\n")
    print(f"{internal_path}: internal-only report (do not distribute)")


if __name__ == "__main__":  # pragma: no cover
    main()
