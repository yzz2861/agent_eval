"""Waiver backend for Bandit scans of vendored code.

Decides, per scanned file, whether a security-team exemption still applies,
based on supply provenance (upstream source/version), the approved content
digest, and the file's location in the tree. Legacy project-wide waivers
(entries without a digest) keep working unchanged.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

WAIVED_UPSTREAM = "waived-upstream"    # pristine copy of approved upstream content
WAIVED_LEGACY = "waived-legacy"        # covered by a legacy global waiver
REVIEW_MODIFIED = "review-modified"    # local patch drifted from approved digest
REVIEW_EXPIRED = "review-expired"      # exemption past its expiry date
NOT_COVERED = "not-covered"            # no waiver matches this location


@dataclass(frozen=True)
class Waiver:
    path: str = "*"              # fnmatch pattern for the scan location
    source: str | None = None    # provenance, e.g. "upstream:requests@2.31.0"
    sha256: str | None = None    # approved content digest; None => legacy global
    expires: dt.date | None = None  # valid through this date; None => no expiry
    note: str = ""

    def matches(self, scan_path: str) -> bool:
        return fnmatch.fnmatch(scan_path, self.path)

    def expired(self, today: dt.date) -> bool:
        return self.expires is not None and today > self.expires


@dataclass(frozen=True)
class Decision:
    path: str
    status: str
    reason: str
    waiver: Waiver | None = None


class WaiverBackend:
    def __init__(self, waivers):
        self.waivers = list(waivers)

    @classmethod
    def load(cls, config_path):
        data = json.loads(Path(config_path).read_text(encoding="utf-8"))
        entries = data.get("waivers", []) if isinstance(data, dict) else data
        return cls([
            Waiver(
                path=e.get("path", "*"),
                source=e.get("source"),
                sha256=e.get("sha256"),
                expires=dt.date.fromisoformat(e["expires"]) if e.get("expires") else None,
                note=e.get("note", ""),
            )
            for e in entries
        ])

    def decide(self, scan_path, content, today=None):
        today = today or dt.date.today()
        digest = hashlib.sha256(content).hexdigest()
        for waiver in self.waivers:
            if not waiver.matches(scan_path):
                continue
            if waiver.expired(today):
                return Decision(scan_path, REVIEW_EXPIRED,
                                f"waiver for {waiver.source or waiver.path!r} "
                                f"expired on {waiver.expires}", waiver)
            if waiver.sha256 is None:  # legacy global: location match is enough
                return Decision(scan_path, WAIVED_LEGACY,
                                waiver.note or f"legacy global waiver ({waiver.path})",
                                waiver)
            if digest == waiver.sha256:
                return Decision(scan_path, WAIVED_UPSTREAM,
                                f"pristine copy of approved {waiver.source}", waiver)
            return Decision(scan_path, REVIEW_MODIFIED,
                            f"locally modified relative to approved {waiver.source}",
                            waiver)
        return Decision(scan_path, NOT_COVERED, "no waiver matches this location")

    def audit(self, files, today=None):
        """Decide every entry in a {scan_path: content_bytes} mapping."""
        return [self.decide(path, content, today) for path, content in files.items()]

    def reaudit_due(self, today=None):
        """Waivers already past their expiry date, needing security re-review."""
        today = today or dt.date.today()
        return [w for w in self.waivers if w.expired(today)]


def filter_bandit_results(results, backend, root=".", today=None):
    """Drop waived Bandit findings; annotate the rest with the decision."""
    kept = []
    for issue in results:
        path = issue["filename"]
        content = Path(root, path).read_bytes()
        decision = backend.decide(path, content, today)
        if decision.status in (WAIVED_UPSTREAM, WAIVED_LEGACY):
            continue
        issue["waiver_status"] = decision.status
        issue["waiver_reason"] = decision.reason
        kept.append(issue)
    return kept
