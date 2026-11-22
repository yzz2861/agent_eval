"""Load detect-secrets findings and merge multi-plugin duplicates."""

import json
from pathlib import Path
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from .models import DEFAULT_QUEUE
from .models import Finding
from .models import make_finding_id


def load_queue_map(path: Optional[str]) -> Dict[str, str]:
    """Load a filename-prefix -> source-queue mapping from JSON."""
    if path is None:
        return {}
    with Path(path).open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("queue map must be a JSON object of prefix -> queue")
    return {str(prefix): str(queue) for prefix, queue in data.items()}


def load_findings(
    baseline_path: str,
    queue_map: Optional[Dict[str, str]] = None,
) -> List[Finding]:
    """Load and de-duplicate findings from a baseline or findings export.

    Two input shapes are supported:

    * a detect-secrets baseline with a top-level ``results`` mapping;
    * an export with a top-level ``findings`` list, where each entry may
      carry an explicit ``source_queue``.

    Entries sharing ``(filename, line_number, hashed_secret)`` are the same
    reviewable location and become one :class:`Finding`, even when several
    plugins reported them.
    """
    with Path(baseline_path).open(encoding="utf-8") as handle:
        payload = json.load(handle)

    entries: List[Dict[str, Any]] = []
    if isinstance(payload, dict) and "results" in payload:
        for filename, secrets in payload["results"].items():
            for secret in secrets:
                merged = dict(secret)
                merged.setdefault("filename", filename)
                entries.append(merged)
    elif isinstance(payload, dict) and "findings" in payload:
        entries = list(payload["findings"])
    else:
        raise ValueError(
            "unable to read findings: expected a baseline with \"results\" "
            "or an export with \"findings\"",
        )

    queue_map = queue_map or {}
    findings: Dict[str, Finding] = {}
    for entry in entries:
        filename = str(entry["filename"])
        line_number = int(entry.get("line_number", 0))
        hashed_secret = str(entry["hashed_secret"])
        finding_id = str(
            entry.get("finding_id")
            or make_finding_id(filename, line_number, hashed_secret),
        )
        detector_type = str(entry["type"])

        if finding_id in findings:
            finding = findings[finding_id]
            if detector_type not in finding.detector_types:
                finding.detector_types.append(detector_type)
            continue

        findings[finding_id] = Finding(
            finding_id=finding_id,
            filename=filename,
            line_number=line_number,
            hashed_secret=hashed_secret,
            detector_types=[detector_type],
            source_queue=_resolve_queue(filename, entry, queue_map),
        )

    result = list(findings.values())
    for finding in result:
        finding.detector_types.sort()
    result.sort(key=lambda item: item.finding_id)
    return result


def _resolve_queue(
    filename: str,
    entry: Dict[str, Any],
    queue_map: Dict[str, str],
) -> str:
    if entry.get("source_queue"):
        return str(entry["source_queue"])

    best_prefix = ""
    best_queue = DEFAULT_QUEUE
    for prefix, queue in queue_map.items():
        if filename.startswith(prefix) and len(prefix) > len(best_prefix):
            best_prefix = prefix
            best_queue = queue
    return best_queue
