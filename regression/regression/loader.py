"""Load and validate the frozen regression inputs.

Scanner outputs follow the native ``bandit -f json`` schema (``results``
and ``errors``). Disabled rules are read either from a top-level
``disabled_rules`` list in the scan JSON or from a separate sidecar file.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .model import Adjudication, Hit, Rule, Sample, ScanLoadResult, Scope


def read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def normalize_path(raw: str) -> str:
    """Map absolute and ``./``-prefixed paths to the frozen sample key."""
    path = str(raw).replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def load_rules(path: Path) -> dict[str, Rule]:
    data = read_json(path)
    rules: dict[str, Rule] = {}
    for row in data["rules"]:
        rule = Rule(
            rule_id=row["rule_id"],
            family=row["family"],
            title=row["title"],
            default_severity=row.get("default_severity", "MEDIUM"),
        )
        if rule.rule_id in rules:
            raise ValueError(
                f"duplicate rule_id in catalogue: {rule.rule_id}"
            )
        rules[rule.rule_id] = rule
    return rules


def load_samples(
    path: Path, sample_root: Path | None = None
) -> list[Sample]:
    data = read_json(path)
    samples: list[Sample] = []
    seen: set[str] = set()
    for row in data["samples"]:
        sample_id = row["sample_id"]
        if sample_id in seen:
            raise ValueError(
                f"duplicate sample_id in manifest: {sample_id}"
            )
        seen.add(sample_id)
        sha256 = row.get("sha256", "")
        if sample_root is not None and sha256 and not row.get(
            "duplicate_of"
        ):
            source = sample_root / row["path"]
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            if digest != sha256:
                raise ValueError(
                    f"frozen sample drifted on disk: {row['path']} "
                    f"(manifest {sha256[:12]} vs disk {digest[:12]})"
                )
        samples.append(
            Sample(
                sample_id=sample_id,
                path=normalize_path(row["path"]),
                family=row["family"],
                adjudication=Adjudication(row["adjudication"]),
                rule_id=row.get("rule_id"),
                severity=row.get("severity"),
                note=row.get("note", ""),
                sha256=sha256,
                duplicate_of=row.get("duplicate_of"),
            )
        )
    return samples


def load_scopes(path: Path) -> dict[tuple[str, str], Scope]:
    data = read_json(path)
    scopes: dict[tuple[str, str], Scope] = {}
    for row in data["applicability"]:
        scope = Scope(
            sample_id=row["sample_id"],
            rule_id=row["rule_id"],
            in_scope=bool(row.get("in_scope", True)),
        )
        key = (scope.sample_id, scope.rule_id)
        if key in scopes:
            raise ValueError(f"duplicate applicability cell: {key}")
        scopes[key] = scope
    return scopes


def load_gate(path: Path) -> tuple[float, dict[str, dict]]:
    data = read_json(path)
    default_min_recall = float(data.get("default_min_recall", 0.8))
    groups = {row["family"]: row for row in data.get("groups", [])}
    return default_min_recall, groups


def load_scan(
    path: Path, label: str, disabled_sidecar: Path | None = None
) -> ScanLoadResult:
    """Parse a Bandit JSON report and collapse duplicate findings."""
    data = read_json(path)
    raw_results = data.get("results", [])
    disabled = {str(rule) for rule in data.get("disabled_rules", [])}
    if disabled_sidecar is not None and disabled_sidecar.exists():
        sidecar = read_json(disabled_sidecar)
        disabled.update(
            str(rule) for rule in sidecar.get("disabled_rules", [])
        )

    deduped: dict[tuple[str, str, tuple[int, ...]], Hit] = {}
    for row in raw_results:
        line_range = tuple(
            int(line) for line in row.get("line_range", [])
        )
        hit = Hit(
            path=normalize_path(row["filename"]),
            rule_id=row["test_id"],
            line_number=int(row.get("line_number", 0)),
            line_range=line_range,
            severity=row.get("issue_severity", "MEDIUM"),
            test_name=row.get("test_name", ""),
        )
        deduped.setdefault(
            (hit.path, hit.rule_id, hit.line_range), hit
        )

    unique_hits = sorted(
        deduped.values(), key=lambda item: (item.path, item.rule_id)
    )
    hit_index: dict[tuple[str, str], list[Hit]] = {}
    for hit in unique_hits:
        hit_index.setdefault((hit.path, hit.rule_id), []).append(hit)

    return ScanLoadResult(
        label=label,
        unique_hits=unique_hits,
        disabled_rules=disabled,
        duplicate_hits_removed=len(raw_results) - len(unique_hits),
        raw_hit_count=len(raw_results),
        errors=list(data.get("errors", [])),
        hit_index=hit_index,
    )
