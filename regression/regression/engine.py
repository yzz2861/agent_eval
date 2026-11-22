"""Pair-wise comparison engine and group gate evaluation."""

from __future__ import annotations

from .loader import ScanLoadResult
from .model import (
    Adjudication,
    Bucket,
    GroupGate,
    PairResult,
    PairVerdict,
    RegressionResult,
    Rule,
    Sample,
    ScanSummary,
    Scope,
)


def build_pairs(
    samples: list[Sample],
    rules: dict[str, Rule],
    scopes: dict[tuple[str, str], Scope],
) -> list[PairResult]:
    """Expand the applicability matrix into one cell per (sample, rule).

    Duplicate samples (re-frozen copies of another sample) are excluded here
    so they can never inflate the denominator.
    """
    unique = [sample for sample in samples if not sample.duplicate_of]
    pairs: list[PairResult] = []
    for sample in unique:
        for (sample_id, rule_id), scope in sorted(scopes.items()):
            if sample_id != sample.sample_id or rule_id not in rules:
                continue
            rule = rules[rule_id]
            expected = (
                sample.adjudication == Adjudication.CONFIRMED
                and sample.rule_id == rule_id
            )
            pairs.append(
                PairResult(
                    sample_id=sample.sample_id,
                    path=sample.path,
                    family=sample.family,
                    rule_id=rule_id,
                    rule_family=rule.family,
                    severity=sample.severity or rule.default_severity,
                    adjudication=sample.adjudication,
                    expected=expected,
                    in_scope=scope.in_scope,
                    verdict=PairVerdict.OUT_OF_SCOPE,
                )
            )
    return pairs


def evaluate_pairs(
    pairs: list[PairResult], scan: ScanLoadResult
) -> list[PairResult]:
    """Attach a recomputed verdict to every applicable pair.

    The three failure/noise states are kept separate:
    * ``scan_missing``     - rule was active but the scanner stayed silent;
    * ``rule_disabled``    - rule was turned off for this scan;
    * ``correctly_silent`` - no confirmed finding expected and none reported.
    """
    evaluated: list[PairResult] = []
    for pair in pairs:
        verdict = pair.verdict
        matched_line = None
        if pair.in_scope:
            hits = scan.hit_index.get((pair.path, pair.rule_id), [])
            if hits:
                verdict = PairVerdict.HIT
                matched_line = hits[0].line_number
            elif pair.rule_id in scan.disabled_rules:
                verdict = PairVerdict.RULE_DISABLED
            elif pair.expected:
                verdict = PairVerdict.SCAN_MISSING
            else:
                verdict = PairVerdict.CORRECTLY_SILENT
        evaluated.append(
            PairResult(
                sample_id=pair.sample_id,
                path=pair.path,
                family=pair.family,
                rule_id=pair.rule_id,
                rule_family=pair.rule_family,
                severity=pair.severity,
                adjudication=pair.adjudication,
                expected=pair.expected,
                in_scope=pair.in_scope,
                verdict=verdict,
                matched_line=matched_line,
            )
        )
    return evaluated


def _new_bucket(name: str) -> Bucket:
    return Bucket(name=name)


def aggregate(
    name: str,
    pairs: list[PairResult],
    family: str | None = None,
) -> Bucket:
    bucket = _new_bucket(name)
    for pair in pairs:
        if family is not None and pair.rule_family != family:
            continue
        if not pair.in_scope:
            bucket.out_of_scope += 1
            continue
        bucket.applicable_pairs += 1
        if pair.expected:
            bucket.expected_pairs += 1
        if pair.verdict == PairVerdict.HIT:
            if pair.expected:
                bucket.true_hits += 1
            else:
                bucket.false_positive_hits += 1
        elif pair.verdict == PairVerdict.SCAN_MISSING:
            bucket.scan_missing += 1
            if pair.severity == "HIGH":
                bucket.missed_critical.append(pair)
        elif pair.verdict == PairVerdict.RULE_DISABLED:
            bucket.rule_disabled += 1
            bucket.disabled_rules.add(pair.rule_id)
        elif pair.verdict == PairVerdict.CORRECTLY_SILENT:
            bucket.correctly_silent += 1
    return bucket


def summarize_scan(
    scan: ScanLoadResult,
    samples: list[Sample],
    rules: dict[str, Rule],
) -> ScanSummary:
    """Classify raw scanner hits against the frozen adjudications."""
    unique_samples = {
        sample.path: sample
        for sample in samples
        if not sample.duplicate_of
    }
    confirmed = fp = unadjudicated = 0
    for hit in scan.unique_hits:
        sample = unique_samples.get(hit.path)
        if sample is None:
            unadjudicated += 1
            continue
        if (
            sample.adjudication == Adjudication.CONFIRMED
            and sample.rule_id == hit.rule_id
        ):
            confirmed += 1
        elif sample.adjudication in (
            Adjudication.FALSE_POSITIVE,
            Adjudication.CLEAN,
        ):
            fp += 1
        else:
            unadjudicated += 1
    return ScanSummary(
        label=scan.label,
        raw_hits=scan.raw_hit_count,
        unique_hits=len(scan.unique_hits),
        duplicate_hits_removed=scan.duplicate_hits_removed,
        disabled_rule_count=len(scan.disabled_rules),
        error_count=len(scan.errors),
        confirmed_hits=confirmed,
        fp_hits_on_adjudicated=fp,
        unadjudicated_hits=unadjudicated,
    )


def evaluate_gates(
    new_pairs: list[PairResult],
    old_pairs: list[PairResult],
    default_min_recall: float,
    group_config: dict[str, dict],
) -> tuple[list[GroupGate], bool]:
    groups: list[GroupGate] = []
    blocked = False
    for family, config in sorted(group_config.items()):
        min_recall = float(config.get("min_recall", default_min_recall))
        block_critical = bool(config.get("block_on_critical_miss", False))
        bucket = aggregate(family, new_pairs, family)
        old_bucket = aggregate(family, old_pairs, family)
        reasons: list[str] = []
        recall = bucket.recall
        if recall is None or recall < min_recall:
            reasons.append(
                f"recall {_fmt(recall)} < floor {min_recall:.2f}"
            )
        if block_critical and bucket.missed_critical:
            for pair in bucket.missed_critical:
                reasons.append(
                    "confirmed HIGH finding lost: "
                    f"{pair.rule_id} @ {pair.path}"
                )
        group_blocked = bool(reasons)
        blocked = blocked or group_blocked
        groups.append(
            GroupGate(
                family=family,
                min_recall=min_recall,
                block_on_critical_miss=block_critical,
                bucket=bucket,
                old_bucket=old_bucket,
                blocked=group_blocked,
                reasons=reasons,
            )
        )
    return groups, blocked


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1%}"


def run_regression(
    freeze_id: str,
    samples: list[Sample],
    rules: dict[str, Rule],
    scopes: dict[tuple[str, str], Scope],
    old_scan: ScanLoadResult,
    new_scan: ScanLoadResult,
    default_min_recall: float,
    group_config: dict[str, dict],
) -> RegressionResult:
    pairs = build_pairs(samples, rules, scopes)
    new_pairs = evaluate_pairs(pairs, new_scan)
    old_pairs = evaluate_pairs(pairs, old_scan)

    overall = aggregate("overall", new_pairs)
    old_overall = aggregate("overall", old_pairs)
    groups, group_blocked = evaluate_gates(
        new_pairs, old_pairs, default_min_recall, group_config
    )

    duplicate_rows = sum(1 for sample in samples if sample.duplicate_of)
    return RegressionResult(
        freeze_id=freeze_id,
        sample_rows=len(samples),
        unique_samples=len(samples) - duplicate_rows,
        duplicate_samples_removed=duplicate_rows,
        pair_results=new_pairs,
        overall=overall,
        old_overall=old_overall,
        groups=groups,
        new_scan=summarize_scan(new_scan, samples, rules),
        old_scan=summarize_scan(old_scan, samples, rules),
        blocked=group_blocked,
    )
