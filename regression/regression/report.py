"""Render the two short regression reports and the machine-readable JSON."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .model import PairVerdict, RegressionResult


VERDICT_CN = {
    PairVerdict.HIT: "命中",
    PairVerdict.SCAN_MISSING: "扫描缺失",
    PairVerdict.RULE_DISABLED: "规则停用",
    PairVerdict.CORRECTLY_SILENT: "确实未报",
    PairVerdict.OUT_OF_SCOPE: "不在有效适用范围",
}


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0%}"


def _scan_line(summary) -> str:
    return (
        f"原始命中 {summary.raw_hits} 条 / 去重后 {summary.unique_hits} 条"
        f"（同位置重复 {summary.duplicate_hits_removed} 条）；"
        f"已确认命中 {summary.confirmed_hits}，裁决为误报/干净但仍报 "
        f"{summary.fp_hits_on_adjudicated}，未纳入裁决 "
        f"{summary.unadjudicated_hits}；停用规则 "
        f"{summary.disabled_rule_count} 个，扫描错误 {summary.error_count} 个"
    )


def _bucket_line(bucket) -> str:
    return (
        f"有效适用 {bucket.applicable_pairs} 格，其中应有发现 "
        f"{bucket.expected_pairs}；应报命中 {bucket.true_hits}，"
        f"误报仍报 {bucket.false_positive_hits}，扫描缺失 "
        f"{bucket.scan_missing}，规则停用 {bucket.rule_disabled}，"
        f"确实未报 {bucket.correctly_silent}；召回率 "
        f"{_pct(bucket.recall)}"
    )


def render_coverage_report(result: RegressionResult) -> str:
    """Short report 1: scope, deduping and the three separated states."""
    lines = [
        "# 回归报告一 · 覆盖与三态对照",
        "",
        f"- 冻结批次：`{result.freeze_id}`；样本行 {result.sample_rows} 条，"
        f"去重后唯一样本 {result.unique_samples} 个"
        f"（重复样本 {result.duplicate_samples_removed} 条未计入分母）",
        f"- 升级前：{_scan_line(result.old_scan)}",
        f"- 升级后：{_scan_line(result.new_scan)}",
        "",
        "## 总体复算（升级后 / 升级前）",
        f"- 升级后：{_bucket_line(result.overall)}",
        f"- 升级前：{_bucket_line(result.old_overall)}",
        f"- 不适用单元格 {result.overall.out_of_scope} 格，"
        "已排除在分母之外",
        "",
        "## 三态分别复算（升级后）",
        "- 扫描缺失：规则在用但扫描保持静默，逐格列于机器结果 `scan_missing`",
        f"- 规则停用：{result.overall.rule_disabled} 格，涉及 "
        f"{sorted(result.overall.disabled_rules) or '无'}",
        "- 确实未报：人工裁决无发现且扫描保持静默，不计为缺失",
        "",
        "## 按代码家族",
    ]
    for group in result.groups:
        lines.append(
            f"- `{group.family}`：{_bucket_line(group.bucket)}；"
            f"升级前召回率 {_pct(group.old_bucket.recall)}"
        )
    return "\n".join(lines) + "\n"


def render_gate_report(result: RegressionResult) -> str:
    """Short report 2: group floors and explicit blocking evidence."""
    verdict = "阻断（BLOCK）" if result.blocked else "通过（PASS）"
    lines = [
        "# 回归报告二 · 门禁裁决",
        "",
        f"- 总体门禁结论：**{verdict}**（冻结批次 `{result.freeze_id}`）",
        f"- 升级后原始命中 {result.new_scan.raw_hits} 条，"
        f"升级前 {result.old_scan.raw_hits} 条；"
        "总数对比不参与门禁，只作背景",
        "",
        "## 重点群组门槛",
    ]
    for group in result.groups:
        status = "阻断" if group.blocked else "通过"
        lines.append(
            f"- `{group.family}`：{status}；下限召回率 "
            f"{group.min_recall:.0%}，实测 {_pct(group.bucket.recall)}"
            f"（升级前 {_pct(group.old_bucket.recall)}）"
        )
        for reason in group.reasons:
            lines.append(f"    - 阻断证据：{reason}")
    lines.extend(["", "## 关键缺失明细（升级后仍为扫描缺失的高严重项）"])
    found = False
    for group in result.groups:
        for pair in group.bucket.missed_critical:
            found = True
            lines.append(
                f"- `{pair.rule_id}` @ `{pair.path}`"
                f"（家族 {pair.rule_family}，严重度 {pair.severity}，"
                f"人工裁决 {pair.adjudication.value}）"
            )
    if not found:
        lines.append("- 无")
    return "\n".join(lines) + "\n"


def export_json(result: RegressionResult, path: Path) -> None:
    """Dump the full recomputation for downstream tooling / audits."""
    payload = {
        "freeze_id": result.freeze_id,
        "blocked": result.blocked,
        "sample_rows": result.sample_rows,
        "unique_samples": result.unique_samples,
        "duplicate_samples_removed": result.duplicate_samples_removed,
        "overall": _bucket_dict(result.overall),
        "old_overall": _bucket_dict(result.old_overall),
        "scans": {
            "old": asdict(result.old_scan),
            "new": asdict(result.new_scan),
        },
        "groups": [
            {
                "family": group.family,
                "min_recall": group.min_recall,
                "block_on_critical_miss": group.block_on_critical_miss,
                "blocked": group.blocked,
                "reasons": group.reasons,
                "bucket": _bucket_dict(group.bucket),
                "old_bucket": _bucket_dict(group.old_bucket),
            }
            for group in result.groups
        ],
        "pairs": [
            {
                "sample_id": pair.sample_id,
                "path": pair.path,
                "rule_id": pair.rule_id,
                "rule_family": pair.rule_family,
                "severity": pair.severity,
                "adjudication": pair.adjudication.value,
                "expected": pair.expected,
                "in_scope": pair.in_scope,
                "verdict": pair.verdict.value,
                "matched_line": pair.matched_line,
            }
            for pair in result.pair_results
        ],
    }
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _bucket_dict(bucket):
    data = asdict(bucket)
    data["recall"] = bucket.recall
    data["disabled_rules"] = sorted(bucket.disabled_rules)
    data["missed_critical"] = [
        {
            "sample_id": pair.sample_id,
            "path": pair.path,
            "rule_id": pair.rule_id,
            "severity": pair.severity,
        }
        for pair in bucket.missed_critical
    ]
    return data
