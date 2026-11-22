"""Human and machine readable reporting for the page audit."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .auditor import (
    CONCLUSION_LABELS,
    EXACT_MATCH,
    MERGED_PAGE,
    MISSING_PAGE,
    MOVED_PAGE,
    SAME_CONTENT_CONFLICT,
    SPLIT_PAGE,
    audit,
)

KIND_LABELS = {
    "structure": "结构证据",
    "resource": "资源证据",
    "content": "内容证据",
}

ORDER = [
    EXACT_MATCH,
    MOVED_PAGE,
    MERGED_PAGE,
    SPLIT_PAGE,
    SAME_CONTENT_CONFLICT,
    MISSING_PAGE,
]


def format_text(original, rearranged, findings):
    lines = []
    lines.append("页面对照保全报告")
    lines.append("=" * 60)
    lines.append("原件页数: %d    重排件页数: %d" % (len(original), len(rearranged)))
    lines.append("说明: 对象号仅在各自文件内有效；跨文件以内容/资源哈希认定同源。")
    lines.append("")

    counts = {key: 0 for key in ORDER}
    for finding in findings:
        counts[finding.conclusion] = counts.get(finding.conclusion, 0) + 1
    lines.append("结论分布: " + "，".join(
        "%s %d" % (CONCLUSION_LABELS[key], counts[key]) for key in ORDER
    ))
    lines.append("")

    for number, finding in enumerate(findings, start=1):
        target = "重排件 p%s" % (finding.target_index + 1) \
            if finding.target_index is not None else "重排件 (无)"
        sources = "、".join("原件 p%d" % (i + 1) for i in finding.source_indices)
        lines.append("[%d] %s" % (number, finding.label))
        lines.append("    判定代号: %s" % finding.conclusion)
        lines.append("    对应关系: %s  <->  %s" % (sources, target))
        for evidence in finding.evidence:
            lines.append("    %s: %s" % (
                KIND_LABELS[evidence.kind], evidence.detail
            ))
        lines.append("    原件引用: %s" % finding.original_ref)
        lines.append("    重排引用: %s" % finding.rearranged_ref)
        lines.append("")
    return chr(10).join(lines)


def format_json(original, rearranged, findings):
    payload = {
        "original_page_count": len(original),
        "rearranged_page_count": len(rearranged),
        "findings": [asdict(finding) for finding in findings],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def run(original_path, rearranged_path, json_output=False):
    original, rearranged, findings = audit(
        Path(original_path), Path(rearranged_path)
    )
    if json_output:
        return format_json(original, rearranged, findings)
    return format_text(original, rearranged, findings)
