#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""生成离线结构化对照验收报告。"""
from __future__ import print_function

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from Registry.StructuredComparison import (
    compare_snapshots,
    load_snapshot,
    parse_firewall_rule,
    resolve_field_alias,
)


SNAPSHOT_DIR = os.path.join(ROOT, "acceptance", "snapshots")
REPORT_PATH = os.path.join(ROOT, "acceptance", "structured-comparison-report.md")
SUMMARY_PATH = os.path.join(ROOT, "acceptance", "acceptance-summary.json")


def fix(name):
    return "`%s`" % str(name).replace("|", "\\|")


def yes_no(value):
    return "是" if value else "否"


VERDICT_ZH = {
    "display_only": "仅展示字段变化；原始字节虽不同，不构成权限变化",
    "security_change": "安全相关字段或安全描述符发生真实变化",
    "needs_review": "存在未批准字段变化，需要人工复核，不能直接定性为权限变化",
    "unknown_version_change": "出现未知版本；已单独追踪版本和偏移，未升级为权限变化",
    "unchanged": "无变化",
}


def load_fixture(name):
    snapshot = load_snapshot(os.path.join(SNAPSHOT_DIR, name))
    snapshot["_filename"] = name
    return snapshot


def firewall_detail(baseline, candidate, result):
    base_offset = baseline.get("base_byte_offset", 0)
    lines = [
        "",
        "### {}：{}".format(candidate["snapshot_id"], result["verdict"]),
        "",
        candidate.get("label", ""),
        "",
        "- 夹具：`acceptance/snapshots/{}`".format(candidate["_filename"]),
        "- 原始字节是否不同：{}".format(yes_no(result["raw_changed"])),
        "- 是否判定为权限/安全变化：**{}**".format(yes_no(result["permission_change"])),
        "- 解释：{}".format(VERDICT_ZH.get(result["verdict"], result["summary"])),
    ]
    if result["changes"]:
        lines.extend([
            "",
            "| 字段 | 分类 | 基线值 | 对照值 | 值的相对偏移 | 绝对原始偏移 |",
            "|---|---|---|---|---:|---:|",
        ])
        for change in result["changes"]:
            rel = change.get("candidate_value_byte_offset")
            abs_offset = base_offset + rel if rel is not None else "-"
            old = change.get("baseline_raw_value") or change.get("baseline_value") or "-"
            new = change.get("candidate_raw_value") or change.get("candidate_value") or "-"
            lines.append("| {} | {} | {} | {} | {} | {} |".format(
                fix(change["token"]), change["category"], fix(old), fix(new),
                rel if rel is not None else "-", fix(abs_offset)))
    if result["raw_byte_changes"]:
        lines.extend([
            "",
            "原始字节块（绝对偏移 = python-registry 原始数据起点 `{}` + 相对偏移）：".format(base_offset),
            "",
            "| 相对偏移 | 绝对偏移 | 长度 | 映射字段 | 字节变化 |",
            "|---:|---:|---:|---|---|",
        ])
        for hunk in result["raw_byte_changes"]:
            rel = hunk.get("offset", hunk.get("baseline_offset", 0))
            field_name = hunk.get("candidate_field") or hunk.get("baseline_field") or "-"
            length = hunk.get("length", hunk.get("baseline_length", 0))
            byte_change = "{} -> {}".format(hunk.get("baseline_hex", ""), hunk.get("candidate_hex", ""))
            lines.append("| {} | {} | {} | {} | {} |".format(
                rel, base_offset + rel, length, field_name, fix(byte_change)))
    return lines


def service_table():
    baseline = load_fixture("service-rasman-baseline.json")
    candidates = [
        load_fixture("service-rasman-display-name.json"),
        load_fixture("service-rasman-display-description.json"),
        load_fixture("service-rasman-security-dacl.json"),
    ]
    lines = [
        "",
        "## 服务键安全描述符对照组",
        "",
        "另一类常见形态是服务键：`DisplayName`、`Description` 是普通展示字段，`Security\\Security` 是二进制自相对安全描述符。",
        "该对照组证明同一套结构判定也适用于真实 DACL 位变化。",
        "",
        "| 对照快照 | 原始值不同 | 判定 | 权限变化 | 差别 |",
        "|---|---:|---|---:|---|",
    ]
    for candidate in candidates:
        result = compare_snapshots(baseline, candidate)
        if result["verdict"] == "display_only":
            explanation = "仅展示字符串变化"
        else:
            sd_changes = result.get("security_descriptor_comparison", {}).get("changes", [])
            explanation = "DACL/SD 语义变化：{}".format(", ".join(item["field"] for item in sd_changes))
        lines.append("| {} | {} | {} | {} | {} |".format(
            fix(candidate["snapshot_id"]), yes_no(result["raw_changed"]),
            fix(result["verdict"]), yes_no(result["permission_change"]), explanation))
    return lines


def main():
    baseline = load_fixture("firewall-rule-baseline.json")
    candidates = [
        load_fixture("firewall-rule-display-name.json"),
        load_fixture("firewall-rule-display-description.json"),
        load_fixture("firewall-rule-security-action.json"),
    ]
    comparisons = [(candidate, compare_snapshots(baseline, candidate)) for candidate in candidates]

    lines = [
        "# 结构化注册表对照验收报告",
        "",
        "## 结论",
        "",
        "选定的已知类型是 **Windows 防火墙 `v2` 规则值**：一个 `REG_SZ` 中同时包含 `Name`、`Desc` 等展示字段，以及 `Action`、`Active`、端口/地址和 `LUAuth` SDDL 等安全字段。",
        "原始字节比较会把三者都报成“注册表值变化”；结构化对照能解释前两个只改展示属性，第三个才是真正的安全设置变化。",
        "",
        "| 验收快照 | 原始字节不同 | 结构化判定 | 权限变化 | 说明 |",
        "|---|---:|---|---:|---|",
    ]
    for candidate, result in comparisons:
        lines.append("| {} | {} | {} | {} | {} |".format(
            fix(candidate["snapshot_id"]), yes_no(result["raw_changed"]),
            fix(result["verdict"]), yes_no(result["permission_change"]),
            VERDICT_ZH.get(result["verdict"], result["summary"]).replace("|", "/")))

    lines.extend(["", "## 三个快照的差别"])
    for candidate, result in comparisons:
        lines.extend(firewall_detail(baseline, candidate, result))

    parsed_baseline = comparisons[0][1]["baseline"]
    lines.extend([
        "",
        "## 批准核对字段与偏移追踪",
        "",
        "该快照命中的批准核对字段如下；只有其中安全相关字段的语义变化会被判定为权限变化：",
        "",
        ", ".join(fix(name) for name in parsed_baseline["approved_checked_fields"]),
        "",
        "未批准/版本专有字段：{}。这些字段保留原值、别名状态和偏移；若发生变化，结论是 `needs_review`，不会被原始字节差异直接升级为权限变化。".format(
            ", ".join(fix(name) for name in parsed_baseline["unapproved_fields"]) or "无"),
        "",
        "每个字段都在 `raw_byte_offsets` / `byte_offsets` 中记录相对原始值起点的偏移和长度；若快照来自 python-registry，还会给出 hive 文件内绝对偏移。",
    ])

    raw_text = bytes.fromhex(baseline["raw_hex"]).decode("utf-16-le")
    unknown = parse_firewall_rule(raw_text.replace("v2.22", "v2.99", 1).encode("utf-16-le"))
    lines.extend([
        "",
        "## 未知版本",
        "",
        "未知版本不会被直接升级成权限变化，也不会丢失。解析器仍逐字段记录偏移，并把版本放入 `unknown_versions`：",
        "",
        "```json",
        json.dumps(unknown["unknown_versions"][0], ensure_ascii=False, indent=2),
        "```",
    ])

    alias = resolve_field_alias("LPort")
    lines.extend([
        "",
        "## 别名与引用来源",
        "",
        f"多个别名解析到同一个规范描述；每个别名都单独保留来源。例如 `LPort` -> `{alias['canonical']}`（{alias['label']}）。",
        "",
        "| 别名 | 接口 | 来源 |",
        "|---|---|---|",
    ])
    for item in alias["aliases"]:
        lines.append("| {} | {} | {} |".format(fix(item["name"]), item["interface"], fix(item["source"])))

    lines.extend(service_table())

    lines.extend([
        "",
        "## 复现命令",
        "",
        "```sh",
        ".venv/bin/python samples/structured_acceptance.py",
        ".venv/bin/python samples/structured_report.py",
        ".venv/bin/python -m pytest tests/test_structured_comparison.py -q",
        "```",
        "",
    ])
    summary = {
        "firewall": [
            {
                "snapshot_file": candidate["_filename"],
                "snapshot_id": candidate["snapshot_id"],
                "verdict": result["verdict"],
                "raw_changed": result["raw_changed"],
                "display_only": result["display_only"],
                "security_change": result["security_change"],
                "permission_change": result["permission_change"],
                "unknown_versions": result["unknown_versions"],
                "changed_tokens": [change["token"] for change in result["changes"]],
                "raw_byte_changes": result["raw_byte_changes"],
            }
            for candidate, result in comparisons
        ],
        "service": [],
    }
    service_baseline = load_fixture("service-rasman-baseline.json")
    for filename in [
        "service-rasman-display-name.json",
        "service-rasman-display-description.json",
        "service-rasman-security-dacl.json",
    ]:
        candidate = load_fixture(filename)
        service_result = compare_snapshots(service_baseline, candidate)
        changed_fields = [change["field"] for change in service_result["changes"]]
        sd_comparison = service_result.get("security_descriptor_comparison") or {}
        if sd_comparison.get("permission_change"):
            changed_fields.append("Security")
        summary["service"].append({
            "snapshot_file": filename,
            "snapshot_id": candidate["snapshot_id"],
            "verdict": service_result["verdict"],
            "raw_changed": service_result["raw_changed"],
            "display_only": service_result["display_only"],
            "security_change": service_result["security_change"],
            "permission_change": service_result["permission_change"],
            "unknown_versions": service_result["unknown_versions"],
            "changed_fields": changed_fields,
        })
    with open(SUMMARY_PATH, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    with open(REPORT_PATH, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
    print(REPORT_PATH)
    print(SUMMARY_PATH)


if __name__ == "__main__":
    main()
