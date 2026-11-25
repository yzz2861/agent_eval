"""离线兼容审查(只读)。

输入:
  readers.json          调用方批准的读者描述(批准口径)
  objects/gen1.json     第 1 代档案的已解码对象
  objects/gen2.json     第 2 代档案的已解码对象

本脚本只读取上述文件并向标准输出打印审查结果,不写入、不修改任何输入,
也不延长任何旧签收(SO-*)的覆盖范围。未知 CBOR 标签一律标记为"待核查",
不在离线审查中放行。
"""

import json
import sys
from pathlib import Path

HERE = Path(__file__).parent

# 已登记的 CBOR 标签 -> 逻辑类别。未登记标签不推断类别,直接列入待核查。
KNOWN_TAGS = {1: "timestamp", 55799: None}  # 55799 = self-described CBOR, 透明


def categorize(node):
    """从已解码对象事实推断逻辑类别。"""
    if isinstance(node, dict):
        if "$bytes" in node:
            return "opaque-bytes"
        if "$tag" in node:
            tag = node["$tag"]
            if tag == 55799:
                return categorize(node["value"])
            if tag in KNOWN_TAGS:
                return KNOWN_TAGS[tag]
            return f"unknown-tag({tag})"
        return "map"
    if isinstance(node, str):
        return "text"
    if isinstance(node, bool):
        return "flag"
    if isinstance(node, (int, float)):
        return "count"
    if isinstance(node, list):
        if not node:
            return "empty[]"
        inner = {categorize(item) for item in node}
        return f"{inner.pop()}[]" if len(inner) == 1 else "mixed[]"
    if node is None:
        return "null"
    return "unknown"


def collect_unknown_tags(node, path="$"):
    """递归收集未登记标签,返回 (路径, 标签号) 列表。"""
    found = []
    if isinstance(node, dict):
        if "$tag" in node:
            if node["$tag"] not in KNOWN_TAGS:
                found.append((path, node["$tag"]))
            found += collect_unknown_tags(node["value"], path)
        else:
            for key, value in node.items():
                found += collect_unknown_tags(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, item in enumerate(node):
            found += collect_unknown_tags(item, f"{path}[{index}]")
    return found


def review_pair(reader, obj_name, obj):
    """对 (读者, 对象) 组合做交接边界审查。返回结构化结果。"""
    approved = reader["fields"]
    boundary = [name for name in approved if name in obj]
    outside = [name for name in obj if name not in approved]
    findings = []

    for name, spec in approved.items():
        if name in obj:
            actual = categorize(obj[name])
            if actual != spec["category"]:
                findings.append({
                    "kind": "category-mismatch",
                    "field": name,
                    "approved": spec["category"],
                    "actual": actual,
                    "attribution": "对象事实(值类别)与批准口径(字段绑定)冲突;变更事实在对象,重审义务来自批准口径",
                })
        elif spec.get("required"):
            findings.append({
                "kind": "required-missing",
                "field": name,
                "approved": spec["category"],
                "actual": None,
                "attribution": "对象事实(字段缺失),相对批准口径的必填要求",
            })

    unknown_tags = collect_unknown_tags(obj)

    if any(f["kind"] == "required-missing" for f in findings):
        verdict = "INCOMPATIBLE"
    elif any(f["kind"] == "category-mismatch" for f in findings):
        verdict = "RE-REVIEW"
    else:
        verdict = "COMPATIBLE"

    return {
        "reader": reader["reader_id"],
        "signoff": reader["signoff"],
        "object": obj_name,
        "boundary": boundary,
        "outside_boundary": outside,
        "findings": findings,
        "unknown_tags_pending": unknown_tags,
        "verdict": verdict,
    }


def render(result):
    lines = [
        f"### {result['reader']} ({result['signoff']}) x {result['object']}",
        f"  交接边界(已批准且实际存在): {', '.join(result['boundary']) or '(空)'}",
        f"  边界外字段(签收不覆盖,交接前须剥离,不延长权限): "
        f"{', '.join(result['outside_boundary']) or '(无)'}",
    ]
    for finding in result["findings"]:
        if finding["kind"] == "category-mismatch":
            lines.append(
                f"  [类别不符] {finding['field']}: 批准={finding['approved']} "
                f"实际={finding['actual']} -> 触发该读者域重审"
            )
        else:
            lines.append(
                f"  [必填缺失] {finding['field']}: 批准={finding['approved']} 实际=缺失"
            )
        lines.append(f"    归因: {finding['attribution']}")
    for path, tag in result["unknown_tags_pending"]:
        lines.append(f"  [待核查] 未知标签 tag({tag}) @ {path} —— 离线审查不放行")
    lines.append(f"  结论: {result['verdict']}")
    return "\n".join(lines)


def run_review(readers_path=None, objects=None):
    readers_path = readers_path or HERE / "readers.json"
    readers = json.loads(Path(readers_path).read_text(encoding="utf-8"))["readers"]
    if objects is None:
        objects = {
            name: json.loads((HERE / "objects" / f"{name}.json").read_text(encoding="utf-8"))["value"]
            for name in ("gen1", "gen2")
        }
    return [review_pair(reader, name, obj) for reader in readers for name, obj in objects.items()]


def main():
    results = run_review()
    for result in results:
        print(render(result))
        print()
    worst = {"COMPATIBLE": 0, "RE-REVIEW": 1, "INCOMPATIBLE": 2}
    overall = max((r["verdict"] for r in results), key=worst.get)
    print(f"总体结论: {overall}")
    return 0 if overall == "COMPATIBLE" else 1


if __name__ == "__main__":
    sys.exit(main())
