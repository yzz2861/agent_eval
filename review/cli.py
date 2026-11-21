"""离线审查入口：python -m review <case.json> [--as-of YYYY-MM-DD]"""

import argparse
import sys
from datetime import date

from .engine import VERDICT_LABELS, evaluate_case
from .model import load_case


def build_parser():
    parser = argparse.ArgumentParser(
        prog="python -m review",
        description="离线审查：对照现有 CVSS 评分复核有来源的排序陈述，"
        "识别确定倒置、可以并列与不同量表不可比较，并指出冲突的陈述组合。",
    )
    parser.add_argument("case", help="工单与排序陈述的 JSON 文件")
    parser.add_argument(
        "--as-of",
        default=date.today().isoformat(),
        metavar="YYYY-MM-DD",
        help="评估基准日，决定哪些陈述在生效时间窗内（默认今天）",
    )
    parser.add_argument(
        "--tolerance",
        type=float,
        default=0.0,
        help="判定并列的分差容差（默认 0.0）",
    )
    return parser


def render_report(result, tickets, statements):
    lines = []
    add = lines.append

    add("离线审查报告")
    add("=" * 60)
    add(
        "评估基准日: {0}    并列容差: {1}".format(
            result["as_of"].isoformat(), result["tolerance"]
        )
    )
    add(
        "工单 {0} 条；排序陈述 {1} 条（本基准日生效 {2} 条）".format(
            len(tickets), len(statements), len(result["active"])
        )
    )
    add("")

    add("一、现有评分条件")
    add("-" * 60)
    for ticket_id in sorted(result["scores"]):
        per_scale = result["scores"][ticket_id]
        rendered = "  ".join(
            "{0} {1:.1f}".format(scale, per_scale[scale])
            for scale in sorted(per_scale)
        )
        add("  {0}: {1}".format(ticket_id, rendered))
    add("")

    add("二、排序陈述逐条判定")
    add("-" * 60)
    for verdict in result["verdicts"]:
        stmt = verdict.statement
        add(
            "  [{0}] {1}（来源: {2}，量表: {3}）{4}".format(
                VERDICT_LABELS[verdict.status],
                stmt.id,
                stmt.author,
                stmt.scale,
                stmt.describe(),
            )
        )
        if verdict.detail:
            add("      依据: {0}".format(verdict.detail))
    add("")

    if result["shadowed"] or result["inactive"]:
        add("三、时间窗与更新的影响")
        add("-" * 60)
        for stmt in result["shadowed"]:
            successor = next(
                s
                for s in result["active"]
                if s.coverage_key == stmt.coverage_key
            )
            add(
                "  {0} 在本基准日被 {1} 取代（仅覆盖对象 {2}，"
                "自 {3} 起；窗口之外原陈述仍然有效）".format(
                    stmt.id,
                    successor.id,
                    "、".join(sorted(stmt.coverage_key)),
                    successor.valid_from.isoformat(),
                )
            )
        for stmt in result["inactive"]:
            add(
                "  {0} 不在本基准日时间窗内（{1} 至 {2}），未参与评估".format(
                    stmt.id,
                    stmt.valid_from.isoformat(),
                    stmt.valid_to.isoformat() if stmt.valid_to else "开放",
                )
            )
        add("")

    add("四、冲突组合")
    add("-" * 60)
    if not result["conflicts"]:
        add("  本基准日生效的陈述之间未发现组合冲突。")
    else:
        for index, conflict in enumerate(result["conflicts"], 1):
            add(
                "  冲突 {0}: {1} 放到一起无法同时成立".format(
                    index, " + ".join(conflict.statement_ids)
                )
            )
            add("      链条: {0}".format(conflict.chain))
    add("")
    return "\n".join(lines)


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        as_of = date.fromisoformat(args.as_of)
    except ValueError:
        print("--as-of 不是合法日期: {0!r}".format(args.as_of), file=sys.stderr)
        return 2
    try:
        tickets, statements = load_case(args.case)
    except (ValueError, KeyError) as exc:
        print("用例文件错误: {0}".format(exc), file=sys.stderr)
        return 2
    result = evaluate_case(tickets, statements, as_of, tolerance=args.tolerance)
    print(render_report(result, tickets, statements))
    return 0
