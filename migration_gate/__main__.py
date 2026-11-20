"""CLI for the migration gate.

Usage:
    python -m migration_gate BEFORE.yaml AFTER.yaml --path a.b [--path c] ...

Exit codes: 0 = PASS, 1 = FAIL, 2 = REVIEW (or usage/IO error).
"""

import argparse
import sys

from .gate import VERDICT_FAIL, VERDICT_PASS, VERDICT_REVIEW, run_gate


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="migration_gate",
        description="比较改写前后两份 YAML 文档中受保护键路径的有效值、类型与共享关系。",
    )
    parser.add_argument("before", help="改写前的 YAML 文档")
    parser.add_argument("after", help="改写后的 YAML 文档")
    parser.add_argument(
        "--path",
        dest="paths",
        action="append",
        required=True,
        help="需要保护的键路径（点号分隔，数字段表示序列下标），可重复",
    )
    parser.add_argument("--max-nodes", type=int, default=None, help="节点数上限")
    parser.add_argument("--max-depth", type=int, default=None, help="嵌套深度上限")
    args = parser.parse_args(argv)

    kwargs = {}
    if args.max_nodes is not None:
        kwargs["max_nodes"] = args.max_nodes
    if args.max_depth is not None:
        kwargs["max_depth"] = args.max_depth

    try:
        with open(args.before, "r", encoding="utf-8") as stream:
            before_text = stream.read()
        with open(args.after, "r", encoding="utf-8") as stream:
            after_text = stream.read()
    except OSError as exc:
        print("读取文档失败: %s" % exc, file=sys.stderr)
        return 2

    report = run_gate(before_text, after_text, args.paths, **kwargs)
    print(report.to_yaml(), end="")
    if report.verdict == VERDICT_PASS:
        return 0
    if report.verdict == VERDICT_FAIL:
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
