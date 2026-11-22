"""Command line entry point.

Examples:
    python -m page_audit                 # regenerate fixtures, then audit
    python -m page_audit --json
    python -m page_audit --original a.pdf --rearranged b.pdf
"""

from __future__ import annotations

import argparse
from pathlib import Path

from .generator import (
    FIXTURE_DIR,
    ORIGINAL_NAME,
    REARRANGED_NAME,
    generate,
)
from .report import run


def main():
    parser = argparse.ArgumentParser(
        description="只读页面对照：核实重排 PDF 与纸质原件的页面对应关系"
    )
    parser.add_argument("--original", help="原件 PDF 路径")
    parser.add_argument("--rearranged", help="重排件 PDF 路径")
    parser.add_argument("--json", action="store_true", help="输出 JSON 报告")
    parser.add_argument(
        "--regenerate", action="store_true",
        help="先重新生成确定性样本 PDF 再审计",
    )
    args = parser.parse_args()

    if args.regenerate or not (
        (FIXTURE_DIR / ORIGINAL_NAME).exists()
        and (FIXTURE_DIR / REARRANGED_NAME).exists()
    ):
        generate()

    original = Path(args.original) if args.original else FIXTURE_DIR / ORIGINAL_NAME
    rearranged = (
        Path(args.rearranged) if args.rearranged
        else FIXTURE_DIR / REARRANGED_NAME
    )
    print(run(original, rearranged, json_output=args.json))


if __name__ == "__main__":
    main()
