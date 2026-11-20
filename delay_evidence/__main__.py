"""Command line entry point for the read-only evidence view."""

from __future__ import annotations

import argparse
import sys

from .analyzer import analyze
from .compare import compare, render_compare_markdown
from .loader import LoaderError, load_path
from .removal import remove_target
from .report import render_markdown, render_removal_summary, render_text


def _load(path, base_rva):
    return load_path(path, fragment_base_rva=base_rva)


def _write(text, output):
    if output:
        with open(output, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        print(text)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="python -m delay_evidence",
        description="Read-only PE delay-import / load-config evidence view",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    view = sub.add_parser("view", help="analyze one PE or fragment")
    view.add_argument("path")
    view.add_argument("--base-rva", type=lambda value: int(value, 0), default=None)
    view.add_argument("--format", choices=["text", "markdown"], default="text")
    view.add_argument("--output")
    remove = sub.add_parser("remove", help="simulate removing a transfer target")
    remove.add_argument("path")
    remove.add_argument("target", help="DLL name, or DLL!Symbol / DLL!#ordinal")
    remove.add_argument("--base-rva", type=lambda value: int(value, 0), default=None)
    remove.add_argument("--format", choices=["text", "markdown"], default="text")
    remove.add_argument("--output")
    cmp_parser = sub.add_parser("compare", help="compare two PEs")
    cmp_parser.add_argument("left")
    cmp_parser.add_argument("right")
    cmp_parser.add_argument("--output")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "view":
            loaded = _load(args.path, args.base_rva)
            result = analyze(loaded)
            text = render_markdown(result) if args.format == "markdown" else render_text(result)
            _write(text, args.output)
        elif args.command == "remove":
            loaded = _load(args.path, args.base_rva)
            result = analyze(loaded)
            broken_levels = remove_target(result, args.target)
            if args.format == "markdown":
                text = render_markdown(result) + render_removal_summary(result, broken_levels)
            else:
                text = render_text(result)
                text = text + chr(10) + "evidence lost at levels: " + ", ".join(
                    level.value for level in broken_levels
                )
            _write(text, args.output)
        elif args.command == "compare":
            left = analyze(_load(args.left, None))
            right = analyze(_load(args.right, None))
            comparison = compare(left, right)
            _write(render_compare_markdown(left, right, comparison), args.output)
    except LoaderError as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
