#!/usr/bin/env python
"""Command line interface for the dlint rule-diff backend."""

from __future__ import annotations

import argparse
import json
import sys

from . import core


def build_parser():
    parser = argparse.ArgumentParser(
        prog="python -m dlint.rule_diff",
        description="Compare two revisions of dlint lint rules on a bounded AST subset.",
    )
    parser.add_argument("--old", required=True, help="Qualified class names of old rules, comma separated.")
    parser.add_argument("--new", required=True, help="Qualified class names of new rules, comma separated.")
    parser.add_argument("--budget-seconds", type=float, default=core.DEFAULT_BUDGET_SECONDS)
    parser.add_argument("--max-programs", type=int, default=core.DEFAULT_MAX_PROGRAMS)
    parser.add_argument("--max-witnesses", type=int, default=core.DEFAULT_MAX_WITNESSES)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser


def _load(names):
    classes = []
    for qualified in names:
        name = qualified.strip()
        if not name:
            continue
        module_name, _, class_name = name.rpartition(".")
        if not module_name:
            raise ValueError("rule must be a fully qualified class name: {}".format(name))
        module = __import__(module_name, fromlist=[class_name])
        classes.append(getattr(module, class_name))
    return tuple(classes)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    old_rules = _load(args.old.split(","))
    new_rules = _load(args.new.split(","))
    budget = core.Budget(
        deadline_seconds=args.budget_seconds,
        max_programs=args.max_programs,
        max_witnesses=args.max_witnesses,
    )
    report = core.compare_rules(old_rules, new_rules, budget=budget)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(core.render_text(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
