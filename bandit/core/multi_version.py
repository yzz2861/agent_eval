# SPDX-License-Identifier: Apache-2.0
"""Run Bandit checks against more than one Python grammar target."""

import ast
import collections
import sys

from bandit.core import config as b_config
from bandit.core import manager as b_manager
from bandit.core import node_visitor as b_node_visitor


CHECKED = "checked"
INCONCLUSIVE = "inconclusive"
REJECTED = "rejected"
UNCOVERED = "uncovered"


def normalize_targets(targets):
    normalized = []
    for target in targets:
        if isinstance(target, str):
            parts = target.split(".")
            if len(parts) != 2 or not all(part.isdigit() for part in parts):
                raise ValueError(f"Invalid Python grammar target: {target}")
            version = tuple(int(part) for part in parts)
        else:
            version = tuple(target)
        if len(version) != 2 or not all(
            isinstance(part, int) and part >= 0 for part in version
        ):
            raise ValueError(f"Invalid Python grammar target: {target}")
        if version not in normalized:
            normalized.append(version)
    return normalized


def target_name(target):
    return f"{target[0]}.{target[1]}"


def supported_targets():
    maximum = (sys.version_info[0], sys.version_info[1])
    minimum = getattr(sys, "_REQUIRED_AST_FEATURE_VERSION", (3, 0))
    return minimum, maximum


def target_status(target):
    minimum, maximum = supported_targets()
    if target < minimum or target > maximum:
        return UNCOVERED
    return CHECKED


def parse_status(source, target):
    try:
        ast.parse(source, feature_version=target)
    except SyntaxError as exc:
        return REJECTED, {
            "message": exc.msg,
            "line_number": exc.lineno,
            "col_offset": exc.offset,
        }
    except ValueError as exc:
        return UNCOVERED, {"message": str(exc)}
    return CHECKED, {}


def scan_path(path, targets, config=None, profile=None, ignore_nosec=False):
    targets = normalize_targets(targets)
    if not targets:
        raise ValueError("At least one Python grammar target is required")
    if config is None:
        config = b_config.BanditConfig()

    try:
        with open(path, "rb") as source_file:
            source = source_file.read()
    except OSError as exc:
        return _unreadable_report(path, targets, exc)

    report = {
        "filename": path,
        "targets": collections.OrderedDict(),
        "findings": [],
    }
    grouped_findings = collections.OrderedDict()

    for target in targets:
        name = target_name(target)
        if target_status(target) == UNCOVERED:
            report["targets"][name] = {
                "status": UNCOVERED,
                "reason": "Host interpreter cannot parse this grammar target",
            }
            continue

        status, details = parse_status(source, target)
        report["targets"][name] = {"status": status}
        if details:
            report["targets"][name]["details"] = details
        if status != CHECKED:
            continue

        manager = b_manager.BanditManager(
            config,
            "file",
            profile=profile or {},
            ignore_nosec=ignore_nosec,
        )
        visitor = b_node_visitor.BanditNodeVisitor(
            path,
            None,
            manager.b_ma,
            manager.b_ts,
            False,
            {},
            manager.metrics,
        )
        try:
            visitor.process(source)
        except Exception as exc:
            report["targets"][name] = {
                "status": INCONCLUSIVE,
                "reason": str(exc),
            }
            continue

        for issue in visitor.tester.results:
            issue.fname = path
            _group_issue(grouped_findings, issue, target)

    report["findings"] = list(grouped_findings.values())
    return report


def _unreadable_report(path, targets, exc):
    return {
        "filename": path,
        "targets": collections.OrderedDict(
            (
                target_name(target),
                {
                    "status": INCONCLUSIVE,
                    "reason": exc.strerror or str(exc),
                },
            )
            for target in normalize_targets(targets)
        ),
        "findings": [],
    }


def _group_issue(grouped_findings, issue, target):
    key = (
        issue.fname,
        issue.lineno,
        tuple(issue.linerange),
        issue.col_offset,
        issue.end_col_offset,
    )
    if key not in grouped_findings:
        grouped_findings[key] = {
            "filename": issue.fname,
            "line_number": issue.lineno,
            "line_range": issue.linerange,
            "col_offset": issue.col_offset,
            "end_col_offset": issue.end_col_offset,
            "rules": collections.OrderedDict(),
        }

    rule = grouped_findings[key]["rules"].setdefault(
        issue.test_id,
        {
            "test_id": issue.test_id,
            "test_name": issue.test,
            "targets": [],
        },
    )
    name = target_name(target)
    if name not in rule["targets"]:
        rule["targets"].append(name)


def scan_paths(paths, targets, **kwargs):
    return [scan_path(path, targets, **kwargs) for path in paths]
