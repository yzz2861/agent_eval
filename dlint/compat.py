#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import argparse
import ast
import difflib
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap

from .linters.bad_xml_use import BadXMLUseLinter
from .linters.base import Flake8Result


try:
    string_types = (basestring,)
except NameError:
    string_types = (str,)


XML_MESSAGE = BadXMLUseLinter._error_tmpl

RESULT_FIELDS = ["lineno", "col_offset", "message"]
EXTENSION_FIELDS = ["lineno", "col_offset", "message", "linter_type"]

PARSE_ERROR = "PARSE_ERROR"
COVERAGE_GAP = "COVERAGE_GAP"
RESULT_DRIFT = "RESULT_DRIFT"
SHAPE_DRIFT = "SHAPE_DRIFT"
PLUGIN_FORMAT = "PLUGIN_FORMAT"
WORKER_ERROR = "WORKER_ERROR"
MANUAL_REVIEW = "MANUAL_REVIEW"

HARD_FAILURES = (
    PARSE_ERROR,
    COVERAGE_GAP,
    RESULT_DRIFT,
    SHAPE_DRIFT,
    PLUGIN_FORMAT,
    WORKER_ERROR,
)

PARSE_FAILURE_EXIT = 2
HARD_FAILURE_EXIT = 1


def _warning(lineno, col_offset=0):
    return {
        "lineno": lineno,
        "col_offset": col_offset,
        "message": XML_MESSAGE,
    }


def _fixture(name, source, warnings, node_paths=None):
    return {
        "name": name,
        "source": source,
        "expected_warnings": warnings,
        "node_paths": node_paths or {},
    }


FIXTURES = (
    _fixture(
        "legacy_warning_positions",
        """
        import xml
        import xmlrpclib
        import lxml
        """,
        [_warning(2), _warning(3), _warning(4)],
        {
            "body[0]": "Import",
            "body[0].names[0]": "alias",
            "body[1]": "Import",
            "body[2]": "Import",
        },
    ),
    _fixture(
        "dotted_import_with_alias",
        """
        import xml.etree.ElementTree as ET
        ET.parse("placeholder.xml")
        """,
        [_warning(2)],
        {
            "body[0]": "Import",
            "body[0].names[0]": "alias",
            "body[1]": "Expr",
            "body[1].value": "Call",
            "body[1].value.func": "Attribute",
            "body[1].value.func.value": "Name",
            "body[1].value.args[0]": "Constant",
        },
    ),
    _fixture(
        "from_import",
        """
        from xml.etree import ElementTree
        ElementTree.parse("placeholder.xml")
        """,
        [_warning(2)],
        {
            "body[0]": "ImportFrom",
            "body[0].names[0]": "alias",
            "body[1].value": "Call",
            "body[1].value.func": "Attribute",
        },
    ),
    _fixture(
        "from_import_with_alias",
        """
        from xml.etree.ElementTree import parse as parse_xml
        parse_xml("placeholder.xml")
        """,
        [_warning(2)],
        {
            "body[0]": "ImportFrom",
            "body[0].names[0]": "alias",
            "body[1].value.func": "Name",
        },
    ),
    _fixture(
        "multiple_names_one_import",
        """
        import os, xml, lxml.html
        """,
        [_warning(2)],
        {
            "body[0]": "Import",
            "body[0].names[0]": "alias",
            "body[0].names[1]": "alias",
            "body[0].names[2]": "alias",
        },
    ),
    _fixture(
        "wildcard_from_import",
        """
        from xml import *
        """,
        [_warning(2)],
        {
            "body[0]": "ImportFrom",
            "body[0].names[0]": "alias",
        },
    ),
    _fixture(
        "saxutils_whitelist",
        """
        from xml.sax import saxutils
        saxutils.escape("<placeholder>")
        """,
        [],
        {
            "body[0]": "ImportFrom",
            "body[1].value": "Call",
            "body[1].value.func": "Attribute",
            "body[1].value.func.value": "Name",
            "body[1].value.args[0]": "Constant",
        },
    ),
    _fixture(
        "saxutils_alias_whitelist",
        """
        import xml.sax.saxutils as saxutils
        """,
        [],
        {
            "body[0]": "Import",
            "body[0].names[0]": "alias",
        },
    ),
    _fixture(
        "defusedxml_safe_import",
        """
        from defusedxml.ElementTree import parse
        parse("placeholder.xml")
        """,
        [],
        {
            "body[0]": "ImportFrom",
            "body[0].names[0]": "alias",
            "body[1].value": "Call",
            "body[1].value.func": "Name",
        },
    ),
    _fixture(
        "relative_import",
        """
        from . import xml
        """,
        [],
        {
            "body[0]": "ImportFrom",
            "body[0].names[0]": "alias",
        },
    ),
    _fixture(
        "nested_import",
        """
        def load_placeholder():
            import xml.etree.ElementTree
            return "placeholder.xml"
        """,
        [_warning(3, 4)],
        {
            "body[0]": "FunctionDef",
            "body[0].body[0]": "Import",
            "body[0].body[0].names[0]": "alias",
        },
    ),
)


def _source(fixture):
    return textwrap.dedent(fixture["source"])


def _node_shape(node):
    return type(node).__name__


_PATH_PART = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(?:\[([0-9]+)\])?$")


def resolve_node_path(tree, path):
    node = tree
    for part in path.split("."):
        match = _PATH_PART.match(part)
        if not match:
            raise ValueError("invalid AST path component: {}".format(part))

        attribute, index = match.groups()
        if not hasattr(node, attribute):
            raise AttributeError(
                "AST path {} has no attribute {}".format(path, attribute)
            )

        node = getattr(node, attribute)
        if index is not None:
            node = node[int(index)]

    return node


def ast_dump(tree):
    try:
        return ast.dump(tree, indent=2)
    except TypeError:
        return ast.dump(tree)


def semantic_ast(node):
    """Return a version-stable AST representation.

    Empty optional fields are ignored here. Python 3.12 added ``type_params``
    and Python 3.13 changed ``ast.dump`` to omit empty optional fields; neither
    should be mistaken for a rule-shape failure. Non-empty field changes still
    differ, so this distinguishes semantic drift from schema/serialization
    changes.
    """
    if isinstance(node, ast.AST):
        fields = []
        for field in node._fields:
            value = semantic_ast(getattr(node, field, None))
            if value is None or value == []:
                continue
            fields.append([field, value])

        attributes = []
        for attribute in getattr(node, "_attributes", ()):
            value = getattr(node, attribute, None)
            if value is None:
                continue
            attributes.append([attribute, value])
        return [_node_shape(node), fields, attributes]
    if isinstance(node, (list, tuple)):
        return [semantic_ast(item) for item in node]
    return node


def _as_warning(record):
    return [record.lineno, record.col_offset, record.message]


def plugin_records(linter):
    """Return the four-field records yielded by Dlint's flake8 extension."""
    return [
        [record.lineno, record.col_offset, record.message, _node_shape(linter)]
        for record in linter.get_results()
    ]


def _syntax_error(exc):
    return {
        "type": type(exc).__name__,
        "message": str(exc),
        "lineno": getattr(exc, "lineno", None),
        "offset": getattr(exc, "offset", None),
        "text": getattr(exc, "text", None),
    }


def probe(fixtures=None, linter_class=None):
    """Run the fixture matrix without executing any fixture source."""
    fixtures = FIXTURES if fixtures is None else fixtures
    linter_class = BadXMLUseLinter if linter_class is None else linter_class

    report = {
        "interpreter": {
            "version": list(sys.version_info[:3]),
            "version_string": sys.version.split()[0],
            "executable": sys.executable,
        },
        "plugin_contract": {
            "result_type": "Flake8Result",
            "result_fields": list(Flake8Result._fields),
            "extension_fields": list(EXTENSION_FIELDS),
        },
        "fixtures": {},
    }

    for fixture in fixtures:
        name = fixture["name"]
        entry = {
            "parse": {"ok": False},
            "warnings": [],
            "plugin": [],
            "shapes": {},
            "semantic": None,
            "dump": None,
        }

        try:
            tree = ast.parse(_source(fixture), filename="<dlint-compat:{}>".format(name))
        except SyntaxError as exc:
            entry["parse"] = {"ok": False, "error": _syntax_error(exc)}
            report["fixtures"][name] = entry
            continue
        except Exception as exc:
            entry["parse"] = {
                "ok": False,
                "error": {
                    "type": type(exc).__name__,
                    "message": str(exc),
                },
            }
            report["fixtures"][name] = entry
            continue

        entry["parse"] = {"ok": True}

        linter = linter_class()
        linter.visit(tree)
        entry["warnings"] = [_as_warning(result) for result in linter.get_results()]
        entry["plugin"] = plugin_records(linter)

        for path in fixture["node_paths"]:
            try:
                entry["shapes"][path] = _node_shape(resolve_node_path(tree, path))
            except (AttributeError, IndexError, TypeError, ValueError) as exc:
                entry["shapes"][path] = {
                    "error": type(exc).__name__,
                    "message": str(exc),
                }

        entry["semantic"] = semantic_ast(tree)
        entry["dump"] = ast_dump(tree)
        report["fixtures"][name] = entry

    return report


def _warning_tuples(warnings):
    tuples = []
    for warning in warnings:
        if isinstance(warning, dict):
            tuples.append(
                (warning["lineno"], warning["col_offset"], warning["message"])
            )
        else:
            tuples.append(tuple(warning))
    return tuples


def _warning_lists(warnings):
    return [list(warning) for warning in _warning_tuples(warnings)]


def _add_finding(findings, category, fixture, message, **details):
    finding = {
        "category": category,
        "fixture": fixture,
        "message": message,
    }
    if details:
        finding["details"] = details
    findings.append(finding)


def _check_plugin_contract(label, report, findings):
    contract = report.get("plugin_contract", {})
    result_fields = contract.get("result_fields")
    extension_fields = contract.get("extension_fields")

    if result_fields != RESULT_FIELDS:
        _add_finding(
            findings,
            PLUGIN_FORMAT,
            None,
            "{} Flake8Result fields changed: {}".format(label, result_fields),
        )
    if extension_fields != EXTENSION_FIELDS:
        _add_finding(
            findings,
            PLUGIN_FORMAT,
            None,
            "{} extension record fields changed: {}".format(label, extension_fields),
        )


def _check_fixture(label, fixture, entry, findings):
    name = fixture["name"]
    parse = entry.get("parse", {})
    if not parse.get("ok"):
        _add_finding(
            findings,
            PARSE_ERROR,
            name,
            "{} could not parse {}: {}".format(
                label,
                name,
                parse.get("error", {}).get("message", "unknown syntax error"),
            ),
            error=parse.get("error"),
        )
        return False

    expected = _warning_tuples(fixture["expected_warnings"])
    actual = _warning_tuples(entry.get("warnings", []))

    if actual != expected:
        missing = [warning for warning in expected if warning not in actual]
        if len(actual) < len(expected):
            _add_finding(
                findings,
                COVERAGE_GAP,
                name,
                "{} missed {} expected DUO107 warning(s)".format(
                    label,
                    len(missing),
                ),
                expected=_warning_lists(expected),
                actual=_warning_lists(actual),
                missing=_warning_lists(missing),
            )
        else:
            _add_finding(
                findings,
                RESULT_DRIFT,
                name,
                "{} emitted an unexpected DUO107 result set".format(label),
                expected=_warning_lists(expected),
                actual=_warning_lists(actual),
            )

    plugin = entry.get("plugin", [])
    if [list(record[:3]) for record in plugin] != [list(w) for w in actual]:
        _add_finding(
            findings,
            PLUGIN_FORMAT,
            name,
            "{} plugin records do not mirror the DUO107 result stream".format(label),
        )

    for record in plugin:
        if (
            len(record) != len(EXTENSION_FIELDS)
            or not isinstance(record[0], int)
            or not isinstance(record[1], int)
            or not isinstance(record[2], string_types)
            or not isinstance(record[3], string_types)
        ):
            _add_finding(
                findings,
                PLUGIN_FORMAT,
                name,
                "{} plugin record is not a four-field flake8 tuple".format(label),
                record=record,
            )
            break

    for path, expected_shape in fixture["node_paths"].items():
        actual_shape = entry.get("shapes", {}).get(path)
        if actual_shape != expected_shape:
            _add_finding(
                findings,
                SHAPE_DRIFT,
                name,
                "{} AST path {} changed shape".format(label, path),
                path=path,
                expected=expected_shape,
                actual=actual_shape,
            )

    return True


def _dump_diff_preview(baseline_dump, candidate_dump):
    diff = difflib.unified_diff(
        baseline_dump.splitlines(),
        candidate_dump.splitlines(),
        fromfile="baseline.ast.dump",
        tofile="candidate.ast.dump",
        lineterm="",
    )
    preview = []
    for line in diff:
        preview.append(line)
        if len(preview) >= 24:
            break
    return preview


def _empty_fields_only_in_baseline(baseline_dump, candidate_dump):
    fields = set()
    for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)=\[\]", baseline_dump):
        token = match.group(0)
        if token not in candidate_dump:
            fields.add(match.group(1))
    return sorted(fields)


def _empty_fields_only_in_candidate(baseline_dump, candidate_dump):
    fields = set()
    for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)=\[\]", candidate_dump):
        token = match.group(0)
        if token not in baseline_dump:
            fields.add(match.group(1))
    return sorted(fields)


def compare_reports(baseline, candidate, fixtures=None):
    """Compare two interpreter reports and categorize every difference."""
    fixtures = FIXTURES if fixtures is None else fixtures
    findings = []

    _check_plugin_contract("baseline", baseline, findings)
    _check_plugin_contract("candidate", candidate, findings)

    serialization_diffs = []

    for fixture in fixtures:
        name = fixture["name"]
        baseline_entry = baseline.get("fixtures", {}).get(name)
        candidate_entry = candidate.get("fixtures", {}).get(name)

        if baseline_entry is None or candidate_entry is None:
            _add_finding(
                findings,
                WORKER_ERROR,
                name,
                "fixture is missing from an interpreter report",
                baseline_present=baseline_entry is not None,
                candidate_present=candidate_entry is not None,
            )
            continue

        baseline_ok = _check_fixture("baseline", fixture, baseline_entry, findings)
        candidate_ok = _check_fixture("candidate", fixture, candidate_entry, findings)

        if not (baseline_ok and candidate_ok):
            continue

        baseline_warnings = _warning_tuples(baseline_entry["warnings"])
        candidate_warnings = _warning_tuples(candidate_entry["warnings"])

        if baseline_warnings != candidate_warnings:
            if baseline_warnings and not candidate_warnings:
                _add_finding(
                    findings,
                    COVERAGE_GAP,
                    name,
                    "candidate silently lost all DUO107 warnings for {}".format(name),
                    baseline=[list(w) for w in baseline_warnings],
                    candidate=[],
                )
            else:
                _add_finding(
                    findings,
                    RESULT_DRIFT,
                    name,
                    "DUO107 positions or messages changed across interpreters",
                    baseline=[list(w) for w in baseline_warnings],
                    candidate=[list(w) for w in candidate_warnings],
                )

        baseline_shapes = baseline_entry.get("shapes", {})
        candidate_shapes = candidate_entry.get("shapes", {})
        if baseline_shapes != candidate_shapes:
            _add_finding(
                findings,
                SHAPE_DRIFT,
                name,
                "preset AST paths differ across interpreters",
                baseline=baseline_shapes,
                candidate=candidate_shapes,
            )

        if baseline_entry.get("semantic") != candidate_entry.get("semantic"):
            _add_finding(
                findings,
                SHAPE_DRIFT,
                name,
                "semantic AST graph differs across interpreters",
            )
        elif baseline_entry.get("dump") != candidate_entry.get("dump"):
            serialization_diffs.append(name)

    if serialization_diffs:
        baseline_version = baseline.get("interpreter", {}).get("version_string")
        candidate_version = candidate.get("interpreter", {}).get("version_string")
        omitted_fields = set()
        added_fields = set()
        preview = []
        for name in serialization_diffs:
            baseline_dump = baseline["fixtures"][name]["dump"]
            candidate_dump = candidate["fixtures"][name]["dump"]
            omitted_fields.update(
                _empty_fields_only_in_baseline(baseline_dump, candidate_dump)
            )
            added_fields.update(
                _empty_fields_only_in_candidate(baseline_dump, candidate_dump)
            )
            if not preview:
                preview = _dump_diff_preview(baseline_dump, candidate_dump)

        field_notes = []
        if omitted_fields:
            field_notes.append("omitted empty field(s): {}".format(
                ", ".join(sorted(omitted_fields))
            ))
        if added_fields:
            field_notes.append("added empty field(s): {}".format(
                ", ".join(sorted(added_fields))
            ))
        field_note = ""
        if field_notes:
            field_note = " {};".format("; ".join(field_notes))

        _add_finding(
            findings,
            MANUAL_REVIEW,
            None,
            (
                "raw ast.dump output differs ({} -> {}), but semantic AST "
                "nodes and DUO107 results agree;{} review golden AST "
                "snapshots or consumers of ast.dump"
            ).format(baseline_version, candidate_version, field_note),
            fixtures=serialization_diffs,
            omitted_empty_fields=sorted(omitted_fields),
            added_empty_fields=sorted(added_fields),
            diff_preview=preview,
        )

    return findings


def _run(command, cwd=None, env=None):
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = process.communicate()
    if not isinstance(stdout, str):
        stdout = stdout.decode("utf-8", "replace")
    if not isinstance(stderr, str):
        stderr = stderr.decode("utf-8", "replace")
    return process.returncode, stdout, stderr


def _interpreter_identity(executable):
    code = (
        "import json, sys; "
        "print(json.dumps({"
        "'version': list(sys.version_info[:3]), "
        "'version_string': sys.version.split()[0], "
        "'executable': sys.executable"
        "}))"
    )
    returncode, stdout, stderr = _run([executable, "-c", code])
    if returncode != 0:
        raise RuntimeError(
            "{} is not a usable interpreter: {}".format(executable, stderr.strip())
        )
    return json.loads(stdout)


def _which(name):
    if hasattr(shutil, "which"):
        return shutil.which(name)

    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def discover_interpreters():
    """Find distinct CPython interpreters available on this worker."""
    candidates = [sys.executable]

    for minor in range(8, 16):
        found = _which("python3.{}".format(minor))
        if found:
            candidates.append(found)

    home = os.path.expanduser("~")
    patterns = [
        os.path.join(home, ".local", "share", "uv", "python", "*", "bin", "python3.*"),
        "/opt/homebrew/bin/python3.*",
        "/usr/local/bin/python3.*",
        "/usr/bin/python3.*",
    ]
    for pattern in patterns:
        candidates.extend(glob.glob(pattern))

    interpreters = {}
    for candidate in candidates:
        real = os.path.realpath(candidate)
        if real in interpreters:
            continue
        try:
            identity = _interpreter_identity(candidate)
        except (OSError, RuntimeError, ValueError):
            continue
        identity["path"] = candidate
        interpreters[real] = identity

    return sorted(
        interpreters.values(),
        key=lambda item: tuple(item["version"]),
    )


def collect_from_interpreter(executable):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = os.environ.copy()
    python_path = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        root if not python_path else root + os.pathsep + python_path
    )
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    returncode, stdout, stderr = _run(
        [executable, "-m", "dlint.compat", "--worker"],
        cwd=root,
        env=env,
    )
    if returncode != 0:
        raise RuntimeError(
            "worker {} failed ({}): {}".format(executable, returncode, stderr.strip())
        )
    return json.loads(stdout)


def select_interpreters(baseline=None, candidate=None):
    interpreters = discover_interpreters()

    if baseline and candidate:
        return baseline, candidate, interpreters

    current = sys.executable
    current_version = tuple(sys.version_info[:3])
    if baseline:
        return baseline, current, interpreters
    if candidate:
        return current, candidate, interpreters

    by_version = {}
    for item in interpreters:
        by_version.setdefault(tuple(item["version"]), item["path"])

    newer = [version for version in sorted(by_version) if version > current_version]
    if newer:
        return current, by_version[newer[0]], interpreters

    older = [version for version in sorted(by_version) if version < current_version]
    if older:
        return by_version[older[-1]], current, interpreters

    return current, current, interpreters


def run_probe(baseline=None, candidate=None):
    baseline, candidate, interpreters = select_interpreters(baseline, candidate)

    try:
        baseline_report = collect_from_interpreter(baseline)
        candidate_report = collect_from_interpreter(candidate)
    except (OSError, RuntimeError, ValueError) as exc:
        return {
            "interpreters": [
                {"path": item["path"], "version": item["version_string"]}
                for item in interpreters
            ],
            "baseline": baseline,
            "candidate": candidate,
            "findings": [
                {
                    "category": WORKER_ERROR,
                    "fixture": None,
                    "message": str(exc),
                }
            ],
        }

    findings = compare_reports(baseline_report, candidate_report)
    return {
        "interpreters": [
            {"path": item["path"], "version": item["version_string"]}
            for item in interpreters
        ],
        "baseline": {
            "path": baseline,
            "version": baseline_report["interpreter"]["version_string"],
            "warnings": sum(
                len(entry.get("warnings", []))
                for entry in baseline_report["fixtures"].values()
            ),
        },
        "candidate": {
            "path": candidate,
            "version": candidate_report["interpreter"]["version_string"],
            "warnings": sum(
                len(entry.get("warnings", []))
                for entry in candidate_report["fixtures"].values()
            ),
        },
        "fixture_count": len(FIXTURES),
        "findings": findings,
    }


def _print_human(report):
    print("Dlint XML AST compatibility probe")
    print("  fixtures: {}".format(report.get("fixture_count")))
    print(
        "  baseline: {version} ({path})".format(
            version=report["baseline"]["version"],
            path=report["baseline"]["path"],
        )
    )
    print(
        "  candidate: {version} ({path})".format(
            version=report["candidate"]["version"],
            path=report["candidate"]["path"],
        )
    )
    print(
        "  DUO107 warnings: baseline={}, candidate={}".format(
            report["baseline"]["warnings"],
            report["candidate"]["warnings"],
        )
    )

    findings = report.get("findings", [])
    if not findings:
        print("\nOK: AST paths, warning positions, and plugin records agree.")
        return

    print("")
    for category in (
        PARSE_ERROR,
        COVERAGE_GAP,
        RESULT_DRIFT,
        SHAPE_DRIFT,
        PLUGIN_FORMAT,
        WORKER_ERROR,
        MANUAL_REVIEW,
    ):
        grouped = [item for item in findings if item["category"] == category]
        if not grouped:
            continue

        if category == MANUAL_REVIEW:
            print("MANUAL REVIEW ({}):".format(len(grouped)))
        else:
            print("{} ({}):".format(category.replace("_", " "), len(grouped)))

        for item in grouped:
            fixture = "" if item.get("fixture") is None else "[{}] ".format(item["fixture"])
            print("  - {}{}".format(fixture, item["message"]))


def _finding_exit_code(findings):
    categories = set(item["category"] for item in findings)
    if categories.intersection((PARSE_ERROR, WORKER_ERROR)):
        return PARSE_FAILURE_EXIT
    if categories.intersection(HARD_FAILURES):
        return HARD_FAILURE_EXIT
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Probe the Dlint XML rule across Python AST versions."
    )
    parser.add_argument("--baseline", help="Baseline Python interpreter")
    parser.add_argument("--candidate", help="Candidate Python interpreter")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Write the complete machine-readable report to stdout",
    )
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args.worker:
        json.dump(probe(), sys.stdout, sort_keys=True)
        return 0

    report = run_probe(args.baseline, args.candidate)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _print_human(report)

    return _finding_exit_code(report.get("findings", []))


if __name__ == "__main__":
    sys.exit(main())
