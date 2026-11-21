# SPDX-License-Identifier: Apache-2.0
"""Local cutover validation harness for retiring Bandit rule B102.

The harness only ever evaluates the fixed corpus checked into
``cutover/corpus`` (no network access, no repository-wide scan, no dynamic
target discovery). It runs two scoped Bandit configurations:

1. ``legacy``  - only the built-in rule B102 (``exec_used``).
2. ``replacement`` - only the local plugin checks X901 (exec) and X902
   (eval), loaded from ``cutover/sast_exec_guard`` via an in-process
   stevedore extension (no package installation required).

For every fixed input file and each target rule it records three facts:

* ``entered``   - the rule function was actually invoked on the file.
* ``completed`` - every invocation returned instead of raising.
* ``hit``       - at least one issue was emitted by the rule for the file.

The recorded matrix is written to ``cutover/results/cutover_matrix.json``
and a human-readable report is written to
``cutover/results/cutover_matrix.txt``.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

CUTOVER_ROOT = Path(__file__).resolve().parent
REPO_ROOT = CUTOVER_ROOT.parent
PLUGIN_SRC = CUTOVER_ROOT / "sast_exec_guard"
CORPUS_ROOT = CUTOVER_ROOT / "corpus"
RESULTS_DIR = CUTOVER_ROOT / "results"

LEGACY_RULE = "B102"
REPLACEMENT_RULES = ("X901", "X902")

sys.path.insert(0, str(PLUGIN_SRC))

from stevedore.extension import Extension  # noqa: E402

from bandit.core import config as b_config  # noqa: E402
from bandit.core import extension_loader  # noqa: E402
from bandit.core import manager as b_manager  # noqa: E402

from sast_exec_guard import plugin as guard_plugin  # noqa: E402


@dataclass
class RuleObservation:
    """What happened when one target rule evaluated one input file."""

    rule_id: str
    rule_name: str
    input_file: str
    entered: bool = False
    completed: bool = True
    hit: bool = False
    parse_status: str = "parsed"
    findings: list = field(default_factory=list)
    note: str = ""

    def as_row(self):
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "input_file": self.input_file,
            "entered": self.entered,
            "completed": self.completed,
            "hit": self.hit,
            "parse_status": self.parse_status,
            "findings": self.findings,
            "note": self.note,
        }


class RuleInstrumentation:
    """Wraps a Bandit check function to record per-file execution facts.

    The wrapper is intentionally side-effect free apart from bookkeeping:
    it forwards the context unchanged and re-raises nothing itself, so
    exceptions still propagate through Bandit for completion tracking.
    """

    def __init__(self, rule_id, rule_name, func, observations, file_scope):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self._func = func
        self._observations = observations
        self._key = (rule_id, rule_name)
        observations.setdefault(self._key, {})
        for input_file in file_scope:
            observations[self._key][input_file] = RuleObservation(
                rule_id=rule_id,
                rule_name=rule_name,
                input_file=input_file,
            )

    @property
    def _checks(self):
        return self._func._checks

    @property
    def _test_id(self):
        return self.rule_id

    @property
    def __name__(self):
        return self.rule_name

    @property
    def __module__(self):
        return self._func.__module__

    @staticmethod
    def _normalize(input_file):
        try:
            return str(Path(input_file).resolve().relative_to(REPO_ROOT))
        except (ValueError, OSError):
            return input_file

    def __call__(self, context, *args, **kwargs):
        input_file = self._normalize(context.filename or "")
        observation = self._observations[self._key].get(input_file)
        if observation is None:
            observation = RuleObservation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                input_file=input_file,
            )
            self._observations[self._key][input_file] = observation
        observation.entered = True
        try:
            result = self._func(context, *args, **kwargs)
        except Exception:
            observation.completed = False
            raise
        if result is not None:
            observation.hit = True
            observation.findings.append(
                {
                    "line": context._context.get("lineno"),
                    "text": result.text,
                }
            )
        return result


def _fixed_corpus_files():
    """Return the fixed, version-controlled input files in scope order."""
    files = sorted(
        str(path.relative_to(REPO_ROOT))
        for path in CORPUS_ROOT.rglob("*.py")
    )
    if not files:
        raise RuntimeError(f"fixed corpus is empty under {CORPUS_ROOT}")
    return files


def _register_replacement_extensions():
    """Register the local plugin without installing or fetching anything."""
    extman = extension_loader.MANAGER
    existing_ids = {ext.plugin._test_id for ext in extman.plugins}
    extensions = list(extman.plugins_mgr.extensions)
    for name, func in (
        ("sast_exec_guard_exec", guard_plugin.guard_exec_used),
        ("sast_exec_guard_eval", guard_plugin.guard_eval_used),
    ):
        if func._test_id in existing_ids:
            continue
        extensions.append(
            Extension(name=name, entry_point=None, plugin=func, obj=None)
        )
    extman.plugins_mgr = type(extman.plugins_mgr).make_test_instance(
        extensions, namespace="bandit.plugins"
    )
    extman.plugins = list(extman.plugins_mgr.extensions)
    extman.plugin_names = [ext.name for ext in extman.plugins]
    extman.plugins_by_id = {
        ext.plugin._test_id: ext for ext in extman.plugins
    }
    extman.plugins_by_name = {ext.name: ext for ext in extman.plugins}


def _instrument(rule_id, rule_name, func, observations, file_scope):
    return RuleInstrumentation(
        rule_id, rule_name, func, observations, file_scope
    )


def _run_bandit_configuration(label, profile_rules, rule_wrappers, corpus_files):
    """Run one scoped Bandit configuration over the fixed corpus.

    ``rule_wrappers`` maps rule id -> instrumented function and is used to
    replace the matching functions inside the Bandit test set so that the
    exact function Bandit dispatches is the observed one.
    """
    configuration = b_config.BanditConfig()
    profile = {"include": list(profile_rules)}
    manager = b_manager.BanditManager(
        configuration,
        agg_type="file",
        profile=profile,
    )
    for checktype, tests in list(manager.b_ts.tests.items()):
        wrapped = []
        for test_func in tests:
            rule_id = getattr(test_func, "_test_id", "")
            if rule_id in rule_wrappers:
                wrapped.append(rule_wrappers[rule_id])
            else:
                wrapped.append(test_func)
        manager.b_ts.tests[checktype] = wrapped
    manager.files_list = [str(REPO_ROOT / path) for path in corpus_files]
    manager.run_tests()
    skipped = {fname: reason for fname, reason in manager.get_skipped()}
    findings_by_rule = {}
    for issue in manager.get_issue_list():
        findings_by_rule.setdefault(issue.test_id, []).append(
            {
                "input_file": str(Path(issue.fname).relative_to(REPO_ROOT)),
                "line": issue.lineno,
                "text": issue.text,
            }
        )
    return {
        "label": label,
        "profile_rules": list(profile_rules),
        "skipped": {
            str(Path(fname).relative_to(REPO_ROOT)): reason
            for fname, reason in skipped.items()
        },
        "findings_by_rule": findings_by_rule,
    }


def run_validation():
    """Execute both configurations and build the per-file evidence matrix."""
    corpus_files = _fixed_corpus_files()
    observations = {}
    _register_replacement_extensions()
    extman = extension_loader.MANAGER

    legacy_func = extman.plugins_by_id[LEGACY_RULE].plugin
    legacy_wrapper = _instrument(
        LEGACY_RULE,
        "exec_used",
        legacy_func,
        observations,
        corpus_files,
    )
    replacement_wrappers = {}
    for rule_id in REPLACEMENT_RULES:
        func = extman.plugins_by_id[rule_id].plugin
        wrapper = _instrument(
            rule_id,
            func.__name__,
            func,
            observations,
            corpus_files,
        )
        replacement_wrappers[rule_id] = wrapper

    legacy_run = _run_bandit_configuration(
        label="legacy-builtin-B102",
        profile_rules=(LEGACY_RULE,),
        rule_wrappers={LEGACY_RULE: legacy_wrapper},
        corpus_files=corpus_files,
    )
    replacement_run = _run_bandit_configuration(
        label="replacement-plugin-X901-X902",
        profile_rules=REPLACEMENT_RULES,
        rule_wrappers=replacement_wrappers,
        corpus_files=corpus_files,
    )

    _annotate_skipped(observations, legacy_run, replacement_run)
    return corpus_files, observations, legacy_run, replacement_run


def _annotate_skipped(observations, legacy_run, replacement_run):
    """Record parser/IO skips so skipped files are not misread as coverage."""
    for run in (legacy_run, replacement_run):
        for input_file, reason in run["skipped"].items():
            for (rule_id, rule_name), by_file in observations.items():
                if rule_id not in run["profile_rules"]:
                    continue
                observation = by_file.get(input_file)
                if observation is None:
                    observation = RuleObservation(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        input_file=input_file,
                    )
                    by_file[input_file] = observation
                observation.note = f"file skipped: {reason}"
                observation.parse_status = "skipped"


def build_coverage_analysis(corpus_files, observations):
    """Compare exec-detection responsibility between B102 and X901.

    Only rules owning the exec-detection responsibility are compared.
    X902 (eval) findings are reported separately and can never close an
    exec-coverage gap.
    """
    legacy = observations[(LEGACY_RULE, "exec_used")]
    replacement = observations[("X901", "guard_exec_used")]
    eval_rule = observations[("X902", "guard_eval_used")]
    rows = []
    gaps = []
    for input_file in corpus_files:
        old = legacy.get(input_file)
        new = replacement.get(input_file)
        row = {
            "input_file": input_file,
            "legacy_entered": bool(old and old.entered),
            "legacy_completed": bool(old and old.completed),
            "legacy_hit": bool(old and old.hit),
            "replacement_entered": bool(new and new.entered),
            "replacement_completed": bool(new and new.completed),
            "replacement_hit": bool(new and new.hit),
            "eval_hit": bool(eval_rule.get(input_file) and
                            eval_rule[input_file].hit),
            "gap_classification": "",
        }
        gap = _classify_gap(input_file, old, new)
        row["gap_classification"] = gap["classification"]
        if gap["classification"] != "covered":
            gaps.append(gap)
        rows.append(row)
    return rows, gaps


LEGACY_SCOPE_FRAGMENT = str(Path("cutover") / "corpus" / "legacy")


def _is_in_unscanned_legacy_root(input_file):
    normalized = os.path.normpath(input_file).replace(os.sep, "/")
    return LEGACY_SCOPE_FRAGMENT in normalized


def _classify_gap(input_file, old, new):
    old_hit = bool(old and old.hit)
    new_entered = bool(new and new.entered)
    new_hit = bool(new and new.hit)
    directory_boundary = _is_in_unscanned_legacy_root(input_file)
    if old_hit and directory_boundary and not new_hit:
        return {
            "input_file": input_file,
            "classification": "directory-coverage-gap",
            "detail": (
                "file lives in the unscanned legacy root; X901 refuses the "
                "directory while legacy B102 still detects exec"
            ),
            "blocks_cutover": True,
        }
    if old_hit and new_entered and not new_hit:
        return {
            "input_file": input_file,
            "classification": "syntax-coverage-gap",
            "detail": (
                "replacement plugin enters the file but does not recognize "
                "the nested-scope bare exec syntax that B102 covers"
            ),
            "blocks_cutover": True,
        }
    if old_hit and new_hit:
        return {
            "input_file": input_file,
            "classification": "covered",
            "detail": "exec responsibility covered by both rules",
            "blocks_cutover": False,
        }
    return {
        "input_file": input_file,
        "classification": "covered",
        "detail": "no exec finding under the legacy rule, no gap",
        "blocks_cutover": False,
    }


def _build_record(corpus_files, observations, legacy_run, replacement_run,
                  coverage_rows, gaps):
    rule_rows = []
    for (rule_id, rule_name), by_file in sorted(observations.items()):
        for input_file in corpus_files:
            observation = by_file.get(input_file)
            if observation is None:
                observation = RuleObservation(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    input_file=input_file,
                )
            rule_rows.append(observation.as_row())
    return {
        "corpus_root": str(CORPUS_ROOT.relative_to(REPO_ROOT)),
        "input_files": corpus_files,
        "rules": {
            "retired": LEGACY_RULE,
            "replacement_exec_rule": "X901",
            "replacement_new_rule": "X902",
        },
        "runs": {"legacy": legacy_run, "replacement": replacement_run},
        "per_file_rule_matrix": rule_rows,
        "exec_responsibility_coverage": coverage_rows,
        "open_coverage_gaps": gaps,
        "new_only_findings": list(
            replacement_run["findings_by_rule"].get("X902", [])
        ),
        "cutover_decision": {
            "approved": not any(gap["blocks_cutover"] for gap in gaps),
            "blocking_gap_count": sum(
                1 for gap in gaps if gap["blocks_cutover"]
            ),
            "rule": "new X902 eval findings do not offset exec-coverage gaps",
        },
    }


def _write_text_report(record):
    lines = []
    lines.append("Bandit B102 cutover validation - fixed local corpus")
    lines.append("=" * 66)
    lines.append("corpus: %s" % record["corpus_root"])
    lines.append("")
    header = "%-6s %-44s %-8s %-10s %s" % (
        "rule", "input file", "entered", "completed", "hit"
    )
    lines.append(header)
    lines.append("-" * len(header))
    for row in record["per_file_rule_matrix"]:
        lines.append(
            "%-6s %-44s %-8s %-10s %s" % (
                row["rule_id"],
                row["input_file"],
                row["entered"],
                row["completed"],
                row["hit"],
            )
        )
        if row["note"]:
            lines.append("       note: %s" % row["note"])
    lines.append("")
    lines.append("Exec-detection responsibility coverage (B102 vs X901)")
    lines.append("-" * 66)
    for row in record["exec_responsibility_coverage"]:
        lines.append(
            "%-44s %s" % (row["input_file"], row["gap_classification"])
        )
    lines.append("")
    lines.append("Blocking coverage gaps (new X902 alerts cannot offset)")
    lines.append("-" * 66)
    if not record["open_coverage_gaps"]:
        lines.append("none")
    for gap in record["open_coverage_gaps"]:
        lines.append(
            "- [%s] %s: %s" % (
                gap["classification"], gap["input_file"], gap["detail"]
            )
        )
    lines.append("")
    lines.append("New-only X902 eval findings (do not close exec gaps)")
    lines.append("-" * 66)
    if not record["new_only_findings"]:
        lines.append("none")
    for finding in record["new_only_findings"]:
        lines.append(
            "- %s:%s %s" % (
                finding["input_file"], finding["line"], finding["text"]
            )
        )
    lines.append("")
    decision = record["cutover_decision"]
    verdict = "APPROVED" if decision["approved"] else "NOT APPROVED"
    lines.append(
        "Decision: %s (blocking gaps: %s)"
        % (verdict, decision["blocking_gap_count"])
    )
    return "\n".join(lines) + "\n"


def _write_approval_form(record):
    lines = []
    lines.append("# B102 cutover approval form")
    lines.append("")
    lines.append("## Scope and detection responsibilities")
    lines.append("")
    lines.append("- Retired built-in rule: `B102` (`exec_used`) - detects use of the Python `exec` builtin at any scope depth, across every scanned directory.")
    lines.append("- Replacement exec rule: `X901` (`guard_exec_used`, local package `sast_exec_guard`) - owns the same exec-detection responsibility, but only for shallow-scope bare `exec(...)` and only outside the unscanned legacy root.")
    lines.append("- Newly added rule: `X902` (`guard_eval_used`) - detects bare `eval(...)`; this is a new responsibility and cannot offset any B102 exec-coverage gap.")
    lines.append("- Fixed local corpus: `%s` (no network, no repository-wide scan)." % record["corpus_root"])
    lines.append("")
    lines.append("## Per-input evidence (real files vs. concrete responsibilities)")
    lines.append("")
    lines.append("| input file | B102 entered/completed/hit | X901 entered/completed/hit | X902 hit | parse status | gap |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    rows_by_file = {}
    for row in record["per_file_rule_matrix"]:
        rows_by_file.setdefault(row["input_file"], {})[row["rule_id"]] = row
    coverage = {row["input_file"]: row["gap_classification"] for row in record["exec_responsibility_coverage"]}
    for input_file in record["input_files"]:
        by_rule = rows_by_file[input_file]
        def cell(rule_id):
            row = by_rule.get(rule_id)
            if row is None:
                return "-/-/-"
            return "%s/%s/%s" % (row["entered"], row["completed"], row["hit"])
        parse_status = by_rule["B102"]["parse_status"]
        lines.append(
            "| `%s` | %s | %s | %s | %s | %s |" % (
                input_file,
                cell("B102"),
                cell("X901"),
                by_rule["X902"]["hit"],
                parse_status,
                coverage.get(input_file, ""),
            )
        )
    lines.append("")
    lines.append("## Blocking coverage gaps on the exec responsibility")
    lines.append("")
    if not record["open_coverage_gaps"]:
        lines.append("None.")
    for gap in record["open_coverage_gaps"]:
        lines.append("- `%s` - **%s**: %s" % (gap["input_file"], gap["classification"], gap["detail"]))
    lines.append("")
    lines.append("## New alerts that do not offset the gaps")
    lines.append("")
    if not record["new_only_findings"]:
        lines.append("None.")
    for finding in record["new_only_findings"]:
        lines.append("- `%s:%s` - %s" % (finding["input_file"], finding["line"], finding["text"]))
    lines.append("")
    decision = record["cutover_decision"]
    verdict = "APPROVED" if decision["approved"] else "NOT APPROVED"
    lines.append("## Decision")
    lines.append("")
    lines.append("**%s** - blocking exec-coverage gaps: %s. New X902 eval alerts are recorded but do not close any B102 exec-coverage gap." % (verdict, decision["blocking_gap_count"]))
    lines.append("")
    return chr(10).join(lines) + chr(10)


def main():
    corpus_files, observations, legacy_run, replacement_run = run_validation()
    coverage_rows, gaps = build_coverage_analysis(corpus_files, observations)
    record = _build_record(
        corpus_files,
        observations,
        legacy_run,
        replacement_run,
        coverage_rows,
        gaps,
    )
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    json_path = RESULTS_DIR / "cutover_matrix.json"
    text_path = RESULTS_DIR / "cutover_matrix.txt"
    json_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    text_path.write_text(_write_text_report(record))
    approval_path = RESULTS_DIR / "cutover_approval_form.md"
    approval_path.write_text(_write_approval_form(record))
    print(_write_text_report(record))
    print("machine-readable matrix: %s" % json_path.relative_to(REPO_ROOT))
    print("human-readable report:  %s" % text_path.relative_to(REPO_ROOT))
    print("cutover approval form:   %s" % approval_path.relative_to(REPO_ROOT))
    return 0 if record["cutover_decision"]["approved"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
