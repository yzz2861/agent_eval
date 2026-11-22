"""Static scan runner, contract diff report and failure shrinker.

The runner drives Bandit's own AST visitor over generated source held
in memory -- the generated code is parsed and analysed statically,
never executed.  ``compare`` attributes every divergence back to a
contract id and a source location.  ``shrink`` minimises a failing
program while the deviation signature stays identical.
"""

import dataclasses
import io
from dataclasses import dataclass

from bandit.core import config as b_config
from bandit.core import metrics as b_metrics
from bandit.core import node_visitor
from bandit.core import test_set as b_test_set

from tests.functional.gencontracts import model
from tests.functional.gencontracts import render

RULE_IDS = (model.RULE_SUBPROCESS_SHELL, model.RULE_HARDCODED_PASSWORD_KWARG)

PSEUDO_FILENAME = "./generated_case.py"


class _ListTestSet:
    """Minimal test set so defect doubles can be injected offline."""

    def __init__(self, tests):
        self._tests = list(tests)

    def get_tests(self, checktype):
        return [
            test
            for test in self._tests
            if checktype in getattr(test, "_checks", ())
        ]


def base_testset():
    """The real team rules, loaded exactly as Bandit loads them."""
    config = b_config.BanditConfig()
    return b_test_set.BanditTestSet(
        config=config, profile={"include": list(RULE_IDS)}
    )


def testset_with_doubles(doubles):
    """Real rules with defect doubles swapped in by rule id."""
    tests = []
    for test_fn in base_testset().get_tests("Call"):
        factory = doubles.get(test_fn._test_id)
        tests.append(factory(test_fn) if factory else test_fn)
    return _ListTestSet(tests)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    lineno: int
    text: str


def scan_source(source, testset):
    """Statically scan generated source, returning findings."""
    data = source.encode("utf-8")
    visitor = node_visitor.BanditNodeVisitor(
        PSEUDO_FILENAME,
        io.BytesIO(data),
        None,  # metaast: only used in debug mode
        testset,
        False,  # debug
        {},  # nosec lines
        b_metrics.Metrics(),
    )
    visitor.process(data)
    return [
        Finding(issue.test_id, issue.severity, issue.lineno, issue.text)
        for issue in visitor.tester.results
    ]


@dataclass(frozen=True)
class Deviation:
    kind: str  # MISSING | UNEXPECTED | SEVERITY | LINE
    cid: str  # "" when no contract can be blamed
    rule_id: str
    expected: str
    actual: str
    lineno: int
    source_line: str


def compare(program, rendered, findings):
    """Attribute every divergence to a contract or a source location."""
    expectations = model.contract_expectations(program)
    src_lines = rendered.source.splitlines()
    deviations = []
    remaining = list(findings)
    for cid in sorted(expectations):
        exp = expectations[cid]
        line = rendered.stmt_lines[cid]
        exact = [
            f
            for f in remaining
            if f.rule_id == exp.rule_id
            and f.lineno == line
            and f.severity == exp.severity
        ]
        if exact:
            remaining.remove(exact[0])
            continue
        same_line = [
            f
            for f in remaining
            if f.rule_id == exp.rule_id and f.lineno == line
        ]
        if same_line:
            remaining.remove(same_line[0])
            deviations.append(
                Deviation(
                    "SEVERITY",
                    cid,
                    exp.rule_id,
                    exp.severity,
                    same_line[0].severity,
                    line,
                    src_lines[line - 1].strip(),
                )
            )
            continue
        drifted = [f for f in remaining if f.rule_id == exp.rule_id]
        if drifted:
            remaining.remove(drifted[0])
            deviations.append(
                Deviation(
                    "LINE",
                    cid,
                    exp.rule_id,
                    "line %d" % line,
                    "line %d" % drifted[0].lineno,
                    drifted[0].lineno,
                    src_lines[drifted[0].lineno - 1].strip(),
                )
            )
            continue
        deviations.append(
            Deviation(
                "MISSING",
                cid,
                exp.rule_id,
                exp.severity,
                "<none>",
                line,
                src_lines[line - 1].strip(),
            )
        )
    for finding in remaining:
        text = ""
        if 0 < finding.lineno <= len(src_lines):
            text = src_lines[finding.lineno - 1].strip()
        deviations.append(
            Deviation(
                "UNEXPECTED",
                "",
                finding.rule_id,
                "<none>",
                finding.severity,
                finding.lineno,
                text,
            )
        )
    return deviations


def deviation_signature(deviations):
    """Line-independent fingerprint of a set of deviations."""
    return tuple(
        sorted((d.kind, d.cid or "-", d.rule_id) for d in deviations)
    )


def format_report(deviations, label):
    """Human-readable report naming the contract and source location."""
    lines = ["contract deviation report (%s):" % label]
    for dev in deviations:
        contract = dev.cid or "<no contract>"
        lines.append(
            "  [%s] contract %s rule %s: expected %s, actual %s"
            % (dev.kind, contract, dev.rule_id, dev.expected, dev.actual)
        )
        lines.append(
            "      at %s:%s | %s"
            % (PSEUDO_FILENAME, dev.lineno, dev.source_line)
        )
    return "\n".join(lines)


def conclusions(rendered, findings):
    """Map findings back to contracts: (by_contract, unattributed)."""
    line_to_cid = {}
    for cid, line in rendered.stmt_lines.items():
        line_to_cid[line] = cid
    by_contract = {}
    unattributed = []
    for finding in findings:
        cid = line_to_cid.get(finding.lineno)
        if cid is None:
            unattributed.append(finding)
        else:
            by_contract.setdefault(cid, []).append(
                (finding.rule_id, finding.severity)
            )
    for cid in by_contract:
        by_contract[cid] = sorted(by_contract[cid])
    return by_contract, unattributed


def evaluate(program, testset, renderer):
    rendered = renderer(program)
    findings = scan_source(rendered.source, testset)
    return rendered, findings, compare(program, rendered, findings)


def _removal_candidates(program):
    scopes = list(program.scopes)
    for index, scope in enumerate(scopes):
        if scope.name:  # function scopes may be dropped wholesale
            yield dataclasses.replace(
                program,
                scopes=tuple(scopes[:index] + scopes[index + 1 :]),
            )
    for index, scope in enumerate(scopes):
        for pos, stmt in enumerate(scope.body):
            defs = model.stmt_defs(stmt)
            others = scope.body[:pos] + scope.body[pos + 1:]
            if defs and any(defs & model.stmt_uses(o) for o in others):
                continue  # something still needs this binding
            new_scope = dataclasses.replace(scope, body=others)
            yield dataclasses.replace(
                program,
                scopes=tuple(
                    scopes[:index] + [new_scope] + scopes[index + 1 :]
                ),
            )


def shrink(program, testset):
    """Minimise a failing program, preserving the deviation signature.

    Returns (shrunk_program, signature).  Every candidate is only ever
    rendered and statically scanned, never executed.
    """
    _, _, base_deviations = evaluate(program, testset, render.render_canonical)
    signature = deviation_signature(base_deviations)
    if not signature:
        raise ValueError("program does not deviate; nothing to shrink")
    current = program
    changed = True
    while changed:
        changed = False
        for candidate in _removal_candidates(current):
            _, _, deviations = evaluate(
                candidate, testset, render.render_canonical
            )
            if deviation_signature(deviations) == signature:
                current = candidate
                changed = True
                break
    return current, signature
