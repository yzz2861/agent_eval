"""Generative contract tests for the team-owned rules B602 and B106.

A fixed seed makes the whole suite reproducible offline.  Expectations
come from the independent contract state in
``tests.functional.gencontracts.model``, never from the rules
themselves.  Generated source is only analysed statically.
"""

import random

import testtools

from tests.functional.gencontracts import doubles
from tests.functional.gencontracts import generator
from tests.functional.gencontracts import harness
from tests.functional.gencontracts import model
from tests.functional.gencontracts import render

CASES = 48


def _generate_cases(count=CASES):
    rng = random.Random(generator.SEED)
    return [generator.generate_case(rng, index) for index in range(count)]


def _rewrite(program):
    seed = "%s:%s:rewrite" % (generator.SEED, program.case_id)
    return render.render_rewrite(program, seed)


def _shell_copy_contracts(program):
    return {
        stmt.cid
        for _, stmt in model.iter_statements(program)
        if isinstance(stmt, model.ShellSink)
        and stmt.shell
        and model.expr_uses_move(stmt.cmd, model.MOVE_COPY)
    }


def _non_exact_password_contracts(program):
    return {
        stmt.cid
        for _, stmt in model.iter_statements(program)
        if isinstance(stmt, model.ConnectSink)
        and stmt.keyword in model.PASSWORD_LIKE_KEYWORDS
        and stmt.keyword != "password"
        and isinstance(stmt.value, model.Lit)
    }


class GenerativeContractTests(testtools.TestCase):
    def test_generation_is_deterministic(self):
        first = [
            (render.render_canonical(p).source, _rewrite(p).source)
            for p in _generate_cases()
        ]
        second = [
            (render.render_canonical(p).source, _rewrite(p).source)
            for p in _generate_cases()
        ]
        self.assertEqual(first, second)

    def test_real_rules_satisfy_generated_contracts(self):
        testset = harness.base_testset()
        for program in _generate_cases():
            for label, renderer in (
                ("canonical", render.render_canonical),
                ("rewrite", _rewrite),
            ):
                rendered, _, deviations = harness.evaluate(
                    program, testset, renderer
                )
                if deviations:
                    self.fail(
                        "case %s (%s) deviates from its contracts:\n"
                        "%s\n\nsource:\n%s"
                        % (
                            program.case_id,
                            label,
                            harness.format_report(
                                deviations,
                                "%s/%s" % (program.case_id, label),
                            ),
                            rendered.source,
                        )
                    )

    def test_equivalent_rewrite_preserves_conclusions(self):
        """A rewrite may move locations, never change conclusions."""
        testset = harness.base_testset()
        saw_reformat = False
        for program in _generate_cases():
            rendered_a = render.render_canonical(program)
            rendered_b = _rewrite(program)
            if rendered_a.source != rendered_b.source:
                saw_reformat = True
            findings_a = harness.scan_source(rendered_a.source, testset)
            findings_b = harness.scan_source(rendered_b.source, testset)
            by_contract_a, extra_a = harness.conclusions(
                rendered_a, findings_a
            )
            by_contract_b, extra_b = harness.conclusions(
                rendered_b, findings_b
            )
            self.assertEqual(
                [],
                extra_a,
                "canonical scan produced unattributed findings",
            )
            self.assertEqual(
                [],
                extra_b,
                "rewrite scan produced unattributed findings",
            )
            self.assertEqual(
                by_contract_a,
                by_contract_b,
                "case %s: conclusions changed under an equivalent "
                "rewrite (canonical: %r, rewrite: %r)"
                % (program.case_id, by_contract_a, by_contract_b),
            )
        self.assertTrue(
            saw_reformat, "rewrites never altered the source; test is vacuous"
        )

    def test_copy_move_blind_double_is_detected_and_shrunk(self):
        testset = harness.testset_with_doubles(
            {model.RULE_SUBPROCESS_SHELL: doubles.copy_move_blind}
        )
        victim = None
        for program in _generate_cases():
            _, _, deviations = harness.evaluate(
                program, testset, render.render_canonical
            )
            if deviations:
                victim = (program, deviations)
                break
        self.assertIsNotNone(
            victim, "defect double produced no deviation; test is vacuous"
        )
        program, deviations = victim

        expected_cids = _shell_copy_contracts(program)
        self.assertTrue(expected_cids)
        self.assertEqual(
            expected_cids,
            {d.cid for d in deviations if d.kind == "MISSING"},
            "report must blame exactly the copy.copy-routed contracts",
        )

        shrunk, signature = harness.shrink(program, testset)
        self.assertLess(
            model.statement_count(shrunk),
            model.statement_count(program),
            "shrinker failed to minimise the failing example",
        )
        _, _, deviations_after = harness.evaluate(
            shrunk, testset, render.render_canonical
        )
        self.assertEqual(
            signature, harness.deviation_signature(deviations_after)
        )
        self.assertTrue(
            all(d.cid in expected_cids for d in deviations_after),
            "shrunk example no longer attributes to the same contracts",
        )

    def test_password_keyword_double_is_detected_and_shrunk(self):
        testset = harness.testset_with_doubles(
            {
                model.RULE_HARDCODED_PASSWORD_KWARG: (
                    doubles.exact_password_keyword_only
                )
            }
        )
        victim = None
        for program in _generate_cases():
            _, _, deviations = harness.evaluate(
                program, testset, render.render_canonical
            )
            if deviations:
                victim = (program, deviations)
                break
        self.assertIsNotNone(
            victim, "defect double produced no deviation; test is vacuous"
        )
        program, deviations = victim

        expected_cids = _non_exact_password_contracts(program)
        self.assertTrue(expected_cids)
        self.assertEqual(
            expected_cids,
            {d.cid for d in deviations if d.kind == "MISSING"},
            "report must blame exactly the non-'password' keyword contracts",
        )

        shrunk, signature = harness.shrink(program, testset)
        self.assertLess(
            model.statement_count(shrunk),
            model.statement_count(program),
            "shrinker failed to minimise the failing example",
        )
        _, _, deviations_after = harness.evaluate(
            shrunk, testset, render.render_canonical
        )
        self.assertEqual(
            signature, harness.deviation_signature(deviations_after)
        )
