#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import unittest

import dlint


class TestBadGeneratorDebugExport(dlint.test.base.BaseTest):

    def lint(self, source):
        python_node = self.get_ast_node(source)
        linter = dlint.linters.BadGeneratorDebugExportLinter()
        linter.visit(python_node)

        return linter.get_results()

    def test_yield_is_reported_but_return_is_not(self):
        result = self.lint(
            """
            def debug_export(values):
                pass

            def relay(classified_sample):
                yield classified_sample
                return classified_sample

            def report(classified_sample):
                debug_export(relay(classified_sample))
            """
        )

        assert len(result) == 1
        assert result[0].lineno == 10
        assert result[0].col_offset == 4
        assert 'yield at' in result[0].message
        assert 'return at' not in result[0].message

    def test_yield_from_delegates_child_yields(self):
        result = self.lint(
            """
            def debug_export(values):
                pass

            def child(classified_sample):
                yield classified_sample

            def parent(classified_sample):
                yield from child(classified_sample)

            def report(classified_sample):
                debug_export(parent(classified_sample))
            """
        )

        assert len(result) == 1
        assert 'yield from "child" at' in result[0].message

    def test_yield_from_does_not_delegate_return_value(self):
        result = self.lint(
            """
            def debug_export(values):
                pass

            def child(classified_sample):
                yield classified_sample.public_fields
                return classified_sample

            def parent(classified_sample):
                tail = yield from child(classified_sample)
                return tail

            def report(classified_sample):
                debug_export(parent(classified_sample))
            """
        )

        assert result == []

    def test_send_value_is_an_input_not_an_output(self):
        result = self.lint(
            """
            def debug_export(values):
                pass

            def relay():
                sent = yield 'ready'
                return sent

            def report(classified_sample):
                values = relay()
                debug_export(values.send(classified_sample))
            """
        )

        assert result == []

    def test_send_value_is_reported_when_explicitly_yielded(self):
        result = self.lint(
            """
            def debug_export(values):
                pass

            def relay():
                sent = yield 'ready'
                yield sent

            def report(classified_sample):
                values = relay()
                debug_export(values.send(classified_sample))
            """
        )

        assert len(result) == 1
        assert 'yield at' in result[0].message

    def test_delegated_return_is_reported_when_it_becomes_output(self):
        result = self.lint(
            """
            def debug_export(values):
                pass

            def child(classified_sample):
                yield classified_sample.public_fields
                return classified_sample

            def parent(classified_sample):
                tail = yield from child(classified_sample)
                yield tail

            def report(classified_sample):
                debug_export(parent(classified_sample))
            """
        )

        assert len(result) == 1
        assert 'return at' in result[0].message
        assert 'yield at' in result[0].message

    def test_public_projection_passes(self):
        result = self.lint(
            """
            def debug_export(values):
                pass

            def public_values(classified_sample):
                yield classified_sample.public_fields

            def report(classified_sample):
                debug_export(public_values(classified_sample))
            """
        )

        assert result == []

    def test_ordinary_generator_passes(self):
        result = self.lint(
            """
            def debug_export(values):
                pass

            def values():
                yield 'ok'

            def report():
                debug_export(values())
            """
        )

        assert result == []

    def test_public_word_in_sink_name_is_not_a_projection(self):
        result = self.lint(
            """
            def debug_export_public(values):
                pass

            def report(classified_sample):
                debug_export_public(classified_sample)
            """
        )

        assert len(result) == 1
        assert result[0].lineno == 6

    def test_uncertain_call_provenance_is_retained(self):
        result = self.lint(
            """
            def debug_export(values):
                pass

            def relay(classified_sample):
                yield from make_reader(classified_sample)

            def report(classified_sample):
                debug_export(relay(classified_sample))
            """
        )

        assert len(result) == 1
        assert 'uncertain call "make_reader"' in result[0].message


if __name__ == "__main__":
    unittest.main()
