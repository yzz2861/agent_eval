#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import unittest

import dlint


class TestBadFrozenDefaultUse(dlint.test.base.BaseTest):

    @staticmethod
    def get_linter():
        linter = dlint.linters.BadFrozenDefaultUseLinter()
        linter.switch_kwargs = ("verify",)
        linter.entry_points = ("request",)
        linter.unsafe_values = (False,)
        return linter

    def test_empty_by_default(self):
        python_node = self.get_ast_node(
            """
            def request(url, verify=False):
                pass

            request("url")
            """
        )

        linter = dlint.linters.BadFrozenDefaultUseLinter()
        linter.visit(python_node)

        result = linter.get_results()

        assert result == []

    def test_explicit_safe_value_overrides_frozen_default(self):
        python_node = self.get_ast_node(
            """
            def request(url, verify=False):
                pass

            request("url", verify=True)
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()

        assert result == []

    def test_explicit_unsafe_value_flagged(self):
        python_node = self.get_ast_node(
            """
            def request(url, verify=True):
                pass

            request("url", verify=False)
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=5,
                col_offset=0,
                message=dlint.linters.BadFrozenDefaultUseLinter._error_tmpl
            )
        ]

        assert result == expected

    def test_frozen_default_ignores_later_rebinding(self):
        python_node = self.get_ast_node(
            """
            SAFE_MODE = False

            def request(url, verify=SAFE_MODE):
                pass

            SAFE_MODE = True

            request("url")
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=9,
                col_offset=0,
                message=dlint.linters.BadFrozenDefaultUseLinter._error_tmpl
            )
        ]

        assert result == expected

    def test_safe_default_before_rebinding_not_flagged(self):
        python_node = self.get_ast_node(
            """
            SAFE_MODE = True

            def request(url, verify=SAFE_MODE):
                pass

            SAFE_MODE = False

            request("url")
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()

        assert result == []

    def test_keyword_only_frozen_default_flagged(self):
        python_node = self.get_ast_node(
            """
            def request(url, *, verify=False):
                pass

            request("url")
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=5,
                col_offset=0,
                message=dlint.linters.BadFrozenDefaultUseLinter._error_tmpl
            )
        ]

        assert result == expected

    def test_keyword_only_explicit_safe_value_not_flagged(self):
        python_node = self.get_ast_node(
            """
            def request(url, *, verify=False):
                pass

            request("url", verify=True)
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()

        assert result == []

    def test_forwarding_call_uses_callee_frozen_default(self):
        python_node = self.get_ast_node(
            """
            def request(url, verify=False):
                pass

            def fetch(url):
                return request(url)
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=6,
                col_offset=11,
                message=dlint.linters.BadFrozenDefaultUseLinter._error_tmpl
            )
        ]

        assert result == expected

    def test_forwarding_call_uses_wrapper_frozen_default(self):
        python_node = self.get_ast_node(
            """
            def request(url, verify=False):
                pass

            def fetch(url, verify=True):
                return request(url, verify=verify)
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()

        assert result == []

    def test_forwarding_call_with_local_rebinding(self):
        python_node = self.get_ast_node(
            """
            def request(url, verify=False):
                pass

            def fetch(url, verify=False):
                verify = True
                return request(url, verify=verify)
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()

        assert result == []

    def test_forwarding_call_defined_before_callee(self):
        python_node = self.get_ast_node(
            """
            def fetch(url):
                return request(url)

            def request(url, verify=False):
                pass
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=3,
                col_offset=11,
                message=dlint.linters.BadFrozenDefaultUseLinter._error_tmpl
            )
        ]

        assert result == expected

    def test_unknown_provenance_remains_unknown(self):
        python_node = self.get_ast_node(
            """
            def request(url, verify=False):
                pass

            def fetch(url, verify):
                return request(url, verify=verify)

            request("url", verify=get_config())
            request("url", **settings)
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()

        assert result == []

    def test_positional_switch_value(self):
        python_node = self.get_ast_node(
            """
            def request(url, verify=True):
                pass

            request("url", False)
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=5,
                col_offset=0,
                message=dlint.linters.BadFrozenDefaultUseLinter._error_tmpl
            )
        ]

        assert result == expected

    def test_attribute_entry_point_match(self):
        python_node = self.get_ast_node(
            """
            import client

            client.request("url", verify=False)
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=4,
                col_offset=0,
                message=dlint.linters.BadFrozenDefaultUseLinter._error_tmpl
            )
        ]

        assert result == expected


if __name__ == "__main__":
    unittest.main()
