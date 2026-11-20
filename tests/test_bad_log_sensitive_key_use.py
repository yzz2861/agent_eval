#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import unittest

import dlint


class TestBadLogSensitiveKeyUse(dlint.test.base.BaseTest):

    def lint(self, source, **config):
        python_node = self.get_ast_node(source)
        linter = dlint.linters.BadLogSensitiveKeyUseLinter(**config)
        linter.visit(python_node)
        return linter.get_results()

    def test_removed_key_reaches_configured_sink(self):
        result = self.lint(
            """
            payload = {"password": "secret"}
            payload.pop("password", None)
            logger.info(payload)
            """,
            sensitive_keys=["password"],
            log_calls=["logger.info"],
        )

        self.assertEqual(
            [(item.lineno, item.message) for item in result],
            [(4, dlint.linters.BadLogSensitiveKeyUseLinter._error_tmpl)],
        )

    def test_default_context_merge_is_reported(self):
        result = self.lint(
            """
            DEFAULT_CONTEXT = {"password": "secret"}
            payload = {"message": "hello"}
            payload.update(DEFAULT_CONTEXT)
            logger.info(payload)
            """,
            sensitive_keys=["password"],
            log_calls=["logger.info"],
        )

        self.assertEqual([item.lineno for item in result], [4])

    def test_alias_shares_the_dictionary(self):
        result = self.lint(
            """
            payload = {"password": "secret"}
            alias = payload
            alias.pop("password")
            logger.info(payload)
            """,
            sensitive_keys=["password"],
            log_calls=["logger.info"],
        )

        self.assertEqual([item.lineno for item in result], [5])

    def test_independent_safe_copy_is_not_flagged(self):
        result = self.lint(
            """
            payload = {"password": "secret"}
            payload.pop("password")
            safe = payload.copy()
            logger.info(safe)
            """,
            sensitive_keys=["password"],
            log_calls=["logger.info"],
        )

        self.assertEqual(result, [])

    def test_unknown_adapter_is_left_alone(self):
        result = self.lint(
            """
            payload = {"password": "secret"}
            payload.pop("password")
            unknown_adapter(payload)
            """,
            sensitive_keys=["password"],
            log_calls=["logger.info"],
        )

        self.assertEqual(result, [])

    def test_same_name_in_other_branch_is_independent(self):
        result = self.lint(
            """
            if condition:
                payload = {"password": "secret"}
                payload.pop("password")
                logger.info(payload)
            else:
                payload = {"message": "safe"}
                logger.info(payload)
            """,
            sensitive_keys=["password"],
            log_calls=["logger.info"],
        )

        self.assertEqual([item.lineno for item in result], [5])

    def test_known_adapter_merge_is_reported(self):
        result = self.lint(
            """
            DEFAULT_CONTEXT = {"password": "secret"}

            def emit(payload):
                merged = payload.copy()
                merged.update(DEFAULT_CONTEXT)
                logger.info(merged)

            payload = {"message": "hello"}
            payload.pop("password", None)
            emit(payload)
            """,
            sensitive_keys=["password"],
            log_calls=["logger.info"],
        )

        self.assertEqual([item.lineno for item in result], [6])

    def test_configuration_from_class_attributes(self):
        class ConfiguredLinter(dlint.linters.BadLogSensitiveKeyUseLinter):
            sensitive_keys = ("token",)
            log_calls = ("audit.emit",)

        python_node = self.get_ast_node(
            """
            payload = {"token": "secret"}
            payload.pop("token")
            audit.emit(payload)
            """
        )
        linter = ConfiguredLinter()
        linter.visit(python_node)

        self.assertEqual([item.lineno for item in linter.get_results()], [4])


    def test_del_and_unknown_merge_reports_merge(self):
        result = self.lint(
            """
            payload = {"password": "secret"}
            del payload["password"]
            payload.update(get_defaults())
            logger.info(payload)
            """,
            sensitive_keys=["password"],
            log_calls=["logger.info"],
        )

        self.assertEqual([item.lineno for item in result], [4])

    def test_dict_union_reports_union(self):
        result = self.lint(
            """
            payload = {"password": "secret", "message": "hello"}
            payload.pop("password", None)
            merged = payload | get_defaults()
            logger.info(merged)
            """,
            sensitive_keys=["password"],
            log_calls=["logger.info"],
        )

        self.assertEqual([item.lineno for item in result], [4])

    def test_imported_copy_alias_is_followed(self):
        result = self.lint(
            """
            from copy import copy as duplicate

            payload = {"password": "secret"}
            alias = duplicate(payload)
            alias.pop("password")
            logger.info(alias)
            """,
            sensitive_keys=["password"],
            log_calls=["logger.info"],
        )

        self.assertEqual([item.lineno for item in result], [7])

    def test_dict_comprehension_can_redact(self):
        result = self.lint(
            """
            payload = {"password": "secret", "message": "hello"}
            safe = {k: v for k, v in payload.items() if k != "password"}
            logger.info(safe)
            """,
            sensitive_keys=["password"],
            log_calls=["logger.info"],
        )

        self.assertEqual(result, [])

    def test_repeated_pop_on_safe_copy_is_not_taint(self):
        result = self.lint(
            """
            payload = {"password": "secret"}
            payload.pop("password")
            safe = payload.copy()
            safe.pop("password", None)
            logger.info(safe)
            """,
            sensitive_keys=["password"],
            log_calls=["logger.info"],
        )

        self.assertEqual(result, [])

    def test_direct_sensitive_key_is_reported_at_sink(self):
        result = self.lint(
            """
            payload = {"password": "secret"}
            logger.info(payload)
            """,
            sensitive_keys=["password"],
            log_calls=["logger.info"],
        )

        self.assertEqual([item.lineno for item in result], [2])


if __name__ == "__main__":
    unittest.main()
