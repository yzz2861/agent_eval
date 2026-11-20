#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import unittest

import dlint


class TestBadLoggingConfigUse(dlint.test.base.BaseTest):

    def test_literal_handler_class_requires_review(self):
        python_node = self.get_ast_node(
            """
            import logging.config

            logging.config.dictConfig({
                'version': 1,
                'handlers': {
                    'console': {
                        'class': 'logging.StreamHandler',
                    },
                },
            })
            """
        )

        linter = dlint.linters.BadLoggingConfigUseLinter()
        linter.visit(python_node)

        findings = linter.factory_findings
        assert len(findings) == 1

        finding = findings[0]
        assert finding.section == 'handlers'
        assert finding.name == 'console'
        assert finding.kind == 'class'
        assert finding.value == 'logging.StreamHandler'
        assert finding.status == 'review'

        results = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=8,
                col_offset=21,
                message=(
                    'DUO139 logging.config.dictConfig factory '
                    '"logging.StreamHandler" requires review '
                    '(handlers.console.class)'
                )
            )
        ]
        assert results == expected

    def test_formatter_and_filter_factories_are_collected(self):
        python_node = self.get_ast_node(
            """
            import logging.config

            logging.config.dictConfig({
                'version': 1,
                'formatters': {
                    'json': {
                        '()': 'myapp.log.JsonFormatter',
                    },
                },
                'filters': {
                    'audit': {
                        '()': 'myapp.log.AuditFilter',
                    },
                },
            })
            """
        )

        linter = dlint.linters.BadLoggingConfigUseLinter()
        linter.visit(python_node)

        findings = linter.factory_findings
        assert [f.section for f in findings] == ['formatters', 'filters']
        assert [f.status for f in findings] == ['review', 'review']
        assert linter.get_approval_list() == [
            'myapp.log.JsonFormatter',
            'myapp.log.AuditFilter',
        ]

    def test_approved_stdlib_factories_are_silent(self):
        python_node = self.get_ast_node(
            """
            import logging.config

            logging.config.dictConfig({
                'version': 1,
                'formatters': {
                    'plain': {
                        '()': 'logging.Formatter',
                    },
                },
                'filters': {
                    'builtin': {
                        '()': 'logging.Filter',
                    },
                },
            })
            """
        )

        linter = dlint.linters.BadLoggingConfigUseLinter()
        linter.visit(python_node)

        assert [f.status for f in linter.factory_findings] == [
            'approved',
            'approved',
        ]
        assert linter.get_results() == []
        assert linter.get_approval_list() == []

    def test_module_constant_reference_is_resolved(self):
        python_node = self.get_ast_node(
            """
            import logging.config

            CONFIG = {
                'version': 1,
                'handlers': {
                    'file': {
                        'class': 'logging.handlers.RotatingFileHandler',
                    },
                },
            }

            logging.config.dictConfig(CONFIG)
            """
        )

        linter = dlint.linters.BadLoggingConfigUseLinter()
        linter.visit(python_node)

        findings = linter.factory_findings
        assert len(findings) == 1
        assert findings[0].value == 'logging.handlers.RotatingFileHandler'
        assert findings[0].status == 'review'

    def test_nested_constant_sections_are_resolved(self):
        python_node = self.get_ast_node(
            """
            import logging.config

            HANDLERS = {
                'queue': {
                    'class': 'myapp.QueueHandler',
                },
            }

            CONFIG = {
                'version': 1,
                'handlers': HANDLERS,
            }

            logging.config.dictConfig(CONFIG)
            """
        )

        linter = dlint.linters.BadLoggingConfigUseLinter()
        linter.visit(python_node)

        findings = linter.factory_findings
        assert len(findings) == 1
        assert findings[0].name == 'queue'
        assert findings[0].value == 'myapp.QueueHandler'

    def test_explicit_starstar_merge_uses_effective_path(self):
        python_node = self.get_ast_node(
            """
            import logging.config

            BASE = {
                'version': 1,
                'handlers': {
                    'shared': {
                        'class': 'old.Handler',
                    },
                },
            }

            OVERRIDE = {
                'handlers': {
                    'shared': {
                        'class': 'new.Handler',
                    },
                },
            }

            logging.config.dictConfig(dict(BASE, **OVERRIDE))
            """
        )

        linter = dlint.linters.BadLoggingConfigUseLinter()
        linter.visit(python_node)

        findings = linter.factory_findings
        assert len(findings) == 1
        assert findings[0].value == 'new.Handler'
        assert linter.get_approval_list() == ['new.Handler']

    def test_starstar_merge_inside_literal_dict(self):
        python_node = self.get_ast_node(
            """
            import logging.config

            BASE = {
                'handlers': {
                    'h': {
                        'class': 'base.Handler',
                    },
                },
            }

            logging.config.dictConfig({
                'version': 1,
                **BASE,
                'handlers': {
                    'h': {
                        'class': 'override.Handler',
                    },
                },
            })
            """
        )

        linter = dlint.linters.BadLoggingConfigUseLinter()
        linter.visit(python_node)

        findings = linter.factory_findings
        assert len(findings) == 1
        assert findings[0].value == 'override.Handler'

    def test_dynamic_factory_value_is_unresolved_not_guessed(self):
        python_node = self.get_ast_node(
            """
            import logging.config

            logging.config.dictConfig({
                'version': 1,
                'handlers': {
                    'dynamic': {
                        'class': build_handler_path(),
                    },
                },
            })
            """
        )

        linter = dlint.linters.BadLoggingConfigUseLinter()
        linter.visit(python_node)

        findings = linter.factory_findings
        assert len(findings) == 1
        assert findings[0].status == 'unresolved'
        assert findings[0].value is None

        results = linter.get_results()
        assert len(results) == 1
        assert results[0].message == (
            'DUO139 logging.config.dictConfig factory at '
            'handlers.dynamic.class cannot be resolved statically'
        )

    def test_dynamic_config_argument_is_reported_separately(self):
        python_node = self.get_ast_node(
            """
            import logging.config

            logging.config.dictConfig(build_config())
            """
        )

        linter = dlint.linters.BadLoggingConfigUseLinter()
        linter.visit(python_node)

        findings = linter.factory_findings
        assert len(findings) == 1
        assert findings[0].status == 'unresolved'
        assert findings[0].section == ''

        results = linter.get_results()
        assert len(results) == 1
        assert results[0].message == (
            'DUO139 logging.config.dictConfig argument '
            'cannot be resolved statically'
        )

    def test_non_string_factory_is_unresolved(self):
        python_node = self.get_ast_node(
            """
            import logging
            import logging.config

            logging.config.dictConfig({
                'version': 1,
                'handlers': {
                    'object': {
                        'class': logging.StreamHandler,
                    },
                },
            })
            """
        )

        linter = dlint.linters.BadLoggingConfigUseLinter()
        linter.visit(python_node)

        findings = linter.factory_findings
        assert len(findings) == 1
        assert findings[0].status == 'unresolved'

    def test_same_string_in_description_is_not_approved_or_flagged(self):
        python_node = self.get_ast_node(
            """
            import logging.config

            logging.config.dictConfig({
                'version': 1,
                'handlers': {
                    'worker': {
                        'class': 'shared.Handler',
                        'description': 'shared.Handler',
                    },
                },
            })
            """
        )

        linter = dlint.linters.BadLoggingConfigUseLinter()
        linter.visit(python_node)

        findings = linter.factory_findings
        assert len(findings) == 1
        assert findings[0].kind == 'class'
        assert findings[0].value == 'shared.Handler'
        assert linter.get_approval_list() == ['shared.Handler']

    def test_approval_list_deduplicates_repeated_factory_strings(self):
        python_node = self.get_ast_node(
            """
            import logging.config

            logging.config.dictConfig({
                'version': 1,
                'handlers': {
                    'first': {
                        'class': 'shared.Handler',
                    },
                    'second': {
                        'class': 'shared.Handler',
                    },
                },
            })
            """
        )

        linter = dlint.linters.BadLoggingConfigUseLinter()
        linter.visit(python_node)

        assert len(linter.factory_findings) == 2
        assert linter.get_approval_list() == ['shared.Handler']
        assert len(linter.get_results()) == 2

    def test_from_import_dictconfig_alias(self):
        python_node = self.get_ast_node(
            """
            from logging.config import dictConfig as configure_logging

            configure_logging({
                'version': 1,
                'handlers': {
                    'h': {
                        'class': 'app.Handler',
                    },
                },
            })
            """
        )

        linter = dlint.linters.BadLoggingConfigUseLinter()
        linter.visit(python_node)

        findings = linter.factory_findings
        assert len(findings) == 1
        assert findings[0].value == 'app.Handler'

    def test_unrelated_dictconfig_call_is_ignored(self):
        python_node = self.get_ast_node(
            """
            from elsewhere import dictConfig

            dictConfig({
                'handlers': {
                    'h': {
                        'class': 'evil.Handler',
                    },
                },
            })
            """
        )

        linter = dlint.linters.BadLoggingConfigUseLinter()
        linter.visit(python_node)

        assert linter.factory_findings == []
        assert linter.get_results() == []

    def test_subclass_can_approve_additional_factories(self):
        python_node = self.get_ast_node(
            """
            import logging.config

            logging.config.dictConfig({
                'version': 1,
                'handlers': {
                    'h': {
                        'class': 'reviewed.Handler',
                    },
                },
            })
            """
        )

        class ReviewedLinter(dlint.linters.BadLoggingConfigUseLinter):
            approved_factories = (
                dlint.linters.BadLoggingConfigUseLinter.approved_factories
                + ('reviewed.Handler',)
            )

        linter = ReviewedLinter()
        linter.visit(python_node)

        assert linter.factory_findings[0].status == 'approved'
        assert linter.get_results() == []
        assert linter.get_approval_list() == []

    def test_keyword_config_argument(self):
        python_node = self.get_ast_node(
            """
            import logging.config

            CONFIG = {
                'version': 1,
                'handlers': {
                    'h': {
                        'class': 'app.Handler',
                    },
                },
            }

            logging.config.dictConfig(config=CONFIG)
            """
        )

        linter = dlint.linters.BadLoggingConfigUseLinter()
        linter.visit(python_node)

        findings = linter.factory_findings
        assert len(findings) == 1
        assert findings[0].value == 'app.Handler'

    def test_module_is_never_imported(self):
        python_node = self.get_ast_node(
            """
            import logging.config

            def build_handler_path():
                raise RuntimeError('must not execute analyzed code')

            logging.config.dictConfig({
                'version': 1,
                'handlers': {
                    'h': {
                        'class': build_handler_path(),
                    },
                },
            })
            """
        )

        linter = dlint.linters.BadLoggingConfigUseLinter()
        linter.visit(python_node)

        assert linter.factory_findings[0].status == 'unresolved'


if __name__ == "__main__":
    unittest.main()
