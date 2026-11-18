#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import unittest

import dlint


def unsafe_message(field, object_name):
    linter_class = dlint.linters.BadFormatStringUseLinter
    return linter_class._error_tmpl_unsafe_attribute.format(
        field=field,
        object_name=object_name
    )


def unknown_object_message(object_name):
    linter_class = dlint.linters.BadFormatStringUseLinter
    return linter_class._error_tmpl_unknown_object.format(
        object_name=object_name
    )


class TestBadFormatStringUse(dlint.test.base.BaseTest):

    def run_linter(self, source, capabilities=None):
        python_node = self.get_ast_node(source)

        linter = dlint.linters.BadFormatStringUseLinter(
            capabilities=capabilities
        )
        linter.visit(python_node)

        return linter.get_results()

    def test_empty(self):
        result = self.run_linter(
            """
            var = 1
            """
        )

        assert result == []

    def test_literal_escapes(self):
        result = self.run_linter(
            """
            result = '{{literal}}'.format(user=user)
            """,
            capabilities={'user': {'name'}}
        )

        assert result == []

    def test_no_attribute_traversal(self):
        # Plain stringification of unknown objects is not a finding
        result = self.run_linter(
            """
            result = '{} {}'.format(a, b)
            """
        )

        assert result == []

    def test_legal_indexes(self):
        result = self.run_linter(
            """
            result = '{0[0]} {0[name]}'.format(record)
            """,
            capabilities={'record': {'name'}}
        )

        assert result == []

    def test_permitted_attribute(self):
        result = self.run_linter(
            """
            result = '{user.name}'.format(user=user)
            """,
            capabilities={'user': {'name'}}
        )

        assert result == []

    def test_unsafe_attribute(self):
        result = self.run_linter(
            """
            result = '{user.secret}'.format(user=user)
            """,
            capabilities={'user': {'name'}}
        )

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=2,
                col_offset=9,
                message=unsafe_message('{user.secret}', 'user')
            )
        ]

        assert result == expected

    def test_nested_overprivileged_field(self):
        result = self.run_linter(
            """
            result = '{0.__class__.__init__.__globals__}'.format(user)
            """,
            capabilities={'user': {'name'}}
        )

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=2,
                col_offset=9,
                message=unsafe_message(
                    '{0.__class__.__init__.__globals__}',
                    'user'
                )
            )
        ]

        assert result == expected

    def test_overprivileged_beyond_dunder(self):
        # Not a dunder check: any attribute outside the permitted
        # capability set is flagged
        result = self.run_linter(
            """
            result = '{user.name.first}'.format(user=user)
            """,
            capabilities={'user': {'name'}}
        )

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=2,
                col_offset=9,
                message=unsafe_message('{user.name.first}', 'user')
            )
        ]

        assert result == expected

    def test_dynamic_width_safe(self):
        result = self.run_linter(
            """
            result = '{0:{w}}'.format(value, w=width)
            """
        )

        assert result == []

    def test_nested_field_overprivileged(self):
        result = self.run_linter(
            """
            result = '{0:{1.prec}}'.format(value, cfg)
            """,
            capabilities={'cfg': {'places'}}
        )

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=2,
                col_offset=9,
                message=unsafe_message('{1.prec}', 'cfg')
            )
        ]

        assert result == expected

    def test_conversion_flag_permitted(self):
        result = self.run_linter(
            """
            result = '{user.name!r}'.format(user=user)
            """,
            capabilities={'user': {'name'}}
        )

        assert result == []

    def test_conversion_flag_unsafe(self):
        result = self.run_linter(
            """
            result = '{user.secret!s}'.format(user=user)
            """,
            capabilities={'user': {'name'}}
        )

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=2,
                col_offset=9,
                message=unsafe_message('{user.secret!s}', 'user')
            )
        ]

        assert result == expected

    def test_constant_wrapper_safe(self):
        result = self.run_linter(
            """
            def CONST(s):
                return s

            FMT = CONST('{user.name}')

            result = FMT.format(user=user)
            """,
            capabilities={'user': {'name'}}
        )

        assert result == []

    def test_constant_wrapper_unsafe(self):
        result = self.run_linter(
            """
            def CONST(s):
                return s

            FMT = CONST('{user.secret}')

            result = FMT.format(user=user)
            """,
            capabilities={'user': {'name'}}
        )

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=7,
                col_offset=9,
                message=unsafe_message('{user.secret}', 'user')
            )
        ]

        assert result == expected

    def test_constant_wrapper_inline(self):
        result = self.run_linter(
            """
            def CONST(s):
                return s

            result = CONST('{user.secret}').format(user=user)
            """,
            capabilities={'user': {'name'}}
        )

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=5,
                col_offset=9,
                message=unsafe_message('{user.secret}', 'user')
            )
        ]

        assert result == expected

    def test_unknown_format_string(self):
        result = self.run_linter(
            """
            result = fmt.format(user=user)
            """,
            capabilities={'user': {'name'}}
        )

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=2,
                col_offset=9,
                message=(
                    dlint.linters.BadFormatStringUseLinter
                    ._error_tmpl_unknown_format_string
                )
            )
        ]

        assert result == expected

    def test_unknown_object_source(self):
        result = self.run_linter(
            """
            result = '{obj.attr}'.format(obj=obj)
            """
        )

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=2,
                col_offset=9,
                message=unknown_object_message('obj')
            )
        ]

        assert result == expected

    def test_unknowns_reported_separately(self):
        result = self.run_linter(
            """
            result = fmt.format(user=user)
            value = '{obj.attr}'.format(obj=obj)
            """
        )

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=2,
                col_offset=9,
                message=(
                    dlint.linters.BadFormatStringUseLinter
                    ._error_tmpl_unknown_format_string
                )
            ),
            dlint.linters.base.Flake8Result(
                lineno=3,
                col_offset=8,
                message=unknown_object_message('obj')
            )
        ]

        assert result == expected

    def test_format_map_safe(self):
        result = self.run_linter(
            """
            result = '{user[name]}'.format_map(mapping)
            """,
            capabilities={'mapping': {'name'}}
        )

        assert result == []

    def test_format_map_unsafe(self):
        result = self.run_linter(
            """
            result = '{user.secret}'.format_map(mapping)
            """,
            capabilities={'mapping': {'name'}}
        )

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=2,
                col_offset=9,
                message=unsafe_message('{user.secret}', 'mapping')
            )
        ]

        assert result == expected

    def test_str_format_unbound_unsafe(self):
        result = self.run_linter(
            """
            result = str.format('{user.secret}', user=user)
            """,
            capabilities={'user': {'name'}}
        )

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=2,
                col_offset=9,
                message=unsafe_message('{user.secret}', 'user')
            )
        ]

        assert result == expected

    def test_analysis_never_instantiates_or_calls_objects(self):
        # Independent control: a harmless object that counts any
        # instantiation, attribute lookup, or call. The analysis must
        # be purely static, so every counter stays at zero.
        class SideEffectControl(object):
            instantiations = 0
            attribute_lookups = 0
            calls = 0

            def __init__(self):
                SideEffectControl.instantiations += 1

            def __getattr__(self, name):
                SideEffectControl.attribute_lookups += 1
                raise AttributeError(name)

            def __call__(self, *args, **kwargs):
                SideEffectControl.calls += 1

        capabilities = {'control': {'name'}}

        python_node = self.get_ast_node(
            """
            result = '{control.name} {control.secret}'.format(control=control)
            """
        )

        linter = dlint.linters.BadFormatStringUseLinter(
            capabilities=capabilities
        )
        linter.visit(python_node)

        result = linter.get_results()

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=2,
                col_offset=9,
                message=unsafe_message('{control.secret}', 'control')
            )
        ]

        assert result == expected

        assert SideEffectControl.instantiations == 0
        assert SideEffectControl.attribute_lookups == 0
        assert SideEffectControl.calls == 0


class TestFormatStringParser(dlint.test.base.BaseTest):

    def test_literal_escapes(self):
        fields = dlint.formatstring.parse_format_string('{{literal}}')

        assert fields == []

    def test_nested_field_and_conversion(self):
        fields = dlint.formatstring.parse_format_string('{0[name]!r:{w}}')

        assert len(fields) == 1

        field = fields[0]

        assert field.root == '0'
        assert field.path == (
            dlint.formatstring.Step(
                dlint.formatstring.STEP_INDEX,
                'name'
            ),
        )
        assert field.conversion == 'r'
        assert len(field.spec_fields) == 1
        assert field.spec_fields[0].root == 'w'

    def test_automatic_numbering(self):
        fields = dlint.formatstring.parse_format_string('{} {:{}}')

        assert [field.root for field in fields] == ['0', '1']
        assert fields[1].spec_fields[0].root == '2'

    def test_mixed_numbering_rejected(self):
        with self.assertRaises(dlint.formatstring.FormatStringParseError):
            dlint.formatstring.parse_format_string('{} {0}')

    def test_check_source_api(self):
        findings = dlint.formatstring.check_source(
            "result = '{user.secret}'.format(user=user)\n",
            capabilities={'user': {'name'}}
        )

        assert len(findings) == 1
        assert findings[0].kind == dlint.formatstring.KIND_UNSAFE_ATTRIBUTE
        assert findings[0].field == '{user.secret}'
        assert findings[0].object_name == 'user'


if __name__ == "__main__":
    unittest.main()
