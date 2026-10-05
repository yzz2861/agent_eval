from copy import deepcopy

from tests import unittest

import jmespath
from jmespath import exceptions
from jmespath import functions
from jmespath import parser
from jmespath.visitor import Options


class TestLetExpressions(unittest.TestCase):
    def setUp(self):
        self.options = Options(enable_let=True)

    def test_filter_projection_uses_let_bindings(self):
        expression = (
            'let $limit = config.limit, $offset = config.offset '
            'in items[?score > $limit && score >= $offset].name'
        )
        data = {
            'config': {'limit': 10, 'offset': 0},
            'items': [
                {'score': 20, 'name': 'high'},
                {'score': 10, 'name': 'equal'},
                {'score': 5, 'name': 'low'},
            ],
        }

        result = jmespath.search(expression, data, self.options)

        self.assertEqual(result, ['high'])

    def test_variable_does_not_follow_projection_current_node(self):
        expression = 'let $limit = config.limit in items[?score > $limit]'
        data = {
            'config': {'limit': 10},
            'items': [
                {'score': 11, 'config': {'limit': 100}},
                {'score': 9, 'config': {'limit': 0}},
            ],
        }

        result = jmespath.search(expression, data, self.options)

        self.assertEqual(result, [{'score': 11, 'config': {'limit': 100}}])

    def test_sequential_bindings_see_previous_bindings(self):
        expression = 'let $first = `1`, $second = $first in [$second, $first]'

        result = jmespath.search(expression, {}, self.options)

        self.assertEqual(result, [1, 1])

    def test_nested_let_shadows_outer_binding(self):
        expression = (
            'let $value = `1`, $nested = let $value = `2` in $value '
            'in [$value, $nested, let $value = `3` in $value]'
        )

        result = jmespath.search(expression, {}, self.options)

        self.assertEqual(result, [1, 2, 3])

    def test_expression_references_capture_lexical_environment(self):
        expression = (
            'let $limit = config.limit, $prefix = config.prefix in '
            'map(&let $group = @ in '
            '{group: $group.name, names: '
            'sort_by($group.items[?score > $limit], '
            '&join(`\'\'`, [$prefix, name]))[*].name}, groups)'
        )
        data = {
            'config': {'limit': 10, 'prefix': 'z'},
            'groups': [
                {
                    'name': 'b',
                    'items': [
                        {'score': 20, 'name': 'a', 'prefix': 'B'},
                        {'score': 15, 'name': 'b', 'prefix': 'A'},
                        {'score': 5, 'name': 'c', 'prefix': 'C'},
                    ],
                },
                {
                    'name': 'a',
                    'items': [
                        {'score': 12, 'name': 'm', 'prefix': 'N'},
                        {'score': 11, 'name': 'n', 'prefix': 'M'},
                    ],
                },
            ],
        }

        result = jmespath.search(expression, data, self.options)

        self.assertEqual(result, [
            {'group': 'b', 'names': ['a', 'b']},
            {'group': 'a', 'names': ['m', 'n']},
        ])

    def test_binding_is_evaluated_once_for_projection(self):
        class CountingFunctions(functions.Functions):
            def __init__(self):
                self.calls = 0

            @functions.signature({'types': ['object']})
            def _func_limit(self, value):
                self.calls += 1
                return value['config']['limit']

        custom_functions = CountingFunctions()
        options = Options(
            enable_let=True,
            custom_functions=custom_functions,
        )
        expression = 'let $limit = limit(@) in map(&$limit, items)'
        data = {
            'config': {'limit': 10},
            'items': [{'score': 1}, {'score': 2}, {'score': 3}],
        }

        result = jmespath.search(expression, data, options)

        self.assertEqual(result, [10, 10, 10])
        self.assertEqual(custom_functions.calls, 1)

    def test_variables_do_not_mutate_input(self):
        expression = 'let $limit = config.limit in items[?score > $limit]'
        data = {
            'config': {'limit': 10},
            'items': [{'score': 20}, {'score': 5}],
        }
        original = deepcopy(data)

        jmespath.search(expression, data, self.options)

        self.assertEqual(data, original)

    def test_compiled_expression_does_not_share_search_values(self):
        expression = 'let $limit = config.limit in items[?score > $limit]'
        compiled = jmespath.compile(expression, self.options)

        first = compiled.search({
            'config': {'limit': 10},
            'items': [{'score': 20}, {'score': 5}],
        })
        second = compiled.search({
            'config': {'limit': 15},
            'items': [{'score': 20}, {'score': 5}],
        })

        self.assertEqual(first, [{'score': 20}])
        self.assertEqual(second, [{'score': 20}])

    def test_undefined_variable_has_token_position(self):
        expression = 'let $x = a in $y'

        with self.assertRaises(exceptions.UndefinedVariableError) as cm:
            jmespath.compile(expression, self.options)

        self.assertEqual(cm.exception.lex_position, 14)
        self.assertEqual(cm.exception.token_value, '$y')
        self.assertEqual(cm.exception.token_type, 'VARIABLE')
        self.assertEqual(cm.exception.expression, expression)

    def test_nested_bindings_do_not_leak_to_outer_scope(self):
        expression = 'let $x = let $y = `1` in $y in $y'

        with self.assertRaises(exceptions.UndefinedVariableError) as cm:
            jmespath.compile(expression, self.options)

        self.assertEqual(cm.exception.lex_position, 31)
        self.assertEqual(cm.exception.token_value, '$y')

    def test_binding_cannot_reference_itself(self):
        expression = 'let $x = $x in $x'

        with self.assertRaises(exceptions.UndefinedVariableError) as cm:
            jmespath.compile(expression, self.options)

        self.assertEqual(cm.exception.lex_position, 9)
        self.assertEqual(cm.exception.token_value, '$x')

    def test_missing_in_has_token_position(self):
        expression = 'let $x = `1` $x'

        with self.assertRaises(exceptions.ParseError) as cm:
            jmespath.compile(expression, self.options)

        self.assertEqual(cm.exception.lex_position, 13)
        self.assertEqual(cm.exception.token_value, '$x')

    def test_extension_is_disabled_by_default(self):
        with self.assertRaises(exceptions.LexerError) as cm:
            jmespath.compile('$x')

        self.assertEqual(cm.exception.lexer_position, 0)
        self.assertEqual(cm.exception.lexer_value, '$')

    def test_enabled_and_disabled_cache_entries_are_separate(self):
        parser.Parser.purge()
        try:
            p = parser.Parser()
            expression = 'let $x = `1` in $x'

            compiled = p.parse(expression, self.options)
            with self.assertRaises(exceptions.LexerError):
                p.parse(expression)

            self.assertEqual(compiled.search({}), 1)
        finally:
            parser.Parser.purge()


if __name__ == '__main__':
    unittest.main()
