from tests import unittest

import jmespath
from jmespath import ast
from jmespath import exceptions
from jmespath import parser


class TestLetExpressions(unittest.TestCase):
    def setUp(self):
        self.options = jmespath.Options(enable_let=True)
        self.data = {
            'config': {'limit': 2, 'inner': 1},
            'items': [
                {'score': 1, 'config': {'limit': 100}},
                {'score': 2},
                {'score': 3},
            ],
        }

    def test_let_is_disabled_by_default(self):
        with self.assertRaises(exceptions.LexerError) as caught:
            jmespath.search('let $limit = config.limit in $limit',
                            self.data)
        self.assertEqual(caught.exception.lexer_position, 4)

    def test_filter_projection_uses_outer_binding(self):
        expression = (
            'let $limit = config.limit '
            'in items[?score > $limit].score'
        )
        result = jmespath.search(expression, self.data, self.options)
        self.assertEqual(result, [3])

    def test_bindings_are_evaluated_sequentially(self):
        expression = (
            'let $base = config.limit, $limit = $base '
            'in items[?score > $limit].score'
        )
        result = jmespath.search(expression, self.data, self.options)
        self.assertEqual(result, [3])

    def test_binding_does_not_change_with_projection_current_node(self):
        expression = (
            'let $limit = config.limit '
            'in items[?score > $limit].score'
        )
        result = jmespath.search(expression, self.data, self.options)
        self.assertEqual(result, [3])
        self.assertNotIn('$limit', self.data)

    def test_nested_let_shadows_outer_binding(self):
        expression = (
            'let $limit = config.limit '
            "in map(&let $limit = `1` in score > $limit, items)"
        )
        result = jmespath.search(expression, self.data, self.options)
        self.assertEqual(result, [False, True, True])

    def test_projection_nested_let_and_expression_reference(self):
        expression = (
            'let $limit = config.limit in '
            'map(&let $pass = score > $limit in '
            '{score: score, pass: $pass}, items)[?pass].score'
        )
        result = jmespath.search(expression, self.data, self.options)
        self.assertEqual(result, [3])

    def test_expression_reference_captures_lexical_environment(self):
        expression = (
            'let $limit = config.limit '
            'in map(&score > $limit, items)'
        )
        result = jmespath.search(expression, self.data, self.options)
        self.assertEqual(result, [False, False, True])

    def test_expression_reference_keeps_environment_after_shadowing(self):
        expression = (
            'let $limit = `2`, $check = &score > $limit '
            'in let $limit = `1` in map($check, items)'
        )
        result = jmespath.search(expression, self.data, self.options)
        self.assertEqual(result, [False, False, True])

    def test_sort_by_expression_reference_uses_captured_binding(self):
        data = {
            'config': {'limit': 2},
            'items': [{'score': 3}, {'score': 1}, {'score': 2}],
        }
        expression = (
            'let $limit = config.limit '
            'in sort_by(items, &let $unused = $limit in score)[*].score'
        )
        result = jmespath.search(expression, data, self.options)
        self.assertEqual(result, [1, 2, 3])

    def test_compiled_expression_does_not_share_binding_values(self):
        compiled = jmespath.compile(
            'let $limit = config.limit in items[?score > $limit].score',
            self.options)
        first = dict(self.data)
        second = {
            'config': {'limit': 1},
            'items': self.data['items'],
        }
        self.assertEqual(compiled.search(first), [3])
        self.assertEqual(compiled.search(second), [2, 3])

    def test_let_ast(self):
        parsed = parser.Parser(enable_let=True).parse(
            'let $limit = config.limit in $limit')
        binding = parsed.parsed['children'][0]
        body = parsed.parsed['children'][1]
        self.assertEqual(parsed.parsed['type'], 'let_expression')
        self.assertEqual(binding, ast.binding(
            'limit',
            ast.subexpression([ast.field('config'), ast.field('limit')])))
        self.assertEqual(body['type'], 'variable')
        self.assertEqual(body['value'], 'limit')
        self.assertEqual(body['start'], 29)
        self.assertEqual(body['end'], 35)

    def test_undefined_variable_reports_variable_position(self):
        expression = 'items[?score > $limit]'
        with self.assertRaises(exceptions.ParseError) as caught:
            parser.Parser(enable_let=True).parse(expression)
        error = caught.exception
        self.assertEqual(error.lex_position, 15)
        self.assertEqual(error.token_value, '$limit')
        self.assertEqual(error.token_type, 'VARIABLE')
        self.assertIn('Undefined variable "$limit"', str(error))

    def test_variable_cannot_reference_itself_in_binding(self):
        with self.assertRaises(exceptions.ParseError) as caught:
            parser.Parser(enable_let=True).parse('let $x = $x in $x')
        self.assertEqual(caught.exception.lex_position, 9)
        self.assertEqual(caught.exception.token_value, '$x')

    def test_duplicate_binding_reports_second_position(self):
        expression = 'let $x = `1`, $x = `2` in $x'
        with self.assertRaises(exceptions.ParseError) as caught:
            parser.Parser(enable_let=True).parse(expression)
        self.assertEqual(caught.exception.lex_position, 14)
        self.assertIn('already bound', str(caught.exception))

    def test_default_and_let_compilation_caches_are_separate(self):
        expression = 'let'
        default_parsed = parser.Parser().parse(expression)
        let_parsed = parser.Parser(enable_let=True).parse(expression)
        self.assertEqual(default_parsed.parsed, ast.field('let'))
        self.assertEqual(let_parsed.parsed, ast.field('let'))
        self.assertIs(default_parsed, parser.Parser._CACHE[expression])
        self.assertIs(let_parsed, parser.Parser._LET_CACHE[expression])


if __name__ == '__main__':
    unittest.main()
