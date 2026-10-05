from decimal import Decimal, InvalidOperation, localcontext

from tests import unittest

import jmespath
from jmespath import exceptions
from jmespath import functions
from jmespath import parser


class DecimalTestCase(unittest.TestCase):
    def setUp(self):
        self.options = jmespath.Options(decimal_mode=True)
        self.data = {
            'a': Decimal('0.1'),
            'b': Decimal('0.2'),
            'nums': [Decimal('1'), 2, Decimal('0.30')],
            'floats': [0.1, 0.2],
            'items': [
                {'v': Decimal('0.1')},
                {'v': Decimal('0.2')},
                {'v': 3},
            ],
            'big': 10 ** 40,
        }

    def search(self, expression, data=None):
        return jmespath.search(expression, self.data if data is None else data,
                               options=self.options)

    def test_float_literal_becomes_decimal(self):
        result = self.search('`0.1`')
        self.assertIsInstance(result, Decimal)
        self.assertEqual(result, Decimal('0.1'))

    def test_integer_literal_stays_int(self):
        result = self.search('`5`')
        self.assertIs(result, 5)

    def test_non_finite_literal_raises_lexer_error(self):
        with self.assertRaises(exceptions.LexerError) as cm:
            self.search('`NaN`')
        self.assertIn('Bad token', str(cm.exception))
        with self.assertRaises(exceptions.LexerError):
            self.search('`Infinity`')

    def test_sum_preserves_decimal_precision(self):
        result = self.search('sum(nums)')
        self.assertIsInstance(result, Decimal)
        self.assertEqual(result, Decimal('3.30'))

    def test_sum_of_integer_literals_is_decimal(self):
        result = self.search('sum([`1`, `2`])', {})
        self.assertIsInstance(result, Decimal)
        self.assertEqual(result, Decimal('3'))

    def test_sum_empty_array_is_decimal_zero(self):
        result = self.search('sum(`[]`)', {})
        self.assertIsInstance(result, Decimal)
        self.assertEqual(result, Decimal(0))

    def test_sum_converts_float_input(self):
        result = self.search('sum(floats)')
        self.assertIsInstance(result, Decimal)
        self.assertEqual(result, Decimal('0.3'))

    def test_avg_is_decimal(self):
        result = self.search('avg(nums)')
        self.assertIsInstance(result, Decimal)
        self.assertEqual(result, Decimal('1.10'))

    def test_avg_uses_decimal_context(self):
        with localcontext() as ctx:
            ctx.prec = 2
            result = self.search('avg(nums)')
        self.assertEqual(result, Decimal('1.1'))
        with localcontext() as ctx:
            ctx.prec = 3
            result = jmespath.search(
                'avg(`[1, 2, 1]`)', {}, options=self.options)
        self.assertEqual(result, Decimal('1.33'))

    def test_abs_is_decimal(self):
        result = self.search('abs(a)')
        self.assertIsInstance(result, Decimal)
        self.assertEqual(result, Decimal('0.1'))

    def test_sort_with_mixed_int_and_decimal(self):
        result = self.search('sort(nums)')
        self.assertEqual(result, [Decimal('0.30'), Decimal('1'), 2])

    def test_sort_converts_float_elements(self):
        result = self.search('sort(floats)')
        self.assertEqual(result, [0.1, 0.2])

    def test_sort_by_uses_decimal_keys(self):
        result = self.search('sort_by(items, &v)')
        self.assertEqual(
            [item['v'] for item in result],
            [Decimal('0.1'), Decimal('0.2'), 3])

    def test_min_and_max(self):
        self.assertEqual(self.search('min(nums)'), Decimal('0.30'))
        self.assertEqual(self.search('max(nums)'), 2)
        self.assertEqual(
            self.search('max_by(items, &v).v'), 3)
        self.assertEqual(
            self.search('min_by(items, &v).v'), Decimal('0.1'))

    def test_ordering_comparison(self):
        self.assertTrue(self.search('a < b'))
        self.assertTrue(self.search('a <= a'))
        self.assertFalse(self.search('a > b'))
        self.assertTrue(self.search('b >= a'))

    def test_equality_with_literal(self):
        self.assertTrue(self.search('a == `0.1`'))
        self.assertFalse(self.search('a != `0.1`'))
        self.assertFalse(self.search('a == `0.1000000000000000055`'))
        self.assertFalse(self.search('a == `0.2`'))

    def test_float_input_compares_as_decimal(self):
        result = jmespath.search(
            'a == `0.1`', {'a': 0.1}, options=self.options)
        self.assertTrue(result)
        self.assertTrue(jmespath.search(
            'a < b', {'a': 0.1, 'b': Decimal('0.2')},
            options=self.options))

    def test_booleans_are_not_numbers(self):
        self.assertFalse(self.search('`true` == `1`', {}))
        self.assertFalse(self.search('`false` == `0`', {}))
        self.assertFalse(
            jmespath.search('a > `0`', {'a': True}, options=self.options))
        with self.assertRaises(exceptions.JMESPathTypeError):
            self.search('abs(`true`)', {})
        with self.assertRaises(exceptions.JMESPathTypeError):
            self.search('sum(`[true]`)', {})

    def test_type_function(self):
        self.assertEqual(self.search('type(a)'), 'number')
        self.assertEqual(self.search('type(`true`)'), 'boolean')

    def test_to_number_with_string(self):
        result = self.search('to_number(`"0.1"`)', {})
        self.assertIsInstance(result, Decimal)
        self.assertEqual(result, Decimal('0.1'))
        self.assertEqual(self.search('to_number(`"abc"`)', {}), None)

    def test_to_number_with_float_is_decimal(self):
        result = jmespath.search(
            'to_number(a)', {'a': 0.25}, options=self.options)
        self.assertEqual(result, Decimal('0.25'))
        self.assertIsInstance(result, Decimal)

    def test_to_number_non_finite_string_returns_null(self):
        self.assertIsNone(self.search('to_number(`"NaN"`)', {}))
        self.assertIsNone(self.search('to_number(`"Infinity"`)', {}))

    def test_non_finite_decimal_data_raises_value_error(self):
        with self.assertRaises(exceptions.JMESPathValueError) as cm:
            jmespath.search('sum(a)', {'a': [Decimal('NaN')]},
                            options=self.options)
        self.assertEqual(cm.exception.function_name, 'sum')
        self.assertIn('non-finite', str(cm.exception))
        with self.assertRaises(exceptions.JMESPathValueError):
            jmespath.search('a < b', {'a': Decimal('NaN'), 'b': 1},
                            options=self.options)
        with self.assertRaises(exceptions.JMESPathValueError):
            jmespath.search('avg(a)', {'a': [float('inf')]},
                            options=self.options)

    def test_non_finite_float_literal_nested_raises(self):
        with self.assertRaises(exceptions.LexerError):
            self.search('sum(`[1, NaN, 2]`)', {})
        with self.assertRaises(exceptions.LexerError):
            self.search('`{"x": Infinity}`', {})

    def test_sort_by_mixed_int_decimal_float_keys(self):
        items = [
            {'v': Decimal('0.3')},
            {'v': 0.1},
            {'v': 2},
        ]
        result = jmespath.search(
            'sort_by(items, &v)', {'items': items},
            options=self.options)
        self.assertEqual(
            [item['v'] for item in result], [0.1, Decimal('0.3'), 2])

    def test_avg_empty_array_is_null(self):
        self.assertIsNone(self.search('avg(`[]`)', {}))

    def test_large_integer_does_not_lose_precision(self):
        result = self.search('big')
        self.assertEqual(result, 10 ** 40)
        self.assertIsInstance(result, int)
        result = self.search('max(nums)', {'nums': [10 ** 40, 10 ** 20]})
        self.assertEqual(result, 10 ** 40)

    def test_nested_expression_composition(self):
        result = self.search(
            'sum([sum(nums), avg(nums), to_number(`"0.6"`)])')
        self.assertIsInstance(result, Decimal)
        self.assertEqual(result, Decimal('5.00'))

    def test_default_mode_keeps_float_semantics(self):
        result = jmespath.search('sum(`[0.1, 0.2]`)', {})
        self.assertIsInstance(result, float)
        self.assertNotEqual(result, Decimal('0.3'))
        self.assertEqual(jmespath.search('`0.1`', {}), 0.1)
        self.assertIsInstance(jmespath.search('`0.1`', {}), float)
        self.assertEqual(jmespath.search('to_number(`"5"`)', {}), 5)
        self.assertIsInstance(jmespath.search('to_number(`"5"`)', {}), int)

    def test_default_mode_rejects_decimal_in_number_signature(self):
        with self.assertRaises(exceptions.JMESPathTypeError):
            jmespath.search('abs(a)', {'a': Decimal('0.1')})

    def test_cache_isolated_between_modes(self):
        expression = '`0.1`'
        parser.Parser.purge()
        normal = jmespath.compile(expression)
        decimal = jmespath.compile(expression, decimal_mode=True)
        self.assertIsInstance(normal.search({}), float)
        self.assertIsInstance(decimal.search({}), Decimal)
        # Running a decimal search first must not poison later normal
        # searches (and vice versa), regardless of order.
        parser.Parser.purge()
        decimal_first = jmespath.compile(expression, decimal_mode=True)
        normal_after = jmespath.compile(expression)
        self.assertIsInstance(decimal_first.search({}), Decimal)
        self.assertIsInstance(normal_after.search({}), float)
        normal_again = jmespath.compile(expression)
        decimal_again = jmespath.compile(expression, decimal_mode=True)
        self.assertIsInstance(normal_again.search({}), float)
        self.assertIsInstance(decimal_again.search({}), Decimal)

    def test_search_helper_accepts_decimal_mode_flag(self):
        result = jmespath.search('sum(a)', {'a': [Decimal('0.1')]},
                                 decimal_mode=True)
        self.assertEqual(result, Decimal('0.1'))

    def test_compiled_decimal_uses_mode_without_options(self):
        compiled = jmespath.compile('sum(a)', decimal_mode=True)
        result = compiled.search({'a': [Decimal('0.1'), Decimal('0.2')]})
        self.assertEqual(result, Decimal('0.3'))
        self.assertIsInstance(result, Decimal)

    def test_compiled_result_mode_mismatch_raises(self):
        compiled = jmespath.compile('a < b')
        with self.assertRaises(exceptions.JMESPathError):
            compiled.search(
                {'a': 1, 'b': 2}, options=jmespath.Options(decimal_mode=True))


class CustomNumberFunctions(functions.Functions):
    @functions.signature({'types': ['number']})
    def _func_double(self, arg):
        if self.decimal_mode:
            return functions.to_decimal(arg, 'double') * Decimal('2')
        return arg * 2

    @functions.signature({'types': ['array-number']})
    def _func_total(self, arg):
        if self.decimal_mode:
            return sum(
                (functions.to_decimal(item, 'total') for item in arg),
                Decimal(0))
        return sum(arg)


class LegacyCustomFunctions(functions.Functions):
    # A subclass without an ``__init__`` override; the interpreter should
    # still propagate the active mode for its signature checks.
    @functions.signature({'types': ['number']})
    def _func_negate(self, arg):
        if self.decimal_mode:
            return -functions.to_decimal(arg, 'negate')
        return -arg


class LegacyCustomFunctionsTest(unittest.TestCase):
    def test_mode_injected_for_legacy_subclass(self):
        options = jmespath.Options(
            custom_functions=LegacyCustomFunctions(),
            decimal_mode=True)
        result = jmespath.search(
            'negate(a)', {'a': Decimal('0.1')}, options=options)
        self.assertEqual(result, Decimal('-0.1'))
        self.assertIsInstance(result, Decimal)


class CustomFunctionsDecimalTest(unittest.TestCase):
    def test_custom_function_number_check_knows_mode(self):
        options = jmespath.Options(
            custom_functions=CustomNumberFunctions(decimal_mode=True),
            decimal_mode=True)
        result = jmespath.search(
            'double(a)', {'a': Decimal('0.1')}, options=options)
        self.assertEqual(result, Decimal('0.2'))
        self.assertIsInstance(result, Decimal)
        result = jmespath.search(
            'total(a)', {'a': [Decimal('0.1'), 2, 0.2]}, options=options)
        self.assertEqual(result, Decimal('2.3'))

    def test_custom_function_still_rejects_boolean(self):
        options = jmespath.Options(
            custom_functions=CustomNumberFunctions(decimal_mode=True),
            decimal_mode=True)
        with self.assertRaises(exceptions.JMESPathTypeError):
            jmespath.search('double(a)', {'a': True}, options=options)

    def test_custom_function_default_mode_unchanged(self):
        options = jmespath.Options(
            custom_functions=CustomNumberFunctions())
        result = jmespath.search('double(a)', {'a': 0.1}, options=options)
        self.assertEqual(result, 0.2)
        self.assertIsInstance(result, float)
        with self.assertRaises(exceptions.JMESPathTypeError):
            jmespath.search(
                'double(a)', {'a': Decimal('0.1')}, options=options)


if __name__ == '__main__':
    unittest.main()
