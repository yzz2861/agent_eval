import decimal
from decimal import Decimal

import pytest

import jmespath
from jmespath import exceptions, functions, parser


class CustomFunctions(jmespath.functions.Functions):
    @functions.signature({'types': ['number']}, {'types': ['number']})
    def _func_add(self, left, right):
        return left + right

    @functions.signature({'types': ['array-number']})
    def _func_nested_avg(self, values):
        return self.call_function('avg', [values])


class TestDecimalMode(object):
    def setup_method(self):
        self.options = jmespath.Options(decimal_mode=True)
        parser.Parser.purge()

    def test_numeric_literals_use_decimal(self):
        result = jmespath.search('`0.1`', {}, self.options)
        assert result == Decimal('0.1')
        assert type(result) is Decimal

    def test_integer_literal_in_json_literal_uses_decimal(self):
        result = jmespath.search('`123456789012345678901234567890`', {},
                                 self.options)
        assert result == Decimal('123456789012345678901234567890')
        assert type(result) is Decimal

    def test_bare_numbers_remain_integer_indices(self):
        result = jmespath.search('[1]', [Decimal('0'), Decimal('1')],
                                 self.options)
        assert result == Decimal('1')

    def test_sum_preserves_decimal_precision(self):
        result = jmespath.search('sum(`[0.1, 0.2]`)', {}, self.options)
        assert result == Decimal('0.3')
        assert type(result) is Decimal

    def test_avg_returns_decimal_for_integers(self):
        result = jmespath.search('avg(`[1, 2]`)', {}, self.options)
        assert result == Decimal('1.5')
        assert type(result) is Decimal

    def test_integer_and_decimal_aggregation_mixes_without_float(self):
        result = jmespath.search('sum(@)', [1, Decimal('0.1')], self.options)
        assert result == Decimal('1.1')
        assert type(result) is Decimal

    def test_integer_sum_preserves_integer_type(self):
        result = jmespath.search('sum(@)', [1, 2], self.options)
        assert result == 3
        assert type(result) is int

    def test_to_number_returns_decimal(self):
        result = jmespath.search('to_number(`"0.1"`)', {}, self.options)
        assert result == Decimal('0.1')
        assert type(result) is Decimal

    def test_to_number_accepts_integer_strings(self):
        result = jmespath.search('to_number(`"42"`)', {}, self.options)
        assert result == Decimal('42')
        assert type(result) is Decimal

    def test_to_number_rejects_booleans(self):
        assert jmespath.search('to_number(`true`)', {}, self.options) is None

    def test_float_input_is_normalized_to_decimal(self):
        result = jmespath.search('sum(@)', [0.1, 0.2], self.options)
        assert result == Decimal('0.3')
        assert type(result) is Decimal

    def test_non_finite_float_function_argument_is_a_type_error(self):
        with pytest.raises(exceptions.JMESPathTypeError, match='abs'):
            jmespath.search('abs(@)', float('nan'), self.options)

    def test_non_finite_decimal_function_argument_is_a_type_error(self):
        with pytest.raises(exceptions.JMESPathTypeError, match='sum'):
            jmespath.search('sum(@)', [Decimal('NaN')], self.options)

    def test_to_number_non_finite_string_returns_null(self):
        result = jmespath.search('to_number(`"NaN"`)', {}, self.options)
        assert result is None

    def test_to_number_non_finite_float_returns_null(self):
        result = jmespath.search('to_number(@)', float('nan'), self.options)
        assert result is None

    def test_non_finite_json_literal_keeps_lexer_error_style(self):
        try:
            jmespath.search('`NaN`', {}, self.options)
        except exceptions.LexerError as exc:
            assert 'Bad jmespath expression' in str(exc)
            assert 'Bad token NaN' in str(exc)
        else:
            raise AssertionError('LexerError was not raised')

    def test_ordering_comparison_normalizes_floats(self):
        assert jmespath.search('@ < `0.3`', 0.1 + 0.2, self.options) is False

    def test_non_finite_ordering_comparison_returns_null(self):
        assert jmespath.search('@ < `1`', float('nan'), self.options) is None

    def test_equality_does_not_match_boolean(self):
        assert jmespath.search('@ == `1`', True, self.options) is False
        assert jmespath.search('@ == `0`', False, self.options) is False

    def test_integer_and_decimal_equality_and_ordering(self):
        assert jmespath.search('@ == `1`', 1, self.options) is True
        assert jmespath.search('@ < `2`', 1, self.options) is True

    def test_sort_by_nested_expression_uses_decimal_keys(self):
        values = [
            {'value': {'amount': '10'}},
            {'value': {'amount': '2'}},
            {'value': {'amount': '0.3'}},
        ]
        result = jmespath.search(
            'sort_by(@, &to_number(value.amount))', values, self.options)
        assert [item['value']['amount'] for item in result] == [
            '0.3', '2', '10']

    def test_sort_mixes_integer_and_decimal_values(self):
        result = jmespath.search('sort(@)', [10, Decimal('2.5'), 3],
                                 self.options)
        assert result == [Decimal('2.5'), 3, 10]

    def test_custom_function_number_validation_knows_decimal_mode(self):
        options = jmespath.Options(
            decimal_mode=True, custom_functions=CustomFunctions())
        result = jmespath.search('add(`0.1`, `0.2`)', {}, options)
        assert result == Decimal('0.3')
        assert type(result) is Decimal

    def test_custom_function_normalizes_float_arguments(self):
        options = jmespath.Options(
            decimal_mode=True, custom_functions=CustomFunctions())
        result = jmespath.search('add(@, `1`)', 0.2, options)
        assert result == Decimal('1.2')
        assert type(result) is Decimal

    def test_custom_function_rejects_boolean_number_arguments(self):
        options = jmespath.Options(
            decimal_mode=True, custom_functions=CustomFunctions())
        with pytest.raises(exceptions.JMESPathTypeError, match='add'):
            jmespath.search('add(`true`, `1`)', {}, options)

    def test_nested_custom_function_keeps_decimal_mode(self):
        options = jmespath.Options(
            decimal_mode=True, custom_functions=CustomFunctions())
        result = jmespath.search('nested_avg(`[1, 2]`)', {}, options)
        assert result == Decimal('1.5')
        assert type(result) is Decimal

    def test_decimal_context_controls_aggregation_precision(self):
        options = jmespath.Options(
            decimal_mode=True,
            decimal_context=decimal.Context(prec=2))
        result = jmespath.search('avg(`[1, 200]`)', {}, options)
        assert result == Decimal('1E+2')

    def test_default_mode_keeps_json_float_conventions(self):
        result = jmespath.search('sum(`[0.1, 0.2]`)', {})
        assert result == 0.1 + 0.2
        assert type(result) is float

    def test_default_mode_rejects_decimal_function_arguments(self):
        with pytest.raises(exceptions.JMESPathTypeError, match='sum'):
            jmespath.search('sum(@)', [Decimal('1')])

    def test_default_cache_does_not_leak_into_decimal(self):
        expression = '`0.1`'
        default_result = jmespath.search(expression, {})
        decimal_result = jmespath.search(expression, {}, self.options)
        assert type(default_result) is float
        assert type(decimal_result) is Decimal

    def test_decimal_cache_does_not_leak_into_default(self):
        expression = '`0.1`'
        decimal_result = jmespath.search(expression, {}, self.options)
        default_result = jmespath.search(expression, {})
        assert type(decimal_result) is Decimal
        assert type(default_result) is float

    def test_compiled_result_reparses_when_search_mode_differs(self):
        compiled = jmespath.compile('`0.1`')
        assert type(compiled.search({})) is float
        assert type(compiled.search({}, self.options)) is Decimal

    def test_decimal_compile_uses_decimal_literals(self):
        compiled = jmespath.compile('`0.1`', self.options)
        assert type(compiled.search({}, self.options)) is Decimal

    def test_decimal_compilation_retains_mode_for_later_searches(self):
        compiled = jmespath.compile('sum(`[0.1, 0.2]`)', self.options)
        result = compiled.search({})
        assert result == Decimal('0.3')
        assert type(result) is Decimal
