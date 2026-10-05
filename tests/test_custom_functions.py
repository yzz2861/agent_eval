import unittest

import jmespath
from jmespath import exceptions
from jmespath import functions


class CustomFunctions(functions.Functions):
    @functions.signature({'types': ['string', 'array', 'object', 'null']})
    def _func_length0(self, s):
        return 0 if s is None else len(s)


class BranchError(Exception):
    pass


class LazyFunctions(functions.Functions):
    def __init__(self):
        self.calls = {}

    @functions.lazy_signature(
        {'types': ['boolean']}, {'types': []}, {'types': []})
    def _func_choose(self, condition, left, right):
        if condition():
            return left()
        return right()

    @functions.lazy_signature({'types': []})
    def _func_call_twice(self, argument):
        argument()
        return argument.get()

    @functions.signature({'types': []})
    def _func_counted(self, value):
        self.calls[value] = self.calls.get(value, 0) + 1
        return value

    @functions.signature({'types': []})
    def _func_fail(self, value):
        self.calls[value] = self.calls.get(value, 0) + 1
        raise BranchError(value)

    @functions.signature({'types': ['number']})
    def _func_number_only(self, value):
        return value


class TestCustomFunctions(unittest.TestCase):
    def setUp(self):
        self.options = jmespath.Options(custom_functions=CustomFunctions())

    def test_null_to_nonetype(self):
        data = {
            'a': {
                'b': [1, 2, 3]
            }
        }

        self.assertEqual(jmespath.search('length0(a.b)', data, self.options), 3)
        self.assertEqual(jmespath.search('length0(a.c)', data, self.options), 0)


class TestLazyCustomFunctions(unittest.TestCase):
    def setUp(self):
        self.functions = LazyFunctions()
        self.options = jmespath.Options(custom_functions=self.functions)

    def test_only_selected_branch_is_evaluated(self):
        data = {'condition': False, 'selected': 'right', 'unused': 'left'}
        result = jmespath.search(
            'choose(condition, counted(unused), counted(selected))',
            data, self.options)
        self.assertEqual(result, 'right')
        self.assertEqual(self.functions.calls, {'right': 1})

    def test_unselected_branch_does_not_raise_type_error(self):
        data = {'condition': False, 'selected': 'right', 'unused': 'left'}
        result = jmespath.search(
            'choose(condition, number_only(unused), selected)',
            data, self.options)
        self.assertEqual(result, 'right')

    def test_selected_branch_type_error_is_raised(self):
        data = {'condition': True, 'selected': 'right', 'unused': 'left'}
        with self.assertRaises(exceptions.JMESPathTypeError):
            jmespath.search(
                'choose(condition, number_only(selected), unused)',
                data, self.options)

    def test_selected_branch_exception_keeps_type(self):
        data = {'condition': True, 'selected': 'right'}
        with self.assertRaises(BranchError):
            jmespath.search(
                'choose(condition, fail(selected), selected)',
                data, self.options)
        self.assertEqual(self.functions.calls, {'right': 1})

    def test_exception_is_cached_for_repeated_evaluation(self):
        with self.assertRaises(BranchError):
            jmespath.search(
                'call_twice(fail(value))',
                {'value': 'once'}, self.options)
        self.assertEqual(self.functions.calls, {'once': 1})

    def test_argument_is_evaluated_at_most_once(self):
        result = jmespath.search(
            'call_twice(counted(value))',
            {'value': 'once'}, self.options)
        self.assertEqual(result, 'once')
        self.assertEqual(self.functions.calls, {'once': 1})

    def test_nested_lazy_arguments_are_each_cached(self):
        result = jmespath.search(
            'call_twice(call_twice(counted(value)))',
            {'value': 'once'}, self.options)
        self.assertEqual(result, 'once')
        self.assertEqual(self.functions.calls, {'once': 1})

    def test_argument_cache_is_per_projection_element(self):
        data = [
            {'value': 'first'},
            {'value': 'second'},
        ]
        result = jmespath.search(
            '[*].call_twice(counted(value))', data, self.options)
        self.assertEqual(result, ['first', 'second'])
        self.assertEqual(self.functions.calls,
                         {'first': 1, 'second': 1})

    def test_argument_cache_does_not_leak_between_searches(self):
        data = {'value': 'once'}
        expression = 'call_twice(counted(value))'
        self.assertEqual(jmespath.search(expression, data, self.options), 'once')
        self.assertEqual(jmespath.search(expression, data, self.options), 'once')
        self.assertEqual(self.functions.calls, {'once': 2})

    def test_arity_is_validated_before_arguments(self):
        with self.assertRaises(exceptions.ArityError):
            jmespath.search(
                'choose(condition, counted(value))',
                {'condition': True, 'value': 'evaluated'}, self.options)
        self.assertEqual(self.functions.calls, {})

    def test_lazy_functions_capture_current_node_recursively(self):
        data = {
            'outer': True,
            'inner': False,
            'a': 'a',
            'b': 'b',
            'c': 'c',
            'd': 'd',
        }
        result = jmespath.search(
            'choose(outer, choose(inner, a, b), choose(inner, c, d))',
            data, self.options)
        self.assertEqual(result, 'b')

    def test_lazy_arguments_capture_projection_current_node(self):
        data = [
            {'take': True, 'value': 'first', 'other': 'not first'},
            {'take': False, 'value': 'not second', 'other': 'second'},
        ]
        result = jmespath.search(
            '[*].call_twice(choose(@.take, counted(@.value), counted(@.other)))',
            data, self.options)
        self.assertEqual(result, ['first', 'second'])
        self.assertEqual(self.functions.calls,
                         {'first': 1, 'second': 1})

    def test_lazy_function_can_be_called_directly(self):
        argument = functions.LazyArgument(lambda: 'value')
        result = self.functions.call_function(
            'call_twice', [argument])
        self.assertEqual(result, 'value')

    def test_direct_lazy_function_arity_is_validated(self):
        with self.assertRaises(exceptions.ArityError):
            self.functions.call_function('call_twice', [])
