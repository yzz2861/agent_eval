import unittest

import jmespath
from jmespath import functions
from jmespath import exceptions


class CustomFunctions(functions.Functions):
    @functions.signature({'types': ['string', 'array', 'object', 'null']})
    def _func_length0(self, s):
        return 0 if s is None else len(s)


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


class LazyFunctions(functions.Functions):
    def __init__(self):
        self.counts = {}

    def _track(self, name):
        self.counts[name] = self.counts.get(name, 0) + 1
        return name

    @functions.signature({'types': ['string']})
    def _func_track(self, name):
        return self._track(name)

    @functions.signature({'types': []})
    def _func_boom(self, arg):
        raise ValueError('boom')

    @functions.lazy_signature(
        {'types': []}, {'types': []}, {'types': []})
    def _func_choose(self, condition, left, right):
        if condition():
            return left()
        return right()

    @functions.lazy_signature({'types': []})
    def _func_twice(self, arg):
        return [arg(), arg()]


class TestLazyFunctions(unittest.TestCase):
    def setUp(self):
        self.functions = LazyFunctions()
        self.options = jmespath.Options(custom_functions=self.functions)

    def search(self, expression, data=None):
        return jmespath.search(expression, data, self.options)

    def test_choose_selects_left_branch(self):
        result = self.search(
            "choose(`true`, track('left'), track('right'))")
        self.assertEqual(result, 'left')
        self.assertEqual(self.functions.counts, {'left': 1})

    def test_choose_selects_right_branch(self):
        result = self.search(
            "choose(`false`, track('left'), track('right'))")
        self.assertEqual(result, 'right')
        self.assertEqual(self.functions.counts, {'right': 1})

    def test_unused_branch_does_not_raise_type_error(self):
        # abs() on a string would raise JMESPathTypeError if evaluated.
        result = self.search("choose(`false`, abs('notanumber'), `42`)")
        self.assertEqual(result, 42)

    def test_used_branch_exception_propagates(self):
        with self.assertRaises(ValueError):
            self.search("choose(`true`, boom(`1`), `2`)")

    def test_used_branch_jmespath_error_propagates(self):
        with self.assertRaises(exceptions.JMESPathTypeError):
            self.search("choose(`true`, abs('notanumber'), `2`)")

    def test_argument_evaluated_at_most_once_per_call(self):
        result = self.search("twice(track('a'))")
        self.assertEqual(result, ['a', 'a'])
        self.assertEqual(self.functions.counts, {'a': 1})

    def test_lazy_arity_is_still_validated(self):
        with self.assertRaises(exceptions.ArityError):
            self.search("choose(`true`, track('left'))")
        # The arity error must be raised before anything is evaluated.
        self.assertEqual(self.functions.counts, {})

    def test_lazy_variadic_arity_is_validated(self):
        class VariadicLazy(functions.Functions):
            @functions.lazy_signature({'types': [], 'variadic': True})
            def _func_first(self, *args):
                return args[0]()
        options = jmespath.Options(custom_functions=VariadicLazy())
        with self.assertRaises(exceptions.VariadictArityError):
            jmespath.search('first()', {}, options)

    def test_no_cache_leak_across_projection_elements(self):
        data = [{'c': True}, {'c': False}, {'c': True}]
        result = self.search(
            "[*].choose(c, track('left'), track('right'))", data)
        self.assertEqual(result, ['left', 'right', 'left'])
        self.assertEqual(
            self.functions.counts, {'left': 2, 'right': 1})

    def test_no_cache_leak_across_search_calls(self):
        expression = "choose(`true`, track('left'), track('right'))"
        self.assertEqual(self.search(expression), 'left')
        self.assertEqual(self.search(expression), 'left')
        self.assertEqual(self.functions.counts, {'left': 2})

    def test_recursive_lazy_calls(self):
        result = self.search(
            "choose(`false`, track('left'), "
            "       choose(`true`, track('inner'), track('right')))")
        self.assertEqual(result, 'inner')
        self.assertEqual(self.functions.counts, {'inner': 1})

    def test_lazy_function_captures_current_node(self):
        data = {'items': [{'v': 1}, {'v': 2}]}
        result = self.search(
            "items[*].choose(`true`, v, `0`)", data)
        self.assertEqual(result, [1, 2])

    def test_eager_functions_still_type_checked(self):
        with self.assertRaises(exceptions.JMESPathTypeError):
            self.search("abs('notanumber')")
