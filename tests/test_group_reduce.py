from datetime import datetime
from tests import unittest

import jmespath
from jmespath import exceptions
from jmespath import functions


class TallyFunctions(functions.Functions):
    @functions.signature({'types': ['object']}, {'types': ['object']})
    def _func_tally(self, accumulator, item):
        accumulator['total'] += item['amount']
        accumulator['count'] += item.get('count', 0)
        return accumulator


class KeyTrackingFunctions(functions.Functions):
    def __init__(self):
        self.calls = []

    @functions.signature({'types': ['object']})
    def _func_tracked_key(self, item):
        self.calls.append((item['region'], item['kind']))
        return [item['region'], item['kind']]


class TestGroupReduce(unittest.TestCase):
    def test_groups_by_nested_keys_and_accumulates_fields(self):
        items = [
            {'group': {'region': 'east', 'kind': 'premium'},
             'amount': 10, 'count': 1},
            {'group': {'kind': 'premium', 'region': 'east'},
             'amount': 5, 'count': 2},
            {'group': ['west', 'standard'], 'amount': 7, 'count': 1},
            {'group': ['standard', 'west'], 'amount': 2, 'count': 1},
            {'flag': True, 'amount': 1},
            {'flag': 1, 'amount': 10},
            {'flag': True, 'amount': 2},
            {'amount': 4},
            {'flag': None, 'amount': 8},
        ]
        expression = (
            'group_reduce(@, &not_null(group, [flag]), &tally(acc, item), '
            '`{"total": 0, "count": 0}`)'
        )
        options = jmespath.Options(custom_functions=TallyFunctions())

        result = jmespath.search(expression, items, options)

        self.assertEqual(result, [
            {'key': {'region': 'east', 'kind': 'premium'},
             'value': {'total': 15, 'count': 3}},
            {'key': ['west', 'standard'],
             'value': {'total': 7, 'count': 1}},
            {'key': ['standard', 'west'],
             'value': {'total': 2, 'count': 1}},
            {'key': [True], 'value': {'total': 3, 'count': 0}},
            {'key': [1], 'value': {'total': 10, 'count': 0}},
            {'key': [None], 'value': {'total': 12, 'count': 0}},
        ])
        self.assertEqual(items[0], {
            'group': {'region': 'east', 'kind': 'premium'},
            'amount': 10, 'count': 1,
        })

    def test_each_group_gets_an_independent_initial_value(self):
        items = [
            {'group': 'first', 'amount': 3},
            {'group': 'second', 'amount': 5},
        ]
        expression = (
            'group_reduce(@, &group, &tally(acc, item), '
            '`{"total": 0, "count": 0}`)'
        )
        options = jmespath.Options(custom_functions=TallyFunctions())

        result = jmespath.search(expression, items, options)

        self.assertEqual(result[0]['value'], {'total': 3, 'count': 0})
        self.assertEqual(result[1]['value'], {'total': 5, 'count': 0})
        self.assertIsNot(result[0]['value'], result[1]['value'])

    def test_nested_initial_values_are_deep_copied(self):
        items = [
            {'group': 'first'},
            {'group': 'second'},
        ]

        class NestedTallyFunctions(functions.Functions):
            @functions.signature({'types': ['object']})
            def _func_nested_tally(self, accumulator):
                accumulator['totals']['amount'] += 1
                return accumulator

        result = jmespath.search(
            'group_reduce(@, &group, &nested_tally(acc), '
            '`{"totals": {"amount": 0}}`)',
            items,
            jmespath.Options(custom_functions=NestedTallyFunctions()))

        self.assertEqual(result, [
            {'key': 'first', 'value': {'totals': {'amount': 1}}},
            {'key': 'second', 'value': {'totals': {'amount': 1}}},
        ])

    def test_key_expression_is_evaluated_once_per_item(self):
        custom_functions = KeyTrackingFunctions()
        options = jmespath.Options(custom_functions=custom_functions)
        items = [
            {'region': 'east', 'kind': 'a'},
            {'region': 'west', 'kind': 'b'},
            {'region': 'east', 'kind': 'a'},
            {'region': 'east', 'kind': 'a'},
        ]

        result = jmespath.search(
            'group_reduce(@, &tracked_key(@), &acc, `0`)', items, options)

        self.assertEqual(custom_functions.calls, [
            ('east', 'a'), ('west', 'b'),
            ('east', 'a'), ('east', 'a'),
        ])
        self.assertEqual(result, [
            {'key': ['east', 'a'], 'value': 0},
            {'key': ['west', 'b'], 'value': 0},
        ])

    def test_rejects_non_json_key(self):
        with self.assertRaises(exceptions.JMESPathError) as error:
            jmespath.search(
                'group_reduce(@, &@, &acc, `0`)', [datetime(2020, 1, 1)])
        message = str(error.exception)
        self.assertIn('group_reduce()', message)
        self.assertIn('index 0', message)
        self.assertIn('expected a JSON value', message)

    def test_rejects_non_finite_number_key(self):
        with self.assertRaisesRegex(
                exceptions.JMESPathError,
                'index 0.*number must be finite'):
            jmespath.search(
                'group_reduce(@, &value, &acc, `0`)',
                [{'value': float('nan')}])

    def test_rejects_circular_key(self):
        cyclic = []
        cyclic.append(cyclic)
        with self.assertRaisesRegex(
                exceptions.JMESPathError, 'index 0.*circular reference'):
            jmespath.search(
                'group_reduce(@, &@, &acc, `0`)', [cyclic])

    def test_rejects_non_string_object_key(self):
        with self.assertRaisesRegex(
                exceptions.JMESPathError,
                'index 0.*object keys must be strings'):
            jmespath.search(
                'group_reduce(@, &@, &acc, `0`)', [{1: 'value'}])

    def test_validates_function_signature(self):
        with self.assertRaises(exceptions.ArityError):
            jmespath.search('group_reduce(@, &@, &acc)', [])
        with self.assertRaises(exceptions.JMESPathTypeError):
            jmespath.search('group_reduce(@, @, &acc, `0`)', {})
        with self.assertRaises(exceptions.JMESPathTypeError):
            jmespath.search('group_reduce(@, &@, acc, `0`)', [])
