#!/usr/bin/env python
from tests import unittest
from datetime import datetime, timedelta
import json

import jmespath
from jmespath import exceptions, functions


class GroupReduceFunctions(functions.Functions):
    def __init__(self):
        super(GroupReduceFunctions, self).__init__()
        self.key_calls = 0

    @functions.signature({'types': []})
    def _func_tracked_key(self, value):
        self.key_calls += 1
        return value

    @functions.signature({'types': ['object']})
    def _func_bump(self, value):
        value['count'] += 1
        value['events'].append(value['count'])
        return value


class TestFunctions(unittest.TestCase):

    def test_can_max_datetimes(self):
        # This is python specific behavior, but JMESPath does not specify what
        # you should do with language specific types.  We're going to add the
        # ability that ``to_string`` will always default to str()'ing values it
        # doesn't understand.
        data = [datetime.now(), datetime.now() + timedelta(seconds=1)]
        result = jmespath.search('max([*].to_string(@))', data)
        self.assertEqual(json.loads(result), str(data[-1]))

    def test_type_error_messages(self):
        with self.assertRaises(exceptions.JMESPathTypeError) as e:
            jmespath.search('length(@)', 2)
        exception = e.exception
        # 1. Function name should be in error message
        self.assertIn('length()', str(exception))
        # 2. Mention it's an invalid type
        self.assertIn('invalid type for value: 2', str(exception))
        # 3. Mention the valid types:
        self.assertIn("expected one of: ['string', 'array', 'object']",
                      str(exception))
        # 4. Mention the actual type.
        self.assertIn('received: "number"', str(exception))

    def test_singular_in_error_message(self):
        with self.assertRaises(exceptions.ArityError) as e:
            jmespath.search('length(@, @)', [0, 1])
        exception = e.exception
        self.assertEqual(
            str(exception),
            'Expected 1 argument for function length(), received 2')

    def test_error_message_is_pluralized(self):
        with self.assertRaises(exceptions.ArityError) as e:
            jmespath.search('sort_by(@)', [0, 1])
        exception = e.exception
        self.assertEqual(
            str(exception),
            'Expected 2 arguments for function sort_by(), received 1')

    def test_variadic_is_pluralized(self):
        with self.assertRaises(exceptions.VariadictArityError) as e:
            jmespath.search('not_null()', 'foo')
        exception = e.exception
        self.assertEqual(
            str(exception),
            'Expected at least 1 argument for function not_null(), received 0')

    def test_group_reduce_nested_composite_keys_and_fields(self):
        items = [
            {'region': 'east', 'tags': {'env': 'prod', 'tier': 'a'},
             'quantity': 2},
            {'region': 'west', 'tags': {'env': 'dev'}, 'quantity': 1},
            {'region': 'east', 'tags': {'tier': 'a', 'env': 'prod'},
             'quantity': 3},
        ]
        expression = (
            'group_reduce('
            'items, '
            '&[region, tags], '
            '&merge(acc, {count: sum([acc.count, `1`]), '
            'quantity: sum([acc.quantity, item.quantity]), '
            'last_index: index}), '
            '`{"count": 0, "quantity": 0}`)'
        )

        result = jmespath.search(expression, {'items': items})

        self.assertEqual(result, [
            {'key': ['east', {'env': 'prod', 'tier': 'a'}],
             'value': {'count': 2, 'quantity': 5, 'last_index': 2}},
            {'key': ['west', {'env': 'dev'}],
             'value': {'count': 1, 'quantity': 1, 'last_index': 1}},
        ])

    def test_group_reduce_preserves_first_seen_order_and_type_identity(self):
        items = [
            {'key': 'b'}, {'key': 'a'}, {'key': 'b'},
            {'key': True}, {'key': 1}, {'key': 1.0},
            {'key': '1'}, {'key': None}, {},
            {'key': [1, 2]}, {'key': [2, 1]},
        ]
        expression = (
            'group_reduce(@, &key, '
            '&merge(acc, {count: sum([acc.count, `1`])}), '
            '`{"count": 0}`)'
        )

        result = jmespath.search(expression, items)

        self.assertEqual(
            [entry['key'] for entry in result],
            ['b', 'a', True, 1, '1', None, [1, 2], [2, 1]]
        )
        counts = [entry['value']['count'] for entry in result]
        self.assertEqual(counts, [2, 1, 1, 2, 1, 2, 1, 1])

    def test_group_reduce_evaluates_key_once_and_copies_initial(self):
        custom_functions = GroupReduceFunctions()
        options = jmespath.Options(custom_functions=custom_functions)
        items = [
            {'group': 'a', 'value': 1},
            {'group': 'b', 'value': 2},
            {'group': 'a', 'value': 3},
        ]
        expression = (
            'group_reduce(@, &tracked_key(group), &bump(acc), '
            '`{"count": 0, "events": []}`)'
        )

        result = jmespath.search(expression, items, options=options)

        self.assertEqual(custom_functions.key_calls, 3)
        self.assertEqual(result, [
            {'key': 'a', 'value': {'count': 2, 'events': [1, 2]}},
            {'key': 'b', 'value': {'count': 1, 'events': [1]}},
        ])
        self.assertEqual(items, [
            {'group': 'a', 'value': 1},
            {'group': 'b', 'value': 2},
            {'group': 'a', 'value': 3},
        ])

    def test_group_reduce_rejects_non_json_key(self):
        expression = 'group_reduce(@, &@, &acc, `0`)'

        with self.assertRaises(exceptions.JMESPathValueError) as error:
            jmespath.search(expression, [datetime.now()])

        self.assertIn('group_reduce()', str(error.exception))
        self.assertIn('key must be a JSON scalar, array, or object',
                      str(error.exception))
        self.assertIn('array index 0', str(error.exception))

    def test_group_reduce_rejects_nested_non_json_key_with_path(self):
        expression = 'group_reduce(@, &key, &acc, `0`)'
        items = [{'key': {'meta': [datetime.now()]}}]

        with self.assertRaises(exceptions.JMESPathValueError) as error:
            jmespath.search(expression, items)

        message = str(error.exception)
        self.assertIn('$.meta[0]', message)
        self.assertIn('array index 0', message)

    def test_group_reduce_validates_signature_and_expression_refs(self):
        with self.assertRaises(exceptions.ArityError):
            jmespath.search('group_reduce(@, &@, &acc)', [])

        with self.assertRaises(exceptions.JMESPathTypeError):
            jmespath.search('group_reduce(@, &@, &acc, `0`)', {})

        with self.assertRaises(exceptions.JMESPathTypeError):
            jmespath.search('group_reduce(@, missing_key, &acc, `0`)',
                            [{'missing_key': 'x'}])

    def test_group_reduce_rejects_circular_nested_key(self):
        circular = []
        circular.append(circular)
        expression = 'group_reduce(@, &@, &acc, `0`)'

        with self.assertRaises(exceptions.JMESPathValueError) as error:
            jmespath.search(expression, [circular])

        self.assertIn('key contains a circular reference',
                      str(error.exception))
        self.assertIn('$[0]', str(error.exception))
