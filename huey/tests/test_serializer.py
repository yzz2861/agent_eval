try:
    import gzip
except ImportError:
    gzip = None
import datetime
import json
import pickle
import unittest
try:
    import zlib
except ImportError:
    zlib = None

from huey.api import MemoryHuey
from huey.api import Result
from huey.api import chord
from huey.exceptions import RetryTask
from huey.exceptions import SerializerError
from huey.exceptions import TaskException
from huey.registry import Message
from huey.serializer import JsonSerializer
from huey.serializer import Serializer
from huey.serializer import SignedJsonSerializer
from huey.tests.base import BaseTestCase
from huey.utils import Error


class TestSerializer(BaseTestCase):
    data = [
        None,
        0, 1,
        b'a' * 1024,
        ['k1', 'k2', 'k3'],
        {'k1': 'v1', 'k2': 'v2', 'k3': 'v3'}]

    def _test_serializer(self, s):
        for item in self.data:
            self.assertEqual(s.deserialize(s.serialize(item)), item)

    def test_serializer(self):
        self._test_serializer(Serializer())

    @unittest.skipIf(gzip is None, 'gzip module not installed')
    def test_serializer_gzip(self):
        self._test_serializer(Serializer(compression=True))

    @unittest.skipIf(zlib is None, 'zlib module not installed')
    def test_serializer_zlib(self):
        self._test_serializer(Serializer(compression=True, use_zlib=True))

    @unittest.skipIf(zlib is None, 'zlib module not installed')
    @unittest.skipIf(gzip is None, 'gzip module not installed')
    def test_mismatched_compression(self):
        for use_zlib in (False, True):
            s = Serializer()
            scomp = Serializer(compression=True, use_zlib=use_zlib)
            for item in self.data:
                self.assertEqual(scomp.deserialize(s.serialize(item)), item)


UTC = datetime.timezone.utc
TZ8 = datetime.timezone(datetime.timedelta(hours=8))
AWARE_DT = datetime.datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)
NAIVE_DT = datetime.datetime(2026, 1, 2, 3, 4, 5, 123456)


class TestJsonSerializer(BaseTestCase):
    data = [
        None,
        True, False,
        0, 1, -1,
        3.14159,
        '', 'hello', '\u4f60\u597d',
        b'', b'\x00\x01\xff' * 128,
        AWARE_DT,
        AWARE_DT.astimezone(TZ8),
        NAIVE_DT,
        (), (1, 'a', None, b'x'),
        [], [1, [2, [3, [4]]]],
        {}, {'k1': 'v1', 'k2': 2},
        {1: 'int-key', (1, 2): 'tuple-key', None: 'none-key'},
        # User dictionaries may use the reserved tag key without colliding
        # with the type-tagging machinery.
        {'__huey__': 'user-value'},
        {'__huey__': ['bytes', 'not-a-tag'], 'nested': {'__huey__': []}},
        Error({'error': 'boom', 'retries': 1, 'traceback': 'tb',
               'task_id': 'abc'}),
        Message('task-id', 'module.Task'),
        Message('task-id', 'module.Task', AWARE_DT, 3, 10, -1, (1, b'x'),
                {'k': NAIVE_DT}, None, None, None, None, None, None, None),
        {'mixed': [b'x', {'dt': AWARE_DT}, (1, 2), None], 's': 'v'},
    ]

    def _test_serializer(self, s):
        for item in self.data:
            self.assertEqual(s.deserialize(s.serialize(item)), item)

    def test_json_serializer(self):
        self._test_serializer(JsonSerializer())

    @unittest.skipIf(gzip is None, 'gzip module not installed')
    def test_json_serializer_gzip(self):
        self._test_serializer(JsonSerializer(compression=True))

    @unittest.skipIf(zlib is None, 'zlib module not installed')
    def test_json_serializer_zlib(self):
        self._test_serializer(JsonSerializer(compression=True, use_zlib=True))

    @unittest.skipIf(zlib is None, 'zlib module not installed')
    @unittest.skipIf(gzip is None, 'gzip module not installed')
    def test_json_mismatched_compression(self):
        for use_zlib in (False, True):
            s = JsonSerializer()
            scomp = JsonSerializer(compression=True, use_zlib=use_zlib)
            for item in self.data:
                self.assertEqual(scomp.deserialize(s.serialize(item)), item)

    def test_json_output_is_inspectable(self):
        s = JsonSerializer()
        message = json.loads(s.serialize({'task': 'x', 'when': AWARE_DT}))
        self.assertEqual(message['version'], 1)
        self.assertIn('data', message)

    def test_unknown_version(self):
        s = JsonSerializer()
        for payload in (
                json.dumps({'version': 0, 'data': None}),
                json.dumps({'version': 99, 'data': None}),
                json.dumps({'data': None}),
                json.dumps(['not', 'an', 'envelope'])):
            self.assertRaises(SerializerError, s.deserialize,
                              payload.encode('utf-8'))

    def test_unknown_type_tag(self):
        s = JsonSerializer()
        for data in ({'__huey__': ['set', [1, 2]]},
                     {'__huey__': ['frobnicate']},
                     {'__huey__': []},
                     {'untagged': 'dict'},
                     {'__huey__': ['bytes']}):
            payload = json.dumps({'version': 1, 'data': data})
            self.assertRaises(SerializerError, s.deserialize,
                              payload.encode('utf-8'))

    def test_unsupported_types_rejected_on_serialize(self):
        s = JsonSerializer()
        for value in ({1, 2}, object(), lambda: None, Exception('x'),
                      {'k': {1, 2}}, [object()]):
            self.assertRaises(SerializerError, s.serialize, value)

    def test_pickle_messages_rejected_by_default(self):
        legacy = pickle.dumps({'a': [1, 2, b'x']})
        s = JsonSerializer()
        try:
            s.deserialize(legacy)
        except SerializerError as exc:
            self.assertIn('allow_pickle', str(exc))
        else:
            self.fail('expected SerializerError')

    def test_pickle_compat_read(self):
        value = {'a': [1, 2, b'x'], 't': (1, 2)}
        legacy = pickle.dumps(value)
        s = JsonSerializer(allow_pickle=True)
        self.assertEqual(s.deserialize(legacy), value)
        # Corrupt data raises a clear error even with compat reads enabled.
        self.assertRaises(SerializerError, s.deserialize, b'\x80not-pickle')

    def test_signed_json_serializer(self):
        s = SignedJsonSerializer(secret='test secret')
        self._test_serializer(s)

        data = bytearray(s.serialize({'k': 'v'}))
        data[5] ^= 0x01
        self.assertRaises(ValueError, s.deserialize, bytes(data))

    def test_signed_json_serializer_with_compression(self):
        s = SignedJsonSerializer(secret='test secret', compression=True)
        self._test_serializer(s)

    def test_signed_json_serializer_requires_secret(self):
        from huey.exceptions import ConfigurationError
        self.assertRaises(ConfigurationError, SignedJsonSerializer)


def _json_first(a, b, when=None):
    return {'total': a + b, 'when': when, 'payload': b'\xde\xad'}

def _json_second(total=None, when=None, payload=None, label=None):
    return (label, total, when, payload)

def _json_sum(results):
    return sum(result['total'] for result in results)

def _json_fail():
    raise KeyError('boom')

def _json_retry():
    raise RetryTask('try again')


class TestJsonSerializerInterop(BaseTestCase):
    """
    Two independent Huey instances (e.g. separate deployments) share a
    queue: one serializes messages, the other deserializes and executes
    them, and vice-versa.
    """
    def _make_huey(self, name):
        huey = MemoryHuey(name, serializer=JsonSerializer())
        tasks = {
            'first': huey.task()(_json_first),
            'second': huey.task()(_json_second),
            'sum': huey.task()(_json_sum),
            'fail': huey.task()(_json_fail),
            'retry': huey.task(retries=3)(_json_retry),
        }
        return huey, tasks

    def setUp(self):
        super(TestJsonSerializerInterop, self).setUp()
        self.huey_a, self.task_a = self._make_huey('json-a')
        self.huey_b, self.task_b = self._make_huey('json-b')

    def transfer(self, src, dst):
        moved = 0
        while True:
            raw = src.storage.dequeue()
            if raw is None:
                return moved
            dst.storage.enqueue(raw)
            moved += 1

    def test_pipeline_roundtrip(self):
        eta = AWARE_DT
        task = self.task_a['first'].s(2, 3, when=eta, eta=eta)
        task.then(self.task_a['second'].s(label='stage-2'))
        self.huey_a.enqueue(task)
        # eta is normalized to naive UTC by Huey; compare against that.
        timestamp = task.eta + datetime.timedelta(seconds=1)

        # The serialized message is consumed by the second Huey instance.
        self.assertEqual(self.transfer(self.huey_a, self.huey_b), 1)
        task_b = self.huey_b.dequeue()
        self.assertEqual(task_b.id, task.id)
        self.assertEqual(task_b.args, (2, 3))
        self.assertEqual(task_b.kwargs, {'when': eta})
        self.assertIsNotNone(task_b.kwargs['when'].tzinfo)
        # Huey normalizes eta to a naive UTC datetime; the round-trip
        # through the second instance preserves it exactly.
        self.assertEqual(task_b.eta, task.eta)
        self.assertIsInstance(task_b.eta, datetime.datetime)
        self.assertTrue(task_b.on_complete is not None)
        self.assertEqual(task_b.on_complete.kwargs, {'label': 'stage-2'})

        self.huey_b.execute(task_b, timestamp=timestamp)

        # The pipeline continuation is enqueued by the consumer instance.
        next_b = self.huey_b.dequeue()
        self.assertTrue(next_b is not None)
        self.huey_b.execute(next_b, timestamp=timestamp)

        # Result values round-trip with types intact.
        result_1 = Result(self.huey_b, task_b)
        self.assertEqual(result_1.get(),
                         {'total': 5, 'when': eta, 'payload': b'\xde\xad'})
        result_2 = Result(self.huey_b, next_b)
        value = result_2.get()
        self.assertEqual(value, ('stage-2', 5, eta, b'\xde\xad'))
        self.assertIsInstance(value, tuple)
        self.assertIsInstance(value[2], datetime.datetime)
        self.assertIsNotNone(value[2].tzinfo)
        self.assertIsInstance(value[3], bytes)

    def test_retry_message_roundtrip(self):
        timestamp = AWARE_DT
        task = self.task_a['retry'].s()
        self.huey_a.enqueue(task)
        self.assertEqual(self.transfer(self.huey_a, self.huey_b), 1)

        task_b = self.huey_b.dequeue()
        self.huey_b.execute(task_b, timestamp=timestamp)

        # The retried message was re-serialized by huey_b; consume it on
        # huey_a to prove retry messages round-trip in both directions.
        self.assertEqual(self.transfer(self.huey_b, self.huey_a), 1)
        retried = self.huey_a.dequeue()
        self.assertEqual(retried.id, task.id)
        self.assertEqual(retried.retries, 3)
        self.huey_a.execute(retried, timestamp=timestamp)
        self.assertEqual(self.huey_a.storage.queue_size(), 1)

    def test_chord_roundtrip(self):
        timestamp = AWARE_DT
        c = chord([self.task_a['first'].s(1, 1),
                   self.task_a['first'].s(2, 2)],
                  self.task_a['sum'].s())
        self.huey_a.enqueue(c)
        self.assertEqual(self.transfer(self.huey_a, self.huey_b), 2)

        for _ in range(2):
            member = self.huey_b.dequeue()
            self.assertTrue(member is not None)
            self.assertTrue(member.chord_config is not None)
            self.huey_b.execute(member, timestamp=timestamp)

        # The chord callback fires once all members have completed.
        callback = self.huey_b.dequeue()
        self.assertTrue(callback is not None)
        self.huey_b.execute(callback, timestamp=timestamp)
        self.assertEqual(Result(self.huey_b, callback).get(), 6)

    def test_error_result_roundtrip(self):
        timestamp = AWARE_DT
        task = self.task_a['fail'].s()
        self.huey_a.enqueue(task)
        self.assertEqual(self.transfer(self.huey_a, self.huey_b), 1)

        task_b = self.huey_b.dequeue()
        self.huey_b.execute(task_b, timestamp=timestamp)

        result = Result(self.huey_b, task_b)
        raw = result.get_raw_result()
        self.assertIsInstance(raw, Error)
        self.assertEqual(raw.metadata['task_id'], task.id)
        self.assertIn('KeyError', raw.metadata['error'])
        self.assertRaises(TaskException, result.get)
