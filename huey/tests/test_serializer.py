import datetime
import gzip
import json
import pickle
import unittest
import zlib

from huey.api import MemoryHuey
from huey.exceptions import SerializationError
from huey.exceptions import TaskException
from huey.serializer import JsonSerializer
from huey.serializer import SignedJsonSerializer
from huey.serializer import SignedSerializer
from huey.serializer import Serializer
from huey.tests.base import BaseTestCase
from huey.utils import Error
from huey.utils import SKIPPED


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


class TestJsonSerializer(BaseTestCase):
    def get_huey(self):
        return MemoryHuey(serializer=JsonSerializer())

    def sample_data(self):
        return (
            None, True, False, 1, 2.5, 'text', b'bytes',
            datetime.datetime(2026, 10, 2, 3, 4, 5,
                              tzinfo=datetime.timezone.utc),
            (1, (2, [3, {'__huey_type__': 'user-value',
                        'nested': [(b'key', ('x', [b'y']))]}])),
            [1, (2,), {'__huey_value__': {'tuple-key': (4, 5)}}],
            {'__huey_type__': 'plain-user-key',
             (1, 2): {'nested': b'value'}})

    def roundtrip(self, value, **kwargs):
        serializer = JsonSerializer(**kwargs)
        return serializer.deserialize(serializer.serialize(value))

    def test_supported_values(self):
        value = self.sample_data()
        self.assertEqual(self.roundtrip(value), value)
        self.assertEqual(self.roundtrip(SKIPPED), SKIPPED)

    def test_envelope_is_versioned_and_inspectable(self):
        payload = json.loads(JsonSerializer().serialize(self.sample_data()))
        self.assertEqual(payload['__huey_format__'], 'huey-json')
        self.assertEqual(payload['__huey_version__'], 1)
        self.assertEqual(payload['__huey_kind__'], 'value')
        self.assertIn('__huey_type__', json.dumps(payload))

    def test_user_dict_keys_do_not_conflict_with_type_tags(self):
        value = {
            '__huey_type__': 'type-name',
            '__huey_value__': 'tagged-value'}
        self.assertEqual(self.roundtrip(value), value)

    def test_unsupported_values_fail_when_serializing(self):
        with self.assertRaises(SerializationError):
            JsonSerializer().serialize({'value': object()})
        with self.assertRaises(SerializationError):
            JsonSerializer().serialize(float('nan'))

    def test_unknown_version_and_type_fail(self):
        serializer = JsonSerializer()
        payload = json.loads(serializer.serialize(self.sample_data()))
        payload['__huey_version__'] = 2
        with self.assertRaises(SerializationError):
            serializer.deserialize(json.dumps(payload).encode('utf8'))

        payload = json.loads(serializer.serialize(self.sample_data()))
        payload['future_envelope_field'] = True
        with self.assertRaises(SerializationError):
            serializer.deserialize(json.dumps(payload).encode('utf8'))

        payload = json.loads(serializer.serialize(self.sample_data()))
        payload['__huey_data__'][0] = {
            '__huey_type__': 'future-type',
            '__huey_value__': None}
        with self.assertRaises(SerializationError):
            serializer.deserialize(json.dumps(payload).encode('utf8'))

    def test_unknown_task_parameter_fails_before_execution(self):
        serializer = JsonSerializer()
        task = self.huey.task()(lambda: None).s()
        message = self.huey.serialize_task(task)
        payload = json.loads(message)
        payload['__huey_data__']['future_parameter'] = True

        with self.assertRaises(SerializationError):
                self.huey.deserialize_task(json.dumps(payload).encode('utf8'))
        self.assertEqual(self.huey.pending_count(), 0)

    def test_missing_task_parameter_fails_before_execution(self):
        serializer = JsonSerializer()
        task = self.huey.task()(lambda: None).s()
        message = self.huey._registry.create_message(task)
        payload = json.loads(serializer.serialize(message))
        del payload['__huey_data__']['args']

        with self.assertRaises(SerializationError):
            serializer.deserialize(json.dumps(payload).encode('utf8'))

    def test_unknown_chord_parameter_fails_before_execution(self):
        serializer = JsonSerializer()
        head = self.huey.task(name='json-head')(lambda value: value).s()
        callback = self.huey.task(name='json-callback')(
            lambda values: values).s()
        head.chord_config = type(
            'ChordConfig',
            (),
            {'cid': 'cid', 'size': 1, 'idx': 0,
             'callback': callback})()
        payload = json.loads(serializer.serialize(
            self.huey._registry.create_message(head)))
        payload['__huey_data__']['chord_config']['future'] = True

        with self.assertRaises(SerializationError):
            serializer.deserialize(json.dumps(payload).encode('utf8'))

    def test_aware_internal_schedule_time_fails_before_execution(self):
        serializer = JsonSerializer()
        task = self.huey.task()(lambda: None).s()
        message = self.huey._registry.create_message(task)
        message = message._replace(eta=datetime.datetime(
            2026, 10, 2, tzinfo=datetime.timezone.utc))

        with self.assertRaises(SerializationError):
            serializer.serialize(message)

    def test_pickle_requires_explicit_compatibility(self):
        legacy = Serializer().serialize(('legacy', self.sample_data()))

        with self.assertRaises(SerializationError):
            JsonSerializer().deserialize(legacy)

        self.assertEqual(
            JsonSerializer(allow_pickle=True).deserialize(legacy),
            ('legacy', self.sample_data()))

    def test_json_parse_failure_does_not_fall_back_to_pickle(self):
        serializer = JsonSerializer(allow_pickle=True)
        with self.assertRaises(SerializationError):
            serializer.deserialize(b'not json or pickle')
        with self.assertRaises(SerializationError):
            serializer.deserialize(b'{')

    @unittest.skipIf(gzip is None, 'gzip module not installed')
    def test_signed_json_and_compression(self):
        for use_zlib in (False, True):
            serializer = SignedJsonSerializer(
                secret='secret',
                compression=True,
                use_zlib=use_zlib)
            self.assertEqual(
                serializer.deserialize(serializer.serialize(self.sample_data())),
                self.sample_data())

    @unittest.skipIf(gzip is None, 'gzip module not installed')
    def test_signed_compressed_legacy_pickle_requires_flag(self):
        legacy = SignedSerializer(
            secret='secret', compression=True).serialize(('old',))

        with self.assertRaises(SerializationError):
            SignedJsonSerializer(secret='secret', compression=True).deserialize(
                legacy)

        decoded = SignedJsonSerializer(
            secret='secret',
            compression=True,
            allow_pickle=True).deserialize(legacy)
        self.assertEqual(decoded, ('old',))

    def test_error_result_roundtrip(self):
        metadata = {
            'error': 'ValueError(bad)',
            'retries': 0,
            'task_id': 'task-id',
            'traceback': 'traceback',
            'when': datetime.datetime(
                2026, 10, 2, tzinfo=datetime.timezone.utc)}
        serializer = JsonSerializer()
        result = serializer.deserialize(serializer.serialize(Error(metadata)))
        self.assertEqual(result.metadata, metadata)


class TestJsonHueyIntegration(BaseTestCase):
    def get_huey(self):
        return MemoryHuey(serializer=JsonSerializer())

    def make_hueys(self):
        return (
            MemoryHuey('json-producer', serializer=JsonSerializer()),
            MemoryHuey('json-consumer', serializer=JsonSerializer()))

    def transfer(self, producer, consumer):
        while producer.pending_count():
            consumer.storage.enqueue(producer.storage.dequeue())

    def sample_payload(self):
        return {
            'scalars': (None, True, 3, 4.5, 'text'),
            'bytes': b'binary',
            'when': datetime.datetime(
                2026, 10, 2, 5, 6, tzinfo=datetime.timezone.utc),
            'nested': [(1,), {'__huey_type__': 'ok'}],
            'tuple': (b'a', ('b', ['c']) )}

    def test_normal_task_complex_result_and_error(self):
        producer, consumer = self.make_hueys()
        payload = self.sample_payload()

        @producer.task(name='json-echo')
        def echo(value):
            return value

        @consumer.task(name='json-echo')
        def echo_consumer(value):
            return value

        @producer.task(name='json-fail')
        def fail():
            raise ValueError('bad')

        @consumer.task(name='json-fail')
        def fail_consumer():
            raise ValueError('bad')

        echo(payload)
        fail()
        self.transfer(producer, consumer)

        success = consumer.dequeue()
        failure = consumer.dequeue()
        self.assertEqual(consumer.execute(success), payload)
        self.assertEqual(consumer.result(success.id), payload)
        consumer.execute(failure)
        with self.assertRaises(TaskException) as cm:
            consumer.result(failure.id)
        self.assertEqual(cm.exception.metadata['error'], "ValueError('bad')")

    def test_retry_message(self):
        producer, consumer = self.make_hueys()
        state = {'calls': 0}
        payload = self.sample_payload()

        @producer.task(retries=1, name='json-retry')
        def flaky(value):
            state['calls'] += 1
            if state['calls'] == 1:
                raise ValueError('try again')
            return value

        @consumer.task(retries=1, name='json-retry')
        def flaky_consumer(value):
            state['calls'] += 1
            if state['calls'] == 1:
                raise ValueError('try again')
            return value

        flaky(payload)
        self.transfer(producer, consumer)

        first = consumer.dequeue()
        self.assertIsNone(consumer.execute(first))
        second = consumer.dequeue()
        self.assertEqual(second.id, first.id)
        self.assertEqual(second.retries, 0)
        self.assertEqual(second.args, (payload,))
        self.assertEqual(consumer.execute(second), payload)

    def test_pipeline_message(self):
        producer, consumer = self.make_hueys()
        payload = self.sample_payload()
        eta = datetime.datetime.now(datetime.timezone.utc) - \
            datetime.timedelta(minutes=1)

        @producer.task(name='json-pipe')
        def pipe(value):
            return (value,)

        @consumer.task(name='json-pipe')
        def pipe_consumer(value):
            return (value,)

        chain = pipe.s(payload, eta=eta).then(pipe).then(pipe)
        results = producer.enqueue(chain)
        self.transfer(producer, consumer)

        first = consumer.dequeue()
        self.assertIsNotNone(first.on_complete)
        self.assertEqual(
            first.eta,
            eta.astimezone(datetime.timezone.utc).replace(tzinfo=None))
        self.assertEqual(consumer.execute(first), (payload,))
        second = consumer.dequeue()
        self.assertEqual(consumer.execute(second), (payload,))
        third = consumer.dequeue()
        self.assertIsNone(third.on_complete)
        self.assertEqual(consumer.execute(third), (payload,))
        self.assertEqual([result.id for result in results],
                         [first.id, second.id, third.id])

    def test_chord_message(self):
        producer, consumer = self.make_hueys()
        first_payload = self.sample_payload()
        second_payload = (b'two', datetime.datetime(
            2026, 10, 2, tzinfo=datetime.timezone.utc))

        @producer.task(name='json-head')
        def head(value):
            return value

        @consumer.task(name='json-head')
        def head_consumer(value):
            return value

        @producer.task(name='json-agg')
        def aggregate(values):
            return {'values': values}

        @consumer.task(name='json-agg')
        def aggregate_consumer(values):
            return {'values': values}

        from huey.api import chord
        producer.enqueue(chord(
            [head.s(first_payload), head.s(second_payload)],
            aggregate.s()))
        self.transfer(producer, consumer)

        member_one = consumer.dequeue()
        member_two = consumer.dequeue()
        self.assertEqual(consumer.execute(member_one), first_payload)
        self.assertEqual(consumer.execute(member_two), second_payload)

        callback = consumer.dequeue()
        self.assertEqual(callback.args[0],
                         [first_payload, second_payload])
        self.assertEqual(consumer.execute(callback),
                         {'values': [first_payload, second_payload]})
