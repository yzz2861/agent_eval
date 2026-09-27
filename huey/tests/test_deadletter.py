import datetime
import os
import threading
import time
import unittest

from huey.api import BlackHoleHuey
from huey.api import MemoryHuey
from huey.api import SqliteHuey
from huey.exceptions import ConfigurationError
from huey.registry import Message
from huey.storage import DeadLetter
from huey.storage import DeadLetterMetadata
from huey.tests.base import BaseTestCase


class DeadLetterTests(object):
    def get_huey(self, **kwargs):
        raise NotImplementedError

    def setUp(self):
        super(DeadLetterTests, self).setUp()
        self.huey = self.get_huey(dead_letters=True)

        @self.huey.task()
        def good_task(n):
            return n + 1

        self.good_task = good_task
        self.state = []

    def tearDown(self):
        self.huey.flush()
        super(DeadLetterTests, self).tearDown()

    def unknown_task_message(self, name='unknown_task', args=()):
        message = Message('task-id', '%s.%s' % (__name__, name), None, 0, 0,
                          None, args, {})
        return self.huey.serializer.serialize(message)

    def truncated_message(self):
        data = self.huey.serialize_task(self.good_task.s(999))
        return data[:len(data) // 2]

    def test_interleaved_good_and_bad_messages(self):
        self.good_task(1)
        self.huey.storage.enqueue(self.truncated_message())
        self.good_task(2)
        self.huey.storage.enqueue(self.unknown_task_message())
        self.good_task(3)

        tasks = [self.huey.dequeue() for _ in range(3)]
        self.assertEqual([task.args for task in tasks], [(1,), (2,), (3,)])
        self.assertIsNone(self.huey.dequeue())

        dead_letters = self.huey.dead_letters()
        self.assertEqual(len(dead_letters), 2)
        self.assertEqual(self.huey.dead_letter_count(), 2)
        for metadata in dead_letters:
            self.assertIsInstance(metadata, DeadLetterMetadata)
            self.assertFalse(hasattr(metadata, 'data'))
            self.assertTrue(metadata.id)
            self.assertIsInstance(metadata.timestamp, datetime.datetime)
            self.assertEqual(metadata.attempts, 1)
            self.assertEqual(metadata.queue, self.huey.name)
            self.assertTrue(metadata.error)
            self.assertTrue(metadata.size > 0)

    def test_record_contents(self):
        raw = self.unknown_task_message()
        self.huey.storage.enqueue(raw)
        self.assertIsNone(self.huey.dequeue())

        record_id, = [m.id for m in self.huey.dead_letters()]
        record = self.huey.get_dead_letter(record_id)
        self.assertIsInstance(record, DeadLetter)
        self.assertEqual(record.id, record_id)
        self.assertEqual(record.data, raw)
        self.assertEqual(record.queue, self.huey.name)
        self.assertEqual(record.attempts, 1)
        self.assertIn('unknown_task', record.error)

        # The truncated message records the deserialization error.
        self.huey.storage.enqueue(self.truncated_message())
        self.assertIsNone(self.huey.dequeue())
        errors = [m.error for m in self.huey.dead_letters()]
        self.assertEqual(len(errors), 2)

    def test_listing_does_not_deserialize(self):
        # A payload that would raise if deserialized is safe to list.
        self.huey.storage.enqueue(b'\x80\x04not-a-valid-message')
        self.assertIsNone(self.huey.dequeue())
        metadata, = self.huey.dead_letters()
        self.assertEqual(metadata.size, len(b'\x80\x04not-a-valid-message'))

    def test_stable_id_and_attempts(self):
        raw = self.unknown_task_message()
        for _ in range(3):
            self.huey.storage.enqueue(raw)
            self.assertIsNone(self.huey.dequeue())

        dead_letters = self.huey.dead_letters()
        self.assertEqual(len(dead_letters), 1)
        self.assertEqual(dead_letters[0].attempts, 3)

    def test_retention_limit(self):
        huey = self.get_huey(dead_letters=True, max_dead_letters=3)
        base = datetime.datetime(2024, 1, 1)
        for i in range(5):
            huey.storage.add_dead_letter(b'message-%d' % i, 'error-%d' % i,
                                         base + datetime.timedelta(hours=i))
        self.assertEqual(huey.dead_letter_count(), 3)
        errors = [m.error for m in huey.dead_letters()]
        self.assertEqual(errors, ['error-4', 'error-3', 'error-2'])

    def test_requeue_after_fix(self):
        # Message references a task that is not registered (yet).
        raw = self.unknown_task_message(name='later_task', args=(41,))
        self.huey.storage.enqueue(raw)
        self.assertIsNone(self.huey.dequeue())
        record_id, = [m.id for m in self.huey.dead_letters()]

        # "Deploy the fix": register the missing task.
        @self.huey.task(name='later_task')
        def later_task(n):
            return n + 1

        self.assertTrue(self.huey.requeue_dead_letter(record_id))
        self.assertEqual(self.huey.dead_letter_count(), 0)

        task = self.huey.dequeue()
        self.assertIsNotNone(task)
        self.assertEqual(task.execute(), 42)

    def test_requeue_unknown_record(self):
        self.assertFalse(self.huey.requeue_dead_letter('no-such-record'))

    def test_requeue_bad_message_is_requarantined(self):
        raw = self.unknown_task_message()
        self.huey.storage.enqueue(raw)
        self.assertIsNone(self.huey.dequeue())
        record_id, = [m.id for m in self.huey.dead_letters()]

        # Requeue without fixing the underlying problem: the message fails
        # again and lands back in the dead-letter store, attempts bumped.
        self.assertTrue(self.huey.requeue_dead_letter(record_id))
        self.assertIsNone(self.huey.dequeue())
        dead_letters = self.huey.dead_letters()
        self.assertEqual(len(dead_letters), 1)
        self.assertEqual(dead_letters[0].id, record_id)
        self.assertEqual(dead_letters[0].attempts, 2)

    def test_concurrent_requeue_succeeds_once(self):
        self.huey.storage.enqueue(self.unknown_task_message())
        self.assertIsNone(self.huey.dequeue())
        record_id, = [m.id for m in self.huey.dead_letters()]

        results = []
        def requeue():
            results.append(self.huey.requeue_dead_letter(record_id))

        threads = [threading.Thread(target=requeue) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(sorted(results), [False] * 7 + [True])
        self.assertEqual(self.huey.dead_letter_count(), 0)
        self.assertEqual(self.huey.pending_count(), 1)

    def test_failed_requeue_is_tracked(self):
        raw = self.unknown_task_message()
        self.huey.storage.enqueue(raw)
        self.assertIsNone(self.huey.dequeue())
        record_id, = [m.id for m in self.huey.dead_letters()]

        original_enqueue = self.huey.storage.enqueue
        def failing_enqueue(data, priority=None):
            raise IOError('storage unavailable')
        self.huey.storage.enqueue = failing_enqueue
        try:
            self.assertRaises(IOError, self.huey.requeue_dead_letter,
                              record_id)
        finally:
            self.huey.storage.enqueue = original_enqueue

        # The record is restored and the failure reason is tracked.
        self.assertEqual(self.huey.dead_letter_count(), 1)
        record = self.huey.get_dead_letter(record_id)
        self.assertEqual(record.data, raw)
        self.assertIn('requeue failed', record.error)
        self.assertIn('storage unavailable', record.error)

        # A subsequent requeue works fine.
        self.assertTrue(self.huey.requeue_dead_letter(record_id))

    def test_task_exception_not_quarantined(self):
        @self.huey.task()
        def failing_task():
            raise ValueError('business logic failure')

        failing_task()
        task = self.huey.dequeue()
        self.assertIsNotNone(task)
        self.huey.execute(task)

        # Normal task exceptions go through the retry/result flow.
        self.assertEqual(self.huey.dead_letter_count(), 0)
        self.assertEqual(self.huey.result_count(), 1)

    def test_disabled_by_default(self):
        huey = self.get_huey()
        huey.storage.enqueue(b'\x80\x04bad')
        self.assertRaises(Exception, huey.dequeue)
        self.assertRaises(ConfigurationError, huey.dead_letters)
        self.assertRaises(ConfigurationError, huey.requeue_dead_letter, 'x')

    def test_unsupported_storage(self):
        self.assertRaises(ConfigurationError, BlackHoleHuey,
                          dead_letters=True)

    def test_consumer_integration(self):
        @self.huey.task()
        def record_value(n):
            self.state.append(n)
            return n

        with self.consumer_context():
            r1 = record_value(1)
            self.huey.storage.enqueue(self.truncated_message())
            r2 = record_value(2)
            self.huey.storage.enqueue(self.unknown_task_message())
            r3 = record_value(3)

            # Good messages on either side of the bad ones are processed.
            self.assertEqual(r1.get(blocking=True, timeout=5), 1)
            self.assertEqual(r2.get(blocking=True, timeout=5), 2)
            self.assertEqual(r3.get(blocking=True, timeout=5), 3)

            # The bad messages end up in the dead-letter store.
            deadline = time.time() + 5
            while self.huey.dead_letter_count() < 2:
                self.assertTrue(time.time() < deadline)
                time.sleep(0.01)

        self.assertEqual(sorted(self.state), [1, 2, 3])
        self.assertEqual(self.huey.dead_letter_count(), 2)


class TestMemoryDeadLetters(DeadLetterTests, BaseTestCase):
    def get_huey(self, **kwargs):
        return MemoryHuey('test-dead-letters', utc=False, **kwargs)


class TestSqliteDeadLetters(DeadLetterTests, BaseTestCase):
    def get_huey(self, **kwargs):
        return SqliteHuey('test-dead-letters', filename='huey-dl-test.db',
                          utc=False, **kwargs)

    def tearDown(self):
        super(TestSqliteDeadLetters, self).tearDown()
        self.huey.storage.close()
        for suffix in ('', '-wal', '-shm'):
            filename = 'huey-dl-test.db' + suffix
            if os.path.exists(filename):
                os.unlink(filename)
