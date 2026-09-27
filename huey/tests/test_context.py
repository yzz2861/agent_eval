import contextvars
import datetime
import threading
import time

from huey.api import MemoryHuey
from huey.exceptions import ConfigurationError
from huey.tests.base import BaseTestCase


trace_id = contextvars.ContextVar('trace_id')
locale = contextvars.ContextVar('locale')
with_default = contextvars.ContextVar('with_default', default='en')


class TestContextCapture(BaseTestCase):
    def get_huey(self):
        return MemoryHuey(utc=False, context_vars=[trace_id, locale])

    def test_capture_on_enqueue(self):
        @self.huey.task()
        def task_a():
            pass

        token = trace_id.set('abc123')
        try:
            task_a()
        finally:
            trace_id.reset(token)

        task = self.huey.dequeue()
        self.assertEqual(task.context_snapshot, {'trace_id': 'abc123'})

    def test_unregistered_vars_not_captured(self):
        unregistered = contextvars.ContextVar('unregistered')

        @self.huey.task()
        def task_a():
            pass

        token = unregistered.set('nope')
        try:
            task_a()
        finally:
            unregistered.reset(token)

        task = self.huey.dequeue()
        self.assertEqual(task.context_snapshot, {})

    def test_unset_var_absent_from_snapshot(self):
        @self.huey.task()
        def task_a():
            pass

        token = locale.set('zh')
        try:
            task_a()
        finally:
            locale.reset(token)

        task = self.huey.dequeue()
        # trace_id was never set, so it is absent rather than None.
        self.assertEqual(task.context_snapshot, {'locale': 'zh'})

    def test_explicit_override(self):
        @self.huey.task()
        def task_a():
            pass

        token = trace_id.set('current')
        try:
            # Via the s() keyword argument.
            self.huey.enqueue(task_a.s(context_snapshot={'trace_id': 'x'}))
            # Via direct assignment on the task.
            task = task_a.s()
            task.context_snapshot = {'trace_id': 'y'}
            self.huey.enqueue(task)
            # Via schedule().
            task_a.schedule(delay=60,
                            context_snapshot={'trace_id': 'z'})
        finally:
            trace_id.reset(token)

        t1 = self.huey.dequeue()
        t2 = self.huey.dequeue()
        t3 = self.huey.dequeue()
        self.assertEqual(t1.context_snapshot, {'trace_id': 'x'})
        self.assertEqual(t2.context_snapshot, {'trace_id': 'y'})
        self.assertEqual(t3.context_snapshot, {'trace_id': 'z'})

    def test_delayed_task_uses_enqueue_time_value(self):
        @self.huey.task()
        def task_a():
            pass

        token = trace_id.set('at-enqueue')
        try:
            task_a.schedule(delay=60)
        finally:
            trace_id.reset(token)

        token = trace_id.set('after-enqueue')
        try:
            # The delayed task sits on the queue until a worker defers it to
            # the schedule; either way it keeps the enqueue-time snapshot.
            task = self.huey.dequeue()
            self.assertEqual(task.context_snapshot,
                             {'trace_id': 'at-enqueue'})

            # The worker defers it to the schedule, snapshot preserved.
            self.huey.execute(task)
            later = datetime.datetime.now() + datetime.timedelta(seconds=120)
            scheduled, = self.huey.read_schedule(later)
            self.assertEqual(scheduled.context_snapshot,
                             {'trace_id': 'at-enqueue'})

            # Simulate the scheduler moving the task onto the queue: the
            # snapshot captured at enqueue-time is preserved.
            self.huey.enqueue(scheduled)
            task = self.huey.dequeue()
            self.assertEqual(task.context_snapshot,
                             {'trace_id': 'at-enqueue'})
        finally:
            trace_id.reset(token)

    def test_snapshot_survives_serialization(self):
        @self.huey.task()
        def task_a(n):
            return n

        token = trace_id.set('xyz')
        try:
            task_a(1)
        finally:
            trace_id.reset(token)

        task = self.huey.dequeue()
        self.assertEqual(task.context_snapshot, {'trace_id': 'xyz'})

    def test_unserializable_value_raises(self):
        @self.huey.task()
        def task_a():
            pass

        token = trace_id.set(lambda: None)  # lambdas cannot be pickled.
        try:
            self.assertRaises(ConfigurationError, task_a)
        finally:
            trace_id.reset(token)

        self.assertEqual(len(self.huey), 0)

    def test_register_unregister(self):
        huey = MemoryHuey(utc=False)
        var = contextvars.ContextVar('dynamic')
        huey.register_context(var)
        self.assertRaises(TypeError, huey.register_context, 'not-a-var')

        @huey.task()
        def task_a():
            pass

        token = var.set('v1')
        try:
            task_a()
        finally:
            var.reset(token)
        task = huey.dequeue()
        self.assertEqual(task.context_snapshot, {'dynamic': 'v1'})

        self.assertTrue(huey.unregister_context(var))
        self.assertFalse(huey.unregister_context(var))
        task_a()
        task = huey.dequeue()
        self.assertTrue(task.context_snapshot is None)

    def test_no_registered_vars_is_noop(self):
        huey = MemoryHuey(utc=False)

        @huey.task()
        def task_a():
            return 1

        task_a()
        task = huey.dequeue()
        self.assertTrue(task.context_snapshot is None)
        self.assertEqual(huey.execute(task), 1)


class TestContextExecution(BaseTestCase):
    def get_huey(self):
        return MemoryHuey(utc=False, context_vars=[trace_id, locale])

    def test_restore_in_task_and_hooks(self):
        seen = {}

        @self.huey.pre_execute()
        def pre(task):
            seen['pre'] = trace_id.get()

        @self.huey.post_execute()
        def post(task, value, exc):
            seen['post'] = trace_id.get()

        @self.huey.task()
        def task_a():
            return trace_id.get()

        token = trace_id.set('tid-1')
        try:
            result = task_a()
        finally:
            trace_id.reset(token)

        # The caller's context no longer has the value.
        self.assertRaises(LookupError, trace_id.get)

        task = self.huey.dequeue()
        self.assertEqual(self.huey.execute(task), 'tid-1')
        self.assertEqual(seen, {'pre': 'tid-1', 'post': 'tid-1'})

        # Caller's context is unchanged after execution.
        self.assertRaises(LookupError, trace_id.get)

    def test_missing_value_is_unset_in_worker(self):
        @self.huey.task()
        def task_a():
            try:
                return trace_id.get()
            except LookupError:
                return 'unset'

        task_a()  # Enqueued with no trace_id set -> snapshot is {}.

        # Simulate a worker thread whose context holds a stale value.
        token = trace_id.set('stale-worker-value')
        try:
            task = self.huey.dequeue()
            self.assertEqual(task.context_snapshot, {})
            # The stale value must not leak into the task.
            self.assertEqual(self.huey.execute(task), 'unset')
            # The worker's own context is restored afterwards.
            self.assertEqual(trace_id.get(), 'stale-worker-value')
        finally:
            trace_id.reset(token)

    def test_retry_reuses_snapshot(self):
        @self.huey.task(retries=1)
        def task_a():
            raise ValueError('nope')

        token = trace_id.set('original')
        try:
            task_a()
        finally:
            trace_id.reset(token)

        task = self.huey.dequeue()
        original_snapshot = task.context_snapshot

        # Change the current context before the retry is requeued.
        token = trace_id.set('changed')
        try:
            self.huey.execute(task)
        finally:
            trace_id.reset(token)

        retried = self.huey.dequeue()
        self.assertEqual(retried.context_snapshot, original_snapshot)
        self.assertEqual(retried.context_snapshot, {'trace_id': 'original'})

    def test_child_task_captures_current_value(self):
        @self.huey.task()
        def child():
            pass

        @self.huey.task()
        def parent():
            trace_id.set('from-parent')
            child()  # Captures the value set by the parent.
            # Explicit override wins over the current value.
            self.huey.enqueue(child.s(
                context_snapshot={'trace_id': 'overridden'}))

        token = trace_id.set('from-web')
        try:
            parent()
        finally:
            trace_id.reset(token)

        task = self.huey.dequeue()
        self.huey.execute(task)

        child1 = self.huey.dequeue()
        child2 = self.huey.dequeue()
        self.assertEqual(child1.context_snapshot, {'trace_id': 'from-parent'})
        self.assertEqual(child2.context_snapshot,
                         {'trace_id': 'overridden'})

    def test_pipeline_child_inherits_parent_context(self):
        @self.huey.task()
        def task_b():
            return trace_id.get()

        @self.huey.task()
        def task_a():
            pass  # Return None so the child receives no extra argument.

        token = trace_id.set('pipeline-tid')
        try:
            pipe = task_a.s().then(task_b)
            results = self.huey.enqueue(pipe)
        finally:
            trace_id.reset(token)

        task = self.huey.dequeue()
        self.huey.execute(task)

        # The on_complete child was enqueued while the parent's context was
        # restored, so it inherits the parent's snapshot.
        child = self.huey.dequeue()
        self.assertEqual(child.context_snapshot, {'trace_id': 'pipeline-tid'})
        self.assertEqual(self.huey.execute(child), 'pipeline-tid')

    def test_deployment_mismatch(self):
        # Worker registers only a subset of the caller's variables.
        worker_huey = MemoryHuey(utc=False, context_vars=[trace_id])

        @worker_huey.task()
        def task_a():
            return trace_id.get()

        # Simulate a message produced by a deployment that also registered
        # "locale" and an unknown variable.
        task = task_a.s()
        task.context_snapshot = {'trace_id': 'tid', 'locale': 'zh',
                                 'unknown': 'x'}
        worker_huey.enqueue(task)

        task = worker_huey.dequeue()
        # Unknown entries are ignored; the task runs with what is registered.
        self.assertEqual(worker_huey.execute(task), 'tid')

    def test_immediate_mode(self):
        self.huey.immediate = True

        @self.huey.task()
        def task_a():
            return trace_id.get()

        token = trace_id.set('immediate-tid')
        try:
            result = task_a()
            self.assertEqual(result.get(), 'immediate-tid')
            # The caller's context is not polluted by the execution.
            self.assertEqual(trace_id.get(), 'immediate-tid')
        finally:
            trace_id.reset(token)

        self.assertRaises(LookupError, trace_id.get)


class TestContextThreadWorkers(BaseTestCase):
    def get_huey(self):
        return MemoryHuey(utc=False, context_vars=[trace_id])

    def test_concurrent_workers_isolated_contexts(self):
        release = threading.Event()
        started = []
        started_lock = threading.Lock()

        @self.huey.task()
        def task_a(expected):
            with started_lock:
                started.append(expected)
                if len(started) < 2:
                    # Wait until both workers are inside their tasks so the
                    # executions overlap.
                    deadline = time.monotonic() + 5
                    while len(started) < 2 and time.monotonic() < deadline:
                        time.sleep(0.01)
            return trace_id.get()

        with self.consumer_context(workers=2):
            token = trace_id.set('tid-1')
            try:
                r1 = task_a('tid-1')
            finally:
                trace_id.reset(token)
            token = trace_id.set('tid-2')
            try:
                r2 = task_a('tid-2')
            finally:
                trace_id.reset(token)

            self.assertEqual(r1.get(blocking=True, timeout=5), 'tid-1')
            self.assertEqual(r2.get(blocking=True, timeout=5), 'tid-2')

        self.assertEqual(sorted(started), ['tid-1', 'tid-2'])

    def test_worker_context_not_polluted_between_tasks(self):
        seen = []

        @self.huey.task()
        def task_a():
            return trace_id.get()

        @self.huey.task()
        def probe():
            # Runs with an empty snapshot; must not observe the value from
            # the previous task executed on the same worker thread.
            try:
                seen.append(trace_id.get())
            except LookupError:
                seen.append('unset')

        with self.consumer_context(workers=1):
            token = trace_id.set('tid-1')
            try:
                r1 = task_a()
            finally:
                trace_id.reset(token)
            self.assertEqual(r1.get(blocking=True, timeout=5), 'tid-1')

            probe()
            deadline = time.monotonic() + 5
            while not seen and time.monotonic() < deadline:
                time.sleep(0.01)

        self.assertEqual(seen, ['unset'])
