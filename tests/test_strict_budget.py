"""Test strict Cache space budgets backed by the Reserve table."""

import io
import multiprocessing as mp
import os
import shutil
import tempfile
import time

import pytest

import diskcache as dc


pytestmark = pytest.mark.filterwarnings('ignore', category=dc.EmptyDirWarning)


def make_cache(**settings):
    directory = settings.pop('directory', None)
    if directory is None:
        directory = tempfile.mkdtemp()
    kwargs = dict(
        strict_size_limit=True,
        eviction_policy='none',
        cull_limit=0,
        disk_min_file_size=100,
        size_limit=100000,
    )
    kwargs.update(settings)
    return directory, dc.Cache(directory, **kwargs)


def val_files(directory):
    return [
        os.path.join(dirpath, filename)
        for dirpath, _dirs, files in os.walk(directory)
        for filename in files
        if filename.endswith('.val')
    ]


def test_default_settings_disable_strict_budget():
    assert dc.DEFAULT_SETTINGS['strict_size_limit'] == 0
    assert dc.DEFAULT_SETTINGS['size_exceed_policy'] == 'reject'
    assert dc.DEFAULT_SETTINGS['reserve_ttl'] == 60.0


def test_invalid_policy_rejected():
    directory, cache = make_cache()
    try:
        with pytest.raises(ValueError):
            cache.reset('size_exceed_policy', 'explode')
    finally:
        cache.close()
        shutil.rmtree(directory)


def test_reject_when_over_budget():
    directory, cache = make_cache()
    try:
        assert cache.set('a', b'x' * 40000)
        with pytest.raises(dc.QuotaExceeded):
            cache.set('b', b'y' * 70000)
        # The rejected value file must never be left on disk.
        assert cache.reset('size') == 40000
        assert sorted(cache) == ['a']
        assert len(val_files(directory)) == 1
        assert cache._sql('SELECT COUNT(*) FROM Reserve').fetchone()[0] == 0
        cache.check(fix=True)
    finally:
        cache.close()
        shutil.rmtree(directory)


def test_wait_policy_allows_eviction():
    directory, cache = make_cache(
        eviction_policy='least-recently-stored',
        size_exceed_policy='wait',
    )
    try:
        assert cache.set('a', b'x' * 40000)
        assert cache.set('b', b'y' * 70000)
        assert sorted(cache) == ['b']
        assert cache._sql('SELECT COUNT(*) FROM Reserve').fetchone()[0] == 0
    finally:
        cache.close()
        shutil.rmtree(directory)


def test_streaming_reserves_incrementally():
    directory, cache = make_cache()
    try:
        stream = io.BytesIO(b'z' * 60000)
        assert cache.set('stream', stream, read=True)
        assert cache['stream'] == b'z' * 60000
        assert cache._sql('SELECT COUNT(*) FROM Reserve').fetchone()[0] == 0

        with pytest.raises(dc.QuotaExceeded):
            cache.set(
                'too-big', io.BytesIO(b'q' * 50000), read=True,
            )
        assert sorted(cache) == ['stream']
        assert len(val_files(directory)) == 1
        assert cache._sql('SELECT COUNT(*) FROM Reserve').fetchone()[0] == 0
    finally:
        cache.close()
        shutil.rmtree(directory)


def test_overwrite_counts_coexistence():
    directory, cache = make_cache()
    try:
        assert cache.set('key', b'x' * 40000)
        with pytest.raises(dc.QuotaExceeded):
            cache.set('key', b'y' * 70000)
        # Original value remains usable after rejection.
        assert cache['key'] == b'x' * 40000
        assert cache.reset('size') == 40000
        assert len(val_files(directory)) == 1

        assert cache.set('key', b'z' * 50000)
        assert cache['key'] == b'z' * 50000
        assert cache.reset('size') == 50000
    finally:
        cache.close()
        shutil.rmtree(directory)


def test_add_failure_releases_reservation():
    directory, cache = make_cache()
    try:
        assert cache.add('a', b'x' * 40000)
        assert cache.add('a', b'y' * 20000) is False
        assert cache['a'] == b'x' * 40000
        with pytest.raises(dc.QuotaExceeded):
            cache.add('b', b'y' * 90000)
        assert cache._sql('SELECT COUNT(*) FROM Reserve').fetchone()[0] == 0
    finally:
        cache.close()
        shutil.rmtree(directory)


def test_push_failure_releases_reservation():
    directory, cache = make_cache()
    try:
        assert cache.push(b'x' * 40000) is not None
        with pytest.raises(dc.QuotaExceeded):
            cache.push(b'y' * 90000)
        assert cache._sql('SELECT COUNT(*) FROM Reserve').fetchone()[0] == 0
    finally:
        cache.close()
        shutil.rmtree(directory)


def test_wait_policy_times_out():
    directory, cache = make_cache(
        timeout=0.05, size_exceed_policy='wait',
    )
    try:
        assert cache.set('a', b'x' * 40000)
        start = time.time()
        with pytest.raises(dc.Timeout):
            cache.set('b', b'y' * 90000)
        assert time.time() - start >= 0.05
        assert cache._sql('SELECT COUNT(*) FROM Reserve').fetchone()[0] == 0
    finally:
        cache.close()
        shutil.rmtree(directory)


def test_wait_policy_proceeds_after_space_freed():
    directory, cache = make_cache(size_exceed_policy='wait')
    directory2, releaser = make_cache(
        directory=directory,
        strict_size_limit=True,
        eviction_policy='none',
        cull_limit=0,
        disk_min_file_size=100,
        size_limit=100000,
        size_exceed_policy='wait',
    )
    try:
        assert cache.set('a', b'x' * 90000)

        errors = []

        def write_later():
            try:
                time.sleep(0.2)
                releaser.delete('a')
            except BaseException as exc:  # pragma: no cover - diagnostic
                errors.append(exc)

        thread = __import__('threading').Thread(target=write_later)
        thread.start()
        assert cache.set('b', b'y' * 20000)
        thread.join()
        assert not errors
        assert cache['b'] == b'y' * 20000
    finally:
        cache.close()
        releaser.close()
        shutil.rmtree(directory)


def _mp_writer(args):
    directory, key, amount, queue = args
    cache = dc.Cache(
        directory, timeout=30, size_limit=100000,
        disk_min_file_size=100, strict_size_limit=True,
        eviction_policy='none', cull_limit=0,
    )
    try:
        cache.set(key, b'x' * amount)
        queue.put((key, True))
    except dc.QuotaExceeded:
        queue.put((key, False))
    finally:
        cache.close()


@pytest.mark.parametrize('trial', range(3))
def test_two_processes_compete_for_last_bytes(trial):
    context = mp.get_context('fork')
    directory = tempfile.mkdtemp()
    queue = context.Queue()
    processes = [
        context.Process(
            target=_mp_writer,
            args=((directory, 'a', 60000, queue),),
        ),
        context.Process(
            target=_mp_writer,
            args=((directory, 'b', 60000, queue),),
        ),
    ]
    try:
        for process in processes:
            process.start()
        results = sorted(queue.get() for _ in processes)
        for process in processes:
            process.join()

        assert results == [('a', False), ('b', True)] or results == [
            ('a', True), ('b', False),
        ]
        winners = [key for key, ok in results if ok]
        with dc.Cache(directory) as cache:
            assert sorted(cache) == winners
            assert cache.reset('size') == 60000
            assert cache._sql('SELECT COUNT(*) FROM Reserve').fetchone()[0] == 0
        assert len(val_files(directory)) == 1
    finally:
        for process in processes:
            process.terminate()
            process.join()
        shutil.rmtree(directory, ignore_errors=True)


def test_two_threads_compete_for_last_bytes():
    directory, cache = make_cache()
    results = []

    def write_value(key):
        try:
            cache.set(key, b'x' * 60000)
            results.append((key, True))
        except dc.QuotaExceeded:
            results.append((key, False))

    try:
        thread_a = __import__('threading').Thread(target=write_value, args=('a',))
        thread_b = __import__('threading').Thread(target=write_value, args=('b',))
        thread_a.start()
        thread_b.start()
        thread_a.join()
        thread_b.join()

        assert sorted(results) in (
            [('a', False), ('b', True)],
            [('a', True), ('b', False)],
        )
        winners = [key for key, ok in results if ok]
        assert sorted(cache) == winners
        assert len(val_files(directory)) == 1
        assert cache._sql('SELECT COUNT(*) FROM Reserve').fetchone()[0] == 0
    finally:
        cache.close()
        shutil.rmtree(directory)


class _SlowStream:
    def __init__(self, size, chunk, delay):
        self.remaining = size
        self.chunk = chunk
        self.delay = delay

    def read(self, _size=-1):
        if self.remaining <= 0:
            return b''
        time.sleep(self.delay)
        amount = min(self.chunk, self.remaining)
        self.remaining -= amount
        return b'x' * amount


def _mp_slow_writer(args):
    directory, started = args
    cache = dc.Cache(
        directory, timeout=30, size_limit=1000000,
        disk_min_file_size=10, strict_size_limit=True,
        eviction_policy='none', cull_limit=0, reserve_ttl=0.2,
    )
    started.set()
    try:
        cache.set('slow', _SlowStream(800000, 100000, 0.1), read=True)
    except Exception:
        pass
    finally:
        cache.close()


def test_crashed_streaming_reservation_is_reclaimed():
    context = mp.get_context('fork')
    directory = tempfile.mkdtemp()
    started = context.Event()
    process = context.Process(
        target=_mp_slow_writer, args=((directory, started),),
    )
    try:
        process.start()
        started.wait(5)
        time.sleep(0.35)

        with dc.Cache(directory) as cache:
            ((bytes_,),) = cache._sql(
                'SELECT bytes FROM Reserve'
            ).fetchall()
            assert bytes_ > 100000
            with pytest.raises(dc.QuotaExceeded):
                cache.set('other', b'y' * 900000)

        process.terminate()
        process.join()

        with dc.Cache(directory, reserve_ttl=0.0) as cache:
            time.sleep(0.3)
            cache._reserve_recover()
            assert cache._sql(
                'SELECT COUNT(*) FROM Reserve'
            ).fetchone()[0] == 0
            assert val_files(directory) == []
            assert cache.check(fix=True) == []
    finally:
        process.terminate()
        process.join()
        shutil.rmtree(directory, ignore_errors=True)


def test_stale_reservation_keeps_referenced_file():
    directory, cache = make_cache(reserve_ttl=-1)
    try:
        assert cache.set('a', b'x' * 10000)
        filename = cache._sql(
            "SELECT filename FROM Cache WHERE key = 'a'"
        ).fetchone()[0]
        # Simulate a leaked reservation left by a dead owner. The file is
        # already registered in Cache, so it must not be deleted.
        cache._sql(
            'INSERT INTO Reserve (pid, tid, updated, bytes, filename)'
            ' VALUES (?, ?, ?, ?, ?)',
            (99999999, 1, 0.0, 10000, filename),
        )
        cache._reserve_recover()
        assert cache._sql('SELECT COUNT(*) FROM Reserve').fetchone()[0] == 0
        assert cache['a'] == b'x' * 10000
        assert len(val_files(directory)) == 1
    finally:
        cache.close()
        shutil.rmtree(directory)


def test_fanout_cache_forwards_strict_settings():
    directory = tempfile.mkdtemp()
    try:
        cache = dc.FanoutCache(
            directory, shards=4, size_limit=200000,
            disk_min_file_size=100, strict_size_limit=True,
            eviction_policy='none', cull_limit=0,
        )
        assert cache.strict_size_limit == 1
        assert cache.size_limit == 50000
        with pytest.raises(dc.QuotaExceeded):
            cache.set('big', b'x' * 90000)
        cache.close()
    finally:
        shutil.rmtree(directory, ignore_errors=True)
