"""Unit tests for the SQLite idempotency store."""

from __future__ import annotations

import sqlite3
import time

import pytest

from falcon.idempotency import SQLiteIdempotencyStore
from falcon.idempotency.store import FingerprintMismatch
from falcon.idempotency.store import STATE_CREATED
from falcon.idempotency.store import STATE_PROCESSING
from falcon.idempotency.store import STATE_REPLAY
from falcon.idempotency.store import STATE_UNKNOWN


@pytest.fixture
def clock():
    return [1000.0]


@pytest.fixture
def store(tmp_path, clock):
    return SQLiteIdempotencyStore(
        str(tmp_path / 'idem.db'),
        lease_seconds=10.0,
        ttl_seconds=100.0,
        now=lambda: clock[0],
    )


def test_claim_replay_and_ttl(store, clock):
    first = store.acquire('u', '/r', 'k', b'fp')
    assert first.state == STATE_CREATED
    assert first.owner

    duplicate = store.acquire('u', '/r', 'k', b'fp')
    assert duplicate.state == STATE_PROCESSING

    with pytest.raises(FingerprintMismatch):
        store.acquire('u', '/r', 'k', b'different')

    assert store.renew_lease('u', '/r', 'k', first.owner)
    assert store.complete('u', '/r', 'k', first.owner, 201, [('X', 'y')], b'hello')

    replayed = store.acquire('u', '/r', 'k', b'fp')
    assert replayed.state == STATE_REPLAY
    assert replayed.record is not None
    assert replayed.record.status_code == 201
    assert replayed.record.headers == [['X', 'y']]
    assert replayed.record.body == b'hello'

    clock[0] += 101
    assert store.get('u', '/r', 'k') is None
    assert store.purge_expired() == 1


def test_expired_lease_flips_to_unknown(store, clock):
    first = store.acquire('u', '/r', 'k', b'fp')

    clock[0] += 11
    result = store.acquire('u', '/r', 'k', b'fp')
    assert result.state == STATE_UNKNOWN

    again = store.acquire('u', '/r', 'k', b'fp')
    assert again.state == STATE_UNKNOWN

    assert store.release('u', '/r', 'k')
    retried = store.acquire('u', '/r', 'k', b'fp')
    assert retried.state == STATE_CREATED
    assert retried.owner != first.owner


def test_expired_completed_record_is_replaced(store, clock):
    first = store.acquire('u', '/r', 'k', b'fp')
    store.complete('u', '/r', 'k', first.owner, 200, [], b'old')
    clock[0] += 200

    replaced = store.acquire('u', '/r', 'k', b'fp')
    assert replaced.state == STATE_CREATED


def test_late_completion_is_rejected(store, clock):
    first = store.acquire('u', '/r', 'k', b'fp')
    owner = first.owner

    clock[0] += 11
    assert store.acquire('u', '/r', 'k', b'fp').state == STATE_UNKNOWN

    assert not store.complete('u', '/r', 'k', owner, 200, [], b'late')
    assert not store.renew_lease('u', '/r', 'k', owner)
    record = store.get('u', '/r', 'k')
    assert record is not None
    assert record.body is None


def test_release_does_not_delete_completed_by_default(store):
    first = store.acquire('u', '/r', 'k', b'fp')
    store.complete('u', '/r', 'k', first.owner, 200, [], b'body')

    assert not store.release('u', '/r', 'k')
    assert store.acquire('u', '/r', 'k', b'fp').state == STATE_REPLAY
    assert store.release('u', '/r', 'k', allow_completed=True)
    assert store.acquire('u', '/r', 'k', b'fp').state == STATE_CREATED


def test_mark_unknown_is_idempotent_for_wrong_owner(store):
    store.acquire('u', '/r', 'k', b'fp')
    assert not store.mark_unknown('u', '/r', 'k', 'someone-else')


def test_lease_and_ttl_validation(tmp_path):
    with pytest.raises(ValueError):
        SQLiteIdempotencyStore(str(tmp_path / 'a.db'), lease_seconds=0)
    with pytest.raises(ValueError):
        SQLiteIdempotencyStore(str(tmp_path / 'b.db'), ttl_seconds=0)


def test_store_shares_schema_across_connections(tmp_path, store):
    first = store.acquire('u', '/r', 'k', b'fp')
    store.complete('u', '/r', 'k', first.owner, 204, [], b'')
    store.close()

    reopened = SQLiteIdempotencyStore._connect(store)
    rows = reopened.execute('SELECT status_code FROM idempotency_records').fetchall()
    assert rows[0]['status_code'] == 204


def test_infinite_ttl_keeps_record_indefinitely(tmp_path, clock):
    store = SQLiteIdempotencyStore(
        str(tmp_path / 'forever.db'), ttl_seconds=None, now=lambda: clock[0]
    )
    first = store.acquire('u', '/r', 'k', b'fp')
    store.complete('u', '/r', 'k', first.owner, 200, [], b'body')
    clock[0] += 10_000_000

    assert store.acquire('u', '/r', 'k', b'fp').state == STATE_REPLAY
    assert store.purge_expired() == 0


def test_release_missing_key_returns_false(store):
    assert not store.release('u', '/r', 'missing')
    assert not store.release('u', '/r', 'missing', allow_completed=True)


def test_close_without_connection_is_safe(tmp_path):
    store = SQLiteIdempotencyStore(str(tmp_path / 'c.db'))
    store.close()  # The main thread owns the init-time connection.
    store.close()


def test_per_record_ttl_overrides_default(store, clock):
    first = store.acquire('u', '/r', 'k', b'fp')
    assert store.complete('u', '/r', 'k', first.owner, 200, [], b'body', ttl_seconds=5)
    clock[0] += 6
    assert store.get('u', '/r', 'k') is None


def test_get_returns_none_for_absent(store):
    assert store.get('u', '/r', 'nope') is None


def test_wrong_owner_cannot_complete(store):
    store.acquire('u', '/r', 'k', b'fp')
    assert not store.complete('u', '/r', 'k', 'wrong', 200, [], b'')


def test_database_lock_is_retried(tmp_path, clock):
    import threading

    db = str(tmp_path / 'lock.db')
    holder = SQLiteIdempotencyStore(
        db,
        lease_seconds=30.0,
        busy_timeout_ms=50,
        now=lambda: clock[0],
    )
    waiter = SQLiteIdempotencyStore(db, busy_timeout_ms=50)
    release = threading.Event()

    def hold_lock():
        connection = holder._immediate()
        release.wait(timeout=5)
        connection.commit()

    thread = threading.Thread(target=hold_lock)
    thread.start()
    import time as time_mod

    time_mod.sleep(0.1)
    timer = threading.Timer(0.3, release.set)
    timer.start()
    result = waiter.acquire('u', '/r', 'k', b'fp')
    timer.join()
    thread.join(timeout=5)
    assert result.state == STATE_CREATED


def test_lock_retry_gives_up(tmp_path, clock, monkeypatch):
    db = str(tmp_path / 'giveup.db')
    holder = SQLiteIdempotencyStore(db, busy_timeout_ms=50)
    blocked = SQLiteIdempotencyStore(db, busy_timeout_ms=50)
    holder._immediate()
    monkeypatch.setattr(time, 'sleep', lambda seconds: None)
    with pytest.raises(sqlite3.OperationalError):
        blocked.acquire('u', '/r', 'locked', b'fp')


def test_rollback_on_error_during_write(store, monkeypatch):
    first = store.acquire('u', '/r', 'k', b'fp')

    def broken_json(*args, **kwargs):
        raise TypeError('boom')

    monkeypatch.setattr('falcon.idempotency.store.json.dumps', broken_json)
    with pytest.raises(TypeError):
        store.complete('u', '/r', 'k', first.owner, 200, [], b'body')

    record = store.get('u', '/r', 'k')
    assert record is not None
    assert record.status.value == 'processing'


@pytest.mark.parametrize(
    'method',
    [
        'renew_lease',
        'mark_unknown',
        'release',
        'purge_expired',
    ],
)
def test_write_helpers_rollback_on_error(store, monkeypatch, method):
    first = store.acquire('u', '/r', 'k', b'fp')

    def fail():
        raise sqlite3.OperationalError('disk I/O error')

    monkeypatch.setattr(store, '_immediate', fail)

    with pytest.raises(sqlite3.OperationalError):
        if method == 'renew_lease':
            store.renew_lease('u', '/r', 'k', first.owner)
        elif method == 'mark_unknown':
            store.mark_unknown('u', '/r', 'k', first.owner)
        elif method == 'release':
            store.release('u', '/r', 'k')
        else:
            store.purge_expired()


def test_memory_database_skips_wal_pragma():
    memory_store = SQLiteIdempotencyStore(':memory:')
    connection = memory_store._connect()
    mode = connection.execute('PRAGMA journal_mode').fetchone()[0]
    assert mode


def test_file_database_enables_wal(tmp_path):
    file_store = SQLiteIdempotencyStore(str(tmp_path / 'wal.db'))
    connection = file_store._connect()
    mode = connection.execute('PRAGMA journal_mode').fetchone()[0]
    assert mode.lower() == 'wal'


def test_renew_with_explicit_interval(store):
    first = store.acquire('u', '/r', 'k', b'fp')
    assert store.renew_lease('u', '/r', 'k', first.owner, lease_seconds=42)
    record = store.get('u', '/r', 'k')
    assert record is not None
    assert record.lease_expires_at == 1042.0
