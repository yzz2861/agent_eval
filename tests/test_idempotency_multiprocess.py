"""Two-process integration tests for shared SQLite idempotency storage."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

from falcon.idempotency import SQLiteIdempotencyStore

HELPER = str(Path(__file__).with_name('idempotency_multiprocess_helper.py'))
REPO_ROOT = str(Path(__file__).resolve().parent.parent)


def _run_worker(tmp_path: Path, db_name: str, mode: str, env_extra=None):
    db_path = str(tmp_path / db_name)
    out_path = tmp_path / f'out-{mode}-{os.getpid()}-{threading.get_ident()}.json'
    env = dict(os.environ)
    env['PYTHONPATH'] = REPO_ROOT + os.pathsep + env.get('PYTHONPATH', '')
    if env_extra:
        env.update(env_extra)

    proc = subprocess.run(
        [sys.executable, HELPER, db_path, mode, str(out_path)],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return proc, db_path, out_path


def _read_result(out_path: Path):
    deadline = time.time() + 10
    while not out_path.exists() and time.time() < deadline:
        time.sleep(0.02)
    return json.loads(out_path.read_text(encoding='utf-8'))


def test_two_instances_concurrent_submit_then_replay(tmp_path):
    box = {}

    def submit_owner():
        proc, db_path, out_path = _run_worker(
            tmp_path,
            'a.db',
            'owner',
            {'IDEMPOTENCY_OWNER_DELAY': '2'},
        )
        box['proc'] = proc
        box['result'] = _read_result(out_path)

    worker = threading.Thread(target=submit_owner)
    worker.start()

    # Give the owner process time to claim the shared key.
    time.sleep(0.8)

    proc, _, out_path = _run_worker(tmp_path, 'a.db', 'concurrent')
    concurrent = _read_result(out_path)
    assert proc.returncode == 0
    assert concurrent['status'] == 409
    assert concurrent['headers'].get('retry-after')

    worker.join(timeout=30)
    owner_result = box['result']
    assert box['proc'].returncode == 0
    assert owner_result['status'] == 201
    assert owner_result['body'] == 'shared-result'

    # A third process (fresh app instance) replays from the shared database.
    proc, _, out_path = _run_worker(tmp_path, 'a.db', 'third')
    replay = _read_result(out_path)
    assert proc.returncode == 0
    assert replay['status'] == 201
    assert replay['body'] == 'shared-result'

    calls = (tmp_path / 'business-calls.txt').read_text(encoding='ascii')
    assert calls == 'x'


def test_owner_crash_before_commit_blocks_retry_until_release(tmp_path):
    calls_path = tmp_path / 'business-calls.txt'
    env = {'IDEMPOTENCY_TEST_LEASE': '2'}

    crashed, db_path, _ = _run_worker(tmp_path, 'b.db', 'crash', env)
    assert crashed.returncode == 2

    # The business side effect happened, but no response was committed.
    assert calls_path.read_text(encoding='ascii') == 'x'

    store = SQLiteIdempotencyStore(db_path, lease_seconds=2.0)
    record = store.get('Bearer user-1', '/orders', 'shared-key')
    assert record is not None
    assert record.status.value == 'processing'

    # Once the lease expires, another instance must not re-run the responder.
    time.sleep(2.2)
    retry, _, out_path = _run_worker(tmp_path, 'b.db', 'retry', env)
    result = _read_result(out_path)
    assert retry.returncode == 0
    assert result['status'] == 409
    assert calls_path.read_text(encoding='ascii') == 'x'

    # The key stays blocked for the caller until an administrator releases it.
    assert store.release('Bearer user-1', '/orders', 'shared-key')
    retried, _, out_path = _run_worker(tmp_path, 'b.db', 'released', env)
    fresh = _read_result(out_path)
    assert retried.returncode == 0
    assert fresh['status'] == 200
    assert calls_path.read_text(encoding='ascii') == 'xx'
