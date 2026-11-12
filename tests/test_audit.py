"""Tests for the explicitly opt-in audit-chain formatter and handler."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import io
import json
import logging
from pathlib import Path
import threading

import pytest

from pythonjsonlogger.audit import (
    AUDIT_FIELD,
    AuditAnchor,
    AuditConfigurationError,
    AuditFileHandler,
    AuditFormatter,
    AuditIntegrityError,
    AuditKey,
    AuditKeyRing,
    AuditVerifier,
    AuditWriteError,
    canonical_json,
    verify_audit_chain,
)
from pythonjsonlogger.json import JsonFormatter

OLD_KEY = "old-secret-value-that-must-never-appear"
NEW_KEY = "new-secret-value-that-must-never-appear"


def _records(lines: str | bytes) -> list[dict]:
    text = lines.decode("utf-8") if isinstance(lines, bytes) else lines
    return [json.loads(line) for line in text.splitlines()]


def _verify(lines: str | bytes, formatter: AuditFormatter) -> object:
    verifier = AuditVerifier(formatter.key_ring)
    return verifier.verify(
        lines,
        anchor=AuditAnchor.genesis(formatter.chain_id),
    )


def test_valid_chain_replays_from_genesis_anchor() -> None:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    formatter = AuditFormatter(keys={"k1": OLD_KEY}, key_id="k1", chain_id="audit-chain")
    handler.setFormatter(formatter)
    logger = logging.getLogger("pythonjsonlogger.tests.audit.valid")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    try:
        logger.info("login failed", extra={"actor": "alice", "event": "login_failed"})
        logger.info("login succeeded", extra={"actor": "bob", "event": "login_ok"})
    finally:
        logger.removeHandler(handler)

    records = _records(stream.getvalue())
    assert [record[AUDIT_FIELD]["seq"] for record in records] == [0, 1]
    assert records[0][AUDIT_FIELD]["prev_digest"] == AuditAnchor.genesis("audit-chain").digest
    assert records[1][AUDIT_FIELD]["prev_digest"] == AuditAnchor.from_record(records[0]).digest

    result = _verify(stream.getvalue(), formatter)
    assert result.count == 2
    assert result.sequence == 1


def test_tampered_field_is_rejected() -> None:
    stream = io.StringIO()
    formatter = AuditFormatter(keys={"k1": OLD_KEY}, chain_id="tamper-chain")
    handler = logging.StreamHandler(stream)
    handler.setFormatter(formatter)
    logger = logging.getLogger("pythonjsonlogger.tests.audit.tamper")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    try:
        logger.info("one", extra={"actor": "alice"})
        logger.info("two", extra={"actor": "bob"})
    finally:
        logger.removeHandler(handler)

    records = _records(stream.getvalue())
    records[1]["actor"] = "mallory"
    tampered = "\n".join(canonical_json(record) for record in records)
    with pytest.raises(AuditIntegrityError, match="HMAC"):
        _verify(tampered, formatter)


def test_deleted_middle_record_is_rejected() -> None:
    formatter = AuditFormatter(keys={"k1": OLD_KEY}, chain_id="delete-chain")
    lines = [
        formatter.build_record(
            logging.LogRecord("n", logging.INFO, "", 0, f"message {i}", (), None)
        ).line
        for i in range(3)
    ]
    with pytest.raises(AuditIntegrityError, match="seq"):
        _verify("\n".join([lines[0], lines[2]]), formatter)


def test_reordered_records_are_rejected() -> None:
    formatter = AuditFormatter(keys={"k1": OLD_KEY}, chain_id="reorder-chain")
    lines = [
        formatter.build_record(
            logging.LogRecord("n", logging.INFO, "", 0, f"message {i}", (), None)
        ).line
        for i in range(3)
    ]
    with pytest.raises(AuditIntegrityError, match="seq"):
        _verify("\n".join([lines[0], lines[2], lines[1]]), formatter)


def test_cross_file_splice_is_rejected() -> None:
    formatter_a = AuditFormatter(keys={"k1": OLD_KEY}, chain_id="file-a")
    formatter_b = AuditFormatter(keys={"k1": OLD_KEY}, chain_id="file-b")
    lines_a = [
        formatter_a.build_record(
            logging.LogRecord("n", logging.INFO, "", 0, f"a{i}", (), None)
        ).line
        for i in range(2)
    ]
    lines_b = [
        formatter_b.build_record(
            logging.LogRecord("n", logging.INFO, "", 0, f"b{i}", (), None)
        ).line
        for i in range(2)
    ]
    spliced = "\n".join(lines_a + lines_b)
    with pytest.raises(AuditIntegrityError, match="cross-file splice"):
        _verify(spliced, formatter_a)


def test_empty_stream_is_valid_with_and_without_anchor() -> None:
    verifier = AuditVerifier(keys={"k1": OLD_KEY})
    empty = verifier.verify([])
    assert empty.count == 0
    assert empty.head is None
    assert AuditVerifier().verify([]).count == 0

    anchor = AuditAnchor.genesis("empty-chain")
    empty_anchored = verifier.verify([], anchor=anchor)
    assert empty_anchored.count == 0
    assert empty_anchored.head == anchor


def test_concurrent_writes_are_serialized_and_chain_replays() -> None:
    path = Path(__file__).resolve().parent / "_audit_concurrent.jsonl"
    if path.exists():
        path.unlink()
    handler = AuditFileHandler(path, keys={"k1": OLD_KEY}, key_id="k1", chain_id="concurrent-chain")
    logger = logging.getLogger("pythonjsonlogger.tests.audit.concurrent")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)

    def emit(index: int) -> None:
        logger.info("concurrent record", extra={"worker_index": index})

    try:
        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(emit, range(200)))
    finally:
        logger.removeHandler(handler)
        handler.close()

    try:
        records = _records(path.read_bytes())
        assert [record[AUDIT_FIELD]["seq"] for record in records] == list(range(200))
        result = AuditVerifier(keys={"k1": OLD_KEY}).verify_file(
            path, anchor=AuditAnchor.genesis("concurrent-chain")
        )
        assert result.count == 200
    finally:
        path.unlink(missing_ok=True)


def test_crash_recovery_resumes_without_duplicate_sequence_numbers() -> None:
    path = Path(__file__).resolve().parent / "_audit_recovery.jsonl"
    if path.exists():
        path.unlink()
    keys = {"k1": OLD_KEY}
    try:
        first = AuditFileHandler(path, keys=keys, key_id="k1", chain_id="recovery-chain")
        logger = logging.getLogger("pythonjsonlogger.tests.audit.recovery")
        logger.setLevel(logging.INFO)
        logger.addHandler(first)
        try:
            for index in range(3):
                logger.info("before crash", extra={"index": index})
        finally:
            logger.removeHandler(first)
            first.close()

        # Simulate a process crashing in the middle of a line write.
        with path.open("ab") as handle:
            handle.write(b'{"_audit":{"seq":3,"chain')

        second = AuditFileHandler(path, keys=keys, key_id="k1", chain_id="recovery-chain")
        logger.addHandler(second)
        try:
            logger.info("after recovery", extra={"actor": "carol"})
        finally:
            logger.removeHandler(second)
            second.close()

        records = _records(path.read_bytes())
        assert [record[AUDIT_FIELD]["seq"] for record in records] == [0, 1, 2, 3]
        result = AuditVerifier(keys=keys).verify_file(
            path, anchor=AuditAnchor.genesis("recovery-chain")
        )
        assert result.count == 4
    finally:
        path.unlink(missing_ok=True)


def test_key_rotation_records_key_ids_and_verifies_old_and_new() -> None:
    formatter = AuditFormatter(keys={"old": OLD_KEY}, key_id="old", chain_id="rotation-chain")
    lines: list[str] = []
    for index in range(2):
        lines.append(
            formatter.build_record(
                logging.LogRecord("n", logging.INFO, "", 0, f"old {index}", (), None)
            ).line
        )
    formatter.rotate_key("new", NEW_KEY)
    for index in range(2):
        lines.append(
            formatter.build_record(
                logging.LogRecord("n", logging.INFO, "", 0, f"new {index}", (), None)
            ).line
        )

    records = _records("\n".join(lines))
    assert [record[AUDIT_FIELD]["key_id"] for record in records] == [
        "old",
        "old",
        "new",
        "new",
    ]
    result = AuditVerifier(formatter.key_ring).verify(
        lines, anchor=AuditAnchor.genesis("rotation-chain")
    )
    assert result.count == 4

    old_only = AuditVerifier(keys={"old": OLD_KEY})
    with pytest.raises(AuditIntegrityError, match="key ID"):
        old_only.verify(lines, anchor=AuditAnchor.genesis("rotation-chain"))


def test_key_rotation_and_recovery_through_file_handler() -> None:
    path = Path(__file__).resolve().parent / "_audit_rotation_recovery.jsonl"
    if path.exists():
        path.unlink()
    logger = logging.getLogger("pythonjsonlogger.tests.audit.handler_rotation")
    logger.setLevel(logging.INFO)
    try:
        first = AuditFileHandler(
            path, keys={"old": OLD_KEY}, key_id="old", chain_id="handler-rotation"
        )
        logger.addHandler(first)
        try:
            logger.info("old key record", extra={"actor": "alice"})
            first.audit_formatter.rotate_key("new", NEW_KEY)
            logger.info("new key record", extra={"actor": "bob"})
        finally:
            logger.removeHandler(first)
            first.close()

        second = AuditFileHandler(
            path,
            keys={"old": OLD_KEY, "new": NEW_KEY},
            key_id="new",
            chain_id="handler-rotation",
        )
        logger.addHandler(second)
        try:
            logger.info("recovered record", extra={"actor": "carol"})
        finally:
            logger.removeHandler(second)
            second.close()

        records = _records(path.read_bytes())
        assert [record[AUDIT_FIELD]["key_id"] for record in records] == [
            "old",
            "new",
            "new",
        ]
        assert [record[AUDIT_FIELD]["seq"] for record in records] == [0, 1, 2]
        AuditVerifier(keys={"old": OLD_KEY, "new": NEW_KEY}).verify_file(
            path, anchor=AuditAnchor.genesis("handler-rotation")
        )
    finally:
        path.unlink(missing_ok=True)


def test_empty_audit_file_and_first_record(tmp_path: Path) -> None:
    path = tmp_path / "empty.jsonl"
    handler = AuditFileHandler(path, keys={"k1": OLD_KEY}, chain_id="empty-file-chain")
    logger = logging.getLogger("pythonjsonlogger.tests.audit.empty_file")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    try:
        logger.info("first record", extra={"actor": "alice"})
    finally:
        logger.removeHandler(handler)
        handler.close()

    records = _records(path.read_bytes())
    assert len(records) == 1
    assert records[0][AUDIT_FIELD]["seq"] == 0
    AuditVerifier(keys={"k1": OLD_KEY}).verify_file(
        path, anchor=AuditAnchor.genesis("empty-file-chain")
    )


def test_secrets_do_not_appear_in_output_exceptions_or_repr() -> None:
    key = AuditKey("key-a", OLD_KEY)
    ring = AuditKeyRing({"key-a": key})
    formatter = AuditFormatter(key_ring=ring, chain_id="redaction-chain")
    output = formatter.build_record(
        logging.LogRecord("n", logging.INFO, "", 0, "redaction", (), None)
    ).line

    for value in (repr(key), str(key), repr(ring), repr(formatter), output):
        assert OLD_KEY not in value

    with pytest.raises(AuditConfigurationError) as exc_info:
        ring.add_key("bad", object())
    assert OLD_KEY not in str(exc_info.value)


def test_flush_failure_does_not_advance_head_and_retry_is_idempotent() -> None:
    path = Path(__file__).resolve().parent / "_audit_flush_failure.jsonl"
    if path.exists():
        path.unlink()
    handler = AuditFileHandler(
        path,
        keys={"k1": OLD_KEY},
        key_id="k1",
        chain_id="flush-chain",
        auto_flush=False,
        delay=True,
    )
    logger = logging.getLogger("pythonjsonlogger.tests.audit.flush")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)

    class FlushFailingStream:
        """Writes reach the OS, but the commit flush reports failure."""

        def __init__(self, wrapped):
            self.wrapped = wrapped
            self.name = wrapped.name

        def write(self, value: bytes) -> None:
            return self.wrapped.write(value)

        def flush(self) -> None:
            raise OSError("simulated flush failure")

        def close(self) -> None:
            return self.wrapped.close()

        def fileno(self) -> int:
            return self.wrapped.fileno()

    try:
        logger.info("before failure", extra={"actor": "alice"})
        logger.info("still buffered", extra={"actor": "alice"})
        assert handler.formatter.head.sequence == -1

        assert handler._buffer is not None
        assert handler._stream is not None
        handler._buffer.stream = FlushFailingStream(handler._buffer.stream)
        handler._stream = handler._buffer.stream
        with pytest.raises(AuditWriteError):
            handler.flush()
        assert handler.formatter.head.sequence == -1

        # The same pending records are retried; a new record gets seq 2 only.
        logger.info("after failure", extra={"actor": "alice"})
        handler.flush()
        assert handler.formatter.head.sequence == 2
    finally:
        logger.removeHandler(handler)
        handler.close()

    try:
        records = _records(path.read_bytes())
        assert [record[AUDIT_FIELD]["seq"] for record in records] == [0, 1, 2]
        AuditVerifier(keys={"k1": OLD_KEY}).verify_file(
            path, anchor=AuditAnchor.genesis("flush-chain")
        )
    finally:
        path.unlink(missing_ok=True)


def test_normal_json_formatter_output_is_unchanged() -> None:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    formatter = JsonFormatter("%(message)s", timestamp=True)
    handler.setFormatter(formatter)
    logger = logging.getLogger("pythonjsonlogger.tests.audit.normal")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    try:
        logger.info("normal", extra={"actor": "alice"})
    finally:
        logger.removeHandler(handler)

    record = json.loads(stream.getvalue())
    assert record["message"] == "normal"
    assert record["actor"] == "alice"
    assert AUDIT_FIELD not in record
    assert set(formatter.prefix) == set() or formatter.prefix == ""


def test_verifier_requires_anchor_for_nonzero_first_sequence() -> None:
    formatter = AuditFormatter(keys={"k1": OLD_KEY}, chain_id="resume-chain", start_sequence=0)
    line = formatter.build_record(
        logging.LogRecord("n", logging.INFO, "", 0, "first", (), None)
    ).line
    with pytest.raises(AuditIntegrityError, match="seq"):
        AuditVerifier(keys={"k1": OLD_KEY}).verify(
            [line], anchor=AuditAnchor("resume-chain", 4, "0" * 64)
        )


def test_start_sequence_anchor_round_trip() -> None:
    first = AuditFormatter(keys={"k1": OLD_KEY}, chain_id="anchor-chain")
    lines = [
        first.build_record(
            logging.LogRecord("n", logging.INFO, "", 0, f"record {i}", (), None)
        ).line
        for i in range(3)
    ]
    result = AuditVerifier(keys={"k1": OLD_KEY}).verify(
        lines, anchor=AuditAnchor.genesis("anchor-chain")
    )
    resumed = AuditFormatter(keys={"k1": OLD_KEY}, key_ring=None, anchor=result.head)
    assert resumed.chain_id == "anchor-chain"
    assert resumed.next_sequence == 3
    line = resumed.build_record(
        logging.LogRecord("n", logging.INFO, "", 0, "resumed", (), None)
    ).line
    AuditVerifier(keys={"k1": OLD_KEY}).verify(
        lines + [line], anchor=AuditAnchor.genesis("anchor-chain")
    )


def test_key_ring_repr_and_conflicting_config() -> None:
    ring = AuditKeyRing({"old": OLD_KEY, "new": NEW_KEY}, active_key_id="new")
    assert OLD_KEY not in repr(ring)
    assert NEW_KEY not in repr(ring)
    with pytest.raises(AuditConfigurationError):
        audit_formatter_bad = AuditFormatter(key_ring=ring, keys={"other": OLD_KEY})
        del audit_formatter_bad


def test_verify_chain_convenience_function_and_thread_safe_formatter() -> None:
    formatter = AuditFormatter(keys={"k1": OLD_KEY}, chain_id="thread-chain")
    lock = threading.Lock()
    lines: list[str] = []

    def build(index: int) -> None:
        record = formatter.build_record(
            logging.LogRecord("n", logging.INFO, "", 0, f"thread {index}", (), None)
        )
        with lock:
            lines.append(record.line)

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(build, range(100)))

    lines.sort(key=lambda line: json.loads(line)[AUDIT_FIELD]["seq"])
    result = verify_audit_chain(
        lines,
        keys={"k1": OLD_KEY},
        anchor=AuditAnchor.genesis("thread-chain"),
    )
    assert result.count == 100
