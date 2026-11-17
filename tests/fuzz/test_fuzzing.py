"""Pytest integration for the stdlib-only joserfc fuzzing harness.

Two layers are exercised, both deterministic and repeatable:

1. every file in ``tests/fuzz_corpus`` is replayed and must either return or
   raise a controlled exception (never an unhandled ``AttributeError`` etc.);
2. a fixed-seed mutation fuzzing run must finish within the per-input timeout
   budget and report zero findings.
"""

from __future__ import annotations

import json
import signal
from pathlib import Path

import pytest

from tests.fuzz.fuzzing import (
    CONTROLLED_EXCEPTIONS,
    DEFAULT_ITERATIONS,
    DEFAULT_SEED,
    DEFAULT_TIMEOUT_SECONDS,
    FuzzTimeout,
    _alarm_handler,
    build_seeds,
    dispatch,
    load_corpus_entry,
    run_fuzz,
)

CORPUS_DIR = Path(__file__).resolve().parent.parent / "fuzz_corpus"
CORPUS_FILES = sorted(CORPUS_DIR.glob("*.json"))


@pytest.mark.parametrize("corpus_file", CORPUS_FILES, ids=lambda path: path.stem)
def test_fuzz_corpus_is_controlled(corpus_file: Path) -> None:
    record = json.loads(corpus_file.read_text(encoding="utf-8"))
    target, payload = load_corpus_entry(record)
    keys = build_seeds().keys
    try:
        dispatch(target, payload, keys)
    except CONTROLLED_EXCEPTIONS:
        return  # controlled rejection is the expected outcome for malformed input


def test_corpus_is_not_empty() -> None:
    assert CORPUS_FILES, "tests/fuzz_corpus must contain regression samples"


def test_deterministic_fuzz_run_has_no_findings() -> None:
    result = run_fuzz(
        iterations=DEFAULT_ITERATIONS,
        seed=DEFAULT_SEED,
        timeout=DEFAULT_TIMEOUT_SECONDS,
    )
    assert result.ok, [finding.corpus_name for finding in result.findings]
    assert result.controlled == DEFAULT_ITERATIONS


def test_fuzz_run_is_reproducible() -> None:
    first = run_fuzz(iterations=200, seed=DEFAULT_SEED)
    second = run_fuzz(iterations=200, seed=DEFAULT_SEED)
    assert first.controlled == second.controlled
    assert [finding.corpus_name for finding in first.findings] == [finding.corpus_name for finding in second.findings]


def test_timeout_budget_is_enforced() -> None:
    signal.signal(signal.SIGALRM, _alarm_handler)
    signal.setitimer(signal.ITIMER_REAL, 0.01)
    try:
        with pytest.raises(FuzzTimeout):
            while True:
                pass
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
