from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from cbor2 import CBORDecodeError, loads

CORPUS_DIR = Path(__file__).with_name("fuzz_corpus")
FUZZER = Path(__file__).with_name("fuzzers").joinpath("random_bytes_fuzzer.py")
CORPUS_FILES = sorted(CORPUS_DIR.glob("*.cbor"))


def _read_case(path: Path) -> tuple[bytes, dict[str, Any]]:
    metadata = json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))
    return path.read_bytes(), metadata


def _cause_messages(exc: BaseException) -> list[str]:
    messages: list[str] = []
    seen: set[int] = set()
    current = exc.__cause__
    while current is not None and id(current) not in seen:
        messages.append(str(current))
        seen.add(id(current))
        current = current.__cause__ or current.__context__

    return messages


@pytest.mark.parametrize("path", CORPUS_FILES, ids=[path.stem for path in CORPUS_FILES])
def test_fuzz_corpus(path: Path, request: pytest.FixtureRequest) -> None:
    payload, metadata = _read_case(path)
    kwargs = metadata.get("kwargs", {})
    outcome = metadata["outcome"]
    if outcome == "ok":
        loads(payload, **kwargs)
        return

    if outcome == "unexpected":
        # Keep a minimized failure reproducible while it is being fixed.  Once
        # the decoder starts honoring the contract, the strict xfail turns
        # into an XPASS failure so the metadata gets updated.
        request.node.add_marker(
            pytest.mark.xfail(
                strict=True,
                reason=f"known fuzz failure: {metadata.get('match', 'unexpected exception')}",
            )
        )
        with pytest.raises(BaseException):
            loads(payload, **kwargs)

        return

    assert outcome == "error"
    with pytest.raises(CBORDecodeError) as excinfo:
        loads(payload, **kwargs)

    expected_exception = metadata.get("exception")
    if expected_exception:
        assert type(excinfo.value).__name__ == expected_exception

    expected_match = metadata.get("match")
    if expected_match:
        assert expected_match in str(excinfo.value)

    expected_cause = metadata.get("cause")
    if expected_cause:
        assert excinfo.value.__cause__ is not None
        assert type(excinfo.value.__cause__).__name__ == expected_cause

    expected_cause_match = metadata.get("cause_match")
    if expected_cause_match:
        assert any(expected_cause_match in message for message in _cause_messages(excinfo.value))


def test_fuzz_corpus_covers_required_input_kinds() -> None:
    categories = {_read_case(path)[1]["category"] for path in CORPUS_FILES}
    assert {
        "map",
        "array",
        "tag",
        "bignum",
        "float",
        "indefinite",
        "shared_reference",
    } <= categories


def test_random_byte_mutation_campaign() -> None:
    # The campaign runs in a subprocess so that a decoder hang in Rust, where
    # Python's alarm signal may never be delivered, still fails the test.
    env = os.environ.copy()
    python_path = env.get("PYTHONPATH")
    env["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(CORPUS_DIR.parents[1]), python_path) if part
    )
    result = subprocess.run(
        [
            sys.executable,
            str(FUZZER),
            "--iterations",
            "10000",
            "--seed",
            str(0xC0B2),
            "--timeout",
            "1.0",
        ],
        capture_output=True,
        env=env,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
