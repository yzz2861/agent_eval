#!/usr/bin/env python3
"""Random-byte mutation fuzzer for the CBOR decoder.

This complements ``loads_fuzzer.py`` (which is meant to be driven by Atheris)
with a dependency-free entry point that starts from structurally valid
maps, arrays, tags, bignums and floats and mutates them byte-wise.  The
contract being fuzzed is deliberately narrow:

* :func:`cbor2.loads` either returns a value or raises :class:`CBORDecodeError`;
* it never raises ``MemoryError`` (not even as a wrapped cause);
* it does not run for an unbounded amount of time.

Run a campaign directly::

    python tests/fuzzers/random_bytes_fuzzer.py
    python tests/fuzzers/random_bytes_fuzzer.py --iterations 100000 --seed 1
    python tests/fuzzers/random_bytes_fuzzer.py --write-corpus

Failures are minimized by deleting bytes while the failure still reproduces.
With ``--write-corpus`` the minimized payload and a JSON metadata file are
written to ``tests/fuzz_corpus`` for the pytest replay suite.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import random
import signal
import struct
import sys
import threading
import time
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

from cbor2 import CBORDecodeError, loads

REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS_DIR = REPO_ROOT / "tests" / "fuzz_corpus"
DEFAULT_SEED = 0xC0B2
DEFAULT_ITERATIONS = 5000
DEFAULT_TIMEOUT = 1.0
MAX_PAYLOAD_SIZE = 4096


class FuzzFailure(AssertionError):
    """Raised when the decoder violates the fuzzing contract."""

    def __init__(
        self,
        reason: str,
        payload: bytes,
        kwargs: Mapping[str, Any],
        exc: BaseException | None = None,
    ) -> None:
        self.reason = reason
        self.payload = payload
        self.kwargs = dict(kwargs)
        self.exc = exc
        super().__init__(
            f"{reason}: payload={payload.hex()} kwargs={dict(kwargs)!r}"
            + (f" exception={type(exc).__name__}: {exc}" if exc is not None else "")
        )


class CaseTimeout(Exception):
    """Raised by the best-effort per-case watchdog."""


def _contains_memory_error(exc: BaseException) -> bool:
    """Return whether ``exc``, or anything it was raised from, is a MemoryError."""

    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        if isinstance(current, MemoryError):
            return True

        seen.add(id(current))
        current = current.__cause__ or current.__context__

    return False


@contextlib.contextmanager
def _time_limit(seconds: float) -> Iterator[None]:
    """Raise :class:`CaseTimeout` if a single case takes too long.

    The alarm is only a fallback: a Rust decoder loop that never calls back
    into Python can delay signal delivery.  The pytest wrapper runs the entire
    campaign in a subprocess with a hard timeout, which also catches that case.
    """

    if (
        seconds <= 0
        or not hasattr(signal, "SIGALRM")
        or threading.current_thread() is not threading.main_thread()
    ):
        yield
        return

    def raise_timeout(signum: int, frame: object) -> None:
        raise CaseTimeout

    previous_handler = signal.signal(signal.SIGALRM, raise_timeout)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, *previous_timer)
        signal.signal(signal.SIGALRM, previous_handler)


def check_payload(
    payload: bytes, kwargs: Mapping[str, Any] | None = None, *, timeout: float = DEFAULT_TIMEOUT
) -> None:
    """Assert the decode contract for a single payload."""

    kwargs = dict(kwargs or {})
    try:
        with _time_limit(timeout):
            loads(payload, **kwargs)
    except CBORDecodeError as exc:
        if _contains_memory_error(exc):
            raise FuzzFailure(
                "decoder raised CBORDecodeError caused by MemoryError", payload, kwargs, exc
            ) from exc
    except MemoryError as exc:
        raise FuzzFailure("decoder raised MemoryError", payload, kwargs, exc) from exc
    except CaseTimeout:
        raise FuzzFailure("decoder timed out", payload, kwargs) from None
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:
        if _contains_memory_error(exc):
            raise FuzzFailure(
                "decoder raised an exception caused by MemoryError", payload, kwargs, exc
            ) from exc

        raise FuzzFailure(
            f"decoder raised uncaught {type(exc).__name__}", payload, kwargs, exc
        ) from exc


# Small, hand-written seeds.  Each one reaches a distinct decoder path, and
# most decode successfully so mutations explore deeper into the parser.
BUILTIN_SEEDS: tuple[bytes, ...] = (
    # Maps and arrays, both definite and indefinite length.
    bytes.fromhex("a0"),
    bytes.fromhex("a26161016162820203"),
    bytes.fromhex("bf616101616202ff"),
    bytes.fromhex("80"),
    bytes.fromhex("84010203f5"),
    bytes.fromhex("8282010281f5"),
    bytes.fromhex("9f01029f0304ffff"),
    # Tags: datetime, bignums, decimals, string/shared references and a
    # self-referential tag used as a map key.
    bytes.fromhex("c06161"),
    bytes.fromhex("c11a514b67b0"),
    bytes.fromhex("c249010000000000000000"),
    bytes.fromhex("c349010000000000000000"),
    bytes.fromhex("c48221196ab3"),
    bytes.fromhex("c5822003"),
    bytes.fromhex("d81c81d81d00"),
    bytes.fromhex("d81ca100d81d00"),
    bytes.fromhex("d9010081d81900"),
    bytes.fromhex("d917706548656c6c6f"),
    bytes.fromhex("a1d81cd903e7d81d0001"),
    # Floats of every width plus the special values.
    bytes.fromhex("f90000"),
    bytes.fromhex("f97e00"),
    bytes.fromhex("fa47c35000"),
    bytes.fromhex("fb3ff199999999999a"),
    # Malformed or truncated inputs around the interesting limits.
    bytes.fromhex("bf6161ff"),
    bytes.fromhex("5f01ff"),
    bytes.fromhex("d81d05"),
    bytes.fromhex("d90102d81c8181d81d00"),
    bytes.fromhex("c25bffffffffffffffff"),
    bytes.fromhex("c5821bffffffffffffffff01"),
    bytes.fromhex("9bffffffffffffffff"),
    bytes.fromhex("bbffffffffffffffff"),
)

INDEFINITE_MARKERS = bytes((0x1F, 0x3F, 0x5F, 0x7F, 0x9F, 0xBF, 0xDF, 0xFF))
LENGTH_PREFIXES = bytes((0x1B, 0x3B, 0x5B, 0x7B, 0x9B, 0xBB, 0xDB, 0xFB))
FLOAT_PREFIXES = (b"\xf9", b"\xfa", b"\xfb")
TAG_NUMBERS = (
    0,
    1,
    2,
    3,
    4,
    5,
    25,
    28,
    29,
    30,
    35,
    36,
    37,
    52,
    54,
    100,
    256,
    258,
    260,
    261,
    1004,
    6000,
    43000,
    55799,
)
INTERESTING_LENGTHS = (
    0,
    1,
    23,
    24,
    255,
    256,
    65535,
    65536,
    2**32 - 1,
    2**32,
    2**63 - 1,
    2**64 - 1,
)


def _encode_head(major_type: int, value: int) -> bytes:
    """Encode a CBOR initial byte and argument for ``value``."""

    if value < 24:
        return bytes(((major_type << 5) | value,))
    if value <= 0xFF:
        return bytes(((major_type << 5) | 24, value))
    if value <= 0xFFFF:
        return bytes(((major_type << 5) | 25,)) + struct.pack(">H", value)
    if value <= 0xFFFFFFFF:
        return bytes(((major_type << 5) | 26,)) + struct.pack(">I", value)
    return bytes(((major_type << 5) | 27,)) + struct.pack(">Q", value)


def load_seed_payloads(corpus_dir: Path = CORPUS_DIR) -> list[bytes]:
    """Return built-in seeds plus every payload in the replay corpus."""

    seeds = list(BUILTIN_SEEDS)
    if corpus_dir.is_dir():
        for path in sorted(corpus_dir.glob("*.cbor")):
            data = path.read_bytes()
            if data not in seeds:
                seeds.append(data)

    return seeds


def mutate(rng: random.Random, data: bytes, seeds: list[bytes]) -> bytes:
    """Apply one to eight random mutations to ``data``."""

    mutated = bytearray(data)
    for _ in range(rng.randint(1, 8)):
        operation = rng.randrange(12)
        if operation == 0 and mutated:
            index = rng.randrange(len(mutated))
            mutated[index] ^= 1 << rng.randrange(8)
        elif operation == 1 and mutated:
            mutated[rng.randrange(len(mutated))] = rng.randrange(256)
        elif operation == 2:
            mutated.insert(rng.randrange(len(mutated) + 1), rng.randrange(256))
        elif operation == 3 and mutated:
            start = rng.randrange(len(mutated))
            del mutated[start : start + rng.randint(1, 16)]
        elif operation == 4 and mutated:
            start = rng.randrange(len(mutated))
            end = min(len(mutated), start + rng.randint(1, 16))
            position = rng.randrange(len(mutated) + 1)
            mutated[position:position] = mutated[start:end]
        elif operation == 5 and mutated:
            # Replace a length/header byte with an oversized length of a
            # random major type.  Major types 2-5 also cover bignum payloads.
            index = rng.randrange(len(mutated))
            length = rng.choice(INTERESTING_LENGTHS + (rng.getrandbits(64),))
            mutated[index : index + 1] = bytes((rng.choice(LENGTH_PREFIXES),)) + struct.pack(
                ">Q", length
            )
        elif operation == 6:
            # Insert an indefinite-length marker or a break stop code.
            position = rng.randrange(len(mutated) + 1)
            mutated[position:position] = bytes((rng.choice(INDEFINITE_MARKERS),))
        elif operation == 7:
            # Wrap the current value in a tag, array or indefinite-length array.
            tag = _encode_head(6, rng.choice(TAG_NUMBERS))
            wrapper = rng.choice((tag, b"\x81", b"\x9f", b"\xd8\x1c"))
            suffix = b"\xff" if wrapper == b"\x9f" else b""
            mutated = bytearray(wrapper + bytes(mutated) + suffix)
        elif operation == 8:
            # Insert a synthetic bignum or float.
            position = rng.randrange(len(mutated) + 1)
            if rng.randrange(2):
                tag = 2 if rng.randrange(2) else 3
                payload = bytes(rng.randrange(256) for _ in range(rng.randint(0, 16)))
                chunk = _encode_head(6, tag) + _encode_head(2, len(payload)) + payload
            else:
                width = rng.choice((2, 4, 8))
                prefixes = FLOAT_PREFIXES[:1] if width == 2 else FLOAT_PREFIXES[1:]
                chunk = rng.choice(prefixes) + bytes(rng.randrange(256) for _ in range(width))
            mutated[position:position] = chunk
        elif operation == 9:
            other = rng.choice(seeds)
            position = rng.randrange(len(mutated) + 1)
            other_position = rng.randrange(len(other) + 1)
            mutated[position:] = other[other_position:]
        elif operation == 10 and mutated:
            del mutated[rng.randrange(len(mutated)) :]
        else:
            mutated.extend(bytes(rng.randrange(256) for _ in range(rng.randint(1, 16))))

        if len(mutated) > MAX_PAYLOAD_SIZE:
            del mutated[MAX_PAYLOAD_SIZE:]

    return bytes(mutated)


def _random_kwargs(rng: random.Random) -> dict[str, Any]:
    choices: tuple[dict[str, Any], ...] = (
        {},
        {"immutable": True},
        {"max_depth": rng.randint(1, 12)},
        {"allow_indefinite": False},
        {"allow_duplicate_keys": False},
        {"strict_hashable_types": True},
        {"str_errors": rng.choice(("ignore", "replace", "backslashreplace", "surrogateescape"))},
        {"max_depth": rng.randint(1, 12), "immutable": True, "strict_hashable_types": True},
    )
    return dict(rng.choice(choices))


def _reproduces(payload: bytes, kwargs: Mapping[str, Any], timeout: float) -> bool:
    try:
        check_payload(payload, kwargs, timeout=timeout)
    except FuzzFailure:
        return True

    return False


def minimize(
    payload: bytes, kwargs: Mapping[str, Any], *, timeout: float = DEFAULT_TIMEOUT
) -> bytes:
    """Greedily delete bytes while the fuzzing failure still reproduces."""

    best = payload
    chunk_size = max(1, len(best) // 2)
    while True:
        changed = False
        index = 0
        while index < len(best):
            candidate = best[:index] + best[index + chunk_size :]
            if _reproduces(candidate, kwargs, timeout):
                best = candidate
                changed = True
            else:
                index += chunk_size

        if not changed:
            if chunk_size == 1:
                break

            chunk_size = max(1, chunk_size // 2)

    return best


def write_corpus_case(failure: FuzzFailure, corpus_dir: Path = CORPUS_DIR) -> Path:
    """Write a minimized failure and its metadata to the replay corpus."""

    corpus_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(failure.payload).hexdigest()[:12]
    payload_path = corpus_dir / f"fuzz_{digest}.cbor"
    metadata_path = payload_path.with_suffix(".json")
    payload_path.write_bytes(failure.payload)
    metadata_path.write_text(
        json.dumps(
            {
                "category": "fuzz",
                "outcome": "unexpected",
                "exception": type(failure.exc).__name__ if failure.exc is not None else "Timeout",
                "match": str(failure.exc) if failure.exc is not None else failure.reason,
                "kwargs": failure.kwargs,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return payload_path


def run_campaign(
    iterations: int = DEFAULT_ITERATIONS,
    *,
    seed: int = DEFAULT_SEED,
    timeout: float = DEFAULT_TIMEOUT,
    corpus_dir: Path = CORPUS_DIR,
    write_corpus: bool = False,
    max_failures: int = 5,
    quiet: bool = False,
) -> list[FuzzFailure]:
    """Run a deterministic mutation campaign and return any failures."""

    rng = random.Random(seed)
    seeds = load_seed_payloads(corpus_dir)
    failures: list[FuzzFailure] = []
    started = time.monotonic()
    for iteration in range(iterations):
        payload = mutate(rng, rng.choice(seeds), seeds)
        kwargs = _random_kwargs(rng)
        try:
            check_payload(payload, kwargs, timeout=timeout)
        except FuzzFailure as failure:
            minimized = minimize(failure.payload, failure.kwargs, timeout=timeout)
            failure = FuzzFailure(failure.reason, minimized, failure.kwargs, failure.exc)
            failures.append(failure)
            if write_corpus:
                path = write_corpus_case(failure, corpus_dir)
                if not quiet:
                    print(f"wrote {path}")
            if not quiet:
                print(f"failure after {iteration + 1} iterations: {failure}")
            if len(failures) >= max_failures:
                break

    if not quiet:
        elapsed = time.monotonic() - started
        print(
            f"Fuzzed {iterations if not failures else iteration + 1} inputs in "
            f"{elapsed:.2f}s ({len(failures)} failures)"
        )

    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="per-case watchdog in seconds (best effort)",
    )
    parser.add_argument(
        "--corpus-dir", type=Path, default=CORPUS_DIR, help="corpus for seeds and new failures"
    )
    parser.add_argument(
        "--write-corpus",
        action="store_true",
        help="write minimized failures to the corpus directory",
    )
    parser.add_argument("--max-failures", type=int, default=5)
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument(
        "--check-file",
        type=Path,
        help="check a single payload file instead of running a campaign",
    )
    args = parser.parse_args(argv)

    if args.check_file is not None:
        payload = args.check_file.read_bytes()
        try:
            check_payload(payload, timeout=args.timeout)
        except FuzzFailure as failure:
            print(failure)
            return 1

        if not args.quiet:
            print(f"{args.check_file}: decode succeeded or raised CBORDecodeError")

        return 0

    failures = run_campaign(
        args.iterations,
        seed=args.seed,
        timeout=args.timeout,
        corpus_dir=args.corpus_dir,
        write_corpus=args.write_corpus,
        max_failures=args.max_failures,
        quiet=args.quiet,
    )
    return 1 if failures else 0


def fuzz_one_input(data: bytes) -> None:
    """Entry point for coverage-guided fuzzers that want the stricter contract."""

    check_payload(data)


if __name__ == "__main__":
    sys.exit(main())
