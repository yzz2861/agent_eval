"""Stdlib-only coverage-guided style fuzzing harness for joserfc.

This module deliberately depends on the Python standard library only (plus the
``joserfc`` package under test). It builds valid JWS/JWE/JWK seed values,
mutates their compact and JSON serializations with a deterministic PRNG, and
drives parsing, key import and signature/decryption verification.

Every input MUST either return normally or raise one of the controlled
exceptions listed in :data:`CONTROLLED_EXCEPTIONS`. A crash (any other
exception) or a timeout is treated as a finding and surfaced with a stable
hex corpus id so the sample can be stored in ``tests/fuzz_corpus``.
"""

from __future__ import annotations

import binascii
import hashlib
import json
import random
import signal
import warnings
from dataclasses import dataclass, field
from typing import Any

from joserfc import jwe, jws
from joserfc.errors import JoseError
from joserfc.jwk import ECKey, OctKey, OKPKey, RSAKey, import_key

# Exceptions that callers are expected to handle for malformed input.
# ``binascii.Error`` is a ``ValueError`` subclass, but it is listed explicitly
# to document that invalid base64url data is an expected, controlled outcome.
CONTROLLED_EXCEPTIONS: tuple[type[BaseException], ...] = (
    JoseError,
    ValueError,
    TypeError,
    KeyError,
    UnicodeError,
    OverflowError,
    binascii.Error,
)

# Per-input wall clock budget. Parsing is bounded by registry size limits, so a
# healthy input always finishes well below this threshold.
DEFAULT_TIMEOUT_SECONDS: float = 2.0
DEFAULT_ITERATIONS: int = 2000
DEFAULT_SEED: int = 20261117

JSON_FIELD_NAMES = (
    "alg",
    "enc",
    "kid",
    "x",
    "payload",
    "signature",
    "protected",
    "header",
    "iv",
    "tag",
    "ciphertext",
    "encrypted_key",
    "unprotected",
    "signatures",
    "recipients",
    "aad",
    "kty",
    "crv",
    "k",
    "n",
    "e",
    "d",
    "p",
    "q",
    "x5c",
)
SCALAR_REPLACEMENTS: tuple[Any, ...] = (None, True, False, 0, 1, -1, 10**9, "", "AA", "abc", [], {})


@dataclass
class FuzzFinding:
    """A single unexpected outcome discovered by the fuzzing loop."""

    target: str
    kind: str  # "exception" or "timeout"
    exception_name: str | None
    message: str
    payload: Any
    iteration: int

    @property
    def corpus_name(self) -> str:
        """Stable, filesystem-safe corpus identifier for the finding."""
        token = self.exception_name.lower() if self.exception_name else self.kind
        token = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in token)
        digest = hashlib.sha1(self._stable_payload()).hexdigest()[:10]
        return f"{self.target}__{token}__{self.iteration}_{digest}.json"

    def _stable_payload(self) -> bytes:
        if isinstance(self.payload, bytes):
            return self.payload
        return json.dumps(self.payload, default=str, ensure_ascii=False).encode("utf-8")


@dataclass
class FuzzResult:
    iterations: int
    seed: int
    controlled: int = 0
    findings: list[FuzzFinding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.findings


class FuzzTimeout(Exception):
    """Raised internally when the per-input alarm fires."""


def mutate_bytes(data: bytes, rng: random.Random, max_size: int = 4096) -> bytes:
    """Byte-level mutation: flips, inserts, deletes, XOR and block reordering."""
    out = bytearray(data)
    if not out:
        return bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 8)))
    for _ in range(rng.randint(1, 4)):
        op = rng.randrange(5)
        if op == 0:
            out[rng.randrange(len(out))] = rng.getrandbits(8)
        elif op == 1 and len(out) < max_size:
            out.insert(rng.randrange(len(out) + 1), rng.getrandbits(8))
        elif op == 2 and len(out) > 1:
            del out[rng.randrange(len(out))]
        elif op == 3:
            index = rng.randrange(len(out))
            out[index] = out[index] ^ (1 << rng.randrange(8))
        else:
            out.reverse()
    return bytes(out)


def mutate_json(obj: Any, rng: random.Random, depth: int = 0) -> Any:
    """Structure-aware mutation that preserves JSON-serializable shapes."""
    if depth > 4:
        return obj
    if isinstance(obj, dict):
        out = dict(obj)
        for _ in range(rng.randint(1, 3)):
            op = rng.randrange(6)
            if op == 0 and out:
                key = rng.choice(list(out.keys()))
                out[key] = mutate_json(out[key], rng, depth + 1)
            elif op == 1:
                name = rng.choice(JSON_FIELD_NAMES)
                replacement = rng.choice(SCALAR_REPLACEMENTS)
                out[name] = mutate_json(replacement, rng, depth + 1)
            elif op == 2 and out:
                del out[rng.choice(list(out.keys()))]
            elif op == 3:
                out[rng.randrange(100000)] = rng.choice((None, 1, "z"))
            elif op == 4 and out:
                key = rng.choice(list(out.keys()))
                raw = str(out[key]).encode("utf-8", "replace")
                out[key] = mutate_bytes(raw, rng).decode("latin-1")
            else:
                return rng.choice((out, None, True, 0, "x", [], {}))
        return out
    if isinstance(obj, list):
        out = list(obj)
        for _ in range(rng.randint(1, 3)):
            op = rng.randrange(4)
            if op == 0 and out:
                index = rng.randrange(len(out))
                out[index] = mutate_json(out[index], rng, depth + 1)
            elif op == 1 and len(out) < 16:
                out.insert(rng.randrange(len(out) + 1), rng.choice((None, {}, [], 0, "AA")))
            elif op == 2 and out:
                del out[rng.randrange(len(out))]
            else:
                out.reverse()
        return out
    return rng.choice((obj, None, True, False, 0, 1, -1, 10**9, "", "AA", [], {}))


def mutate_compact(text: str, rng: random.Random) -> bytes:
    """Mutate a compact serialization both as raw bytes and per segment."""
    if rng.random() < 0.5:
        return mutate_bytes(text.encode("utf-8"), rng)
    parts = text.split(".")
    for _ in range(rng.randint(1, 3)):
        op = rng.randrange(5)
        if op == 0 and parts:
            index = rng.randrange(len(parts))
            mutated = mutate_bytes(parts[index].encode("ascii", "ignore"), rng)
            parts[index] = mutated.decode("latin-1")
        elif op == 1:
            parts.insert(rng.randrange(len(parts) + 1), rng.choice(("", "AA", "abc", ".")))
        elif op == 2 and len(parts) > 1:
            del parts[rng.randrange(len(parts))]
        elif op == 3 and parts:
            parts[rng.randrange(len(parts))] = rng.choice(("", "AA", "!!!", "abc", "="))
        else:
            parts.reverse()
    return ".".join(parts).encode("utf-8")


@dataclass
class FuzzSeeds:
    compact: list[tuple[str, str]]
    json_serialized: list[tuple[str, dict[str, Any]]]
    jwk_dicts: list[tuple[str, dict[str, Any]]]
    raw_keys: list[tuple[str, bytes]]
    keys: dict[str, Any]


def build_seeds() -> FuzzSeeds:
    """Generate valid JWS/JWE/JWK seed material covering every target."""
    oct_key = OctKey.import_key(b"fuzz-secret-key-0123456789-abcdef")
    oct_key_128 = OctKey.import_key(b"0123456789abcdef")
    rsa_key = RSAKey.generate_key(2048)
    ec_key = ECKey.generate_key("P-256")
    okp_key = OKPKey.generate_key("Ed25519")
    keys = {
        "oct": oct_key,
        "oct_128": oct_key_128,
        "rsa": rsa_key,
        "ec": ec_key,
        "okp": okp_key,
    }

    compact: list[tuple[str, str]] = [
        ("jws_compact", jws.serialize_compact({"alg": "HS256"}, b"hello", oct_key)),
        ("jws_compact", jws.serialize_compact({"alg": "none"}, b"hi", None, algorithms=["none"])),
        ("jws_compact", jws.serialize_compact({"alg": "RS256"}, b"hello", rsa_key)),
        ("jwe_compact", jwe.encrypt_compact({"alg": "RSA-OAEP", "enc": "A128GCM"}, b"hello", rsa_key)),
        ("jwe_compact", jwe.encrypt_compact({"alg": "A128KW", "enc": "A128GCM"}, b"hello", oct_key_128)),
    ]

    json_serialized: list[tuple[str, dict[str, Any]]] = [
        ("jws_json", jws.serialize_json({"protected": {"alg": "HS256"}}, b"hello", oct_key)),
        (
            "jws_json",
            jws.serialize_json([{"protected": {"alg": "HS256"}}, {"protected": {"alg": "HS256"}}], b"hello", oct_key),
        ),
    ]
    flat = jwe.FlattenedJSONEncryption({"enc": "A128GCM"}, b"hello")
    flat.add_recipient({"alg": "A128KW"}, oct_key_128)
    json_serialized.append(("jwe_json", jwe.encrypt_json(flat, None)))
    general = jwe.GeneralJSONEncryption({"enc": "A128GCM"}, b"hello")
    general.add_recipient({"alg": "A128KW"}, oct_key_128)
    json_serialized.append(("jwe_json", jwe.encrypt_json(general, None)))

    jwk_dicts: list[tuple[str, dict[str, Any]]] = []
    raw_keys: list[tuple[str, bytes]] = []
    for key in (oct_key, rsa_key, ec_key, okp_key):
        jwk_dicts.append(("jwk_dict", key.as_dict()))
        jwk_dicts.append(("jwk_dict", key.as_dict(private=True)))
        raw_keys.append(("jwk_raw", key.as_pem() if hasattr(key, "as_pem") else bytes(key.raw_value)))
    return FuzzSeeds(compact, json_serialized, jwk_dicts, raw_keys, keys)


def dispatch(target: str, payload: Any, keys: dict[str, Any]) -> None:
    """Drive one parsed/imported/verification path with the mutated payload."""
    if target == "jws_compact":
        jws.deserialize_compact(payload, keys["oct"], algorithms=["HS256", "none"])
    elif target == "jws_json":
        jws.deserialize_json(payload, keys["oct"])
    elif target == "jwe_compact":
        jwe.decrypt_compact(payload, keys["rsa"])
    elif target == "jwe_json":
        jwe.decrypt_json(payload, keys["oct_128"])
    elif target == "jwk_dict":
        import_key(payload)
    elif target == "jwk_raw":
        import_key(payload, "oct")
    else:  # pragma: no cover - defensive programming
        raise ValueError(f"Unknown fuzz target: {target}")


def _alarm_handler(signum: int, frame: Any) -> None:
    raise FuzzTimeout()


def _mutate(target: str, seed_value: Any, rng: random.Random) -> Any:
    if target in ("jws_compact", "jwe_compact"):
        return mutate_compact(seed_value, rng)
    if target in ("jws_json", "jwe_json", "jwk_dict"):
        return mutate_json(seed_value, rng)
    return mutate_bytes(seed_value, rng)


def run_fuzz(
    iterations: int = DEFAULT_ITERATIONS,
    seed: int = DEFAULT_SEED,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    seeds: FuzzSeeds | None = None,
) -> FuzzResult:
    """Run deterministic mutation fuzzing and return a :class:`FuzzResult`."""
    warnings.simplefilter("ignore")
    rng = random.Random(seed)
    if seeds is None:
        seeds = build_seeds()
    entries = seeds.compact + seeds.json_serialized + seeds.jwk_dicts + seeds.raw_keys
    result = FuzzResult(iterations=iterations, seed=seed)

    previous_handler = signal.signal(signal.SIGALRM, _alarm_handler)
    try:
        for iteration in range(iterations):
            target, seed_value = entries[rng.randrange(len(entries))]
            payload = _mutate(target, seed_value, rng)
            signal.setitimer(signal.ITIMER_REAL, timeout)
            try:
                dispatch(target, payload, seeds.keys)
            except FuzzTimeout:
                result.findings.append(
                    FuzzFinding(target, "timeout", None, "input exceeded time budget", payload, iteration)
                )
            except CONTROLLED_EXCEPTIONS:
                result.controlled += 1
            except Exception as exc:  # noqa: BLE001 - any other exception is a finding
                result.findings.append(
                    FuzzFinding(
                        target,
                        "exception",
                        type(exc).__name__,
                        str(exc)[:200],
                        payload,
                        iteration,
                    )
                )
            else:
                result.controlled += 1
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
    finally:
        signal.signal(signal.SIGALRM, previous_handler)
    return result


BYTES_MARKER = "bytes::b64::"


def encode_corpus_entry(finding: FuzzFinding) -> dict[str, Any]:
    """Serialize a finding into a JSON-friendly corpus record."""
    import base64

    payload = finding.payload
    if isinstance(payload, bytes):
        payload = BYTES_MARKER + base64.b64encode(payload).decode("ascii")
    return {
        "target": finding.target,
        "kind": finding.kind,
        "exception": finding.exception_name,
        "message": finding.message,
        "iteration": finding.iteration,
        "seed": DEFAULT_SEED,
        "payload": payload,
    }


def load_corpus_entry(record: dict[str, Any]) -> tuple[str, Any]:
    """Inverse of :func:`encode_corpus_entry` for deterministic replay."""
    import base64

    payload: Any = record["payload"]
    if isinstance(payload, str) and payload.startswith(BYTES_MARKER):
        payload = base64.b64decode(payload[len(BYTES_MARKER) :])
    return record["target"], payload


def _main() -> int:
    import argparse
    import os

    parser = argparse.ArgumentParser(description="joserfc stdlib fuzzing harness")
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--corpus-dir", default="tests/fuzz_corpus")
    args = parser.parse_args()
    result = run_fuzz(args.iterations, args.seed, args.timeout)
    if result.ok:
        print(f"fuzz ok: {result.controlled}/{result.iterations} inputs controlled (seed={result.seed})")
        return 0
    os.makedirs(args.corpus_dir, exist_ok=True)
    for finding in result.findings:
        entry = encode_corpus_entry(finding)
        path = os.path.join(args.corpus_dir, finding.corpus_name)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(entry, handle, indent=2, default=str)
        print(f"finding saved: {path} ({finding.exception_name or finding.kind})")
    print(f"fuzz failed: {len(result.findings)} finding(s) out of {result.iterations} iterations")
    return 1


if __name__ == "__main__":
    raise SystemExit(_main())
