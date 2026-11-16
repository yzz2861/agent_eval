"""Deterministic mutation fuzzing for the CBOR decode entry points.

The fuzzer only relies on the Python standard library.  It mutates a small
seed corpus of valid COSE objects and checks that every decoder either returns
an object or rejects the input with ``CoseException``.  Native CBOR/Python
exceptions and per-input timeouts are test failures.

Set ``PYCOSE_FUZZ_SAVE_CORPUS=1`` to persist novel rejecting inputs in
``tests/corpus`` as hex files.  Normal test runs never modify the repository.
"""

import contextlib
import hashlib
import os
import random
import signal
import threading
import time
from pathlib import Path

import pytest

from pycose.exceptions import CoseException
from pycose.keys import CoseKey
from pycose.messages import CoseMessage, Enc0Message, Mac0Message, Sign1Message


CORPUS_DIR = Path(__file__).resolve().parent / "corpus"

FUZZ_SEED = int(os.environ.get("PYCOSE_FUZZ_SEED", "0xC05E"), 0)
FUZZ_ITERATIONS = int(os.environ.get("PYCOSE_FUZZ_ITERATIONS", "4096"))
FUZZ_TIMEOUT = float(os.environ.get("PYCOSE_FUZZ_TIMEOUT", "2.0"))
WRITE_CORPUS = os.environ.get("PYCOSE_FUZZ_SAVE_CORPUS") == "1"

# Valid, independently decodable samples.  Keeping them inline makes the seed
# set stable even if the JSON test-vector layout changes.
SEEDS = {
    "sign1": bytes.fromhex(
        "D28443A10126A10442313154546869732069732074686520636F6E74656E742E5840"
        "10729CD711CB3813D8D8E944A8DA7111E7B258C9BDCA6135F7AE1ADBEE950989"
        "1267837E1E33BD36C150326AE62755C6BD8E540C3E8F92D7D225E8DB72B8820B"
    ),
    "enc0": bytes.fromhex(
        "D08343A1010AA1054D89F52F65A1C580933B5261A72F581C6899DA0A132BD2D2"
        "B9B10915743EE1F7B92A4680E7C51BDBC1B320EA"
    ),
    "mac0": bytes.fromhex(
        "D18440A1010554546869732069732074686520636F6E74656E742E5820176DCE"
        "14C1E57430C13658233F41DC89AA4FA0FF9B8783F23B0EF51CA6B026BC"
    ),
    "key_symmetric": bytes.fromhex("A201042050000102030405060708090A0B0C0D0E0F"),
    "key_ec2": bytes.fromhex(
        "A401022001215820BAC5B11CAD8F99F9C72B05CF4B9E26D244DC189F7452"
        "28255A219A86D6A09EFF22582020138BF82DC1B6D562BE0FA54AB7804A3A64B6"
        "D72CCFED6B6FB6ED28BBFC117E"
    ),
    "key_okp": bytes.fromhex("A301012006215820D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A"),
}

DECODERS = (
    ("CoseMessage.decode", CoseMessage.decode, CoseMessage),
    ("Sign1Message.decode", Sign1Message.decode, Sign1Message),
    ("Enc0Message.decode", Enc0Message.decode, Enc0Message),
    ("Mac0Message.decode", Mac0Message.decode, Mac0Message),
    ("CoseKey.decode", CoseKey.decode, CoseKey),
)


class _InputTimeout(Exception):
    pass


@contextlib.contextmanager
def _time_limit(seconds: float):
    """Enforce a wall-clock limit when SIGALRM is available."""

    if not hasattr(signal, "setitimer") or threading.current_thread() is not threading.main_thread():
        start = time.monotonic()
        yield
        elapsed = time.monotonic() - start
        if elapsed > seconds:
            raise _InputTimeout(f"decoder took {elapsed:.3f}s")
        return

    def _handle_alarm(signum, frame):
        raise _InputTimeout(f"decoder exceeded {seconds:.3f}s")

    previous_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, _handle_alarm)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0] > 0:
            signal.setitimer(signal.ITIMER_REAL, *previous_timer)


def _corpus_files():
    return sorted(CORPUS_DIR.glob("*.hex"))


def _read_hex_sample(path: Path) -> bytes:
    return bytes.fromhex(path.read_text(encoding="ascii").strip())


def _save_corpus_sample(data: bytes, decoder_name: str, exc: CoseException) -> None:
    if not WRITE_CORPUS:
        return

    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    signature = f"{decoder_name}:{type(exc).__name__}:{exc}".encode("utf-8")
    digest = hashlib.sha256(data + b"\x00" + signature).hexdigest()[:20]
    path = CORPUS_DIR / f"fuzz_{digest}.hex"
    if not path.exists():
        path.write_text(data.hex() + "\n", encoding="ascii")


def _assert_decode_safe(data: bytes, decoder_name: str, decoder, expected_type) -> bool:
    label = f"{decoder_name} on {data.hex()}"
    try:
        with _time_limit(FUZZ_TIMEOUT):
            result = decoder(data)
    except CoseException as exc:
        _save_corpus_sample(data, decoder_name, exc)
        return False
    except _InputTimeout:
        pytest.fail(f"{label} did not finish within {FUZZ_TIMEOUT:.1f}s", pytrace=False)
    except Exception as exc:
        pytest.fail(
            f"{label} leaked {type(exc).__name__}: {exc}",
            pytrace=False,
        )

    assert isinstance(result, expected_type), f"{label} returned {type(result).__name__}"
    return True


def _random_bytes(rng: random.Random, max_length: int = 128) -> bytes:
    return bytes(rng.getrandbits(8) for _ in range(rng.randint(0, max_length)))


def _mutate(rng: random.Random, seeds) -> bytes:
    strategy = rng.randrange(8)

    if strategy == 0:
        return _random_bytes(rng)

    data = bytearray(rng.choice(seeds))

    if strategy == 1:
        for _ in range(rng.randint(1, 16)):
            if not data:
                break
            index = rng.randrange(len(data))
            data[index] ^= 1 << rng.randrange(8)

    elif strategy == 2:
        for _ in range(rng.randint(1, 8)):
            if not data:
                break
            data[rng.randrange(len(data))] = rng.getrandbits(8)

    elif strategy == 3:
        return bytes(data[:rng.randrange(len(data) + 1)])

    elif strategy == 4:
        if data:
            del data[rng.randrange(len(data))]

    elif strategy == 5:
        index = rng.randrange(len(data) + 1)
        data[index:index] = _random_bytes(rng, max_length=16)

    elif strategy == 6:
        other = rng.choice(seeds)
        if data and other:
            left = rng.randrange(len(data) + 1)
            right = rng.randrange(len(other) + 1)
            data = bytearray(bytes(data[:left]) + bytes(other[right:]))

    else:
        data.extend(_random_bytes(rng, max_length=16))

    return bytes(data)


@pytest.mark.parametrize("name", sorted(SEEDS))
def test_valid_seed_decodes(name):
    data = SEEDS[name]
    is_key = name.startswith("key_")
    decoder = CoseKey.decode if is_key else CoseMessage.decode
    expected_type = CoseKey if is_key else CoseMessage

    with _time_limit(FUZZ_TIMEOUT):
        decoded = decoder(data)

    assert isinstance(decoded, expected_type)


def test_decode_mutation_fuzz_is_deterministic_and_bounded():
    rng = random.Random(FUZZ_SEED)
    seeds = tuple(SEEDS[k] for k in sorted(SEEDS))

    for iteration in range(FUZZ_ITERATIONS):
        data = _mutate(rng, seeds)
        for decoder_name, decoder, expected_type in DECODERS:
            _assert_decode_safe(data, f"{decoder_name}#{iteration}", decoder, expected_type)


@pytest.mark.parametrize("path", _corpus_files(), ids=lambda path: path.stem)
def test_saved_corpus_samples_are_handled(path):
    data = _read_hex_sample(path)
    rejected = False

    for decoder_name, decoder, expected_type in DECODERS:
        if not _assert_decode_safe(data, f"{decoder_name}:{path.name}", decoder, expected_type):
            rejected = True

    assert rejected, f"corpus sample {path.name} no longer exercises a rejection path"
