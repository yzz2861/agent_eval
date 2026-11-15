# Copyright 2013 Donald Stufft and individual contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import os
import pickle

import pytest

import nacl.exceptions
import nacl.secret
import nacl.utils


def test_random_bytes_produces():
    assert len(nacl.utils.random(16)) == 16


def test_random_bytes_produces_different_bytes():
    assert nacl.utils.random(16) != nacl.utils.random(16)


def test_string_fixer():
    assert str(nacl.secret.SecretBox(b"\x00" * 32)) == str(b"\x00" * 32)


def test_deterministic_random_bytes():
    expected = (
        b"0d8e6cc68715648926732e7ea73250cfaf2d58422083904c841a8ba"
        b"33b986111f346ba50723a68ae283524a6bded09f83be6b80595856f"
        b"72e25b86918e8b114bafb94bc8abedd73daab454576b7c5833eb0bf"
        b"982a1bb4587a5c970ff0810ca3b791d7e12"
    )
    seed = (
        b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d"
        b"\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b"
        b"\x1c\x1d\x1e\x1f"
    )
    assert (
        nacl.utils.randombytes_deterministic(
            100, seed, encoder=nacl.encoding.HexEncoder
        )
        == expected
    )


def test_deterministic_random_bytes_invalid_seed_length():
    expected = "Deterministic random bytes must be generated from 32 bytes"
    seed = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
    with pytest.raises(TypeError) as e:
        nacl.utils.randombytes_deterministic(100, seed)
    assert expected in str(e.value)


NONCE_SIZE = nacl.secret.SecretBox.NONCE_SIZE


def test_random_nonce_generator_is_nonce_generator():
    generator = nacl.utils.RandomNonceGenerator()
    nonce = generator(NONCE_SIZE)

    assert isinstance(generator, nacl.utils.NonceGenerator)
    assert len(nonce) == NONCE_SIZE
    assert generator(NONCE_SIZE) != nonce


def test_random_nonce_generator_detects_collision(monkeypatch):
    generator = nacl.utils.RandomNonceGenerator()
    nonce = generator(NONCE_SIZE)
    monkeypatch.setattr(nacl.utils, "random", lambda size: nonce)

    with pytest.raises(nacl.exceptions.NonceReuseError) as info:
        generator(NONCE_SIZE)
    assert nonce.hex() in str(info.value)
    assert generator.scope in str(info.value)


def test_counter_nonce_generator_layout():
    generator = nacl.utils.CounterNonceGenerator(b"layout-w")

    nonce_0 = generator(NONCE_SIZE)
    nonce_1 = generator(NONCE_SIZE)

    assert nonce_0.startswith(b"layout-w")
    assert len(nonce_0) == NONCE_SIZE
    assert nonce_1.startswith(b"layout-w")
    assert nonce_0 != nonce_1
    assert generator.counter == 2


def test_counter_nonce_generator_rejects_reuse_with_scope():
    generator = nacl.utils.CounterNonceGenerator(b"scope-w")
    nonce = generator(NONCE_SIZE)

    with pytest.raises(nacl.exceptions.NonceReuseError) as info:
        generator.check_nonce(nonce)
    message = str(info.value)
    assert nonce.hex() in message
    assert generator.scope in message


def test_counter_nonce_generator_rollback_is_rejected():
    generator = nacl.utils.CounterNonceGenerator(b"rollback-w")
    first = generator(NONCE_SIZE)
    generator(NONCE_SIZE)
    rolled_back = nacl.utils.CounterNonceGenerator(b"rollback-w", counter=0)

    with pytest.raises(nacl.exceptions.NonceReuseError):
        rolled_back.check_nonce(first)


def test_counter_nonce_generator_boundary():
    generator = nacl.utils.CounterNonceGenerator(b"p" * (NONCE_SIZE - 1))

    for value in range(256):
        nonce = generator(NONCE_SIZE)
        assert nonce[-1] == value

    with pytest.raises(nacl.exceptions.NonceOverflowError) as info:
        generator(NONCE_SIZE)
    assert "256" in str(info.value)
    assert generator.scope in str(info.value)


def test_counter_nonce_generator_eager_boundary_check():
    with pytest.raises(nacl.exceptions.NonceOverflowError):
        nacl.utils.CounterNonceGenerator(
            b"p" * (NONCE_SIZE - 1), counter=256, nonce_size=NONCE_SIZE
        )


def test_counter_nonce_generator_requires_prefix_room():
    with pytest.raises(nacl.exceptions.ValueError):
        nacl.utils.CounterNonceGenerator(
            b"p" * NONCE_SIZE, nonce_size=NONCE_SIZE
        )


def test_counter_nonce_generator_validates_arguments():
    with pytest.raises(nacl.exceptions.TypeError):
        nacl.utils.CounterNonceGenerator("not-bytes")
    with pytest.raises(nacl.exceptions.ValueError):
        nacl.utils.CounterNonceGenerator(b"")
    with pytest.raises(nacl.exceptions.TypeError):
        nacl.utils.CounterNonceGenerator(b"p", counter=True)
    with pytest.raises(nacl.exceptions.ValueError):
        nacl.utils.CounterNonceGenerator(b"p", counter=-1)


def test_counter_nonce_generator_for_process_prefix():
    generator = nacl.utils.CounterNonceGenerator.for_process(
        b"worker-7", nonce_size=NONCE_SIZE
    )
    other = nacl.utils.CounterNonceGenerator.for_process(
        b"worker-8", nonce_size=NONCE_SIZE
    )

    assert generator.prefix.startswith(b"worker-7")
    assert other.prefix.startswith(b"worker-8")
    assert generator.prefix != other.prefix
    assert len(generator(NONCE_SIZE)) == NONCE_SIZE


def test_counter_nonce_generator_for_process_accepts_integer_worker():
    generator = nacl.utils.CounterNonceGenerator.for_process(7)

    assert generator.prefix
    assert len(generator(NONCE_SIZE)) == NONCE_SIZE
    with pytest.raises(nacl.exceptions.ValueError):
        nacl.utils.CounterNonceGenerator.for_process(-1)


def test_counter_nonce_generator_pickle_keeps_counter_and_history():
    generator = nacl.utils.CounterNonceGenerator(b"pickle-w")
    first = generator(NONCE_SIZE)
    second = generator(NONCE_SIZE)

    restored = pickle.loads(pickle.dumps(generator))

    assert restored.counter == generator.counter == 2
    third = restored(NONCE_SIZE)
    assert third not in (first, second)
    with pytest.raises(nacl.exceptions.NonceReuseError):
        restored.check_nonce(first)


def test_random_nonce_generator_pickle_keeps_history(monkeypatch):
    generator = nacl.utils.RandomNonceGenerator()
    nonce = generator(NONCE_SIZE)
    restored = pickle.loads(pickle.dumps(generator))
    monkeypatch.setattr(nacl.utils, "random", lambda size: nonce)

    with pytest.raises(nacl.exceptions.NonceReuseError):
        restored(NONCE_SIZE)


def test_counter_nonce_generator_detects_fork():
    generator = nacl.utils.CounterNonceGenerator(b"fork-w")
    generator(NONCE_SIZE)

    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - runs in the forked child
        os.close(read_fd)
        try:
            generator(NONCE_SIZE)
        except nacl.exceptions.NonceGeneratorForkError as error:
            message = str(error).encode()
            child = nacl.utils.CounterNonceGenerator.for_process(
                b"child", nonce_size=NONCE_SIZE
            )
            child_nonce = child(NONCE_SIZE)
            os.write(write_fd, message + b"|" + child_nonce)
        finally:
            os.close(write_fd)
            os._exit(0)

    os.close(write_fd)
    payload = os.read(read_fd, 4096)
    os.waitpid(pid, 0)
    message, child_nonce = payload.split(b"|", 1)

    assert str(os.getpid()).encode() in message
    assert len(child_nonce) == NONCE_SIZE
    assert child_nonce.startswith(b"child")
