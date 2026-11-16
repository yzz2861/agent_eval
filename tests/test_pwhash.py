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
from __future__ import annotations

import binascii
import json
import os
import sys
import unicodedata as ud

import pytest
from hypothesis import given, settings
from hypothesis.strategies import integers, text

import nacl.bindings
import nacl.encoding
import nacl.exceptions as exc
import nacl.pwhash
import nacl.pwhash._params as _pwhash_params

_all_unicode = "".join(chr(i) for i in range(sys.maxunicode))
PASSWD_CHARS = "".join(
    c
    for c in _all_unicode
    if (
        ud.category(c).startswith("L")
        or ud.category(c).startswith("N")
        or ud.category(c) == "Zs"
    )
)
# Select Letters, number representations and spacing characters


def argon2i_modular_crypt_ref() -> list[tuple[str, str]]:
    DATA = "modular_crypt_argon2i_hashes.json"
    path = os.path.join(os.path.dirname(__file__), "data", DATA)
    with open(path) as f:
        jvectors = json.load(f)
    vectors = [
        (x["pwhash"], x["passwd"]) for x in jvectors if x["mode"] == "crypt"
    ]
    return vectors


def argon2i_raw_ref() -> list[tuple[int, str, str, int, int, str]]:
    DATA = "raw_argon2i_hashes.json"
    path = os.path.join(os.path.dirname(__file__), "data", DATA)
    with open(path) as f:
        jvectors = json.load(f)
    vectors = [
        (
            x["dgst_len"],
            x["passwd"],
            x["salt"],
            x["iters"],
            x["maxmem"],
            x["pwhash"],
        )
        for x in jvectors
        if x["mode"] == "raw"
    ]
    return vectors


def argon2id_modular_crypt_ref() -> list[tuple[str, str]]:
    DATA = "modular_crypt_argon2id_hashes.json"
    path = os.path.join(os.path.dirname(__file__), "data", DATA)
    with open(path) as f:
        jvectors = json.load(f)
    vectors = [
        (x["pwhash"], x["passwd"])
        for x in jvectors
        if (x["mode"] == "crypt" and x["construct"] == "argon2id")
    ]
    return vectors


def argon2id_raw_ref() -> list[tuple[int, str, str, int, int, str]]:
    DATA = "raw_argon2id_hashes.json"
    path = os.path.join(os.path.dirname(__file__), "data", DATA)
    with open(path) as f:
        jvectors = json.load(f)
    vectors = [
        (
            x["dgst_len"],
            x["passwd"],
            x["salt"],
            x["iters"],
            x["maxmem"],
            x["pwhash"],
        )
        for x in jvectors
        if (x["mode"] == "raw" and x["construct"] == "argon2id")
    ]
    return vectors


@pytest.mark.skipif(
    not nacl.pwhash.scrypt.AVAILABLE, reason="Requires full build of libsodium"
)
@pytest.mark.parametrize(
    ("size", "password", "salt", "opslimit", "memlimit", "expected"),
    [
        (
            32,
            b"The quick brown fox jumps over the lazy dog.",
            b"ef537f25c895bfa782526529a9b63d97",
            32768,
            (2**20) * 100,
            (
                b"\x10e>\xc8A8\x11\xde\x07\xf1\x0f\x98"
                b"EG\xe6}V]\xd4yN\xae\xd3P\x87yP\x1b\xc7+n*"
            ),
        ),
    ],
)
def test_kdf_scryptsalsa208sha256(
    size: int,
    password: bytes,
    salt: bytes,
    opslimit: int,
    memlimit: int,
    expected: bytes,
):
    res = nacl.pwhash.kdf_scryptsalsa208sha256(
        size, password, salt, opslimit, memlimit
    )
    assert res == expected


@pytest.mark.skipif(
    not nacl.pwhash.scrypt.AVAILABLE, reason="Requires full build of libsodium"
)
@pytest.mark.parametrize(
    ("password",), [(b"The quick brown fox jumps over the lazy dog.",)]
)
def test_scryptsalsa208sha256_random(password: bytes):
    h1 = nacl.pwhash.scryptsalsa208sha256_str(password)
    h2 = nacl.pwhash.scryptsalsa208sha256_str(password)
    assert h1 != h2


@pytest.mark.skipif(
    not nacl.pwhash.scrypt.AVAILABLE, reason="Requires full build of libsodium"
)
@pytest.mark.parametrize(
    ("password",), [(b"The quick brown fox jumps over the lazy dog.",)]
)
def test_scryptsalsa208sha256_verify(password: bytes):
    assert nacl.pwhash.verify_scryptsalsa208sha256(
        nacl.pwhash.scryptsalsa208sha256_str(password), password
    )


@pytest.mark.skipif(
    not nacl.pwhash.scrypt.AVAILABLE, reason="Requires full build of libsodium"
)
@pytest.mark.parametrize(
    ("password",), [(b"The quick brown fox jumps over the lazy dog.",)]
)
def test_scryptsalsa208sha256_verify_incorrect(password: bytes):
    with pytest.raises(exc.InvalidkeyError):
        nacl.pwhash.verify_scryptsalsa208sha256(
            nacl.pwhash.scryptsalsa208sha256_str(password),
            password.replace(b"dog", b"cat"),
        )


@pytest.mark.skipif(
    not nacl.pwhash.scrypt.AVAILABLE, reason="Requires full build of libsodium"
)
@pytest.mark.parametrize(
    ("size", "password", "salt", "opslimit", "memlimit"),
    [
        (
            32,
            b"The quick brown fox jumps over the lazy dog.",
            b"ef537f25c895bfa782526529a9",
            32768,
            (2**20) * 100,
        ),
    ],
)
def test_wrong_salt_length(
    size: int, password: bytes, salt: bytes, opslimit: int, memlimit: int
):
    with pytest.raises(exc.ValueError):
        nacl.pwhash.kdf_scryptsalsa208sha256(
            size, password, salt, opslimit, memlimit
        )


@pytest.mark.skipif(
    not nacl.pwhash.scrypt.AVAILABLE, reason="Requires full build of libsodium"
)
@pytest.mark.parametrize(
    ("passwd_hash", "password"),
    [
        (
            b"Too short (and wrong) hash",
            b"a password",
        )
    ],
)
def test_wrong_hash_length(passwd_hash: bytes, password: bytes):
    with pytest.raises(exc.ValueError):
        nacl.pwhash.verify_scryptsalsa208sha256(passwd_hash, password)


@pytest.mark.skipif(
    not nacl.pwhash.scrypt.AVAILABLE, reason="Requires full build of libsodium"
)
@pytest.mark.parametrize(
    ("size", "password", "salt", "opslimit", "memlimit"),
    [
        (
            32,
            b"The quick brown fox jumps over the lazy dog.",
            b"ef537f25c895bfa782526529a9b6",
            32768,
            (2**20) * 100,
        ),
    ],
)
def test_kdf_wrong_salt_length(
    size: int, password: bytes, salt: bytes, opslimit: int, memlimit: int
):
    with pytest.raises(exc.ValueError):
        nacl.pwhash.kdf_scryptsalsa208sha256(
            size, password, salt, opslimit, memlimit
        )


@pytest.mark.skipif(
    not nacl.pwhash.scrypt.AVAILABLE, reason="Requires full build of libsodium"
)
@pytest.mark.parametrize(
    ("passwd_hash", "password"),
    [
        (
            b"Too short (and wrong) hash",
            b"another password",
        )
    ],
)
def test_str_verify_wrong_hash_length(passwd_hash: bytes, password: bytes):
    with pytest.raises(exc.ValueError):
        nacl.pwhash.verify_scryptsalsa208sha256(passwd_hash, password)


@pytest.mark.skipif(
    not nacl.pwhash.scrypt.AVAILABLE, reason="Requires full build of libsodium"
)
@pytest.mark.parametrize(
    ("size", "password", "salt", "opslimit", "memlimit", "expected"),
    [
        (
            32,
            b"The quick brown fox jumps over the lazy dog.",
            b"ef537f25c895bfa782526529a9b63d97",
            32768,
            (2**20) * 100,
            (
                b"\x10e>\xc8A8\x11\xde\x07\xf1\x0f\x98"
                b"EG\xe6}V]\xd4yN\xae\xd3P\x87yP\x1b\xc7+n*"
            ),
        ),
    ],
)
def test_scrypt_kdf(
    size: int,
    password: bytes,
    salt: bytes,
    opslimit: int,
    memlimit: int,
    expected: bytes,
):
    res = nacl.pwhash.scrypt.kdf(size, password, salt, opslimit, memlimit)
    assert res == expected


@pytest.mark.skipif(
    not nacl.pwhash.scrypt.AVAILABLE, reason="Requires full build of libsodium"
)
@pytest.mark.parametrize(
    ("password",), [(b"The quick brown fox jumps over the lazy dog.",)]
)
def test_scrypt_random(password: bytes):
    h1 = nacl.pwhash.scrypt.str(password)
    h2 = nacl.pwhash.scrypt.str(password)
    assert h1 != h2


@pytest.mark.skipif(
    not nacl.pwhash.scrypt.AVAILABLE, reason="Requires full build of libsodium"
)
@pytest.mark.parametrize(
    ("password",), [(b"The quick brown fox jumps over the lazy dog.",)]
)
def test_scrypt_verify(password: bytes):
    assert nacl.pwhash.scrypt.verify(
        nacl.pwhash.scrypt.str(password), password
    )


@pytest.mark.skipif(
    not nacl.pwhash.scrypt.AVAILABLE, reason="Requires full build of libsodium"
)
@pytest.mark.parametrize(
    ("password",), [(b"The quick brown fox jumps over the lazy dog.",)]
)
def test_scrypt_verify_incorrect(password: bytes):
    with pytest.raises(exc.InvalidkeyError):
        nacl.pwhash.scrypt.verify(
            nacl.pwhash.scrypt.str(password), password.replace(b"dog", b"cat")
        )


@pytest.mark.skipif(
    not nacl.pwhash.scrypt.AVAILABLE, reason="Requires full build of libsodium"
)
@pytest.mark.parametrize(
    ("size", "password", "salt", "opslimit", "memlimit"),
    [
        (
            32,
            b"The quick brown fox jumps over the lazy dog.",
            b"ef537f25c895bfa782526529a9",
            32768,
            (2**20) * 100,
        ),
    ],
)
def test_wrong_scrypt_salt_length(
    size: int, password: bytes, salt: bytes, opslimit: int, memlimit: int
):
    with pytest.raises(exc.ValueError):
        nacl.pwhash.scrypt.kdf(size, password, salt, opslimit, memlimit)


@pytest.mark.skipif(
    not nacl.pwhash.scrypt.AVAILABLE, reason="Requires full build of libsodium"
)
@pytest.mark.parametrize(
    ("passwd_hash", "password"),
    [
        (
            b"Too short (and wrong) hash",
            b"a password",
        )
    ],
)
def test_wrong_scrypt_hash_length(passwd_hash: bytes, password: bytes):
    with pytest.raises(exc.ValueError):
        nacl.pwhash.scrypt.verify(passwd_hash, password)


@pytest.mark.skipif(
    not nacl.pwhash.scrypt.AVAILABLE, reason="Requires full build of libsodium"
)
@pytest.mark.parametrize(
    ("size", "password", "salt", "opslimit", "memlimit"),
    [
        (
            32,
            b"The quick brown fox jumps over the lazy dog.",
            b"ef537f25c895bfa782526529a9b6",
            32768,
            (2**20) * 100,
        ),
    ],
)
def test_scrypt_kdf_wrong_salt_length(
    size: int, password: bytes, salt: bytes, opslimit: int, memlimit: int
):
    with pytest.raises(exc.ValueError):
        nacl.pwhash.scrypt.kdf(size, password, salt, opslimit, memlimit)


@pytest.mark.parametrize(
    ("opslimit", "memlimit", "n", "r", "p"),
    [
        (32768, 2 * (2**20), 10, 8, 1),
        (32768, 8 * (2**10), 3, 8, 128),
        (65536, (2**20) * 2, 11, 8, 1),
        (262144, (2**20) * 2, 11, 8, 4),
        (2 * (2**20), 2 * (2**20), 11, 8, 32),
    ],
)
def test_variable_limits(opslimit: int, memlimit: int, n: int, r: int, p: int):
    rn, rr, rp = nacl.bindings.nacl_bindings_pick_scrypt_params(
        opslimit, memlimit
    )
    assert rn == n
    assert rr == r
    assert rp == p


@pytest.mark.skipif(
    not nacl.pwhash.scrypt.AVAILABLE, reason="Requires full build of libsodium"
)
@pytest.mark.parametrize(
    ("passwd_hash", "password"),
    [
        (
            b"Too short (and wrong) hash",
            b"another password",
        )
    ],
)
def test_scrypt_str_verify_wrong_hash_length(
    passwd_hash: bytes, password: bytes
):
    with pytest.raises(exc.ValueError):
        nacl.pwhash.scrypt.verify(passwd_hash, password)


@pytest.mark.parametrize(
    ("password_hash", "password"),
    argon2i_modular_crypt_ref() + argon2id_modular_crypt_ref(),
)
def test_str_verify_argon2_ref(password_hash: str, password: str):
    pw_hash = password_hash.encode("ascii")
    pw = password.encode("ascii")
    res = nacl.pwhash.argon2id.verify(pw_hash, pw)
    assert res is True


@pytest.mark.parametrize(
    ("password_hash", "password"),
    argon2i_modular_crypt_ref() + argon2id_modular_crypt_ref(),
)
def test_str_verify_argon2_ref_fail(password_hash: str, password: str):
    pw_hash = password_hash.encode("ascii")
    pw = ("a" + password).encode("ascii")
    with pytest.raises(exc.InvalidkeyError):
        nacl.pwhash.argon2id.verify(pw_hash, pw)


@given(
    text(alphabet=PASSWD_CHARS, min_size=5, max_size=20),
    integers(min_value=4, max_value=6),
    integers(min_value=1024 * 1024, max_value=16 * 1024 * 1024).map(
        lambda value: value - (value % 1024)
    ),
)
@settings(deadline=None, max_examples=20)
def test_argon2i_str_and_verify(password: str, ops: int, mem: int):
    _psw = password.encode("utf-8")
    pw_hash = nacl.pwhash.argon2i.str(_psw, opslimit=ops, memlimit=mem)
    res = nacl.pwhash.argon2i.verify(pw_hash, _psw)
    assert res is True


@given(
    text(alphabet=PASSWD_CHARS, min_size=5, max_size=20),
    integers(min_value=1, max_value=4),
    integers(min_value=1024 * 1024, max_value=16 * 1024 * 1024).map(
        lambda value: value - (value % 1024)
    ),
)
@settings(deadline=None, max_examples=20)
def test_argon2id_str_and_verify(password: str, ops: int, mem: int):
    _psw = password.encode("utf-8")
    pw_hash = nacl.pwhash.argon2id.str(_psw, opslimit=ops, memlimit=mem)
    res = nacl.pwhash.argon2id.verify(pw_hash, _psw)
    assert res is True


@given(
    text(alphabet=PASSWD_CHARS, min_size=5, max_size=20),
    integers(min_value=4, max_value=6),
    integers(min_value=1024 * 1024, max_value=16 * 1024 * 1024).map(
        lambda value: value - (value % 1024)
    ),
)
@settings(deadline=None, max_examples=20)
def test_argon2i_str_and_verify_fail(password: str, ops: int, mem: int):
    _psw = password.encode("utf-8")
    pw_hash = nacl.pwhash.argon2i.str(_psw, opslimit=ops, memlimit=mem)
    with pytest.raises(exc.InvalidkeyError):
        nacl.pwhash.argon2i.verify(pw_hash, b"A" + _psw)


@given(text(alphabet=PASSWD_CHARS, min_size=5, max_size=20))
@settings(deadline=None, max_examples=5)
def test_pwhash_str_and_verify(password: str):
    _psw = password.encode("utf-8")

    a2i_hash = nacl.pwhash.argon2i.str(
        _psw,
        opslimit=nacl.pwhash.argon2i.OPSLIMIT_INTERACTIVE,
        memlimit=nacl.pwhash.argon2i.MEMLIMIT_INTERACTIVE,
    )
    a2i_res = nacl.pwhash.verify(a2i_hash, _psw)
    assert a2i_res is True

    a2id_hash = nacl.pwhash.argon2id.str(
        _psw,
        opslimit=nacl.pwhash.argon2id.OPSLIMIT_INTERACTIVE,
        memlimit=nacl.pwhash.argon2id.MEMLIMIT_INTERACTIVE,
    )
    a2id_res = nacl.pwhash.verify(a2id_hash, _psw)
    assert a2id_res is True


@pytest.mark.skipif(
    not nacl.pwhash.scrypt.AVAILABLE, reason="Requires full build of libsodium"
)
@given(text(alphabet=PASSWD_CHARS, min_size=5, max_size=20))
@settings(deadline=None, max_examples=5)
def test_pwhash_scrypt_str_and_verify(password: str):
    _psw = password.encode("utf-8")

    scrypt_hash = nacl.pwhash.scrypt.str(
        _psw,
        opslimit=nacl.pwhash.scrypt.OPSLIMIT_INTERACTIVE,
        memlimit=nacl.pwhash.scrypt.MEMLIMIT_INTERACTIVE,
    )
    scrypt_res = nacl.pwhash.verify(scrypt_hash, _psw)
    assert scrypt_res is True


def test_invalid_modular_scrypt_prefix():
    psw = b"always invalid password"
    invalid_modular_hash = b"$invalid_prefix$"
    with pytest.raises(exc.InvalidkeyError):
        nacl.pwhash.verify(invalid_modular_hash, psw)


def test_crypt_prefix_error():
    psw = b"always invalid password"
    invalid_modular_hash = b"$invalid_prefix$"
    with pytest.raises(exc.CryptPrefixError):
        nacl.pwhash.verify(invalid_modular_hash, psw)


@pytest.mark.parametrize(
    ("dk_size", "password", "salt", "iters", "mem_kb", "pwhash"),
    argon2i_raw_ref(),
)
def test_argon2i_kdf(
    dk_size: int,
    password: str,
    salt: str,
    iters: int,
    mem_kb: int,
    pwhash: str,
):
    dk = nacl.pwhash.argon2i.kdf(
        dk_size,
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iters,
        1024 * mem_kb,
    )
    ref = binascii.unhexlify(pwhash)
    assert dk == ref


@pytest.mark.parametrize(
    ("dk_size", "password", "salt", "iters", "mem_kb", "pwhash"),
    argon2id_raw_ref(),
)
def test_argon2_kdf_alg_argon2id(
    dk_size: int,
    password: str,
    salt: str,
    iters: int,
    mem_kb: int,
    pwhash: str,
):
    dk = nacl.pwhash.argon2id.kdf(
        dk_size,
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iters,
        1024 * mem_kb,
    )
    ref = binascii.unhexlify(pwhash)
    assert dk == ref


raising_argon2_parameters = [
    #  wrong salt length:
    (20, "aPassword", 3 * "salt", 3, 256),
    #  too short output:
    (15, "aPassword", 4 * "salt", 4, 256),
    #  too long output:
    (0xFFFFFFFF + 1, "aPassword", 4 * "salt", 4, 256),
    #  too high iteration count:
    (20, "aPassword", 4 * "salt", 0xFFFFFFFF + 1, 256),
    #  too low memory usage:
    (20, "aPassword", 4 * "salt", 4, 2),
    #  too high memory usage:
    (20, "aPassword", 4 * "salt", 4, 0xFFFFFFFF + 1),
]


@pytest.mark.parametrize(
    ("dk_size", "password", "salt", "iters", "mem_kb"),
    raising_argon2_parameters
    + [
        #  too low iteration count:
        (20, "aPassword", 4 * "salt", 1, 256),
    ],
)
def test_argon2i_kdf_invalid_parms(
    dk_size: int, password: str, salt: str, iters: int, mem_kb: int
):
    with pytest.raises(exc.ValueError):
        nacl.pwhash.argon2i.kdf(
            dk_size,
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iters,
            1024 * mem_kb,
        )


@pytest.mark.parametrize(
    ("dk_size", "password", "salt", "iters", "mem_kb"),
    raising_argon2_parameters
    + [
        #  too low iteration count:
        (20, "aPassword", 4 * "salt", 0, 256),
    ],
)
def test_argon2id_kdf_invalid_parms(
    dk_size: int, password: str, salt: str, iters: int, mem_kb: int
):
    with pytest.raises(exc.ValueError):
        nacl.pwhash.argon2id.kdf(
            dk_size,
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iters,
            1024 * mem_kb,
        )


def test_check_limits_for_unknown_algorithm():
    from nacl.bindings.crypto_pwhash import _check_argon2_limits_alg

    with pytest.raises(exc.TypeError):
        _check_argon2_limits_alg(4, 1024, -1)


@pytest.mark.skipif(
    nacl.pwhash.scrypt.AVAILABLE, reason="Requires minimal build of libsodium"
)
def test_scryptsalsa208sha256_unavailable():
    empty = b""

    with pytest.raises(exc.UnavailableError):
        nacl.pwhash.kdf_scryptsalsa208sha256(0, empty, empty)
    with pytest.raises(exc.UnavailableError):
        nacl.pwhash.scryptsalsa208sha256_str(empty)
    with pytest.raises(exc.UnavailableError):
        nacl.pwhash.verify_scryptsalsa208sha256(empty, empty)


@pytest.mark.skipif(
    nacl.pwhash.scrypt.AVAILABLE, reason="Requires minimal build of libsodium"
)
def test_scrypt_unavailable():
    empty = b""

    with pytest.raises(exc.UnavailableError):
        nacl.pwhash.scrypt.kdf(0, empty, empty)
    with pytest.raises(exc.UnavailableError):
        nacl.pwhash.scrypt.str(empty)
    with pytest.raises(exc.UnavailableError):
        nacl.pwhash.scrypt.verify(empty, empty)


# ---------------------------------------------------------------------------
# Server side validation of the work factor parameters and of the salt
# ---------------------------------------------------------------------------


LIMIT_CASES = [
    # opslimit below the scrypt/argon2 minimums
    ("opslimit_too_low", "ops", 32767, 16 * 1024 * 1024),
    # opslimit above the service cap
    (
        "opslimit_too_high",
        "ops",
        _pwhash_params.SERVER_OPSLIMIT_MAX + 1,
        16 * 1024 * 1024,
    ),
    # memlimit below the scrypt/argon2 minimums
    ("memlimit_too_low", "mem", 33554432, 1024),
    # memlimit above the service cap
    (
        "memlimit_too_high",
        "mem",
        33554432,
        _pwhash_params.SERVER_MEMLIMIT_MAX + 1024,
    ),
    # memlimit not aligned to MEMLIMIT_ALIGNMENT
    ("memlimit_misaligned", "mem", 33554432, 16 * 1024 * 1024 + 1),
]


@pytest.mark.skipif(
    not nacl.pwhash.scrypt.AVAILABLE, reason="Requires full build of libsodium"
)
@pytest.mark.parametrize(("case", "kind", "opslimit", "memlimit"), LIMIT_CASES)
def test_scrypt_kdf_rejects_out_of_limits(
    monkeypatch, case, kind, opslimit, memlimit
):
    salt = b"a" * nacl.pwhash.scrypt.SALTBYTES

    def boom(*args, **kwargs):
        raise AssertionError("key derivation must not start for " + case)

    monkeypatch.setattr(
        nacl.bindings, "nacl_bindings_pick_scrypt_params", boom
    )
    with pytest.raises(exc.ValueError):
        nacl.pwhash.scrypt.kdf(32, b"password", salt, opslimit, memlimit)


@pytest.mark.skipif(
    not nacl.pwhash.scrypt.AVAILABLE, reason="Requires full build of libsodium"
)
@pytest.mark.parametrize(("case", "kind", "opslimit", "memlimit"), LIMIT_CASES)
def test_scrypt_str_rejects_out_of_limits(
    monkeypatch, case, kind, opslimit, memlimit
):
    def boom(*args, **kwargs):
        raise AssertionError("hashing must not start for " + case)

    monkeypatch.setattr(
        nacl.bindings, "crypto_pwhash_scryptsalsa208sha256_str", boom
    )
    with pytest.raises(exc.ValueError):
        nacl.pwhash.scrypt.str(b"password", opslimit, memlimit)


ARGON2_LIMIT_CASES = [
    # opslimit below the per algorithm OPSLIMIT_MIN
    ("opslimit_too_low", "ops", 0, 16 * 1024 * 1024),
    # opslimit above the service cap
    (
        "opslimit_too_high",
        "ops",
        _pwhash_params.SERVER_OPSLIMIT_MAX + 1,
        16 * 1024 * 1024,
    ),
    # memlimit below MEMLIMIT_MIN
    ("memlimit_too_low", "mem", 4, 1024),
    # memlimit above the service cap
    (
        "memlimit_too_high",
        "mem",
        4,
        _pwhash_params.SERVER_MEMLIMIT_MAX + 1024,
    ),
    # memlimit not aligned to MEMLIMIT_ALIGNMENT
    ("memlimit_misaligned", "mem", 4, 16 * 1024 * 1024 + 1),
]


@pytest.mark.parametrize("module", (nacl.pwhash.argon2i, nacl.pwhash.argon2id))
@pytest.mark.parametrize(
    ("case", "kind", "opslimit", "memlimit"), ARGON2_LIMIT_CASES
)
def test_argon2_kdf_rejects_out_of_limits(
    monkeypatch, module, case, kind, opslimit, memlimit
):
    salt = b"a" * module.SALTBYTES

    def boom(*args, **kwargs):
        raise AssertionError("key derivation must not start for " + case)

    monkeypatch.setattr(nacl.bindings, "crypto_pwhash_alg", boom)
    with pytest.raises(exc.ValueError):
        module.kdf(32, b"password", salt, opslimit, memlimit)


@pytest.mark.parametrize("module", (nacl.pwhash.argon2i, nacl.pwhash.argon2id))
@pytest.mark.parametrize(
    ("case", "kind", "opslimit", "memlimit"), ARGON2_LIMIT_CASES
)
def test_argon2_str_rejects_out_of_limits(
    monkeypatch, module, case, kind, opslimit, memlimit
):
    def boom(*args, **kwargs):
        raise AssertionError("hashing must not start for " + case)

    monkeypatch.setattr(nacl.bindings, "crypto_pwhash_str_alg", boom)
    with pytest.raises(exc.ValueError):
        module.str(b"password", opslimit, memlimit)


@pytest.mark.parametrize("module", (nacl.pwhash.argon2i, nacl.pwhash.argon2id))
def test_argon2_boundary_limits_are_accepted(monkeypatch, module):
    salt = b"z" * module.SALTBYTES
    accepted = object()
    monkeypatch.setattr(nacl.bindings, "crypto_pwhash_alg", lambda *a: accepted)
    monkeypatch.setattr(
        nacl.bindings, "crypto_pwhash_str_alg", lambda *a: accepted
    )

    assert module.kdf(
        32,
        b"password",
        salt,
        module.OPSLIMIT_MIN,
        module.MEMLIMIT_MIN,
    ) is accepted
    assert module.kdf(
        32,
        b"password",
        salt,
        module.OPSLIMIT_SERVER_MAX,
        module.MEMLIMIT_SERVER_MAX,
    ) is accepted
    assert module.str(
        b"password",
        module.OPSLIMIT_SERVER_MAX,
        module.MEMLIMIT_SERVER_MAX,
    ) is accepted


@pytest.mark.skipif(
    not nacl.pwhash.scrypt.AVAILABLE, reason="Requires full build of libsodium"
)
def test_scrypt_boundary_limits_are_accepted(monkeypatch):
    module = nacl.pwhash.scrypt
    salt = b"z" * module.SALTBYTES
    accepted = object()

    monkeypatch.setattr(
        nacl.bindings, "nacl_bindings_pick_scrypt_params", lambda *a: (4, 8, 1)
    )
    monkeypatch.setattr(
        nacl.bindings,
        "crypto_pwhash_scryptsalsa208sha256_ll",
        lambda *a, **k: accepted,
    )
    monkeypatch.setattr(
        nacl.bindings, "crypto_pwhash_scryptsalsa208sha256_str", lambda *a: accepted
    )

    assert module.kdf(
        32,
        b"password",
        salt,
        module.OPSLIMIT_MIN,
        module.MEMLIMIT_MIN,
    ) is accepted
    assert module.kdf(
        32,
        b"password",
        salt,
        module.OPSLIMIT_SERVER_MAX,
        module.MEMLIMIT_SERVER_MAX,
    ) is accepted
    assert module.str(
        b"password",
        module.OPSLIMIT_SERVER_MAX,
        module.MEMLIMIT_SERVER_MAX,
    ) is accepted


@pytest.mark.parametrize("module", (nacl.pwhash.argon2i, nacl.pwhash.argon2id))
def test_argon2_kdf_rejects_bad_salt(module):
    secret_salt = b"\x00\x01\x02super-secret-salt-marker\x99"

    with pytest.raises(exc.ValueError) as excinfo:
        module.kdf(32, b"password", secret_salt[:-1], 4, 16 * 1024 * 1024)
    message = str(excinfo.value)
    assert str(module.SALTBYTES) in message
    assert b"secret" not in message.encode()
    assert b"marker" not in message.encode()

    with pytest.raises(exc.TypeError):
        module.kdf(
            32,
            b"password",
            "not-raw-bytes",  # type: ignore[arg-type]
            4,
            16 * 1024 * 1024,
        )


@pytest.mark.skipif(
    not nacl.pwhash.scrypt.AVAILABLE, reason="Requires full build of libsodium"
)
def test_scrypt_kdf_rejects_bad_salt():
    module = nacl.pwhash.scrypt
    secret_salt = b"\x00\x01\x02super-secret-scrypt-salt-marker" + b"\x99" * 8

    with pytest.raises(exc.ValueError) as excinfo:
        module.kdf(
            32,
            b"password",
            secret_salt[:-1],
            module.OPSLIMIT_INTERACTIVE,
            module.MEMLIMIT_INTERACTIVE,
        )
    message = str(excinfo.value)
    assert str(module.SALTBYTES) in message
    assert b"secret" not in message.encode()
    assert b"marker" not in message.encode()

    with pytest.raises(exc.TypeError):
        module.kdf(
            32,
            b"password",
            "not-raw-bytes",  # type: ignore[arg-type]
            module.OPSLIMIT_INTERACTIVE,
            module.MEMLIMIT_INTERACTIVE,
        )


@pytest.mark.parametrize("module", (nacl.pwhash.argon2i, nacl.pwhash.argon2id))
def test_argon2_bad_salt_fails_before_computation(monkeypatch, module):
    def boom(*args, **kwargs):
        raise AssertionError("key derivation must not start for a bad salt")

    monkeypatch.setattr(nacl.bindings, "crypto_pwhash_alg", boom)
    with pytest.raises((exc.ValueError, exc.TypeError)):
        module.kdf(32, b"password", b"short", 4, 16 * 1024 * 1024)


@pytest.mark.skipif(
    not nacl.pwhash.scrypt.AVAILABLE, reason="Requires full build of libsodium"
)
def test_scrypt_bad_salt_fails_before_computation(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("key derivation must not start for a bad salt")

    monkeypatch.setattr(
        nacl.bindings, "nacl_bindings_pick_scrypt_params", boom
    )
    with pytest.raises((exc.ValueError, exc.TypeError)):
        nacl.pwhash.scrypt.kdf(32, b"password", b"short")


@pytest.mark.parametrize("module", (nacl.pwhash.argon2i, nacl.pwhash.argon2id))
def test_argon2_kdf_rejects_non_integer_limits(module):
    salt = b"a" * module.SALTBYTES
    with pytest.raises(exc.TypeError):
        module.kdf(
            32, b"password", salt, 4.0, 16 * 1024 * 1024  # type: ignore[arg-type]
        )
    with pytest.raises(exc.TypeError):
        module.kdf(
            32, b"password", salt, 4, 16 * 1024 * 1024.0  # type: ignore[arg-type]
        )
    with pytest.raises(exc.TypeError):
        module.str(b"password", True, 16 * 1024 * 1024)


@pytest.mark.skipif(
    not nacl.pwhash.scrypt.AVAILABLE, reason="Requires full build of libsodium"
)
def test_scrypt_kdf_rejects_non_integer_limits():
    module = nacl.pwhash.scrypt
    salt = b"a" * module.SALTBYTES
    with pytest.raises(exc.TypeError):
        module.kdf(
            32,
            b"password",
            salt,
            32768.0,  # type: ignore[arg-type]
            module.MEMLIMIT_INTERACTIVE,
        )
    with pytest.raises(exc.TypeError):
        module.kdf(
            32,
            b"password",
            salt,
            module.OPSLIMIT_INTERACTIVE,
            16.0 * 1024 * 1024,  # type: ignore[arg-type]
        )


def test_limit_error_messages_are_diagnostic():
    salt = b"a" * nacl.pwhash.argon2id.SALTBYTES
    module = nacl.pwhash.argon2id
    bad_mem = _pwhash_params.SERVER_MEMLIMIT_MAX + 1024
    with pytest.raises(exc.ValueError) as excinfo:
        module.kdf(32, b"password", salt, 4, bad_mem)
    message = str(excinfo.value)
    assert "memlimit" in message
    assert str(_pwhash_params.SERVER_MEMLIMIT_MAX) in message
    assert str(bad_mem) in message

    bad_ops = _pwhash_params.SERVER_OPSLIMIT_MAX + 1
    with pytest.raises(exc.ValueError) as excinfo:
        module.str(b"password", bad_ops, module.MEMLIMIT_INTERACTIVE)
    message = str(excinfo.value)
    assert "opslimit" in message
    assert str(_pwhash_params.SERVER_OPSLIMIT_MAX) in message
    assert str(bad_ops) in message


# ---------------------------------------------------------------------------
# Legitimate hashing/verification keeps working through the public API
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("module", (nacl.pwhash.argon2i, nacl.pwhash.argon2id))
def test_argon2_str_verify_consistency(module):
    password = b"the quick brown fox"
    password_hash = module.str(
        password,
        opslimit=module.OPSLIMIT_INTERACTIVE,
        memlimit=module.MEMLIMIT_INTERACTIVE,
    )
    assert module.verify(password_hash, password) is True
    assert nacl.pwhash.verify(password_hash, password) is True
    with pytest.raises(exc.InvalidkeyError):
        module.verify(password_hash, b"wrong password")


@pytest.mark.skipif(
    not nacl.pwhash.scrypt.AVAILABLE, reason="Requires full build of libsodium"
)
def test_scrypt_str_verify_consistency():
    module = nacl.pwhash.scrypt
    password = b"the quick brown fox"
    password_hash = module.str(
        password,
        opslimit=module.OPSLIMIT_INTERACTIVE,
        memlimit=module.MEMLIMIT_INTERACTIVE,
    )
    assert module.verify(password_hash, password) is True
    assert nacl.pwhash.verify_scryptsalsa208sha256(password_hash, password) is True
    assert nacl.pwhash.verify(password_hash, password) is True
    with pytest.raises(exc.InvalidkeyError):
        module.verify(password_hash, b"wrong password")


@pytest.mark.skipif(
    not nacl.pwhash.scrypt.AVAILABLE, reason="Requires full build of libsodium"
)
def test_scrypt_kdf_results_are_stable():
    module = nacl.pwhash.scrypt
    salt = b"0123456789abcdef0123456789abcdef"
    args = (
        32,
        b"the quick brown fox",
        salt,
        module.OPSLIMIT_INTERACTIVE,
        module.MEMLIMIT_INTERACTIVE,
    )
    first = module.kdf(*args)
    second = nacl.pwhash.kdf_scryptsalsa208sha256(*args)
    assert first == second
    assert len(first) == 32


@pytest.mark.parametrize("module", (nacl.pwhash.argon2i, nacl.pwhash.argon2id))
def test_argon2_kdf_results_are_stable(module):
    salt = b"0123456789abcdef"
    args = (
        32,
        b"the quick brown fox",
        salt,
        module.OPSLIMIT_INTERACTIVE,
        module.MEMLIMIT_INTERACTIVE,
    )
    assert module.kdf(*args) == module.kdf(*args)
