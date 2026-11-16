# Copyright 2026 Donald Stufft and individual contributors
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

"""
Shared validation helpers for the password hashing constructions.

Caller supplied work factors are checked against server side caps *before*
any memory is allocated or a key derivation is started, so that a tenant
cannot exhaust the container resources with an over sized ``memlimit``.

Salts are only handled as fixed length raw bytes: error messages report the
expected and observed salt length, but never the salt contents.
"""

from __future__ import annotations

from nacl import exceptions as exc
from nacl.exceptions import ensure

#: Upper bound enforced by the service for every password hash construction,
#: regardless of the much larger limits accepted by libsodium itself.
SERVER_OPSLIMIT_MAX = 33554432

#: Maximum memory occupation (in bytes) accepted by the service: 1 GiB.
SERVER_MEMLIMIT_MAX = 1024 * 1024 * 1024

#: ``memlimit`` must be a whole multiple of this block size, so the service
#: only deals with predictable, page aligned memory budgets.
MEMLIMIT_ALIGNMENT = 1024


def check_pwhash_params(
    opslimit: int,
    memlimit: int,
    opslimit_min: int,
    opslimit_max: int,
    memlimit_min: int,
    memlimit_max: int,
) -> None:
    """
    Validate the caller supplied ``opslimit`` and ``memlimit``.

    The accepted interval is the libsodium documented minimum/maximum
    intersected with the service caps; values outside of it, non integer
    values and misaligned memory limits raise before any computation
    starts.

    :raises nacl.exceptions.TypeError: if a limit is not an integer
    :raises nacl.exceptions.ValueError: if a limit is out of range or the
        memory limit is not aligned to :py:const:`MEMLIMIT_ALIGNMENT`
    """
    ensure(
        type(opslimit) is int,
        "opslimit must be an integer",
        raising=exc.TypeError,
    )
    ensure(
        type(memlimit) is int,
        "memlimit must be an integer",
        raising=exc.TypeError,
    )

    effective_opslimit_max = min(opslimit_max, SERVER_OPSLIMIT_MAX)
    ensure(
        opslimit_min <= opslimit <= effective_opslimit_max,
        (
            "opslimit must be between "
            f"{opslimit_min} and {effective_opslimit_max}, got {opslimit}"
        ),
        raising=exc.ValueError,
    )

    effective_memlimit_max = min(memlimit_max, SERVER_MEMLIMIT_MAX)
    ensure(
        memlimit_min <= memlimit <= effective_memlimit_max,
        (
            "memlimit must be between "
            f"{memlimit_min} and {effective_memlimit_max} bytes, "
            f"got {memlimit}"
        ),
        raising=exc.ValueError,
    )

    ensure(
        memlimit % MEMLIMIT_ALIGNMENT == 0,
        (
            "memlimit must be a multiple of "
            f"{MEMLIMIT_ALIGNMENT} bytes, got {memlimit}"
        ),
        raising=exc.ValueError,
    )


def check_salt(salt: bytes, salt_bytes: int) -> None:
    """
    Validate that ``salt`` is a raw bytes object exactly ``salt_bytes``
    long.

    Only the length is reported in the error message: the salt contents
    are never echoed back, so they cannot leak through exception logs.

    :raises nacl.exceptions.TypeError: if the salt is not raw bytes
    :raises nacl.exceptions.ValueError: if the salt length is wrong
    """
    ensure(
        type(salt) is bytes,
        "salt must be raw bytes",
        raising=exc.TypeError,
    )
    ensure(
        len(salt) == salt_bytes,
        (
            "the salt must be exactly "
            f"{salt_bytes} bytes long, got {len(salt)}"
        ),
        raising=exc.ValueError,
    )
