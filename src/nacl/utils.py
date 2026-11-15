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

import os
from typing import (
    TYPE_CHECKING,
    ClassVar,
    Dict,
    Optional,
    SupportsBytes,
    Union,
)

import nacl.bindings
from nacl import encoding, exceptions as exc

if TYPE_CHECKING:
    from typing_extensions import Self


class NonceGenerator:
    """
    Abstract base class for pluggable nonce generation strategies.

    A generator is a callable returning a fresh nonce of the requested
    size. Implementations are responsible for never handing out the same
    nonce twice within their :attr:`scope`, and for remaining safe when a
    process using them is forked or when the generator is serialized and
    restored.

    :cvar scope: Human readable identifier of the uniqueness domain, used
                 when reporting nonce reuse.
    """

    scope: str

    def __call__(self, nonce_size: int) -> bytes:
        raise NotImplementedError

    def _describe(self, nonce: bytes) -> str:
        return (
            f"nonce {nonce.hex()} in scope {self.scope!r} "
            f"of {type(self).__name__}"
        )


class RandomNonceGenerator(NonceGenerator):
    """
    Default nonce strategy: draws every nonce from the operating system
    CSPRNG through :func:`random`.

    This preserves the historical behaviour of
    :meth:`~nacl.secret.SecretBox.encrypt` when no explicit strategy is
    configured. Random nonces carry no per-process or counter state, so
    forking and pickling do not affect their behaviour.

    :param scope: Label reported if the astronomically unlikely event of a
                  CSPRNG collision is ever observed.
    """

    def __init__(
        self,
        scope: str = "nacl.utils.RandomNonceGenerator",
    ) -> None:
        self.scope = scope
        self._seen: set[bytes] = set()

    def __call__(self, nonce_size: int) -> bytes:
        nonce = random(nonce_size)
        if nonce in self._seen:
            raise exc.NonceReuseError(
                f"reused random {self._describe(nonce)}",
            )
        self._seen.add(nonce)
        return nonce

    def __getstate__(self) -> Dict[str, object]:
        return {"scope": self.scope, "_seen": set(self._seen)}

    def __setstate__(self, state: Dict[str, object]) -> None:
        self.scope = state["scope"]
        self._seen = set(state["_seen"])


class CounterNonceGenerator(NonceGenerator):
    """
    Deterministic nonce strategy built from a process unique prefix and a
    big-endian counter.

    Each generated nonce is ``prefix + counter`` where ``counter`` occupies
    the trailing ``nonce_size - len(prefix)`` bytes of the nonce. Distinct
    workers must use distinct prefixes (see :meth:`for_process`); within a
    single process the monotonic counter guarantees uniqueness.

    Generators sharing a prefix share a process-wide registry of every
    nonce ever issued under that prefix, so a second generator whose
    counter was rolled back cannot silently re-emit a used nonce.

    Every nonce handed out, explicitly checked through :meth:`check_nonce`,
    or seen after a restart is remembered for the lifetime of the generator,
    so accidental reuse (including a counter rolled back by restoring older
    serialized state) is rejected instead of silently encrypting under a
    repeated key/nonce pair.

    The generator records the PID of the process it belongs to. After a
    :func:`os.fork`, child processes share the parent's memory image but
    must not keep emitting nonces from it; use :meth:`for_process` in the
    child to obtain a generator with a distinct prefix. Unpickling, which
    deliberately moves state into a new owner, is not treated as a fork.

    :param prefix: Fixed, process unique bytes prepended to every nonce.
    :param counter: Initial value of the big-endian counter. It must fit in
                    ``nonce_size - len(prefix)`` bytes when ``nonce_size``
                    is supplied; otherwise the bound is checked on first
                    use.
    :param nonce_size: Optional nonce length used to validate the prefix
                       and counter eagerly.
    :param scope: Label reported with any nonce reuse error. Defaults to an
                  identifier derived from the prefix.
    """

    _registries: ClassVar[Dict[bytes, set[bytes]]] = {}

    def __init__(
        self,
        prefix: bytes,
        counter: int = 0,
        nonce_size: Optional[int] = None,
        scope: Optional[str] = None,
    ) -> None:
        if not isinstance(prefix, bytes):
            raise exc.TypeError("prefix must be bytes")
        if not prefix:
            raise exc.ValueError(
                "a non-empty process unique prefix is required",
            )
        if not isinstance(counter, int) or isinstance(counter, bool):
            raise exc.TypeError("counter must be an integer")
        if counter < 0:
            raise exc.ValueError("counter must be non-negative")

        self._prefix = prefix
        self._counter = counter
        self._pid = os.getpid()
        self._seen = self._registries.setdefault(prefix, set())
        self.scope = (
            scope
            if scope is not None
            else f"nacl.utils.CounterNonceGenerator(prefix={prefix.hex()})"
        )

        if nonce_size is not None:
            self._check_layout(nonce_size, counter)

    @classmethod
    def for_process(
        cls,
        worker_id: Union[bytes, int] = b"",
        nonce_size: Optional[int] = None,
        random_size: int = 8,
    ) -> "CounterNonceGenerator":
        """
        Build a generator whose prefix is unique for the current process.

        The prefix combines ``worker_id`` (an explicit worker label or
        numeric id), the current PID, and ``random_size`` random bytes.
        Including randomness means two generators created in the same
        process, or in processes that happen to reuse a PID, still get
        distinct prefixes.

        :param worker_id: Optional bytes or non-negative integer naming the
                          worker. Integer ids are encoded big-endian.
        :param nonce_size: Forwarded to the constructor for eager layout
                           validation.
        :param random_size: Number of random bytes appended to the prefix.
        """
        if isinstance(worker_id, int):
            if isinstance(worker_id, bool) or worker_id < 0:
                raise exc.ValueError(
                    "worker_id must be a non-negative integer or bytes",
                )
            worker_id = worker_id.to_bytes(
                max(1, (worker_id.bit_length() + 7) // 8), "big"
            )
        elif not isinstance(worker_id, bytes):
            raise exc.TypeError("worker_id must be bytes or an integer")

        pid = os.getpid().to_bytes(4, "big")
        prefix = worker_id + pid + random(random_size)
        return cls(prefix, nonce_size=nonce_size)

    @property
    def prefix(self) -> bytes:
        """The fixed prefix prepended to every generated nonce."""
        return self._prefix

    @property
    def counter(self) -> int:
        """The next counter value that will be encoded."""
        return self._counter

    def _check_layout(self, nonce_size: int, counter: int) -> None:
        if len(self._prefix) >= nonce_size:
            raise exc.ValueError(
                f"prefix of {len(self._prefix)} bytes leaves no room for a "
                f"counter in a {nonce_size} byte nonce (scope "
                f"{self.scope!r})",
            )
        counter_width = nonce_size - len(self._prefix)
        maximum = (1 << (8 * counter_width)) - 1
        if counter > maximum:
            raise exc.NonceOverflowError(
                f"counter {counter} does not fit in {counter_width} "
                f"counter byte(s) (maximum {maximum}) in scope "
                f"{self.scope!r}",
            )

    def _check_pid(self) -> None:
        current_pid = os.getpid()
        if current_pid != self._pid:
            raise exc.NonceGeneratorForkError(
                f"nonce generator {self.scope!r} was created in process "
                f"{self._pid} but is being used in process {current_pid} "
                "after a fork(); create a per-process generator with "
                "CounterNonceGenerator.for_process() instead",
            )

    def check_nonce(self, nonce: bytes) -> None:
        """
        Reject ``nonce`` if it was already issued within :attr:`scope`.

        All generators with the same prefix share one history, so this
        also catches nonces issued by an earlier generator instance, for
        example when a counter has been rolled back to an older value.
        """
        if nonce in self._seen:
            raise exc.NonceReuseError(
                f"reused {self._describe(nonce)}",
            )

    def __call__(self, nonce_size: int) -> bytes:
        self._check_pid()
        self._check_layout(nonce_size, self._counter)

        counter_width = nonce_size - len(self._prefix)
        nonce = self._prefix + self._counter.to_bytes(counter_width, "big")
        self.check_nonce(nonce)

        self._seen.add(nonce)
        self._counter += 1
        return nonce

    def __getstate__(self) -> Dict[str, object]:
        return {
            "_prefix": self._prefix,
            "_counter": self._counter,
            "_seen": set(self._seen),
            "scope": self.scope,
        }

    def __setstate__(self, state: Dict[str, object]) -> None:
        self._prefix = state["_prefix"]
        self._counter = state["_counter"]
        self.scope = state["scope"]
        # Ownership moves to the unpickling process; do not mistake this
        # for a fork, but keep the monotonic counter and full history.
        self._pid = os.getpid()
        history = self._registries.setdefault(self._prefix, set())
        history.update(state["_seen"])
        self._seen = history


class EncryptedMessage(bytes):
    """
    A bytes subclass that holds a messaged that has been encrypted by a
    :class:`SecretBox`.
    """

    _nonce: bytes
    _ciphertext: bytes

    @classmethod
    def _from_parts(
        cls,
        nonce: bytes,
        ciphertext: bytes,
        combined: bytes,
    ) -> Self:
        obj = cls(combined)
        obj._nonce = nonce
        obj._ciphertext = ciphertext
        return obj

    @property
    def nonce(self) -> bytes:
        """
        The nonce used during the encryption of the :class:`EncryptedMessage`.
        """
        return self._nonce

    @property
    def ciphertext(self) -> bytes:
        """
        The ciphertext contained within the :class:`EncryptedMessage`.
        """
        return self._ciphertext


class StringFixer:
    def __str__(self: SupportsBytes) -> str:
        return str(self.__bytes__())


def bytes_as_string(bytes_in: bytes) -> str:
    return bytes_in.decode("ascii")


def random(size: int = 32) -> bytes:
    return os.urandom(size)


def randombytes_deterministic(
    size: int, seed: bytes, encoder: encoding.Encoder = encoding.RawEncoder
) -> bytes:
    """
    Returns ``size`` number of deterministically generated pseudorandom bytes
    from a seed

    :param size: int
    :param seed: bytes
    :param encoder: The encoder class used to encode the produced bytes
    :rtype: bytes
    """
    raw_data = nacl.bindings.randombytes_buf_deterministic(size, seed)

    return encoder.encode(raw_data)
