# SPDX-FileCopyrightText: 2026 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""Process-wide tracking of one-time initialization values (IVs and nonces).

Stream cipher modes (e.g. CTR) and CBC require that the IV/nonce is never
reused with the same key. Reuse typically means that the same key stream is
encrypted under twice, or that plaintext equality becomes visible, which
compromises confidentiality.

This module keeps an explicit, process-wide registry of the initialization
values already consumed by ciphers created with the one-time semantic
(``reuse=False``). The registry is opt-in: ciphers created without that
semantic keep their historical, permissive behavior for backward
compatibility.
"""

from __future__ import annotations

import threading
from typing import Optional


class ReusedInitializationValueError(ValueError):
    """An IV/nonce already used with the same key was passed again.

    This is a subclass of :class:`ValueError`, so existing code catching
    ``ValueError`` keeps working.
    """


def normalize_reuse(reuse: Optional[bool], mode_name: str) -> Optional[bool]:
    """Validate the ``reuse`` keyword accepted by the stream-style modes.

    Args:
        reuse:
            - ``None`` (the default): no tracking is performed, like in older
              releases (backward-compatible behavior).
            - ``True``: the caller explicitly declares that reusing the
              IV/nonce is intended; no tracking is performed.
            - ``False``: the IV/nonce is one-time; initializing another
              cipher with the same key and IV/nonce raises
              :class:`ReusedInitializationValueError`.
        mode_name:
            Human-readable name of the cipher mode, used in error messages.
    """

    if reuse is None or reuse is True or reuse is False:
        return reuse
    raise TypeError("'%s' reuse must be a boolean (True or False), or None" % mode_name)


class _OneTimeRegistry:
    """Track the (cipher name, key, initialization value) triples already
    consumed by ciphers created with the one-time semantic."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._used: set[tuple[str, bytes, bytes]] = set()

    def claim(
        self,
        cipher_name: str,
        key: bytes,
        init_value: bytes,
        reuse: Optional[bool],
    ) -> None:
        """Record a new initialization, or reject a repeated one.

        Nothing is tracked unless the one-time semantic (``reuse=False``)
        was explicitly requested.
        """

        if reuse is not False:
            return

        entry = (cipher_name, key, init_value)
        with self._lock:
            if entry in self._used:
                raise ReusedInitializationValueError(
                    "This IV/nonce has already been used with this key;"
                    " create a new one for each message, or pass reuse=True"
                    " if reuse is really intended"
                )
            self._used.add(entry)

    def reset(self) -> None:
        """Forget all recorded initializations (mostly useful for tests)."""

        with self._lock:
            self._used.clear()


one_time_registry = _OneTimeRegistry()
