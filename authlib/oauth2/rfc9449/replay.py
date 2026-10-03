"""authlib.oauth2.rfc9449.replay.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Replay detection storage for DPoP ``jti`` values, per RFC 9449
Section 11.1. The store interface is atomic: a single
``check_and_store`` call both detects and records a proof identifier,
so concurrent requests presenting the same proof cannot both pass.
"""

import threading
import time

__all__ = ["DPoPReplayStore", "InMemoryDPoPReplayStore"]


class DPoPReplayStore:
    """Interface of an atomic replay store. Developers MAY re-implement
    this interface with a shared backend (e.g. Redis ``SET NX PX``) so
    that replay detection works across multiple server instances.
    """

    def check_and_store(self, key: str, expires_at: float) -> bool:
        """Atomically store ``key`` if absent.

        :param key: unique identifier of the proof, usually ``jkt:jti``
        :param expires_at: POSIX timestamp after which the entry MAY be
            discarded
        :return: ``True`` if the key was newly stored (the proof is
            fresh), ``False`` if the key already existed (the proof is
            a replay)
        """
        raise NotImplementedError()


class InMemoryDPoPReplayStore(DPoPReplayStore):
    """A thread-safe in-process replay store, suitable for a single
    server instance and for tests."""

    def __init__(self, now=None):
        self._data = {}
        self._lock = threading.Lock()
        self._now = now or time.time

    def check_and_store(self, key: str, expires_at: float) -> bool:
        with self._lock:
            self._purge()
            if key in self._data:
                return False
            self._data[key] = expires_at
            return True

    def _purge(self):
        now = self._now()
        expired = [k for k, exp in self._data.items() if exp <= now]
        for k in expired:
            del self._data[k]
