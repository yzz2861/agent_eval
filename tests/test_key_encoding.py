"""
Tests for the versioned storage key encodings (:mod:`limits.keys`).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from limits import (
    RateLimitItemPerHour,
    RateLimitItemPerMinute,
    RateLimitItemPerSecond,
)
from limits.aio.storage.memory import MemoryStorage as AsyncMemoryStorage
from limits.aio.strategies import (
    FixedWindowRateLimiter as AsyncFixedWindowRateLimiter,
)
from limits.keys import DEFAULT_KEY_ENCODING
from limits.storage.memory import MemoryStorage
from limits.strategies import FixedWindowRateLimiter


class TestV1Compatibility:
    def test_default_encoding_is_v1(self):
        assert DEFAULT_KEY_ENCODING == "v1"

    def test_default_key_format_is_unchanged(self):
        item = RateLimitItemPerMinute(1)
        assert item.key_for("a/b", "c") == "LIMITER/a/b/c/1/1/minute"
        assert item.key_for("a/b", "c") == item.key_for("a/b", "c", encoding="v1")

    def test_v1_collides_on_identifier_boundaries(self):
        # reproduces the legacy flaw: component boundaries are lost, so
        # different identifier tuples collapse onto the same key
        item = RateLimitItemPerMinute(1)
        assert item.key_for("a/b", "c") == item.key_for("a", "b/c")

    def test_v1_collides_on_namespace_boundaries(self):
        assert RateLimitItemPerMinute(1, namespace="a").key_for("b/c") == (
            RateLimitItemPerMinute(1, namespace="a/b").key_for("c")
        )


class TestV2Encoding:
    def test_v2_golden_key(self):
        item = RateLimitItemPerMinute(2, 3, namespace="ns")
        assert item.key_for("a/b", "é", b"\x00\xff", 7, 1.5, encoding="v2") == (
            "v2|9|s2:ns|s3:a/b|s2:é|b2:00ff|i7|f1.5|i2|i3|s6:minute"
        )

    def test_v2_resolves_identifier_boundaries(self):
        item = RateLimitItemPerMinute(1)
        assert item.key_for("a/b", "c", encoding="v2") != item.key_for(
            "a", "b/c", encoding="v2"
        )

    def test_v2_resolves_namespace_boundaries(self):
        assert RateLimitItemPerMinute(1, namespace="a").key_for(
            "b/c", encoding="v2"
        ) != RateLimitItemPerMinute(1, namespace="a/b").key_for("c", encoding="v2")

    def test_v2_preserves_component_types(self):
        item = RateLimitItemPerMinute(1)
        keys = {
            item.key_for("1", encoding="v2"),
            item.key_for(b"1", encoding="v2"),
            item.key_for(1, encoding="v2"),
            item.key_for(1.0, encoding="v2"),
        }
        assert len(keys) == 4

    def test_v2_bool_follows_int_semantics(self):
        item = RateLimitItemPerMinute(1)
        assert item.key_for(True, encoding="v2") == item.key_for(1, encoding="v2")

    def test_v2_preserves_component_count(self):
        item = RateLimitItemPerMinute(1)
        assert item.key_for(encoding="v2") != item.key_for("", encoding="v2")
        assert item.key_for("a", "a", encoding="v2") != item.key_for(
            "aa", encoding="v2"
        )
        # namespace, amount, multiples and granularity are always present
        assert item.key_for(encoding="v2").startswith("v2|4|")
        assert item.key_for("a", "b", encoding="v2").startswith("v2|6|")

    def test_v2_key_reflects_limit_structure(self):
        assert RateLimitItemPerMinute(1).key_for("id", encoding="v2") != (
            RateLimitItemPerMinute(2).key_for("id", encoding="v2")
        )
        assert RateLimitItemPerMinute(1, 2).key_for("id", encoding="v2") != (
            RateLimitItemPerMinute(1, 3).key_for("id", encoding="v2")
        )
        assert RateLimitItemPerMinute(1).key_for("id", encoding="v2") != (
            RateLimitItemPerHour(1).key_for("id", encoding="v2")
        )
        ns1 = RateLimitItemPerMinute(1, namespace="ns1").key_for("id", encoding="v2")
        ns2 = RateLimitItemPerMinute(1, namespace="ns2").key_for("id", encoding="v2")
        assert ns1 != ns2

    def test_v2_length_prefix_counts_utf8_bytes(self):
        item = RateLimitItemPerMinute(1)
        key = item.key_for("é", encoding="v2")
        # a single character but two utf-8 bytes; a character based length
        # prefix would be ambiguous once the key is encoded for transport
        assert "s2:é" in key

    def test_v2_does_not_normalize_unicode(self):
        item = RateLimitItemPerMinute(1)
        assert item.key_for("\u00e9", encoding="v2") != item.key_for(
            "e\u0301", encoding="v2"
        )

    def test_v2_encodes_bytes_as_hex(self):
        key = RateLimitItemPerMinute(1).key_for(b"\x00\xff", encoding="v2")
        assert "b2:00ff" in key

    def test_v2_float_representation(self):
        item = RateLimitItemPerMinute(1)
        assert "f1.5" in item.key_for(1.5, encoding="v2")
        assert item.key_for(-0.0, encoding="v2") != item.key_for(0.0, encoding="v2")
        assert item.key_for(1.0, encoding="v2") != item.key_for(1, encoding="v2")

    @pytest.mark.parametrize(
        "identifier",
        [
            pytest.param(None, id="none"),
            pytest.param(object(), id="object"),
            pytest.param(["a"], id="list"),
            pytest.param({"a": 1}, id="dict"),
            pytest.param(float("nan"), id="nan"),
            pytest.param(float("inf"), id="inf"),
            pytest.param(float("-inf"), id="-inf"),
            pytest.param("\udcff", id="lone-surrogate"),
        ],
    )
    def test_v2_rejects_values_without_stable_representation(self, identifier):
        with pytest.raises((TypeError, ValueError)):
            RateLimitItemPerMinute(1).key_for(identifier, encoding="v2")

    def test_v2_key_is_deterministic_across_processes(self):
        expected = RateLimitItemPerMinute(2, 3, namespace="ns").key_for(
            "a/b", "é", b"\x00\xff", 7, 1.5, encoding="v2"
        )
        program = ";".join(
            [
                "from limits import RateLimitItemPerMinute",
                'item = RateLimitItemPerMinute(2, 3, namespace="ns")',
                'print(item.key_for("a/b", "é", b"\\x00\\xff", 7, 1.5, encoding="v2"))',
            ]
        )
        result = subprocess.run(
            [sys.executable, "-c", program],
            capture_output=True,
            text=True,
            check=True,
            cwd=Path(__file__).resolve().parent.parent,
        )
        assert result.stdout.strip() == expected


class TestUnknownEncoding:
    def test_key_for_rejects_unknown_encoding(self):
        with pytest.raises(ValueError, match="Unknown key encoding"):
            RateLimitItemPerMinute(1).key_for("a", encoding="v3")  # type: ignore[arg-type]

    def test_strategy_rejects_unknown_encoding(self):
        with pytest.raises(ValueError, match="Unknown key encoding"):
            FixedWindowRateLimiter(
                MemoryStorage("memory://"),
                key_encoding="v3",  # type: ignore[arg-type]
            )


class RecordingMemoryStorage(MemoryStorage):
    """
    Memory storage that records every key it is asked to operate on.
    """

    def __init__(self):
        super().__init__("memory://")
        self.recorded_keys: list[str] = []

    def incr(self, key, *args, **kwargs):
        self.recorded_keys.append(key)
        return super().incr(key, *args, **kwargs)

    def get(self, key):
        self.recorded_keys.append(key)
        return super().get(key)

    def get_expiry(self, key):
        self.recorded_keys.append(key)
        return super().get_expiry(key)

    def clear(self, key):
        self.recorded_keys.append(key)
        return super().clear(key)


class TestStrategyEncoding:
    def test_strategy_uses_single_encoding_for_all_operations(self):
        storage = RecordingMemoryStorage()
        limiter = FixedWindowRateLimiter(storage, key_encoding="v2")
        limit = RateLimitItemPerMinute(3)

        limiter.hit(limit, "user")
        limiter.test(limit, "user")
        limiter.get_window_stats(limit, "user")
        limiter.clear(limit, "user")

        assert storage.recorded_keys
        assert all(key.startswith("v2|") for key in storage.recorded_keys)
        assert len(set(storage.recorded_keys)) == 1

    def test_strategy_defaults_to_legacy_encoding(self):
        storage = RecordingMemoryStorage()
        limiter = FixedWindowRateLimiter(storage)
        limit = RateLimitItemPerMinute(3)

        limiter.hit(limit, "user")
        limiter.test(limit, "user")
        limiter.get_window_stats(limit, "user")
        limiter.clear(limit, "user")

        assert storage.recorded_keys
        assert set(storage.recorded_keys) == {"LIMITER/user/3/1/minute"}

    def test_encoding_versions_are_isolated(self):
        storage = MemoryStorage("memory://")
        limit = RateLimitItemPerSecond(2)
        legacy = FixedWindowRateLimiter(storage)
        structured = FixedWindowRateLimiter(storage, key_encoding="v2")

        assert legacy.hit(limit, "user")
        assert legacy.hit(limit, "user")
        assert not legacy.hit(limit, "user")

        # the v2 window for the same limit and identifiers is untouched
        assert structured.test(limit, "user")
        assert structured.get_window_stats(limit, "user").remaining == 2

        # and v2 hits do not leak back into the legacy window
        assert structured.hit(limit, "user")
        assert legacy.get_window_stats(limit, "user").remaining == 0

    async def test_async_strategy_uses_configured_encoding(self):
        storage = AsyncMemoryStorage("async+memory://")
        limiter = AsyncFixedWindowRateLimiter(storage, key_encoding="v2")
        limit = RateLimitItemPerMinute(2)

        assert await limiter.hit(limit, "user")
        assert await limiter.test(limit, "user")
        assert (await limiter.get_window_stats(limit, "user")).remaining == 1
        await limiter.clear(limit, "user")
        assert (await limiter.get_window_stats(limit, "user")).remaining == 2
