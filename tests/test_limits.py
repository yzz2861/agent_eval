from __future__ import annotations

import math
import subprocess
import sys
from collections import defaultdict

import pytest

from limits import (
    KeyEncodingVersion,
    RateLimitItemPerMinute,
    limits,
    parse,
    parse_many,
)
from limits.storage.memory import MemoryStorage
from limits.strategies import FixedWindowRateLimiter


class TestLimits:
    class FakeLimit(limits.RateLimitItem):
        GRANULARITY = limits.Granularity(1, "fake")

    class OtherFakeLimit(limits.RateLimitItem):
        GRANULARITY = limits.Granularity(1, "otherfake")

    def test_key_all_strings_default_namespace(self):
        item = self.FakeLimit(1, 1)
        assert item.key_for("a", "b", "c") == "LIMITER/a/b/c/1/1/fake"

    def test_key_with_none_default_namespace(self):
        item = self.FakeLimit(1, 1)
        assert item.key_for("a", None, None) == "LIMITER/a/None/None/1/1/fake"

    def test_key_with_int_default_namespace(self):
        item = self.FakeLimit(1, 1)
        assert item.key_for("a", 1) == "LIMITER/a/1/1/1/fake"

    def test_key_with_mixed_string_types_default_namespace(self):
        item = self.FakeLimit(1, 1)
        assert item.key_for(b"a", "b") == "LIMITER/a/b/1/1/fake"

    def test_version1_preserves_slash_collision(self):
        item = self.FakeLimit(1, 1)
        assert item.key_for("a/b", "c") == item.key_for("a", "b/c")

    def test_version2_separates_component_boundaries(self):
        item = self.FakeLimit(1, 1, key_encoding_version=KeyEncodingVersion.V2)
        assert item.key_for("a/b", "c") != item.key_for("a", "b/c")

    def test_version2_separates_component_counts(self):
        item = self.FakeLimit(1, 1, key_encoding_version=KeyEncodingVersion.V2)
        assert item.key_for("ab") != item.key_for("a", "b")

    @pytest.mark.parametrize(
        ("left", "right"),
        [
            ("1", 1),
            (b"1", "1"),
            (1, 1.0),
            (1, True),
            (0.0, -0.0),
        ],
    )
    def test_version2_preserves_identifier_types(self, left, right):
        item = self.FakeLimit(1, 1, key_encoding_version=KeyEncodingVersion.V2)
        assert item.key_for(left) != item.key_for(right)

    def test_version2_includes_namespace_quota_and_granularity(self):
        item = self.FakeLimit(
            1, 1, namespace="a/b", key_encoding_version=KeyEncodingVersion.V2
        )
        assert item.key_for("c") != self.FakeLimit(
            1, 1, namespace="a", key_encoding_version=KeyEncodingVersion.V2
        ).key_for("b/c")
        assert (
            item.key_for()
            != self.FakeLimit(
                2, 1, namespace="a/b", key_encoding_version=KeyEncodingVersion.V2
            ).key_for()
        )
        assert (
            item.key_for()
            != self.FakeLimit(
                1, 2, namespace="a/b", key_encoding_version=KeyEncodingVersion.V2
            ).key_for()
        )
        assert (
            item.key_for()
            != self.OtherFakeLimit(
                1, 1, namespace="a/b", key_encoding_version=KeyEncodingVersion.V2
            ).key_for()
        )

    def test_version2_unicode_length_is_unambiguous(self):
        item = self.FakeLimit(1, 1, key_encoding_version=KeyEncodingVersion.V2)
        composed = item.key_for("é")
        decomposed = item.key_for("e\u0301")
        assert composed.isascii()
        assert decomposed.isascii()
        assert "s2:c3a9" in composed
        assert "s3:65cc81" in decomposed
        assert composed != decomposed
        assert item.key_for("é", "") != item.key_for("é")
        assert item.key_for(b"\xc3\xa9") != item.key_for("é")
        assert "b1:ff" in item.key_for(b"\xff")

    @pytest.mark.parametrize("value", [None, object(), math.nan, math.inf, -math.inf])
    def test_version2_rejects_identifiers_without_stable_representation(self, value):
        item = self.FakeLimit(1, 1, key_encoding_version=KeyEncodingVersion.V2)
        with pytest.raises((TypeError, ValueError)):
            item.key_for(value)

    def test_version2_rejects_non_string_namespace(self):
        item = self.FakeLimit(
            1,
            1,
            namespace=b"LIMITER",
            key_encoding_version=KeyEncodingVersion.V2,
        )
        with pytest.raises(TypeError):
            item.key_for()

    def test_invalid_key_encoding_version(self):
        with pytest.raises(TypeError):
            self.FakeLimit(1, 1, key_encoding_version=2)

    def test_version2_key_is_deterministic_across_processes(self):
        expected = self.FakeLimit(
            1,
            1,
            namespace="ns/é",
            key_encoding_version=KeyEncodingVersion.V2,
        ).key_for("a/b", b"\xff", -1, 1.5)
        assert expected == (
            "limits.v2:n5:6e732fc3a9i4:s3:612f62b1:ffi2:2d31"
            "f20:3078312e38303030303030303030303030702b30a1:31m1:31"
            "g2:s1:31n4:66616b65"
        )
        code = (
            "from limits.limits import RateLimitItem, KeyEncodingVersion, Granularity\n"
            "class FakeLimit(RateLimitItem):\n"
            "    GRANULARITY = Granularity(1, 'fake')\n"
            "print(FakeLimit(1, 1, namespace='ns/é', "
            "key_encoding_version=KeyEncodingVersion.V2).key_for(\n"
            "    'a/b', b'\\xff', -1, 1.5))\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            check=True,
            capture_output=True,
            text=True,
        )
        assert result.stdout.strip() == expected

    def test_encoding_versions_use_isolated_windows(self):
        storage = MemoryStorage()
        limiter = FixedWindowRateLimiter(storage)
        version1 = self.FakeLimit(1, 1)
        version2 = self.FakeLimit(1, 1, key_encoding_version=KeyEncodingVersion.V2)

        assert limiter.hit(version1, "user", "resource")
        assert not limiter.test(version1, "user", "resource")
        assert limiter.hit(version2, "user", "resource")
        assert not limiter.test(version2, "user", "resource")
        assert not limiter.test(version1, "user", "resource")

    def test_strategy_storage_operations_share_one_key(self):
        storage = MemoryStorage()
        limiter = FixedWindowRateLimiter(storage)

        class TrackingLimit(self.FakeLimit):
            key_for_calls = []

            def key_for(self, *identifiers):
                self.key_for_calls.append(identifiers)
                return super().key_for(*identifiers)

        limit = TrackingLimit(
            1,
            1,
            key_encoding_version=KeyEncodingVersion.V2,
        )

        limiter.get_window_stats(limit, "user", "resource")
        assert TrackingLimit.key_for_calls == [("user", "resource")]

    def test_equality(self):
        item = self.FakeLimit(1, 1)
        assert item == self.FakeLimit(1, 1)
        assert item != self.FakeLimit(1, 2)
        assert item != self.FakeLimit(2, 1)
        assert item != RateLimitItemPerMinute(1, 1)
        assert item != "someething else"

    def test_hashabilty(self):
        mapping = defaultdict(lambda: 1)
        mapping[self.FakeLimit(1, 1)] += 1
        mapping[self.FakeLimit(1, 1)] += 1
        mapping[self.FakeLimit(1, 2)] += 1
        mapping[self.FakeLimit(1, 2)] += 1
        mapping[self.OtherFakeLimit(1, 2)] += 1

        assert len(mapping) == 3

    def test_parse_custom_limit(self):
        item = parse("1/fake")
        assert item == self.FakeLimit(1, 1)
        item = parse("5/10 fake")
        assert item == self.FakeLimit(5, 10)
        items = parse_many("1/fake,10/minute,10 per 10 fakes")
        assert items == [
            self.FakeLimit(1, 1),
            RateLimitItemPerMinute(10, 1),
            self.FakeLimit(10, 10),
        ]
