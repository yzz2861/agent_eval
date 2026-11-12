from __future__ import annotations

import dataclasses
import math
import zlib

import pytest

from itsdangerous.encoding import base64_decode
from itsdangerous.encoding import base64_encode
from itsdangerous.exc import BadPayload
from itsdangerous.exc import BadSignature
from itsdangerous.serializer import DecompressionBudget
from itsdangerous.url_safe import URLSafeSerializer
from itsdangerous.url_safe import URLSafeTimedSerializer

SECRET = "secret-key"


@pytest.fixture()
def serializer():
    return URLSafeSerializer(SECRET)


def _unsigned_payload(serializer: URLSafeSerializer, value: object) -> bytes:
    return serializer.make_signer().unsign(serializer.dumps(value))


def _compressed_payload(data: bytes) -> bytes:
    return b"." + base64_encode(zlib.compress(data))


class TestRoundTrip:
    @pytest.mark.parametrize(
        "value",
        (None, True, 1, "text", [1, 2, 3], {"id": 42}, "a" * 5000),
    )
    def test_default_round_trip_unchanged(self, serializer, value):
        signed = serializer.dumps(value)
        assert serializer.loads(signed) == value

    def test_output_is_byte_identical_to_legacy_compact_form(self, serializer):
        # The dump path and wire format must not change for legal cookies.
        value = "a" * 1000
        payload = _unsigned_payload(serializer, value)
        assert payload.startswith(b".")
        assert zlib.decompress(base64_decode(payload[1:])) == (
            ("\"" + value + "\"").encode()
        )

    def test_timed_serializer_round_trip(self):
        serializer = URLSafeTimedSerializer(SECRET)
        assert serializer.loads(serializer.dumps({"id": 42})) == {"id": 42}


class TestCompactAndCompressedLimits:
    def test_compact_size_limit(self, serializer):
        budget = DecompressionBudget(max_compact_bytes=8)
        strict = URLSafeSerializer(SECRET, decompression_budget=budget)
        payload = _unsigned_payload(strict, {"id": 42})
        assert len(payload) > 8

        with pytest.raises(BadPayload, match="compact size"):
            strict.load_payload(payload)

    def test_oversized_compact_payload_rejected_before_decoding(
        self, serializer, monkeypatch
    ):
        import itsdangerous.url_safe as url_safe

        def fail(*args, **kwargs):
            raise AssertionError("base64 decode must not run")

        monkeypatch.setattr(url_safe, "_strict_base64_decode", fail)

        with pytest.raises(BadPayload, match="compact size"):
            serializer.load_payload(b"." + b"A" * 5000)

    def test_compressed_size_limit(self):
        # A payload whose compact form fits but whose decoded compressed bytes
        # exceed max_compressed_bytes.
        budget = DecompressionBudget(
            max_compact_bytes=8192,
            max_compressed_bytes=64,
            max_decompression_ratio=10_000,
        )
        serializer = URLSafeSerializer(SECRET, decompression_budget=budget)
        incompressible = bytes((i * 37) % 256 for i in range(2_000))
        payload = _compressed_payload(incompressible)
        assert len(base64_decode(payload[1:])) > 64

        with pytest.raises(BadPayload, match="compressed size"):
            serializer.load_payload(payload)


class TestDecompressionBombs:
    def test_high_ratio_bomb_blocked(self, serializer):
        # Tiny compressed form, ~1.5 MiB expansion; the ratio limit trips.
        bomb = b"[" + b"0," * 800_000 + b"0]"
        payload = _compressed_payload(bomb)

        with pytest.raises(BadPayload, match="ratio") as exc_info:
            serializer.load_payload(payload)

        # Error text must not leak decompressed material.
        assert b"0,0,0" not in str(exc_info.value).encode()

    def test_absolute_size_bomb_blocked(self):
        # Moderate ratio (under 1000) but the output crosses the 1 MiB cap.
        budget = DecompressionBudget(
            max_compact_bytes=8192,
            max_compressed_bytes=8192,
            max_decompression_ratio=100_000,
        )
        serializer = URLSafeSerializer(SECRET, decompression_budget=budget)
        bomb = b"abcdefghijklmnop" * 100_000
        payload = _compressed_payload(bomb)
        assert len(zlib.compress(bomb)) < 4096
        assert len(bomb) > 1_048_576

        with pytest.raises(BadPayload, match="decompressed size"):
            serializer.load_payload(payload)

    def test_bomb_uses_single_decompressor_and_bounded_memory(
        self, serializer, monkeypatch
    ):
        import itsdangerous.url_safe as url_safe

        calls = 0
        real = zlib.decompressobj

        def counting(*args, **kwargs):
            nonlocal calls
            calls += 1
            return real(*args, **kwargs)

        monkeypatch.setattr(url_safe.zlib, "decompressobj", counting)
        bomb = b"[" + b"0," * 800_000 + b"0]"

        with pytest.raises(BadPayload):
            serializer.load_payload(_compressed_payload(bomb))

        assert calls == 1

    def test_nested_compression_blocked(self, serializer):
        inner = zlib.compress(
            bytes((i * 37) % 256 for i in range(2_000))
        )
        nested = zlib.compress(inner)
        payload = b"." + base64_encode(nested)

        with pytest.raises(BadPayload, match="[Nn]ested"):
            serializer.load_payload(payload)


class TestMalformedStreams:
    @pytest.fixture()
    def low_ratio_compressed(self):
        data = bytes((i * 37) % 256 for i in range(2_000))
        return zlib.compress(data)

    def test_truncated_zlib_fails(self, serializer, low_ratio_compressed):
        payload = b"." + base64_encode(low_ratio_compressed[:-6])

        with pytest.raises(BadPayload) as exc_info:
            serializer.load_payload(payload)

        assert exc_info.value.original_error is not None

    def test_trailing_garbage_fails(self, serializer, low_ratio_compressed):
        payload = b"." + base64_encode(low_ratio_compressed + b"junk-bytes")

        with pytest.raises(BadPayload, match="trailing"):
            serializer.load_payload(payload)

    def test_bad_checksum_fails(self, serializer, low_ratio_compressed):
        corrupted = low_ratio_compressed[:-1] + bytes(
            [low_ratio_compressed[-1] ^ 0x01]
        )
        payload = b"." + base64_encode(corrupted)

        with pytest.raises(BadPayload) as exc_info:
            serializer.load_payload(payload)

        assert exc_info.value.original_error is not None

    @pytest.mark.parametrize(
        "raw",
        (
            b"A" * 5,  # length mod 4 == 1
            b"ab cd",  # whitespace
            b"ab+cd",  # non URL-safe alphabet
            base64_encode(b"hello") + b"==",  # explicit padding
        ),
    )
    def test_non_canonical_base64_fails(self, serializer, raw):
        with pytest.raises(BadPayload) as exc_info:
            serializer.load_payload(raw)

        assert exc_info.value.original_error is not None

    @pytest.mark.parametrize("payload", (b"", b"."))
    def test_empty_payloads_fail(self, serializer, payload):
        with pytest.raises(BadPayload):
            serializer.load_payload(payload)


class TestJsonDepth:
    @pytest.mark.parametrize("depth", (1, 50, 100))
    def test_depth_at_or_below_limit_allowed(self, serializer, depth):
        data = b"[" * depth + b"1" + b"]" * depth
        assert serializer.load_payload(base64_encode(data)) == json_loads(data)

    @pytest.mark.parametrize("depth", (101, 200))
    def test_depth_above_limit_rejected(self, serializer, depth):
        data = b"[" * depth + b"1" + b"]" * depth

        with pytest.raises(BadPayload, match="depth"):
            serializer.load_payload(base64_encode(data))

    def test_braces_inside_strings_are_ignored(self, serializer):
        data = b'{"a":"[{]]\\"{{{","b":[1,2]}'
        assert serializer.load_payload(base64_encode(data)) == json_loads(data)

    def test_custom_depth_budget(self):
        budget = DecompressionBudget(max_json_depth=5)
        serializer = URLSafeSerializer(SECRET, decompression_budget=budget)
        data = b"[" * 6 + b"1" + b"]" * 6

        with pytest.raises(BadPayload, match="depth"):
            serializer.load_payload(base64_encode(data))


class TestBudgetConfiguration:
    @pytest.mark.parametrize(
        ("kwargs", "error"),
        (
            ({"max_compact_bytes": 0}, ValueError),
            ({"max_compressed_bytes": -2}, ValueError),
            ({"max_decompressed_bytes": math.inf}, TypeError),
            ({"max_decompression_ratio": 1.5}, TypeError),
            ({"max_json_depth": True}, TypeError),
            ({"max_json_depth": 0}, ValueError),
        ),
    )
    def test_invalid_values_rejected(self, kwargs, error):
        with pytest.raises(error):
            DecompressionBudget(**kwargs)

    def test_infinite_budget_is_impossible(self):
        with pytest.raises(TypeError):
            DecompressionBudget(max_decompressed_bytes=math.inf)

    def test_stricter_budget_is_supported(self):
        strict = DecompressionBudget(
            max_compact_bytes=64,
            max_compressed_bytes=128,
            max_decompressed_bytes=1024,
            max_decompression_ratio=4,
            max_json_depth=8,
        )
        serializer = URLSafeSerializer(SECRET, decompression_budget=strict)
        assert serializer.decompression_budget == strict

    def test_budgets_are_not_shared_between_instances(self):
        first = URLSafeSerializer(SECRET)
        second = URLSafeSerializer(SECRET)
        assert first.decompression_budget is not second.decompression_budget
        assert first.decompression_budget == second.decompression_budget

        custom = DecompressionBudget(max_json_depth=3)
        third = URLSafeSerializer(SECRET, decompression_budget=custom)
        assert third.decompression_budget is custom
        assert first.decompression_budget.max_json_depth == 100

    def test_budget_is_frozen(self):
        budget = DecompressionBudget()

        with pytest.raises(dataclasses.FrozenInstanceError):
            budget.max_json_depth = 3  # type: ignore[misc]


class TestSignatureFirst:
    def test_tampered_signature_fails_before_budget_checks(
        self, serializer, monkeypatch
    ):
        import itsdangerous.url_safe as url_safe

        def fail(*args, **kwargs):
            raise AssertionError("payload processing must not run")

        monkeypatch.setattr(url_safe, "_budgeted_decompress", fail)
        signed = serializer.dumps("a" * 1000)

        with pytest.raises(BadSignature):
            serializer.loads(signed[:-1])

    def test_errors_do_not_leak_decompressed_content(self, serializer):
        secret = "super-secret-value-inside"
        compressed = zlib.compress(secret.encode())
        payload = b"." + base64_encode(compressed[:-4])

        with pytest.raises(BadPayload) as exc_info:
            serializer.load_payload(payload)

        assert secret not in str(exc_info.value)

    def test_loads_unsafe_neutralizes_unsigned_bomb(self, serializer):
        bomb = b"[" + b"0," * 800_000 + b"0]"
        payload = _compressed_payload(bomb)
        # A signed bomb whose signature is then broken.
        signed = serializer.make_signer().sign(payload)[:-1]

        assert serializer.loads_unsafe(signed) == (False, None)

    def test_loads_unsafe_still_enforces_budget_with_valid_signature(
        self, serializer
    ):
        bomb = b"[" + b"0," * 800_000 + b"0]"
        signed = serializer.make_signer().sign(_compressed_payload(bomb))

        with pytest.raises(BadPayload):
            serializer.loads_unsafe(signed)


class TestDefaults:
    def test_default_budget_is_finite_and_positive(self):
        budget = DecompressionBudget()

        assert budget.max_compact_bytes == 4096
        assert budget.max_compressed_bytes == 8192
        assert budget.max_decompressed_bytes == 1_048_576
        assert budget.max_decompression_ratio == 1000
        assert budget.max_json_depth == 100

    def test_serializer_carries_its_own_budget(self):
        serializer = URLSafeSerializer(SECRET)
        assert isinstance(serializer.decompression_budget, DecompressionBudget)


def json_loads(data: bytes):
    import json

    return json.loads(data.decode())
