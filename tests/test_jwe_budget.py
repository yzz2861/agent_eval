import json
import tracemalloc
import zlib

import pytest

from jose import jwe, jwk
from jose.budgets import JWEBudget
from jose.constants import ALGORITHMS, ZIPS
from jose.exceptions import JWEDecompressError
from jose.exceptions import JWEError
from jose.exceptions import JWEParseError
from jose.exceptions import JWEPayloadError
from jose.exceptions import JWEPolicyError
from jose.jwk import AESKey
from jose.utils import base64url_encode

pytestmark = pytest.mark.skipif(AESKey is None, reason="Test requires AES Backend")

KEY = b"0123456789abcdef0123456789abcdef"
ENC = ALGORITHMS.A256GCM
PAYLOAD = json.dumps({"hello": "world", "nums": list(range(10))}).encode()


def _compact(header_bytes, iv, ciphertext, tag):
    return b".".join(
        [
            base64url_encode(header_bytes),
            b"",
            base64url_encode(iv),
            base64url_encode(ciphertext),
            base64url_encode(tag),
        ]
    )


def _craft_token(header_obj, compressed_payload):
    header_bytes = json.dumps(header_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    encoded_header = base64url_encode(header_bytes)
    encryption_key = jwk.construct(KEY, ENC)
    iv, ciphertext, tag = encryption_key.encrypt(compressed_payload, encoded_header)
    return _compact(header_bytes, iv, ciphertext, tag)


def _zip_token(plaintext=PAYLOAD, extra_header=None):
    header = {"alg": ALGORITHMS.DIR, "enc": ENC, "zip": ZIPS.DEF}
    if extra_header:
        header.update(extra_header)
    return _craft_token(header, zlib.compress(plaintext))


def _zlib_bomb_token(expanded_size=2 * 1024 * 1024):
    compressor = zlib.compressobj()
    compressed = compressor.compress(b"A" * expanded_size) + compressor.flush()
    return _zip_token_plain(compressed), compressed


def _zip_token_plain(compressed_payload):
    return _craft_token({"alg": ALGORITHMS.DIR, "enc": ENC, "zip": ZIPS.DEF}, compressed_payload)


class TestBudgetConfiguration:
    @pytest.mark.parametrize(
        "kwargs",
        [
            {"max_compact_size": 0},
            {"max_compact_size": -1},
            {"max_decompressed_size": 0},
            {"max_compression_ratio": 0},
            {"max_compression_ratio": float("inf")},
            {"max_compression_ratio": float("nan")},
            {"max_json_depth": 0},
            {"max_json_containers": 0},
        ],
    )
    def test_limits_must_be_positive_and_finite(self, kwargs):
        with pytest.raises((ValueError, TypeError)):
            JWEBudget(**kwargs)

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"max_compact_size": 1.5},
            {"max_json_depth": True},
            {"max_compression_ratio": "100"},
        ],
    )
    def test_limits_reject_wrong_types(self, kwargs):
        with pytest.raises(TypeError):
            JWEBudget(**kwargs)

    def test_decrypt_rejects_non_budget_objects(self):
        token = _zip_token()
        with pytest.raises(TypeError):
            jwe.decrypt(token, KEY, budget="unlimited")


class TestCompatibility:
    def test_legitimate_compressed_token_round_trips(self):
        token = _zip_token()
        assert jwe.decrypt(token, KEY) == PAYLOAD

    def test_legitimate_token_round_trips_through_decrypt_json(self):
        token = _zip_token()
        assert jwe.decrypt_json(token, KEY) == json.loads(PAYLOAD)

    def test_uncompressed_token_round_trips(self):
        token = jwe.encrypt(PAYLOAD, KEY, ENC, ALGORITHMS.DIR)
        assert jwe.decrypt(token, KEY) == PAYLOAD

    def test_tightened_budget_keeps_legitimate_token_working(self):
        token = _zip_token()
        budget = JWEBudget(
            max_compact_size=len(token) + 16,
            max_decompressed_size=4096,
            max_compression_ratio=20,
            max_json_depth=32,
            max_json_containers=128,
        )
        assert jwe.decrypt(token, KEY, budget) == PAYLOAD
        assert jwe.decrypt_json(token, KEY, budget) == json.loads(PAYLOAD)

    def test_budget_state_is_isolated_between_calls(self):
        token = _zip_token()
        budget = JWEBudget(max_decompressed_size=4096)
        for _ in range(5):
            assert jwe.decrypt(token, KEY, budget) == PAYLOAD
            assert jwe.decrypt_json(token, KEY, budget) == json.loads(PAYLOAD)

    def test_failed_call_does_not_poison_later_calls(self):
        good = _zip_token()
        bomb, _ = _zlib_bomb_token()
        with pytest.raises(JWEPolicyError):
            jwe.decrypt(bomb, KEY)
        assert jwe.decrypt(good, KEY) == PAYLOAD

    def test_separate_budget_instances_do_not_share_state(self):
        token = _zip_token()
        first = JWEBudget(max_decompressed_size=4096)
        second = JWEBudget(max_decompressed_size=8192)
        assert jwe.decrypt(token, KEY, first) == PAYLOAD
        assert jwe.decrypt(token, KEY, second) == PAYLOAD
        assert jwe.decrypt_json(token, KEY, first) == json.loads(PAYLOAD)
        assert jwe.decrypt_json(token, KEY, second) == json.loads(PAYLOAD)


class TestCompactSizePolicy:
    def test_oversized_compact_token_is_policy_error(self):
        token = _zip_token()
        budget = JWEBudget(max_compact_size=len(token) - 1)
        with pytest.raises(JWEPolicyError) as excinfo:
            jwe.decrypt(token, KEY, budget)
        message = str(excinfo.value)
        assert "JWE string" in message
        assert "bytes exceeds" in message

    def test_default_compact_limit_message_is_stable(self):
        token = _zip_token()
        budget = JWEBudget(max_compact_size=4)
        with pytest.raises(JWEPolicyError) as excinfo:
            jwe.decrypt(token, KEY, budget)
        assert "JWE string" in str(excinfo.value)


class TestDecompressionPolicy:
    def test_high_ratio_bomb_is_rejected_without_large_allocation(self):
        token, compressed = _zlib_bomb_token()
        assert len(compressed) < 10 * 1024
        tracemalloc.start()
        try:
            with pytest.raises(JWEPolicyError) as excinfo:
                jwe.decrypt(token, KEY)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert "compression ratio" in str(excinfo.value)
        # The expanded payload would be 2 MiB; streaming enforcement must keep
        # peak allocations at roughly the compressed size plus small chunks.
        assert peak < 512 * 1024

    def test_absolute_size_limit_bounds_memory_when_ratio_is_relaxed(self):
        token, _ = _zlib_bomb_token()
        budget = JWEBudget(max_compression_ratio=10**9)
        tracemalloc.start()
        try:
            with pytest.raises(JWEPolicyError) as excinfo:
                jwe.decrypt(token, KEY, budget)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert "Decompressed JWE string exceeds" in str(excinfo.value)
        assert peak < 512 * 1024

    def test_unknown_compression_algorithm_is_decompress_error(self):
        token = _craft_token(
            {"alg": ALGORITHMS.DIR, "enc": ENC, "zip": "GZIP"},
            PAYLOAD,
        )
        with pytest.raises(JWEDecompressError) as excinfo:
            jwe.decrypt(token, KEY)
        assert "GZIP" not in str(excinfo.value)

    def test_truncated_stream_is_decompress_error(self):
        compressed = zlib.compress(PAYLOAD)[:-4]
        token = _zip_token_plain(compressed)
        with pytest.raises(JWEDecompressError) as excinfo:
            jwe.decrypt(token, KEY)
        assert "Truncated" in str(excinfo.value)

    def test_trailing_bytes_are_decompress_error(self):
        compressed = zlib.compress(PAYLOAD) + b"trailing-bytes"
        token = _zip_token_plain(compressed)
        with pytest.raises(JWEDecompressError) as excinfo:
            jwe.decrypt(token, KEY)
        assert "Trailing data" in str(excinfo.value)

    def test_corrupt_stream_is_decompress_error(self):
        token = _zip_token_plain(b"this is not a zlib stream")
        with pytest.raises(JWEDecompressError):
            jwe.decrypt(token, KEY)

    def test_error_messages_do_not_echo_plaintext(self):
        secret_fragment = b"secret-marker-12345"
        compressed = zlib.compress(secret_fragment)[:-5]
        token = _zip_token_plain(compressed)
        with pytest.raises(JWEError) as excinfo:
            jwe.decrypt(token, KEY)
        assert b"secret-marker" not in str(excinfo.value).encode()


class TestHeaderPolicy:
    def test_known_critical_header_is_accepted(self):
        token = _zip_token(extra_header={"crit": ["zip"]})
        assert jwe.decrypt(token, KEY) == PAYLOAD

    def test_unknown_critical_header_is_parse_error(self):
        token = _zip_token(extra_header={"crit": ["urn:custom-parameter"]})
        with pytest.raises(JWEParseError) as excinfo:
            jwe.decrypt(token, KEY)
        assert "not supported" in str(excinfo.value)

    def test_critical_header_missing_from_header_is_parse_error(self):
        token = _zip_token(extra_header={"crit": ["kid"]})
        with pytest.raises(JWEParseError) as excinfo:
            jwe.decrypt(token, KEY)
        assert "not present" in str(excinfo.value)

    @pytest.mark.parametrize(
        "crit",
        [
            [],
            "zip",
            [1],
            ["zip", "zip"],
        ],
    )
    def test_malformed_crit_header_is_parse_error(self, crit):
        token = _zip_token(extra_header={"crit": crit})
        with pytest.raises(JWEParseError):
            jwe.decrypt(token, KEY)

    def test_duplicate_zip_header_is_rejected(self):
        header_bytes = b'{"alg":"dir","enc":"A256GCM","zip":"DEF","zip":"DEF"}'
        encoded_header = base64url_encode(header_bytes)
        encryption_key = jwk.construct(KEY, ENC)
        iv, ciphertext, tag = encryption_key.encrypt(zlib.compress(PAYLOAD), encoded_header)
        token = _compact(header_bytes, iv, ciphertext, tag)
        with pytest.raises(JWEParseError) as excinfo:
            jwe.decrypt(token, KEY)
        assert "duplicate header parameter 'zip'" in str(excinfo.value)
        with pytest.raises(JWEParseError):
            jwe.get_unverified_header(token)

    def test_header_policy_runs_before_decompression(self, monkeypatch):
        # A token with an unsupported crit header must fail at the parse/policy
        # stage without entering the decompression path.
        bomb_with_crit = _zip_token(extra_header={"crit": ["urn:custom-parameter"]})
        monkeypatch.setattr(
            JWEBudget,
            "decompress",
            staticmethod(lambda *args, **kwargs: pytest.fail("decompression should not run")),
        )
        with pytest.raises(JWEParseError):
            jwe.decrypt(bomb_with_crit, KEY)


class TestJsonPayloadPolicy:
    def test_deeply_nested_json_is_policy_error(self):
        deep = ("[" * 120) + "1" + ("]" * 120)
        token = _zip_token(deep.encode())
        with pytest.raises(JWEPolicyError) as excinfo:
            jwe.decrypt_json(token, KEY)
        assert "nesting depth" in str(excinfo.value)

    def test_too_many_containers_is_policy_error(self):
        many = b"[" + b"{}," * 119 + b"{}]"
        budget = JWEBudget(max_json_depth=256, max_json_containers=100)
        token = _zip_token(many)
        with pytest.raises(JWEPolicyError) as excinfo:
            jwe.decrypt_json(token, KEY, budget)
        assert "container count" in str(excinfo.value)

    def test_invalid_json_is_payload_error(self):
        token = _zip_token(b"not json at all")
        with pytest.raises(JWEPayloadError):
            jwe.decrypt_json(token, KEY)

    def test_trailing_json_bytes_are_payload_error(self):
        token = _zip_token(b'{"a": 1} trailing')
        with pytest.raises(JWEPayloadError):
            jwe.decrypt_json(token, KEY)

    def test_plain_decrypt_still_returns_bytes_for_non_json_payload(self):
        token = _zip_token(b"binary-ish" + bytes(range(8)))
        assert jwe.decrypt(token, KEY).startswith(b"binary-ish")

    def test_deep_json_still_available_as_raw_plaintext(self):
        deep = ("[" * 120) + "1" + ("]" * 120)
        token = _zip_token(deep.encode())
        assert jwe.decrypt(token, KEY) == deep.encode()
