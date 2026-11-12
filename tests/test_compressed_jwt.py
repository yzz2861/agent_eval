import gzip
import json
import zlib
from unittest import mock
import pytest
import jwt
from jwt import CompressedPyJWT, CompressionBudget
from jwt.compression import (
    COMPRESSION_ALGORITHMS,
    ZIP_DEF,
    ZIP_DEFLATE_RAW,
    ZIP_GZIP,
    bounded_decompress,
    compress_payload,
    scan_claim_limits,
)
from jwt.exceptions import (
    ClaimDepthLimitExceededError,
    ClaimNodeLimitExceededError,
    CompressedPayloadSizeError,
    CompressionRatioError,
    DecodeError,
    InvalidCompressedPayloadError,
    TrailingCompressedDataError,
    TruncatedCompressedPayloadError,
    UnsupportedCompressionAlgorithmError,
)

SECRET = "a-very-secret-key-that-is-long-enough-32b"
# pako deflateRaw sample from the original regression test; no zip header.
LEGACY_TOKEN = (
    b"eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9"
    b".q1bKSM3JyVeyUlAqzy_KSVGqBQA"
    b".AAn1elCJC5MQCYFwTwa2tjjtyLgqLUVU-Y1vFBsU8jo"
)


@pytest.fixture
def codec() -> CompressedPyJWT:
    return CompressedPyJWT()


def _raw_deflate(data: bytes) -> bytes:
    return (
        zlib.compressobj(9, zlib.DEFLATED, -15).compress(data)
        + zlib.COM_PRESSION_PLACEHOLDER
    )


def _make_compressed_token(
    payload: object,
    zip_name: str,
    *,
    secret: str | bytes = SECRET,
) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    algorithm = COMPRESSION_ALGORITHMS[zip_name]
    compressed = compress_payload(raw, algorithm)
    return jwt.PyJWS().encode(
        compressed,
        secret,
        algorithm="HS256",
        headers={"zip": zip_name},
    )


def _wrap_raw_payload(zip_name: str | None, raw_payload: bytes) -> str:
    headers = {"alg": "HS256"}
    if zip_name is not None:
        headers["zip"] = zip_name
    return jwt.PyJWS().encode(raw_payload, SECRET, algorithm="HS256", headers=headers)


class TestRoundTrip:
    @pytest.mark.parametrize("zip_name", [ZIP_DEF, ZIP_DEFLATE_RAW, ZIP_GZIP])
    def test_encode_decode_roundtrip(self, codec, zip_name):
        claims = {"hello": "world", "n": [1, 2, 3], "ok": True}
        token = codec.encode(claims, SECRET, algorithm="HS256", compression=zip_name)
        assert jwt.get_unverified_header(token)["zip"] == zip_name
        assert codec.decode(token, SECRET, algorithms=["HS256"]) == claims

    @pytest.mark.parametrize("zip_name", [ZIP_DEF, ZIP_DEFLATE_RAW, ZIP_GZIP])
    def test_decode_complete_preserves_header_and_shape(self, codec, zip_name):
        token = codec.encode({"a": 1}, SECRET, algorithm="HS256", compression=zip_name)
        decoded = codec.decode_complete(token, SECRET, algorithms=["HS256"])
        assert decoded["header"]["zip"] == zip_name
        assert decoded["payload"] == {"a": 1}
        assert isinstance(decoded["signature"], bytes)

    def test_gzip_matches_gzip_module(self, codec):
        claims = {"gzip": "payload", "v": 42}
        token = codec.encode(claims, SECRET, algorithm="HS256", compression=ZIP_GZIP)
        payload_segment = token.split(".")[1]
        raw = jwt.utils.base64url_decode(payload_segment.encode())
        assert (
            gzip.decompress(raw) == json.dumps(claims, separators=(",", ":")).encode()
        )

    def test_legacy_headerless_deflate_token_needs_explicit_default(self):
        # Without a configured default the payload is plain JSON and fails.
        with pytest.raises(DecodeError):
            CompressedPyJWT().decode(LEGACY_TOKEN, SECRET, algorithms=["HS256"])
        legacy_codec = CompressedPyJWT(default_algorithm=ZIP_DEFLATE_RAW)
        decoded = legacy_codec.decode_complete(
            LEGACY_TOKEN, "secret", algorithms=["HS256"]
        )
        assert decoded["payload"] == {"hello": "world"}

    def test_uncompressed_tokens_still_decode(self, codec):
        token = codec.encode({"plain": True}, SECRET, algorithm="HS256")
        assert "zip" not in jwt.get_unverified_header(token)
        assert codec.decode(token, SECRET, algorithms=["HS256"]) == {"plain": True}

    def test_zip_header_in_encode_arguments(self, codec):
        token = codec.encode(
            {"a": 1},
            SECRET,
            algorithm="HS256",
            headers={"zip": ZIP_GZIP},
        )
        assert codec.decode(token, SECRET, algorithms=["HS256"]) == {"a": 1}

    def test_instance_default_compression(self):
        gzip_codec = CompressedPyJWT(compression=ZIP_GZIP)
        token = gzip_codec.encode({"a": 1}, SECRET, algorithm="HS256")
        assert jwt.get_unverified_header(token)["zip"] == ZIP_GZIP

    def test_conflicting_compression_arguments_rejected(self, codec):
        with pytest.raises(UnsupportedCompressionAlgorithmError):
            codec.encode(
                {"a": 1},
                SECRET,
                algorithm="HS256",
                compression=ZIP_GZIP,
                headers={"zip": ZIP_DEF},
            )

    def test_unknown_compression_constructor_argument_rejected(self):
        with pytest.raises(UnsupportedCompressionAlgorithmError):
            CompressedPyJWT(compression="BOGUS")
        with pytest.raises(UnsupportedCompressionAlgorithmError):
            CompressedPyJWT(default_algorithm="BOGUS")


class TestUnknownAlgorithm:
    def test_unknown_zip_header_fails_before_decompression(self):
        token = _wrap_raw_payload("BOGUS", b"whatever-bytes")
        codec = CompressedPyJWT()
        with mock.patch("jwt.api_jwt.bounded_decompress") as decompress:
            with pytest.raises(UnsupportedCompressionAlgorithmError):
                codec.decode(token, SECRET, algorithms=["HS256"])
        decompress.assert_not_called()

    def test_disallowed_algorithm_fails_before_decompression(self):
        budget = CompressionBudget(allowed_algorithms=frozenset({ZIP_GZIP}))
        codec = CompressedPyJWT(budget=budget)
        token = _make_compressed_token({"a": 1}, ZIP_DEF)
        with mock.patch("jwt.api_jwt.bounded_decompress") as decompress:
            with pytest.raises(UnsupportedCompressionAlgorithmError):
                codec.decode(token, SECRET, algorithms=["HS256"])
        decompress.assert_not_called()

    def test_non_string_zip_header_rejected(self):
        token = _wrap_raw_payload(None, b"x")
        # Rebuild with a non-string zip header at the JWS layer.
        token = jwt.PyJWS().encode(
            b"x", SECRET, algorithm="HS256", headers={"zip": 123}
        )
        with pytest.raises(UnsupportedCompressionAlgorithmError):
            CompressedPyJWT().decode(token, SECRET, algorithms=["HS256"])


class TestMalformedStreams:
    @pytest.mark.parametrize("zip_name", [ZIP_DEF, ZIP_DEFLATE_RAW, ZIP_GZIP])
    def test_truncated_stream(self, zip_name):
        algorithm = COMPRESSION_ALGORITHMS[zip_name]
        good = compress_payload(b'{"a":1}', algorithm)
        truncated = good[: max(1, len(good) - 4)]
        token = _wrap_raw_payload(zip_name, truncated)
        with pytest.raises(TruncatedCompressedPayloadError):
            CompressedPyJWT().decode(token, SECRET, algorithms=["HS256"])

    @pytest.mark.parametrize("zip_name", [ZIP_DEF, ZIP_DEFLATE_RAW, ZIP_GZIP])
    def test_trailing_garbage(self, zip_name):
        algorithm = COMPRESSION_ALGORITHMS[zip_name]
        good = compress_payload(b'{"a":1}', algorithm)
        token = _wrap_raw_payload(zip_name, good + b"junk-after-stream")
        with pytest.raises(TrailingCompressedDataError):
            CompressedPyJWT().decode(token, SECRET, algorithms=["HS256"])

    @pytest.mark.parametrize("zip_name", [ZIP_DEF, ZIP_DEFLATE_RAW, ZIP_GZIP])
    def test_corrupt_stream(self, zip_name):
        token = _wrap_raw_payload(zip_name, b"\x00\x01\x02not-a-stream")
        with pytest.raises(InvalidCompressedPayloadError):
            CompressedPyJWT().decode(token, SECRET, algorithms=["HS256"])

    def test_empty_compressed_payload_is_truncated(self):
        token = _wrap_raw_payload(ZIP_DEFLATE_RAW, b"")
        with pytest.raises(TruncatedCompressedPayloadError):
            CompressedPyJWT().decode(token, SECRET, algorithms=["HS256"])

    def test_error_messages_never_contain_payload_bytes(self):
        token = _wrap_raw_payload(ZIP_DEFLATE_RAW, b"SECRET-prefix-not-valid")
        with pytest.raises(DecodeError) as exc_info:
            CompressedPyJWT().decode(token, SECRET, algorithms=["HS256"])
        assert "SECRET-prefix" not in str(exc_info.value)


class TestDecompressionBudget:
    def test_compressed_size_checked_before_decompressor(self):
        budget = CompressionBudget(max_compressed_size=4)
        payload = compress_payload(b'{"a":1}', COMPRESSION_ALGORITHMS[ZIP_GZIP])
        assert len(payload) > 4
        with mock.patch("jwt.compression.zlib.decompressobj") as factory:
            with pytest.raises(CompressedPayloadSizeError):
                bounded_decompress(
                    payload, budget, algorithm=COMPRESSION_ALGORITHMS[ZIP_GZIP]
                )
        factory.assert_not_called()

    def test_decompressed_size_budget_stops_bomb_before_large_allocation(self):
        # A small highly compressible stream that would inflate far past
        # the decompressed byte budget.
        big = b"A" * (256 * 1024)
        compressed = compress_payload(big, COMPRESSION_ALGORITHMS[ZIP_DEFLATE_RAW])
        budget = CompressionBudget(
            max_decompressed_size=4096,
            max_compression_ratio=10_000.0,
        )
        calls = {"decompress": 0}

        class CountingDecompress:
            def __init__(self, wbits):
                self._inner = zlib.decompressobj(wbits)

            def decompress(self, data, max_length=-1):
                calls["decompress"] += 1
                return self._inner.decompress(data, max_length)

            @property
            def eof(self):
                return self._inner.eof

            @property
            def unused_data(self):
                return self._inner.unused_data

            @property
            def unconsumed_tail(self):
                return self._inner.unconsumed_tail

        with pytest.raises(CompressedPayloadSizeError):
            bounded_decompress(
                compressed,
                budget,
                algorithm=COMPRESSION_ALGORITHMS[ZIP_DEFLATE_RAW],
                chunk_size=1024,
                decompressobj_factory=CountingDecompress,
            )
        assert calls["decompress"] >= 1

    def test_ratio_budget_rejects_zip_bomb(self):
        big = b"B" * (512 * 1024)
        compressed = compress_payload(big, COMPRESSION_ALGORITHMS[ZIP_DEFLATE_RAW])
        budget = CompressionBudget(
            max_decompressed_size=64 * 1024 * 1024,
            max_compression_ratio=50.0,
        )
        with pytest.raises(CompressionRatioError):
            bounded_decompress(
                compressed,
                budget,
                algorithm=COMPRESSION_ALGORITHMS[ZIP_DEFLATE_RAW],
            )

    def test_under_budget_decompresses_fully(self):
        raw = b'{"ok":true}'
        for zip_name in (ZIP_DEF, ZIP_DEFLATE_RAW, ZIP_GZIP):
            algorithm = COMPRESSION_ALGORITHMS[zip_name]
            compressed = compress_payload(raw, algorithm)
            out = bounded_decompress(
                compressed, CompressionBudget(), algorithm=algorithm
            )
            assert bytes(out) == raw

    def test_single_decompressor_object_per_decode(self):
        big = b"x" * 200_000
        compressed = compress_payload(big, COMPRESSION_ALGORITHMS[ZIP_DEFLATE_RAW])
        created = []

        def factory(wbits):
            obj = zlib.decompressobj(wbits)
            created.append(obj)
            return obj

        bounded_decompress(
            compressed,
            CompressionBudget(max_compression_ratio=10_000.0),
            algorithm=COMPRESSION_ALGORITHMS[ZIP_DEFLATE_RAW],
            chunk_size=4096,
            decompressobj_factory=factory,
        )
        assert len(created) == 1

    def test_input_bytes_are_not_copied(self):
        raw = b'{"ok":true}'
        compressed = compress_payload(raw, COMPRESSION_ALGORITHMS[ZIP_DEF])
        with mock.patch("jwt.compression.memoryview") as view_factory:
            real_memoryview = memoryview
            view_factory.side_effect = lambda obj: real_memoryview(obj)
            bounded_decompress(
                compressed,
                CompressionBudget(),
                algorithm=COMPRESSION_ALGORITHMS[ZIP_DEF],
            )
        # Exactly one memoryview wraps the caller's bytes; no bytes() copies.
        assert view_factory.call_count == 1
        assert view_factory.call_args.args[0] is compressed


class TestClaimLimits:
    @pytest.mark.parametrize(
        "sample",
        [
            b"{}",
            b"[]",
            b'{"a":1}',
            b'{"a":{}}',
            b'{"a":[]}',
            b'{"esc":"a\\\\b"}',
            b'  { "x" : [ 1 , 2 ] }  ',
            b'{"n":-1.5e10}',
            b"[true,false,null]",
            b'{"":0}',
            b'{"a":{"b":{"c":[1,[2,[3]]]}}}',
        ],
    )
    def test_valid_json_passes_scan(self, sample):
        scan_claim_limits(sample, CompressionBudget())

    @pytest.mark.parametrize(
        "sample",
        [
            b"",
            b"   ",
            b"x",
            b"tru",
            b"{",
            b"}",
            b"[]1",
            b"{,}",
            b'{"a"}',
            b"{'a':1}",
            b'{"a":}',
            b"[1,]",
            b'{"a":1,}',
            b"123a",
            b'{"a" 1}',
            b"[1 2]",
            b'"unterminated',
            b"nullx",
        ],
    )
    def test_invalid_json_matches_json_loader(self, sample):
        json_raises = False
        try:
            json.loads(sample)
        except (ValueError, RecursionError):
            json_raises = True
        scan_raises = False
        try:
            scan_claim_limits(sample, CompressionBudget())
        except DecodeError:
            scan_raises = True
        assert json_raises
        assert scan_raises

    def test_node_limit_counts_values_only(self):
        budget = CompressionBudget(max_claim_nodes=3)
        scan_claim_limits(b'{"a":1}', budget)
        scan_claim_limits(b"[1,2,3]", budget)
        # Containers themselves are not nodes; only scalar values count, so a
        # single nested object still only contains one scalar.
        scan_claim_limits(b'{"a":{"b":1}}', budget)
        scan_claim_limits(b'{"a":1,"b":2}', budget)
        with pytest.raises(ClaimNodeLimitExceededError):
            scan_claim_limits(b'{"a":1,"b":2,"c":3,"d":4}', budget)
        with pytest.raises(ClaimNodeLimitExceededError):
            scan_claim_limits(b"[1,2,3,4]", budget)

    def test_depth_limit_root_container_is_depth_one(self):
        budget = CompressionBudget(max_claim_depth=2)
        scan_claim_limits(b"{}", budget)
        scan_claim_limits(b'{"a":{}}', budget)
        scan_claim_limits(b"[[1]]", budget)
        with pytest.raises(ClaimDepthLimitExceededError):
            scan_claim_limits(b'{"a":{"b":{}}}', budget)
        with pytest.raises(ClaimDepthLimitExceededError):
            scan_claim_limits(b"[[[1]]]", budget)

    def test_node_limit_enforced_end_to_end_before_object_build(self):
        claims = {"items": list(range(20))}
        token = _make_compressed_token(claims, ZIP_DEFLATE_RAW)
        tight = CompressionBudget(max_claim_nodes=5)
        calls = {"loads": 0, "scans": 0}

        class InstrumentedPyJWT(CompressedPyJWT):
            def _decode_payload(self, decoded):
                import jwt.api_jwt as api_jwt_module

                real_scan = api_jwt_module.scan_claim_limits

                def counting_scan(data, budget):
                    calls["scans"] += 1
                    return real_scan(data, budget)

                with (
                    mock.patch.object(
                        api_jwt_module, "scan_claim_limits", side_effect=counting_scan
                    ),
                    mock.patch.object(
                        json,
                        "loads",
                        side_effect=lambda *a, **k: calls.__setitem__(
                            "loads", calls["loads"] + 1
                        ),
                    ),
                ):
                    try:
                        return super()._decode_payload(decoded)
                    finally:
                        # The structural check must run first and raise, so the
                        # claims object is never materialized.
                        assert calls["scans"] == 1
                        assert calls["loads"] == 0

        codec = InstrumentedPyJWT(budget=tight)
        with pytest.raises(ClaimNodeLimitExceededError):
            codec.decode(token, SECRET, algorithms=["HS256"])

    def test_depth_limit_enforced_end_to_end(self):
        claims = {"a": {"b": {"c": {"d": 1}}}}
        token = _make_compressed_token(claims, ZIP_DEFLATE_RAW)
        tight = CompressionBudget(max_claim_depth=2)
        codec = CompressedPyJWT(budget=tight)
        with pytest.raises(ClaimDepthLimitExceededError):
            codec.decode(token, SECRET, algorithms=["HS256"])

    def test_tight_budget_still_accepts_small_token(self):
        tight = CompressionBudget(
            max_compressed_size=1024,
            max_decompressed_size=1024,
            max_compression_ratio=10.0,
            max_claim_nodes=10,
            max_claim_depth=3,
        )
        codec = CompressedPyJWT(budget=tight)
        token = codec.encode({"a": 1}, SECRET, algorithm="HS256", compression=ZIP_DEF)
        assert codec.decode(token, SECRET, algorithms=["HS256"]) == {"a": 1}


class TestEndToEndBomb:
    def test_zip_bomb_never_fully_inflates(self):
        # Same attack shape as the 64 KB -> 1.8 GB incident, at a scale fast
        # enough for CI: the budget trips on the first oversized chunk and
        # the inflated bytearray never reaches the bomb's full size.
        inflated_target = 8 * 1024 * 1024
        bomb = b"Z" * inflated_target
        compressed = compress_payload(bomb, COMPRESSION_ALGORITHMS[ZIP_DEFLATE_RAW])
        assert len(compressed) < 20_000
        token = _wrap_raw_payload(ZIP_DEFLATE_RAW, compressed)
        budget = CompressionBudget(
            max_decompressed_size=64 * 1024,
            max_compression_ratio=100.0,
        )
        calls = {"decompress": 0, "factories": 0}

        class CountingCompressedPyJWT(CompressedPyJWT):
            def _decode_payload(self, decoded):
                from jwt.compression import bounded_decompress as real_bounded

                zip_name = decoded["header"].get("zip")
                algorithm = COMPRESSION_ALGORITHMS[zip_name]

                class CountingDecompress:
                    def __init__(self, wbits):
                        calls["factories"] += 1
                        self._inner = zlib.decompressobj(wbits)

                    def decompress(self, data, max_length=-1):
                        calls["decompress"] += 1
                        return self._inner.decompress(data, max_length)

                    @property
                    def eof(self):
                        return self._inner.eof

                    @property
                    def unused_data(self):
                        return self._inner.unused_data

                    @property
                    def unconsumed_tail(self):
                        return self._inner.unconsumed_tail

                inflated = real_bounded(
                    decoded["payload"],
                    self._budget,
                    algorithm=algorithm,
                    decompressobj_factory=CountingDecompress,
                )
                scan_claim_limits(inflated, self._budget)
                return json.loads(inflated)

        codec = CountingCompressedPyJWT(budget=budget)
        with pytest.raises((CompressedPayloadSizeError, CompressionRatioError)):
            codec.decode(token, SECRET, algorithms=["HS256"])
        # Exactly one decompressor for the decode and far fewer calls than a
        # full 8 MB inflation would need at the 64 KiB chunk size.
        assert calls["factories"] == 1
        assert calls["decompress"] <= 3

    def test_signature_failure_short_circuits_before_decompression(self):
        token = _make_compressed_token({"a": 1}, ZIP_DEF)
        codec = CompressedPyJWT()
        with mock.patch("jwt.api_jwt.bounded_decompress") as decompress:
            with pytest.raises(jwt.InvalidSignatureError):
                codec.decode(
                    token,
                    "wrong-key-32-bytes-long-aaaaaaaaaa",
                    algorithms=["HS256"],
                )
        decompress.assert_not_called()


class TestBudgetIsolation:
    def test_budget_is_immutable(self):
        budget = CompressionBudget()
        with pytest.raises((AttributeError, TypeError)):
            budget.max_decompressed_size = 1  # type: ignore[misc]

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"max_compressed_size": 0},
            {"max_decompressed_size": -1},
            {"max_claim_nodes": 0},
            {"max_claim_depth": 0},
            {"max_compression_ratio": 0.5},
            {"allowed_algorithms": frozenset()},
            {"allowed_algorithms": frozenset({"NOPE"})},
        ],
    )
    def test_invalid_budget_rejected(self, kwargs):
        with pytest.raises((ValueError, TypeError)):
            CompressionBudget(**kwargs)

    def test_state_does_not_leak_between_calls(self):
        codec = CompressedPyJWT()
        good = codec.encode({"a": 1}, SECRET, algorithm="HS256", compression=ZIP_DEF)
        bomb = b"Q" * (2 * 1024 * 1024)
        bomb_token = _wrap_raw_payload(
            ZIP_DEFLATE_RAW,
            compress_payload(bomb, COMPRESSION_ALGORITHMS[ZIP_DEFLATE_RAW]),
        )
        tight = CompressedPyJWT(
            budget=CompressionBudget(
                max_decompressed_size=4096, max_compression_ratio=10.0
            )
        )
        with pytest.raises((CompressedPayloadSizeError, CompressionRatioError)):
            tight.decode(bomb_token, SECRET, algorithms=["HS256"])
        assert codec.decode(good, SECRET, algorithms=["HS256"]) == {"a": 1}
        assert codec.decode(good, SECRET, algorithms=["HS256"]) == {"a": 1}

    def test_different_keys_do_not_share_budget_state(self):
        codec = CompressedPyJWT()
        token_one = codec.encode(
            {"k": 1}, SECRET, algorithm="HS256", compression=ZIP_GZIP
        )
        other_secret = "b-very-secret-key-that-is-long-enough-32b"
        token_two = codec.encode(
            {"k": 2},
            other_secret,
            algorithm="HS256",
            compression=ZIP_GZIP,
        )
        assert codec.decode(token_one, SECRET, algorithms=["HS256"]) == {"k": 1}
        assert codec.decode(token_two, other_secret, algorithms=["HS256"]) == {"k": 2}

    def test_independent_codec_instances_have_independent_budgets(self):
        strict = CompressedPyJWT(budget=CompressionBudget(max_claim_nodes=2))
        loose = CompressedPyJWT()
        token = loose.encode(
            {"a": 1, "b": 2, "c": 3},
            SECRET,
            algorithm="HS256",
            compression=ZIP_DEF,
        )
        with pytest.raises(ClaimNodeLimitExceededError):
            strict.decode(token, SECRET, algorithms=["HS256"])
        assert loose.decode(token, SECRET, algorithms=["HS256"]) == {
            "a": 1,
            "b": 2,
            "c": 3,
        }


class TestLegacyCompressedPyJWTSubclass:
    def test_original_pako_sample_still_works(self):
        # Preserves the exact subclass pattern from the original regression
        # test (raw deflate via zlib.decompressobj semantics).
        class LegacyCompressedPyJWT(jwt.PyJWT):
            def _decode_payload(self, decoded):
                payload = json.loads(
                    zlib.decompress(decoded["payload"], wbits=-15).decode("utf-8")
                )
                assert isinstance(payload, dict)
                return payload

        decoded = LegacyCompressedPyJWT().decode_complete(
            LEGACY_TOKEN, "secret", algorithms=["HS256"]
        )
        assert decoded["payload"] == {"hello": "world"}
