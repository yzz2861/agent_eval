import pytest

from jose import jwk
from jose.backends import AESKey, ECKey, HMACKey, RSAKey
from jose.backends.base import Key
from jose.exceptions import JWKError

hmac_key = {
    "kty": "oct",
    "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
    "use": "sig",
    "alg": "HS256",
    "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
}

rsa_key = {
    "kty": "RSA",
    "kid": "bilbo.baggins@hobbiton.example",
    "use": "sig",
    "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
    "e": "AQAB",
}

ec_key = {
    "kty": "EC",
    "kid": "bilbo.baggins@hobbiton.example",
    "use": "sig",
    "crv": "P-521",
    "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
    "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
}


class TestJWK:
    def test_interface(self):
        key = jwk.Key("key", "ALG")

        with pytest.raises(NotImplementedError):
            key.sign("")

        with pytest.raises(NotImplementedError):
            key.verify("", "")

    @pytest.mark.skipif(RSAKey is None, reason="RSA is not available")
    def test_invalid_hash_alg(self):
        with pytest.raises(JWKError):
            key = HMACKey(hmac_key, "RS512")

        with pytest.raises(JWKError):
            key = RSAKey(rsa_key, "HS512")

        with pytest.raises(JWKError):
            key = ECKey(ec_key, "RS512")  # noqa: F841

    @pytest.mark.skipif(RSAKey is None, reason="RSA is not available")
    def test_invalid_jwk(self):
        with pytest.raises(JWKError):
            key = HMACKey(rsa_key, "HS256")

        with pytest.raises(JWKError):
            key = RSAKey(hmac_key, "RS256")

        with pytest.raises(JWKError):
            key = ECKey(rsa_key, "ES256")  # noqa: F841

    @pytest.mark.skipif(RSAKey is None, reason="RSA is not available")
    def test_RSAKey_errors(self):
        rsa_key = {
            "kty": "RSA",
            "kid": "bilbo.baggins@hobbiton.example",
            "use": "sig",
            "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
            "e": "AQAB",
        }

        with pytest.raises(JWKError):
            key = RSAKey(rsa_key, "HS256")

        rsa_key = {
            "kty": "oct",
            "kid": "bilbo.baggins@hobbiton.example",
            "use": "sig",
            "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
            "e": "AQAB",
        }

        with pytest.raises(JWKError):
            key = RSAKey(rsa_key, "RS256")  # noqa: F841

    def test_construct_from_jwk(self):
        hmac_key = {
            "kty": "oct",
            "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
            "use": "sig",
            "alg": "HS256",
            "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
        }

        key = jwk.construct(hmac_key)
        assert isinstance(key, jwk.Key)

    def test_construct_EC_from_jwk(self):
        key = ECKey(ec_key, algorithm="ES512")
        assert isinstance(key, jwk.Key)

    def test_construct_from_jwk_missing_alg(self):
        hmac_key = {
            "kty": "oct",
            "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
            "use": "sig",
            "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
        }

        with pytest.raises(JWKError):
            key = jwk.construct(hmac_key)

        with pytest.raises(JWKError):
            key = jwk.construct("key", algorithm="NONEXISTENT")  # noqa: F841

    def test_get_key(self):
        hs_key = jwk.get_key("HS256")
        assert hs_key == HMACKey
        assert issubclass(hs_key, Key)
        if RSAKey is not None:
            assert issubclass(jwk.get_key("RS256"), Key)
        assert issubclass(jwk.get_key("ES256"), Key)

        assert jwk.get_key("NONEXISTENT") is None

    @pytest.mark.skipif(AESKey is None, reason="No AES provider")
    def test_get_aes_key(self):
        assert issubclass(jwk.get_key("A256CBC-HS512"), Key)

    def test_register_key(self):
        assert jwk.register_key("ALG", jwk.Key)
        assert jwk.get_key("ALG") == jwk.Key

        with pytest.raises(TypeError):
            assert jwk.register_key("ALG", object)


def _b64u(raw):
    import base64

    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ASCII")


@pytest.mark.skipif(RSAKey is None, reason="RSA is not available")
class TestAlgorithmAwareJWK:
    def test_family_mapping(self):
        assert jwk.get_algorithm_family("HS256") == "oct"
        assert jwk.get_algorithm_family("RS256") == "RSA"
        assert jwk.get_algorithm_family("ES256") == "EC"
        assert jwk.get_algorithm_family("NONEXISTENT") is None

    def test_kty_must_match_algorithm(self):
        with pytest.raises(JWKError):
            jwk.validate_jwk(rsa_key, "HS256")
        with pytest.raises(JWKError):
            jwk.validate_jwk(hmac_key, "RS256")
        with pytest.raises(JWKError):
            jwk.validate_jwk(ec_key, "RS256")

    def test_unknown_kty_rejected(self):
        unknown = dict(hmac_key, kty="OKP")
        with pytest.raises(JWKError):
            jwk.validate_jwk(unknown, "HS256")

    def test_jwk_alg_must_match(self):
        mismatched = dict(hmac_key, alg="HS512")
        with pytest.raises(JWKError):
            jwk.validate_jwk(mismatched, "HS256")

        # An absent alg member is allowed; the header alg drives selection.
        jwk.validate_jwk(dict(hmac_key, alg=None), "HS256")

    def test_use_enc_rejected_for_signing(self):
        with pytest.raises(JWKError):
            jwk.validate_jwk(dict(hmac_key, use="enc"), "HS256")

    def test_key_ops_must_permit_operation(self):
        sign_only = dict(hmac_key, key_ops=["sign"])
        with pytest.raises(JWKError):
            jwk.validate_jwk(sign_only, "HS256", operation="verify")

        verify_only = dict(hmac_key, key_ops=["verify"])
        with pytest.raises(JWKError):
            jwk.validate_jwk(verify_only, "HS256", operation="sign")

        jwk.validate_jwk(dict(hmac_key, key_ops=["sign", "verify"]), "HS256", operation="verify")

    def test_invalid_key_ops_rejected(self):
        with pytest.raises(JWKError):
            jwk.validate_jwk(dict(hmac_key, key_ops=[]), "HS256")

    def test_short_oct_key_rejected(self):
        short_key = dict(hmac_key, k=_b64u(b"short"))
        with pytest.raises(JWKError):
            jwk.validate_jwk(short_key, "HS256")

    def test_oct_min_size_per_algorithm(self):
        key_256 = dict(hmac_key, alg=None, k=_b64u(b"a" * 32))
        jwk.validate_jwk(key_256, "HS256")
        with pytest.raises(JWKError):
            jwk.validate_jwk(key_256, "HS384")

        key_384 = dict(hmac_key, alg=None, k=_b64u(b"a" * 48))
        jwk.validate_jwk(key_384, "HS384")
        with pytest.raises(JWKError):
            jwk.validate_jwk(key_384, "HS512")

        key_512 = dict(hmac_key, alg=None, k=_b64u(b"a" * 64))
        jwk.validate_jwk(key_512, "HS512")

    def test_invalid_oct_member_rejected(self):
        with pytest.raises(JWKError):
            jwk.validate_jwk(dict(hmac_key, k=1234), "HS256")
        with pytest.raises(JWKError):
            jwk.validate_jwk(dict(hmac_key, k="***"), "HS256")

    def test_short_rsa_modulus_rejected(self):
        from cryptography.hazmat.primitives.asymmetric import rsa as rsa_module

        small = rsa_module.generate_private_key(public_exponent=65537, key_size=1024).public_key().public_numbers()
        small_jwk = {
            "kty": "RSA",
            "kid": "small",
            "n": _b64u(small.n.to_bytes((small.n.bit_length() + 7) // 8, "big")),
            "e": _b64u(small.e.to_bytes((small.e.bit_length() + 7) // 8, "big")),
        }
        with pytest.raises(JWKError):
            jwk.validate_jwk(small_jwk, "RS256")

    def test_ec_curve_must_match_algorithm(self):
        with pytest.raises(JWKError):
            jwk.validate_jwk(dict(ec_key, crv="P-256"), "ES512")
        with pytest.raises(JWKError):
            jwk.validate_jwk(dict(ec_key, crv="P-384"), "ES256")

    def test_ec_missing_coordinates_rejected(self):
        with pytest.raises(JWKError):
            jwk.validate_jwk({"kty": "EC", "crv": "P-256", "x": "AAAA"}, "ES256")

    def test_construct_from_jwk_caches_by_family_and_kid(self):
        jwk.clear_jwk_cache()
        first = jwk.construct_from_jwk(hmac_key, "HS256")
        second = jwk.construct_from_jwk(hmac_key, "HS256")
        assert first is second

        cache_keys = list(jwk._jwk_cache)
        assert cache_keys == [("oct", hmac_key["kid"], "HS256")]

        # Same kid, different family uses a distinct cache entry.
        rsa_with_same_kid = dict(rsa_key, kid=hmac_key["kid"], alg="RS256")
        rsa_constructed = jwk.construct_from_jwk(rsa_with_same_kid, "RS256")
        assert ("RSA", hmac_key["kid"], "RS256") in jwk._jwk_cache
        assert rsa_constructed is not first
        jwk.clear_jwk_cache()

    def test_cache_key_never_holds_key_material(self):
        jwk.clear_jwk_cache()
        jwk.construct_from_jwk(hmac_key, "HS256")
        cache_key = next(iter(jwk._jwk_cache))
        assert hmac_key["k"] not in cache_key
        jwk.clear_jwk_cache()

    def test_jwk_without_kid_is_not_cached(self):
        jwk.clear_jwk_cache()
        kidless = dict(hmac_key, kid=None)
        first = jwk.construct_from_jwk(kidless, "HS256")
        second = jwk.construct_from_jwk(kidless, "HS256")
        assert first is not second
        assert jwk._jwk_cache == {}
        jwk.clear_jwk_cache()

    def test_non_dict_jwk_rejected(self):
        with pytest.raises(JWKError):
            jwk.validate_jwk("not-a-jwk", "HS256")
