import json

import pytest

from jwt.algorithms import has_crypto
from jwt.api_jwk import PyJWKSet
from jwt.exceptions import PyJWKClientError, PyJWKSetError, PyJWKSetImportError
from jwt.jwk_import_policy import JWKImportPolicy
from jwt.jwks_client import PyJWKClient
from jwt.utils import base64url_encode, to_base64url_uint

from .test_jwks_client import mocked_success_response
from .utils import crypto_required

if has_crypto:
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    EC_CURVES = {
        "P-256": (ec.SECP256R1, "ES256"),
        "P-384": (ec.SECP384R1, "ES384"),
        "P-521": (ec.SECP521R1, "ES512"),
    }


def b64uint(value: int) -> str:
    return to_base64url_uint(value).decode("ascii")


def make_rsa_jwk(bits: int = 2048, kid: str = "rsa-1", **extra):
    """Generate a local RSA key and return its public JWK dict."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public = private_key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "n": b64uint(public.n),
        "e": b64uint(public.e),
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
    }
    jwk.update(extra)
    return jwk


def make_ec_jwk(crv: str = "P-256", kid: str = "ec-1", **extra):
    """Generate a local EC key and return its public JWK dict."""
    curve_class, alg = EC_CURVES[crv]
    private_key = ec.generate_private_key(curve_class())
    public = private_key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": crv,
        "x": b64uint(public.x),
        "y": b64uint(public.y),
        "kid": kid,
        "use": "sig",
        "alg": alg,
    }
    jwk.update(extra)
    return jwk


def make_okp_jwk(kid: str = "okp-1", **extra):
    """Generate a local Ed25519 key and return its public JWK dict."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64url_encode(public_bytes).decode("ascii"),
        "kid": kid,
        "use": "sig",
        "alg": "EdDSA",
    }
    jwk.update(extra)
    return jwk


def make_oct_jwk(kid: str = "oct-1", **extra):
    jwk = {
        "kty": "oct",
        "k": base64url_encode(b"super-secret-key-material").decode("ascii"),
        "kid": kid,
        "use": "sig",
        "alg": "HS256",
    }
    jwk.update(extra)
    return jwk


@crypto_required
class TestJWKImportPolicy:
    def test_valid_keys_are_accepted(self):
        keys = [make_rsa_jwk(), make_ec_jwk(), make_okp_jwk(), make_oct_jwk()]
        report = JWKImportPolicy().evaluate(keys)

        assert report.ok
        assert report.accepted_indices == [0, 1, 2, 3]
        assert report.rejected == []

    def test_rejects_disallowed_use(self):
        report = JWKImportPolicy().evaluate([make_rsa_jwk(use="enc")])

        assert not report.ok
        assert "use 'enc' is not allowed" in report.rejected[0].reasons

    def test_use_check_can_be_disabled(self):
        report = JWKImportPolicy(allowed_uses=None).evaluate([make_rsa_jwk(use="enc")])

        assert report.ok

    def test_rejects_key_ops_without_verify(self):
        report = JWKImportPolicy().evaluate([make_rsa_jwk(key_ops=["sign", "wrapKey"])])

        assert not report.ok
        assert any("key_ops" in reason for reason in report.rejected[0].reasons)

    def test_accepts_key_ops_including_verify(self):
        report = JWKImportPolicy().evaluate(
            [make_rsa_jwk(key_ops=["verify", "wrapKey"])]
        )

        assert report.ok

    def test_rejects_disallowed_curve(self):
        policy = JWKImportPolicy(allowed_curves={"P-256"})
        report = policy.evaluate([make_ec_jwk(crv="P-384", kid="ec-384")])

        assert not report.ok
        assert "crv 'P-384' is not allowed" in report.rejected[0].reasons

    def test_rejects_rsa_below_minimum_bits(self):
        policy = JWKImportPolicy(min_rsa_bits=2048)
        report = policy.evaluate([make_rsa_jwk(bits=1024, kid="rsa-weak")])

        assert not report.ok
        assert any(
            "below the minimum 2048" in reason for reason in report.rejected[0].reasons
        )

    def test_accepts_rsa_meeting_minimum_bits(self):
        policy = JWKImportPolicy(min_rsa_bits=2048)
        report = policy.evaluate([make_rsa_jwk(bits=2048)])

        assert report.ok

    def test_rejects_kty_alg_mismatch(self):
        report = JWKImportPolicy().evaluate([make_rsa_jwk(alg="ES256")])

        assert not report.ok
        assert any(
            "inconsistent with kty" in reason for reason in report.rejected[0].reasons
        )

    def test_rejects_alg_curve_mismatch(self):
        report = JWKImportPolicy().evaluate([make_ec_jwk(alg="ES384")])

        assert not report.ok
        assert any(
            "inconsistent with crv" in reason for reason in report.rejected[0].reasons
        )

    def test_rejects_disallowed_alg(self):
        policy = JWKImportPolicy(allowed_algs={"RS256"})
        report = policy.evaluate([make_rsa_jwk(alg="RS512")])

        assert not report.ok
        assert "alg 'RS512' is not allowed" in report.rejected[0].reasons

    def test_rejects_disallowed_kty(self):
        policy = JWKImportPolicy(allowed_ktys={"RSA"})
        report = policy.evaluate([make_ec_jwk()])

        assert not report.ok
        assert "kty 'EC' is not allowed" in report.rejected[0].reasons

    def test_rejects_non_dict_member(self):
        report = JWKImportPolicy().evaluate(["not-a-jwk"])

        assert not report.ok
        assert report.rejected[0].reasons == ("key is not a JSON object",)

    def test_rejects_unloadable_key_without_leaking_details(self):
        # The point (1, 2) is not on P-256, so the key cannot be constructed.
        jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": b64uint(1),
            "y": b64uint(2),
            "kid": "broken",
        }
        report = JWKImportPolicy().evaluate([jwk])

        assert not report.ok
        assert report.rejected[0].reasons

    def test_duplicate_kid_with_different_material_rejects_both(self):
        first = make_rsa_jwk(kid="shared")
        second = make_rsa_jwk(kid="shared")
        report = JWKImportPolicy().evaluate([first, second])

        assert not report.ok
        assert len(report.rejected) == 2
        for decision in report.rejected:
            assert any("different key material" in r for r in decision.reasons)

    def test_duplicate_kid_with_identical_material_keeps_first(self):
        first = make_rsa_jwk(kid="shared")
        second = dict(first)
        report = JWKImportPolicy().evaluate([first, second])

        assert report.accepted_indices == [0]
        assert len(report.rejected) == 1
        assert any("duplicate" in r for r in report.rejected[0].reasons)

    def test_same_kid_same_material_different_metadata_is_not_a_conflict(self):
        first = make_rsa_jwk(kid="shared")
        second = dict(first, use=None)
        second.pop("use")
        second["x5t"] = "some-thumbprint"
        report = JWKImportPolicy().evaluate([first, second])

        # Identical material: the duplicate is dropped, not a conflict.
        assert report.accepted_indices == [0]
        assert not any(
            "different key material" in r for r in report.rejected[0].reasons
        )

    def test_reasons_do_not_contain_private_material(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = private_key.private_numbers()
        jwk = make_rsa_jwk(kid="leaky", use="enc")
        jwk["d"] = b64uint(numbers.d)
        jwk["p"] = b64uint(numbers.p)
        jwk["q"] = b64uint(numbers.q)

        policy = JWKImportPolicy()
        report = policy.evaluate([jwk])
        assert not report.ok

        report_text = report.summary() + repr(report) + str(report.rejected[0].reasons)
        assert jwk["d"] not in report_text
        assert jwk["p"] not in report_text
        assert jwk["q"] not in report_text
        assert jwk["n"] not in report_text

    def test_report_summary_lists_each_rejection(self):
        keys = [make_rsa_jwk(kid="a", use="enc"), make_ec_jwk(kid="b", use="enc")]
        report = JWKImportPolicy().evaluate(keys)

        summary = report.summary()
        assert "kid 'a'" in summary
        assert "kid 'b'" in summary


@crypto_required
class TestPyJWKSetWithImportPolicy:
    def test_no_policy_keeps_lenient_loading(self):
        keys = [make_rsa_jwk(), {"kty": "unsupported-kty"}]
        jwk_set = PyJWKSet(keys)

        assert len(jwk_set.keys) == 1
        assert jwk_set.import_policy is None
        assert jwk_set.import_report is None

    def test_quarantine_imports_only_accepted_keys(self):
        policy = JWKImportPolicy()
        keys = [make_rsa_jwk(kid="good"), make_ec_jwk(kid="bad", use="enc")]
        jwk_set = PyJWKSet(keys, import_policy=policy)

        assert [key.key_id for key in jwk_set.keys] == ["good"]
        assert jwk_set.import_report is not None
        assert len(jwk_set.import_report.rejected) == 1

    def test_strict_policy_rejects_whole_set(self):
        policy = JWKImportPolicy(strict=True)
        keys = [make_rsa_jwk(kid="good"), make_ec_jwk(kid="bad", use="enc")]

        with pytest.raises(PyJWKSetImportError) as exc_info:
            PyJWKSet(keys, import_policy=policy)

        assert len(exc_info.value.report.rejected) == 1
        assert "kid 'bad'" in str(exc_info.value)

    def test_strict_policy_accepts_clean_set(self):
        policy = JWKImportPolicy(strict=True)
        jwk_set = PyJWKSet([make_rsa_jwk()], import_policy=policy)

        assert len(jwk_set.keys) == 1

    def test_strict_error_does_not_leak_private_material(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = private_key.private_numbers()
        jwk = make_rsa_jwk(kid="leaky", use="enc")
        jwk["d"] = b64uint(numbers.d)

        with pytest.raises(PyJWKSetImportError) as exc_info:
            PyJWKSet([jwk], import_policy=JWKImportPolicy(strict=True))

        assert jwk["d"] not in str(exc_info.value)
        assert jwk["n"] not in str(exc_info.value)

    def test_set_with_all_keys_rejected_raises(self):
        policy = JWKImportPolicy()
        with pytest.raises(PyJWKSetError):
            PyJWKSet([make_rsa_jwk(use="enc")], import_policy=policy)

    def test_from_dict_and_from_json_accept_policy(self):
        policy = JWKImportPolicy()
        payload = {
            "keys": [make_rsa_jwk(kid="good"), make_ec_jwk(kid="bad", use="enc")]
        }

        from_dict = PyJWKSet.from_dict(payload, import_policy=policy)
        from_json = PyJWKSet.from_json(json.dumps(payload), import_policy=policy)

        assert [key.key_id for key in from_dict.keys] == ["good"]
        assert [key.key_id for key in from_json.keys] == ["good"]


@crypto_required
class TestPyJWKClientWithImportPolicy:
    def test_client_applies_policy_on_fetch(self):
        policy = JWKImportPolicy()
        data = {"keys": [make_rsa_jwk(kid="good"), make_ec_jwk(kid="bad", use="enc")]}
        client = PyJWKClient("https://example.com/jwks.json", jwk_import_policy=policy)

        with mocked_success_response(data):
            signing_key = client.get_signing_key("good")

        assert signing_key.key_id == "good"
        assert client.get_jwk_set().import_report is not None

    def test_client_quarantined_kid_is_not_found(self):
        policy = JWKImportPolicy()
        data = {"keys": [make_rsa_jwk(kid="good"), make_ec_jwk(kid="bad", use="enc")]}
        client = PyJWKClient("https://example.com/jwks.json", jwk_import_policy=policy)

        with mocked_success_response(data):
            client.get_jwk_set()
            with pytest.raises(PyJWKClientError):
                client.get_signing_key("bad")

    def test_cache_hit_does_not_bypass_policy(self):
        policy = JWKImportPolicy()
        client = PyJWKClient("https://example.com/jwks.json", jwk_import_policy=policy)

        # Simulate a cached JWK Set that was imported without the policy.
        unscreened = PyJWKSet(
            [make_rsa_jwk(kid="good"), make_ec_jwk(kid="bad", use="enc")]
        )
        client.jwk_set_cache.put(unscreened)

        jwk_set = client.get_jwk_set()
        assert [key.key_id for key in jwk_set.keys] == ["good"]

    def test_signing_key_cache_only_holds_accepted_keys(self):
        policy = JWKImportPolicy()
        data = {"keys": [make_rsa_jwk(kid="good"), make_ec_jwk(kid="bad", use="enc")]}
        client = PyJWKClient(
            "https://example.com/jwks.json",
            cache_keys=True,
            jwk_import_policy=policy,
        )

        with mocked_success_response(data):
            first = client.get_signing_key("good")
            second = client.get_signing_key("good")

        assert first is second
        with pytest.raises(PyJWKClientError):
            client.get_signing_key("bad")

    def test_strict_policy_client_raises_on_fetch(self):
        policy = JWKImportPolicy(strict=True)
        data = {"keys": [make_rsa_jwk(kid="good"), make_ec_jwk(kid="bad", use="enc")]}
        client = PyJWKClient("https://example.com/jwks.json", jwk_import_policy=policy)

        with mocked_success_response(data):
            with pytest.raises(PyJWKSetImportError):
                client.get_jwk_set()

    def test_duplicate_kid_conflict_via_client(self):
        policy = JWKImportPolicy()
        data = {
            "keys": [
                make_rsa_jwk(kid="shared"),
                make_rsa_jwk(kid="shared"),
                make_ec_jwk(kid="good"),
            ]
        }
        client = PyJWKClient("https://example.com/jwks.json", jwk_import_policy=policy)

        with mocked_success_response(data):
            jwk_set = client.get_jwk_set()

        assert [key.key_id for key in jwk_set.keys] == ["good"]
