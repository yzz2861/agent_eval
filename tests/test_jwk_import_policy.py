import contextlib
import json
from unittest import mock

import pytest

from jwt import PyJWKClient, PyJWKSet
from jwt.algorithms import has_crypto
from jwt.exceptions import PyJWKSetError
from jwt.jwk_import_policy import (
    JWKImportPolicy,
    JWKImportReport,
)
from jwt.jwk_set_cache import JWKSetCache

from .utils import crypto_required

if has_crypto:
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    from jwt.algorithms import ECAlgorithm, HMACAlgorithm, OKPAlgorithm, RSAAlgorithm


def make_rsa_jwk(kid, bits=2048, **extra):
    private_key = rsa.generate_private_key(65537, bits)
    jwk = RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    jwk.update(extra)
    return jwk


def make_rsa_private_jwk(kid, bits=2048, **extra):
    private_key = rsa.generate_private_key(65537, bits)
    jwk = RSAAlgorithm.to_jwk(private_key, as_dict=True)
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    jwk.update(extra)
    return jwk


def make_ec_jwk(kid, curve=None, **extra):
    private_key = ec.generate_private_key(curve or ec.SECP256R1())
    jwk = ECAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    jwk.update({"kid": kid, "use": "sig"})
    jwk.update(extra)
    return jwk


def make_okp_jwk(kid, **extra):
    private_key = ed25519.Ed25519PrivateKey.generate()
    jwk = OKPAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    jwk.update({"kid": kid, "use": "sig", "alg": "EdDSA"})
    jwk.update(extra)
    return jwk


def make_oct_jwk(kid, secret=b"not-a-real-secret-key", **extra):
    jwk = HMACAlgorithm.to_jwk(secret, as_dict=True)
    jwk.update({"kid": kid, "use": "sig", "alg": "HS256"})
    jwk.update(extra)
    return jwk


@contextlib.contextmanager
def mocked_jwks_response(payload):
    with mock.patch("urllib.request.build_opener") as build_opener_mock:
        opener = mock.Mock()
        build_opener_mock.return_value = opener
        urlopen_mock = opener.open
        response = mock.Mock()
        response.__enter__ = mock.Mock(return_value=response)
        response.__exit__ = mock.Mock()
        response.read.side_effect = [json.dumps(payload)]
        urlopen_mock.return_value = response
        yield urlopen_mock


@crypto_required
class TestJWKImportPolicyEvaluate:
    def setup_method(self) -> None:
        self.policy = JWKImportPolicy()

    def test_valid_keys_are_accepted(self) -> None:
        assert self.policy.evaluate(make_rsa_jwk("rsa")) == ()
        assert self.policy.evaluate(make_ec_jwk("ec")) == ()
        assert self.policy.evaluate(make_okp_jwk("okp")) == ()
        assert self.policy.evaluate(make_oct_jwk("oct")) == ()

    def test_kty_alg_mismatch_is_rejected(self) -> None:
        reasons = self.policy.evaluate(make_rsa_jwk("mm", alg="ES256"))
        assert any("inconsistent with alg" in reason for reason in reasons)

    def test_alg_crv_mismatch_is_rejected(self) -> None:
        reasons = self.policy.evaluate(make_ec_jwk("mm", alg="ES384"))
        assert any("inconsistent with alg" in reason for reason in reasons)

    def test_unknown_alg_is_rejected(self) -> None:
        reasons = self.policy.evaluate(make_rsa_jwk("unknown", alg="NOPE999"))
        assert any("not a recognized algorithm" in reason for reason in reasons)

    def test_missing_alg_is_allowed(self) -> None:
        jwk = make_rsa_jwk("noalg")
        del jwk["alg"]
        assert self.policy.evaluate(jwk) == ()

    def test_use_other_than_sig_is_rejected(self) -> None:
        reasons = self.policy.evaluate(make_rsa_jwk("enc", use="enc"))
        assert any("use 'enc' is not allowed" in reason for reason in reasons)

    def test_missing_use_is_allowed(self) -> None:
        jwk = make_rsa_jwk("nouse")
        del jwk["use"]
        assert self.policy.evaluate(jwk) == ()

    def test_key_ops_without_verify_is_rejected(self) -> None:
        reasons = self.policy.evaluate(make_rsa_jwk("ops", key_ops=["sign"]))
        assert any("key_ops" in reason for reason in reasons)

    def test_key_ops_with_verify_is_accepted(self) -> None:
        jwk = make_rsa_jwk("ops", key_ops=["verify", "unwrapKey"])
        assert self.policy.evaluate(jwk) == ()

    def test_malformed_key_ops_is_rejected(self) -> None:
        reasons = self.policy.evaluate(make_rsa_jwk("ops", key_ops="verify"))
        assert any("key_ops is not a list of strings" in reason for reason in reasons)

    def test_disallowed_curve_is_rejected(self) -> None:
        policy = JWKImportPolicy(allowed_curves=("P-256",))
        reasons = policy.evaluate(make_ec_jwk("p384", curve=ec.SECP384R1()))
        assert any("not in the allowed curves" in reason for reason in reasons)
        assert policy.evaluate(make_ec_jwk("p256")) == ()

    def test_small_rsa_key_is_rejected(self) -> None:
        reasons = self.policy.evaluate(make_rsa_jwk("small", bits=1024))
        assert any("1024 bits" in reason for reason in reasons)

    def test_small_rsa_key_allowed_when_minimum_lowered(self) -> None:
        policy = JWKImportPolicy(min_rsa_bits=1024)
        assert policy.evaluate(make_rsa_jwk("small", bits=1024)) == ()

    def test_non_string_metadata_is_rejected(self) -> None:
        reasons = self.policy.evaluate(make_rsa_jwk("bad", alg=123, use=42))
        assert any("alg is not a string" in reason for reason in reasons)
        assert any("use is not a string" in reason for reason in reasons)

    def test_invalid_on_kid_conflict_value(self) -> None:
        with pytest.raises(ValueError):
            JWKImportPolicy(on_kid_conflict="explode")


@crypto_required
class TestPyJWKSetImportPolicy:
    def test_report_records_per_key_decisions(self) -> None:
        keys = [
            make_rsa_jwk("good"),
            make_rsa_jwk("small", bits=1024),
            make_ec_jwk("enc", use="enc"),
        ]
        jwk_set = PyJWKSet(keys, import_policy=JWKImportPolicy())

        assert [key.key_id for key in jwk_set.keys] == ["good"]

        report = jwk_set.import_report
        assert isinstance(report, JWKImportReport)
        assert len(report) == 3
        assert [d.index for d in report.accepted] == [0]
        assert [d.index for d in report.rejected] == [1, 2]
        assert report.rejected[0].kid == "small"
        assert any("1024 bits" in r for r in report.rejected[0].reasons)
        assert any("use 'enc'" in r for r in report.rejected[1].reasons)

    def test_non_object_members_are_reported(self) -> None:
        jwk_set = PyJWKSet(
            ["not-a-dict", make_rsa_jwk("good")], import_policy=JWKImportPolicy()
        )
        assert [key.key_id for key in jwk_set.keys] == ["good"]
        rejected = jwk_set.import_report.rejected
        assert len(rejected) == 1
        assert rejected[0].index == 0
        assert "not a JWK object" in rejected[0].reasons[0]

    def test_unconstructable_key_is_reported_without_exception_details(self) -> None:
        broken = make_rsa_jwk("broken")
        broken["n"] = "!!!not-base64url!!!"
        jwk_set = PyJWKSet(
            [broken, make_rsa_jwk("good")], import_policy=JWKImportPolicy()
        )
        rejected = jwk_set.import_report.rejected
        assert len(rejected) == 1
        assert "could not be constructed" in rejected[0].reasons[0]

    def test_all_keys_rejected_raises_set_error(self) -> None:
        with pytest.raises(PyJWKSetError, match="import policy"):
            PyJWKSet(
                [make_rsa_jwk("small", bits=1024)], import_policy=JWKImportPolicy()
            )

    def test_kid_conflict_is_isolated_by_default(self) -> None:
        keys = [make_rsa_jwk("dup"), make_rsa_jwk("dup"), make_rsa_jwk("good")]
        jwk_set = PyJWKSet(keys, import_policy=JWKImportPolicy())

        assert [key.key_id for key in jwk_set.keys] == ["good"]
        rejected = jwk_set.import_report.rejected
        assert [d.kid for d in rejected] == ["dup", "dup"]
        assert all("conflicting key material" in d.reasons[0] for d in rejected)

    def test_kid_conflict_rejects_whole_set_when_configured(self) -> None:
        keys = [make_rsa_jwk("dup"), make_rsa_jwk("dup")]
        policy = JWKImportPolicy(on_kid_conflict="reject")
        with pytest.raises(PyJWKSetError, match="conflicting keys for kid 'dup'"):
            PyJWKSet(keys, import_policy=policy)

    def test_identical_kid_duplicates_are_deduplicated(self) -> None:
        jwk = make_rsa_jwk("dup")
        jwk_set = PyJWKSet([jwk, dict(jwk)], import_policy=JWKImportPolicy())

        assert len(jwk_set.keys) == 1
        rejected = jwk_set.import_report.rejected
        assert len(rejected) == 1
        assert "duplicate" in rejected[0].reasons[0]

    def test_same_kid_same_material_different_metadata_is_deduplicated(self) -> None:
        first = make_rsa_jwk("dup")
        second = dict(first, use=None, key_ops=["verify"])
        jwk_set = PyJWKSet([first, second], import_policy=JWKImportPolicy())
        assert len(jwk_set.keys) == 1

    def test_kid_lookup_never_returns_conflicting_key(self) -> None:
        keys = [make_rsa_jwk("dup"), make_rsa_jwk("dup"), make_rsa_jwk("good")]
        jwk_set = PyJWKSet(keys, import_policy=JWKImportPolicy())
        with pytest.raises(KeyError):
            jwk_set["dup"]
        assert jwk_set["good"].key_id == "good"

    def test_report_does_not_leak_private_key_material(self) -> None:
        private_jwk = make_rsa_private_jwk("private", bits=1024)
        oct_jwk = make_oct_jwk("oct-secret", use="enc")
        jwk_set = PyJWKSet(
            [private_jwk, oct_jwk, make_rsa_jwk("good")],
            import_policy=JWKImportPolicy(),
        )

        report_text = str(jwk_set.import_report)
        for param in ("d", "p", "q", "dp", "dq", "qi"):
            assert private_jwk[param] not in report_text
        assert oct_jwk["k"] not in report_text

    def test_private_keys_may_pass_policy_but_stay_out_of_report(self) -> None:
        private_jwk = make_rsa_private_jwk("private", key_ops=["sign", "verify"])
        jwk_set = PyJWKSet([private_jwk], import_policy=JWKImportPolicy())
        assert len(jwk_set.keys) == 1
        report_text = str(jwk_set.import_report)
        for param in ("d", "p", "q", "dp", "dq", "qi"):
            assert private_jwk[param] not in report_text

    def test_from_json_accepts_import_policy(self) -> None:
        payload = json.dumps(
            {"keys": [make_rsa_jwk("good"), make_rsa_jwk("small", bits=1024)]}
        )
        jwk_set = PyJWKSet.from_json(payload, import_policy=JWKImportPolicy())
        assert [key.key_id for key in jwk_set.keys] == ["good"]

    def test_legacy_lenient_loading_is_unchanged(self) -> None:
        keys = [make_rsa_jwk("small", bits=1024), make_ec_jwk("enc", use="enc")]
        jwk_set = PyJWKSet(keys)
        assert sorted(key.key_id for key in jwk_set.keys) == ["enc", "small"]
        assert jwk_set.import_report is None


@crypto_required
class TestJWKSetCacheImportPolicy:
    def test_put_dict_applies_policy(self) -> None:
        cache = JWKSetCache(300, import_policy=JWKImportPolicy())
        cache.put({"keys": [make_rsa_jwk("good"), make_rsa_jwk("enc", use="enc")]})

        cached = cache.get()
        assert cached is not None
        assert [key.key_id for key in cached.keys] == ["good"]
        assert cached.import_report is not None

    def test_cache_hit_serves_policy_filtered_set(self) -> None:
        cache = JWKSetCache(300, import_policy=JWKImportPolicy())
        payload = {"keys": [make_rsa_jwk("good"), make_rsa_jwk("small", bits=1024)]}
        cache.put(payload)

        first = cache.get()
        second = cache.get()
        assert first is second
        assert [key.key_id for key in second.keys] == ["good"]


@crypto_required
class TestPyJWKClientImportPolicy:
    def test_client_filters_keys_and_caches_filtered_set(self) -> None:
        payload = {
            "keys": [
                make_rsa_jwk("good"),
                make_rsa_jwk("small", bits=1024),
                make_ec_jwk("enc", use="enc"),
            ]
        }
        client = PyJWKClient(
            "https://example.com/jwks", import_policy=JWKImportPolicy()
        )

        with mocked_jwks_response(payload) as urlopen_mock:
            signing_keys = client.get_signing_keys()
            assert [key.key_id for key in signing_keys] == ["good"]

            # Second call is served from the JWK Set cache; the policy must
            # still hold without a new fetch.
            signing_keys = client.get_signing_keys()
            assert [key.key_id for key in signing_keys] == ["good"]
            assert urlopen_mock.call_count == 1

        cached = client.jwk_set_cache.get()
        assert [key.key_id for key in cached.keys] == ["good"]
        assert isinstance(cached.import_report, JWKImportReport)
        assert len(cached.import_report.rejected) == 2

    def test_signing_key_cache_only_contains_policy_compliant_keys(self) -> None:
        payload = {"keys": [make_rsa_jwk("good"), make_rsa_jwk("small", bits=1024)]}
        client = PyJWKClient(
            "https://example.com/jwks",
            cache_keys=True,
            import_policy=JWKImportPolicy(),
        )

        with mocked_jwks_response(payload):
            assert client.get_signing_key("good").key_id == "good"
            with pytest.raises(Exception, match="small"):
                client.get_signing_key("small")

    def test_client_without_policy_keeps_legacy_behavior(self) -> None:
        payload = {"keys": [make_rsa_jwk("small", bits=1024)]}
        client = PyJWKClient("https://example.com/jwks")

        with mocked_jwks_response(payload):
            assert client.get_signing_key("small").key_id == "small"
        assert client.jwk_set_cache.get().import_report is None
