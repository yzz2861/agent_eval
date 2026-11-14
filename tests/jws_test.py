"""Tests for josepy.jws."""

import base64
import json
import sys
import unittest
from unittest import mock

import pytest
import test_util
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from josepy import errors, json_util, jwa, jwk

CERT = test_util.load_cert("cert.pem")
KEY = jwk.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))


class MediaTypeTest(unittest.TestCase):
    """Tests for josepy.jws.MediaType."""

    def test_decode(self) -> None:
        from josepy.jws import MediaType

        assert "application/app" == MediaType.decode("application/app")
        assert "application/app" == MediaType.decode("app")
        with pytest.raises(errors.DeserializationError):
            MediaType.decode("app;foo")

    def test_encode(self) -> None:
        from josepy.jws import MediaType

        assert "app" == MediaType.encode("application/app")
        assert "application/app;foo" == MediaType.encode("application/app;foo")


class HeaderTest(unittest.TestCase):
    """Tests for josepy.jws.Header."""

    def setUp(self) -> None:
        from josepy.jws import Header

        self.header1 = Header(jwk="foo")
        self.header2 = Header(jwk="bar")
        self.crit = Header(crit=("a", "b"))
        self.empty = Header()

    def test_add_non_empty(self) -> None:
        from josepy.jws import Header

        assert Header(jwk="foo", crit=("a", "b")) == self.header1 + self.crit

    def test_add_empty(self) -> None:
        assert self.header1 == self.header1 + self.empty
        assert self.header1 == self.empty + self.header1

    def test_add_overlapping_error(self) -> None:
        from josepy.jws import Header

        with pytest.raises(errors.HeaderConflictError):
            self.header1.__add__(self.header2)

    def test_add_overlapping_same_value_still_errors(self) -> None:
        from josepy.jws import Header

        with pytest.raises(errors.HeaderConflictError):
            Header(jwk="foo") + Header(jwk="foo")

    def test_add_wrong_type_error(self) -> None:
        with pytest.raises(TypeError):
            self.header1.__add__("xxx")

    def test_crit_decode_always_errors(self) -> None:
        from josepy.jws import Header

        with pytest.raises(errors.DeserializationError):
            Header.from_json({"crit": ["a", "b"]})

    def test_x5c_decoding(self) -> None:
        from josepy.jws import Header

        header = Header(x5c=(CERT, CERT))
        jobj = header.to_partial_json()
        assert isinstance(CERT, x509.Certificate)
        cert_asn1 = CERT.public_bytes(Encoding.DER)
        cert_b64 = base64.b64encode(cert_asn1)
        assert jobj == {"x5c": [cert_b64, cert_b64]}
        assert header == Header.from_json(jobj)
        jobj["x5c"][0] = base64.b64encode(b"xxx" + cert_asn1)
        with pytest.raises(errors.DeserializationError):
            Header.from_json(jobj)

    def test_find_key(self) -> None:
        assert "foo" == self.header1.find_key()
        assert "bar" == self.header2.find_key()
        with pytest.raises(errors.Error):
            self.crit.find_key()


class SignatureTest(unittest.TestCase):
    """Tests for josepy.jws.Signature."""

    def test_from_json(self) -> None:
        from josepy.jws import Header, Signature

        assert Signature(signature=b"foo", header=Header(alg=jwa.RS256)) == Signature.from_json(
            {"signature": "Zm9v", "header": {"alg": "RS256"}}
        )

    def test_from_json_no_alg_error(self) -> None:
        from josepy.jws import Signature

        with pytest.raises(errors.DeserializationError):
            Signature.from_json({"signature": "foo"})


class JWSTest(unittest.TestCase):
    """Tests for josepy.jws.JWS."""

    def setUp(self) -> None:
        self.privkey = KEY
        self.pubkey = self.privkey.public_key()

        from josepy.jws import JWS

        self.unprotected = JWS.sign(payload=b"foo", key=self.privkey, alg=jwa.RS256)
        self.protected = JWS.sign(
            payload=b"foo", key=self.privkey, alg=jwa.RS256, protect=frozenset(["jwk", "alg"])
        )
        self.mixed = JWS.sign(
            payload=b"foo", key=self.privkey, alg=jwa.RS256, protect=frozenset(["alg"])
        )

    def test_pubkey_jwk(self) -> None:
        assert self.unprotected.signature.combined.jwk == self.pubkey
        assert self.protected.signature.combined.jwk == self.pubkey
        assert self.mixed.signature.combined.jwk == self.pubkey

    def test_sign_unprotected(self) -> None:
        assert self.unprotected.verify() is True

    def test_sign_protected(self) -> None:
        assert self.protected.verify() is True

    def test_sign_mixed(self) -> None:
        assert self.mixed.verify() is True

    def test_compact_lost_unprotected(self) -> None:
        compact = self.mixed.to_compact()
        assert (
            b"eyJhbGciOiAiUlMyNTYifQ.Zm9v.OHdxFVj73l5LpxbFp1AmYX4yJM0Pyb"
            b"_893n1zQjpim_eLS5J1F61lkvrCrCDErTEJnBGOGesJ72M7b6Ve1cAJA" == compact
        )

        from josepy.jws import JWS

        mixed = JWS.from_compact(compact)

        assert self.mixed != mixed
        assert {"alg"} == set(mixed.signature.combined.not_omitted())

    def test_from_compact_missing_components(self) -> None:
        from josepy.jws import JWS

        with pytest.raises(errors.DeserializationError):
            JWS.from_compact(b".")

    def test_protected_header_must_be_json_object(self) -> None:
        from josepy.jws import Header, Signature

        with pytest.raises(errors.DeserializationError):
            Header.from_json(["alg", "RS256"])
        with pytest.raises(errors.DeserializationError):
            Signature.from_json(
                {
                    "protected": json_util.encode_b64jose(b'["alg", "RS256"]'),
                    "signature": "Zm9v",
                }
            )

    def test_from_compact_unknown_alg_is_classified(self) -> None:
        from josepy.jws import JWS

        protected = json_util.encode_b64jose(b'{"alg": "rs256"}')
        compact = protected.encode() + b"." + json_util.encode_b64jose(b"foo").encode() + b".Zm9v"
        with pytest.raises(errors.AlgorithmError):
            JWS.from_compact(compact)

    def test_json_omitempty(self) -> None:
        protected_jobj = self.protected.to_partial_json(flat=True)
        unprotected_jobj = self.unprotected.to_partial_json(flat=True)

        assert "protected" not in unprotected_jobj
        assert "header" not in protected_jobj

        unprotected_jobj["header"] = unprotected_jobj["header"].to_json()

        from josepy.jws import JWS

        assert JWS.from_json(protected_jobj) == self.protected
        assert JWS.from_json(unprotected_jobj) == self.unprotected

    def test_json_flat(self) -> None:
        jobj_to = {
            "signature": json_util.encode_b64jose(self.mixed.signature.signature),
            "payload": json_util.encode_b64jose(b"foo"),
            "header": self.mixed.signature.header,
            "protected": json_util.encode_b64jose(self.mixed.signature.protected.encode("utf-8")),
        }

        from josepy.jws import Header

        jobj_from = jobj_to.copy()
        header = jobj_from["header"]
        assert isinstance(header, Header)
        jobj_from["header"] = header.to_json()

        assert self.mixed.to_partial_json(flat=True) == jobj_to
        from josepy.jws import JWS

        assert self.mixed == JWS.from_json(jobj_from)

    def test_json_not_flat(self) -> None:
        jobj_to = {
            "signatures": (self.mixed.signature,),
            "payload": json_util.encode_b64jose(b"foo"),
        }
        jobj_from = jobj_to.copy()
        signature = jobj_to["signatures"][0]
        from josepy.jws import Signature

        assert isinstance(signature, Signature)
        jobj_from["signatures"] = [signature.to_json()]

        assert self.mixed.to_partial_json(flat=False) == jobj_to
        from josepy.jws import JWS

        assert self.mixed == JWS.from_json(jobj_from)

    def test_from_json_mixed_flat(self) -> None:
        from josepy.jws import JWS

        with pytest.raises(errors.DeserializationError):
            JWS.from_json({"signatures": (), "signature": "foo"})

    def test_from_json_hashable(self) -> None:
        from josepy.jws import JWS

        hash(JWS.from_json(self.mixed.to_json()))


class HeaderMergeTest(unittest.TestCase):
    """Deterministic, traceable merging of protected/unprotected headers."""

    def setUp(self) -> None:
        from josepy.jws import Header

        self.Header = Header
        self.protected = Header(alg=jwa.RS256, nonce="nonce-value", url="https://example/")
        self.unprotected = Header(jwk=KEY.public_key(), kid=None)

    def test_merge_records_origins(self) -> None:
        combined, origins = self.Header.merge(self.protected, self.unprotected)
        assert combined.alg is jwa.RS256
        assert combined.nonce == "nonce-value"
        assert origins["alg"] == "protected"
        assert origins["nonce"] == "protected"
        assert origins["url"] == "protected"
        assert origins["jwk"] == "unprotected"

    def test_merge_duplicate_rejected_even_with_identical_values(self) -> None:
        for other in (self.Header(alg=jwa.RS256), self.Header(alg=jwa.HS256)):
            with pytest.raises(errors.HeaderConflictError):
                self.Header.merge(self.Header(alg=jwa.RS256), other)

    def test_merge_empty_layers(self) -> None:
        combined, origins = self.Header.merge(self.Header(), self.Header())
        assert combined == self.Header()
        assert origins == {}

    def test_jwk_and_kid_are_mutually_exclusive(self) -> None:
        header = self.Header(alg=jwa.RS256, jwk=KEY.public_key(), kid="account")
        with pytest.raises(errors.KeySelectorError):
            header.validate_key_selection()


class SignatureHeaderSecurityTest(unittest.TestCase):
    """Cross-layer header attacks must fail with classified errors."""

    def setUp(self) -> None:
        from josepy.jws import JWS

        self.jws = JWS
        self.privkey = KEY
        self.pubkey = KEY.public_key()

    def _flat(self, protected: dict, header: dict | None = None) -> dict:
        jobj = {
            "protected": json_util.encode_b64jose(
                json.dumps(protected, separators=(",", ":")).encode()
            ),
            "payload": json_util.encode_b64jose(b"foo"),
            "signature": json_util.encode_b64jose(b"signature"),
        }
        if header:
            jobj["header"] = header
        return jobj

    def test_cross_layer_duplicate_alg_rejected(self) -> None:
        jobj = self._flat({"alg": "RS256", "jwk": self.pubkey.to_json()}, {"alg": "HS256"})
        with pytest.raises(errors.HeaderConflictError):
            self.jws.from_json(jobj)

    def test_cross_layer_duplicate_same_value_rejected(self) -> None:
        jobj = self._flat({"alg": "RS256", "jwk": self.pubkey.to_json()}, {"alg": "RS256"})
        with pytest.raises(errors.HeaderConflictError):
            self.jws.from_json(jobj)

    def test_cross_layer_duplicate_nonce_rejected(self) -> None:
        jobj = self._flat(
            {"alg": "RS256", "jwk": self.pubkey.to_json(), "nonce": "a"},
            {"nonce": "a"},
        )
        with pytest.raises(errors.HeaderConflictError):
            self.jws.from_json(jobj)

    def test_jwk_and_kid_across_layers_rejected(self) -> None:
        jobj = self._flat({"alg": "RS256", "jwk": self.pubkey.to_json()}, {"kid": "account"})
        with pytest.raises(errors.KeySelectorError):
            self.jws.from_json(jobj)

    def test_jwk_and_kid_same_layer_rejected(self) -> None:
        jobj = self._flat({"alg": "RS256", "jwk": self.pubkey.to_json(), "kid": "account"})
        with pytest.raises(errors.KeySelectorError):
            self.jws.from_json(jobj)

    def test_empty_alg_rejected(self) -> None:
        with pytest.raises(errors.AlgorithmError):
            self.jws.from_json(self._flat({"alg": ""}))

    def test_alg_name_is_case_sensitive(self) -> None:
        for name in ("rs256", "Rs256", "RS256 "):
            with self.subTest(name=name):
                with pytest.raises(errors.AlgorithmError):
                    self.jws.from_json(self._flat({"alg": name}))

    def test_unknown_alg_rejected(self) -> None:
        with pytest.raises(errors.AlgorithmError):
            self.jws.from_json(self._flat({"alg": "NOPE"}))

    def test_unknown_crit_rejected_before_verification(self) -> None:
        from josepy.jws import Signature

        jobj = self._flat({"alg": "RS256", "crit": ["unknown"], "unknown": 1})
        with pytest.raises(errors.CriticalHeaderError):
            Signature.from_json(jobj)

    def test_crit_without_matching_header_rejected(self) -> None:
        jobj = self._flat({"alg": "RS256", "crit": ["missing"]})
        with pytest.raises(errors.CriticalHeaderError):
            self.jws.from_json(jobj)

    def test_crit_empty_array_rejected(self) -> None:
        jobj = self._flat({"alg": "RS256", "crit": []})
        with pytest.raises(errors.CriticalHeaderError):
            self.jws.from_json(jobj)

    def test_error_messages_do_not_leak_nonce_or_jwk(self) -> None:
        secret_nonce = "super-secret-nonce"
        jws_obj = self.jws.sign(payload=b"foo", key=self.privkey, alg=jwa.RS256, nonce=secret_nonce)
        with pytest.raises(errors.HeaderSourceError) as exc_info:
            jws_obj.verify_detailed(acme=True)
        message = str(exc_info.value)
        assert secret_nonce not in message
        assert str(self.privkey.key) not in message


class ACMESourceConstraintTest(unittest.TestCase):
    """RFC 8555 section 6.2 protected header source constraints."""

    def setUp(self) -> None:
        from josepy.jws import JWS

        self.jws = JWS
        self.key = KEY

    def _sign(self, **kwargs) -> "JWS":
        return self.jws.sign(payload=b"foo", key=self.key, alg=jwa.RS256, **kwargs)

    def test_fully_protected_request_passes(self) -> None:
        jws_obj = self._sign(
            protect=frozenset(["alg", "jwk", "nonce", "url"]),
            nonce="nonce",
            url="https://example/new-account",
        )
        result = jws_obj.verify_detailed(acme=True)
        assert len(result) == 1
        assert bool(result[0]) is True
        assert result[0].alg is jwa.RS256

    def test_kid_based_request_requires_external_key(self) -> None:
        jws_obj = self._sign(
            include_jwk=False,
            protect=frozenset(["alg", "kid", "nonce", "url"]),
            kid="account-url",
            nonce="nonce",
            url="https://example/order",
        )
        with pytest.raises(errors.KeySelectorError):
            jws_obj.verify_detailed(acme=True)
        result = jws_obj.verify_detailed(key=self.key.public_key(), acme=True)
        assert bool(result[0]) is True
        from josepy.jws import KEY_SOURCE_KID

        assert result[0].key_source == KEY_SOURCE_KID

    def test_unprotected_alg_rejected_for_acme(self) -> None:
        jws_obj = self._sign()
        with pytest.raises(errors.HeaderSourceError):
            jws_obj.verify_detailed(acme=True)

    def test_unprotected_nonce_rejected_for_acme(self) -> None:
        jws_obj = self._sign(protect=frozenset(["alg", "jwk"]), nonce="nonce")
        with pytest.raises(errors.HeaderSourceError):
            jws_obj.verify_detailed(acme=True)

    def test_acme_requires_jwk_or_kid(self) -> None:
        jws_obj = self._sign(
            include_jwk=False,
            protect=frozenset(["alg", "nonce", "url"]),
            nonce="nonce",
            url="https://example/",
        )
        with pytest.raises(errors.KeySelectorError):
            jws_obj.verify_detailed(acme=True)


class VerifyDetailedTest(unittest.TestCase):
    """Verification reports the actual algorithm and key origin."""

    def setUp(self) -> None:
        from josepy.jws import JWS, KEY_SOURCE_JWK

        self.JWS = JWS
        self.KEY_SOURCE_JWK = KEY_SOURCE_JWK
        self.key = KEY

    def test_jwk_key_source(self) -> None:
        jws_obj = self.JWS.sign(payload=b"foo", key=self.key, alg=jwa.RS256)
        result = jws_obj.verify_detailed()
        assert bool(result[0]) is True
        assert result[0].alg is jwa.RS256
        assert result[0].key_source == self.KEY_SOURCE_JWK

    def test_external_key_source_and_boolean_verify(self) -> None:
        from josepy.jws import KEY_SOURCE_EXTERNAL

        jws_obj = self.JWS.sign(payload=b"foo", key=self.key, alg=jwa.RS256)
        result = jws_obj.verify_detailed(key=self.key.public_key())
        assert result[0].key_source == KEY_SOURCE_EXTERNAL
        assert jws_obj.verify() is True

    def test_tampered_signature_is_invalid_but_reports_alg(self) -> None:
        jws_obj = self.JWS.sign(payload=b"foo", key=self.key, alg=jwa.RS256)
        jobj = jws_obj.to_json()
        jobj["signature"] = json_util.encode_b64jose(b"not-the-signature")
        jws_obj = self.JWS.from_json(jobj)
        result = jws_obj.verify_detailed()
        assert bool(result[0]) is False
        assert result[0].alg is jwa.RS256

    def test_verify_uses_merged_header_algorithm(self) -> None:
        from josepy.jws import Signature

        jws_obj = self.JWS.sign(
            payload=b"foo", key=self.key, alg=jwa.RS256, protect=frozenset(["alg"])
        )
        with mock.patch.object(jwa.RS256, "verify", return_value=True) as verify_mock:
            result = jws_obj.verify_detailed()
        assert bool(result[0]) is True
        verify_mock.assert_called_once()
        _, kwargs = verify_mock.call_args
        assert kwargs["sig"] == jws_obj.signature.signature
        assert Signature._msg(jws_obj.signature.protected, b"foo") == kwargs["msg"]


class CLITest(unittest.TestCase):
    def setUp(self) -> None:
        self.key_path = test_util.vector_path("rsa512_key.pem")

    def test_unverified(self) -> None:
        from josepy.jws import CLI

        with mock.patch("sys.stdin") as sin:
            sin.read.return_value = '{"payload": "foo", "signature": "xxx"}'
            with mock.patch("sys.stdout"):
                assert CLI.run(["verify"]) is False

    def test_json(self) -> None:
        from josepy.jws import CLI

        with mock.patch("sys.stdin") as sin:
            sin.read.return_value = "foo"
            with mock.patch("sys.stdout") as sout:
                CLI.run(["sign", "-k", self.key_path, "-a", "RS256", "-p", "jwk"])
                sin.read.return_value = sout.write.mock_calls[0][1][0]
                assert 0 == CLI.run(["verify"])

    def test_compact(self) -> None:
        from josepy.jws import CLI

        with mock.patch("sys.stdin") as sin:
            sin.read.return_value = "foo"
            with mock.patch("sys.stdout") as sout:
                CLI.run(["--compact", "sign", "-k", self.key_path])
                sin.read.return_value = sout.write.mock_calls[0][1][0]
                assert 0 == CLI.run(["--compact", "verify", "--kty", "RSA", "-k", self.key_path])


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
