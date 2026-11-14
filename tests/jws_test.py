"""Tests for josepy.jws."""

import base64
import hashlib
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

# Fixed ACME key authorization vectors. The expected values are recomputed
# here with only the standard library so regressions in serialization,
# Unicode handling, padding or digest input are caught byte by byte.
KA_TOKEN = "QfO9bMUP-W2WxV8v4t1qJQ"
KA_THUMBPRINT = "8-e-qGDS2nDpfZzOPtD8Sb7NkifUbw70MeqOKIqyaRw"
KA_RAW = b"QfO9bMUP-W2WxV8v4t1qJQ.8-e-qGDS2nDpfZzOPtD8Sb7NkifUbw70MeqOKIqyaRw"
KA_DNS01 = "0FlqkMHfgJ7oDbu-W8NTjmtX3moup4MVnaHCoYVr7ds"

# Second fully hard-coded vector (no key object involved).
KA2_TOKEN = "DGyRejmCefe7v4NfDGDKfA"
KA2_THUMBPRINT = "Hn1om9Wq54M24cWOBXfkv1x7m0QzV0jY6R3N8l2a7b8"
KA2_RAW = b"DGyRejmCefe7v4NfDGDKfA.Hn1om9Wq54M24cWOBXfkv1x7m0QzV0jY6R3N8l2a7b8"
KA2_DNS01 = "Avh9EiZDF83IDRVYyRq6V3_sWO5XFZtVaNTwnG_DrGo"


class KeyAuthorizationTest(unittest.TestCase):
    """Tests for the fixed-byte ACME key authorization flow."""

    def test_fixed_vectors(self) -> None:
        from josepy.jws import key_authorization, key_authorization_bytes

        assert key_authorization_bytes(KA_TOKEN, KA_THUMBPRINT) == KA_RAW
        assert key_authorization(KA_TOKEN, KA_THUMBPRINT) == KA_RAW
        assert key_authorization_bytes(KA2_TOKEN, KA2_THUMBPRINT) == KA2_RAW

    def test_fixed_vectors_match_standard_library(self) -> None:
        from josepy.jws import dns01_validation

        for token, thumbprint, raw in (
            (KA_TOKEN, KA_THUMBPRINT, KA_RAW),
            (KA2_TOKEN, KA2_THUMBPRINT, KA2_RAW),
        ):
            assert token.encode("ascii") + b"." + thumbprint.encode("ascii") == raw
            digest = hashlib.sha256(raw).digest()
            assert base64.urlsafe_b64encode(digest).rstrip(b"=") == (
                dns01_validation(token, thumbprint).encode("ascii")
            )

    def test_str_and_bytes_are_identical(self) -> None:
        from josepy.jws import key_authorization_bytes

        assert key_authorization_bytes(
            KA_TOKEN.encode(), KA_THUMBPRINT.encode()
        ) == key_authorization_bytes(KA_TOKEN, KA_THUMBPRINT)

    def test_exact_byte_layout(self) -> None:
        from josepy.jws import key_authorization_bytes

        raw = key_authorization_bytes(KA_TOKEN, KA_THUMBPRINT)
        token, thumbprint = raw.split(b".")
        assert token == KA_TOKEN.encode("ascii")
        assert thumbprint == KA_THUMBPRINT.encode("ascii")
        assert raw.count(b".") == 1
        assert not raw.endswith(b".")
        assert not raw.endswith(b"\n")
        assert b" " not in raw and b"\t" not in raw
        assert b"=" not in raw
        assert raw == raw.decode("ascii").encode("ascii")

    def test_dns01_fixed_vectors(self) -> None:
        from josepy.jws import dns01_validation, dns_challenge_response

        assert dns01_validation(KA_TOKEN, KA_THUMBPRINT) == KA_DNS01
        assert dns_challenge_response(KA2_TOKEN, KA2_THUMBPRINT) == KA2_DNS01
        assert dns01_validation(KA_TOKEN, KA_THUMBPRINT) == (
            dns_challenge_response(KA_TOKEN, KA_THUMBPRINT)
        )

    def test_dns01_has_no_padding_and_43_chars(self) -> None:
        from josepy.jws import dns01_validation

        value = dns01_validation(KA_TOKEN, KA_THUMBPRINT)
        assert len(value) == 43
        assert "=" not in value
        assert value.isascii()
        assert not value.endswith(".")
        assert "\n" not in value

    def test_http_and_dns_share_the_same_digest_input(self) -> None:
        from josepy.jws import dns01_validation, key_authorization

        raw = key_authorization(KA_TOKEN, KA_THUMBPRINT)
        expected = (
            base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode("ascii")
        )
        assert dns01_validation(KA_TOKEN, KA_THUMBPRINT) == expected

    def test_trailing_dot_is_rejected_not_trimmed(self) -> None:
        from josepy import errors
        from josepy.jws import key_authorization_bytes

        with pytest.raises(errors.KeyAuthorizationError):
            key_authorization_bytes(KA_TOKEN + ".", KA_THUMBPRINT)
        with pytest.raises(errors.KeyAuthorizationError):
            key_authorization_bytes(KA_TOKEN, KA_THUMBPRINT + ".")

    def test_newline_is_rejected(self) -> None:
        from josepy import errors
        from josepy.jws import key_authorization_bytes

        with pytest.raises(errors.KeyAuthorizationError):
            key_authorization_bytes(KA_TOKEN + "\n", KA_THUMBPRINT)
        with pytest.raises(errors.KeyAuthorizationError):
            key_authorization_bytes(KA_TOKEN, KA_THUMBPRINT + "\r\n")

    def test_padded_thumbprint_is_rejected(self) -> None:
        from josepy import errors
        from josepy.jws import key_authorization_bytes

        padded = KA_THUMBPRINT + "="
        with pytest.raises(errors.KeyAuthorizationError):
            key_authorization_bytes(KA_TOKEN, padded)
        assert b"=" not in key_authorization_bytes(KA_TOKEN, KA_THUMBPRINT)

    def test_case_is_preserved_byte_for_byte(self) -> None:
        from josepy.jws import key_authorization_bytes

        mixed = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_"
        raw = key_authorization_bytes(mixed, mixed)
        assert raw == mixed.encode("ascii") + b"." + mixed.encode("ascii")
        assert raw != raw.lower()

    def test_no_json_round_trip_or_normalization(self) -> None:
        from josepy.jws import key_authorization_bytes

        raw = key_authorization_bytes(KA_TOKEN, KA_THUMBPRINT)
        jsonized = json.dumps(raw.decode("ascii")).encode("ascii")
        assert jsonized != raw
        assert jsonized.startswith(b'"') and jsonized.endswith(b'"')
        spaced = json.dumps(
            {"token": KA_TOKEN, "thumbprint": KA_THUMBPRINT}, separators=(", ", ": ")
        ).encode("ascii")
        assert b" " in spaced and spaced != raw

    def test_invalid_token_is_rejected(self) -> None:
        from josepy import errors
        from josepy.jws import key_authorization_bytes

        for bad_token in (
            "",
            b"",
            "abc.def",
            b"abc.def",
            "abc=",
            "a b",
            "a\tb",
            "a/+",
            "\u00e9",
            b"\xff",
            "a\n",
            "a.",
            ".",
        ):
            with self.subTest(bad_token=bad_token):
                with pytest.raises(errors.KeyAuthorizationError):
                    key_authorization_bytes(bad_token, KA_THUMBPRINT)
        for bad_token in (None, 123):
            with self.subTest(bad_token=bad_token):
                with pytest.raises(TypeError):
                    key_authorization_bytes(bad_token, KA_THUMBPRINT)  # type: ignore[arg-type]

    def test_invalid_thumbprint_is_rejected(self) -> None:
        from josepy import errors
        from josepy.jws import key_authorization_bytes

        for bad_thumbprint in (
            "",
            b"",
            "abc.",
            "===",
            "a b",
            "\u00e9",
            b"\xff",
            "x\n",
        ):
            with self.subTest(bad_thumbprint=bad_thumbprint):
                with pytest.raises(errors.KeyAuthorizationError):
                    key_authorization_bytes(KA_TOKEN, bad_thumbprint)
        for bad_thumbprint in (None, 123):
            with self.subTest(bad_thumbprint=bad_thumbprint):
                with pytest.raises(TypeError):
                    key_authorization_bytes(KA_TOKEN, bad_thumbprint)  # type: ignore[arg-type]

    def test_overlong_input_is_rejected(self) -> None:
        from josepy import errors
        from josepy.jws import MAX_KEY_AUTHORIZATION_SIZE, key_authorization_bytes

        huge_token = "A" * MAX_KEY_AUTHORIZATION_SIZE
        with pytest.raises(errors.KeyAuthorizationError):
            key_authorization_bytes(huge_token, KA_THUMBPRINT)

        boundary = "A" * (MAX_KEY_AUTHORIZATION_SIZE - 1 - len(KA_THUMBPRINT))
        assert len(key_authorization_bytes(boundary, KA_THUMBPRINT)) == MAX_KEY_AUTHORIZATION_SIZE
        with pytest.raises(errors.KeyAuthorizationError):
            key_authorization_bytes(boundary + "A", KA_THUMBPRINT)

    def test_error_type_and_message(self) -> None:
        from josepy import errors
        from josepy.jws import key_authorization_bytes

        with pytest.raises(ValueError):
            key_authorization_bytes("", KA_THUMBPRINT)
        with pytest.raises(errors.SerializationError):
            key_authorization_bytes("", KA_THUMBPRINT)
        try:
            key_authorization_bytes("bad token", KA_THUMBPRINT)
        except errors.KeyAuthorizationError as error:
            message = str(error)
            assert "token" in message.lower()
            assert KA_THUMBPRINT not in message

    def test_aliases(self) -> None:
        from josepy import jws

        assert jws.http_challenge_response is jws.key_authorization
        assert jws.dns_challenge_response is jws.dns01_validation
        assert jws.http_challenge_response(KA_TOKEN, KA_THUMBPRINT) == jws.key_authorization_bytes(
            KA_TOKEN, KA_THUMBPRINT
        )


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
        with pytest.raises(TypeError):
            self.header1.__add__(self.header2)

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
