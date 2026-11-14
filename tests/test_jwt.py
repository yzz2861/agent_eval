import base64
import json
from datetime import datetime, timedelta

try:
    from datetime import UTC  # Preferred in Python 3.13+
except ImportError:
    from datetime import timezone  # Preferred in Python 3.12 and below

    UTC = timezone.utc

import pytest

from jose import jws, jwt
from jose.exceptions import JWTError
from jose.exceptions import JWTClaimsError
from jose.jwt import _nested_token_digest
from tests.test_jws import rsa_private_key, rsa_public_key


@pytest.fixture
def claims():
    claims = {"a": "b"}
    return claims


@pytest.fixture
def key():
    return "secret"


@pytest.fixture
def headers():
    headers = {
        "kid": "my-key-id",
    }
    return headers


class TestJWT:
    def test_no_alg(self, claims, key):
        token = jwt.encode(claims, key, algorithm="HS384")
        b64header, b64payload, b64signature = token.split(".")
        header_json = base64.urlsafe_b64decode(b64header.encode("utf-8"))
        header = json.loads(header_json.decode("utf-8"))
        del header["alg"]
        bad_header_json_bytes = json.dumps(header).encode("utf-8")
        bad_b64header_bytes = base64.urlsafe_b64encode(bad_header_json_bytes)
        bad_b64header_bytes_short = bad_b64header_bytes.replace(b"=", b"")
        bad_b64header = bad_b64header_bytes.decode("utf-8")
        bad_token = ".".join([bad_b64header, b64payload, b64signature])
        with pytest.raises(JWTError):
            jwt.decode(token=bad_token, key=key, algorithms=[])

    @pytest.mark.parametrize(
        "key, token",
        [
            (
                "1234567890",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidGVzdCJ9.aNBlulVhiYSCzvsh1rTzXZC2eWJmNrMBjINT-0wQz4k",
            ),
            (
                "123456789.0",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidGVzdCJ9.D8WLFPMi3yKgua2jm3BKThFsParXpgxhIbsUc39zJDw",
            ),
        ],
    )
    def test_numeric_key(self, key, token):
        token_info = jwt.decode(token, key)
        assert token_info == {"name": "test"}

    def test_invalid_claims_json(self):
        old_jws_verify = jws.verify
        try:
            token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8"

            def return_invalid_json(token, key, algorithms, verify=True):
                return b'["a", "b"}'

            jws.verify = return_invalid_json

            with pytest.raises(JWTError, match="Invalid payload string: "):
                jwt.decode(token, "secret", ["HS256"])
        finally:
            jws.verify = old_jws_verify

    def test_invalid_claims(self):
        old_jws_verify = jws.verify
        try:
            token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8"

            def return_encoded_array(token, key, algorithms, verify=True):
                return b'["a","b"]'

            jws.verify = return_encoded_array

            with pytest.raises(JWTError, match="Invalid payload string: must be a json object"):
                jwt.decode(token, "secret", ["HS256"])
        finally:
            jws.verify = old_jws_verify

    def test_non_default_alg(self, claims, key):
        encoded = jwt.encode(claims, key, algorithm="HS384")
        decoded = jwt.decode(encoded, key, algorithms="HS384")
        assert claims == decoded

    def test_non_default_alg_positional_bwcompat(self, claims, key):
        encoded = jwt.encode(claims, key, "HS384")
        decoded = jwt.decode(encoded, key, "HS384")
        assert claims == decoded

    def test_no_alg_default_headers(self, claims, key, headers):
        token = jwt.encode(claims, key, algorithm="HS384")
        b64header, b64payload, b64signature = token.split(".")
        bad_token = b64header + "." + b64payload
        with pytest.raises(JWTError):
            jwt.get_unverified_headers(bad_token)

    def test_non_default_headers(self, claims, key, headers):
        encoded = jwt.encode(claims, key, headers=headers)
        decoded = jwt.decode(encoded, key)
        assert claims == decoded
        all_headers = jwt.get_unverified_headers(encoded)
        for k, v in headers.items():
            assert all_headers[k] == v

    def test_deterministic_headers(self):
        from collections import OrderedDict

        from jose.utils import base64url_decode

        claims = {"a": "b"}
        key = "secret"

        headers1 = OrderedDict(
            (
                ("kid", "my-key-id"),
                ("another_key", "another_value"),
            )
        )
        encoded1 = jwt.encode(claims, key, algorithm="HS256", headers=headers1)
        encoded_headers1 = encoded1.split(".", 1)[0]

        headers2 = OrderedDict(
            (
                ("another_key", "another_value"),
                ("kid", "my-key-id"),
            )
        )
        encoded2 = jwt.encode(claims, key, algorithm="HS256", headers=headers2)
        encoded_headers2 = encoded2.split(".", 1)[0]

        assert encoded_headers1 == encoded_headers2

        # manually decode header to compare it to known good
        decoded_headers1 = base64url_decode(encoded_headers1.encode("utf-8"))
        assert decoded_headers1 == b"""{"alg":"HS256","another_key":"another_value","kid":"my-key-id","typ":"JWT"}"""

    def test_encode(self, claims, key):
        expected = (
            ("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" ".eyJhIjoiYiJ9" ".xNtk2S0CNbCBZX_f67pFgGRugaP1xi2ICfet3nwOSxw"),
            ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ".eyJhIjoiYiJ9" ".jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8"),
        )

        encoded = jwt.encode(claims, key)

        assert encoded in expected

    def test_decode(self, claims, key):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ".eyJhIjoiYiJ9" ".jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8"

        decoded = jwt.decode(token, key)

        assert decoded == claims

    @pytest.mark.parametrize(
        "key",
        [
            b"key",
            "key",
        ],
    )
    def test_round_trip_with_different_key_types(self, key):
        token = jwt.encode({"testkey": "testvalue"}, key, algorithm="HS256")
        verified_data = jwt.decode(token, key, algorithms=["HS256"])
        assert "testkey" in verified_data.keys()
        assert verified_data["testkey"] == "testvalue"

    def test_leeway_is_int(self):
        pass

    def test_leeway_is_timedelta(self, claims, key):
        nbf = datetime.now(UTC) + timedelta(seconds=5)
        leeway = timedelta(seconds=10)

        claims = {
            "nbf": nbf,
        }

        options = {"leeway": leeway}

        token = jwt.encode(claims, key)
        jwt.decode(token, key, options=options)

    def test_iat_not_int(self, key):
        claims = {"iat": "test"}

        token = jwt.encode(claims, key)

        with pytest.raises(JWTError):
            jwt.decode(token, key)

    def test_nbf_not_int(self, key):
        claims = {"nbf": "test"}

        token = jwt.encode(claims, key)

        with pytest.raises(JWTError):
            jwt.decode(token, key)

    def test_nbf_datetime(self, key):
        nbf = datetime.now(UTC) - timedelta(seconds=5)

        claims = {"nbf": nbf}

        token = jwt.encode(claims, key)
        jwt.decode(token, key)

    def test_nbf_with_leeway(self, key):
        nbf = datetime.now(UTC) + timedelta(seconds=5)

        claims = {
            "nbf": nbf,
        }

        options = {"leeway": 10}

        token = jwt.encode(claims, key)
        jwt.decode(token, key, options=options)

    def test_nbf_in_future(self, key):
        nbf = datetime.now(UTC) + timedelta(seconds=5)

        claims = {"nbf": nbf}

        token = jwt.encode(claims, key)

        with pytest.raises(JWTError):
            jwt.decode(token, key)

    def test_nbf_skip(self, key):
        nbf = datetime.now(UTC) + timedelta(seconds=5)

        claims = {"nbf": nbf}

        token = jwt.encode(claims, key)

        with pytest.raises(JWTError):
            jwt.decode(token, key)

        options = {"verify_nbf": False}

        jwt.decode(token, key, options=options)

    def test_exp_not_int(self, key):
        claims = {"exp": "test"}

        token = jwt.encode(claims, key)

        with pytest.raises(JWTError):
            jwt.decode(token, key)

    def test_exp_datetime(self, key):
        exp = datetime.now(UTC) + timedelta(seconds=5)

        claims = {"exp": exp}

        token = jwt.encode(claims, key)
        jwt.decode(token, key)

    def test_exp_with_leeway(self, key):
        exp = datetime.now(UTC) - timedelta(seconds=5)

        claims = {
            "exp": exp,
        }

        options = {"leeway": 10}

        token = jwt.encode(claims, key)
        jwt.decode(token, key, options=options)

    def test_exp_in_past(self, key):
        exp = datetime.now(UTC) - timedelta(seconds=5)

        claims = {"exp": exp}

        token = jwt.encode(claims, key)

        with pytest.raises(JWTError):
            jwt.decode(token, key)

    def test_exp_skip(self, key):
        exp = datetime.now(UTC) - timedelta(seconds=5)

        claims = {"exp": exp}

        token = jwt.encode(claims, key)

        with pytest.raises(JWTError):
            jwt.decode(token, key)

        options = {"verify_exp": False}

        jwt.decode(token, key, options=options)

    def test_aud_string(self, key):
        aud = "audience"

        claims = {"aud": aud}

        token = jwt.encode(claims, key)
        jwt.decode(token, key, audience=aud)

    def test_aud_list(self, key):
        aud = "audience"

        claims = {"aud": [aud]}

        token = jwt.encode(claims, key)
        jwt.decode(token, key, audience=aud)

    def test_aud_list_multiple(self, key):
        aud = "audience"

        claims = {"aud": [aud, "another"]}

        token = jwt.encode(claims, key)
        jwt.decode(token, key, audience=aud)

    def test_aud_list_is_strings(self, key):
        aud = "audience"

        claims = {"aud": [aud, 1]}

        token = jwt.encode(claims, key)
        with pytest.raises(JWTError):
            jwt.decode(token, key, audience=aud)

    def test_aud_case_sensitive(self, key):
        aud = "audience"

        claims = {"aud": [aud]}

        token = jwt.encode(claims, key)
        with pytest.raises(JWTError):
            jwt.decode(token, key, audience="AUDIENCE")

    def test_aud_empty_claim(self, claims, key):
        aud = "audience"

        token = jwt.encode(claims, key)
        jwt.decode(token, key, audience=aud)

    def test_aud_not_string_or_list(self, key):
        aud = 1

        claims = {"aud": aud}

        token = jwt.encode(claims, key)
        with pytest.raises(JWTError):
            jwt.decode(token, key)

    def test_aud_given_number(self, key):
        aud = "audience"

        claims = {"aud": aud}

        token = jwt.encode(claims, key)
        with pytest.raises(JWTError):
            jwt.decode(token, key, audience=1)

    def test_iss_string(self, key):
        iss = "issuer"

        claims = {"iss": iss}

        token = jwt.encode(claims, key)
        jwt.decode(token, key, issuer=iss)

    def test_iss_list(self, key):
        iss = "issuer"

        claims = {"iss": iss}

        token = jwt.encode(claims, key)
        jwt.decode(token, key, issuer=["https://issuer", "issuer"])

    def test_iss_tuple(self, key):
        iss = "issuer"

        claims = {"iss": iss}

        token = jwt.encode(claims, key)
        jwt.decode(token, key, issuer=("https://issuer", "issuer"))

    def test_iss_invalid(self, key):
        iss = "issuer"

        claims = {"iss": iss}

        token = jwt.encode(claims, key)
        with pytest.raises(JWTError):
            jwt.decode(token, key, issuer="another")

    def test_sub_string(self, key):
        sub = "subject"

        claims = {"sub": sub}

        token = jwt.encode(claims, key)
        jwt.decode(token, key)

    def test_sub_invalid(self, key):
        sub = 1

        claims = {"sub": sub}

        token = jwt.encode(claims, key)
        with pytest.raises(JWTError):
            jwt.decode(token, key)

    def test_sub_correct(self, key):
        sub = "subject"

        claims = {"sub": sub}

        token = jwt.encode(claims, key)
        jwt.decode(token, key, subject=sub)

    def test_sub_incorrect(self, key):
        sub = "subject"

        claims = {"sub": sub}

        token = jwt.encode(claims, key)
        with pytest.raises(JWTError):
            jwt.decode(token, key, subject="another")

    def test_jti_string(self, key):
        jti = "JWT ID"

        claims = {"jti": jti}

        token = jwt.encode(claims, key)
        jwt.decode(token, key)

    def test_jti_invalid(self, key):
        jti = 1

        claims = {"jti": jti}

        token = jwt.encode(claims, key)
        with pytest.raises(JWTError):
            jwt.decode(token, key)

    def test_at_hash(self, claims, key):
        access_token = "<ACCESS_TOKEN>"
        token = jwt.encode(claims, key, access_token=access_token)
        payload = jwt.decode(token, key, access_token=access_token)
        assert "at_hash" in payload

    def test_at_hash_invalid(self, claims, key):
        token = jwt.encode(claims, key, access_token="<ACCESS_TOKEN>")
        with pytest.raises(JWTError):
            jwt.decode(token, key, access_token="<OTHER_TOKEN>")

    def test_at_hash_missing_access_token(self, claims, key):
        token = jwt.encode(claims, key, access_token="<ACCESS_TOKEN>")
        with pytest.raises(JWTError):
            jwt.decode(token, key)

    def test_at_hash_missing_claim(self, claims, key):
        token = jwt.encode(claims, key)
        payload = jwt.decode(token, key, access_token="<ACCESS_TOKEN>")
        assert "at_hash" not in payload

    def test_at_hash_unable_to_calculate(self, claims, key):
        token = jwt.encode(claims, key, access_token="<ACCESS_TOKEN>")
        with pytest.raises(JWTError):
            jwt.decode(token, key, access_token="\xe2")

    def test_bad_claims(self):
        bad_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.iOJ5SiNfaNO_pa2J4Umtb3b3zmk5C18-mhTCVNsjnck"
        with pytest.raises(JWTError):
            jwt.get_unverified_claims(bad_token)

    def test_unverified_claims_string(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aW52YWxpZCBjbGFpbQ.iOJ5SiNfaNO_pa2J4Umtb3b3zmk5C18-mhTCVNsjnck"
        with pytest.raises(JWTError):
            jwt.get_unverified_claims(token)

    def test_unverified_claims_list(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.WyJpbnZhbGlkIiwgImNsYWltcyJd.nZvw_Rt1FfUPb5OiVbrSYZGtWSE5c-gdJ6nQnTTBkYo"
        with pytest.raises(JWTError):
            jwt.get_unverified_claims(token)

    def test_unverified_claims_object(self, claims, key):
        token = jwt.encode(claims, key)
        assert jwt.get_unverified_claims(token) == claims

    @pytest.mark.parametrize(
        "claim,value",
        [
            ("aud", "aud"),
            ("ait", "ait"),
            ("exp", lambda: datetime.now(UTC) + timedelta(seconds=3600)),
            ("nbf", lambda: datetime.now(UTC) - timedelta(seconds=5)),
            ("iss", "iss"),
            ("sub", "sub"),
            ("jti", "jti"),
        ],
    )
    def test_require(self, claims, key, claim, value):
        if callable(value):
            value = value()
        options = {"require_" + claim: True, "verify_" + claim: False}

        token = jwt.encode(claims, key)
        with pytest.raises(JWTError):
            jwt.decode(token, key, options=options, audience=str(value))

        new_claims = dict(claims)
        new_claims[claim] = value
        token = jwt.encode(new_claims, key)
        jwt.decode(token, key, options=options, audience=str(value))


def _nest(payload, key, algorithm="HS256", cty="JWT", headers=None):
    extra = {}
    if cty is not None:
        extra["cty"] = cty
    if headers:
        extra.update(headers)
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return jws.sign(payload, key, headers=extra, algorithm=algorithm)


def _build_nested(depth, keys, claims, algorithm="HS256"):
    token = jwt.encode(claims, keys[depth - 1], algorithm=algorithm)
    for i in range(depth - 2, -1, -1):
        token = _nest(token, keys[i], algorithm=algorithm)
    return token


class TestNestedJWT:
    @pytest.fixture
    def claims(self):
        return {"sub": "alice", "aud": "message-bus", "iss": "issuer"}

    def test_depths_1_to_5(self, claims):
        for depth in range(1, 6):
            keys = ["secret-%d" % i for i in range(depth)]
            token = _build_nested(depth, keys, claims)
            result = jwt.decode_nested(
                token,
                keys,
                algorithms=["HS256"],
                audience="message-bus",
                issuer="issuer",
                max_depth=5,
            )
            assert result["depth"] == depth
            assert result["claims"] == claims
            assert [layer["algorithm"] for layer in result["layers"]] == ["HS256"] * depth
            assert [layer["index"] for layer in result["layers"]] == list(range(depth))
            assert result["layers"][-1]["claims"] == claims
            assert result["layers"][-1]["nested"] is False
            for layer in result["layers"][:-1]:
                assert layer["nested"] is True
                assert layer["claims"] is None
                assert layer["header"]["cty"] == "JWT"
                assert layer["header"]["alg"] == "HS256"

    def test_verification_count_matches_depth(self, claims, monkeypatch):
        keys = ["k0", "k1", "k2", "k3"]
        token = _build_nested(4, keys, claims)
        calls = []
        original_verify = jws.verify

        def counting_verify(token, key, algorithms, verify=True):
            calls.append(token)
            return original_verify(token, key, algorithms, verify=verify)

        monkeypatch.setattr(jws, "verify", counting_verify)
        jwt.decode_nested(token, keys, algorithms=["HS256"], audience="message-bus", issuer="issuer")
        assert len(calls) == 4

    def test_single_layer_matches_decode(self, claims):
        token = jwt.encode(claims, "secret", algorithm="HS256")
        expected = jwt.decode(token, "secret", algorithms=["HS256"], audience="message-bus", issuer="issuer")
        result = jwt.decode_nested(
            token,
            "secret",
            algorithms=["HS256"],
            audience="message-bus",
            issuer="issuer",
        )
        assert result["claims"] == expected
        assert result["depth"] == 1
        assert result["layers"][0]["nested"] is False

    def test_missing_cty_treated_as_terminal(self, claims):
        inner = jwt.encode(claims, "k1")
        outer = _nest(inner, "k0", cty=None)
        with pytest.raises(JWTError, match="Invalid payload string"):
            jwt.decode_nested(outer, ["k0", "k1"], algorithms=["HS256"])

    @pytest.mark.parametrize("cty", ["JWE", "json", "JWT2", "JWT JWT", 123, ["JWT"]])
    def test_wrong_cty_rejected(self, claims, cty):
        inner = jwt.encode(claims, "k1")
        outer = _nest(inner, "k0", cty=cty)
        with pytest.raises(JWTError, match="cty"):
            jwt.decode_nested(outer, ["k0", "k1"], algorithms=["HS256"])

    @pytest.mark.parametrize("cty", ["JWT", "jwt", "Jwt", "application/jwt", "Application/JWT", " JWT "])
    def test_cty_value_forms_accepted(self, claims, cty):
        inner = jwt.encode(claims, "k1")
        outer = _nest(inner, "k0", cty=cty)
        result = jwt.decode_nested(
            outer,
            ["k0", "k1"],
            algorithms=["HS256"],
            audience="message-bus",
            issuer="issuer",
        )
        assert result["claims"] == claims
        assert result["depth"] == 2

    def test_max_depth_exceeded(self, claims):
        keys = ["k0", "k1", "k2"]
        token = _build_nested(3, keys, claims)
        with pytest.raises(JWTError, match="maximum depth"):
            jwt.decode_nested(token, keys, algorithms=["HS256"], max_depth=2)

    @pytest.mark.parametrize("max_depth", [0, -1])
    def test_invalid_max_depth(self, claims, max_depth):
        token = jwt.encode(claims, "k")
        with pytest.raises(JWTError, match="max_depth"):
            jwt.decode_nested(token, "k", max_depth=max_depth)

    def test_self_cycle_detected(self, claims, monkeypatch):
        token = _nest(jwt.encode(claims, "k1"), "k0")

        def looping_verify(token_arg, key, algorithms, verify=True):
            return token.encode("utf-8")

        monkeypatch.setattr(jws, "verify", looping_verify)
        with pytest.raises(JWTError, match="cycle"):
            jwt.decode_nested(token, "k0", algorithms=["HS256"], max_depth=100)

    def test_two_token_cycle_detected(self, claims, monkeypatch):
        b = _nest(jwt.encode(claims, "k1"), "k1")
        a = _nest(b, "k0")
        payloads = {a: b.encode("utf-8"), b: a.encode("utf-8")}
        monkeypatch.setattr(jws, "verify", lambda t, k, alg, verify=True: payloads[t])
        with pytest.raises(JWTError, match="cycle"):
            jwt.decode_nested(a, "k0", algorithms=["HS256"], max_depth=100)

    def test_alg_downgrade_rejected(self, claims, monkeypatch):
        # Attacker downgrades the inner layer from RS256 to HS256; the
        # per-layer algorithm policy must reject it even though the inner
        # signature itself verifies against the presented key.
        inner = jwt.encode(claims, "hmac-secret", algorithm="HS256")
        outer = _nest(inner, rsa_private_key, algorithm="RS256")
        calls = []
        original_verify = jws.verify

        def counting_verify(token, key, algorithms, verify=True):
            calls.append(token)
            return original_verify(token, key, algorithms, verify=verify)

        monkeypatch.setattr(jws, "verify", counting_verify)
        with pytest.raises(JWTError, match="alg value is not allowed"):
            jwt.decode_nested(
                outer,
                [rsa_public_key, "hmac-secret"],
                layer_algorithms={0: ["RS256"], 1: ["RS256"]},
            )
        assert len(calls) == 2

    def test_mixed_algorithms_per_layer(self, claims):
        inner = jwt.encode(claims, "inner-secret", algorithm="HS256")
        outer = _nest(inner, rsa_private_key, algorithm="RS256")
        result = jwt.decode_nested(
            outer,
            [rsa_public_key, "inner-secret"],
            layer_algorithms={0: ["RS256"], 1: ["HS256"]},
            audience="message-bus",
            issuer="issuer",
        )
        assert [layer["algorithm"] for layer in result["layers"]] == ["RS256", "HS256"]
        assert result["claims"] == claims

    def test_outer_key_not_trusted_for_inner_layer(self, claims):
        inner = jwt.encode(claims, "inner-secret")
        outer = _nest(inner, "outer-secret")
        with pytest.raises(JWTError, match="Signature verification failed"):
            jwt.decode_nested(outer, "outer-secret", algorithms=["HS256"])
        result = jwt.decode_nested(
            outer,
            ["outer-secret", "inner-secret"],
            algorithms=["HS256"],
            audience="message-bus",
            issuer="issuer",
        )
        assert result["claims"] == claims

    def test_callable_key_resolver(self, claims):
        keys = ["k0", "k1"]
        token = _build_nested(2, keys, claims)
        seen = []

        def resolver(index, header):
            seen.append((index, header["alg"]))
            return keys[index]

        result = jwt.decode_nested(
            token,
            resolver,
            algorithms=["HS256"],
            audience="message-bus",
            issuer="issuer",
        )
        assert result["claims"] == claims
        assert seen == [(0, "HS256"), (1, "HS256")]

    def test_missing_layer_key(self, claims):
        token = _build_nested(3, ["k0", "k1", "k2"], claims)
        with pytest.raises(JWTError, match="No key configured"):
            jwt.decode_nested(token, ["k0"], algorithms=["HS256"], max_depth=3)

    def test_audience_and_issuer_enforced(self, claims):
        token = _build_nested(2, ["k0", "k1"], claims)
        with pytest.raises(JWTClaimsError):
            jwt.decode_nested(token, ["k0", "k1"], algorithms=["HS256"], audience="someone-else")
        with pytest.raises(JWTClaimsError):
            jwt.decode_nested(token, ["k0", "k1"], algorithms=["HS256"], issuer="other-issuer")

    def test_aud_iss_cannot_be_disabled_via_options(self, claims):
        token = _build_nested(2, ["k0", "k1"], claims)
        with pytest.raises(JWTClaimsError):
            jwt.decode_nested(
                token,
                ["k0", "k1"],
                algorithms=["HS256"],
                audience="someone-else",
                options={"verify_aud": False},
            )
        with pytest.raises(JWTClaimsError):
            jwt.decode_nested(
                token,
                ["k0", "k1"],
                algorithms=["HS256"],
                issuer="other-issuer",
                options={"verify_iss": False},
            )

    @pytest.mark.parametrize(
        "header",
        [
            {"jku": "https://evil.example/jwks.json"},
            {"x5u": "https://evil.example/cert.pem"},
        ],
    )
    def test_inner_jku_x5u_rejected(self, claims, header):
        inner = jwt.encode(claims, "k1", headers=header)
        outer = _nest(inner, "k0")
        with pytest.raises(JWTError, match="never fetched"):
            jwt.decode_nested(outer, ["k0", "k1"], algorithms=["HS256"])

    def test_byte_budget_single_layer(self):
        claims = {"data": "x" * 4096}
        token = jwt.encode(claims, "k")
        with pytest.raises(JWTError, match="byte budget"):
            jwt.decode_nested(token, "k", algorithms=["HS256"], max_bytes=1024)
        result = jwt.decode_nested(token, "k", algorithms=["HS256"], max_bytes=len(token))
        assert result["claims"] == claims

    def test_byte_budget_accumulates_across_layers(self):
        claims = {"data": "x" * 1024}
        t1 = jwt.encode(claims, "k2")
        t2 = _nest(t1, "k1")
        t3 = _nest(t2, "k0")
        budget = len(t1) + len(t2) + len(t3)
        with pytest.raises(JWTError, match="byte budget"):
            jwt.decode_nested(t3, ["k0", "k1", "k2"], algorithms=["HS256"], max_depth=3, max_bytes=budget - 1)
        result = jwt.decode_nested(t3, ["k0", "k1", "k2"], algorithms=["HS256"], max_depth=3, max_bytes=budget)
        assert result["depth"] == 3

    @pytest.mark.parametrize("max_bytes", [0, -1])
    def test_invalid_max_bytes(self, claims, max_bytes):
        token = jwt.encode(claims, "k")
        with pytest.raises(JWTError, match="max_bytes"):
            jwt.decode_nested(token, "k", max_bytes=max_bytes)

    def test_base64_reencoded_token_stable_error(self, claims):
        token = jwt.encode(claims, "secret")
        header_segment, payload_segment, signature_segment = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(header_segment + "==").decode("utf-8"))
        # Re-serializing the header changes the signing input: the token is
        # rejected deterministically by both decode() and decode_nested().
        reencoded_header = base64.urlsafe_b64encode(json.dumps(header, indent=2).encode("utf-8"))
        reencoded_header = reencoded_header.rstrip(b"=").decode("utf-8")
        reencoded = ".".join([reencoded_header, payload_segment, signature_segment])
        with pytest.raises(JWTError):
            jwt.decode(reencoded, "secret", algorithms=["HS256"])
        with pytest.raises(JWTError):
            jwt.decode_nested(reencoded, "secret", algorithms=["HS256"])
        padded = ".".join([header_segment + "=", payload_segment, signature_segment])
        with pytest.raises(JWTError):
            jwt.decode_nested(padded, "secret", algorithms=["HS256"])

    def test_nested_token_digest_canonical(self):
        token = jwt.encode({"a": "b"}, "secret")
        padded = ".".join(segment + "=" * (-len(segment) % 4) for segment in token.split("."))
        assert _nested_token_digest(token.encode("utf-8")) == _nested_token_digest(padded.encode("utf-8"))
        other = jwt.encode({"a": "c"}, "secret")
        assert _nested_token_digest(token.encode("utf-8")) != _nested_token_digest(other.encode("utf-8"))

    def test_deep_nesting_is_iterative(self, monkeypatch):
        depth = 2000
        tokens = [
            "{0}.{1}.{2}".format(
                base64.urlsafe_b64encode(b'{"alg": "HS256"}').rstrip(b"=").decode("ascii"),
                base64.urlsafe_b64encode(str(i).encode("utf-8")).rstrip(b"=").decode("ascii"),
                base64.urlsafe_b64encode(b"sig" + str(i).encode("utf-8")).rstrip(b"=").decode("ascii"),
            )
            for i in range(depth)
        ]
        headers = {}
        payloads = {}
        for i, token in enumerate(tokens):
            headers[token] = {"alg": "HS256", "typ": "JWT"}
            if i < depth - 1:
                headers[token]["cty"] = "JWT"
                payloads[token] = tokens[i + 1].encode("utf-8")
            else:
                payloads[token] = b'{"a": "b"}'
        calls = []

        def fake_verify(token, key, algorithms, verify=True):
            calls.append(token)
            return payloads[token]

        monkeypatch.setattr(jws, "verify", fake_verify)
        monkeypatch.setattr(jws, "get_unverified_headers", lambda token: headers[token])
        result = jwt.decode_nested(tokens[0], "k", algorithms=["HS256"], max_depth=depth, max_bytes=10**6)
        assert result["depth"] == depth
        assert result["claims"] == {"a": "b"}
        assert len(calls) == depth
