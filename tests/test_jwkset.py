# Copyright 2017 Gehirn Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
from unittest import TestCase

from pytest import raises

from jwt.exceptions import JWSDecodeError
from jwt.jwk import jwk_from_dict
from jwt.jwkset import JWKSet
from jwt.jws import JWS

from .helper import load_testdata


class JWKSetTest(TestCase):

    def setUp(self):
        self.inst = JWKSet()

        self.oct_json = json.loads(load_testdata("oct.json", "r"))
        self.inst.append(jwk_from_dict(self.oct_json))

        self.rsa_json = json.loads(load_testdata("rsa_privkey_full.json", "r"))
        self.rsa_pub_json = json.loads(load_testdata("rsa_pubkey.json", "r"))
        self.inst.append(jwk_from_dict(self.rsa_json))

    def test_filter_keys(self):
        self.assertEqual(
            [key.to_dict(public_only=True) for key in self.inst.filter_keys()],
            [self.oct_json, self.rsa_pub_json],
        )

        self.assertEqual(
            [
                key.to_dict(public_only=True)
                for key in self.inst.filter_keys(
                    kid="HMAC key used in JWS A.1 example"
                )
            ],
            [self.oct_json],
        )

        self.assertEqual(
            [
                key.to_dict(public_only=True)
                for key in self.inst.filter_keys(kty="RSA")
            ],
            [self.rsa_pub_json],
        )

        self.assertEqual(
            [
                key.to_dict(public_only=True)
                for key in self.inst.filter_keys(
                    kid="HMAC key used in JWS A.1 example", kty="oct"
                )
            ],
            [self.oct_json],
        )

    def test_to_dict(self):
        self.maxDiff = None
        self.assertEqual(
            self.inst.to_dict(public_only=True),
            {"keys": [self.oct_json, self.rsa_pub_json]},
        )

    def test_from_dict(self):
        inst = JWKSet.from_dict({"keys": [self.oct_json, self.rsa_pub_json]})
        self.assertEqual(inst[0].to_dict(public_only=True), self.oct_json)
        self.assertEqual(inst[1].to_dict(public_only=True), self.rsa_pub_json)


class JWKSetKeyConstraintTest(TestCase):
    """Constraints are enforced on the JWK selected via kid/kty."""

    def setUp(self):
        self.jws = JWS()
        self.payload = b"protected payload"

        self.oct_json = json.loads(load_testdata("oct.json", "r"))
        self.oct_key = jwk_from_dict(self.oct_json)
        self.oct_jws = self.jws.encode(
            self.payload, self.oct_key, alg="HS256"
        )

        self.rsa_priv = jwk_from_dict(
            json.loads(load_testdata("rsa_privkey.json", "r"))
        )
        self.rsa_jws = self.jws.encode(
            self.payload, self.rsa_priv, alg="RS256"
        )

    def _jwkset(self, *key_dicts):
        return JWKSet([jwk_from_dict(dct) for dct in key_dicts])

    def test_selected_key_by_kid_passes_when_unconstrained(self):
        jwkset = self._jwkset(self.oct_json)
        (selected,) = jwkset.filter_keys(
            kid="HMAC key used in JWS A.1 example"
        )
        self.assertEqual(
            self.jws.decode(self.oct_jws, selected), self.payload
        )

    def test_selected_key_by_kty_rejects_alg_confusion(self):
        # An oct key pinned to HS512 is selected but the JWS uses HS256.
        confused = dict(self.oct_json, alg="HS512")
        jwkset = self._jwkset(confused)
        (selected,) = jwkset.filter_keys(kty="oct")
        with raises(JWSDecodeError, match="alg"):
            self.jws.decode(self.oct_jws, selected)

    def test_selected_key_rejects_missing_verify_key_op(self):
        no_verify = dict(self.oct_json, key_ops=["sign"])
        jwkset = self._jwkset(no_verify)
        (selected,) = jwkset.filter_keys(kty="oct")
        with raises(JWSDecodeError, match="key_ops"):
            self.jws.decode(self.oct_jws, selected)

    def test_selected_key_rejects_enc_use(self):
        enc_only = dict(self.oct_json, use="enc")
        jwkset = self._jwkset(enc_only)
        (selected,) = jwkset.filter_keys(kty="oct")
        with raises(JWSDecodeError, match="use"):
            self.jws.decode(self.oct_jws, selected)

    def test_selected_rsa_key_rejects_hmac_kty_mismatch(self):
        # Selecting an RSA JWK (by kty) for an HMAC JWS must fail the
        # kty check before signature verification.
        rsa_pub_json = json.loads(load_testdata("rsa_pubkey.json", "r"))
        jwkset = self._jwkset(rsa_pub_json)
        (selected,) = jwkset.filter_keys(kty="RSA")
        with raises(JWSDecodeError, match="oct"):
            self.jws.decode(self.oct_jws, selected)

    def test_selected_rsa_key_verifies_rsa_jws_with_sig_use(self):
        rsa_pub_json = dict(
            json.loads(load_testdata("rsa_pubkey.json", "r")),
            use="sig", key_ops=["verify"], alg="RS256"
        )
        jwkset = self._jwkset(rsa_pub_json)
        (selected,) = jwkset.filter_keys(kty="RSA")
        self.assertEqual(
            self.jws.decode(self.rsa_jws, selected), self.payload
        )

