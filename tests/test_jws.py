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

from freezegun import freeze_time
from pytest import raises

from jwt.exceptions import JWSDecodeError
from jwt.jwk import jwk_from_dict
from jwt.jws import JWS

from .helper import load_testdata


class JWSTest(TestCase):

    def setUp(self):
        self.inst = JWS()
        self.key = jwk_from_dict(
            json.loads(load_testdata("rsa_privkey.json", "r"))
        )
        self.pubkey = jwk_from_dict(
            json.loads(load_testdata("rsa_pubkey.json", "r"))
        )

        self.message = (
            b'{"iss":"joe",\r\n'
            b' "exp":1300819380,\r\n'
            b' "http://example.com/is_root":true}'
        )
        self.compact_jws = (
            "eyJhbGciOiJSUzI1NiJ9"
            "."
            "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
            "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
            "."
            "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7"
            "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4"
            "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K"
            "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv"
            "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB"
            "p0igcN_IoypGlUPQGe77Rw"
        )

    def test_encode(self):
        compact_jws = self.inst.encode(self.message, self.key, alg="RS256")
        self.assertEqual(compact_jws, self.compact_jws)

    def test_decode(self):
        message = self.inst.decode(self.compact_jws, self.key)
        self.assertEqual(message, self.message)

    @freeze_time("2011-03-22 18:00:00", tz_offset=0)
    def test_decode_pubkey(self):
        message = self.inst.decode(self.compact_jws, self.pubkey)
        self.assertEqual(message, self.message)


class JWSKeyConstraintTest(TestCase):
    """JWK usage constraints are enforced before signature verification."""

    def setUp(self):
        self.inst = JWS()
        self.payload = b"protected payload"

        self.oct_key = jwk_from_dict(
            json.loads(load_testdata("oct.json", "r"))
        )
        self.oct_jws = self.inst.encode(
            self.payload, self.oct_key, alg="HS256"
        )

        self.rsa_key = jwk_from_dict(
            json.loads(load_testdata("rsa_privkey.json", "r"))
        )
        self.rsa_jws = self.inst.encode(
            self.payload, self.rsa_key, alg="RS256"
        )
        self.rsa_pubkey = jwk_from_dict(
            json.loads(load_testdata("rsa_pubkey.json", "r"))
        )

    def _oct_key_with(self, **overrides):
        key_json = json.loads(load_testdata("oct.json", "r"))
        key_json.update(overrides)
        return jwk_from_dict(key_json)

    def _rsa_pubkey_with(self, **overrides):
        key_json = json.loads(load_testdata("rsa_pubkey.json", "r"))
        key_json.update(overrides)
        return jwk_from_dict(key_json)

    def test_decode_with_matching_jwk_alg(self):
        key = self._oct_key_with(alg="HS256")
        self.assertEqual(self.inst.decode(self.oct_jws, key), self.payload)

    def test_decode_with_legacy_jwk_without_constraints(self):
        self.assertEqual(
            self.inst.decode(self.oct_jws, self.oct_key), self.payload
        )
        self.assertEqual(
            self.inst.decode(self.rsa_jws, self.rsa_pubkey), self.payload
        )

    def test_decode_rejects_conflicting_jwk_alg(self):
        key = self._oct_key_with(alg="HS512")
        with raises(JWSDecodeError, match="alg"):
            self.inst.decode(self.oct_jws, key)

    def test_decode_rejects_hmac_with_rsa_jwk_alg(self):
        # An RSA JWK selected for an HMAC-protected JWS conflicts on alg.
        key = self._rsa_pubkey_with(alg="RS256")
        with raises(JWSDecodeError, match="alg"):
            self.inst.decode(self.oct_jws, key)

    def test_decode_rejects_key_ops_without_verify(self):
        key = self._oct_key_with(key_ops=["sign"])
        with raises(JWSDecodeError, match="key_ops"):
            self.inst.decode(self.oct_jws, key)

    def test_decode_accepts_key_ops_including_verify(self):
        key = self._oct_key_with(key_ops=["sign", "verify"])
        self.assertEqual(self.inst.decode(self.oct_jws, key), self.payload)

    def test_decode_rejects_non_signature_use(self):
        key = self._oct_key_with(use="enc")
        with raises(JWSDecodeError, match="use"):
            self.inst.decode(self.oct_jws, key)

    def test_decode_accepts_signature_use(self):
        key = self._rsa_pubkey_with(use="sig")
        self.assertEqual(self.inst.decode(self.rsa_jws, key), self.payload)

    def test_decode_rejects_hmac_with_non_oct_key(self):
        # An RSA public key selected for an HMAC-protected JWS must be
        # rejected before any signature computation runs.
        with raises(JWSDecodeError, match="oct"):
            self.inst.decode(self.oct_jws, self.rsa_pubkey)

    def test_validation_runs_before_signature_verification(self):
        # A tampered JWS still surfaces the constraint error rather than a
        # generic signature failure when the JWK is not usable.
        key = self._oct_key_with(key_ops=["sign"])
        header_b64, payload_b64, signature_b64 = self.oct_jws.split(".")
        tampered = header_b64 + "." + payload_b64 + "." + signature_b64 + "A"
        with raises(JWSDecodeError, match="key_ops"):
            self.inst.decode(tampered, key)

    def test_skips_key_constraints_when_verify_disabled(self):
        key = self._oct_key_with(
            key_ops=["sign"], use="enc", alg="HS512"
        )
        self.assertEqual(
            self.inst.decode(self.oct_jws, key, do_verify=False),
            self.payload,
        )

