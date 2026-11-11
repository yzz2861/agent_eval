import json
from unittest import TestCase

from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.exceptions import InvalidJSONStructure
from webauthn.helpers.parse_client_data_json import parse_client_data_json
from webauthn.helpers.structs import ClientDataType, TokenBindingStatus


class TestParseClientDataJSON(TestCase):
    def test_can_parse_attestation_client_data(self):
        client_data_bytes = base64url_to_bytes(
            "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidkZHdmt6UFZzQ0JKOXVLMWxHT0ZucGl4NDF5clB1eFBITFlMdGJRckVYNjNqSlplYXNaVlBfY3lZZkExYktmelJJbk1vcG05VUJtNkNvS2FfakZ0MWciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
        )
        expected_challenge = base64url_to_bytes(
            "vFGvkzPVsCBJ9uK1lGOFnpix41yrPuxPHLYLtbQrEX63jJZeasZVP_cyYfA1bKfzRInMopm9UBm6CoKa_jFt1g"
        )

        output = parse_client_data_json(client_data_bytes)

        assert output.type == "webauthn.create"
        assert output.challenge == expected_challenge
        assert output.origin == "http://localhost:5000"
        assert output.cross_origin is False
        assert output.token_binding is None

    def test_raises_exception_on_bad_json(self):
        client_data_bytes = b"not_real-JS0N"

        with self.assertRaisesRegex(
            InvalidJSONStructure,
            "Unable to decode",
        ):
            parse_client_data_json(client_data_bytes)

    def test_requires_type(self):
        client_data_str = json.dumps(
            {
                "challenge": bytes_to_base64url(b"challenge"),
                "origin": "http://localhost:5000",
            }
        )
        client_data_bytes = client_data_str.encode("utf-8")

        with self.assertRaisesRegex(
            InvalidJSONStructure,
            'missing required property "type"',
        ):
            parse_client_data_json(client_data_bytes)

    def test_requires_challenge(self):
        client_data_str = json.dumps(
            {"type": "webauthn.create", "origin": "http://localhost:5000"}
        )
        client_data_bytes = client_data_str.encode("utf-8")

        with self.assertRaisesRegex(
            InvalidJSONStructure,
            'missing required property "challenge"',
        ):
            parse_client_data_json(client_data_bytes)

    def test_requires_origin(self):
        client_data_str = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": bytes_to_base64url(b"challenge"),
            }
        )
        client_data_bytes = client_data_str.encode("utf-8")

        with self.assertRaisesRegex(
            InvalidJSONStructure,
            'missing required property "origin"',
        ):
            parse_client_data_json(client_data_bytes)

    def test_omit_cross_origin_if_not_present(self):
        client_data_str = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": bytes_to_base64url(b"challenge"),
                "origin": "http://localhost:5000",
            }
        )
        client_data_bytes = client_data_str.encode("utf-8")

        output = parse_client_data_json(client_data_bytes)

        assert output.cross_origin is None

    def test_omit_token_binding_if_not_present(self):
        client_data_str = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": bytes_to_base64url(b"challenge"),
                "origin": "http://localhost:5000",
            }
        )
        client_data_bytes = client_data_str.encode("utf-8")

        output = parse_client_data_json(client_data_bytes)

        assert output.token_binding is None

    def test_include_token_binding_when_present(self):
        client_data_str = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": bytes_to_base64url(b"challenge"),
                "origin": "http://localhost:5000",
                "tokenBinding": {"status": "present", "id": "someidhere"},
            }
        )
        client_data_bytes = client_data_str.encode("utf-8")

        output = parse_client_data_json(client_data_bytes)

        assert output.token_binding
        assert output.token_binding.status == TokenBindingStatus.PRESENT
        assert output.token_binding.id == "someidhere"

    def test_require_status_in_token_binding_when_present(self):
        client_data_str = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": bytes_to_base64url(b"challenge"),
                "origin": "http://localhost:5000",
                "tokenBinding": {"id": "someidhere"},
            }
        )
        client_data_bytes = client_data_str.encode("utf-8")

        with self.assertRaises(InvalidJSONStructure) as context:
            parse_client_data_json(client_data_bytes)

        assert 'missing required property "status"' in str(context.exception)

    def test_omit_id_when_missing_from_token_binding(self):
        client_data_str = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": bytes_to_base64url(b"challenge"),
                "origin": "http://localhost:5000",
                "tokenBinding": {
                    "status": "present",
                },
            }
        )
        client_data_bytes = client_data_str.encode("utf-8")

        output = parse_client_data_json(client_data_bytes)

        assert output.token_binding
        assert output.token_binding.id is None

    def test_rejects_duplicate_type(self):
        challenge = "c2VjcmV0LWNoYWxsZW5nZQ"
        client_data_bytes = (
            b'{"type":"webauthn.create","challenge":"'
            + challenge.encode()
            + b'","origin":"https://example.com","type":"webauthn.get"}'
        )

        with self.assertRaisesRegex(
            InvalidJSONStructure, 'duplicate property "type"'
        ) as context:
            parse_client_data_json(client_data_bytes)

        assert challenge not in str(context.exception)

    def test_rejects_duplicate_challenge(self):
        client_data_bytes = (
            b'{"type":"webauthn.create","challenge":"c2VjcmV0LWNoYWxsZW5nZQ",'
            b'"origin":"https://example.com","challenge":"b3RoZXItY2hhbGxlbmdl"}'
        )

        with self.assertRaisesRegex(
            InvalidJSONStructure, 'duplicate property "challenge"'
        ) as context:
            parse_client_data_json(client_data_bytes)

        exception_text = str(context.exception)
        assert "c2VjcmV0LWNoYWxsZW5nZQ" not in exception_text
        assert "b3RoZXItY2hhbGxlbmdl" not in exception_text

    def test_rejects_duplicate_property_in_nested_object(self):
        client_data_bytes = (
            b'{"type":"webauthn.create","challenge":"c2VjcmV0LWNoYWxsZW5nZQ",'
            b'"origin":"https://example.com",'
            b'"user":{"name":"sensitive-value","name":"other-value"}}'
        )

        with self.assertRaisesRegex(
            InvalidJSONStructure, 'duplicate property "name"'
        ) as context:
            parse_client_data_json(client_data_bytes)

        exception_text = str(context.exception)
        assert "sensitive-value" not in exception_text
        assert "other-value" not in exception_text

    def test_rejects_trailing_content(self):
        client_data_bytes = (
            b'{"type":"webauthn.create","challenge":"c2VjcmV0LWNoYWxsZW5nZQ",'
            b'"origin":"https://example.com"} trailing'
        )

        with self.assertRaisesRegex(
            InvalidJSONStructure, "Unable to decode.*trailing content"
        ):
            parse_client_data_json(client_data_bytes)

    def test_rejects_non_object_root(self):
        for client_data_bytes in (
            b"[]",
            b'"a string"',
            b"123",
            b"true",
            b"null",
        ):
            with self.subTest(client_data_bytes=client_data_bytes):
                with self.assertRaisesRegex(InvalidJSONStructure, "was not a dict"):
                    parse_client_data_json(client_data_bytes)

    def test_rejects_bad_base64url_challenge(self):
        for challenge in (
            "not+base64/url",
            "bad length",
            "A",
            "AB",
            "YWJjZA==",
            "YWJjZA=",
            "",
        ):
            with self.subTest(challenge=challenge):
                client_data_bytes = json.dumps(
                    {
                        "type": "webauthn.create",
                        "challenge": challenge,
                        "origin": "https://example.com",
                    }
                ).encode("utf-8")

                with self.assertRaisesRegex(
                    InvalidJSONStructure, 'property "challenge"'
                ) as context:
                    parse_client_data_json(client_data_bytes)

                if challenge:
                    assert challenge not in str(context.exception)

    def test_rejects_wrong_field_types(self):
        valid = {
            "type": "webauthn.create",
            "challenge": "c2VjcmV0LWNoYWxsZW5nZQ",
            "origin": "https://example.com",
        }
        cases = (
            ({"type": 123}, 'property "type" must be a string'),
            ({"challenge": 123}, 'property "challenge" must be a string'),
            ({"origin": 123}, 'property "origin" must be a string'),
            ({"crossOrigin": "false"}, 'property "crossOrigin" must be a boolean'),
            ({"crossOrigin": 0}, 'property "crossOrigin" must be a boolean'),
            ({"topOrigin": False}, 'property "topOrigin" must be a string'),
            ({"tokenBinding": "present"}, 'property "tokenBinding" must be an object'),
            (
                {"tokenBinding": {"status": 1}},
                'property "tokenBinding.status" must be a string',
            ),
            (
                {"tokenBinding": {"status": "present", "id": 1}},
                'property "tokenBinding.id" must be a string',
            ),
        )

        for overrides, expected_error in cases:
            with self.subTest(overrides=overrides):
                client_data = {**valid, **overrides}
                with self.assertRaisesRegex(InvalidJSONStructure, expected_error):
                    parse_client_data_json(json.dumps(client_data).encode("utf-8"))

    def test_rejects_unknown_enums(self):
        cases = (
            (
                {
                    "type": "webauthn.unknown-secret",
                    "challenge": "c2VjcmV0LWNoYWxsZW5nZQ",
                    "origin": "https://example.com",
                },
                'property "type" has an unknown value',
            ),
            (
                {
                    "type": "webauthn.create",
                    "challenge": "c2VjcmV0LWNoYWxsZW5nZQ",
                    "origin": "https://example.com",
                    "tokenBinding": {"status": "unknown-secret"},
                },
                'property "tokenBinding.status" has an unknown value',
            ),
        )

        for client_data, expected_error in cases:
            with self.subTest(client_data=client_data):
                with self.assertRaisesRegex(
                    InvalidJSONStructure, expected_error
                ) as context:
                    parse_client_data_json(json.dumps(client_data).encode("utf-8"))

                exception_text = str(context.exception)
                assert "unknown-secret" not in exception_text
                assert "c2VjcmV0LWNoYWxsZW5nZQ" not in exception_text

    def test_rejects_invalid_utf8(self):
        cases = (
            (
                b'{"type":"webauthn.create","challenge":"c2VjcmV0LWNoYWxsZW5nZQ",'
                b'"origin":"https://example.com/\xff"}',
                'property "origin"',
            ),
            (
                b'{"type":"webauthn.create\xff","challenge":"c2VjcmV0LWNoYWxsZW5nZQ",'
                b'"origin":"https://example.com"}',
                'property "type"',
            ),
        )

        for client_data_bytes, expected_field in cases:
            with self.subTest(client_data_bytes=client_data_bytes):
                with self.assertRaisesRegex(
                    InvalidJSONStructure, "Unable to decode.*UTF-8"
                ) as context:
                    parse_client_data_json(client_data_bytes)

                assert expected_field in str(context.exception)

    def test_parses_authentication_client_data_with_browser_field_order(self):
        raw_client_data = (
            b'{"challenge":"YXV0aC1jaGFsbGVuZ2U","origin":"https://example.com",'
            b'"type":"webauthn.get","crossOrigin":true,'
            b'"topOrigin":"https://login.example.com",'
            b'"tokenBinding":{"status":"supported"}}'
        )

        output = parse_client_data_json(raw_client_data)

        assert output.type == ClientDataType.WEBAUTHN_GET
        assert output.challenge == base64url_to_bytes("YXV0aC1jaGFsbGVuZ2U")
        assert output.origin == "https://example.com"
        assert output.cross_origin is True
        assert output.top_origin == "https://login.example.com"
        assert output.token_binding
        assert output.token_binding.status == TokenBindingStatus.SUPPORTED
        assert output.token_binding.id is None

    def test_accepts_different_origin_forms_without_normalization(self):
        origins = (
            "http://localhost:5000",
            "https://example.com:8443",
            "https://xn--h1alffa9f.xn--p1ai",
            "https://sub.example.com",
            "https://例え.com",
        )

        for origin in origins:
            with self.subTest(origin=origin):
                client_data_bytes = json.dumps(
                    {
                        "type": "webauthn.create",
                        "challenge": "c2VjcmV0LWNoYWxsZW5nZQ",
                        "origin": origin,
                    }
                ).encode("utf-8")

                output = parse_client_data_json(client_data_bytes)

                assert output.origin == origin

    def test_accepts_nested_unknown_fields_with_distinct_properties(self):
        raw_client_data = (
            b'{"type":"webauthn.create","challenge":"Y2hhbGxlbmdl",'
            b'"origin":"https://example.com",'
            b'"clientExtensions":{"first":{"value":1},'
            b'"second":[{"value":2},{"value":3}]}}'
        )

        output = parse_client_data_json(raw_client_data)

        assert output.type == ClientDataType.WEBAUTHN_CREATE
        assert output.challenge == b"challenge"
        assert output.origin == "https://example.com"

    def test_retains_raw_signed_bytes_and_field_ranges(self):
        raw_client_data = (
            b'{"type":"webauthn.create","challenge":"Y2hhbGxlbmdl",'
            b'"origin":"https://example.com","crossOrigin":false,'
            b'"tokenBinding":{"status":"present","id":"binding-id"}}'
        )

        output = parse_client_data_json(raw_client_data)

        assert output.raw_bytes == raw_client_data
        assert output.type == "webauthn.create"
        assert output.challenge == b"challenge"
        assert output.origin == "https://example.com"

        assert json.loads(output.get_raw_field_bytes("type")) == "webauthn.create"
        assert json.loads(output.get_raw_field_bytes("challenge")) == "Y2hhbGxlbmdl"
        assert json.loads(output.get_raw_field_bytes("origin")) == "https://example.com"
        assert json.loads(output.get_raw_field_bytes("crossOrigin")) is False
        assert (
            json.loads(output.get_raw_field_bytes("tokenBinding.status")) == "present"
        )

        # Parsing the same input twice must produce identical derived values and
        # byte locations without a re-serialization round-trip.
        output_again = parse_client_data_json(raw_client_data)
        assert output_again == output

    def test_distinguishes_missing_and_explicit_false_cross_origin(self):
        base = {
            "type": "webauthn.create",
            "challenge": "c2VjcmV0LWNoYWxsZW5nZQ",
            "origin": "https://example.com",
        }

        missing = parse_client_data_json(json.dumps(base).encode("utf-8"))
        explicit_false = parse_client_data_json(
            json.dumps({**base, "crossOrigin": False}).encode("utf-8")
        )

        assert missing.cross_origin is None
        assert explicit_false.cross_origin is False

    def test_exceptions_do_not_include_sensitive_client_data(self):
        secret_challenge = "c2VjcmV0LWNoYWxsZW5nZQ"
        secret_user_info = "private-user-info"
        client_data_bytes = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": secret_challenge,
                "origin": "https://example.com",
                "user": {"displayName": secret_user_info},
                "crossOrigin": "not-a-boolean",
            }
        ).encode("utf-8")

        with self.assertRaises(InvalidJSONStructure) as context:
            parse_client_data_json(client_data_bytes)

        exception_text = str(context.exception)
        assert 'property "crossOrigin"' in exception_text
        assert secret_challenge not in exception_text
        assert secret_user_info not in exception_text
        assert client_data_bytes.decode("utf-8") not in exception_text
