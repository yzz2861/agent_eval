from datetime import datetime, timedelta, timezone
from unittest import TestCase
from unittest.mock import MagicMock, patch

from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    ExistingCredential,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    RegistrationPolicy,
    UserVerificationRequirement,
)
from webauthn.helpers.exceptions import AmbiguousCredentialIdError
from webauthn.helpers.options_to_json_dict import options_to_json_dict
from webauthn import generate_registration_options


class TestGenerateRegistrationOptions(TestCase):
    @patch("secrets.token_bytes")
    def test_generates_options_with_defaults(self, token_bytes_mock: MagicMock) -> None:
        token_bytes_mock.return_value = b"12345"
        user_id = "ABAV6QWPBEY9WOTOA1A4".encode("utf-8")

        options = generate_registration_options(
            rp_id="example.com",
            rp_name="Example Co",
            user_id=user_id,
            user_name="lee",
        )

        assert options.rp == PublicKeyCredentialRpEntity(
            id="example.com",
            name="Example Co",
        )
        assert options.challenge == b"12345"
        assert options.user == PublicKeyCredentialUserEntity(
            id=user_id,
            name="lee",
            display_name="lee",
        )
        assert options.pub_key_cred_params[0] == PublicKeyCredentialParameters(
            type="public-key",
            alg=COSEAlgorithmIdentifier.EDDSA,
        )
        assert options.timeout == 60000
        assert options.exclude_credentials == []
        assert options.authenticator_selection is None
        assert options.attestation == AttestationConveyancePreference.NONE

    def test_generates_options_with_custom_values(self) -> None:
        user_id = "ABAV6QWPBEY9WOTOA1A4".encode("utf-8")

        options = generate_registration_options(
            rp_id="example.com",
            rp_name="Example Co",
            user_id=user_id,
            user_name="lee",
            user_display_name="Lee",
            attestation=AttestationConveyancePreference.DIRECT,
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                resident_key=ResidentKeyRequirement.REQUIRED,
            ),
            challenge=b"1234567890",
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=b"1234567890"),
            ],
            supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_512],
            timeout=120000,
        )

        assert options.rp == PublicKeyCredentialRpEntity(id="example.com", name="Example Co")
        assert options.challenge == b"1234567890"
        assert options.user == PublicKeyCredentialUserEntity(
            id=user_id,
            name="lee",
            display_name="Lee",
        )
        assert options.pub_key_cred_params[0] == PublicKeyCredentialParameters(
            type="public-key",
            alg=COSEAlgorithmIdentifier.ECDSA_SHA_512,
        )
        assert options.timeout == 120000
        assert options.exclude_credentials == [PublicKeyCredentialDescriptor(id=b"1234567890")]
        assert options.authenticator_selection == AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.REQUIRED,
            require_resident_key=True,
        )
        assert options.attestation == AttestationConveyancePreference.DIRECT

    def test_raises_on_empty_rp_id(self) -> None:
        with self.assertRaisesRegex(ValueError, "rp_id"):
            generate_registration_options(
                rp_id="",
                rp_name="Example Co",
                user_name="blah",
            )

    def test_raises_on_empty_rp_name(self) -> None:
        with self.assertRaisesRegex(ValueError, "rp_name"):
            generate_registration_options(
                rp_id="example.com",
                rp_name="",
                user_name="blah",
            )

    @patch("secrets.token_bytes")
    def test_generated_random_id_on_empty_user_id(self, token_bytes_mock: MagicMock) -> None:
        token_bytes_mock.return_value = bytes([1, 2, 3, 4])

        options = generate_registration_options(
            rp_id="example.com",
            rp_name="Example Co",
            user_name="blah",
            user_id=None,
        )

        self.assertEqual(options.user.id, bytes([1, 2, 3, 4]))

    def test_raises_on_non_bytes_user_id(self) -> None:
        with self.assertRaisesRegex(ValueError, "user_id"):
            generate_registration_options(
                rp_id="example.com",
                rp_name="Example Co",
                user_name="hello",
                user_id="hello",  # type: ignore
            )

    def test_raises_on_empty_user_name(self) -> None:
        with self.assertRaisesRegex(ValueError, "user_name"):
            generate_registration_options(
                rp_id="example.com",
                rp_name="Example Co",
                user_name="",
            )

    def test_suggests_popular_default_supported_algorithms(self) -> None:
        """
        Popular = Ed25519 is pretty cool, so use it when it's available. ES256 and RS256 are safe
        and common fallbacks.
        """
        options = generate_registration_options(
            rp_id="example.com",
            rp_name="Example Co",
            user_name="blah",
            user_id=None,
        )

        self.assertEqual(len(options.pub_key_cred_params), 3)
        self.assertEqual(
            options.pub_key_cred_params[0].alg,
            COSEAlgorithmIdentifier.EDDSA,
        )
        self.assertEqual(
            options.pub_key_cred_params[1].alg,
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
        )
        self.assertEqual(
            options.pub_key_cred_params[2].alg,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        )

    def test_policy_dedupes_same_credential_id_across_transports(self) -> None:
        options = generate_registration_options(
            rp_id="example.com",
            rp_name="Example Co",
            user_name="lee",
            user_id=b"user",
            existing_credentials=[
                ExistingCredential(credential_id=b"b", transports=[AuthenticatorTransport.USB]),
                ExistingCredential(credential_id=b"a", transports=[AuthenticatorTransport.INTERNAL]),
                ExistingCredential(credential_id=b"b", transports=[AuthenticatorTransport.NFC]),
            ],
        )

        self.assertEqual(
            options.exclude_credentials,
            [
                PublicKeyCredentialDescriptor(
                    id=b"a", transports=[AuthenticatorTransport.INTERNAL]
                ),
                PublicKeyCredentialDescriptor(
                    id=b"b",
                    transports=[AuthenticatorTransport.NFC, AuthenticatorTransport.USB],
                ),
            ],
        )

    def test_policy_filters_revoked_and_expired_credentials(self) -> None:
        now = datetime(2026, 11, 12, tzinfo=timezone.utc)
        options = generate_registration_options(
            rp_id="example.com",
            rp_name="Example Co",
            user_name="lee",
            user_id=b"user",
            registration_policy=RegistrationPolicy(
                existing_credentials=[
                    ExistingCredential(credential_id=b"revoked", revoked=True),
                    ExistingCredential(credential_id=b"revoked-at", revoked_at=now),
                    ExistingCredential(credential_id=b"expired", expires_at=now - timedelta(days=1)),
                    ExistingCredential(credential_id=b"valid", expires_at=now + timedelta(days=1)),
                ],
                now=now,
            ),
        )

        self.assertEqual(
            options.exclude_credentials,
            [PublicKeyCredentialDescriptor(id=b"valid")],
        )

    def test_policy_with_empty_credentials_produces_empty_exclusions(self) -> None:
        options = generate_registration_options(
            rp_id="example.com",
            rp_name="Example Co",
            user_name="lee",
            user_id=b"user",
            existing_credentials=[],
        )

        self.assertEqual(options.exclude_credentials, [])

    def test_policy_rejects_shared_credential_ids_from_distinct_authenticators(self) -> None:
        with self.assertRaisesRegex(AmbiguousCredentialIdError, "share credential id"):
            generate_registration_options(
                rp_id="example.com",
                rp_name="Example Co",
                user_name="lee",
                user_id=b"user",
                existing_credentials=[
                    ExistingCredential(
                        credential_id=b"shared",
                        aaguid="11111111-1111-1111-1111-111111111111",
                    ),
                    ExistingCredential(
                        credential_id=b"shared",
                        aaguid="22222222-2222-2222-2222-222222222222",
                    ),
                ],
            )

    def test_policy_excludes_incompatible_transports_and_aaguids(self) -> None:
        options = generate_registration_options(
            rp_id="example.com",
            rp_name="Example Co",
            user_name="lee",
            user_id=b"user",
            registration_policy=RegistrationPolicy(
                existing_credentials=[
                    ExistingCredential(
                        credential_id=b"usb",
                        transports=[AuthenticatorTransport.USB],
                    ),
                    ExistingCredential(
                        credential_id=b"internal",
                        transports=[AuthenticatorTransport.INTERNAL],
                    ),
                    ExistingCredential(
                        credential_id=b"blocked-aaguid",
                        transports=[AuthenticatorTransport.HYBRID],
                        aaguid="22222222-2222-2222-2222-222222222222",
                    ),
                ],
                excluded_transports=[AuthenticatorTransport.USB],
                excluded_aaguids=["22222222-2222-2222-2222-222222222222"],
            ),
        )

        self.assertEqual(
            options.exclude_credentials,
            [
                PublicKeyCredentialDescriptor(
                    id=b"internal", transports=[AuthenticatorTransport.INTERNAL]
                )
            ],
        )

    def test_exclude_credentials_do_not_leak_internal_metadata(self) -> None:
        options = generate_registration_options(
            rp_id="example.com",
            rp_name="Example Co",
            user_name="lee",
            user_id=b"user",
            existing_credentials=[
                ExistingCredential(
                    credential_id=b"credential",
                    transports=[AuthenticatorTransport.INTERNAL],
                    database_id=42,
                    user_handle=b"handle-secret",
                    label="Work laptop",
                )
            ],
        )

        exclude_credentials_json = options_to_json_dict(options)["excludeCredentials"]
        self.assertEqual(len(exclude_credentials_json), 1)
        self.assertEqual(
            set(exclude_credentials_json[0]), {"id", "type", "transports"}
        )
        self.assertNotIn("handle-secret", str(exclude_credentials_json))
        self.assertNotIn("Work laptop", str(exclude_credentials_json))

    def test_resident_key_policy_supports_all_three_values(self) -> None:
        for resident_key, expected_require_resident_key in (
            (ResidentKeyRequirement.DISCOURAGED, False),
            (ResidentKeyRequirement.PREFERRED, False),
            (ResidentKeyRequirement.REQUIRED, True),
        ):
            with self.subTest(resident_key=resident_key):
                options = generate_registration_options(
                    rp_id="example.com",
                    rp_name="Example Co",
                    user_name="lee",
                    user_id=b"user",
                    registration_policy=RegistrationPolicy(
                        resident_key=resident_key,
                        user_verification=UserVerificationRequirement.REQUIRED,
                    ),
                )

                self.assertIsNotNone(options.authenticator_selection)
                assert options.authenticator_selection is not None
                self.assertEqual(
                    options.authenticator_selection.resident_key, resident_key
                )
                self.assertEqual(
                    options.authenticator_selection.require_resident_key,
                    expected_require_resident_key,
                )
                self.assertEqual(
                    options.authenticator_selection.user_verification,
                    UserVerificationRequirement.REQUIRED,
                )
