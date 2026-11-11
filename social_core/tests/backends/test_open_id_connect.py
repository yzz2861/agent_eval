from __future__ import annotations

import copy
import datetime as dt
import json
import threading
import time
from typing import Protocol, cast
from unittest.mock import patch

import jwt
import requests
import responses
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from jwt.utils import base64url_encode

from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.exceptions import (
    AuthConfigurationError,
    AuthCredentialError,
    AuthResponseError,
)
from social_core.tests.exception_helpers import assert_auth_error
from social_core.utils import get_querystring, parse_qs

from .oauth import BaseAuthUrlTestMixin
from .open_id_connect import (
    JWK_KEY,
    JWK_PUBLIC_KEY,
    PARTIAL_ID_TOKEN_KEY,
    STORED_ID_TOKEN_CONTEXT_KEY,
    OpenIdConnectTest,
)
from .open_id_connect_nonce import OpenIdConnectNonceAssertionsMixin


def decode_id_token_context(id_token: str) -> dict:
    claims = jwt.decode(id_token, options={"verify_signature": False})
    return {
        claim: claims[claim]
        for claim in ("iss", "sub", "aud", "auth_time", "nonce")
        if claim in claims
    }


class OpenIdConnectPkceAssertionsCapable(Protocol):
    backend: OpenIdConnectAuth

    def assertEqual(self, first, second, msg=None) -> None: ...

    def assertIsNone(self, obj, msg=None) -> None: ...

    def assertIsNotNone(self, obj, msg=None) -> None: ...


class OpenIdConnectPkceAssertionsMixin:
    backend: OpenIdConnectAuth

    def assert_pkce_enabled(self: OpenIdConnectPkceAssertionsCapable) -> None:
        auth_request = next(
            r.request
            for r in responses.calls
            if cast("str", r.request.url).startswith(self.backend.authorization_url())
        )
        code_challenge = get_querystring(cast("str", auth_request.url)).get(
            "code_challenge"
        )
        code_challenge_method = get_querystring(cast("str", auth_request.url)).get(
            "code_challenge_method"
        )

        self.assertIsNotNone(code_challenge)
        self.assertEqual(code_challenge_method, "S256")

        auth_complete = next(
            r.request
            for r in responses.calls
            if cast("str", r.request.url).startswith(self.backend.access_token_url())
        )
        code_verifier = parse_qs(auth_complete.body).get("code_verifier")

        self.assertEqual(
            self.backend.generate_code_challenge(code_verifier, code_challenge_method),
            code_challenge,
        )

    def assert_pkce_disabled(self: OpenIdConnectPkceAssertionsCapable) -> None:
        auth_request = next(
            r.request
            for r in responses.calls
            if cast("str", r.request.url).startswith(self.backend.authorization_url())
        )
        auth_query = get_querystring(cast("str", auth_request.url))

        self.assertIsNone(auth_query.get("code_challenge"))
        self.assertIsNone(auth_query.get("code_challenge_method"))

        auth_complete = next(
            r.request
            for r in responses.calls
            if cast("str", r.request.url).startswith(self.backend.access_token_url())
        )

        self.assertIsNone(parse_qs(auth_complete.body).get("code_verifier"))


class BaseOpenIdConnectTest(
    OpenIdConnectTest,
    BaseAuthUrlTestMixin,
    OpenIdConnectPkceAssertionsMixin,
    OpenIdConnectNonceAssertionsMixin,
):
    backend_path = "social_core.backends.open_id_connect.OpenIdConnectAuth"
    issuer = "https://example.com"
    openid_config_body = json.dumps(
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/oidc/auth",
            "token_endpoint": "https://example.com/oidc/token",
            "userinfo_endpoint": "https://example.com/oidc/userinfo",
            "revocation_endpoint": "https://example.com/oidc/revoke",
            "jwks_uri": "https://example.com/oidc/certs",
        }
    )

    expected_username = "cartman"

    def extra_settings(self):
        settings = super().extra_settings()
        settings.update(
            {
                "SOCIAL_AUTH_OIDC_OIDC_ENDPOINT": "https://example.com/oidc",
            }
        )
        return settings

    def pre_complete_callback(self, start_url) -> None:
        super().pre_complete_callback(start_url)
        responses.add(
            "GET",
            url=self.backend.userinfo_url(),
            status=200,
            body=json.dumps({"preferred_username": self.expected_username}),
            content_type="text/json",
        )

    def test_partial_pipeline(self) -> None:
        self.do_partial_pipeline()

    def test_partial_pipeline_saves_validated_claims(self) -> None:
        resume = self.resume_partial_pipeline
        with patch.object(self, "resume_partial_pipeline", side_effect=resume) as mock:
            self.do_partial_pipeline()
        saved = [c.args[0].kwargs.get(PARTIAL_ID_TOKEN_KEY) for c in mock.mock_calls]
        self.assertEqual(saved, [self.backend.id_token] * 2)

    def test_partial_pipeline_before_details_and_uid(self) -> None:
        self.pipeline_settings()
        pipeline = list(self.strategy.get_pipeline(self.backend))
        pipeline.remove("social_core.tests.pipeline.ask_for_password")
        pipeline.insert(0, "social_core.tests.pipeline.ask_for_password")
        self.strategy.set_settings(
            {"SOCIAL_AUTH_PIPELINE": pipeline, "SOCIAL_AUTH_OIDC_ID_KEY": "custom_id"}
        )
        get_id_token = self.get_id_token

        def token_with_profile(*args, **kwargs):
            return {
                **get_id_token(*args, **kwargs),
                "custom_id": "token-only-id",
                "email": "token@example.com",
            }

        with (
            patch.object(self, "pipeline_settings"),
            patch.object(self, "get_id_token", side_effect=token_with_profile),
        ):
            user = self.do_partial_pipeline()

        self.assertEqual(user.email, "token@example.com")
        self.assertEqual(user.social[0].uid, "token-only-id")

    def test_partial_pipeline_after_token_expires(self) -> None:
        resume = self.resume_partial_pipeline

        def resume_after_expiration(partial):
            claims = partial.kwargs[PARTIAL_ID_TOKEN_KEY]
            expired_time = dt.datetime.fromtimestamp(
                claims["exp"] + self.backend.ID_TOKEN_MAX_AGE + 1,
                dt.UTC,
            )
            with (
                patch("jwt.api_jwt.datetime") as jwt_datetime,
                patch("social_core.backends.open_id_connect.dt") as oidc_datetime,
            ):
                jwt_datetime.now.return_value = expired_time
                oidc_datetime.datetime.now.return_value = expired_time
                return resume(partial)

        with patch.object(
            self, "resume_partial_pipeline", side_effect=resume_after_expiration
        ):
            self.do_partial_pipeline()

    def test_partial_pipeline_without_saved_claims_rejects_token(self) -> None:
        resume = self.resume_partial_pipeline

        def resume_without_claims(partial):
            if "password" in partial.kwargs:
                partial.kwargs.pop(PARTIAL_ID_TOKEN_KEY, None)
            return resume(partial)

        with (
            patch.object(
                self, "resume_partial_pipeline", side_effect=resume_without_claims
            ),
            assert_auth_error(self, AuthResponseError, "invalid_claim"),
        ):
            self.do_partial_pipeline()

    def test_pipeline_does_not_trust_caller_supplied_claims(self) -> None:
        user = self.do_login()
        social = user.social[0]
        claims = self.backend.id_token
        self.backend.id_token = None

        with assert_auth_error(self, AuthResponseError, "invalid_claim") as error:
            self.backend.pipeline(
                ["social_core.pipeline.social_auth.load_extra_data"],
                user=user,
                uid=social.uid,
                social=social,
                details={},
                response={"id_token": social.extra_data["id_token"]},
                **{PARTIAL_ID_TOKEN_KEY: claims},
            )
        self.assertEqual(error.exception.stage, "pipeline")
        self.assertEqual(error.exception.public_metadata()["error_stage"], "pipeline")

    def test_pkce_disabled_by_default(self) -> None:
        self.do_login()
        self.assert_pkce_disabled()

    def test_pkce_can_be_enabled_by_setting(self) -> None:
        self.strategy.set_settings(
            {
                **self.extra_settings(),
                f"SOCIAL_AUTH_{self.name}_USE_PKCE": True,
            }
        )

        self.do_login()

        self.assert_pkce_enabled()

    def assert_refresh_rejected(self, body: str, code: str) -> None:
        social = self.login_for_refresh()
        original_extra_data = copy.deepcopy(social.extra_data)

        with assert_auth_error(self, AuthResponseError, code) as error:
            self.refresh_social(social, body)

        self.assertEqual(error.exception.stage, "refresh")
        self.assertEqual(error.exception.public_metadata()["error_stage"], "refresh")
        self.assertEqual(social.extra_data, original_extra_data)

    def assert_refresh_requires_reauthentication(self, social) -> None:
        original_extra_data = copy.deepcopy(social.extra_data)

        with self.assertRaises(AuthCredentialError):
            self.refresh_social(social, self.refresh_response())

        self.assertEqual(social.extra_data, original_extra_data)

    def test_refresh_without_id_token_preserves_id_token(self) -> None:
        social = self.login_for_refresh()
        original_id_token = social.extra_data["id_token"]
        original_context = decode_id_token_context(original_id_token)
        self.assertEqual(
            social.extra_data[STORED_ID_TOKEN_CONTEXT_KEY],
            original_context,
        )

        self.refresh_social(
            social,
            json.dumps(
                {
                    "access_token": "refreshed-access-token",
                    "token_type": "bearer",
                }
            ),
        )

        self.assertEqual(social.extra_data["access_token"], "refreshed-access-token")
        self.assertEqual(social.extra_data["id_token"], original_id_token)
        self.assertEqual(
            social.extra_data[STORED_ID_TOKEN_CONTEXT_KEY],
            original_context,
        )

    def test_refresh_retains_original_claims_across_refreshes(self) -> None:
        auth_time = 1_700_000_000
        social = self.login_for_refresh(auth_time=auth_time)
        original_context = copy.deepcopy(social.extra_data[STORED_ID_TOKEN_CONTEXT_KEY])

        first_body = self.refresh_response()
        self.refresh_social(social, first_body)

        self.assertEqual(social.extra_data["access_token"], "refreshed-access-token")
        self.assertEqual(
            social.extra_data[STORED_ID_TOKEN_CONTEXT_KEY],
            original_context,
        )
        self.assertEqual(
            social.extra_data["id_token"],
            json.loads(first_body)["id_token"],
        )

        second_body = self.prepare_access_token_body(
            access_token="second-refreshed-access-token",  # ruff: ignore[hardcoded-password-func-arg]
            nonce=original_context["nonce"],
            auth_time=auth_time,
        )
        self.refresh_social(social, second_body)

        self.assertEqual(
            social.extra_data["access_token"],
            "second-refreshed-access-token",
        )
        self.assertEqual(
            social.extra_data["id_token"],
            json.loads(second_body)["id_token"],
        )
        self.assertEqual(
            social.extra_data[STORED_ID_TOKEN_CONTEXT_KEY],
            original_context,
        )

    def test_refresh_rejects_missing_access_token(self) -> None:
        body = self.prepare_access_token_body(
            access_token=None,
            include_nonce=False,
        )
        self.assert_refresh_rejected(
            body,
            "missing_claim",
        )

    def test_refresh_rejects_non_object_json_without_updating_credentials(self) -> None:
        self.assert_refresh_rejected("[]", "malformed_response")

    def test_refresh_does_not_persist_unvalidated_id_token(self) -> None:
        social = self.login_for_refresh()
        original_extra_data = copy.deepcopy(social.extra_data)

        with (
            patch.object(
                type(self.backend),
                "validate_and_return_refresh_id_token",
                return_value=None,
            ),
            assert_auth_error(self, AuthResponseError, "invalid_claim") as error,
        ):
            self.refresh_social(social, self.refresh_response())

        self.assertEqual(error.exception.stage, "refresh")
        self.assertEqual(error.exception.public_metadata()["error_stage"], "refresh")
        self.assertEqual(social.extra_data, original_extra_data)

    def test_refresh_rejects_invalid_signature(self) -> None:
        self.assert_refresh_rejected(
            self.refresh_response(tamper_message=True),
            "invalid_signature",
        )

    def test_refresh_rejects_expired_id_token(self) -> None:
        expiration_datetime = dt.datetime.now(dt.UTC) - dt.timedelta(days=1)
        self.assert_refresh_rejected(
            self.refresh_response(expiration_datetime=expiration_datetime),
            "response_expired",
        )

    def test_refresh_rejects_stale_issue_time(self) -> None:
        issue_datetime = dt.datetime.now(dt.UTC) - dt.timedelta(
            seconds=self.backend.ID_TOKEN_MAX_AGE * 2,
        )
        self.assert_refresh_rejected(
            self.refresh_response(issue_datetime=issue_datetime),
            "response_expired",
        )

    def test_refresh_rejects_missing_expiration(self) -> None:
        self.assert_refresh_rejected(
            self.refresh_response(exclude_claims=("exp",)),
            "missing_claim",
        )

    def test_refresh_rejects_changed_audience_set(self) -> None:
        self.assert_refresh_rejected(
            self.refresh_response(client_key=[self.client_key, "another-audience"]),
            "invalid_claim",
        )

    def test_refresh_accepts_reordered_audience_set(self) -> None:
        social = self.login_for_refresh(
            client_key=[self.client_key, "another-audience"],
        )

        self.refresh_social(
            social,
            self.refresh_response(
                client_key=["another-audience", self.client_key],
                authorized_party=self.client_key,
            ),
        )

        self.assertEqual(social.extra_data["access_token"], "refreshed-access-token")

    def test_refresh_rejects_missing_azp_for_multiple_audiences(self) -> None:
        self.assert_refresh_rejected(
            self.refresh_response(
                client_key=[self.client_key, "another-audience"],
                include_azp=False,
            ),
            "invalid_claim",
        )

    def test_refresh_rejects_invalid_azp(self) -> None:
        self.assert_refresh_rejected(
            self.refresh_response(authorized_party="another-audience"),
            "invalid_claim",
        )

    def test_refresh_accepts_added_azp(self) -> None:
        social = self.login_for_refresh(include_azp=False)

        self.refresh_social(social, self.refresh_response())

        self.assertEqual(social.extra_data["access_token"], "refreshed-access-token")

    def test_refresh_accepts_omitted_azp(self) -> None:
        social = self.login_for_refresh()

        self.refresh_social(
            social,
            self.refresh_response(include_azp=False),
        )

        self.assertEqual(social.extra_data["access_token"], "refreshed-access-token")

    def test_refresh_rejects_changed_subject(self) -> None:
        self.assert_refresh_rejected(
            self.refresh_response(subject="different-subject"),
            "invalid_claim",
        )

    def test_refresh_rejects_changed_auth_time(self) -> None:
        social = self.login_for_refresh(auth_time=1_700_000_000)
        original_extra_data = copy.deepcopy(social.extra_data)

        with assert_auth_error(self, AuthResponseError, "invalid_claim"):
            self.refresh_social(
                social,
                self.refresh_response(auth_time=1_700_000_001),
            )

        self.assertEqual(social.extra_data, original_extra_data)

    def test_refresh_rejects_changed_nonce(self) -> None:
        self.assert_refresh_rejected(
            self.prepare_access_token_body(
                access_token="refreshed-access-token",  # ruff: ignore[hardcoded-password-func-arg]
                nonce="different-nonce",
            ),
            "invalid_claim",
        )

    def test_refresh_without_context_establishes_new_baseline(self) -> None:
        social = self.login_for_refresh()
        social.extra_data.pop("id_token")
        social.extra_data.pop(STORED_ID_TOKEN_CONTEXT_KEY)

        self.refresh_social(
            social,
            self.refresh_response(subject="migrated-subject"),
        )
        self.assertEqual(
            social.extra_data[STORED_ID_TOKEN_CONTEXT_KEY]["sub"],
            "migrated-subject",
        )
        migrated_extra_data = copy.deepcopy(social.extra_data)

        with assert_auth_error(self, AuthResponseError, "invalid_claim"):
            self.refresh_social(
                social,
                self.refresh_response(subject="another-subject"),
            )

        self.assertEqual(social.extra_data, migrated_extra_data)

    def test_refresh_requires_reauthentication_for_incomplete_context(self) -> None:
        social = self.login_for_refresh()
        social.extra_data[STORED_ID_TOKEN_CONTEXT_KEY].pop("sub")

        self.assert_refresh_requires_reauthentication(social)


class ExampleOpenIdConnectAuth(OpenIdConnectAuth):
    name = "example123"
    OIDC_ENDPOINT = "https://example.com/oidc"


class OpenIdConnectPkceEnabledByDefault(ExampleOpenIdConnectAuth):
    name = "example123-pkce-default"
    DEFAULT_USE_PKCE = True


class OpenIdConnectStrictJwksAuth(ExampleOpenIdConnectAuth):
    name = "example123-strict-jwks"


class ExampleOpenIdConnectTest(OpenIdConnectTest):
    backend_path = (
        "social_core.tests.backends.test_open_id_connect.ExampleOpenIdConnectAuth"
    )
    issuer = "https://example.com"
    openid_config_body = json.dumps(
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/oidc/auth",
            "token_endpoint": "https://example.com/oidc/token",
            "userinfo_endpoint": "https://example.com/oidc/userinfo",
            "revocation_endpoint": "https://example.com/oidc/revoke",
            "jwks_uri": "https://example.com/oidc/certs",
        }
    )

    expected_username = "cartman"

    def setUp(self) -> None:
        super().setUp()
        self.userinfo_response = {"preferred_username": self.expected_username}

    def pre_complete_callback(self, start_url) -> None:
        super().pre_complete_callback(start_url)
        responses.add(
            responses.GET,
            url=self.backend.userinfo_url(),
            status=200,
            body=json.dumps(self.userinfo_response),
            content_type="text/json",
        )

    def test_everything_works(self) -> None:
        self.do_login()

    def test_malformed_id_token_raises_auth_token_error(self) -> None:
        with self.assertRaises(AuthResponseError) as context:
            self.backend.validate_and_return_id_token("malformed", "access-token")

        self.assertIsInstance(context.exception.__cause__, jwt.PyJWTError)

    def test_user_id_comes_from_id_token_when_userinfo_omits_sub(self) -> None:
        user = self.do_login()

        self.assertEqual(user.social[0].uid, "1234")

    def test_missing_id_token_subject_raises_error(self) -> None:
        self.authtoken_raised(
            "missing_claim",
            exclude_claims=("sub",),
        )

    def test_missing_id_token_expiration_raises_error(self) -> None:
        self.authtoken_raised(
            "missing_claim",
            exclude_claims=("exp",),
        )

    def test_missing_id_token_issue_time_raises_error(self) -> None:
        self.access_token_kwargs = {"exclude_claims": ("iat",)}
        with self.assertRaises(AuthResponseError) as caught:
            self.do_login()
        self.assertEqual(caught.exception.code, "missing_claim")
        self.assertEqual(caught.exception.claim, "iat")
        self.assertEqual(caught.exception.stage, "token_validation")
        self.assertEqual(caught.exception.recovery, "contact_administrator")

    def test_matching_userinfo_sub_succeeds(self) -> None:
        self.userinfo_response["sub"] = "1234"

        user = self.do_login()

        self.assertEqual(user.social[0].uid, "1234")

    def test_mismatched_userinfo_sub_raises_error(self) -> None:
        self.userinfo_response["sub"] = "not-validated-subject"

        with assert_auth_error(self, AuthResponseError, "invalid_claim"):
            self.do_login()

    def test_missing_access_token_response_raises_token_error(self) -> None:
        self.authtoken_raised(
            "missing_claim",
            access_token=None,
        )


class ExampleOpenIdConnectPkceEnabledByDefaultTest(
    OpenIdConnectTest, OpenIdConnectPkceAssertionsMixin
):
    backend_path = "social_core.tests.backends.test_open_id_connect.OpenIdConnectPkceEnabledByDefault"
    issuer = "https://example.com"
    openid_config_body = json.dumps(
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/oidc/auth",
            "token_endpoint": "https://example.com/oidc/token",
            "userinfo_endpoint": "https://example.com/oidc/userinfo",
            "revocation_endpoint": "https://example.com/oidc/revoke",
            "jwks_uri": "https://example.com/oidc/certs",
        }
    )

    expected_username = "cartman"

    def pre_complete_callback(self, start_url) -> None:
        super().pre_complete_callback(start_url)
        responses.add(
            responses.GET,
            url=self.backend.userinfo_url(),
            status=200,
            body=json.dumps({"preferred_username": self.expected_username}),
            content_type="text/json",
        )

    def test_everything_works(self) -> None:
        self.do_login()

    def test_pkce_enabled_by_backend_default(self) -> None:
        self.do_login()
        self.assert_pkce_enabled()

    def test_pkce_can_be_disabled_by_setting(self) -> None:
        self.strategy.set_settings(
            {
                **self.extra_settings(),
                f"SOCIAL_AUTH_{self.name}_USE_PKCE": False,
            }
        )

        self.do_login()

        self.assert_pkce_disabled()


class OpenIdConnectAuthNoValidateAtHash(ExampleOpenIdConnectAuth):
    VALIDATE_AT_HASH = False


class ExampleOpenIdConnectNoValidateAtHashTest(OpenIdConnectTest):
    backend_path = "social_core.tests.backends.test_open_id_connect.OpenIdConnectAuthNoValidateAtHash"
    issuer = "https://example.com"
    openid_config_body = json.dumps(
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/oidc/auth",
            "token_endpoint": "https://example.com/oidc/token",
            "userinfo_endpoint": "https://example.com/oidc/userinfo",
            "revocation_endpoint": "https://example.com/oidc/revoke",
            "jwks_uri": "https://example.com/oidc/certs",
        }
    )

    expected_username = "cartman"
    allow_invalid_at_hash = True

    def pre_complete_callback(self, start_url) -> None:
        super().pre_complete_callback(start_url)
        responses.add(
            responses.GET,
            url=self.backend.userinfo_url(),
            status=200,
            body=json.dumps({"preferred_username": self.expected_username}),
            content_type="text/json",
        )

    def test_everything_works(self) -> None:
        self.do_login()


class OpenIdConnectCustomAtHash(ExampleOpenIdConnectAuth):
    CUSTOM_AT_HASH_ALGO = "SHA512"


class ExampleOpenIdConnectCustomAtHashTest(OpenIdConnectTest):
    backend_path = (
        "social_core.tests.backends.test_open_id_connect.OpenIdConnectCustomAtHash"
    )
    issuer = "https://example.com"
    openid_config_body = json.dumps(
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/oidc/auth",
            "token_endpoint": "https://example.com/oidc/token",
            "userinfo_endpoint": "https://example.com/oidc/userinfo",
            "revocation_endpoint": "https://example.com/oidc/revoke",
            "jwks_uri": "https://example.com/oidc/certs",
        }
    )

    expected_username = "cartman"

    def pre_complete_callback(self, start_url) -> None:
        super().pre_complete_callback(start_url)
        responses.add(
            responses.GET,
            url=self.backend.userinfo_url(),
            status=200,
            body=json.dumps({"preferred_username": self.expected_username}),
            content_type="text/json",
        )

    def prepare_access_token_body(
        self,
        client_key=None,
        tamper_message=False,
        expiration_datetime=None,
        kid=None,
        issue_datetime=None,
        nonce=None,
        issuer=None,
        at_hash=None,
        subject=None,
        access_token: str | None = "foobar",  # ruff: ignore[hardcoded-password-default]
        refresh_token: str | None = None,
        include_nonce: bool = True,
        auth_time: int | None = None,
        include_azp: bool = True,
        authorized_party: str | None = None,
        exclude_claims: tuple[str, ...] = (),
    ):
        if at_hash is None and access_token is not None:
            at_hash = OpenIdConnectAuth.calc_at_hash(access_token, "RS256", "sha512")
        return super().prepare_access_token_body(
            client_key=client_key,
            tamper_message=tamper_message,
            expiration_datetime=expiration_datetime,
            kid=kid,
            issue_datetime=issue_datetime,
            nonce=nonce,
            issuer=issuer,
            at_hash=at_hash,
            subject=subject,
            access_token=access_token,
            refresh_token=refresh_token,
            include_nonce=include_nonce,
            auth_time=auth_time,
            include_azp=include_azp,
            authorized_party=authorized_party,
            exclude_claims=exclude_claims,
        )

    def test_everything_works(self) -> None:
        self.do_login()

    def test_mismatch_custom_at_hash_algo(self) -> None:
        if self.skip_invalid_at_hash:
            self.skipTest("the call doesn't match any registered mock.")

        at_hash = OpenIdConnectAuth.calc_at_hash("foobar", "RS256", "sha256")

        if self.allow_invalid_at_hash:
            self.access_token_kwargs = {"at_hash": at_hash}
            self.do_login()
        else:
            self.authtoken_raised("invalid_claim", at_hash=at_hash)

    def test_invalid_custom_at_hash_algo(self) -> None:
        with self.assertRaisesRegex(
            NotImplementedError, "Unsupported custom at hash algorithm"
        ):
            OpenIdConnectAuth.calc_at_hash("foobar", "RS256", "INVALID_ALGO")


class OpenIdConnectWithAcrValues(ExampleOpenIdConnectAuth):
    ACR_VALUES = "urn:mace:incommon:iap:silver"


class ExampleOpenIdConnectAcrValuesTest(OpenIdConnectTest):
    backend_path = (
        "social_core.tests.backends.test_open_id_connect.OpenIdConnectWithAcrValues"
    )
    issuer = "https://example.com"
    openid_config_body = json.dumps(
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/oidc/auth",
            "token_endpoint": "https://example.com/oidc/token",
            "userinfo_endpoint": "https://example.com/oidc/userinfo",
            "revocation_endpoint": "https://example.com/oidc/revoke",
            "jwks_uri": "https://example.com/oidc/certs",
        }
    )

    expected_username = "cartman"

    def pre_complete_callback(self, start_url) -> None:
        super().pre_complete_callback(start_url)
        responses.add(
            responses.GET,
            url=self.backend.userinfo_url(),
            status=200,
            body=json.dumps({"preferred_username": self.expected_username}),
            content_type="text/json",
        )

    def test_everything_works(self) -> None:
        self.do_login()

    def test_acr_values_in_auth_params(self) -> None:
        params = self.backend.auth_params(state=self.backend.get_or_create_state())
        self.assertEqual(params["acr_values"], "urn:mace:incommon:iap:silver")


class OpenIdConnectWithLoginHint(ExampleOpenIdConnectAuth):
    LOGIN_HINT = "user@example.com"


class ExampleOpenIdConnectLoginHintTest(OpenIdConnectTest):
    backend_path = (
        "social_core.tests.backends.test_open_id_connect.OpenIdConnectWithLoginHint"
    )
    issuer = "https://example.com"
    openid_config_body = json.dumps(
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/oidc/auth",
            "token_endpoint": "https://example.com/oidc/token",
            "userinfo_endpoint": "https://example.com/oidc/userinfo",
            "revocation_endpoint": "https://example.com/oidc/revoke",
            "jwks_uri": "https://example.com/oidc/certs",
        }
    )

    expected_username = "cartman"

    def pre_complete_callback(self, start_url) -> None:
        super().pre_complete_callback(start_url)
        responses.add(
            responses.GET,
            url=self.backend.userinfo_url(),
            status=200,
            body=json.dumps({"preferred_username": self.expected_username}),
            content_type="text/json",
        )

    def test_everything_works(self) -> None:
        self.do_login()

    def test_login_hint_in_auth_params(self) -> None:
        params = self.backend.auth_params(state=self.backend.get_or_create_state())
        self.assertEqual(params["login_hint"], "user@example.com")


class OpenIdConnectWithIdTokenHint(ExampleOpenIdConnectAuth):
    ID_TOKEN_HINT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.fake"


class ExampleOpenIdConnectIdTokenHintTest(OpenIdConnectTest):
    backend_path = (
        "social_core.tests.backends.test_open_id_connect.OpenIdConnectWithIdTokenHint"
    )
    issuer = "https://example.com"
    openid_config_body = json.dumps(
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/oidc/auth",
            "token_endpoint": "https://example.com/oidc/token",
            "userinfo_endpoint": "https://example.com/oidc/userinfo",
            "revocation_endpoint": "https://example.com/oidc/revoke",
            "jwks_uri": "https://example.com/oidc/certs",
        }
    )

    expected_username = "cartman"

    def pre_complete_callback(self, start_url) -> None:
        super().pre_complete_callback(start_url)
        responses.add(
            responses.GET,
            url=self.backend.userinfo_url(),
            status=200,
            body=json.dumps({"preferred_username": self.expected_username}),
            content_type="text/json",
        )

    def test_everything_works(self) -> None:
        self.do_login()

    def test_id_token_hint_in_auth_params(self) -> None:
        params = self.backend.auth_params(state=self.backend.get_or_create_state())
        self.assertEqual(
            params["id_token_hint"],
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.fake",
        )


class OpenIdConnectWithUiLocales(ExampleOpenIdConnectAuth):
    UI_LOCALES = "en-US fr-CA"


class ExampleOpenIdConnectUiLocalesTest(OpenIdConnectTest):
    backend_path = (
        "social_core.tests.backends.test_open_id_connect.OpenIdConnectWithUiLocales"
    )
    issuer = "https://example.com"
    openid_config_body = json.dumps(
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/oidc/auth",
            "token_endpoint": "https://example.com/oidc/token",
            "userinfo_endpoint": "https://example.com/oidc/userinfo",
            "revocation_endpoint": "https://example.com/oidc/revoke",
            "jwks_uri": "https://example.com/oidc/certs",
        }
    )

    expected_username = "cartman"

    def pre_complete_callback(self, start_url) -> None:
        super().pre_complete_callback(start_url)
        responses.add(
            responses.GET,
            url=self.backend.userinfo_url(),
            status=200,
            body=json.dumps({"preferred_username": self.expected_username}),
            content_type="text/json",
        )

    def test_everything_works(self) -> None:
        self.do_login()

    def test_ui_locales_in_auth_params(self) -> None:
        params = self.backend.auth_params(state=self.backend.get_or_create_state())
        self.assertEqual(params["ui_locales"], "en-US fr-CA")


class OpenIdConnectWithInvalidParams(ExampleOpenIdConnectAuth):
    """Test invalid empty parameter values"""


class ExampleOpenIdConnectInvalidParamsTest(OpenIdConnectTest):
    backend_path = (
        "social_core.tests.backends.test_open_id_connect.OpenIdConnectWithInvalidParams"
    )
    issuer = "https://example.com"
    openid_config_body = json.dumps(
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/oidc/auth",
            "token_endpoint": "https://example.com/oidc/token",
            "userinfo_endpoint": "https://example.com/oidc/userinfo",
            "revocation_endpoint": "https://example.com/oidc/revoke",
            "jwks_uri": "https://example.com/oidc/certs",
        }
    )

    expected_username = "cartman"

    def test_empty_acr_values_raises_error(self) -> None:
        with self.assertRaises(AuthConfigurationError):
            self.strategy.set_settings(
                {
                    **self.extra_settings(),
                    f"SOCIAL_AUTH_{self.backend.name.upper().replace('-', '_')}_ACR_VALUES": "",
                }
            )
            self.backend.auth_params(state=self.backend.get_or_create_state())

    def test_empty_login_hint_raises_error(self) -> None:
        with self.assertRaises(AuthConfigurationError):
            self.strategy.set_settings(
                {
                    **self.extra_settings(),
                    f"SOCIAL_AUTH_{self.backend.name.upper().replace('-', '_')}_LOGIN_HINT": "",
                }
            )
            self.backend.auth_params(state=self.backend.get_or_create_state())

    def test_empty_id_token_hint_raises_error(self) -> None:
        with self.assertRaises(AuthConfigurationError):
            self.strategy.set_settings(
                {
                    **self.extra_settings(),
                    f"SOCIAL_AUTH_{self.backend.name.upper().replace('-', '_')}_ID_TOKEN_HINT": "",
                }
            )
            self.backend.auth_params(state=self.backend.get_or_create_state())

    def test_empty_ui_locales_raises_error(self) -> None:
        with self.assertRaises(AuthConfigurationError):
            self.strategy.set_settings(
                {
                    **self.extra_settings(),
                    f"SOCIAL_AUTH_{self.backend.name.upper().replace('-', '_')}_UI_LOCALES": "",
                }
            )
            self.backend.auth_params(state=self.backend.get_or_create_state())


class OpenIdConnectJwksKeySelectionTest(OpenIdConnectTest):
    backend_path = (
        "social_core.tests.backends.test_open_id_connect.OpenIdConnectStrictJwksAuth"
    )
    issuer = "https://example.com"
    openid_config_body = json.dumps(
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/oidc/auth",
            "token_endpoint": "https://example.com/oidc/token",
            "userinfo_endpoint": "https://example.com/oidc/userinfo",
            "revocation_endpoint": "https://example.com/oidc/revoke",
            "jwks_uri": "https://example.com/oidc/certs",
        }
    )
    jwks_url = "https://example.com/oidc/certs"

    expected_username = "cartman"

    def setUp(self) -> None:
        super().setUp()
        refresh_state = patch.dict(
            "social_core.backends.open_id_connect.OpenIdConnectAuth._jwks_refresh_attempts",
            {},
        )
        refresh_state.start()
        self.addCleanup(refresh_state.stop)
        self.backend.get_jwks_keys_for_uri.invalidate()

    def pre_complete_callback(self, start_url) -> None:
        super().pre_complete_callback(start_url)
        responses.add(
            responses.GET,
            url=self.backend.userinfo_url(),
            status=200,
            body=json.dumps({"preferred_username": self.expected_username}),
            content_type="text/json",
        )

    @staticmethod
    def generate_rsa_jwk(kid: str = "testkey", **public_overrides):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_jwk = RSAAlgorithm.to_jwk(private_key, as_dict=True)
        public_jwk = RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
        private_jwk["kid"] = kid
        public_jwk["kid"] = kid
        public_jwk.update(public_overrides)
        return private_jwk, public_jwk

    @staticmethod
    def make_token(signing_key, algorithm: str = "RS256", kid: str | None = "testkey"):
        headers = {"kid": kid} if kid is not None else None
        return jwt.encode(
            {"sub": "1234"}, signing_key, algorithm=algorithm, headers=headers
        )

    @staticmethod
    def rsa_signing_key():
        return jwt.PyJWK(JWK_KEY).key

    def serve_jwks(self, keys) -> None:
        responses.replace(responses.GET, self.jwks_url, json={"keys": keys})
        self.backend.get_jwks_keys_for_uri.invalidate()

    def jwks_fetch_count(self) -> int:
        return sum(1 for call in responses.calls if call.request.url == self.jwks_url)

    def backend_setting(self, suffix: str) -> str:
        return f"SOCIAL_AUTH_{self.backend.name.upper().replace('-', '_')}_{suffix}"

    def test_login_with_key_without_use_and_alg(self) -> None:
        key = {
            name: value
            for name, value in JWK_PUBLIC_KEY.items()
            if name not in ("use", "alg")
        }
        self.serve_jwks([key])
        self.do_login()

    def test_jwks_use_enc_key_rejected(self) -> None:
        self.serve_jwks([{**JWK_PUBLIC_KEY, "use": "enc"}])
        token = self.make_token(self.rsa_signing_key())
        self.assertIsNone(self.backend.find_valid_key(token))

    def test_jwks_key_ops_without_verify_rejected(self) -> None:
        self.serve_jwks([{**JWK_PUBLIC_KEY, "key_ops": ["encrypt"]}])
        token = self.make_token(self.rsa_signing_key())
        self.assertIsNone(self.backend.find_valid_key(token))

    def test_jwks_key_ops_with_verify_accepted(self) -> None:
        self.serve_jwks([{**JWK_PUBLIC_KEY, "key_ops": ["verify"]}])
        token = self.make_token(self.rsa_signing_key())
        self.assertEqual(self.backend.find_valid_key(token)["kid"], "testkey")

    def test_jwk_alg_mismatch_rejected(self) -> None:
        self.serve_jwks([{**JWK_PUBLIC_KEY, "alg": "RS512"}])
        token = self.make_token(self.rsa_signing_key())
        self.assertIsNone(self.backend.find_valid_key(token))

    def test_kty_algorithm_mismatch_rejected(self) -> None:
        self.serve_jwks([{**JWK_PUBLIC_KEY, "kty": "EC"}])
        token = self.make_token(self.rsa_signing_key())
        self.assertIsNone(self.backend.find_valid_key(token))

    def test_header_algorithm_not_configured_rejected(self) -> None:
        token = self.make_token(self.rsa_signing_key(), algorithm="RS512")
        with assert_auth_error(self, AuthResponseError, "invalid_claim"):
            self.backend.find_valid_key(token)

    def test_none_algorithm_rejected_even_when_configured(self) -> None:
        self.strategy.set_settings(
            {
                **self.extra_settings(),
                self.backend_setting("JWT_ALGORITHMS"): ["RS256", "none"],
            }
        )
        token = self.make_token(None, algorithm="none", kid=None)
        with assert_auth_error(self, AuthResponseError, "invalid_claim"):
            self.backend.find_valid_key(token)

    def serve_symmetric_jwks(self, hmac_key: str, allow_symmetric: bool) -> str:
        self.strategy.set_settings(
            {
                **self.extra_settings(),
                self.backend_setting("JWT_ALGORITHMS"): ["HS256"],
                self.backend_setting("JWKS_ALLOW_SYMMETRIC_KEYS"): allow_symmetric,
            }
        )
        self.serve_jwks(
            [
                {
                    "kty": "oct",
                    "k": base64url_encode(hmac_key.encode()).decode(),
                    "kid": "testkey",
                    "alg": "HS256",
                }
            ]
        )
        return self.make_token(hmac_key, algorithm="HS256")

    def test_symmetric_jwks_key_rejected_by_default(self) -> None:
        token = self.serve_symmetric_jwks("test-hmac-key" * 4, allow_symmetric=False)
        self.assertIsNone(self.backend.find_valid_key(token))

    def test_symmetric_jwks_key_allowed_with_explicit_setting(self) -> None:
        token = self.serve_symmetric_jwks("test-hmac-key" * 4, allow_symmetric=True)
        self.assertEqual(self.backend.find_valid_key(token)["kid"], "testkey")

    def test_duplicate_kid_with_single_matching_key_accepted(self) -> None:
        _other_private_jwk, other_public_jwk = self.generate_rsa_jwk(kid="testkey")
        self.serve_jwks([other_public_jwk, JWK_PUBLIC_KEY])
        self.access_token_kwargs = {"kid": "testkey"}
        self.do_login()

    def test_duplicate_kid_with_multiple_matching_keys_rejected(self) -> None:
        self.serve_jwks([JWK_PUBLIC_KEY, dict(JWK_PUBLIC_KEY)])
        self.authtoken_raised("invalid_signature", kid="testkey")

    def test_unknown_kid_refresh_has_cooldown(self) -> None:
        self.backend.get_jwks_keys()
        self.assertEqual(self.jwks_fetch_count(), 1)
        now = [1000.0]
        with patch("social_core.backends.open_id_connect._monotonic", lambda: now[0]):
            for kid in ("unknown-1", "unknown-2"):
                token = self.make_token(self.rsa_signing_key(), kid=kid)
                self.assertIsNone(self.backend.find_valid_key(token))
            self.assertEqual(self.jwks_fetch_count(), 2)

            now[0] += self.backend.JWKS_REFRESH_COOLDOWN + 1
            token = self.make_token(self.rsa_signing_key(), kid="unknown-3")
            self.assertIsNone(self.backend.find_valid_key(token))
            self.assertEqual(self.jwks_fetch_count(), 3)

    def test_bad_signature_does_not_trigger_refresh(self) -> None:
        self.backend.get_jwks_keys()
        self.assertEqual(self.jwks_fetch_count(), 1)
        token = self.make_token(self.rsa_signing_key(), kid="testkey")
        header, message, _signature = token.rsplit(".")
        tampered = f"{header}.{message}.{'A' * 43}"
        self.assertIsNone(self.backend.find_valid_key(tampered))
        self.assertEqual(self.jwks_fetch_count(), 1)

    def test_failed_refresh_preserves_cached_keys(self) -> None:
        original_keys = self.backend.get_jwks_keys()
        responses.replace(
            responses.GET,
            self.jwks_url,
            body=requests.ConnectionError("jwks unavailable"),
        )
        token = self.make_token(self.rsa_signing_key(), kid="unknown-kid")
        self.assertIsNone(self.backend.find_valid_key(token))
        self.assertEqual(self.jwks_fetch_count(), 2)
        self.assertEqual(self.backend.get_jwks_keys(), original_keys)

        valid_token = self.make_token(self.rsa_signing_key(), kid="testkey")
        self.assertEqual(self.backend.find_valid_key(valid_token)["kid"], "testkey")

    def test_concurrent_refresh_is_single_flight(self) -> None:
        self.backend.get_jwks_keys()
        self.assertEqual(self.jwks_fetch_count(), 1)
        token = self.make_token(self.rsa_signing_key(), kid="unknown-kid")
        fetch_count = 0
        fetch_lock = threading.Lock()
        original = type(self.backend).get_remote_jwks_keys

        def counting_remote(backend, uri=None):
            nonlocal fetch_count
            with fetch_lock:
                fetch_count += 1
            time.sleep(0.2)
            return original(backend, uri)

        barrier = threading.Barrier(8)
        results = []

        def worker() -> None:
            barrier.wait()
            results.append(self.backend.find_valid_key(token))

        with patch.object(type(self.backend), "get_remote_jwks_keys", counting_remote):
            threads = [threading.Thread(target=worker) for _ in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        self.assertEqual(fetch_count, 1)
        self.assertEqual(results, [None] * 8)

    def test_legitimate_key_rotation(self) -> None:
        private_jwk, public_jwk = self.generate_rsa_jwk(kid="rotated-key")
        self.backend.get_jwks_keys()
        self.assertEqual(self.jwks_fetch_count(), 1)
        # Rotate the remote keys while the cache still holds the old ones.
        responses.replace(responses.GET, self.jwks_url, json={"keys": [public_jwk]})
        self.key = private_jwk
        self.access_token_kwargs = {"kid": "rotated-key"}
        self.do_login()
        self.assertEqual(self.jwks_fetch_count(), 2)
