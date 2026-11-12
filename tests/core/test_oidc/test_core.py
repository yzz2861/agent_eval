import types

import pytest
from joserfc.errors import InvalidClaimError
from joserfc.errors import MissingClaimError

from authlib.deprecate import AuthlibDeprecationWarning
from authlib.oauth2.rfc6749 import AuthorizationServer
from authlib.oauth2.rfc6749 import InvalidRequestError
from authlib.oauth2.rfc6749.grants import AuthorizationEndpointMixin
from authlib.oauth2.rfc6749.grants import BaseGrant
from authlib.oauth2.rfc6749.grants import TokenEndpointMixin
from authlib.oidc.core import AuthorizationSessionMixin
from authlib.oidc.core import CodeIDToken
from authlib.oidc.core import HybridIDToken
from authlib.oidc.core import ImplicitIDToken
from authlib.oidc.core import OpenIDCode
from authlib.oidc.core import UserInfo
from authlib.oidc.core import get_claim_cls_by_response_type
from authlib.oidc.core.errors import LoginRequiredError
from authlib.oidc.core.grants.util import validate_request_prompt
from authlib.oidc.core.util import create_half_hash

USER = object()


def test_essential_claims():
    claims = CodeIDToken({}, {})
    with pytest.raises(MissingClaimError):
        claims.validate()
    claims = CodeIDToken(
        {"iss": "1", "sub": "1", "aud": "1", "exp": 10000, "iat": 100}, {}
    )
    claims.validate(1000)


def test_validate_auth_time():
    claims = CodeIDToken(
        {"iss": "1", "sub": "1", "aud": "1", "exp": 10000, "iat": 100}, {}
    )
    claims.params = {"max_age": 100}
    with pytest.raises(MissingClaimError):
        claims.validate(1000)

    claims["auth_time"] = "foo"
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)


def test_validate_nonce():
    claims = CodeIDToken(
        {"iss": "1", "sub": "1", "aud": "1", "exp": 10000, "iat": 100}, {}
    )
    claims.params = {"nonce": "foo"}
    with pytest.raises(MissingClaimError):
        claims.validate(1000)
    claims["nonce"] = "bar"
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)
    claims["nonce"] = "foo"
    claims.validate(1000)


def test_validate_amr():
    claims = CodeIDToken(
        {
            "iss": "1",
            "sub": "1",
            "aud": "1",
            "exp": 10000,
            "iat": 100,
            "amr": "invalid",
        },
        {},
    )
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)


@pytest.mark.parametrize("aud", ["1", ["1", "3"]])
def test_validate_aud(aud):
    """The audience must contain the client_id, even with an azp claim."""
    claims = CodeIDToken(
        {"iss": "1", "sub": "1", "aud": aud, "azp": "2", "exp": 10000, "iat": 100},
        {},
    )
    claims.params = {"client_id": "2"}
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)


def test_validate_azp():
    claims = CodeIDToken(
        {
            "iss": "1",
            "sub": "1",
            "aud": ["1", "2"],
            "exp": 10000,
            "iat": 100,
        },
        {},
    )
    claims.params = {"client_id": "2"}
    with pytest.raises(MissingClaimError):
        claims.validate(1000)

    claims["azp"] = "1"
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)

    claims["azp"] = "2"
    claims.validate(1000)


def test_validate_aud_single_value_must_be_string():
    """A single audience is a string; other JSON types are invalid."""
    for aud in (1, [1], ["1", 2], []):
        claims = CodeIDToken(
            {"iss": "1", "sub": "1", "aud": aud, "exp": 10000, "iat": 100},
            {"alg": "HS256"},
        )
        claims.params = {"client_id": "1"}
        with pytest.raises(InvalidClaimError):
            claims.validate(1000)


def test_validate_aud_single_element_array():
    """Issuers that always encode aud as an array keep working."""
    claims = CodeIDToken(
        {"iss": "1", "sub": "1", "aud": ["1"], "exp": 10000, "iat": 100},
        {"alg": "HS256"},
    )
    claims.params = {"client_id": "1"}
    claims.validate(1000)


def test_validate_multi_audience_requires_azp():
    """With several audiences, the current client needs an azp claim."""
    claims = CodeIDToken(
        {
            "iss": "1",
            "sub": "1",
            "aud": ["1", "2"],
            "exp": 10000,
            "iat": 100,
        },
        {"alg": "HS256"},
    )
    claims.params = {"client_id": "2"}
    with pytest.raises(MissingClaimError) as exc:
        claims.validate(1000)
    assert exc.value.claim == "azp"
    assert "client" not in str(exc.value)


def test_validate_multi_audience_wrong_azp():
    """An azp that is not the current client rejects a token issued to
    another client, even when its aud contains the current client."""
    claims = CodeIDToken(
        {
            "iss": "1",
            "sub": "1",
            "aud": ["1", "2"],
            "azp": "1",
            "exp": 10000,
            "iat": 100,
        },
        {"alg": "HS256"},
    )
    claims.params = {"client_id": "2"}
    with pytest.raises(InvalidClaimError) as exc:
        claims.validate(1000)
    assert exc.value.claim == "azp"

    claims["azp"] = "2"
    claims.validate(1000)


def test_validate_multi_audience_azp_type():
    """The azp claim, when present, is a client ID string."""
    claims = CodeIDToken(
        {
            "iss": "1",
            "sub": "1",
            "aud": ["1", "2"],
            "azp": ["2"],
            "exp": 10000,
            "iat": 100,
        },
        {"alg": "HS256"},
    )
    claims.params = {"client_id": "2"}
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)


def test_validate_at_hash():
    claims = CodeIDToken(
        {
            "iss": "1",
            "sub": "1",
            "aud": "1",
            "exp": 10000,
            "iat": 100,
            "at_hash": "a",
        },
        {},
    )
    claims.params = {"access_token": "a"}

    # invalid alg will raise too
    claims.header = {"alg": "HS222"}
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)

    claims.header = {"alg": "HS256"}
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)


def _id_token_claims(extra_claims=None, params=None, cls=CodeIDToken, alg="HS256"):
    claims = {
        "iss": "1",
        "sub": "1",
        "aud": "1",
        "exp": 10000,
        "iat": 100,
    }
    if extra_claims:
        claims.update(extra_claims)
    token_claims = cls(claims, {"alg": alg})
    token_claims.params = params or {}
    return token_claims


def test_validate_at_hash_matches_alg():
    """The half hash uses the JWS alg and is truncated to the left half."""
    access_token = "access-token-value"
    at_hash = create_half_hash(access_token, "HS256").decode("utf-8")
    claims = _id_token_claims({"at_hash": at_hash}, {"access_token": access_token})
    claims.validate(1000)


def test_validate_at_hash_wrong_alg():
    """A hash computed with another alg is rejected."""
    access_token = "access-token-value"
    at_hash = create_half_hash(access_token, "HS384").decode("utf-8")
    claims = _id_token_claims({"at_hash": at_hash}, {"access_token": access_token})
    with pytest.raises(InvalidClaimError) as exc:
        claims.validate(1000)
    assert exc.value.claim == "at_hash"
    assert access_token not in str(exc.value)


def test_validate_at_hash_truncated():
    """A half hash with missing characters is rejected."""
    access_token = "access-token-value"
    at_hash = create_half_hash(access_token, "HS256").decode("utf-8")
    claims = _id_token_claims({"at_hash": at_hash[:-1]}, {"access_token": access_token})
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)


def test_validate_at_hash_wrong_case():
    """at_hash is case-sensitive: changing the case rejects the token."""
    access_token = "access-token-value"
    at_hash = create_half_hash(access_token, "HS256").decode("utf-8")
    claims = _id_token_claims(
        {"at_hash": at_hash.swapcase()}, {"access_token": access_token}
    )
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)


def test_validate_at_hash_without_access_token():
    """In the code flow, at_hash cannot be checked without the access token
    and is then rejected instead of being accepted silently."""
    access_token = "access-token-value"
    at_hash = create_half_hash(access_token, "HS256").decode("utf-8")
    claims = _id_token_claims({"at_hash": at_hash})
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)


def test_implicit_at_hash_required_with_access_token():
    """id_token token requires at_hash when an access token is returned."""
    claims = _id_token_claims(
        params={"access_token": "access-token-value"}, cls=ImplicitIDToken
    )
    with pytest.raises(MissingClaimError) as exc:
        claims.validate(1000)
    assert exc.value.claim == "at_hash"


def test_implicit_at_hash_forbidden_without_access_token():
    """id_token never returns an access token, so at_hash is rejected."""
    claims = _id_token_claims({"at_hash": "whatever"}, cls=ImplicitIDToken)
    with pytest.raises(InvalidClaimError) as exc:
        claims.validate(1000)
    assert exc.value.claim == "at_hash"


def test_implicit_id_token_without_nonce():
    """The claims class only enforces nonce when the request sent one."""
    claims = _id_token_claims(cls=ImplicitIDToken)
    claims.validate(1000)


def test_hybrid_c_hash_matches_alg():
    code = "authorization-code-value"
    c_hash = create_half_hash(code, "HS256").decode("utf-8")
    claims = _id_token_claims({"c_hash": c_hash}, {"code": code}, cls=HybridIDToken)
    claims.validate(1000)


def test_hybrid_c_hash_wrong_case():
    code = "authorization-code-value"
    c_hash = create_half_hash(code, "HS256").decode("utf-8")
    claims = _id_token_claims(
        {"c_hash": c_hash.swapcase()}, {"code": code}, cls=HybridIDToken
    )
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)


def test_hybrid_c_hash_truncated():
    code = "authorization-code-value"
    c_hash = create_half_hash(code, "HS256").decode("utf-8")
    claims = _id_token_claims(
        {"c_hash": c_hash[:-2]}, {"code": code}, cls=HybridIDToken
    )
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)


def test_nonce_only_required_with_request_nonce():
    """Without a nonce in the request, the claim is optional."""
    claims = _id_token_claims()
    claims.validate(1000)


def test_nonce_missing_with_request_nonce():
    claims = _id_token_claims(params={"nonce": "foo"})
    with pytest.raises(MissingClaimError) as exc:
        claims.validate(1000)
    assert exc.value.claim == "nonce"


def test_nonce_replay_with_different_value():
    """A token whose nonce does not match the request nonce is rejected,
    with a constant-time comparison."""
    claims = _id_token_claims({"nonce": "bar"}, params={"nonce": "foo"})
    with pytest.raises(InvalidClaimError) as exc:
        claims.validate(1000)
    assert exc.value.claim == "nonce"
    assert "foo" not in str(exc.value)


def test_custom_claims_class_can_override_defaults():
    """Subclasses keep replacing individual validate_ methods."""

    class LenientCodeIDToken(CodeIDToken):
        def validate_at_hash(self):
            return None

    access_token = "access-token-value"
    at_hash = create_half_hash(access_token, "HS256").decode("utf-8")
    claims = _id_token_claims(
        {"at_hash": at_hash + "tampered"},
        {"access_token": access_token},
        cls=LenientCodeIDToken,
    )
    claims.validate(1000)


def test_implicit_id_token():
    claims = ImplicitIDToken(
        {
            "iss": "1",
            "sub": "1",
            "aud": "1",
            "exp": 10000,
            "iat": 100,
        },
        {},
    )
    claims.params = {"access_token": "a"}
    with pytest.raises(MissingClaimError):
        claims.validate(1000)


def test_hybrid_id_token():
    claims = HybridIDToken(
        {
            "iss": "1",
            "sub": "1",
            "aud": "1",
            "exp": 10000,
            "iat": 100,
            "nonce": "a",
        },
        {},
    )
    claims.validate(1000)

    claims.params = {"code": "a"}
    with pytest.raises(MissingClaimError):
        claims.validate(1000)

    # invalid alg will raise too
    claims.header = {"alg": "HS222"}
    claims["c_hash"] = "a"
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)

    claims.header = {"alg": "HS256"}
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)


def test_get_claim_cls_by_response_type():
    cls = get_claim_cls_by_response_type("id_token")
    assert cls == ImplicitIDToken
    cls = get_claim_cls_by_response_type("code")
    assert cls == CodeIDToken
    cls = get_claim_cls_by_response_type("code id_token")
    assert cls == HybridIDToken
    cls = get_claim_cls_by_response_type("token id_token")
    assert cls == ImplicitIDToken
    cls = get_claim_cls_by_response_type("token id_token code")
    assert cls == HybridIDToken
    cls = get_claim_cls_by_response_type("code code")
    assert cls is None
    cls = get_claim_cls_by_response_type(None)
    assert cls is None
    cls = get_claim_cls_by_response_type("none")
    assert cls is None


def test_userinfo_getattribute():
    user = UserInfo({"sub": "1"})
    assert user.sub == "1"
    assert user.email is None
    with pytest.raises(AttributeError):
        user.invalid  # noqa: B018


def test_userinfo_validate_locale():
    UserInfo({"sub": "1"}).validate_locale()
    UserInfo({"sub": "1", "locale": "en"}).validate_locale()
    UserInfo({"sub": "1", "locale": "en-US"}).validate_locale()
    UserInfo({"sub": "1", "locale": "zh-Hans-CN"}).validate_locale()
    UserInfo({"sub": "1", "locale": "x-custom"}).validate_locale()

    with pytest.raises(ValueError, match="BCP 47"):
        UserInfo({"sub": "1", "locale": "fr_FR"}).validate_locale()

    with pytest.raises(ValueError, match="BCP 47"):
        UserInfo({"sub": "1", "locale": "toolongsubtag"}).validate_locale()


def test_openid_code_on_custom_grant(monkeypatch):
    """OpenIDCode extends a grant that does not inherit AuthorizationCodeGrant."""
    calls = []

    class CustomCodeGrant(AuthorizationEndpointMixin, TokenEndpointMixin, BaseGrant):
        def validate_authorization_request_payload(self, redirect_uri):
            pass

        def validate_consent_request(self):
            return "https://client.test/cb"

        def create_token_response(self):
            return "token response"

    class RecordingOpenIDCode(OpenIDCode):
        def validate_openid_authorization_request(self, grant, redirect_uri):
            calls.append(("validate_openid_authorization_request", redirect_uri))

        def process_token(self, grant, response):
            calls.append(("process_token", response))

    monkeypatch.setattr(
        "authlib.oidc.core.grants.code.validate_request_prompt",
        lambda grant, redirect_uri, **kwargs: calls.append(
            ("validate_request_prompt", redirect_uri)
        ),
    )
    payload = types.SimpleNamespace(scope="openid", data={})
    request = types.SimpleNamespace(payload=payload)
    grant = CustomCodeGrant(request, None)
    RecordingOpenIDCode()(grant)

    grant.validate_authorization_request_payload("https://client.test/cb")
    grant.validate_consent_request()
    grant.create_token_response()

    assert calls == [
        ("validate_openid_authorization_request", None),
        ("validate_request_prompt", "https://client.test/cb"),
        ("process_token", "token response"),
    ]


class FixedSession(AuthorizationSessionMixin):
    """An authorization session with fixed times."""

    def __init__(self, request_time=None, account_selection_needed=False, **times):
        self.request_time = request_time
        self.account_selection_needed = account_selection_needed
        self.times = times

    def get_user(self):
        return USER

    def get_request_time(self, request):
        return self.request_time

    def get_interaction_time(self, request, interaction):
        return self.times.get(interaction)

    def is_account_selection_needed(self, request):
        return self.account_selection_needed


def validate_prompt(
    prompt=None, max_age=None, user=USER, session=None, default_max_age=None
):
    """Validate a request, and return its interactions."""
    data = {"prompt": prompt, "max_age": max_age}
    payload = types.SimpleNamespace(
        data={k: v for k, v in data.items() if v is not None}
    )
    client = types.SimpleNamespace(default_max_age=default_max_age)
    request_time = session.request_time if session else None
    request = types.SimpleNamespace(
        payload=payload, user=user, client=client, request_time=request_time
    )
    grant = types.SimpleNamespace(
        request=request,
        interactions=[],
        server=AuthorizationServer(),
        authorization_session=session,
    )
    validate_request_prompt(grant, None)
    return grant.interactions


@pytest.mark.parametrize("prompt", ["login", "consent", "select_account"])
def test_interaction_after_request_time(prompt):
    """An interaction that the request asks for is done when it happened
    after the start of the request."""
    for interaction_time, request_time in [(1000, 1000), (1000, 999.5)]:
        session = FixedSession(request_time, **{prompt: interaction_time})
        assert validate_prompt(prompt, session=session) == []

    session = FixedSession(1000, **{prompt: 999})
    assert validate_prompt(prompt, session=session) == [prompt]

    session = FixedSession(None, **{prompt: 10**12})
    assert validate_prompt(prompt, session=session) == [prompt]


def test_unknown_auth_time():
    """When the login time is unknown, the user must log in."""
    assert validate_prompt("login", session=FixedSession(0)) == ["login"]


def test_default_max_age():
    """The default_max_age client metadata applies without max_age."""
    session = FixedSession(1061, login=1000)
    assert validate_prompt(session=session, default_max_age=60) == ["login"]
    assert validate_prompt(session=session, default_max_age=-1) == []


def test_max_age_overrides_default_max_age():
    """The max_age parameter overrides default_max_age."""
    session = FixedSession(1061, login=1000)
    interactions = validate_prompt(max_age=3600, session=session, default_max_age=60)
    assert interactions == []


@pytest.mark.parametrize("max_age", [-1, True, 1.5, "abc"])
def test_max_age_invalid_value(max_age):
    """A negative, boolean, float or non-numeric max_age gives
    invalid_request."""
    with pytest.raises(InvalidRequestError):
        validate_prompt(max_age=max_age, session=FixedSession())


def test_account_selection_needed():
    """The authorization session can require the account selection. It is
    done when the user selects an account or logs in after the request
    started."""
    session = FixedSession(1000, login=0, account_selection_needed=True)
    assert validate_prompt(session=session) == ["select_account"]

    for times in [{"select_account": 1000, "login": 0}, {"login": 1000}]:
        session = FixedSession(1000, account_selection_needed=True, **times)
        assert validate_prompt(session=session) == []


@pytest.mark.parametrize(
    "params,interactions",
    [
        ({"prompt": "login"}, ["login"]),
        ({"max_age": 0}, ["login"]),
        ({"default_max_age": 0}, ["login"]),
        ({"max_age": 60}, []),
        ({"prompt": "consent"}, ["consent"]),
    ],
)
def test_without_authorization_session(params, interactions):
    """Without an authorization session, only prompt and max_age=0 add
    interactions, and a deprecation warning is shown."""
    with pytest.warns(AuthlibDeprecationWarning, match="authorization session"):
        assert validate_prompt(**params) == interactions


def test_consent_after_login():
    """After the login, prompt=consent still applies."""
    session = FixedSession(1000, login=1000)
    assert validate_prompt("login consent", session=session) == ["consent"]


def test_login_counts_as_account_selection():
    """A login after the start of the request satisfies
    prompt=select_account."""
    session = FixedSession(1000, login=1000)
    assert validate_prompt("select_account", session=session) == []

    session = FixedSession(1000, login=999)
    assert validate_prompt("select_account", session=session) == ["select_account"]


@pytest.mark.parametrize(
    "user,prompt,interactions",
    [
        (None, "select_account login consent", ["login", "consent"]),
        (USER, "consent select_account", ["select_account", "consent"]),
        (
            USER,
            "consent login select_account",
            ["login", "select_account", "consent"],
        ),
        (USER, "none", []),
    ],
)
def test_interactions(user, prompt, interactions):
    """The interactions are listed in order: login, account selection, then
    consent. An anonymous user selects their account when they log in."""
    session = FixedSession(login=0)
    assert validate_prompt(prompt, user=user, session=session) == interactions


def test_prompt_none_without_user():
    """With prompt=none, a needed login gives login_required right away."""
    with pytest.raises(LoginRequiredError):
        validate_prompt("none", user=None, session=FixedSession())


def test_anonymous_interactions():
    """For an anonymous user, the interactions that prompt asks for are added
    without looking at the session."""

    class FailingSession(FixedSession):
        def get_interaction_time(self, request, interaction):
            assert interaction == "login"

    interactions = validate_prompt(
        "consent select_account", user=None, session=FailingSession()
    )
    assert interactions == ["login", "consent"]
