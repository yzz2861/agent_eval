from dataclasses import replace
from typing import Any, Dict, List, Optional, Union

from webauthn.helpers import generate_challenge, generate_user_handle
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.registration_policy import (
    coerce_registration_policy,
    resolve_exclude_credentials,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    PublicKeyCredentialHint,
)


def _generate_pub_key_cred_params(
    supported_algs: List[COSEAlgorithmIdentifier],
) -> List[PublicKeyCredentialParameters]:
    """
    Take an array of algorithm ID ints and return an array of PublicKeyCredentialParameters
    """
    return [PublicKeyCredentialParameters(type="public-key", alg=alg) for alg in supported_algs]


default_supported_pub_key_algs = [
    COSEAlgorithmIdentifier.EDDSA,  # -8
    COSEAlgorithmIdentifier.ECDSA_SHA_256,  # -7
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,  # -257
]
default_supported_pub_key_params = _generate_pub_key_cred_params(default_supported_pub_key_algs)


def generate_registration_options(
    *,
    rp_id: str,
    rp_name: str,
    user_name: str,
    user_id: Optional[bytes] = None,
    user_display_name: Optional[str] = None,
    challenge: Optional[bytes] = None,
    timeout: int = 60000,
    attestation: AttestationConveyancePreference = AttestationConveyancePreference.NONE,
    authenticator_selection: Optional[AuthenticatorSelectionCriteria] = None,
    exclude_credentials: Optional[List[PublicKeyCredentialDescriptor]] = None,
    supported_pub_key_algs: Optional[List[COSEAlgorithmIdentifier]] = None,
    hints: Optional[List[PublicKeyCredentialHint]] = None,
    existing_credentials: Optional[List[Any]] = None,
    registration_policy: Optional[Union[Any, Dict[str, Any]]] = None,
    policy: Optional[Union[Any, Dict[str, Any]]] = None,
    resident_key: Optional[ResidentKeyRequirement] = None,
    require_resident_key: Optional[bool] = None,
    user_verification: Optional[UserVerificationRequirement] = None,
    excluded_transports: Optional[List[Any]] = None,
    allowed_transports: Optional[List[Any]] = None,
    excluded_aaguids: Optional[List[Any]] = None,
    allowed_aaguids: Optional[List[Any]] = None,
    **kwargs: Any,
) -> PublicKeyCredentialCreationOptions:
    """Generate options for registering a credential via navigator.credentials.create()

    Args:
        `rp_id`: A unique, constant identifier for this Relying Party.
        `rp_name`: A user-friendly, readable name for the Relying Party.
        `user_name`: A value that will help the user identify which account this credential is associated with. Can be an email address, etc...
        (optional) `user_id`: A collection of random bytes that identify a user account. For privacy reasons it should NOT be something like an email address. Defaults to 64 random bytes.
        (optional) `user_display_name`: A user-friendly representation of their account. Can be a full name ,etc... Defaults to the value of `user_name`.
        (optional) `challenge`: A byte sequence for the authenticator to return back in its response. Defaults to 64 random bytes.
        (optional) `timeout`: How long in milliseconds the browser should give the user to choose an authenticator. This value is a *hint* and may be ignored by the browser.
        (optional) `attestation`: The level of attestation to be provided by the authenticator.
        (optional) `authenticator_selection`: Require certain characteristics about an authenticator, like attachment, support for resident keys, user verification, etc...
        (optional) `exclude_credentials`: A list of credentials the user has previously registered so that they cannot re-register them. Legacy callers can continue passing plain descriptors; when a policy is used these values are resolved through the same filtering rules as `existing_credentials`.
        (optional) `existing_credentials`: The user's stored credential records. Records may be `ExistingCredential` instances, dicts, or plain descriptors. Revoked/expired records are dropped, duplicate credential IDs are resolved, and only safe descriptor fields are emitted in `excludeCredentials`.
        (optional) `registration_policy`: A `RegistrationPolicy` (or equivalent dict) that groups credential exclusions and authenticator requirements. Explicit policy arguments below override matching policy values.
        (optional) `policy`: Alias for `registration_policy`.
        (optional) `resident_key`: Resident-key requirement, also expressible on the policy.
        (optional) `require_resident_key`: Legacy resident-key flag, also expressible on the policy.
        (optional) `user_verification`: User-verification requirement, also expressible on the policy.
        (optional) `excluded_transports`: Transport values that make a stored credential incompatible.
        (optional) `allowed_transports`: Transport values a stored credential must support when known.
        (optional) `excluded_aaguids`: Authenticator model AAGUIDs to exclude.
        (optional) `allowed_aaguids`: Authenticator model AAGUIDs to permit when known.
        (optional) `supported_pub_key_algs`: A list of public key algorithm IDs the RP chooses to restrict support to. Defaults to all supported algorithm IDs.

    Returns:
        Registration options ready for the browser. Consider using `helpers.options_to_json()` in this library to quickly convert the options to JSON.
    """

    if not rp_id:
        raise ValueError("rp_id cannot be an empty string")

    if not rp_name:
        raise ValueError("rp_name cannot be an empty string")

    if not user_name:
        raise ValueError("user_name cannot be an empty string")

    if user_id:
        if not isinstance(user_id, bytes):
            raise ValueError("user_id must be bytes")
    else:
        user_id = generate_user_handle()

    ########
    # Set defaults for required values
    ########

    if not user_display_name:
        user_display_name = user_name

    pub_key_cred_params = default_supported_pub_key_params
    if supported_pub_key_algs:
        pub_key_cred_params = _generate_pub_key_cred_params(supported_pub_key_algs)

    if not challenge:
        challenge = generate_challenge()

    if registration_policy is None and policy is None:
        registration_policy = kwargs.pop(
            "registration_options_policy", kwargs.pop("credential_policy", None)
        )
    if existing_credentials is None:
        for alias in (
            "credentials",
            "stored_credentials",
            "credential_records",
            "excluded_credentials",
            "existing_credential_records",
            "credential_descriptors",
        ):
            if alias in kwargs:
                existing_credentials = kwargs.pop(alias)
                break
    if excluded_transports is None:
        excluded_transports = kwargs.pop(
            "exclude_transports", kwargs.pop("transport_exclusions", None)
        )
    if allowed_transports is None:
        allowed_transports = kwargs.pop(
            "include_transports", kwargs.pop("transport_allowlist", None)
        )
    if excluded_aaguids is None:
        excluded_aaguids = kwargs.pop(
            "exclude_aaguids", kwargs.pop("aaguid_exclusions", None)
        )
    if allowed_aaguids is None:
        allowed_aaguids = kwargs.pop(
            "include_aaguids", kwargs.pop("aaguid_allowlist", None)
        )
    if kwargs:
        unexpected = next(iter(kwargs))
        raise TypeError(f"generate_registration_options() got an unexpected keyword argument {unexpected!r}")

    effective_policy = coerce_registration_policy(registration_policy or policy)

    policy_resident_key = (
        resident_key if resident_key is not None else effective_policy.resident_key
        if effective_policy is not None
        else None
    )
    policy_require_resident_key = (
        require_resident_key
        if require_resident_key is not None
        else effective_policy.require_resident_key
        if effective_policy is not None
        else None
    )
    policy_user_verification = (
        user_verification
        if user_verification is not None
        else effective_policy.user_verification
        if effective_policy is not None
        else None
    )
    policy_excluded_transports = (
        excluded_transports
        if excluded_transports is not None
        else effective_policy.excluded_transports
        if effective_policy is not None
        else None
    )
    policy_allowed_transports = (
        allowed_transports
        if allowed_transports is not None
        else effective_policy.allowed_transports
        if effective_policy is not None
        else None
    )
    policy_excluded_aaguids = (
        excluded_aaguids
        if excluded_aaguids is not None
        else effective_policy.excluded_aaguids
        if effective_policy is not None
        else None
    )
    policy_allowed_aaguids = (
        allowed_aaguids
        if allowed_aaguids is not None
        else effective_policy.allowed_aaguids
        if effective_policy is not None
        else None
    )

    if policy_resident_key is not None and not isinstance(
        policy_resident_key, ResidentKeyRequirement
    ):
        policy_resident_key = ResidentKeyRequirement(policy_resident_key)
    if policy_user_verification is not None and not isinstance(
        policy_user_verification, UserVerificationRequirement
    ):
        policy_user_verification = UserVerificationRequirement(policy_user_verification)

    legacy_exclude_credentials = exclude_credentials
    if not legacy_exclude_credentials:
        legacy_exclude_credentials = []

    has_policy_input = any(
        value is not None
        for value in (
            effective_policy,
            existing_credentials,
            policy_resident_key,
            policy_require_resident_key,
            policy_user_verification,
            policy_excluded_transports,
            policy_allowed_transports,
            policy_excluded_aaguids,
            policy_allowed_aaguids,
        )
    )
    has_record_input = any(
        not isinstance(credential, PublicKeyCredentialDescriptor)
        for credential in legacy_exclude_credentials
    )
    legacy_ids = [
        credential.id
        for credential in legacy_exclude_credentials
        if isinstance(credential, PublicKeyCredentialDescriptor)
    ]
    has_duplicate_legacy_ids = len(legacy_ids) != len(set(legacy_ids))

    if has_policy_input or has_record_input or has_duplicate_legacy_ids:
        records: List[Any] = []
        if effective_policy is not None and effective_policy.existing_credentials is not None:
            records.extend(effective_policy.existing_credentials)
        if existing_credentials is not None:
            records.extend(existing_credentials)
        records.extend(legacy_exclude_credentials)

        exclude_credentials = resolve_exclude_credentials(
            records,
            excluded_transports=policy_excluded_transports,
            allowed_transports=policy_allowed_transports,
            excluded_aaguids=policy_excluded_aaguids,
            allowed_aaguids=policy_allowed_aaguids,
            now=effective_policy.now if effective_policy is not None else None,
        )
    else:
        exclude_credentials = list(legacy_exclude_credentials)

    ########
    # Generate the actual options
    ########

    options = PublicKeyCredentialCreationOptions(
        rp=PublicKeyCredentialRpEntity(
            name=rp_name,
            id=rp_id,
        ),
        user=PublicKeyCredentialUserEntity(
            id=user_id,
            name=user_name,
            display_name=user_display_name,
        ),
        challenge=challenge,
        pub_key_cred_params=pub_key_cred_params,
        timeout=timeout,
        exclude_credentials=exclude_credentials,
        attestation=attestation,
        hints=hints,
    )

    ########
    # Set optional values if specified
    ########

    resolved_authenticator_selection: Optional[AuthenticatorSelectionCriteria] = None
    if authenticator_selection is not None:
        resolved_authenticator_selection = replace(authenticator_selection)

    policy_attachment = (
        effective_policy.authenticator_attachment
        if effective_policy is not None
        else None
    )
    if any(
        value is not None
        for value in (
            policy_attachment,
            policy_resident_key,
            policy_require_resident_key,
            policy_user_verification,
        )
    ):
        if resolved_authenticator_selection is None:
            resolved_authenticator_selection = AuthenticatorSelectionCriteria()

        if policy_attachment is not None:
            resolved_authenticator_selection.authenticator_attachment = policy_attachment
        if policy_resident_key is not None:
            resolved_authenticator_selection.resident_key = policy_resident_key
        if policy_require_resident_key is not None:
            resolved_authenticator_selection.require_resident_key = (
                policy_require_resident_key
            )
        if policy_user_verification is not None:
            resolved_authenticator_selection.user_verification = policy_user_verification

    if resolved_authenticator_selection is not None:
        # "Relying Parties SHOULD set [requireResidentKey] to true if, and only if,
        # residentKey is set to "required""
        #
        # See https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-requireresidentkey
        if (
            resolved_authenticator_selection.resident_key
            == ResidentKeyRequirement.REQUIRED
        ):
            resolved_authenticator_selection.require_resident_key = True
        options.authenticator_selection = resolved_authenticator_selection

    return options
