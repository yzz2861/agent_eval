from enum import Enum
from dataclasses import dataclass, field
from typing import Any, List, Literal, Optional, Union

from .cose import COSEAlgorithmIdentifier


################
#
# Fundamental data structures
#
################


class AuthenticatorTransport(str, Enum):
    """How an authenticator communicates to the client/browser.

    Members:
        `USB`: USB wired connection
        `NFC`: Near Field Communication
        `BLE`: Bluetooth Low Energy
        `INTERNAL`: Direct connection (read: a platform authenticator)
        `CABLE`: Cloud Assisted Bluetooth Low Energy
        `HYBRID`: A combination of (often separate) data-transport and proximity mechanisms

    https://www.w3.org/TR/webauthn-2/#enum-transport
    """

    USB = "usb"
    NFC = "nfc"
    BLE = "ble"
    SMART_CARD = "smart-card"
    INTERNAL = "internal"
    CABLE = "cable"
    HYBRID = "hybrid"


class AuthenticatorAttachment(str, Enum):
    """How an authenticator is connected to the client/browser.

    Members:
        `PLATFORM`: A non-removable authenticator, like TouchID or Windows Hello
        `CROSS_PLATFORM`: A "roaming" authenticator, like a YubiKey

    https://www.w3.org/TR/webauthn-2/#enumdef-authenticatorattachment
    """

    PLATFORM = "platform"
    CROSS_PLATFORM = "cross-platform"


class ResidentKeyRequirement(str, Enum):
    """The Relying Party's preference for the authenticator to create a dedicated "client-side" credential for it. Requiring an authenticator to store a dedicated credential should not be done lightly due to the limited storage capacity of some types of authenticators.

    Members:
        `DISCOURAGED`: The authenticator should not create a dedicated credential
        `PREFERRED`: The authenticator can create and store a dedicated credential, but if it doesn't that's alright too
        `REQUIRED`: The authenticator MUST create a dedicated credential. If it cannot, the RP is prepared for an error to occur.

    https://www.w3.org/TR/webauthn-2/#enum-residentKeyRequirement
    """

    DISCOURAGED = "discouraged"
    PREFERRED = "preferred"
    REQUIRED = "required"


class UserVerificationRequirement(str, Enum):
    """The degree to which the Relying Party wishes to verify a user's identity.

    Members:
        `REQUIRED`: User verification must occur
        `PREFERRED`: User verification would be great, but if not that's okay too
        `DISCOURAGED`: User verification should not occur, but it's okay if it does

    https://www.w3.org/TR/webauthn-2/#enumdef-userverificationrequirement
    """

    REQUIRED = "required"
    PREFERRED = "preferred"
    DISCOURAGED = "discouraged"


class AttestationConveyancePreference(str, Enum):
    """The Relying Party's interest in receiving an attestation statement.

    Members:
        `NONE`: The Relying Party isn't interested in receiving an attestation statement
        `INDIRECT`: The Relying Party is interested in an attestation statement, but the client is free to generate it as it sees fit
        `DIRECT`: The Relying Party is interested in an attestation statement generated directly by the authenticator
        `ENTERPRISE`: The Relying Party is interested in a statement with identifying information. Typically used within organizations

    https://www.w3.org/TR/webauthn-2/#enum-attestation-convey
    """

    NONE = "none"
    INDIRECT = "indirect"
    DIRECT = "direct"
    ENTERPRISE = "enterprise"


class PublicKeyCredentialType(str, Enum):
    """The type of credential that should be returned by an authenticator. There's but a single member because this is a specific subclass of a higher-level `CredentialType` that can be of other types.

    Members:
        `PUBLIC_KEY`: The literal string `"public-key"`

    https://www.w3.org/TR/webauthn-2/#enumdef-publickeycredentialtype
    """

    PUBLIC_KEY = "public-key"


class AttestationFormat(str, Enum):
    """The "syntax" of an attestation statement. Formats should be registered with the IANA and include documented signature verification steps.

    Members:
        `PACKED`
        `TPM`
        `ANDROID_KEY`
        `ANDROID_SAFETYNET`
        `FIDO_U2F`
        `APPLE`
        `NONE`

    https://www.iana.org/assignments/webauthn/webauthn.xhtml
    """

    PACKED = "packed"
    TPM = "tpm"
    ANDROID_KEY = "android-key"
    ANDROID_SAFETYNET = "android-safetynet"
    FIDO_U2F = "fido-u2f"
    APPLE = "apple"
    NONE = "none"


class ClientDataType(str, Enum):
    """Specific values included in authenticator registration and authentication responses to help avoid certain types of "signature confusion attacks".

    Members:
        `WEBAUTHN_CREATE`: The string "webauthn.create". Synonymous with `navigator.credentials.create()` in the browser
        `WEBAUTHN_GET`: The string "webauthn.get". Synonymous with `navigator.credentials.get()` in the browser

    https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-type
    """

    WEBAUTHN_CREATE = "webauthn.create"
    WEBAUTHN_GET = "webauthn.get"


class TokenBindingStatus(str, Enum):
    """
    https://www.w3.org/TR/webauthn-2/#dom-tokenbinding-status
    """

    PRESENT = "present"
    SUPPORTED = "supported"


class PublicKeyCredentialHint(str, Enum):
    """Categories of authenticators that Relying Parties can pass along to browsers during
    registration. Browsers that understand these values can optimize their modal experience to
    start the user off in a particular registration flow. These values are less strict than
    `authenticatorAttachment` (see `webauthn.helpers.strucAuthenticatorAttachment`)

    Members:
        `SECURITY_KEY`: A portable FIDO2 authenticator capable of being used on multiple devices via a USB or NFC connection
        `CLIENT_DEVICE`: The device that WebAuthn is being called on. Typically synonymous with platform authenticators
        `HYBRID`: A platform authenticator on a mobile device

    https://w3c.github.io/webauthn/#enumdef-publickeycredentialhint
    """

    SECURITY_KEY = "security-key"
    CLIENT_DEVICE = "client-device"
    HYBRID = "hybrid"


@dataclass
class TokenBinding:
    """
    https://www.w3.org/TR/webauthn-2/#dictdef-tokenbinding
    """

    status: TokenBindingStatus
    id: Optional[str] = None


@dataclass
class PublicKeyCredentialRpEntity:
    """Information about the Relying Party.

    Attributes:
        `name`: A user-readable name for the Relying Party
        (optional) `id`: A unique, constant value assigned to the Relying Party. Authenticators use this value to associate a credential with a particular Relying Party user

    https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialrpentity
    """

    name: str
    id: Optional[str] = None


@dataclass
class PublicKeyCredentialUserEntity:
    """Information about a user of a Relying Party.

    Attributes:
        `id`: An "opaque byte sequence" that uniquely identifies a user. Typically something like a UUID, but never user-identifying like an email address. Cannot exceed 64 bytes. These bytes should be stored internally alongside your normal user identifier and only used for WebAuthn.
        `name`: A value which a user can see to determine which account this credential is associated with. A username or email address is fine here.
        `display_name`: A user-friendly representation of a user, like a full name.

    https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialuserentity
    """

    id: bytes
    name: str
    display_name: str


@dataclass
class PublicKeyCredentialParameters:
    """Information about a cryptographic algorithm that may be used when creating a credential.

    Attributes:
        `type`: The literal string `"public-key"`
        `alg`: A numeric indicator of a particular algorithm

    https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialparameters
    """

    type: Literal["public-key"]
    alg: COSEAlgorithmIdentifier


@dataclass
class PublicKeyCredentialDescriptor:
    """Information about a generated credential.

    Attributes:
        `type`: The literal string `"public-key"`
        `id`: The sequence of bytes representing the credential's ID
        (optional) `transports`: The types of connections to the client/browser the authenticator supports

    https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialdescriptor
    """

    id: bytes
    type: Literal[PublicKeyCredentialType.PUBLIC_KEY] = PublicKeyCredentialType.PUBLIC_KEY
    transports: Optional[List[AuthenticatorTransport]] = None


@dataclass(init=False)
class ExistingCredential:
    """An existing credential, as stored by a Relying Party.

    This is intentionally richer than :class:`PublicKeyCredentialDescriptor`. Policy-related
    metadata (database identifiers, user handles, labels, revocation and expiry state) is used
    only while resolving registration options and is never copied into ``excludeCredentials``.

    Attributes:
        `credential_id`: The credential's WebAuthn ID
        (optional) `transports`: How the credential's authenticator communicates with clients
        (optional) `aaguid`: The authenticator model's AAGUID, useful for compatibility rules
        (optional) `revoked`: Whether the credential has been revoked
        (optional) `revoked_at`: When the credential was revoked, if applicable
        (optional) `expires_at`: When the credential expires, if applicable
        (optional) `database_id`: Internal database identifier. Never serialized into options
        (optional) `user_handle`: The user's WebAuthn handle. Never serialized into options
        (optional) `label`: A human-readable label. Never serialized into options
    """

    credential_id: bytes
    transports: Optional[List[AuthenticatorTransport]] = None
    aaguid: Optional[Union[str, bytes, Any]] = None
    revoked: bool = False
    revoked_at: Optional[Any] = None
    expires_at: Optional[Any] = None
    expired: Optional[bool] = None
    status: Optional[str] = None
    database_id: Optional[Any] = None
    user_handle: Optional[bytes] = None
    label: Optional[str] = None

    def __init__(
        self,
        credential_id: Optional[bytes] = None,
        *,
        id: Optional[bytes] = None,
        credentialId: Optional[bytes] = None,
        transports: Optional[List[AuthenticatorTransport]] = None,
        aaguid: Optional[Any] = None,
        revoked: bool = False,
        revoked_at: Optional[Any] = None,
        expires_at: Optional[Any] = None,
        expired: Optional[bool] = None,
        status: Optional[str] = None,
        database_id: Optional[Any] = None,
        db_id: Optional[Any] = None,
        internal_id: Optional[Any] = None,
        user_handle: Optional[bytes] = None,
        label: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        resolved_id = credential_id if credential_id is not None else credentialId
        if resolved_id is None:
            resolved_id = id
        if resolved_id is None:
            for alias in ("credentialID", "cred_id", "credential"):
                if kwargs.get(alias) is not None:
                    resolved_id = kwargs[alias]
                    break
        if resolved_id is None:
            raise ValueError("credential_id is required")

        self.credential_id = resolved_id
        self.transports = transports if transports is not None else kwargs.get("transport")
        self.aaguid = aaguid if aaguid is not None else kwargs.get("AAGUID")
        self.revoked = bool(
            revoked
            or kwargs.get("is_revoked", False)
            or kwargs.get("isRevoked", False)
        )
        self.revoked_at = (
            revoked_at
            if revoked_at is not None
            else kwargs.get("revokedAt", kwargs.get("revocation_date"))
        )
        self.expires_at = (
            expires_at
            if expires_at is not None
            else kwargs.get("expiresAt", kwargs.get("expiration", kwargs.get("expiry")))
        )
        self.expired = expired if expired is not None else kwargs.get("is_expired")
        self.status = status if status is not None else kwargs.get("state")
        self.database_id = (
            database_id
            if database_id is not None
            else db_id
            if db_id is not None
            else internal_id
        )
        self.user_handle = (
            user_handle
            if user_handle is not None
            else kwargs.get("userHandle")
        )
        self.label = label if label is not None else kwargs.get("name")

    @property
    def id(self) -> bytes:
        """Alias for `credential_id`, matching WebAuthn descriptor terminology."""
        return self.credential_id

    @id.setter
    def id(self, value: bytes) -> None:
        self.credential_id = value


# Descriptive aliases for callers that think in terms of a credential database record.
RegistrationCredentialRecord = ExistingCredential
StoredCredential = ExistingCredential
CredentialRecord = ExistingCredential
UserCredential = ExistingCredential


@dataclass(init=False)
class RegistrationPolicy:
    """Explicit policy for selecting credentials and authenticator requirements.

    Policy resolution is deterministic: revoked/expired records are removed, duplicate credential
    IDs are merged (or rejected when they identify different authenticators), incompatible
    transports/AAGUIDs are excluded, and the remaining descriptors are sorted by credential ID.

    Attributes:
        (optional) `existing_credentials`: Credentials already registered to the user
        (optional) `resident_key`: Desired resident-key support
        (optional) `require_resident_key`: Legacy companion to `resident_key`
        (optional) `user_verification`: Desired user-verification level
        (optional) `authenticator_attachment`: Desired authenticator attachment
        (optional) `excluded_transports`: A credential using any of these is incompatible
        (optional) `allowed_transports`: A credential must support one of these when known
        (optional) `excluded_aaguids`: Authenticator models to exclude
        (optional) `allowed_aaguids`: Authenticator models to allow when their AAGUID is known
        (optional) `now`: Time used to evaluate expiry. Defaults to the current UTC time
    """

    existing_credentials: Optional[List[Any]] = None
    resident_key: Optional[ResidentKeyRequirement] = None
    require_resident_key: Optional[bool] = None
    user_verification: Optional[UserVerificationRequirement] = None
    authenticator_attachment: Optional[AuthenticatorAttachment] = None
    excluded_transports: Optional[List[AuthenticatorTransport]] = None
    allowed_transports: Optional[List[AuthenticatorTransport]] = None
    excluded_aaguids: Optional[List[Any]] = None
    allowed_aaguids: Optional[List[Any]] = None
    now: Optional[Any] = None

    def __init__(
        self,
        existing_credentials: Optional[List[Any]] = None,
        *,
        credentials: Optional[List[Any]] = None,
        excluded_credentials: Optional[List[Any]] = None,
        exclude_credentials: Optional[List[Any]] = None,
        credential_descriptions: Optional[List[Any]] = None,
        credential_descriptors: Optional[List[Any]] = None,
        existing_credential_records: Optional[List[Any]] = None,
        resident_key: Optional[ResidentKeyRequirement] = None,
        require_resident_key: Optional[bool] = None,
        user_verification: Optional[UserVerificationRequirement] = None,
        authenticator_attachment: Optional[AuthenticatorAttachment] = None,
        excluded_transports: Optional[List[AuthenticatorTransport]] = None,
        allowed_transports: Optional[List[AuthenticatorTransport]] = None,
        excluded_aaguids: Optional[List[Any]] = None,
        allowed_aaguids: Optional[List[Any]] = None,
        now: Optional[Any] = None,
        **kwargs: Any,
    ) -> None:
        resolved_credentials = existing_credentials
        if resolved_credentials is None:
            resolved_credentials = credentials
        if resolved_credentials is None:
            resolved_credentials = excluded_credentials
        if resolved_credentials is None:
            resolved_credentials = exclude_credentials
        if resolved_credentials is None:
            resolved_credentials = credential_descriptions
        if resolved_credentials is None:
            resolved_credentials = credential_descriptors
        if resolved_credentials is None:
            resolved_credentials = existing_credential_records
        if resolved_credentials is None:
            resolved_credentials = kwargs.get("existingCredentialRecords")

        if resident_key is None and kwargs.get("residentKey") is not None:
            resident_key = kwargs["residentKey"]
        if resident_key is not None and not isinstance(
            resident_key, ResidentKeyRequirement
        ):
            resident_key = ResidentKeyRequirement(resident_key)
        if require_resident_key is None:
            require_resident_key = kwargs.get("requireResidentKey")
        if user_verification is None:
            user_verification = kwargs.get("userVerification")
        if isinstance(user_verification, str):
            user_verification = UserVerificationRequirement(user_verification)
        if authenticator_attachment is None:
            authenticator_attachment = kwargs.get("attachment")
        if authenticator_attachment is not None and not isinstance(
            authenticator_attachment, AuthenticatorAttachment
        ):
            authenticator_attachment = AuthenticatorAttachment(authenticator_attachment)

        if excluded_transports is None:
            excluded_transports = kwargs.get(
                "exclude_transports",
                kwargs.get(
                    "transport_exclusions",
                    kwargs.get(
                        "excludeTransports",
                        kwargs.get(
                            "blocked_transports",
                            kwargs.get("deny_transports"),
                        ),
                    ),
                ),
            )
        if allowed_transports is None:
            allowed_transports = kwargs.get(
                "include_transports", kwargs.get("allowedTransports")
            )
        if excluded_aaguids is None:
            excluded_aaguids = kwargs.get(
                "exclude_aaguids",
                kwargs.get(
                    "aaguid_exclusions",
                    kwargs.get(
                        "excludeAaguids",
                        kwargs.get(
                            "blocked_aaguids",
                            kwargs.get("deny_aaguids"),
                        ),
                    ),
                ),
            )
        if allowed_aaguids is None:
            allowed_aaguids = kwargs.get(
                "include_aaguids", kwargs.get("allowedAaguids")
            )

        self.existing_credentials = resolved_credentials
        self.resident_key = resident_key
        self.require_resident_key = require_resident_key
        self.user_verification = user_verification
        self.authenticator_attachment = authenticator_attachment
        self.excluded_transports = excluded_transports
        self.allowed_transports = allowed_transports
        self.excluded_aaguids = excluded_aaguids
        self.allowed_aaguids = allowed_aaguids
        self.now = now if now is not None else kwargs.get("current_time")

    @property
    def credentials(self) -> Optional[List[Any]]:
        return self.existing_credentials

    @credentials.setter
    def credentials(self, value: Optional[List[Any]]) -> None:
        self.existing_credentials = value

    @property
    def excluded_credentials(self) -> Optional[List[Any]]:
        return self.existing_credentials

    @excluded_credentials.setter
    def excluded_credentials(self, value: Optional[List[Any]]) -> None:
        self.existing_credentials = value


RegistrationOptionsPolicy = RegistrationPolicy
RegistrationCredentialPolicy = RegistrationPolicy
CredentialExclusionPolicy = RegistrationPolicy


@dataclass
class AuthenticatorSelectionCriteria:
    """A Relying Party's requirements for the types of authenticators that may interact with the client/browser.

    Attributes:
        (optional) `authenticator_attachment`: How the authenticator can be connected to the client/browser
        (optional) `resident_key`: Whether the authenticator should be able to store a credential on itself
        (optional) `require_resident_key`: DEPRECATED, set a value for `resident_key` instead
        (optional) `user_verification`: How the authenticator should be capable of determining user identity

    https://www.w3.org/TR/webauthn-2/#dictdef-authenticatorselectioncriteria
    """

    authenticator_attachment: Optional[AuthenticatorAttachment] = None
    resident_key: Optional[ResidentKeyRequirement] = None
    require_resident_key: Optional[bool] = False
    user_verification: Optional[UserVerificationRequirement] = (
        UserVerificationRequirement.PREFERRED
    )


@dataclass
class CollectedClientData:
    """Decoded ClientDataJSON

    Attributes:
        `type`: Either `"webauthn.create"` or `"webauthn.get"`, for registration and authentication ceremonies respectively
        `challenge`: The challenge passed to the authenticator within the options
        `origin`: The base domain with protocol on which the registration or authentication ceremony took place (e.g. "https://foo.bar")
        (optional) `cross_origin`: Whether or not the registration or authentication ceremony took place on a different origin (think within an <iframe>)
        (optional) `token_binding`: Information on the state of the Token Binding protocol

    https://www.w3.org/TR/webauthn-2/#dictdef-collectedclientdata
    """

    type: ClientDataType
    challenge: bytes
    origin: str
    cross_origin: Optional[bool] = None
    token_binding: Optional[TokenBinding] = None


################
#
# Registration
#
################


@dataclass
class PublicKeyCredentialCreationOptions:
    """Registration Options.

    Attributes:
        `rp`: Information about the Relying Party
        `user`: Information about the user
        `challenge`: A unique byte sequence to be returned by the authenticator. Helps prevent replay attacks
        `pub_key_cred_params`: Cryptographic algorithms supported by the Relying Party when verifying signatures
        (optional) `timeout`: How long the client/browser should give the user to interact with an authenticator
        (optional) `exclude_credentials`: A list of credentials associated with the user to prevent them from re-enrolling one of them
        (optional) `authenticator_selection`: Additional qualities about the authenticators the user can use to complete registration
        (optional) `hints`: Suggestions to the browser about the type of authenticator the user should try and register. Multiple values should be ordered by decreasing preference
        (optional) `attestation`: The Relying Party's desire for a declaration of an authenticator's provenance via attestation statement

    https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialcreationoptions
    """

    rp: PublicKeyCredentialRpEntity
    user: PublicKeyCredentialUserEntity
    challenge: bytes
    pub_key_cred_params: List[PublicKeyCredentialParameters]
    timeout: Optional[int] = None
    exclude_credentials: Optional[List[PublicKeyCredentialDescriptor]] = None
    authenticator_selection: Optional[AuthenticatorSelectionCriteria] = None
    hints: Optional[List[PublicKeyCredentialHint]] = None
    attestation: AttestationConveyancePreference = AttestationConveyancePreference.NONE


@dataclass
class AuthenticatorAttestationResponse:
    """The `response` property on a registration credential.

    Attributes:
        `client_data_json`: Information the authenticator collects about the client/browser it communicates with
        `attestation_object`: Encoded information about an attestation
        (optional) `transports`: The authenticator's supported methods of communication with a client/browser

    https://www.w3.org/TR/webauthn-2/#authenticatorattestationresponse
    """

    client_data_json: bytes
    attestation_object: bytes
    # Optional in L2, but becomes required in L3. Play it safe until L3 becomes Recommendation
    transports: Optional[List[AuthenticatorTransport]] = None


@dataclass
class RegistrationCredential:
    """A registration-specific subclass of PublicKeyCredential returned from `navigator.credentials.create()`

    Attributes:
        `id`: The Base64URL-encoded representation of raw_id
        `raw_id`: A byte sequence representing the credential's unique identifier
        `response`: The authenticator's attestation data
        `type`: The literal string `"public-key"`

    https://www.w3.org/TR/webauthn-2/#publickeycredential
    """

    id: str
    raw_id: bytes
    response: AuthenticatorAttestationResponse
    authenticator_attachment: Optional[AuthenticatorAttachment] = None
    type: Literal[PublicKeyCredentialType.PUBLIC_KEY] = PublicKeyCredentialType.PUBLIC_KEY


@dataclass
class AttestationStatement:
    """A collection of all possible fields that may exist in an attestation statement. Combinations of these fields are specific to a particular attestation format.

    https://www.w3.org/TR/webauthn-2/#sctn-defined-attestation-formats

    TODO: Decide if this is acceptable, or if we want to split this up into multiple
    format-specific classes that define only the fields that are present for a given
    attestation format.
    """

    sig: Optional[bytes] = None
    x5c: Optional[List[bytes]] = None
    response: Optional[bytes] = None
    alg: Optional[COSEAlgorithmIdentifier] = None
    ver: Optional[str] = None
    cert_info: Optional[bytes] = None
    pub_area: Optional[bytes] = None


@dataclass
class AuthenticatorDataFlags:
    """Flags the authenticator will set about information contained within the `attestationObject.authData` property.

    Attributes:
        `up`: [U]ser was [P]resent
        `uv`: [U]ser was [V]erified
        `be`: [B]ackup [E]ligible
        `bs`: [B]ackup [S]tate
        `at`: [AT]tested credential is included
        `ed`: [E]xtension [D]ata is included

    https://www.w3.org/TR/webauthn-2/#flags
    """

    up: bool
    uv: bool
    be: bool
    bs: bool
    at: bool
    ed: bool


@dataclass
class AttestedCredentialData:
    """Information about a credential.

    Attributes:
        `aaguid`: A 128-bit identifier indicating the type and vendor of the authenticator
        `credential_id`: The ID of the private/public key pair generated by the authenticator
        `credential_public_key`: The public key generated by the authenticator

    https://www.w3.org/TR/webauthn-2/#attested-credential-data
    """

    aaguid: bytes
    credential_id: bytes
    credential_public_key: bytes


@dataclass
class AuthenticatorData:
    """Context the authenticator provides about itself and the environment in which the registration or authentication ceremony took place.

    Attributes:
        `rp_id_hash`: A SHA-256 hash of the website origin on which the registration or authentication ceremony took place
        `flags`: Properties about the user and registration, where applicable
        `sign_count`: The number of times the credential was used
        (optional) `attested_credential_data`: Information about the credential created during a registration ceremony
        (optional) `extensions`: CBOR-encoded extension data corresponding to extensions specified in the registration or authentication ceremony options

    https://www.w3.org/TR/webauthn-2/#sctn-attestation
    https://www.w3.org/TR/webauthn-2/#sctn-attested-credential-data
    """

    rp_id_hash: bytes
    flags: AuthenticatorDataFlags
    sign_count: int
    attested_credential_data: Optional[AttestedCredentialData] = None
    extensions: Optional[bytes] = None


@dataclass
class AttestationObject:
    """Information about an attestation, including a statement and authenticator data.

    Attributes:
        `fmt`: The attestation statement's format
        `att_stmt`: An attestation statement to be verified according to the format
        `auth_data`: Contextual information provided by authenticator

    https://www.w3.org/TR/webauthn-2/#sctn-attestation
    """

    fmt: AttestationFormat
    auth_data: AuthenticatorData
    att_stmt: AttestationStatement = field(default_factory=AttestationStatement)


################
#
# Authentication
#
################


@dataclass
class PublicKeyCredentialRequestOptions:
    """Authentication Options.

    Attributes:
        `challenge`: A unique byte sequence to be returned by the authenticator. Helps prevent replay attacks
        (optional) `timeout`: How long the client/browser should give the user to interact with an authenticator
        (optional) `rp_id`: The unique, constant identifier assigned to the Relying Party
        (optional) `allow_credentials`: A list of credentials associated with the user that they can use to complete the authentication
        (optional) `user_verification`: How the authenticator should be capable of determining user identity

    https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options
    """

    challenge: bytes
    timeout: Optional[int] = None
    rp_id: Optional[str] = None
    allow_credentials: Optional[List[PublicKeyCredentialDescriptor]] = None
    user_verification: Optional[UserVerificationRequirement] = (
        UserVerificationRequirement.PREFERRED
    )


@dataclass
class AuthenticatorAssertionResponse:
    """The `response` property on an authentication credential.

    Attributes:
        `client_data_json`: Information the authenticator collects about the client/browser it communicates with
        `authenticator_data`: Contextual information provided by authenticator
        `signature`: A byte sequence signed by the authenticator's private key, to be verified with a user's public key
        (optional) `user_handle`: The user ID specified for the user during attestation

    https://www.w3.org/TR/webauthn-2/#authenticatorassertionresponse
    """

    client_data_json: bytes
    authenticator_data: bytes
    signature: bytes
    user_handle: Optional[bytes] = None


@dataclass
class AuthenticationCredential:
    """An authentication-specific subclass of PublicKeyCredential. Returned from `navigator.credentials.get()`

    Attributes:
        `id`: The Base64URL-encoded representation of raw_id
        `raw_id`: A byte sequence representing the credential's unique identifier
        `response`: The authenticator's assertion data
        `type`: The literal string `"public-key"`

    https://www.w3.org/TR/webauthn-2/#publickeycredential
    """

    id: str
    raw_id: bytes
    response: AuthenticatorAssertionResponse
    authenticator_attachment: Optional[AuthenticatorAttachment] = None
    type: Literal[PublicKeyCredentialType.PUBLIC_KEY] = PublicKeyCredentialType.PUBLIC_KEY


################
#
# Credential Backup State
#
################


class CredentialDeviceType(str, Enum):
    """A determination of the number of devices a credential can be used from

    Members:
        `SINGLE_DEVICE`: A credential that is bound to a single device
        `MULTI_DEVICE`: A credential that can be used from multiple devices (e.g. passkeys)

    https://w3c.github.io/webauthn/#sctn-credential-backup (L3 Draft)
    """

    SINGLE_DEVICE = "single_device"
    MULTI_DEVICE = "multi_device"
