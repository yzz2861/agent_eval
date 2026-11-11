class WebAuthnException(Exception):
    pass


class InvalidRegistrationOptions(WebAuthnException):
    pass


class InvalidRegistrationResponse(WebAuthnException):
    pass


class InvalidAuthenticationOptions(WebAuthnException):
    pass


class InvalidAuthenticationResponse(WebAuthnException):
    pass


class InvalidPublicKeyStructure(WebAuthnException):
    pass


class UnsupportedPublicKeyType(WebAuthnException):
    pass


class InvalidJSONStructure(WebAuthnException):
    pass


class InvalidAuthenticatorDataStructure(WebAuthnException):
    pass


class SignatureVerificationException(WebAuthnException):
    pass


class UnsupportedAlgorithm(WebAuthnException):
    pass


class UnsupportedPublicKey(WebAuthnException):
    pass


class UnsupportedEC2Curve(WebAuthnException):
    pass


class InvalidTPMPubAreaStructure(WebAuthnException):
    pass


class InvalidTPMCertInfoStructure(WebAuthnException):
    pass


class InvalidCertificateChain(WebAuthnException):
    pass


class InvalidBackupFlags(WebAuthnException):
    pass


class InvalidCredentialBackupState(WebAuthnException):
    """Raised when an enabled credential backup state policy rejects a transition.

    The stable, machine-readable reason is available both as the exception's ``reason`` attribute
    and (as its string value) inside the exception message.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class InvalidCBORData(WebAuthnException):
    pass


class InvalidAttestationObjectStructure(WebAuthnException):
    pass
