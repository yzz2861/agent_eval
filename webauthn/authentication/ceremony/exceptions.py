from webauthn.helpers.exceptions import WebAuthnException


class AuthenticationCeremonyException(WebAuthnException):
    """Base class for errors raised by the stateful authentication ceremony layer."""


class ChallengeNotFound(AuthenticationCeremonyException):
    """Raised when no challenge record exists for the challenge in a response.

    This covers both a challenge that was never issued and one that has already
    been consumed by an earlier submission.
    """


class ChallengeExpired(AuthenticationCeremonyException):
    """Raised when a challenge record exists but its expiry time has passed."""


class ChallengePurposeMismatch(AuthenticationCeremonyException):
    """Raised when a challenge was issued for a different ceremony purpose."""


class ChallengeAlreadyConsumed(AuthenticationCeremonyException):
    """Raised when a challenge record has already been consumed (replay)."""


class ChallengeUserMismatch(AuthenticationCeremonyException):
    """Raised when a response's userHandle does not match the bound user."""


class CredentialNotAllowed(AuthenticationCeremonyException):
    """Raised when the submitted credential is not in the challenge's allow list."""


class CredentialNotFound(AuthenticationCeremonyException):
    """Raised when no stored credential matches the submitted credential id."""


class CredentialRevoked(AuthenticationCeremonyException):
    """Raised when the submitted credential has been marked as revoked."""


class CredentialUserMismatch(AuthenticationCeremonyException):
    """Raised when the credential belongs to a different user than the challenge."""


class SignCountReplay(AuthenticationCeremonyException):
    """Raised when a non-zero sign count fails to strictly increase.

    A sign count that goes backwards or stays the same indicates a replayed
    authenticator assertion.
    """


class BackupStateChanged(AuthenticationCeremonyException):
    """Raised when a credential's backup eligibility flag changes after registration."""
