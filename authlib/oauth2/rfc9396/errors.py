from ..base import OAuth2Error

__all__ = ["InvalidAuthorizationDetailsError"]


class InvalidAuthorizationDetailsError(OAuth2Error):
    """The request contains invalid RFC 9396 authorization details."""

    error = "invalid_authorization_details"
    description = "The authorization details are invalid, unsupported, or malformed."
    status_code = 400
