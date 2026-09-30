from ..rfc6749 import OAuth2Error

__all__ = ["InvalidPushedRequestUriError"]


class InvalidPushedRequestUriError(OAuth2Error):
    error = "invalid_request_uri"
    description = "The request_uri is invalid, expired, or was already used."
    status_code = 400
