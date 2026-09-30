from ..base import OAuth2Error


class InvalidRequestUriError(OAuth2Error):
    error = "invalid_request_uri"
    description = "The request_uri is invalid, expired, or has already been used."
    status_code = 400
