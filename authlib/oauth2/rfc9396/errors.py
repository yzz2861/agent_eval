"""authlib.oauth2.rfc9396.errors.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Implementation for OAuth 2.0 Rich Authorization Requests error
responses, defined in RFC 9396_.

.. _RFC 9396: https://www.rfc-editor.org/rfc/rfc9396
"""

from authlib.oauth2.base import OAuth2Error

__all__ = ["InvalidAuthorizationDetailsError"]


class InvalidAuthorizationDetailsError(OAuth2Error):
    """The ``authorization_details`` parameter is invalid, contains an
    unknown or unsupported ``type``, or the requested authorization
    details exceed the ones granted by the resource owner.

    https://www.rfc-editor.org/rfc/rfc9396#section-5
    """

    error = "invalid_authorization_details"
    description = "The 'authorization_details' parameter is invalid."
