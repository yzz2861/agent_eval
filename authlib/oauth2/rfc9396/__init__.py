"""authlib.oauth2.rfc9396.
~~~~~~~~~~~~~~~~~~~~~~~

Implementation of OAuth 2.0 Rich Authorization Requests, defined in
RFC 9396. It introduces the ``authorization_details`` parameter that
allows clients to specify their fine-grained authorization requirements
using a JSON structure, across the authorization request, the token
response and token introspection.

https://www.rfc-editor.org/rfc/rfc9396
"""

from .errors import InvalidAuthorizationDetailsError
from .metadata import AuthorizationServerMetadata
from .registry import AuthorizationDetailsRegistry
from .registry import AuthorizationDetailsType
from .registry import dumps_authorization_details

__all__ = [
    "InvalidAuthorizationDetailsError",
    "AuthorizationServerMetadata",
    "AuthorizationDetailsRegistry",
    "AuthorizationDetailsType",
    "dumps_authorization_details",
]
