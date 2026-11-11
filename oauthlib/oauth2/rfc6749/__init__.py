"""
oauthlib.oauth2.rfc6749
~~~~~~~~~~~~~~~~~~~~~~~

This module is an implementation of various logic needed
for consuming and providing OAuth 2.0 RFC6749.
"""
import functools
import logging

from .endpoints.base import BaseEndpoint, catch_errors_and_unavailability
from .errors import (
    FatalClientError, OAuth2Error, ServerError, TemporarilyUnavailableError,
)
from .redirect_uri import (
    DuplicateRedirectURIError,
    RedirectURIError,
    RedirectURIMatcher,
    RedirectURIRegistry,
    RedirectUriRegistry,
    WildcardRedirectURIError,
    canonical_redirect_uri,
    canonicalize_redirect_uri,
    normalize_redirect_uri,
)

log = logging.getLogger(__name__)
