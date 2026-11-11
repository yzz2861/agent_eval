=================
Request Validator
=================

.. autoclass:: oauthlib.oauth2.RequestValidator
    :members:

Redirect URI registry
---------------------

Redirect URI matching is not enabled by default.  To use the explicit
registry, register the callback URIs for each client and pass the registry to
the grant (or to a preconfigured server)::

    from oauthlib.oauth2 import RedirectURIRegistry, WebApplicationServer

    redirect_uris = RedirectURIRegistry()
    redirect_uris.register('client-id', 'https://shop.example.com/callback')
    server = WebApplicationServer(
        your_validator, redirect_uri_registry=redirect_uris)

When a registry is attached, the authorization endpoint replaces the
request's redirect URI with its canonical match before the code is saved or
the browser is redirected.  The token endpoint canonicalizes the redirect URI
again and passes that same form to ``confirm_redirect_uri``, so the code is
always checked against the form that was bound to it.

The registry only normalizes differences with no semantic effect:

* scheme and host names are lowercased;
* the default port is removed for ``http`` and ``https``;
* percent escapes for unreserved characters are decoded and other escape hex
  digits are uppercased;
* a registered loopback callback without a port (``http://127.0.0.1/...`` or
  ``http://[::1]/...``) accepts any valid port, and the matched URI keeps the
  actual port; ``localhost`` and non-loopback hosts do not get this exception.

Everything else must match exactly, including path segments (consecutive
slashes and a trailing slash are significant) and the query string.  Dot
segments, path backslashes, userinfo, fragments, control characters, invalid
percent escapes, and hostnames with a trailing dot are rejected.  Wildcards
are not accepted, and registering two spellings that canonicalize to the same
URI for one client raises ``DuplicateRedirectURIError``.

.. autoclass:: oauthlib.oauth2.RedirectURIRegistry
    :members: register, register_many, canonicalize, match, is_registered
