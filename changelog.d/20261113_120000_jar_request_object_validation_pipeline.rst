Added
~~~~~

- ``JWTAuthenticationRequest`` provides a built-in request object validation
  pipeline. The new ``require_iss``, ``require_aud``, ``require_exp`` and
  ``require_jti`` options enforce the ``iss``, ``aud``, ``exp``/``nbf``/``iat``
  and ``jti`` claims. ``jti`` values are consumed atomically, scoped to the
  client, via ``consume_request_object_jti``; the in-memory default can be
  replaced by an atomic database or cache operation. Symmetric ``HS*``
  signatures are rejected unless ``allow_symmetric_signing_algorithm`` opts in,
  and request object encryption and nested JWTs require the explicit
  ``allow_encrypted_request_object`` and ``allow_nested_request_object``
  switches, both disabled by default.

Security
~~~~~~~~

- Conflicting security parameters (``redirect_uri``, ``response_type``,
  ``state``, ``scope`` and PKCE parameters) sent both in the outer request and
  in the request object are now rejected with ``invalid_request_object`` instead
  of being silently overridden. This prevents request object replay across
  tenants together with the strict ``iss``, ``aud`` and single-use ``jti``
  checks.
