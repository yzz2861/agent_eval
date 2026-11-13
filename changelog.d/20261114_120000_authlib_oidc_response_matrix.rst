Security
~~~~~~~~

- The OpenID Connect implicit and hybrid grants now validate their
  authorization responses against a response matrix shared with the
  ``IDToken`` claims validation, per OpenID Connect Core 1.0 Sections
  3.1.2.5, 3.2.2.5 and 3.3.2.5. A response with a missing, duplicated or
  non-string ``code``, ``id_token`` or ``access_token`` is refused with a
  ``server_error``, and the code and the token are saved only once the
  whole response is valid, so a failure cannot leave a half-issued
  authorization behind. The ``nonce``, ``c_hash`` and ``at_hash`` claims
  are validated against the response they belong to, and must be strings.
