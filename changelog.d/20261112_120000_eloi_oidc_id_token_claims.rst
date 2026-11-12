Security
~~~~~~~~

- The OpenID Connect ID Token claim classes centralize the cross-field
  validation of the code, implicit and hybrid flows. With multiple
  audiences the ``azp`` claim is required and must be the current client,
  so a token issued to another client can no longer be accepted. ``aud``
  must be a string or an array of strings. The ``at_hash`` and ``c_hash``
  claims are compared with the half hash of the JWS ``alg``, with a
  constant-time, case-sensitive comparison, and missing hashes are reported
  by claim name. ``nonce`` is only enforced when the request sent one.
