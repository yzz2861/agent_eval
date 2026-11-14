Security
~~~~~~~~

- The revocation endpoint treats ``token_type_hint`` as a search hint. An
  unknown or mismatched hint falls back to all supported token types. Revoking
  a refresh token also revokes its access token, and the SQLAlchemy endpoint
  checks client ownership and writes the revocation atomically. Unknown,
  repeated and other-client tokens all get the same response, so the endpoint
  does not reveal whether a token exists.
