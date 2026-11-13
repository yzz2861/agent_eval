import threading
import time

from joserfc import jwe
from joserfc import jwt
from joserfc.errors import DecodeError
from joserfc.errors import JoseError
from joserfc.errors import UnsupportedAlgorithmError
from joserfc.jws import JWSRegistry

from authlib._joserfc_helpers import audience_matches
from authlib._joserfc_helpers import import_any_key

from ..rfc6749 import AuthorizationServer
from ..rfc6749 import ClientMixin
from ..rfc6749 import InvalidClientError
from ..rfc6749 import InvalidRequestError
from ..rfc6749.requests import BasicOAuth2Payload
from ..rfc6749.requests import OAuth2Request
from .errors import DuplicateRequestParameterError
from .errors import InvalidRequestObjectError
from .errors import InvalidRequestUriError
from .errors import JTIReplayError
from .errors import RequestNotSupportedError
from .errors import RequestUriNotSupportedError


class _RequestObjectPayload(BasicOAuth2Payload):
    """The authorization request parameters of a request object."""


#: Authorization parameters whose value can never be silently overridden by
#: the request object when they are also sent in the query string or form.
PROTECTED_REQUEST_PARAMETERS = frozenset(
    {
        "client_id",
        "redirect_uri",
        "response_type",
        "scope",
        "state",
        "code_challenge",
        "code_challenge_method",
        "response_mode",
        "nonce",
    }
)

#: The JWS ``alg`` values that use a shared secret. Public JWK material must
#: never be used as an HMAC secret, so symmetric signatures are rejected
#: unless an integration explicitly allows them for the client.
SYMMETRIC_SIGNING_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})


class JWTAuthenticationRequest:
    """Authorization server extension implementing the support
    for JWT secured authentication request, as defined in :rfc:`RFC9101 <9101>`.

    :param support_request: Whether to enable support for the ``request`` parameter.
    :param support_request_uri: Whether to enable support for the ``request_uri`` parameter.
    :param require_iss: Require and validate the ``iss`` claim against the client.
    :param require_aud: Require the ``aud`` claim to identify this server.
    :param require_exp: Require the ``exp`` claim.
    :param require_jti: Require the ``jti`` claim and consume it atomically.
    :param allow_encrypted_request_object: Accept JWE request objects (disabled by default).
    :param allow_nested_request_object: Accept a signed request object nested in a JWE
        (disabled by default).

    This extension is intended to be inherited and registered into the authorization server::

        class JWTAuthenticationRequest(rfc9101.JWTAuthenticationRequest):
            def resolve_client_public_key(self, client: ClientMixin):
                return get_jwks_for_client(client)

            def validate_request_uri(self, request_uri: str, client: ClientMixin):
                return is_approved_request_uri(request_uri, client)

            def get_request_object(self, request_uri: str):
                # Apply the retrieval safeguards documented in get_request_object.
                return fetch_approved_request_object(request_uri)

            def get_server_metadata(self):
                return {
                    "issuer": ...,
                    "authorization_endpoint": ...,
                    "require_signed_request_object": ...,
                }

            def get_client_require_signed_request_object(self, client: ClientMixin):
                return client.require_signed_request_object


        authorization_server.register_extension(
            JWTAuthenticationRequest(require_jti=True, require_aud=True)
        )
    """

    #: Backwards compatible default registry; the actual options are built in
    #: :meth:`_build_claims_registry` from the strict policy flags.
    claims_validator = jwt.JWTClaimsRegistry(
        client_id={"essential": True},
    )

    def __init__(
        self,
        support_request: bool = True,
        support_request_uri: bool = True,
        require_iss: bool = False,
        require_aud: bool = False,
        require_exp: bool = False,
        require_jti: bool = False,
        allow_encrypted_request_object: bool = False,
        allow_nested_request_object: bool = False,
    ):
        self.support_request = support_request
        self.support_request_uri = support_request_uri
        self.require_iss = require_iss
        self.require_aud = require_aud
        self.require_exp = require_exp
        self.require_jti = require_jti
        self.allow_encrypted_request_object = allow_encrypted_request_object
        self.allow_nested_request_object = allow_nested_request_object
        self._jti_lock = threading.Lock()
        self._consumed_jtis: set[tuple[str, str]] = set()

    def __call__(self, authorization_server: AuthorizationServer):
        authorization_server.register_authorization_parameters(
            {"request": str, "request_uri": str}
        )
        authorization_server.register_hook(
            self.parse_authorization_request,
            before=AuthorizationServer.get_authorization_grant,
        )
        authorization_server.register_hook(
            self.validate_grant_parameter_types,
            after=AuthorizationServer.get_authorization_grant,
        )

    def get_request_object_signing_algorithms(self, client):
        """Return the supported algorithms for verifying the ``request_object`` JWT signature.
        By default, this method will only return the recommended algorithms. If signed request
        object is not required, "none" algorithm will be included. The signature
        requirement is enforced independently, even if this method returns "none".

        Developers can override this method to customize the supported algorithms::

            def get_request_object_signing_algorithms(self, client):
                return ["RS256"]
        """
        metadata = self.get_server_metadata()
        algorithms = metadata.get("request_object_signing_alg_values_supported")
        if not algorithms:
            require_signed1 = self.get_client_require_signed_request_object(client)
            require_signed2 = metadata.get("require_signed_request_object", False)
            if require_signed1 or require_signed2:
                algorithms = JWSRegistry.recommended
            else:
                algorithms = [*JWSRegistry.recommended, "none"]
        return algorithms

    def parse_authorization_request(
        self, authorization_server: AuthorizationServer, request: OAuth2Request
    ):
        client_id = request.payload.client_id
        if client_id is None:
            raise InvalidClientError(
                status_code=404,
                description="Missing 'client_id' parameter.",
            )

        client = authorization_server.query_client(client_id)
        if not client:
            raise InvalidClientError(
                status_code=404,
                description="The client does not exist on this server.",
            )

        if not self._shoud_proceed_with_request_object(request, client):
            return

        raw_request_object = self._get_raw_request_object(request, client)
        request_object = self._decode_request_object(
            request, client, raw_request_object
        )
        self._validate_parameter_conflicts(request, request_object.claims)
        _validate_parameter_types(
            request_object.claims,
            authorization_server.authorization_parameters,
            request.payload.state,
        )
        self._validate_request_object_claims(request, client, request_object)
        request.payload = _RequestObjectPayload(request_object.claims)

    def validate_grant_parameter_types(self, authorization_server, grant):
        """Check the JSON types of the request object parameters that the
        grant and its extensions declare.

        :param authorization_server: the authorization server
        :param grant: the grant chosen for the authorization request
        :raises InvalidRequestObjectError: if a parameter has an invalid type
        """
        payload = grant.request.payload
        if isinstance(payload, _RequestObjectPayload):
            _validate_parameter_types(
                payload.data, grant.authorization_parameters, payload.state
            )

    def _shoud_proceed_with_request_object(
        self,
        request: OAuth2Request,
        client: ClientMixin,
    ) -> bool:
        if "request" in request.payload.data and "request_uri" in request.payload.data:
            raise InvalidRequestError(
                "The 'request' and 'request_uri' parameters are mutually exclusive.",
                state=request.payload.state,
            )

        if "request" in request.payload.data:
            if not self.support_request:
                raise RequestNotSupportedError(state=request.payload.state)
            return True

        if "request_uri" in request.payload.data:
            if not self.support_request_uri:
                raise RequestUriNotSupportedError(state=request.payload.state)
            return True

        # When the value of it [require_signed_request_object] as client metadata is true,
        # then the server MUST reject the authorization request
        # from the client that does not conform to this specification.
        if self.get_client_require_signed_request_object(client):
            raise InvalidRequestError(
                "Authorization requests for this client must use signed request objects.",
                state=request.payload.state,
            )

        # When the value of it [require_signed_request_object] as server metadata is true,
        # then the server MUST reject the authorization request
        # from any client that does not conform to this specification.
        metadata = self.get_server_metadata()
        if metadata and metadata.get("require_signed_request_object", False):
            raise InvalidRequestError(
                "Authorization requests for this server must use signed request objects.",
                state=request.payload.state,
            )

        return False

    def _get_raw_request_object(
        self, request: OAuth2Request, client: ClientMixin
    ) -> str:
        if "request_uri" in request.payload.data:
            request_uri = request.payload.data["request_uri"]
            if not request_uri or not self.validate_request_uri(request_uri, client):
                raise InvalidRequestUriError(state=request.payload.state)
            raw_request_object = self.get_request_object(request_uri)
            if not raw_request_object:
                raise InvalidRequestUriError(state=request.payload.state)

        else:
            raw_request_object = request.payload.data["request"]

        return raw_request_object

    def _decode_request_object(
        self, request, client: ClientMixin, raw_request_object: str
    ):
        metadata = self.get_server_metadata() or {}
        segment_count = (
            raw_request_object.count(".") if isinstance(raw_request_object, str) else -1
        )
        if segment_count == 4:
            if not self.allow_encrypted_request_object:
                raise InvalidRequestObjectError(
                    description=(
                        "Encrypted request objects are not supported by this server."
                    ),
                    state=request.payload.state,
                )
            nested_raw = self._decrypt_request_object(
                request, client, raw_request_object
            )
            if not self.allow_nested_request_object:
                raise InvalidRequestObjectError(
                    description=(
                        "Nested request objects are not supported by this server."
                    ),
                    state=request.payload.state,
                )
            raw_request_object = nested_raw
        elif segment_count != 2:
            raise InvalidRequestObjectError(state=request.payload.state)

        return self._decode_signed_request_object(
            request, client, raw_request_object, metadata
        )

    def _decrypt_request_object(
        self, request, client: ClientMixin, raw_jwe: str
    ) -> str:
        key = import_any_key(self.resolve_client_private_key(client))
        algorithms = self.get_request_object_encryption_algorithms(client)
        try:
            if not algorithms:
                raise UnsupportedAlgorithmError()
            encrypted = jwe.decrypt_compact(raw_jwe, key, algorithms=algorithms)
            plaintext = encrypted.plaintext
        except UnsupportedAlgorithmError as error:
            raise InvalidRequestError(
                "Authorization requests must be encrypted with supported algorithms.",
                state=request.payload.state,
            ) from error
        except JoseError as error:
            raise InvalidRequestObjectError(
                description=error.description or InvalidRequestObjectError.description,
                state=request.payload.state,
            ) from error

        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as error:
            raise InvalidRequestObjectError(state=request.payload.state) from error

    def _decode_signed_request_object(
        self, request, client: ClientMixin, raw_request_object: str, metadata: dict
    ):
        jwks = self.resolve_client_public_key(client)
        key = import_any_key(jwks)
        algorithms = self.get_request_object_signing_algorithms(client)
        if self.get_client_require_signed_request_object(client) or metadata.get(
            "require_signed_request_object", False
        ):
            # Algorithm customization must not weaken the signature requirement.
            algorithms = [algorithm for algorithm in algorithms if algorithm != "none"]

        try:
            if not algorithms:
                raise UnsupportedAlgorithmError()
            request_object = jwt.decode(raw_request_object, key, algorithms=algorithms)
            self._check_algorithm_family(request_object.header, client)
            registry = self._build_claims_registry()
            registry.validate(request_object.claims)
        except UnsupportedAlgorithmError as error:
            raise InvalidRequestError(
                "Authorization requests must be signed with supported algorithms.",
                state=request.payload.state,
            ) from error
        except DecodeError as error:
            raise InvalidRequestObjectError(state=request.payload.state) from error
        except JoseError as error:
            raise InvalidRequestObjectError(
                description=error.description or InvalidRequestObjectError.description,
                state=request.payload.state,
            ) from error

        return request_object

    def _check_algorithm_family(self, header: dict, client: ClientMixin):
        """Reject symmetric signatures unless the integration allows them.

        The client public JWK must not be used as an HMAC secret. An
        integration that registers shared secrets may explicitly allow the
        ``HS*`` family for a client.
        """
        algorithm = header.get("alg")
        if (
            algorithm in SYMMETRIC_SIGNING_ALGORITHMS
            and not self.allow_symmetric_signing_algorithm(client)
        ):
            raise UnsupportedAlgorithmError()

    def _build_claims_registry(self) -> jwt.JWTClaimsRegistry:
        options = {
            "client_id": {"essential": True},
            "exp": {"essential": self.require_exp},
            "nbf": {"essential": False},
            "iat": {"essential": False},
            "jti": {"essential": self.require_jti},
        }
        return jwt.JWTClaimsRegistry(
            self.get_current_time,
            self.get_clock_leeway(),
            **options,
        )

    def _validate_request_object_claims(self, request, client: ClientMixin, token):
        claims = token.claims
        state = request.payload.state

        # The client ID values in the client_id request parameter and in
        # the Request Object client_id claim MUST be identical.
        if claims["client_id"] != request.payload.client_id:
            raise InvalidRequestError(
                "The 'client_id' claim from the request parameters "
                "and the request object claims don't match.",
                state=state,
            )

        self._validate_issuer(request, client, claims)
        self._validate_audience(request, claims)

        # The Request Object MAY be sent by value, as described in Section 5.1,
        # or by reference, as described in Section 5.2. request and
        # request_uri parameters MUST NOT be included in Request Objects.
        if "request" in claims or "request_uri" in claims:
            raise InvalidRequestError(
                "The 'request' and 'request_uri' parameters must not be included in the request object.",
                state=state,
            )

        # jti consumption is the last step: when a previous check fails, the
        # identifier must remain available and no state must be written.
        if self.require_jti:
            self._consume_jti(client, claims, state)

    def _validate_issuer(self, request, client: ClientMixin, claims):
        """Bind the request object to its client (and tenant).

        RFC 9101 §5.4: the ``iss`` claim, when present, MUST contain the
        client_id of the OAuth client that sent the request object. With the
        strict policy, a missing ``iss`` claim is rejected.
        """
        if not self.require_iss:
            return

        expected_issuer = self.get_expected_request_object_issuer(client)
        issuer = claims.get("iss")
        if not isinstance(issuer, str) or not self.issuer_matches_client(
            issuer, client, expected_issuer
        ):
            raise InvalidRequestObjectError(
                description="The 'iss' claim does not identify the client.",
                state=request.payload.state,
            )

    def _validate_audience(self, request, claims):
        if not self.require_aud and "aud" not in claims:
            return

        audiences = self.get_audiences()
        if not audiences or not audience_matches(claims.get("aud"), audiences):
            raise InvalidRequestObjectError(
                description="The 'aud' claim does not identify this server.",
                state=request.payload.state,
            )

    def _validate_parameter_conflicts(self, request, claims):
        """Reject security parameters present both outside and inside the
        request object with different values, instead of letting the request
        object silently override them.
        """
        outer = request.payload.data
        for name in PROTECTED_REQUEST_PARAMETERS:
            # client_id has its own mandatory equality check and error code.
            if name == "client_id":
                continue
            if name in outer and name in claims and outer[name] != claims[name]:
                raise DuplicateRequestParameterError(
                    description=(
                        f"The '{name}' parameter conflicts with the request object."
                    ),
                    state=request.payload.state,
                )

    def _consume_jti(self, client: ClientMixin, claims, state):
        jti = claims.get("jti")
        if not isinstance(jti, str) or not jti:
            raise InvalidRequestObjectError(
                description="The 'jti' claim must be a non-empty string.",
                state=state,
            )
        with self._jti_lock:
            if not self.consume_request_object_jti(client, jti):
                raise JTIReplayError(state=state)

    def validate_request_uri(self, request_uri: str, client: ClientMixin) -> bool:
        """Return whether ``request_uri`` may be retrieved for this client.

        Called before :meth:`get_request_object`. The default rejects every URI;
        applications supporting ``request_uri`` must implement a secure policy.
        For network retrieval, prevent SSRF, including private destinations and
        DNS rebinding. For references to locally stored request objects, validate
        that the object belongs to the requesting client.

        OIDC URI registration is handled by
        :class:`authlib.oidc.core.JWTAuthenticationRequest` independently of this
        application policy.
        """
        return False

    def get_request_object(self, request_uri: str):
        """Retrieve the request object at an approved ``request_uri``.

        This method must be implemented if ``request_uri`` is supported.
        For network retrieval, enforce HTTPS and restrict outbound connections
        to approved public destinations, including the resolved IP addresses.
        Do not follow redirects. Limit response size and retrieval time, and
        check the response media type, as described in :rfc:`9101` Section 10.4.1.

        The authorization view usually calls ``get_consent_grant`` twice, to
        show the consent page and to handle the answer of the user. Each call
        fetches the request object again, and the client can return a
        different one the second time. See :ref:`jar-consent-retention`.

        The following example adds HTTP response safeguards. The application's
        HTTP transport or network policy must also block private destinations
        and prevent DNS rebinding::

            def get_request_object(self, request_uri):
                try:
                    with requests.get(
                        request_uri,
                        timeout=(3, 5),
                        allow_redirects=False,
                        stream=True,
                        headers={"Accept": "application/oauth-authz-req+jwt"},
                    ) as response:
                        media_type = response.headers.get("Content-Type", "").split(
                            ";", 1
                        )[0]
                        if (
                            response.status_code != 200
                            or media_type != "application/oauth-authz-req+jwt"
                        ):
                            return None
                        content = bytearray()
                        for chunk in response.iter_content(chunk_size=4096):
                            content.extend(chunk)
                            if len(content) > 262144:
                                return None
                        return content.decode("utf-8")
                except (requests.RequestException, UnicodeError):
                    return None

        A timeout between reads is not an overall deadline. Also enforce an
        overall retrieval deadline in the transport or application.
        """
        raise NotImplementedError()

    def resolve_client_public_key(self, client: ClientMixin):
        """Resolve the client public key for verifying the JWT signature.
        A client may have many public keys, in this case, we can retrieve it
        via ``kid`` value in headers. Developers MUST implement this method::

            from joserfc import KeySet


            class JWTAuthenticationRequest(rfc9101.JWTAuthenticationRequest):
                def resolve_client_public_key(self, client):
                    if client.jwks_uri:
                        data = requests.get(client.jwks_uri).json()
                        return KeySet.import_key_set(data)

                    return KeySet.import_key_set(client.jwks)

        The key is the only signature key source: request objects are never
        verified with keys supplied in the request itself or fetched from an
        unapproved location, which prevents key-confusion attacks.
        """
        raise NotImplementedError()

    def resolve_client_private_key(self, client: ClientMixin):
        """Resolve the server-side private key for decrypting a JWE request object.

        Only called when :attr:`allow_encrypted_request_object` is enabled.
        Implementations must return key material registered for this client,
        never a key derived from the request itself. The default reuses
        :meth:`resolve_client_public_key` for clients that register a shared
        symmetric key.
        """
        return self.resolve_client_public_key(client)

    def get_request_object_encryption_algorithms(self, client: ClientMixin):
        """Return the accepted JWE ``alg``/``enc`` values for request objects.

        Override this to restrict key management and content encryption
        algorithms when :attr:`allow_encrypted_request_object` is enabled.
        An empty list rejects every encrypted request object.
        """
        metadata = self.get_server_metadata() or {}
        return metadata.get("request_object_encryption_alg_values_supported", [])

    def allow_symmetric_signing_algorithm(self, client: ClientMixin) -> bool:
        """Whether the client may sign request objects with an ``HS*`` algorithm.

        Return :data:`True` only when the client registered a shared secret
        intended for request object signatures. Asymmetric clients must keep
        rejecting symmetric algorithms so their public JWK cannot be used as
        an HMAC secret.
        """
        return False

    def get_current_time(self) -> int:
        """Return the current Unix timestamp used for every time claim check.

        ``exp``, ``nbf`` and ``iat`` are all evaluated against this single
        value, so one request object never mixes two clock readings.
        """
        return int(time.time())

    def get_clock_leeway(self) -> int:
        """Return the clock skew tolerance, in seconds, for time claims."""
        return 0

    def get_expected_request_object_issuer(self, client: ClientMixin) -> str:
        """Return the expected ``iss`` value of the client's request objects.

        Per RFC 9101 §5.4, this is the ``client_id`` of the client that sends
        the request object. Override it to bind the issuer to a tenant-specific
        identifier, and implement :meth:`issuer_matches_client` accordingly.
        """
        return client.get_client_id()

    def issuer_matches_client(
        self, issuer: str, client: ClientMixin, expected_issuer: str
    ) -> bool:
        """Return whether the request object ``iss`` belongs to the client.

        Multi-tenant deployments can override this to additionally verify that
        the issuer is scoped to the tenant that owns ``client``.
        """
        return issuer == expected_issuer

    def consume_request_object_jti(self, client: ClientMixin, jti: str) -> bool:
        """Atomically mark ``jti`` as consumed for the client.

        Return :data:`True` when the identifier was free and is now consumed,
        and :data:`False` when it was already consumed. The call runs inside a
        lock and only after every other validation succeeded, so a rejected
        request object never writes state.

        The default keeps identifiers in memory, which fits single-process
        deployments and tests. Production deployments should override it with
        an atomic database insert or a ``SET NX`` cache operation scoped to the
        client, with a retention window covering the request object lifetime::

            def consume_request_object_jti(self, client, jti):
                try:
                    db.session.add(
                        ConsumedJTI(client_id=client.get_client_id(), jti=jti)
                    )
                    db.session.commit()
            except IntegrityError:
                db.session.rollback()
                return False
            return True
        """
        key = (client.get_client_id(), jti)
        if key in self._consumed_jtis:
            return False
        self._consumed_jtis.add(key)
        return True

    def get_server_metadata(self) -> dict:
        """Return server metadata which includes supported grant types,
        response types and etc.

        When the ``require_signed_request_object`` claim is :data:`True`,
        all clients require that authorization requests
        use request objects, and an error will be returned when the authorization
        request payload is passed in the request body or query string::

            class JWTAuthenticationRequest(rfc9101.JWTAuthenticationRequest):
                def get_server_metadata(self):
                    return {
                        "issuer": ...,
                        "authorization_endpoint": ...,
                        "require_signed_request_object": ...,
                        "request_object_signing_alg_values_supported": ["RS256", ...],
                    }

        """
        return {}  # pragma: no cover

    def get_audiences(self) -> list[str]:
        """Return the accepted values of the request object ``aud`` claim.

        A request object with an ``aud`` claim is rejected when ``aud`` does not
        contain one of these values. When the strict audience policy is enabled,
        a request object without ``aud`` is also rejected. By default, it returns
        the ``issuer`` of :meth:`get_server_metadata`, or an empty list when there
        is none. Developers MAY re-implement it in subclass, for example to also
        accept the authorization endpoint URL::

            def get_audiences(self):
                metadata = self.get_server_metadata()
                return [metadata["issuer"], metadata["authorization_endpoint"]]

        :return: list of strings
        """
        issuer = (self.get_server_metadata() or {}).get("issuer")
        return [issuer] if issuer else []

    def get_client_require_signed_request_object(self, client: ClientMixin) -> bool:
        """Return the 'require_signed_request_object' client metadata.

        When :data:`True`, the client requires that authorization requests
        use request objects, and an error will be returned when the authorization
        request payload is passed in the request body or query string::

           class JWTAuthenticationRequest(rfc9101.JWTAuthenticationRequest):
               def get_client_require_signed_request_object(self, client):
                   return client.require_signed_request_object

        If not implemented, the value is considered as :data:`False`.
        """
        return False  # pragma: no cover


def _validate_parameter_types(claims, parameters, state):
    """Check the JSON types of the request object parameters."""
    # RFC 9101 §4: parameter names and string values MUST be included as
    # JSON strings. Numerical values MUST be included as JSON numbers.
    for name, expected_type in parameters.items():
        if name not in claims:
            continue

        value = claims[name]
        if isinstance(value, bool) or not isinstance(value, expected_type):
            raise InvalidRequestObjectError(
                description=f"The '{name}' parameter has an invalid type.",
                state=state,
            )
