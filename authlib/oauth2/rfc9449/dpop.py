"""authlib.oauth2.rfc9449.dpop.
~~~~~~~~~~~~~~~~~~~~~~~~~~~

DPoP proof validation, per RFC 9449 Section 4.3. This module reuses
the JOSE implementation of ``authlib.jose``; no signature algorithm
is implemented here.

https://www.rfc-editor.org/rfc/rfc9449#section-4.3
"""

import hashlib
import time
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

from authlib.common.encoding import json_loads
from authlib.common.encoding import to_bytes
from authlib.common.encoding import to_unicode
from authlib.common.encoding import urlsafe_b64encode
from authlib.jose import JoseError
from authlib.jose import JsonWebKey
from authlib.jose import JsonWebSignature
from authlib.jose.errors import DecodeError
from authlib.jose.util import extract_header

from .errors import InvalidDPoPProofError
from .errors import UseDPoPNonceError

__all__ = ["DPoPProof", "DPoPProofValidator", "compute_ath", "normalize_htu"]

#: asymmetric JWS algorithms acceptable for DPoP proofs, per RFC 9449
#: Section 4.2: "the alg value MUST be an asymmetric algorithm ...
#: and MUST NOT be none or a symmetric (MAC) algorithm"
DEFAULT_ALLOWED_ALGS = (
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES256K",
    "ES384",
    "ES512",
    "EdDSA",
)


def normalize_htu(url):
    """Normalize an HTTP URI for ``htu`` comparison, per RFC 9449
    Section 4.3: the query and fragment parts are omitted, scheme and
    host are case-insensitive, and default ports are ignored. The
    query string is never part of the binding value.
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"Invalid port in URI: {url!r}") from exc
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    netloc = host if port is None else f"{host}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, "", ""))


def compute_ath(access_token):
    """Compute the ``ath`` value of an access token, per RFC 9449
    Section 4.2: base64url-encoded SHA-256 hash of the token, without
    padding."""
    digest = hashlib.sha256(to_bytes(access_token)).digest()
    return to_unicode(urlsafe_b64encode(digest)).rstrip("=")


class DPoPProof:
    """A validated DPoP proof.

    :param header: the JWS protected header of the proof
    :param claims: the JWT claims set of the proof
    :param key: the public key embedded in the proof ``jwk`` header
    """

    def __init__(self, header, claims, key):
        self.header = header
        self.claims = claims
        self.key = key

    @property
    def jkt(self):
        """The JWK SHA-256 thumbprint of the proof public key, used as
        the ``cnf.jkt`` confirmation value of DPoP-bound tokens."""
        return self.key.thumbprint().rstrip("=")


class DPoPProofValidator:
    """Validate DPoP proofs bound to an HTTP request.

    :param allowed_algs: acceptable JWS ``alg`` values; defaults to
        :data:`DEFAULT_ALLOWED_ALGS`. Symmetric algorithms and ``none``
        are always rejected.
    :param replay_store: a :class:`DPoPReplayStore` for ``jti`` replay
        detection; replay checking is skipped when ``None``
    :param nonce_provider: an optional :class:`DPoPNonceProvider`; when
        set, proofs must carry a valid ``nonce`` claim
    :param max_age: maximum age of a proof in seconds
    :param leeway: clock skew leeway in seconds for ``iat`` checks
    :param now: callable returning the current POSIX timestamp,
        defaults to ``time.time``
    :param realm: realm value for ``WWW-Authenticate`` error headers
    """

    def __init__(
        self,
        allowed_algs=None,
        replay_store=None,
        nonce_provider=None,
        max_age=300,
        leeway=30,
        now=None,
        realm=None,
    ):
        self.allowed_algs = tuple(allowed_algs or DEFAULT_ALLOWED_ALGS)
        self.replay_store = replay_store
        self.nonce_provider = nonce_provider
        self.max_age = max_age
        self.leeway = leeway
        self._now = now or time.time
        self.realm = realm
        self._jws = JsonWebSignature(algorithms=list(self.allowed_algs))

    def error(self, description):
        return InvalidDPoPProofError(description, realm=self.realm)

    def validate_request(self, request, access_token=None):
        """Validate the ``DPoP`` header of an HTTP request.

        :param request: an object with ``method``, ``uri`` and
            ``headers`` attributes
        :param access_token: the access token of the request, required
            on protected resource requests for the ``ath`` check
        :return: a validated :class:`DPoPProof`
        """
        proof = request.headers.get("DPoP")
        if not proof:
            raise self.error("Missing DPoP proof.")
        return self.validate(proof, request.method, request.uri, access_token)

    def validate(self, proof, method, url, access_token=None):
        """Validate a DPoP proof JWT.

        :param proof: the compact JWS value of the ``DPoP`` header
        :param method: the HTTP method of the request
        :param url: the HTTP URI of the request
        :param access_token: the access token of the request, required
            on protected resource requests for the ``ath`` check
        :return: a validated :class:`DPoPProof`
        """
        header = self._extract_header(proof)
        key = self._validate_header(header)
        claims = self._verify_signature(proof, key)
        dpop_proof = DPoPProof(header, claims, key)
        self._validate_claims(claims, method, url, access_token)
        self._validate_nonce(claims)
        self._check_replay(dpop_proof)
        return dpop_proof

    def _extract_header(self, proof):
        try:
            proof = to_bytes(proof)
            header_segment = proof.split(b".", 1)[0]
            return extract_header(header_segment, DecodeError)
        except (JoseError, ValueError) as exc:
            raise self.error("Malformed DPoP proof.") from exc

    def _validate_header(self, header):
        typ = header.get("typ")
        if typ != "dpop+jwt":
            raise self.error("Invalid 'typ' value in DPoP proof, 'dpop+jwt' expected.")

        alg = header.get("alg")
        if (
            not alg
            or alg == "none"
            or alg.startswith("HS")
            or alg not in self.allowed_algs
        ):
            raise self.error(f"Invalid 'alg' value in DPoP proof: {alg!r}.")

        jwk = header.get("jwk")
        if not isinstance(jwk, dict):
            raise self.error("Missing 'jwk' header in DPoP proof.")
        if "d" in jwk:
            raise self.error("The 'jwk' header MUST NOT contain a private key.")

        try:
            return JsonWebKey.import_key(jwk)
        except (ValueError, JoseError) as exc:
            raise self.error("Invalid 'jwk' header in DPoP proof.") from exc

    def _verify_signature(self, proof, key):
        try:
            jws_obj = self._jws.deserialize_compact(proof, key, decode=json_loads)
        except (JoseError, ValueError) as exc:
            raise self.error("Invalid DPoP proof signature.") from exc
        if not isinstance(jws_obj.payload, dict):
            raise self.error("Invalid DPoP proof payload.")
        return jws_obj.payload

    def _validate_claims(self, claims, method, url, access_token):
        jti = claims.get("jti")
        if not isinstance(jti, str) or not jti:
            raise self.error("Missing or invalid 'jti' claim in DPoP proof.")

        htm = claims.get("htm")
        if not isinstance(htm, str) or htm.upper() != method.upper():
            raise self.error("Invalid 'htm' claim in DPoP proof.")

        htu = claims.get("htu")
        if not isinstance(htu, str):
            raise self.error("Missing 'htu' claim in DPoP proof.")
        try:
            htu_matches = normalize_htu(htu) == normalize_htu(url)
        except ValueError as exc:
            raise self.error("Invalid 'htu' claim in DPoP proof.") from exc
        if not htu_matches:
            raise self.error("Invalid 'htu' claim in DPoP proof.")

        iat = claims.get("iat")
        if isinstance(iat, bool) or not isinstance(iat, int):
            raise self.error("Missing or invalid 'iat' claim in DPoP proof.")
        now = self._now()
        if iat > now + self.leeway:
            raise self.error("The 'iat' claim of the DPoP proof is in the future.")
        if iat < now - self.max_age:
            raise self.error("The DPoP proof is too old.")

        if access_token is not None:
            ath = claims.get("ath")
            if not isinstance(ath, str) or ath != compute_ath(access_token):
                raise self.error("Invalid 'ath' claim in DPoP proof.")

    def _validate_nonce(self, claims):
        if self.nonce_provider is None:
            return
        nonce = claims.get("nonce")
        if not isinstance(nonce, str) or not self.nonce_provider.validate_nonce(nonce):
            raise UseDPoPNonceError(
                nonce=self.nonce_provider.get_nonce(), realm=self.realm
            )

    def _check_replay(self, proof):
        if self.replay_store is None:
            return
        key = f"{proof.jkt}:{proof.claims['jti']}"
        expires_at = proof.claims["iat"] + self.max_age
        if not self.replay_store.check_and_store(key, expires_at):
            raise self.error("Replayed DPoP proof.")
