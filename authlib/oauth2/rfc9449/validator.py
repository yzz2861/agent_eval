from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any
from typing import Callable
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

from joserfc.errors import JoseError
from joserfc.jwk import import_key
from joserfc.jws import deserialize_compact

from authlib.common.encoding import json_loads
from authlib.common.encoding import to_bytes
from authlib.common.encoding import to_unicode
from authlib.common.encoding import urlsafe_b64decode
from authlib.common.encoding import urlsafe_b64encode

from .errors import InvalidDPoPProofError
from .errors import UseDPoPNonceError
from .nonce import DPoPNoncePolicy
from .replay import DPoPReplayCache
from .replay import InMemoryDPoPReplayCache


DEFAULT_ALGORITHMS = (
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
    "Ed25519",
    "Ed448",
)


@dataclass(frozen=True)
class DPoPProof:
    raw: str
    header: dict[str, Any]
    claims: dict[str, Any]
    key: Any
    jkt: str


def canonical_request_uri(uri: str) -> str:
    parts = urlsplit(uri)
    path = parts.path or "/"
    return urlunsplit(
        (
            parts.scheme.lower(),
            parts.netloc.lower(),
            path,
            "",
            "",
        )
    )


def compare_request_uris(expected: str, provided: str) -> bool:
    expected_parts = urlsplit(expected)
    provided_parts = urlsplit(provided)
    if (
        expected_parts.scheme.lower() != provided_parts.scheme.lower()
        or (expected_parts.hostname or "").lower()
        != (provided_parts.hostname or "").lower()
    ):
        return False
    expected_port = expected_parts.port
    provided_port = provided_parts.port
    if expected_port != provided_port:
        default_ports = {"http": 80, "https": 443}
        default_port = default_ports.get(expected_parts.scheme.lower())
        expected_port = expected_port or default_port
        provided_port = provided_port or default_port
        if expected_port != provided_port:
            return False
    expected_path = expected_parts.path or "/"
    provided_path = provided_parts.path or "/"
    return expected_path == provided_path


def access_token_hash(access_token: str) -> str:
    digest = hashlib.sha256(to_bytes(access_token)).digest()
    return to_unicode(urlsafe_b64encode(digest))


def get_header(headers: Any, name: str) -> str | None:
    if headers is None:
        return None
    getlist = getattr(headers, "getlist", None)
    if callable(getlist):
        values = getlist(name)
        if len(values) > 1:
            raise InvalidDPoPProofError(f"Multiple '{name}' headers.")
        return values[0] if values else None
    if hasattr(headers, "items"):
        name = name.lower()
        values = [value for key, value in headers.items() if key.lower() == name]
        if len(values) > 1:
            raise InvalidDPoPProofError("Multiple 'DPoP' headers.")
        return values[0] if values else None
    return headers.get(name)


class DPoPProofValidator:
    DEFAULT_MAX_AGE = 300

    def __init__(
        self,
        target_uri: str | Callable[[Any], str] | None = None,
        *,
        algorithms=DEFAULT_ALGORITHMS,
        replay_cache: DPoPReplayCache | None = None,
        nonce_policy: DPoPNoncePolicy | None = None,
        leeway: int = 60,
        max_age: int = DEFAULT_MAX_AGE,
        replay_ttl: int | None = None,
        time_func: Callable[[], int | float] = time.time,
    ):
        self.target_uri = target_uri
        self.algorithms = tuple(algorithms)
        self.replay_cache = replay_cache or InMemoryDPoPReplayCache()
        self.nonce_policy = nonce_policy
        self.leeway = leeway
        self.max_age = max_age
        self.replay_ttl = max_age if replay_ttl is None else replay_ttl
        self.time_func = time_func

    def get_target_uri(self, request: Any) -> str:
        if self.target_uri is None:
            return request.uri
        if callable(self.target_uri):
            return self.target_uri(request)
        return self.target_uri

    def issue_nonce(self, request: Any) -> str | None:
        if self.nonce_policy is None:
            return None
        get_nonce = getattr(self.nonce_policy, "get_nonce", None)
        if callable(get_nonce):
            return get_nonce(request)
        return self.nonce_policy.issue(request)

    def validate_token_request(self, request: Any) -> DPoPProof:
        raw_proof = self.get_proof(request)
        if raw_proof is None:
            if self.nonce_policy is not None:
                raise UseDPoPNonceError(nonce=self.issue_nonce(request))
            raise InvalidDPoPProofError("Missing 'DPoP' header.")
        return self.validate_proof(request, raw_proof, request.method)

    def validate_resource_request(
        self, request: Any, access_token: str
    ) -> DPoPProof:
        raw_proof = self.get_proof(request)
        if raw_proof is None:
            if self.nonce_policy is not None:
                raise UseDPoPNonceError(nonce=self.issue_nonce(request))
            raise InvalidDPoPProofError("Missing 'DPoP' header.")
        proof = self.validate_proof(request, raw_proof, request.method, access_token)
        self.validate_ath(proof, access_token)
        return proof

    def get_proof(self, request: Any) -> str | None:
        return get_header(request.headers, "DPoP")

    def validate_proof(
        self,
        request: Any,
        raw_proof: str,
        method: str,
        access_token: str | None = None,
    ) -> DPoPProof:
        if not isinstance(raw_proof, str) or not raw_proof:
            raise InvalidDPoPProofError("Invalid 'DPoP' header.")

        try:
            parts = raw_proof.split(".")
            if len(parts) != 3:
                raise InvalidDPoPProofError()
            header_segment = parts[0]
            header = json_loads(urlsafe_b64decode(header_segment.encode("ascii")))
            if not isinstance(header, dict):
                raise InvalidDPoPProofError()
            alg = header.get("alg")
            if alg not in self.algorithms or alg == "none" or alg.startswith("HS"):
                raise InvalidDPoPProofError("Unsupported 'alg' header.")
            if header.get("typ") != "dpop+jwt":
                raise InvalidDPoPProofError("Invalid 'typ' header.")
            jwk = header.get("jwk")
            key = self.import_public_key(jwk)
            obj = deserialize_compact(
                raw_proof,
                key,
                algorithms=self.algorithms,
            )
            claims = self.parse_claims(obj.payload)
        except InvalidDPoPProofError:
            raise
        except JoseError as error:
            raise InvalidDPoPProofError() from error
        except (TypeError, ValueError) as error:
            raise InvalidDPoPProofError() from error

        self.validate_method(claims, method)
        self.validate_target(request, claims)
        self.validate_issued_at(claims)
        jti = self.validate_jti(claims)
        self.validate_ath_claim(claims, access_token is not None)
        self.validate_nonce(request, claims.get("nonce"))

        now = self.time_func()
        if not self.replay_cache.claim(jti, self.replay_ttl, now):
            raise InvalidDPoPProofError("The DPoP proof has already been used.")

        return DPoPProof(
            raw=raw_proof,
            header=header,
            claims=claims,
            key=key,
            jkt=key.thumbprint(),
        )

    def import_public_key(self, jwk: Any):
        if not isinstance(jwk, dict):
            raise InvalidDPoPProofError("Missing public 'jwk' header.")
        private_params = ("d", "p", "q", "dp", "dq", "qi", "k", "oth")
        if any(name in jwk for name in private_params):
            raise InvalidDPoPProofError("The DPoP JWK must be a public key.")
        key = import_key(jwk)
        if getattr(key, "is_private", False):
            raise InvalidDPoPProofError("The DPoP JWK must be a public key.")
        return key

    @staticmethod
    def parse_claims(payload: bytes) -> dict[str, Any]:
        try:
            claims = json_loads(payload)
        except (TypeError, ValueError) as error:
            raise InvalidDPoPProofError() from error
        if not isinstance(claims, dict):
            raise InvalidDPoPProofError()
        return claims

    @staticmethod
    def validate_method(claims: dict[str, Any], method: str):
        if claims.get("htm") != method.upper():
            raise InvalidDPoPProofError("Invalid 'htm' claim.")

    def validate_target(self, request: Any, claims: dict[str, Any]):
        expected = self.get_target_uri(request)
        htu = claims.get("htu")
        if not isinstance(htu, str):
            raise InvalidDPoPProofError("Missing 'htu' claim.")
        try:
            claim_parts = urlsplit(htu)
            if claim_parts.query or claim_parts.fragment:
                raise InvalidDPoPProofError(
                    "The 'htu' claim must not include query or fragment."
                )
            if not compare_request_uris(expected, htu):
                raise InvalidDPoPProofError("Invalid 'htu' claim.")
        except ValueError as error:
            raise InvalidDPoPProofError("Invalid 'htu' claim.") from error

    def validate_issued_at(self, claims: dict[str, Any]):
        iat = claims.get("iat")
        if not isinstance(iat, (int, float)) or isinstance(iat, bool):
            raise InvalidDPoPProofError("Invalid 'iat' claim.")
        now = self.time_func()
        if iat > now + self.leeway:
            raise InvalidDPoPProofError("The DPoP proof was issued in the future.")
        if now > iat + self.max_age + self.leeway:
            raise InvalidDPoPProofError("The DPoP proof has expired.")

    @staticmethod
    def validate_jti(claims: dict[str, Any]) -> str:
        jti = claims.get("jti")
        if not isinstance(jti, str) or not jti:
            raise InvalidDPoPProofError("Invalid 'jti' claim.")
        return jti

    @staticmethod
    def validate_ath_claim(proof: dict[str, Any], present: bool):
        ath = proof.get("ath")
        if present and not isinstance(ath, str):
            raise InvalidDPoPProofError("Missing 'ath' claim.")
        if not present and ath is not None:
            raise InvalidDPoPProofError("Unexpected 'ath' claim.")

    @staticmethod
    def validate_ath(proof: DPoPProof, access_token: str):
        if proof.claims.get("ath") != access_token_hash(access_token):
            raise InvalidDPoPProofError("Invalid 'ath' claim.")

    def validate_nonce(self, request: Any, nonce: str | None):
        if self.nonce_policy is None:
            return
        expected = self.issue_nonce(request)
        if not isinstance(nonce, str) or not self.nonce_policy.validate(nonce, request):
            raise UseDPoPNonceError(nonce=expected)

    @staticmethod
    def bind_token(token: dict[str, Any], proof: DPoPProof) -> dict[str, Any]:
        token["token_type"] = "DPoP"
        token["cnf"] = {"jkt": proof.jkt}
        return token
