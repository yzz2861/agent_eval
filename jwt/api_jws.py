from __future__ import annotations

import binascii
import json
import warnings
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from typing import Literal, TypedDict

from .algorithms import (
    Algorithm,
    get_default_algorithms,
    has_crypto,
    requires_cryptography,
)
from .api_jwk import PyJWK, PyJWKSet
from .exceptions import (
    DecodeError,
    InvalidAlgorithmError,
    InvalidKeyError,
    InvalidSignatureError,
    InvalidTokenError,
    PyJWTError,
    UnmetSignerPolicyError,
)
from .utils import base64url_decode, base64url_encode
from .warnings import InsecureKeyLengthWarning, RemovedInPyjwt3Warning

if TYPE_CHECKING:
    from .algorithms import AllowedPrivateKeys, AllowedPublicKeys
    from .api_jwk import PyJWKSet
    from .types import SigOptions

    JWSVerifyKey = AllowedPublicKeys | PyJWK | str | bytes | None
    JSONKey = (
        JWSVerifyKey
        | PyJWKSet
        | Mapping[str | None, Any]
        | Callable[[str | None, dict[str, Any]], Any]
    )
else:  # pragma: no cover
    JWSVerifyKey = Any
    JSONKey = Any


class JWSSigner(TypedDict, total=False):
    key: AllowedPrivateKeys | PyJWK | str | bytes | None
    algorithm: Any
    protected_headers: dict[str, Any]
    unprotected_headers: dict[str, Any]


SignatureStatus = Literal["valid", "invalid", "skipped"]


@dataclass(frozen=True)
class JWSSignatureResult:
    """Verification details for one JSON-serialized JWS signature."""

    index: int
    kid: str | None
    status: SignatureStatus
    protected_header: dict[str, Any]
    unprotected_header: dict[str, Any]
    header: dict[str, Any]
    signature: bytes
    error: Exception | None = None


@dataclass(frozen=True)
class JWSVerificationResult:
    """Verification details for a General or Flattened JSON-serialized JWS."""

    verified: bool
    payload: bytes | None
    signatures: list[JWSSignatureResult]


@dataclass(frozen=True)
class _LoadedJSONSignature:
    status: Literal["loaded"]
    index: int
    kid: str | None
    protected_header: dict[str, Any]
    unprotected_header: dict[str, Any]
    header: dict[str, Any]
    signature: bytes
    signing_input: bytes


_ALGORITHM_UNSET = object()
_BASE64URL_ALPHABET = (
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def _reject_duplicate_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise DecodeError(f"Duplicate JSON member: {key}")
        seen.add(key)
    return dict(pairs)


class PyJWS:
    header_typ = "JWT"

    def __init__(
        self,
        algorithms: Sequence[str] | None = None,
        options: SigOptions | None = None,
    ) -> None:
        self._algorithms = get_default_algorithms()
        self._valid_algs = (
            set(algorithms) if algorithms is not None else set(self._algorithms)
        )

        # Remove algorithms that aren't on the whitelist
        for key in list(self._algorithms.keys()):
            if key not in self._valid_algs:
                del self._algorithms[key]

        self.options: SigOptions = self._get_default_options()
        if options is not None:
            self.options = {**self.options, **options}

    @staticmethod
    def _get_default_options() -> SigOptions:
        return {"verify_signature": True, "enforce_minimum_key_length": False}

    def register_algorithm(self, alg_id: str, alg_obj: Algorithm) -> None:
        """
        Registers a new Algorithm for use when creating and verifying tokens.

        :param str alg_id: the ID of the Algorithm
        :param alg_obj: the Algorithm object
        :type alg_obj: Algorithm
        """
        if alg_id in self._algorithms:
            raise ValueError("Algorithm already has a handler.")

        if not isinstance(alg_obj, Algorithm):
            raise TypeError("Object is not of type `Algorithm`")

        self._algorithms[alg_id] = alg_obj
        self._valid_algs.add(alg_id)

    def unregister_algorithm(self, alg_id: str) -> None:
        """
        Unregisters an Algorithm for use when creating and verifying tokens
        :param str alg_id: the ID of the Algorithm
        :raises KeyError: if algorithm is not registered.
        """
        if alg_id not in self._algorithms:
            raise KeyError(
                "The specified algorithm could not be removed"
                " because it is not registered."
            )

        del self._algorithms[alg_id]
        self._valid_algs.remove(alg_id)

    def get_algorithms(self) -> list[str]:
        """
        Returns a list of supported values for the `alg` parameter.

        :rtype: list[str]
        """
        return list(self._valid_algs)

    def get_algorithm_by_name(self, alg_name: str) -> Algorithm:
        """
        For a given string name, return the matching Algorithm object.

        Example usage:
        >>> jws_obj = PyJWS()
        >>> jws_obj.get_algorithm_by_name("RS256")

        :param alg_name: The name of the algorithm to retrieve
        :type alg_name: str
        :rtype: Algorithm
        """
        try:
            return self._algorithms[alg_name]
        except KeyError as e:
            if not has_crypto and alg_name in requires_cryptography:
                raise NotImplementedError(
                    f"Algorithm '{alg_name}' could not be found. Do you have cryptography installed?"
                ) from e
            raise NotImplementedError("Algorithm not supported") from e

    def encode(
        self,
        payload: bytes,
        key: AllowedPrivateKeys | PyJWK | str | bytes,
        algorithm: str | None = _ALGORITHM_UNSET,  # type: ignore[assignment]
        headers: dict[str, Any] | None = None,
        json_encoder: type[json.JSONEncoder] | None = None,
        is_payload_detached: bool = False,
        sort_headers: bool = True,
    ) -> str:
        segments: list[bytes] = []

        # declare a new var to narrow the type for type checkers
        if algorithm is _ALGORITHM_UNSET:
            if isinstance(key, PyJWK):
                algorithm_ = key.algorithm_name
            else:
                algorithm_ = "HS256"
        elif algorithm is None:
            if isinstance(key, PyJWK):
                algorithm_ = key.algorithm_name
            else:
                algorithm_ = "none"
        else:
            algorithm_ = algorithm

        # Prefer headers values if present to function parameters.
        if headers:
            headers_alg = headers.get("alg")
            if headers_alg:
                algorithm_ = headers["alg"]

            headers_b64 = headers.get("b64")
            if headers_b64 is False:
                is_payload_detached = True

        # Header
        header: dict[str, Any] = {"typ": self.header_typ, "alg": algorithm_}

        if headers:
            self._validate_headers(headers, encoding=True)
            header.update(headers)

        if not header["typ"]:
            del header["typ"]

        if is_payload_detached:
            header["b64"] = False
            # RFC 7797 §3: producers MUST list "b64" in "crit" whenever
            # "b64" appears in the protected header, so b64-unaware
            # verifiers don't silently treat an unencoded payload as
            # base64-encoded.
            existing_crit = header.get("crit", [])
            if not isinstance(existing_crit, list):
                raise InvalidTokenError("Invalid 'crit' header: must be a list")
            if "b64" not in existing_crit:
                header["crit"] = [*existing_crit, "b64"]
        elif "b64" in header:
            # True is the standard value for b64, so no need for it
            del header["b64"]

        json_header = json.dumps(
            header, separators=(",", ":"), cls=json_encoder, sort_keys=sort_headers
        ).encode()

        segments.append(base64url_encode(json_header))

        if is_payload_detached:
            msg_payload = payload
        else:
            msg_payload = base64url_encode(payload)
        segments.append(msg_payload)

        # Segments
        signing_input = b".".join(segments)

        signature = self._sign(signing_input, key, algorithm_)

        segments.append(base64url_encode(signature))

        # Don't put the payload content inside the encoded token when detached
        if is_payload_detached:
            segments[1] = b""
        encoded_string = b".".join(segments)

        return encoded_string.decode("utf-8")

    def encode_json(
        self,
        payload: bytes,
        signers: JWSSigner | Collection[JWSSigner],
        *,
        json_encoder: type[json.JSONEncoder] | None = None,
        sort_headers: bool = True,
    ) -> dict[str, Any]:
        """Encode a payload as a General or Flattened JSON-serialized JWS."""
        if not isinstance(payload, bytes):
            raise TypeError("Payload must be bytes")

        signer_list = self._normalize_json_signers(signers)
        encoded_payload = base64url_encode(payload).decode("utf-8")
        signatures: list[dict[str, Any]] = []

        for signer in signer_list:
            protected_headers = dict(signer.get("protected_headers") or {})
            unprotected_headers = dict(signer.get("unprotected_headers") or {})
            self._validate_json_header_partitions(
                protected_headers, unprotected_headers, encoding=True
            )
            algorithm = self._resolve_json_encode_algorithm(
                signer, protected_headers, unprotected_headers
            )
            if any(
                header.get("b64", True) is False
                for header in (protected_headers, unprotected_headers)
            ):
                raise NotImplementedError(
                    "Detached payloads are not supported for JSON serialization"
                )

            protected = (
                dict(protected_headers)
                if "alg" in unprotected_headers
                else {"alg": algorithm, **protected_headers}
            )
            self._validate_headers(protected, encoding=True)
            self._validate_headers(unprotected_headers, encoding=True)
            protected_json = json.dumps(
                protected,
                separators=(",", ":"),
                cls=json_encoder,
                sort_keys=sort_headers,
            ).encode("utf-8")
            protected_segment = base64url_encode(protected_json)
            signing_input = b".".join([protected_segment, base64url_encode(payload)])
            signature = self._sign(
                signing_input, signer.get("key"), algorithm, stacklevel=3
            )

            signature_object: dict[str, Any] = {
                "protected": protected_segment.decode("utf-8"),
                "signature": base64url_encode(signature).decode("utf-8"),
            }
            if unprotected_headers:
                signature_object["header"] = unprotected_headers
            signatures.append(signature_object)

        if len(signatures) == 1:
            return {"payload": encoded_payload, **signatures[0]}
        return {"payload": encoded_payload, "signatures": signatures}

    @staticmethod
    def _normalize_json_signers(
        signers: JWSSigner | Collection[JWSSigner],
    ) -> list[JWSSigner]:
        if isinstance(signers, Mapping):
            return [signers]  # type: ignore[list-item]
        if not isinstance(signers, Collection) or isinstance(signers, (str, bytes)):
            raise TypeError("signers must be a mapping or collection of mappings")
        signer_list = list(signers)
        if not signer_list:
            raise ValueError("At least one signer is required")
        if not all(isinstance(signer, Mapping) for signer in signer_list):
            raise TypeError("Each signer must be a mapping")
        return signer_list

    @staticmethod
    def _validate_json_header_partitions(
        protected_headers: dict[str, Any],
        unprotected_headers: dict[str, Any],
        *,
        encoding: bool = False,
    ) -> None:
        duplicates = set(protected_headers).intersection(unprotected_headers)
        if duplicates:
            duplicated = ", ".join(sorted(duplicates))
            raise DecodeError(
                f"Header parameter appears in both protected and header: {duplicated}"
            )
        if "crit" in unprotected_headers:
            raise DecodeError("The 'crit' header parameter must be integrity protected")
        if not encoding and unprotected_headers.get("b64", True) is False:
            raise DecodeError("The 'b64' header parameter must be integrity protected")

    def _resolve_json_encode_algorithm(
        self,
        signer: JWSSigner,
        protected_headers: dict[str, Any],
        unprotected_headers: dict[str, Any],
    ) -> Any:
        explicit_algorithm = signer.get("algorithm", _ALGORITHM_UNSET)
        key = signer.get("key")
        if explicit_algorithm is _ALGORITHM_UNSET:
            algorithm = key.algorithm_name if isinstance(key, PyJWK) else "HS256"
        elif explicit_algorithm is None and isinstance(key, PyJWK):
            algorithm = key.algorithm_name
        elif explicit_algorithm is None:
            algorithm = "none"
        else:
            algorithm = explicit_algorithm

        header_algorithms = [
            header["alg"]
            for header in (protected_headers, unprotected_headers)
            if "alg" in header
        ]
        if header_algorithms:
            header_algorithm = header_algorithms[0]
            if explicit_algorithm is not _ALGORITHM_UNSET and (
                header_algorithm != algorithm
            ):
                raise InvalidAlgorithmError("Conflicting algorithm values")
            algorithm = header_algorithm
        if any(header_algorithm != algorithm for header_algorithm in header_algorithms):
            raise InvalidAlgorithmError("Conflicting algorithm values")
        if not algorithm:
            raise InvalidAlgorithmError("Algorithm not specified")
        return algorithm

    def _sign(
        self,
        signing_input: bytes,
        key: AllowedPrivateKeys | PyJWK | str | bytes | None,
        algorithm: str,
        *,
        stacklevel: int = 2,
    ) -> bytes:
        alg_obj = self.get_algorithm_by_name(algorithm)
        if isinstance(key, PyJWK):
            if key.algorithm_name != algorithm:
                raise InvalidAlgorithmError(
                    f"Key algorithm {key.algorithm_name!r} does not match {algorithm!r}"
                )
            key = key.key
        prepared_key = alg_obj.prepare_key(key)
        key_length_msg = alg_obj.check_key_length(prepared_key)
        if key_length_msg:
            if self.options.get("enforce_minimum_key_length", False):
                raise InvalidKeyError(key_length_msg)
            warnings.warn(
                key_length_msg, InsecureKeyLengthWarning, stacklevel=stacklevel + 1
            )
        return alg_obj.sign(signing_input, prepared_key)

    def decode_complete(
        self,
        jwt: str | bytes,
        key: AllowedPublicKeys | PyJWK | str | bytes = "",
        algorithms: Sequence[str] | None = None,
        options: SigOptions | None = None,
        detached_payload: bytes | None = None,
        **kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        if kwargs:
            warnings.warn(
                "passing additional kwargs to decode_complete() is deprecated "
                "and will be removed in pyjwt version 3. "
                f"Unsupported kwargs: {tuple(kwargs.keys())}",
                RemovedInPyjwt3Warning,
                stacklevel=2,
            )
        merged_options: SigOptions
        if options is None:
            merged_options = self.options
        else:
            merged_options = {**self.options, **options}

        verify_signature = merged_options["verify_signature"]

        if verify_signature and not algorithms and not isinstance(key, PyJWK):
            raise DecodeError(
                'It is required that you pass in a value for the "algorithms" argument when calling decode().'
            )

        payload, signing_input, header, signature = self._load(jwt)

        self._validate_headers(header)

        if detached_payload is not None and header.get("b64", True) is not False:
            raise DecodeError(
                'It is only valid to pass "detached_payload" when the protected header has "b64" set to false.'
            )

        if header.get("b64", True) is False:
            # RFC 7797 §3: when "b64" is present in the protected header,
            # it MUST also appear in "crit". A token that sets b64=false
            # without declaring it critical is malformed.
            crit = header.get("crit") or []
            if not isinstance(crit, list) or "b64" not in crit:
                raise InvalidTokenError(
                    "The 'b64' header parameter requires 'b64' to be listed in 'crit'."
                )
            if detached_payload is None:
                raise DecodeError(
                    'It is required that you pass in a value for the "detached_payload" argument to decode a message having the b64 header set to false.'
                )
            payload = detached_payload
            signing_input = b".".join([signing_input.rsplit(b".", 1)[0], payload])

        if verify_signature:
            self._verify_signature(
                signing_input,
                header,
                signature,
                key,
                algorithms,
                options=merged_options,
            )

        return {
            "payload": payload,
            "header": header,
            "signature": signature,
        }

    def decode(
        self,
        jwt: str | bytes,
        key: AllowedPublicKeys | PyJWK | str | bytes = "",
        algorithms: Sequence[str] | None = None,
        options: SigOptions | None = None,
        detached_payload: bytes | None = None,
        **kwargs: dict[str, Any],
    ) -> Any:
        if kwargs:
            warnings.warn(
                "passing additional kwargs to decode() is deprecated "
                "and will be removed in pyjwt version 3. "
                f"Unsupported kwargs: {tuple(kwargs.keys())}",
                RemovedInPyjwt3Warning,
                stacklevel=2,
            )
        decoded = self.decode_complete(
            jwt, key, algorithms, options, detached_payload=detached_payload
        )
        return decoded["payload"]

    def verify_json(
        self,
        message: str | bytes | Mapping[str, Any],
        key: JSONKey = "",
        algorithms: Sequence[str] | None = None,
        options: SigOptions | None = None,
        *,
        required_signers: Collection[str] | None = None,
        minimum_signers: int | None = None,
    ) -> JWSVerificationResult:
        """Verify a JSON-serialized JWS and report every signature's status.

        Unlike :meth:`decode_json_complete`, this never raises when the
        caller's signer policy is not satisfied. Instead the returned result
        has ``verified=False`` and ``payload=None``. Per-signature structural
        or cryptographic failures are recorded independently.
        """
        merged_options: SigOptions
        if options is None:
            merged_options = self.options
        else:
            merged_options = {**self.options, **options}

        verify_signature = merged_options["verify_signature"]
        required = self._validate_signer_policy(
            verify_signature, required_signers, minimum_signers
        )

        obj = self._load_json_object(message)
        payload_segment, signature_objects = self._load_json_structure(obj)
        try:
            payload = self._decode_base64url_segment(
                payload_segment.encode("ascii"), "payload"
            )
        except UnicodeEncodeError as e:
            raise DecodeError("Invalid payload encoding") from e

        results: list[JWSSignatureResult] = []
        for index, signature_object in enumerate(signature_objects):
            result = self._load_json_signature(signature_object, index, payload_segment)
            if result.status == "invalid":
                results.append(result)
                continue

            if not verify_signature:
                results.append(
                    JWSSignatureResult(
                        index=index,
                        kid=result.kid,
                        status="skipped",
                        protected_header=result.protected_header,
                        unprotected_header=result.unprotected_header,
                        header=result.header,
                        signature=result.signature,
                    )
                )
                continue

            try:
                verification_key, per_signature_algorithms = self._resolve_json_key(
                    key, result.kid, result.header, algorithms
                )
                self._verify_signature(
                    result.signing_input,
                    result.header,
                    result.signature,
                    verification_key,
                    per_signature_algorithms,
                    options=merged_options,
                )
            except PyJWTError as error:
                results.append(
                    JWSSignatureResult(
                        index=index,
                        kid=result.kid,
                        status="invalid",
                        protected_header=result.protected_header,
                        unprotected_header=result.unprotected_header,
                        header=result.header,
                        signature=result.signature,
                        error=error,
                    )
                )
            else:
                results.append(
                    JWSSignatureResult(
                        index=index,
                        kid=result.kid,
                        status="valid",
                        protected_header=result.protected_header,
                        unprotected_header=result.unprotected_header,
                        header=result.header,
                        signature=result.signature,
                    )
                )

        verification = JWSVerificationResult(
            verified=not verify_signature,
            payload=payload if not verify_signature else None,
            signatures=results,
        )

        if verify_signature:
            valid_signers = {
                result.kid
                for result in results
                if result.status == "valid" and result.kid is not None
            }
            if required is not None:
                policy_satisfied = required.issubset(valid_signers)
            else:
                assert minimum_signers is not None
                policy_satisfied = len(valid_signers) >= minimum_signers
            if policy_satisfied:
                verification = JWSVerificationResult(
                    verified=True, payload=payload, signatures=results
                )

        return verification

    def decode_json_complete(
        self,
        message: str | bytes | Mapping[str, Any],
        key: JSONKey = "",
        algorithms: Sequence[str] | None = None,
        options: SigOptions | None = None,
        *,
        required_signers: Collection[str] | None = None,
        minimum_signers: int | None = None,
    ) -> JWSVerificationResult:
        """Verify a JSON-serialized JWS, returning payload only on policy success."""
        verification = self.verify_json(
            message,
            key,
            algorithms,
            options,
            required_signers=required_signers,
            minimum_signers=minimum_signers,
        )
        if not verification.verified:
            raise UnmetSignerPolicyError(
                "JWS signature policy was not satisfied", verification
            )
        return verification

    def decode_json(
        self,
        message: str | bytes | Mapping[str, Any],
        key: JSONKey = "",
        algorithms: Sequence[str] | None = None,
        options: SigOptions | None = None,
        *,
        required_signers: Collection[str] | None = None,
        minimum_signers: int | None = None,
    ) -> bytes:
        """Return payload only when the caller's signer policy is satisfied."""
        decoded = self.decode_json_complete(
            message,
            key,
            algorithms,
            options,
            required_signers=required_signers,
            minimum_signers=minimum_signers,
        )
        return decoded.payload

    @staticmethod
    def _validate_signer_policy(
        verify_signature: bool,
        required_signers: Collection[str] | None,
        minimum_signers: int | None,
    ) -> set[str] | None:
        if not verify_signature:
            if required_signers is not None or minimum_signers is not None:
                raise ValueError(
                    "Signer policies cannot be used when verify_signature is false"
                )
            return None

        if (required_signers is None) == (minimum_signers is None):
            raise ValueError(
                "Specify exactly one of required_signers or minimum_signers"
            )
        if required_signers is not None:
            if isinstance(required_signers, (str, bytes)) or not isinstance(
                required_signers, Collection
            ):
                raise TypeError("required_signers must be a collection of strings")
            required = set(required_signers)
            if not required or any(
                not isinstance(signer, str) or not signer for signer in required
            ):
                raise ValueError("required_signers must contain non-empty strings")
            return required

        if isinstance(minimum_signers, bool) or not isinstance(minimum_signers, int):
            raise TypeError("minimum_signers must be an integer")
        if minimum_signers < 1:
            raise ValueError("minimum_signers must be greater than zero")
        return None

    def _load_json_object(
        self, message: str | bytes | Mapping[str, Any]
    ) -> dict[str, Any]:
        if isinstance(message, Mapping):
            obj = dict(message)
        else:
            if isinstance(message, str):
                message = message.encode("utf-8")
            if not isinstance(message, bytes):
                raise DecodeError(f"Invalid token type. Token must be a {bytes}")
            try:
                loaded = json.loads(
                    message, object_pairs_hook=_reject_duplicate_json_object
                )
            except (ValueError, RecursionError) as e:
                raise DecodeError(f"Invalid JWS JSON: {e}") from e
            if not isinstance(loaded, dict):
                raise DecodeError("Invalid JWS JSON: must be an object")
            obj = loaded
        return obj

    def _load_json_structure(
        self, obj: dict[str, Any]
    ) -> tuple[str, list[dict[str, Any]]]:
        payload_segment = obj.get("payload")
        if not isinstance(payload_segment, str):
            raise DecodeError("JWS JSON payload must be a string")

        flattened_members = {"protected", "header", "signature"}
        has_flattened_members = any(member in obj for member in flattened_members)
        if "signatures" in obj and has_flattened_members:
            raise DecodeError("JWS JSON cannot use both General and Flattened forms")

        if "signatures" in obj:
            raw_signatures = obj["signatures"]
            if not isinstance(raw_signatures, list) or not raw_signatures:
                raise DecodeError("JWS JSON signatures must be a non-empty list")
            signatures = []
            for raw_signature in raw_signatures:
                if not isinstance(raw_signature, dict):
                    raise DecodeError("Each JWS signature must be an object")
                if "payload" in raw_signature:
                    raise DecodeError("General JWS signatures cannot contain payload")
                signatures.append(raw_signature)
            return payload_segment, signatures

        if not has_flattened_members:
            raise DecodeError("JWS JSON does not contain a signature")
        return payload_segment, [obj]

    def _load_json_signature(
        self, raw_signature: dict[str, Any], index: int, payload_segment: str
    ) -> "_LoadedJSONSignature | JWSSignatureResult":
        protected_header: dict[str, Any] = {}
        unprotected_header: dict[str, Any] = {}
        header: dict[str, Any] = {}
        signature = b""
        kid = None

        try:
            protected_segment = raw_signature.get("protected", "")
            if not isinstance(protected_segment, str):
                raise DecodeError("JWS protected header must be a string")
            if protected_segment:
                protected_data = self._decode_base64url_segment(
                    protected_segment.encode("ascii"), "protected header"
                )
                loaded_protected = json.loads(
                    protected_data,
                    object_pairs_hook=_reject_duplicate_json_object,
                )
                if not isinstance(loaded_protected, dict):
                    raise DecodeError(
                        "Invalid protected header string: must be a json object"
                    )
                protected_header = loaded_protected

            unprotected_header = raw_signature.get("header", {})
            if not isinstance(unprotected_header, dict):
                raise DecodeError("JWS header must be an object")
            self._validate_json_header_partitions(protected_header, unprotected_header)

            header = {**protected_header, **unprotected_header}
            self._validate_headers(header)
            if header.get("b64", True) is False:
                raise DecodeError(
                    "Detached payloads are not supported for JSON serialization"
                )
            kid = header.get("kid")

            signature_segment = raw_signature.get("signature")
            if not isinstance(signature_segment, str):
                raise DecodeError("JWS signature must be a string")
            signature = self._decode_base64url_segment(
                signature_segment.encode("ascii"), "crypto"
            )
            signing_input = b".".join(
                [protected_segment.encode("ascii"), payload_segment.encode("ascii")]
            )
        except (PyJWTError, ValueError, TypeError, UnicodeError) as error:
            return JWSSignatureResult(
                index=index,
                kid=kid,
                status="invalid",
                protected_header=protected_header,
                unprotected_header=unprotected_header,
                header=header,
                signature=signature,
                error=error,
            )

        return _LoadedJSONSignature(
            "loaded",
            index,
            kid,
            protected_header,
            unprotected_header,
            header,
            signature,
            signing_input,
        )

    def _resolve_json_key(
        self,
        key: JSONKey,
        kid: str | None,
        header: dict[str, Any],
        algorithms: Sequence[str] | None,
    ) -> tuple[JWSVerifyKey, Collection[str] | None]:
        if callable(key):
            try:
                resolved = key(kid, header)
            except KeyError:
                raise DecodeError(f"No key configured for kid: {kid}") from None
        elif isinstance(key, PyJWKSet):
            if kid is None:
                raise DecodeError("A kid header is required when using a JWK Set")
            try:
                resolved = key[kid]
            except KeyError:
                raise DecodeError(f"No key configured for kid: {kid}") from None
        elif isinstance(key, Mapping):
            if kid not in key:
                raise DecodeError(f"No key configured for kid: {kid}")
            resolved = key[kid]
        else:
            resolved = key

        if isinstance(resolved, tuple):
            if len(resolved) != 2:
                raise TypeError("Key resolution tuples must contain key and algorithms")
            verification_key, per_signature_algorithms = resolved
        else:
            verification_key, per_signature_algorithms = resolved, algorithms

        if per_signature_algorithms is None and not isinstance(verification_key, PyJWK):
            per_signature_algorithms = []

        if per_signature_algorithms is not None and (
            isinstance(per_signature_algorithms, (str, bytes))
            or not isinstance(per_signature_algorithms, Collection)
        ):
            raise TypeError("Algorithm allowlists must be a collection of strings")
        return verification_key, per_signature_algorithms

    def get_unverified_header(self, jwt: str | bytes) -> dict[str, Any]:
        """Returns back the JWT header parameters as a `dict`

        Note: The signature is not verified so the header parameters
        should not be fully trusted until signature verification is complete
        """
        headers = self._load(jwt)[2]
        self._validate_headers(headers)

        return headers

    @staticmethod
    def _decode_base64url_segment(segment: bytes, name: str) -> bytes:
        if len(segment) % 4 == 1 or any(
            character not in _BASE64URL_ALPHABET for character in segment
        ):
            raise DecodeError(f"Invalid {name} padding")

        try:
            decoded = base64url_decode(segment)
        except (TypeError, binascii.Error) as err:
            raise DecodeError(f"Invalid {name} padding") from err

        if base64url_encode(decoded) != segment:
            raise DecodeError(f"Invalid {name} padding")

        return decoded

    def _load(self, jwt: str | bytes) -> tuple[bytes, bytes, dict[str, Any], bytes]:
        if isinstance(jwt, str):
            jwt = jwt.encode("utf-8")

        if not isinstance(jwt, bytes):
            raise DecodeError(f"Invalid token type. Token must be a {bytes}")

        try:
            signing_input, crypto_segment = jwt.rsplit(b".", 1)
            header_segment, payload_segment = signing_input.split(b".", 1)
        except ValueError as err:
            raise DecodeError("Not enough segments") from err

        header_data = self._decode_base64url_segment(header_segment, "header")

        try:
            header: dict[str, Any] = json.loads(header_data)
        except (ValueError, RecursionError) as e:
            raise DecodeError(f"Invalid header string: {e}") from e

        if not isinstance(header, dict):
            raise DecodeError("Invalid header string: must be a json object")

        if header.get("b64", True) is False:
            # Detached payload form (RFC 7515 Appendix F): the compact-form
            # payload segment must be empty; the caller supplies the actual
            # payload via the `detached_payload` argument in decode_complete.
            # Skipping the base64 decode here removes an unauthenticated work
            # amplifier — otherwise an attacker can inflate the unused
            # segment to force CPU + memory cost before the signature is
            # even checked.
            if payload_segment:
                raise DecodeError("Payload segment must be empty when 'b64' is false.")
            payload = b""
        else:
            payload = self._decode_base64url_segment(payload_segment, "payload")

        signature = self._decode_base64url_segment(crypto_segment, "crypto")

        return (payload, signing_input, header, signature)

    def _verify_signature(
        self,
        signing_input: bytes,
        header: dict[str, Any],
        signature: bytes,
        key: AllowedPublicKeys | PyJWK | str | bytes = "",
        algorithms: Sequence[str] | None = None,
        options: SigOptions | None = None,
    ) -> None:
        effective_options = options if options is not None else self.options

        if algorithms is None and isinstance(key, PyJWK):
            algorithms = [key.algorithm_name]
        try:
            alg = header["alg"]
        except KeyError:
            raise InvalidAlgorithmError("Algorithm not specified") from None

        if not alg or (algorithms is not None and alg not in algorithms):
            raise InvalidAlgorithmError("The specified alg value is not allowed")

        if isinstance(key, PyJWK):
            # The PyJWK has a fixed algorithm bound at construction time.
            # Verification must use that algorithm, not whatever the token
            # header advertises, otherwise the caller's allow-list check
            # above degenerates into a string compare with no behavioural
            # effect on which algorithm actually verifies the signature.
            if alg != key.algorithm_name:
                raise InvalidAlgorithmError(
                    f"Token algorithm {alg!r} does not match the key's "
                    f"algorithm {key.algorithm_name!r}"
                )
            alg_obj = key.Algorithm
            prepared_key = alg_obj.prepare_key(key.key)
        else:
            try:
                alg_obj = self.get_algorithm_by_name(alg)
            except NotImplementedError as e:
                raise InvalidAlgorithmError("Algorithm not supported") from e
            prepared_key = alg_obj.prepare_key(key)

        key_length_msg = alg_obj.check_key_length(prepared_key)
        if key_length_msg:
            if effective_options.get("enforce_minimum_key_length", False):
                raise InvalidKeyError(key_length_msg)
            else:
                warnings.warn(key_length_msg, InsecureKeyLengthWarning, stacklevel=4)

        if not alg_obj.verify(signing_input, prepared_key, signature):
            raise InvalidSignatureError("Signature verification failed")

    # Extensions that PyJWT actually understands and supports
    _supported_crit: set[str] = {"b64"}

    def _validate_headers(
        self, headers: dict[str, Any], *, encoding: bool = False
    ) -> None:
        if "kid" in headers:
            self._validate_kid(headers["kid"])
        if not encoding and "crit" in headers:
            self._validate_crit(headers)

    def _validate_kid(self, kid: Any) -> None:
        if not isinstance(kid, str):
            raise InvalidTokenError("Key ID header parameter must be a string")

    def _validate_crit(self, headers: dict[str, Any]) -> None:
        crit = headers["crit"]
        if not isinstance(crit, list) or len(crit) == 0:
            raise InvalidTokenError("Invalid 'crit' header: must be a non-empty list")
        for ext in crit:
            if not isinstance(ext, str):
                raise InvalidTokenError("Invalid 'crit' header: values must be strings")
            if ext not in self._supported_crit:
                raise InvalidTokenError(f"Unsupported critical extension: {ext}")
            if ext not in headers:
                raise InvalidTokenError(
                    f"Critical extension '{ext}' is missing from headers"
                )


_jws_global_obj = PyJWS()
encode = _jws_global_obj.encode
encode_json = _jws_global_obj.encode_json
verify_json = _jws_global_obj.verify_json
decode_complete = _jws_global_obj.decode_complete
decode_json_complete = _jws_global_obj.decode_json_complete
decode = _jws_global_obj.decode
decode_json = _jws_global_obj.decode_json
register_algorithm = _jws_global_obj.register_algorithm
unregister_algorithm = _jws_global_obj.unregister_algorithm
get_algorithm_by_name = _jws_global_obj.get_algorithm_by_name
get_unverified_header = _jws_global_obj.get_unverified_header
