from __future__ import annotations

import binascii
import json
import warnings
from collections.abc import Callable, Mapping, Sequence
from typing import TYPE_CHECKING, Any

from .algorithms import (
    Algorithm,
    get_default_algorithms,
    has_crypto,
    requires_cryptography,
)
from .api_jwk import PyJWK
from .exceptions import (
    DecodeError,
    InvalidAlgorithmError,
    InvalidKeyError,
    InvalidSignatureError,
    InvalidTokenError,
    PyJWTError,
)
from .utils import base64url_decode, base64url_encode
from .warnings import InsecureKeyLengthWarning, RemovedInPyjwt3Warning

if TYPE_CHECKING:
    from .algorithms import AllowedPrivateKeys, AllowedPublicKeys
    from .types import (
        JSONHeader,
        JWSJSONDecodeResult,
        JWSJSONSignatureResult,
        JWSSigner,
        SigOptions,
    )

_ALGORITHM_UNSET = object()
_BASE64URL_ALPHABET = (
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


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

        alg_obj = self.get_algorithm_by_name(algorithm_)
        if isinstance(key, PyJWK):
            key = key.key
        key = alg_obj.prepare_key(key)

        key_length_msg = alg_obj.check_key_length(key)
        if key_length_msg:
            if self.options.get("enforce_minimum_key_length", False):
                raise InvalidKeyError(key_length_msg)
            else:
                warnings.warn(key_length_msg, InsecureKeyLengthWarning, stacklevel=2)

        signature = alg_obj.sign(signing_input, key)

        segments.append(base64url_encode(signature))

        # Don't put the payload content inside the encoded token when detached
        if is_payload_detached:
            segments[1] = b""
        encoded_string = b".".join(segments)

        return encoded_string.decode("utf-8")

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

    def encode_json(
        self,
        payload: bytes,
        signers: Sequence[JWSSigner | tuple[Any, str]],
        serialization: str = "general",
        json_encoder: type[json.JSONEncoder] | None = None,
        sort_headers: bool = True,
    ) -> str:
        """Encode a payload using a JWS JSON Serialization."""
        if not signers:
            raise InvalidTokenError("At least one signer is required")

        if serialization == "auto":
            serialization = "flattened" if len(signers) == 1 else "general"

        if serialization not in {"general", "flattened"}:
            raise ValueError("serialization must be 'general', 'flattened', or 'auto'")

        if serialization == "flattened" and len(signers) != 1:
            raise ValueError(
                "Flattened JWS JSON Serialization supports exactly one signature"
            )

        payload_segment = base64url_encode(payload)
        encoded_signatures = [
            self._encode_json_signature(
                payload_segment,
                signer,
                json_encoder=json_encoder,
                sort_headers=sort_headers,
            )
            for signer in signers
        ]

        message: dict[str, Any] = {"payload": payload_segment.decode("ascii")}
        if serialization == "flattened":
            message.update(encoded_signatures[0])
        else:
            message["signatures"] = encoded_signatures

        return json.dumps(message, separators=(",", ":"), cls=json_encoder)

    def encode_general(
        self,
        payload: bytes,
        signers: Sequence[JWSSigner | tuple[Any, str]],
        json_encoder: type[json.JSONEncoder] | None = None,
        sort_headers: bool = True,
    ) -> str:
        """Encode a payload using the General JWS JSON Serialization."""
        return self.encode_json(
            payload,
            signers,
            serialization="general",
            json_encoder=json_encoder,
            sort_headers=sort_headers,
        )

    def encode_flattened(
        self,
        payload: bytes,
        signer: JWSSigner | tuple[Any, str] | None = None,
        key: AllowedPrivateKeys | PyJWK | str | bytes | None = None,
        algorithm: str | None = None,
        protected_headers: JSONHeader | None = None,
        unprotected_headers: JSONHeader | None = None,
        json_encoder: type[json.JSONEncoder] | None = None,
        sort_headers: bool = True,
    ) -> str:
        """Encode a payload using the Flattened JWS JSON Serialization."""
        if signer is None:
            if key is None:
                raise InvalidTokenError("A signing key is required")
            new_signer: JWSSigner = {
                "key": key,
                "algorithm": algorithm or "HS256",
                "protected": protected_headers or {},
                "header": unprotected_headers or {},
            }
            signer_input: JWSSigner | tuple[Any, str] = new_signer
        elif key is not None or algorithm is not None:
            raise ValueError("signer cannot be combined with individual key fields")
        else:
            signer_input = signer

        return self.encode_json(
            payload,
            [signer_input],
            serialization="flattened",
            json_encoder=json_encoder,
            sort_headers=sort_headers,
        )

    def decode_json_complete(
        self,
        token: str | bytes | dict[str, Any],
        key: AllowedPublicKeys | PyJWK | str | bytes = "",
        algorithms: Sequence[str] | None = None,
        options: SigOptions | None = None,
        *,
        keys: (
            Mapping[str, Any]
            | Sequence[Any | Mapping[str, Any] | Callable[[str], Any]]
            | Callable[[str], Any]
            | None
        ) = None,
        required_signers: Sequence[str] | None = None,
        minimum_signers: int | None = None,
        raise_on_policy_failure: bool = True,
        **kwargs: Any,
    ) -> JWSJSONDecodeResult:
        """Decode and independently verify signatures in a JWS JSON Serialization."""
        required_signers = self._normalize_required_signers(
            required_signers,
            kwargs.pop("required_kids", None)
            or kwargs.pop("required_signer_kids", None)
            or kwargs.pop("kids", None),
        )
        minimum_signers = self._normalize_minimum_signers(
            minimum_signers,
            kwargs.pop("min_signers", None),
            kwargs.pop("min_distinct_signers", None),
            kwargs.pop("minimum_distinct_signers", None),
        )
        if kwargs:
            raise TypeError(f"Unsupported keyword argument(s): {tuple(kwargs)}")

        merged_options: SigOptions
        if options is None:
            merged_options = self.options
        else:
            merged_options = {**self.options, **options}

        verify_signature = merged_options["verify_signature"]
        if verify_signature:
            if required_signers is None and minimum_signers is None:
                minimum_signers = 1
            if minimum_signers is not None and minimum_signers < 1:
                raise ValueError("minimum_signers must be greater than zero")

        message = self._load_json(token)
        payload_segment, raw_signatures = self._load_json_signatures(message)
        payload = self._decode_base64url_segment(payload_segment, "payload")

        key_configs = self._normalize_key_configs(key, keys)
        signature_results: list[JWSJSONSignatureResult] = [
            self._verify_json_signature(
                index,
                payload_segment,
                raw_signature,
                key_configs,
                algorithms,
                merged_options,
                verify_signature,
            )
            for index, raw_signature in enumerate(raw_signatures)
        ]

        valid_signer_set: set[str] = set()
        for signature_result in signature_results:
            kid = signature_result.get("kid")
            if signature_result.get("valid") is True and isinstance(kid, str):
                valid_signer_set.add(kid)
        valid_signers: list[str] = sorted(valid_signer_set)
        has_valid_anonymous_signature = any(
            signature_result.get("valid") is True
            and signature_result.get("kid") is None
            for signature_result in signature_results
        )
        distinct_valid_signers = len(valid_signers) + int(
            has_valid_anonymous_signature
        )
        missing_signers = sorted(set(required_signers) - set(valid_signers))
        policy_satisfied = not verify_signature or (
            not missing_signers
            and (
                minimum_signers is None
                or distinct_valid_signers >= minimum_signers
            )
        )

        decode_result: JWSJSONDecodeResult = {
            "payload": payload if policy_satisfied else None,
            "verified": policy_satisfied if verify_signature else False,
            "valid_signers": valid_signers,
            "required_signers": list(required_signers),
            "missing_signers": missing_signers,
            "minimum_signers": minimum_signers,
            "distinct_valid_signers": distinct_valid_signers,
            "signatures": signature_results,
        }

        if verify_signature and not policy_satisfied and raise_on_policy_failure:
            error = InvalidSignatureError("Required JWS signer policy was not met")
            error.result = decode_result  # type: ignore[attr-defined]
            raise error

        return decode_result

    def decode_json(
        self,
        token: str | bytes | dict[str, Any],
        key: AllowedPublicKeys | PyJWK | str | bytes = "",
        algorithms: Sequence[str] | None = None,
        options: SigOptions | None = None,
        *,
        keys: (
            Mapping[str, Any]
            | Sequence[Any | Mapping[str, Any] | Callable[[str], Any]]
            | Callable[[str], Any]
            | None
        ) = None,
        required_signers: Sequence[str] | None = None,
        minimum_signers: int | None = None,
        **kwargs: Any,
    ) -> bytes:
        """Return a JWS JSON Serialization payload only if the signer policy passes."""
        decoded = self.decode_json_complete(
            token,
            key,
            algorithms,
            options,
            keys=keys,
            required_signers=required_signers,
            minimum_signers=minimum_signers,
            **kwargs,
        )
        return decoded["payload"]  # type: ignore[return-value]

    def decode_general(
        self, token: str | bytes | dict[str, Any], *args: Any, **kwargs: Any
    ) -> bytes:
        """Decode a General JWS JSON Serialization."""
        message = self._load_json(token)
        if "signatures" not in message:
            raise DecodeError("Expected a General JWS JSON Serialization")
        return self.decode_json(message, *args, **kwargs)

    def decode_general_complete(
        self, token: str | bytes | dict[str, Any], *args: Any, **kwargs: Any
    ) -> JWSJSONDecodeResult:
        """Decode a General JWS JSON Serialization with signature statuses."""
        message = self._load_json(token)
        if "signatures" not in message:
            raise DecodeError("Expected a General JWS JSON Serialization")
        return self.decode_json_complete(message, *args, **kwargs)

    def decode_flattened(
        self, token: str | bytes | dict[str, Any], *args: Any, **kwargs: Any
    ) -> bytes:
        """Decode a Flattened JWS JSON Serialization."""
        message = self._load_json(token)
        if "signatures" in message:
            raise DecodeError("Expected a Flattened JWS JSON Serialization")
        return self.decode_json(token, *args, **kwargs)

    def decode_flattened_complete(
        self, token: str | bytes | dict[str, Any], *args: Any, **kwargs: Any
    ) -> JWSJSONDecodeResult:
        """Decode a Flattened JWS JSON Serialization with signature statuses."""
        message = self._load_json(token)
        if "signatures" in message:
            raise DecodeError("Expected a Flattened JWS JSON Serialization")
        return self.decode_json_complete(message, *args, **kwargs)

    def verify_json_signatures(
        self,
        token: str | bytes | dict[str, Any],
        key: AllowedPublicKeys | PyJWK | str | bytes = "",
        algorithms: Sequence[str] | None = None,
        *,
        keys: (
            Mapping[str, Any]
            | Sequence[Any | Mapping[str, Any] | Callable[[str], Any]]
            | Callable[[str], Any]
            | None
        ) = None,
        required_signers: Sequence[str] | None = None,
        minimum_signers: int | None = None,
        options: SigOptions | None = None,
        **policy_kwargs: Any,
    ) -> JWSJSONDecodeResult:
        """Return per-signature statuses without raising for policy failure."""
        return self.decode_json_complete(
            token,
            key,
            algorithms,
            options,
            keys=keys,
            required_signers=required_signers,
            minimum_signers=minimum_signers,
            **policy_kwargs,
            raise_on_policy_failure=False,
        )

    def get_unverified_header(self, jwt: str | bytes) -> dict[str, Any]:
        """Returns back the JWT header parameters as a `dict`

        Note: The signature is not verified so the header parameters
        should not be fully trusted until signature verification is complete
        """
        headers = self._load(jwt)[2]
        self._validate_headers(headers)

        return headers

    @staticmethod
    def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise DecodeError(f"Duplicate JSON member: {key}")
            result[key] = value
        return result

    def _load_json(
        self, token: str | bytes | dict[str, Any]
    ) -> dict[str, Any]:
        if isinstance(token, dict):
            message = token
        else:
            if isinstance(token, bytes):
                try:
                    token = token.decode("utf-8")
                except UnicodeDecodeError as err:
                    raise DecodeError("Invalid JWS JSON Serialization") from err
            if not isinstance(token, str):
                raise DecodeError(f"Invalid token type. Token must be a {bytes}")

            try:
                message = json.loads(
                    token, object_pairs_hook=self._reject_duplicate_json_keys
                )
            except (ValueError, RecursionError) as err:
                raise DecodeError("Invalid JWS JSON Serialization") from err

        if not isinstance(message, dict):
            raise DecodeError("Invalid JWS JSON Serialization: must be an object")

        payload = message.get("payload")
        if not isinstance(payload, str):
            raise DecodeError("Invalid JWS JSON Serialization: invalid payload")

        return message

    def _load_json_signatures(
        self, message: dict[str, Any]
    ) -> tuple[bytes, list[Any]]:
        payload_segment = message["payload"].encode("ascii")

        if "signatures" in message:
            invalid_top_level = set(message) - {"payload", "signatures"}
            if invalid_top_level:
                raise DecodeError("Invalid General JWS JSON Serialization")

            signatures = message["signatures"]
            if not isinstance(signatures, list) or not signatures:
                raise DecodeError("Invalid General JWS JSON Serialization")
            return payload_segment, signatures

        invalid_top_level = set(message) - {"payload", "protected", "header", "signature"}
        if invalid_top_level or not isinstance(message.get("signature"), str):
            raise DecodeError("Invalid Flattened JWS JSON Serialization")

        signature = {"signature": message["signature"]}
        if "protected" in message:
            signature["protected"] = message["protected"]
        if "header" in message:
            signature["header"] = message["header"]
        return payload_segment, [signature]

    @staticmethod
    def _normalize_required_signers(
        required_signers: Sequence[str] | None,
        required_kids: Sequence[str] | None = None,
    ) -> list[str]:
        provided = [
            value
            for value in (required_signers, required_kids)
            if value is not None
        ]
        if not provided:
            return []
        if len(provided) != 1:
            raise ValueError("Conflicting required signer arguments")
        value = provided[0]
        if value is None:
            return []
        if not all(isinstance(kid, str) and kid for kid in value):
            raise ValueError("required_signers must contain non-empty strings")
        if len(value) != len(set(value)):
            raise ValueError("required_signers must not contain duplicates")
        return list(value)

    @staticmethod
    def _normalize_minimum_signers(*values: int | None) -> int | None:
        provided = [value for value in values if value is not None]
        if not provided:
            return None
        if any(not isinstance(value, int) or isinstance(value, bool) for value in provided):
            raise ValueError("minimum_signers must be an integer")
        if len(set(provided)) != 1:
            raise ValueError("Conflicting minimum signer arguments")
        return provided[0]

    @staticmethod
    def _key_config(
        key: Any = "", algorithms: Sequence[str] | None = None
    ) -> dict[str, Any]:
        return {
            "key": key,
            "algorithms": list(algorithms) if algorithms is not None else None,
        }

    def _normalize_key_configs(
        self,
        key: AllowedPublicKeys | PyJWK | str | bytes,
        keys: (
            Mapping[str, Any]
            | Sequence[Any | Mapping[str, Any] | Callable[[str], Any]]
            | Callable[[str], Any]
            | None
        ),
    ) -> dict[str, Any]:
        if keys is None:
            return {"default": self._key_config(key)}

        if isinstance(keys, Mapping):
            if any(not isinstance(kid, str) for kid in keys):
                raise ValueError("Key mapping identifiers must be strings")
            return {
                "mapping": {kid: self._coerce_key_config(value) for kid, value in keys.items()}
            }

        if isinstance(keys, Sequence) and not isinstance(keys, (str, bytes)):
            return {"sequence": [self._coerce_key_config(value) for value in keys]}

        if callable(keys):
            return {"callable": keys}

        raise ValueError("Unsupported keys argument")

    def _coerce_key_config(self, value: Any) -> dict[str, Any]:
        if isinstance(value, Mapping):
            if "key" not in value and "key_getter" not in value:
                raise ValueError("Key configuration must include a key")
            algorithms = value.get("algorithms", value.get("algs"))
            if isinstance(algorithms, str):
                algorithms = [algorithms]
            key = value.get("key", value.get("key_getter"))
            if callable(key):
                key = key(value.get("kid"))
            kid = value.get("kid")
            return self._key_config({"key": key, "kid": kid}, algorithms)
        if isinstance(value, tuple) and len(value) == 2:
            algorithm = value[1]
            if isinstance(algorithm, str):
                algorithm = [algorithm]
            return self._key_config(value[0], algorithm)
        return self._key_config(value)

    def _encode_json_signature(
        self,
        payload_segment: bytes,
        signer: JWSSigner | tuple[Any, str],
        json_encoder: type[json.JSONEncoder] | None,
        sort_headers: bool,
    ) -> dict[str, str]:
        if isinstance(signer, tuple):
            if len(signer) != 2:
                raise ValueError("Tuple signers must be (key, algorithm)")
            signer = {"key": signer[0], "algorithm": signer[1]}

        if not isinstance(signer, Mapping):
            raise TypeError("Each signer must be a mapping or (key, algorithm) tuple")

        key = signer.get("key")
        algorithm = signer.get("algorithm", signer.get("alg"))
        if key is None:
            if callable(signer.get("key_getter")):
                key = signer["key_getter"]()
            else:
                raise InvalidTokenError("Each JSON signer requires a key")

        protected = self._copy_header(
            signer.get("protected") or signer.get("protected_headers")
        )
        unprotected = self._copy_header(
            signer.get("header")
            or signer.get("unprotected_headers")
            or signer.get("headers")
        )

        if algorithm is None:
            algorithm = protected.get("alg")
        if algorithm is None:
            algorithm = key.algorithm_name if isinstance(key, PyJWK) else "HS256"

        if "alg" in protected and protected["alg"] != algorithm:
            raise InvalidAlgorithmError("Conflicting algorithm values")
        protected["alg"] = algorithm

        kid = signer.get("kid")
        if kid is not None:
            protected.setdefault("kid", kid)

        self._validate_json_headers(protected, unprotected)

        protected_json = json.dumps(
            protected,
            separators=(",", ":"),
            cls=json_encoder,
            sort_keys=sort_headers,
        ).encode("ascii")
        protected_segment = base64url_encode(protected_json)
        signing_input = b".".join([protected_segment, payload_segment])

        alg_obj = self.get_algorithm_by_name(str(protected["alg"]))
        signing_key = key.key if isinstance(key, PyJWK) else key
        prepared_key = alg_obj.prepare_key(signing_key)
        key_length_msg = alg_obj.check_key_length(prepared_key)
        if key_length_msg:
            if self.options.get("enforce_minimum_key_length", False):
                raise InvalidKeyError(key_length_msg)
            warnings.warn(key_length_msg, InsecureKeyLengthWarning, stacklevel=2)

        signature = alg_obj.sign(signing_input, prepared_key)
        result: dict[str, Any] = {
            "protected": protected_segment.decode("ascii"),
            "signature": base64url_encode(signature).decode("ascii"),
        }
        if unprotected:
            result["header"] = unprotected
        return result

    @staticmethod
    def _copy_header(header: Any) -> dict[str, Any]:
        if header is None:
            return {}
        if not isinstance(header, dict):
            raise InvalidTokenError("JWS headers must be JSON objects")
        return dict(header)

    def _validate_json_headers(
        self, protected: dict[str, Any], unprotected: dict[str, Any]
    ) -> None:
        duplicate_names = set(protected) & set(unprotected)
        if duplicate_names:
            raise InvalidTokenError(
                "Duplicate JWS header parameter(s): "
                + ", ".join(sorted(duplicate_names))
            )
        merged = {**protected, **unprotected}
        self._validate_headers(protected, encoding=True)
        self._validate_headers(unprotected, encoding=True)
        self._validate_headers(merged)
        if "crit" in unprotected:
            raise InvalidTokenError("The 'crit' header must be protected")
        if "alg" not in protected:
            raise InvalidAlgorithmError("Algorithm not specified")
        if merged.get("b64", True) is False:
            raise InvalidTokenError(
                "JWS JSON Serialization does not support unencoded payloads"
            )

    def _verify_json_signature(
        self,
        index: int,
        payload_segment: bytes,
        raw_signature: Any,
        key_configs: dict[str, Any],
        algorithms: Sequence[str] | None,
        options: SigOptions,
        verify_signature: bool,
    ) -> JWSJSONSignatureResult:
        result: JWSJSONSignatureResult = {
            "index": index,
            "kid": None,
            "protected": {},
            "header": {},
            "signature": b"",
            "valid": False if verify_signature else None,
            "status": "invalid" if verify_signature else "skipped",
            "error": None,
            "error_type": None,
        }

        try:
            if not isinstance(raw_signature, dict):
                raise DecodeError("Invalid JWS signature object")
            protected, unprotected = self._parse_json_headers(raw_signature)
            signature_segment = raw_signature["signature"].encode("ascii")
            signature = self._decode_base64url_segment(
                signature_segment, "signature"
            )
            self._validate_json_headers(protected, unprotected)
            merged_header = {**protected, **unprotected}
            kid = merged_header.get("kid")

            result.update(
                {
                    "protected": protected,
                    "header": unprotected,
                    "signature": signature,
                    "kid": kid if isinstance(kid, str) else None,
                }
            )

            if verify_signature:
                verification_key, allowed_algorithms = self._resolve_json_key(
                    kid, key_configs, algorithms, merged_header["alg"]
                )
                protected_segment = raw_signature.get("protected", "").encode("ascii")
                signing_input = b".".join([protected_segment, payload_segment])
                self._verify_signature(
                    signing_input,
                    merged_header,
                    signature,
                    verification_key,
                    allowed_algorithms,
                    options=options,
                )
                result.update(
                    {
                        "valid": True,
                        "status": "valid",
                        "error": None,
                        "error_type": None,
                    }
                )
            else:
                result.update({"status": "skipped", "valid": None})
        except (
            PyJWTError,
            ValueError,
            TypeError,
            NotImplementedError,
        ) as err:
            if verify_signature:
                result.update({"valid": False, "status": "invalid"})
            else:
                result.update({"valid": None, "status": "invalid"})
            result["error"] = str(err) or err.__class__.__name__
            result["error_type"] = err.__class__.__name__

        return result

    def _parse_json_headers(
        self, raw_signature: dict[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        allowed_fields = {"protected", "header", "signature"}
        invalid_fields = set(raw_signature) - allowed_fields
        if invalid_fields:
            raise DecodeError("Invalid JWS signature object")

        signature = raw_signature.get("signature")
        if not isinstance(signature, str):
            raise DecodeError("Invalid JWS signature")

        unprotected = raw_signature.get("header", {})
        if not isinstance(unprotected, dict):
            raise DecodeError("Invalid JWS unprotected header")

        protected_segment = raw_signature.get("protected", "")
        if not isinstance(protected_segment, str):
            raise DecodeError("Invalid JWS protected header")
        if protected_segment == "":
            return {}, dict(unprotected)

        protected_data = self._decode_base64url_segment(
            protected_segment.encode("ascii"), "protected header"
        )
        try:
            protected = json.loads(
                protected_data,
                object_pairs_hook=self._reject_duplicate_json_keys,
            )
        except (ValueError, RecursionError) as err:
            raise DecodeError(f"Invalid protected header string: {err}") from err

        if not isinstance(protected, dict):
            raise DecodeError("Invalid protected header string: must be a json object")

        return protected, dict(unprotected)

    def _resolve_json_key(
        self,
        kid: str | None,
        key_configs: dict[str, Any],
        global_algorithms: Sequence[str] | None,
        algorithm: str,
    ) -> tuple[Any, Sequence[str] | None]:
        if "default" in key_configs:
            if kid is not None:
                raise InvalidKeyError("No key found for signature")
            config = key_configs["default"]
        elif "mapping" in key_configs:
            if kid is None or kid not in key_configs["mapping"]:
                raise InvalidKeyError("No key found for signature")
            config = key_configs["mapping"][kid]
        elif "callable" in key_configs:
            config = self._coerce_key_config(key_configs["callable"](kid))
        else:
            matching = []
            for config in key_configs["sequence"]:
                config_kid = config["key"].get("kid") if isinstance(
                    config["key"], Mapping
                ) else None
                if config_kid is None or config_kid == kid:
                    matching.append(config)
            if len(matching) != 1:
                raise InvalidKeyError("No key found for signature")
            config = matching[0]

        key_value = config["key"]
        if isinstance(key_value, Mapping) and "key" in key_value:
            key_value = key_value["key"]
        allowed_algorithms = config["algorithms"] or global_algorithms
        if allowed_algorithms is None and not isinstance(key_value, PyJWK):
            raise DecodeError(
                'It is required that you pass in a value for the "algorithms" '
                "argument when decoding a JWS JSON Serialization."
            )
        if key_value in ("", b"", None) and algorithm != "none":
            raise InvalidKeyError("No key found for signature")

        if config["algorithms"] is not None and global_algorithms is not None:
            allowed = set(config["algorithms"]) & set(global_algorithms)
            return key_value, list(allowed)
        return key_value, allowed_algorithms

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
decode_complete = _jws_global_obj.decode_complete
decode = _jws_global_obj.decode
encode_json = _jws_global_obj.encode_json
encode_general = _jws_global_obj.encode_general
encode_flattened = _jws_global_obj.encode_flattened
decode_json_complete = _jws_global_obj.decode_json_complete
decode_json = _jws_global_obj.decode_json
decode_general_complete = _jws_global_obj.decode_general_complete
decode_general = _jws_global_obj.decode_general
decode_flattened_complete = _jws_global_obj.decode_flattened_complete
decode_flattened = _jws_global_obj.decode_flattened
verify_json_signatures = _jws_global_obj.verify_json_signatures
register_algorithm = _jws_global_obj.register_algorithm
unregister_algorithm = _jws_global_obj.unregister_algorithm
get_algorithm_by_name = _jws_global_obj.get_algorithm_by_name
get_unverified_header = _jws_global_obj.get_unverified_header
