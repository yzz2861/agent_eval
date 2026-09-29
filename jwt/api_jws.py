from __future__ import annotations

import binascii
import json
import warnings
from collections.abc import Sequence
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
)
from .utils import base64url_decode, base64url_encode
from .warnings import InsecureKeyLengthWarning, RemovedInPyjwt3Warning

if TYPE_CHECKING:
    from .algorithms import AllowedPrivateKeys, AllowedPublicKeys
    from .types import CritValidator, SigOptions

_ALGORITHM_UNSET = object()
_BASE64URL_ALPHABET = (
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def _validate_b64_crit(value: Any, header: dict[str, Any]) -> None:
    # RFC 7797 §4: the "b64" header parameter value must be a boolean.
    if not isinstance(value, bool):
        raise InvalidTokenError("The 'b64' header parameter must be a boolean")


# Critical header extensions that PyJWT understands out of the box. These
# are always present in every instance registry and cannot be overridden
# or unregistered.
_BUILTIN_CRIT_EXTENSIONS: dict[str, CritValidator] = {"b64": _validate_b64_crit}


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

        # Per-instance registry of understood "crit" extensions. Starts
        # from the built-ins; applications declare additional extensions
        # via register_crit_extension(). Never a process-global set.
        self._crit_extensions: dict[str, CritValidator] = dict(_BUILTIN_CRIT_EXTENSIONS)

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

    def register_crit_extension(self, name: str, validator: CritValidator) -> None:
        """
        Registers a critical ("crit") header extension that this instance
        understands, together with its semantic validation callback.

        The validator is called with the extension's header value and the
        complete protected header dict, and must raise (typically
        jwt.exceptions.InvalidTokenError) when the value is not acceptable.
        Validators only run after the signature has been verified, so they
        are never invoked for unauthenticated tokens.

        Registration is per-instance and does not affect other decoders.
        Built-in extensions (currently only "b64") cannot be overridden.

        :param str name: the extension name as it appears in "crit"
        :param validator: the semantic validation callback
        :raises TypeError: if 'name' is not a string or 'validator' is not
            callable
        :raises ValueError: if 'name' is empty or already registered
        """
        if not isinstance(name, str):
            raise TypeError("Critical extension name must be a string")
        if not name:
            raise ValueError("Critical extension name must not be empty")
        if name in self._crit_extensions:
            raise ValueError(f"Critical extension {name!r} is already registered")
        if not callable(validator):
            raise TypeError("Critical extension validator must be callable")

        self._crit_extensions[name] = validator

    def unregister_crit_extension(self, name: str) -> None:
        """
        Unregisters a critical ("crit") header extension from this instance.

        :param str name: the extension name to remove
        :raises ValueError: if 'name' is a built-in extension
        :raises KeyError: if 'name' is not registered
        """
        if name in _BUILTIN_CRIT_EXTENSIONS:
            raise ValueError(f"Cannot unregister built-in critical extension {name!r}")
        if name not in self._crit_extensions:
            raise KeyError(
                "The specified critical extension could not be removed"
                " because it is not registered."
            )

        del self._crit_extensions[name]

    def get_crit_extensions(self) -> list[str]:
        """
        Returns the names of the critical ("crit") header extensions this
        instance understands, including the built-in ones.

        :rtype: list[str]
        """
        return list(self._crit_extensions)

    def encode(
        self,
        payload: bytes,
        key: AllowedPrivateKeys | PyJWK | str | bytes,
        algorithm: str | None = _ALGORITHM_UNSET,  # type: ignore[assignment]
        headers: dict[str, Any] | None = None,
        json_encoder: type[json.JSONEncoder] | None = None,
        is_payload_detached: bool = False,
        sort_headers: bool = True,
        validate_crit: bool = False,
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

        if validate_crit and "crit" in header:
            # Opt-in producer-side check: verify that the extension headers
            # being generated are complete and well-formed according to the
            # extensions registered on this instance.
            crit_registry = dict(self._crit_extensions)
            self._validate_crit_format(header, crit_registry)
            self._run_crit_validators(header, crit_registry)

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

        # Snapshot the extension registry so the whole decode uses one
        # consistent view, even if extensions are registered or
        # unregistered concurrently while the decode is in flight.
        crit_registry = dict(self._crit_extensions)

        payload, signing_input, header, signature = self._load(jwt)

        self._validate_headers(header, crit_registry=crit_registry)

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
            # Semantic extension callbacks run only after the signature
            # has been verified, so validators with side effects never
            # execute for unauthenticated tokens.
            self._run_crit_validators(header, crit_registry)

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

    def _validate_headers(
        self,
        headers: dict[str, Any],
        *,
        encoding: bool = False,
        crit_registry: dict[str, CritValidator] | None = None,
    ) -> None:
        if "kid" in headers:
            self._validate_kid(headers["kid"])
        if not encoding and "crit" in headers:
            if crit_registry is None:
                crit_registry = dict(self._crit_extensions)
            self._validate_crit_format(headers, crit_registry)

    def _validate_kid(self, kid: Any) -> None:
        if not isinstance(kid, str):
            raise InvalidTokenError("Key ID header parameter must be a string")

    @staticmethod
    def _validate_crit_format(
        headers: dict[str, Any], crit_registry: dict[str, CritValidator]
    ) -> None:
        # Structural validation only: this runs before signature
        # verification and must stay free of application-level side
        # effects. Semantic checks live in _run_crit_validators.
        crit = headers["crit"]
        if not isinstance(crit, list) or len(crit) == 0:
            raise InvalidTokenError("Invalid 'crit' header: must be a non-empty list")
        seen: set[str] = set()
        for ext in crit:
            if not isinstance(ext, str):
                raise InvalidTokenError("Invalid 'crit' header: values must be strings")
            if ext in seen:
                raise InvalidTokenError(
                    f"Invalid 'crit' header: duplicate extension {ext!r}"
                )
            seen.add(ext)
            if ext not in crit_registry:
                raise InvalidTokenError(f"Unsupported critical extension: {ext}")
            if ext not in headers:
                raise InvalidTokenError(
                    f"Critical extension '{ext}' is missing from headers"
                )

    @staticmethod
    def _run_crit_validators(
        headers: dict[str, Any], crit_registry: dict[str, CritValidator]
    ) -> None:
        # Semantic validation for each declared critical extension. Only
        # called after the signature has been verified (or, on the encode
        # path, for self-produced headers).
        crit = headers.get("crit")
        if not crit:
            return
        for ext in crit:
            validator = crit_registry.get(ext)
            if validator is not None:
                validator(headers[ext], headers)


_jws_global_obj = PyJWS()
encode = _jws_global_obj.encode
decode_complete = _jws_global_obj.decode_complete
decode = _jws_global_obj.decode
register_algorithm = _jws_global_obj.register_algorithm
unregister_algorithm = _jws_global_obj.unregister_algorithm
get_algorithm_by_name = _jws_global_obj.get_algorithm_by_name
get_unverified_header = _jws_global_obj.get_unverified_header
