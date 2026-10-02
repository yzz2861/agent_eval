from __future__ import annotations

import json
import time
from collections.abc import Iterator
from typing import Any

from .algorithms import get_default_algorithms, has_crypto, requires_cryptography
from .exceptions import (
    InvalidKeyError,
    MissingCryptographyError,
    PyJWKError,
    PyJWKSetError,
    PyJWTError,
)
from .jwk_import_policy import (
    KID_CONFLICT_REJECT,
    JWKImportDecision,
    JWKImportPolicy,
    JWKImportReport,
    public_key_material,
)
from .types import JWKDict


class PyJWK:
    def __init__(self, jwk_data: JWKDict, algorithm: str | None = None) -> None:
        """A class that represents a `JSON Web Key <https://www.rfc-editor.org/rfc/rfc7517>`_.

        :param jwk_data: The decoded JWK data.
        :type jwk_data: dict[str, typing.Any]
        :param algorithm: The key algorithm. If not specified, the key's ``alg`` will be used.
        :type algorithm: str or None
        :raises InvalidKeyError: If the key type (``kty``) is not found or unsupported, or if the curve (``crv``) is not found or unsupported.
        :raises MissingCryptographyError: If the algorithm requires ``cryptography`` to be installed and it is not available.
        :raises PyJWKError: If unable to find an algorithm for the key.
        """
        self._jwk_data = jwk_data

        kty = self._jwk_data.get("kty", None)
        if not kty:
            raise InvalidKeyError(f"kty is not found: {self._jwk_data}")

        if not algorithm and isinstance(self._jwk_data, dict):
            algorithm = self._jwk_data.get("alg", None)

        if not algorithm:
            # Determine alg with kty (and crv).
            crv = self._jwk_data.get("crv", None)
            if kty == "EC":
                if crv == "P-256" or not crv:
                    algorithm = "ES256"
                elif crv == "P-384":
                    algorithm = "ES384"
                elif crv == "P-521":
                    algorithm = "ES512"
                elif crv == "secp256k1":
                    algorithm = "ES256K"
                else:
                    raise InvalidKeyError(f"Unsupported crv: {crv}")
            elif kty == "RSA":
                algorithm = "RS256"
            elif kty == "oct":
                algorithm = "HS256"
            elif kty == "OKP":
                if not crv:
                    raise InvalidKeyError(f"crv is not found: {self._jwk_data}")
                if crv == "Ed25519":
                    algorithm = "EdDSA"
                else:
                    raise InvalidKeyError(f"Unsupported crv: {crv}")
            else:
                raise InvalidKeyError(f"Unsupported kty: {kty}")

        if not has_crypto and algorithm in requires_cryptography:
            raise MissingCryptographyError(
                f"{algorithm} requires 'cryptography' to be installed."
            )

        self.algorithm_name = algorithm

        try:
            self.Algorithm = get_default_algorithms()[algorithm]
        except KeyError:
            raise PyJWKError(
                f"Unable to find an algorithm for key: {self._jwk_data}",
            ) from None

        try:
            self.key = self.Algorithm.from_jwk(self._jwk_data)
        except (TypeError, ValueError) as error:
            raise InvalidKeyError(
                f"Unable to construct key from JWK: {error}"
            ) from error

    @staticmethod
    def from_dict(obj: JWKDict, algorithm: str | None = None) -> PyJWK:
        """Creates a :class:`PyJWK` object from a JSON-like dictionary.

        :param obj: The JWK data, as a dictionary
        :type obj: dict[str, typing.Any]
        :param algorithm: The key algorithm. If not specified, the key's ``alg`` will be used.
        :type algorithm: str or None
        :rtype: PyJWK
        """
        return PyJWK(obj, algorithm)

    @staticmethod
    def from_json(data: str, algorithm: str | None = None) -> PyJWK:
        """Create a :class:`PyJWK` object from a JSON string.
        Implicitly calls :meth:`PyJWK.from_dict()`.

        :param str data: The JWK data, as a JSON string.
        :param algorithm:  The key algorithm.  If not specific, the key's ``alg`` will be used.
        :type algorithm: str or None

        :rtype: PyJWK
        """
        obj = json.loads(data)
        return PyJWK.from_dict(obj, algorithm)

    @property
    def key_type(self) -> str | None:
        """The `kty` property from the JWK.

        :rtype: str or None
        """
        return self._jwk_data.get("kty", None)

    @property
    def key_id(self) -> str | None:
        """The `kid` property from the JWK.

        :rtype: str or None
        """
        return self._jwk_data.get("kid", None)

    @property
    def public_key_use(self) -> str | None:
        """The `use` property from the JWK.

        :rtype: str or None
        """
        return self._jwk_data.get("use", None)


class PyJWKSet:
    def __init__(
        self,
        keys: list[JWKDict],
        import_policy: JWKImportPolicy | None = None,
    ) -> None:
        self.keys: list[PyJWK] = []
        self.import_report: JWKImportReport | None = None

        if not keys:
            raise PyJWKSetError("The JWK Set did not contain any keys")

        if not isinstance(keys, list):
            raise PyJWKSetError("Invalid JWK Set value")

        if import_policy is None:
            for key in keys:
                if not isinstance(key, dict):
                    # skip members that aren't JWK objects
                    continue
                try:
                    self.keys.append(PyJWK(key))
                except PyJWTError as error:
                    if isinstance(error, MissingCryptographyError):
                        raise error
                    # skip unusable keys
                    continue
        else:
            self._import_with_policy(keys, import_policy)

        if len(self.keys) == 0:
            if import_policy is None:
                raise PyJWKSetError(
                    "The JWK Set did not contain any usable keys. Perhaps 'cryptography' is not installed?"
                )
            raise PyJWKSetError(
                "The JWK Set did not contain any keys that satisfy the import policy"
            )

    def _import_with_policy(
        self, keys: list[JWKDict], import_policy: JWKImportPolicy
    ) -> None:
        decisions: list[JWKImportDecision] = []

        for index, key in enumerate(keys):
            if not isinstance(key, dict):
                decisions.append(
                    JWKImportDecision(
                        index, None, False, ("member is not a JWK object",)
                    )
                )
                continue

            kid = key.get("kid")
            if not isinstance(kid, str):
                kid = None

            reasons = import_policy.evaluate(key)
            if reasons:
                decisions.append(JWKImportDecision(index, kid, False, reasons))
                continue

            try:
                pyjwk = PyJWK(key)
            except PyJWTError as error:
                if isinstance(error, MissingCryptographyError):
                    raise error
                # Do not propagate the exception message: it may embed the
                # raw JWK, which can contain private key material.
                decisions.append(
                    JWKImportDecision(
                        index,
                        kid,
                        False,
                        (f"key could not be constructed ({type(error).__name__})",),
                    )
                )
                continue

            self.keys.append(pyjwk)
            decisions.append(JWKImportDecision(index, kid, True))

        self._resolve_duplicate_kids(decisions, import_policy)
        self.import_report = JWKImportReport(decisions)

    def _resolve_duplicate_kids(
        self,
        decisions: list[JWKImportDecision],
        import_policy: JWKImportPolicy,
    ) -> None:
        # Group accepted keys by kid; keys without a kid cannot collide.
        by_kid: dict[str, list[int]] = {}
        for position, pyjwk in enumerate(self.keys):
            if pyjwk.key_id is not None:
                by_kid.setdefault(pyjwk.key_id, []).append(position)

        drop: set[int] = set()
        # Map each accepted key back to its decision so it can be annotated.
        accepted_positions = [
            i for i, decision in enumerate(decisions) if decision.accepted
        ]

        for kid, positions in by_kid.items():
            if len(positions) < 2:
                continue

            materials = {
                public_key_material(self.keys[position]._jwk_data)
                for position in positions
            }

            if len(materials) == 1:
                # Same key repeated: keep the first occurrence.
                for position in positions[1:]:
                    drop.add(position)
                    decision_index = accepted_positions[position]
                    decisions[decision_index] = JWKImportDecision(
                        decisions[decision_index].index,
                        kid,
                        False,
                        ("duplicate of an earlier key with the same kid",),
                    )
                continue

            # Same kid, different key material: never silently pick one.
            if import_policy.on_kid_conflict == KID_CONFLICT_REJECT:
                raise PyJWKSetError(
                    f"The JWK Set contains conflicting keys for kid {kid!r}"
                )
            for position in positions:
                drop.add(position)
                decision_index = accepted_positions[position]
                decisions[decision_index] = JWKImportDecision(
                    decisions[decision_index].index,
                    kid,
                    False,
                    (f"conflicting key material for kid {kid!r}; key isolated",),
                )

        if drop:
            self.keys = [
                pyjwk
                for position, pyjwk in enumerate(self.keys)
                if position not in drop
            ]

    @staticmethod
    def from_dict(
        obj: dict[str, Any], import_policy: JWKImportPolicy | None = None
    ) -> PyJWKSet:
        keys = obj.get("keys", [])
        return PyJWKSet(keys, import_policy=import_policy)

    @staticmethod
    def from_json(data: str, import_policy: JWKImportPolicy | None = None) -> PyJWKSet:
        obj = json.loads(data)
        return PyJWKSet.from_dict(obj, import_policy=import_policy)

    def __getitem__(self, kid: str) -> PyJWK:
        for key in self.keys:
            if key.key_id == kid:
                return key
        raise KeyError(f"keyset has no key for kid: {kid}")

    def __iter__(self) -> Iterator[PyJWK]:
        return iter(self.keys)


class PyJWTSetWithTimestamp:
    def __init__(self, jwk_set: PyJWKSet):
        self.jwk_set = jwk_set
        self.timestamp = time.monotonic()

    def get_jwk_set(self) -> PyJWKSet:
        return self.jwk_set

    def get_timestamp(self) -> float:
        return self.timestamp
