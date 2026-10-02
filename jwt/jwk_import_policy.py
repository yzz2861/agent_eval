from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .exceptions import MissingCryptographyError, PyJWTError
from .types import JWKDict
from .utils import from_base64url_uint

# JWK members that carry key material. Used to fingerprint the cryptographic
# material of a key so that two keys sharing a ``kid`` can be compared without
# ever embedding the values themselves in a report.
_MATERIAL_MEMBERS = ("kty", "crv", "k", "n", "e", "x", "y")


# Map an ``alg`` value to the ``kty`` family it is consistent with.
def _kty_for_alg(alg: str) -> str | None:
    if alg.startswith("HS"):
        return "oct"
    if alg.startswith(("RS", "PS")):
        return "RSA"
    if alg.startswith("ES"):
        return "EC"
    if alg == "EdDSA":
        return "OKP"
    return None


# Map an ``alg`` value to the curve it requires, where applicable.
_CURVE_FOR_ALG = {
    "ES256": "P-256",
    "ES384": "P-384",
    "ES512": "P-521",
    "ES256K": "secp256k1",
    "EdDSA": "Ed25519",
}


def _material_fingerprint(jwk: JWKDict) -> tuple[tuple[str, Any], ...]:
    return tuple((name, jwk.get(name)) for name in _MATERIAL_MEMBERS if name in jwk)


@dataclass(frozen=True)
class JWKImportDecision:
    """The per-key outcome of a :class:`JWKImportPolicy` evaluation.

    ``reasons`` only ever contains static metadata (``kid``, ``kty``, ``alg``,
    ``use``, ``key_ops``, ``crv``, key size) and never key material, so a
    decision is safe to log or include in an error report.
    """

    index: int
    kid: str | None
    accepted: bool
    reasons: tuple[str, ...] = ()


class JWKImportReport:
    """The result of evaluating a JWK Set against a :class:`JWKImportPolicy`."""

    def __init__(self, decisions: list[JWKImportDecision]) -> None:
        self.decisions: list[JWKImportDecision] = decisions

    @property
    def accepted(self) -> list[JWKImportDecision]:
        """Decisions for keys that passed the policy."""
        return [decision for decision in self.decisions if decision.accepted]

    @property
    def rejected(self) -> list[JWKImportDecision]:
        """Decisions for keys that were rejected by the policy."""
        return [decision for decision in self.decisions if not decision.accepted]

    @property
    def accepted_indices(self) -> list[int]:
        """Indices (into the original ``keys`` list) of accepted keys."""
        return [decision.index for decision in self.accepted]

    @property
    def ok(self) -> bool:
        """``True`` when no key was rejected."""
        return not self.rejected

    def summary(self) -> str:
        """A sanitized, one-line-per-key description of the rejections."""
        lines = []
        for decision in self.rejected:
            label = (
                f"kid {decision.kid!r}"
                if decision.kid is not None
                else f"key at index {decision.index}"
            )
            lines.append(f"{label}: {'; '.join(decision.reasons)}")
        return "\n".join(lines)

    def __repr__(self) -> str:
        return (
            f"JWKImportReport(accepted={len(self.accepted)}, "
            f"rejected={len(self.rejected)})"
        )


class JWKImportPolicy:
    """An optional import policy for screening JWK Set members before use.

    Each key is checked for ``kty``/``alg`` consistency, ``use``, ``key_ops``,
    allowed curves, and a configurable minimum RSA key size. Keys that share a
    ``kid`` but carry different key material are all rejected rather than
    silently resolving to the first one.

    :param allowed_ktys: If set, only these ``kty`` values are accepted.
    :param allowed_algs: If set, a key's ``alg`` (when present) must be listed.
    :param allowed_curves: If set, EC/OKP keys must use one of these curves.
    :param allowed_uses: A key's ``use`` (when present) must be listed.
        Defaults to ``("sig",)``; pass ``None`` to disable the check.
    :param allowed_key_ops: A key's ``key_ops`` (when present) must intersect
        this set. Defaults to ``("verify",)``; pass ``None`` to disable.
    :param min_rsa_bits: If set, RSA keys smaller than this are rejected.
    :param strict: When ``True``, any rejection fails the whole set (raised as
        :class:`jwt.exceptions.PyJWKSetImportError` by :class:`PyJWKSet`).
        When ``False`` (the default), rejected keys are quarantined and the
        remaining keys are imported.
    """

    def __init__(
        self,
        *,
        allowed_ktys: set[str] | frozenset[str] | None = None,
        allowed_algs: set[str] | frozenset[str] | None = None,
        allowed_curves: set[str] | frozenset[str] | None = None,
        allowed_uses: set[str] | frozenset[str] | None = frozenset({"sig"}),
        allowed_key_ops: set[str] | frozenset[str] | None = frozenset({"verify"}),
        min_rsa_bits: int | None = None,
        strict: bool = False,
    ) -> None:
        self.allowed_ktys = allowed_ktys
        self.allowed_algs = allowed_algs
        self.allowed_curves = allowed_curves
        self.allowed_uses = allowed_uses
        self.allowed_key_ops = allowed_key_ops
        self.min_rsa_bits = min_rsa_bits
        self.strict = strict

    def evaluate(self, keys: list[Any]) -> JWKImportReport:
        """Evaluate *keys* against this policy.

        :param keys: The ``keys`` list from a JWK Set.
        :returns: A :class:`JWKImportReport` with one decision per item.
        """
        decisions = [
            JWKImportDecision(
                index=index,
                kid=key.get("kid") if isinstance(key, dict) else None,
                accepted=not reasons,
                reasons=tuple(reasons),
            )
            for index, key in enumerate(keys)
            for reasons in [self._check_key(key)]
        ]
        self._check_duplicate_kids(keys, decisions)
        return JWKImportReport(decisions)

    def _check_key(self, key: Any) -> list[str]:
        if not isinstance(key, dict):
            return ["key is not a JSON object"]

        reasons: list[str] = []

        kty = key.get("kty")
        if not kty:
            reasons.append("missing 'kty'")
        elif self.allowed_ktys is not None and kty not in self.allowed_ktys:
            reasons.append(f"kty {kty!r} is not allowed")

        alg = key.get("alg")
        if alg is not None:
            if self.allowed_algs is not None and alg not in self.allowed_algs:
                reasons.append(f"alg {alg!r} is not allowed")
            expected_kty = _kty_for_alg(alg) if isinstance(alg, str) else None
            if kty and expected_kty is not None and expected_kty != kty:
                reasons.append(f"alg {alg!r} is inconsistent with kty {kty!r}")

        use = key.get("use")
        if (
            use is not None
            and self.allowed_uses is not None
            and use not in self.allowed_uses
        ):
            reasons.append(f"use {use!r} is not allowed")

        key_ops = key.get("key_ops")
        if key_ops is not None and self.allowed_key_ops is not None:
            if not isinstance(key_ops, list) or not set(key_ops) & set(
                self.allowed_key_ops
            ):
                reasons.append("key_ops does not include an allowed operation")

        crv = key.get("crv")
        if kty in ("EC", "OKP"):
            if (
                crv is not None
                and self.allowed_curves is not None
                and crv not in self.allowed_curves
            ):
                reasons.append(f"crv {crv!r} is not allowed")
            if (
                isinstance(alg, str)
                and crv is not None
                and _CURVE_FOR_ALG.get(alg) is not None
                and _CURVE_FOR_ALG[alg] != crv
            ):
                reasons.append(f"alg {alg!r} is inconsistent with crv {crv!r}")

        if kty == "RSA" and self.min_rsa_bits is not None:
            reasons.extend(self._check_rsa_bits(key))

        reasons.extend(self._check_constructible(key))
        return reasons

    def _check_rsa_bits(self, key: JWKDict) -> list[str]:
        n = key.get("n")
        if not isinstance(n, str):
            return ["missing RSA modulus 'n'"]
        try:
            bits = from_base64url_uint(n).bit_length()
        except Exception:
            return ["unable to determine RSA key size"]
        if bits < self.min_rsa_bits:
            return [f"RSA key size {bits} is below the minimum {self.min_rsa_bits}"]
        return []

    @staticmethod
    def _check_constructible(key: JWKDict) -> list[str]:
        # Imported here to avoid a circular import at module load time.
        from .api_jwk import PyJWK

        try:
            PyJWK(key)
        except MissingCryptographyError:
            raise
        except PyJWTError as error:
            # Only the exception type is reported: error messages may embed
            # the raw JWK, which can contain private key material.
            return [f"key failed to load ({type(error).__name__})"]
        return []

    @staticmethod
    def _check_duplicate_kids(
        keys: list[Any], decisions: list[JWKImportDecision]
    ) -> None:
        by_kid: dict[str, list[int]] = {}
        for decision in decisions:
            if decision.accepted and decision.kid is not None:
                by_kid.setdefault(decision.kid, []).append(decision.index)

        for kid, indices in by_kid.items():
            if len(indices) < 2:
                continue
            fingerprints = {
                index: _material_fingerprint(keys[index]) for index in indices
            }
            if len(set(fingerprints.values())) > 1:
                # Same kid, different material: never silently pick the first.
                for index in indices:
                    decisions[index] = _reject(
                        decisions[index],
                        f"kid {kid!r} is shared by keys with different key material",
                    )
            else:
                # Exact duplicates: import the first, drop the rest.
                for index in indices[1:]:
                    decisions[index] = _reject(
                        decisions[index],
                        f"duplicate of the key at index {indices[0]} "
                        f"(identical kid {kid!r} and material)",
                    )


def _reject(decision: JWKImportDecision, reason: str) -> JWKImportDecision:
    return JWKImportDecision(
        index=decision.index,
        kid=decision.kid,
        accepted=False,
        reasons=decision.reasons + (reason,),
    )
