from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .types import JWKDict
from .utils import base64url_decode

__all__ = ["JWKImportDecision", "JWKImportPolicy", "JWKImportReport"]

#: JWK parameters that carry private key material (RFC 7518 / RFC 8037).
#: These must never appear in import reports or error messages.
PRIVATE_JWK_PARAMETERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})

#: Public key material per kty, used to tell whether two JWKs that share
#: a kid actually describe the same key. For oct keys the material is
#: the secret itself; it is only ever compared, never reported.
_PUBLIC_MATERIAL_PARAMETERS: dict[str, tuple[str, ...]] = {
    "RSA": ("kty", "n", "e"),
    "EC": ("kty", "crv", "x", "y"),
    "OKP": ("kty", "crv", "x"),
    "oct": ("kty", "k"),
}

#: Maps a JWS alg to the kty (and, where the algorithm is bound to a
#: single curve, the crv) a JWK must have to be consistent with it.
_ALG_KTY_CRV: dict[str, tuple[str, str | None]] = {
    "HS256": ("oct", None),
    "HS384": ("oct", None),
    "HS512": ("oct", None),
    "RS256": ("RSA", None),
    "RS384": ("RSA", None),
    "RS512": ("RSA", None),
    "PS256": ("RSA", None),
    "PS384": ("RSA", None),
    "PS512": ("RSA", None),
    "ES256": ("EC", "P-256"),
    "ES384": ("EC", "P-384"),
    "ES512": ("EC", "P-521"),
    "ES521": ("EC", "P-521"),
    "ES256K": ("EC", "secp256k1"),
    "EdDSA": ("OKP", None),
}

KID_CONFLICT_ISOLATE = "isolate"
KID_CONFLICT_REJECT = "reject"


def _rsa_modulus_bits(jwk: JWKDict) -> int | None:
    """Return the bit length of the RSA modulus, or None if undecodable."""
    n = jwk.get("n")
    if not isinstance(n, str):
        return None
    try:
        return int.from_bytes(base64url_decode(n.encode("ascii")), "big").bit_length()
    except Exception:
        return None


def public_key_material(jwk: JWKDict) -> tuple[tuple[str, Any], ...] | None:
    """Return a comparable fingerprint of a JWK's public key material.

    Two JWKs with the same fingerprint describe the same key, even if their
    metadata (kid, use, alg, ...) differs. Returns None for unsupported or
    malformed key types.
    """
    kty = jwk.get("kty")
    fields = _PUBLIC_MATERIAL_PARAMETERS.get(kty) if isinstance(kty, str) else None
    if fields is None:
        return None
    return tuple((name, jwk.get(name)) for name in fields)


@dataclass(frozen=True)
class JWKImportPolicy:
    """Optional strict import policy for :class:`jwt.PyJWKSet`.

    When a policy is supplied, every JWK in the set is checked before it is
    accepted, and the outcome of each check is recorded in
    :attr:`jwt.PyJWKSet.import_report`. The defaults describe a key suitable
    for *verifying* signatures:

    - ``alg`` (when present) must be recognized and consistent with ``kty``
      (and ``crv`` for curve-bound algorithms).
    - ``use`` (when present) must be one of ``allowed_uses``.
    - ``key_ops`` (when present) must include every operation in
      ``required_key_ops``.
    - EC/OKP ``crv`` must be one of ``allowed_curves``.
    - RSA keys must be at least ``min_rsa_bits`` bits long.

    When several accepted keys share a ``kid`` but contain different key
    material, ``on_kid_conflict`` selects the behavior: ``"isolate"`` (the
    default) drops every key with that ``kid`` and records the conflict in
    the report, while ``"reject"`` raises
    :class:`jwt.exceptions.PyJWKSetError` for the whole set. Identical
    duplicates are always deduplicated, keeping the first occurrence.
    """

    allowed_uses: tuple[str, ...] = ("sig",)
    required_key_ops: tuple[str, ...] = ("verify",)
    allowed_curves: tuple[str, ...] = ("P-256", "P-384", "P-521", "Ed25519")
    min_rsa_bits: int = 2048
    on_kid_conflict: str = KID_CONFLICT_ISOLATE

    def __post_init__(self) -> None:
        if self.on_kid_conflict not in (KID_CONFLICT_ISOLATE, KID_CONFLICT_REJECT):
            raise ValueError(
                f"on_kid_conflict must be {KID_CONFLICT_ISOLATE!r} or "
                f"{KID_CONFLICT_REJECT!r}, got {self.on_kid_conflict!r}"
            )

    def evaluate(self, jwk: JWKDict) -> tuple[str, ...]:
        """Check a single JWK against this policy.

        :param jwk: The JWK data, as a dictionary.
        :returns: A tuple of human-readable rejection reasons. An empty tuple
            means the key is acceptable. Reasons only ever reference public
            metadata (kty, alg, crv, use, key_ops) and key sizes -- never
            private key material.
        """
        reasons: list[str] = []

        kty = jwk.get("kty")
        alg = jwk.get("alg")
        if alg is not None:
            if not isinstance(alg, str):
                reasons.append("alg is not a string")
            else:
                expected = _ALG_KTY_CRV.get(alg)
                if expected is None:
                    reasons.append(f"alg {alg!r} is not a recognized algorithm")
                else:
                    expected_kty, expected_crv = expected
                    if kty != expected_kty:
                        reasons.append(
                            f"kty {kty!r} is inconsistent with alg {alg!r}"
                            f" (expected kty {expected_kty!r})"
                        )
                    elif expected_crv is not None and jwk.get("crv") != expected_crv:
                        reasons.append(
                            f"crv {jwk.get('crv')!r} is inconsistent with alg"
                            f" {alg!r} (expected crv {expected_crv!r})"
                        )

        use = jwk.get("use")
        if use is not None:
            if not isinstance(use, str):
                reasons.append("use is not a string")
            elif use not in self.allowed_uses:
                reasons.append(
                    f"use {use!r} is not allowed (allowed: {sorted(self.allowed_uses)})"
                )

        key_ops = jwk.get("key_ops")
        if key_ops is not None:
            if not isinstance(key_ops, list) or not all(
                isinstance(op, str) for op in key_ops
            ):
                reasons.append("key_ops is not a list of strings")
            elif not set(self.required_key_ops) <= set(key_ops):
                reasons.append(
                    f"key_ops {sorted(key_ops)} does not include the required"
                    f" operations {sorted(self.required_key_ops)}"
                )

        if kty in ("EC", "OKP"):
            crv = jwk.get("crv")
            if crv is not None and crv not in self.allowed_curves:
                reasons.append(
                    f"crv {crv!r} is not in the allowed curves"
                    f" {sorted(self.allowed_curves)}"
                )

        if kty == "RSA" and self.min_rsa_bits > 0:
            bits = _rsa_modulus_bits(jwk)
            if bits is not None and bits < self.min_rsa_bits:
                reasons.append(
                    f"RSA key is {bits} bits, below the minimum of"
                    f" {self.min_rsa_bits} bits"
                )

        return tuple(reasons)


@dataclass(frozen=True)
class JWKImportDecision:
    """The per-key outcome of applying a :class:`JWKImportPolicy`.

    ``index`` is the key's position in the original ``keys`` list of the
    JWK Set. ``reasons`` is empty for accepted keys.
    """

    index: int
    kid: str | None
    accepted: bool
    reasons: tuple[str, ...] = ()

    def __str__(self) -> str:
        status = "accepted" if self.accepted else "rejected"
        detail = f": {'; '.join(self.reasons)}" if self.reasons else ""
        return f"key #{self.index} (kid={self.kid!r}) {status}{detail}"


class JWKImportReport:
    """The outcome of importing a JWK Set under a :class:`JWKImportPolicy`.

    Available as :attr:`jwt.PyJWKSet.import_report` when a policy was used.
    Its string representation lists one line per key and never includes
    private key material.
    """

    def __init__(self, decisions: list[JWKImportDecision]) -> None:
        self.decisions: tuple[JWKImportDecision, ...] = tuple(decisions)

    @property
    def accepted(self) -> tuple[JWKImportDecision, ...]:
        """Decisions for keys that entered the set."""
        return tuple(d for d in self.decisions if d.accepted)

    @property
    def rejected(self) -> tuple[JWKImportDecision, ...]:
        """Decisions for keys that were skipped, deduplicated, or isolated."""
        return tuple(d for d in self.decisions if not d.accepted)

    def __len__(self) -> int:
        return len(self.decisions)

    def __str__(self) -> str:
        return "\n".join(str(decision) for decision in self.decisions)
