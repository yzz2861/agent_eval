"""Dead Simple Signing Envelope"""

from __future__ import annotations

import logging
from typing import Any

from securesystemslib import exceptions
from securesystemslib._internal.utils import b64dec, b64enc, make_hashable
from securesystemslib.signer import Key, Signature, Signer

logger = logging.getLogger(__name__)


class Envelope:
    """DSSE Envelope to provide interface for signing arbitrary data.

    Attributes:
        payload: Arbitrary byte sequence of serialized body.
        payload_type: string that identifies how to interpret payload.
        signatures: dict of Signature key id and Signatures.

    """

    def __init__(
        self,
        payload: bytes,
        payload_type: str,
        signatures: dict[str, Signature],
    ):
        self.payload = payload
        self.payload_type = payload_type
        self.signatures = signatures

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Envelope):
            return False

        return (
            self.payload == other.payload
            and self.payload_type == other.payload_type
            and self.signatures == other.signatures
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.payload,
                self.payload_type,
                make_hashable(self.signatures),
            )
        )

    @classmethod
    def from_dict(cls, data: dict) -> Envelope:
        """Creates a DSSE Envelope from its JSON/dict representation.

        Arguments:
            data: A dict containing a valid payload, payloadType and signatures

        Raises:
            KeyError: If any of the "payload", "payloadType" and "signatures"
                fields are missing from the "data".

            FormatError: If signature in "signatures" is incorrect.

        Returns:
            A "Envelope" instance.
        """

        payload = b64dec(data["payload"])
        payload_type = data["payloadType"]

        signatures = {}
        for signature in data["signatures"]:
            signature["sig"] = b64dec(signature["sig"]).hex()
            sig = Signature.from_dict(signature)
            if sig.keyid in signatures:
                raise ValueError(f"Multiple signatures found for keyid {sig.keyid}")
            signatures[sig.keyid] = sig
        return cls(payload, payload_type, signatures)

    def to_dict(self) -> dict:
        """Returns the JSON-serializable dictionary representation of self."""

        signatures = []
        for signature in self.signatures.values():
            sig_dict = signature.to_dict()
            sig_dict["sig"] = b64enc(bytes.fromhex(sig_dict["sig"]))
            signatures.append(sig_dict)

        return {
            "payload": b64enc(self.payload),
            "payloadType": self.payload_type,
            "signatures": signatures,
        }

    def pae(self) -> bytes:
        """Pre-Auth-Encoding byte sequence of self."""

        payload_type = self.payload_type.encode("utf-8")
        return b"DSSEv1 %d %b %d %b" % (
            len(payload_type),
            payload_type,
            len(self.payload),
            self.payload,
        )

    def sign(self, signer: Signer) -> Signature:
        """Sign the payload and create the signature.

        Arguments:
            signer: A "Signer" class instance.

        Returns:
            A "Signature" instance.
        """

        signature = signer.sign(self.pae())
        self.signatures[signature.keyid] = signature

        return signature

    def verify(  # noqa: PLR0913
        self,
        keys: list[Key],
        threshold: int,
        *,
        artifact: Any = None,
        artifact_name: str | None = None,
        evidence: Any = None,
        certificates: Any = None,
        disabled_backends: Any = None,
        disabled_algorithms: Any = None,
        backend_status: Any = None,
        key_factories: Any = None,
    ) -> dict[str, Key]:
        """Verify the payload with the provided Keys.

        Arguments:
            keys: A list of public keys to verify the signatures.
            threshold: Number of signatures needed to pass the verification.
            artifact: Optional artifact bytes, path, or file object that the
                verification input refers to. Used with the evidence output.
            artifact_name: Optional artifact name to record in evidence.
            evidence: Optional offline evidence destination. A path writes a
                JSON document, a callable receives the evidence object, a
                writable object receives JSON, and ``True`` stores the evidence
                on ``self.last_evidence``.
            certificates: Optional caller-provided certificates used to
                establish the recorded public key identity.
            disabled_backends: Optional verifier backends that are no longer
                available. Their sealed conclusions are preserved but are not
                counted as recomputable.
            disabled_algorithms: Optional ``scheme`` or ``keytype/scheme``
                values that may not be used for recomputation.
            backend_status: Optional mapping of backend name to a status such
                as ``"retired"``.
            key_factories: Optional mapping from recorded implementation names
                to custom key factories.
        Raises:
            ValueError: If "threshold" is not valid.
            VerificationError: If the enclosed signatures do not pass the
                verification.

        Note:
            Mandating keyid in signatures and matching them with keyid of Key
            in order to consider them for verification, is not DSSE spec
            compliant (Issue #416).

        Returns:
            A dict of the threshold of unique public keys that verified a
            signature.
        """

        if (
            artifact is None
            and artifact_name is None
            and evidence is None
            and certificates is None
            and disabled_backends is None
            and disabled_algorithms is None
            and backend_status is None
            and key_factories is None
        ):
            return self._verify_legacy(keys, threshold)

        evidence_obj = self.verify_with_evidence(
            keys,
            threshold,
            artifact=artifact,
            artifact_name=artifact_name,
            certificates=certificates,
            disabled_backends=disabled_backends,
            disabled_algorithms=disabled_algorithms,
            backend_status=backend_status,
            key_factories=key_factories,
        )
        self._emit_evidence(evidence, evidence_obj)
        conclusion = evidence_obj.to_dict()["conclusion"]
        if conclusion["status"] != "verified":
            error = exceptions.VerificationError(
                conclusion.get("message")
                or "Evidence verification did not reach the required threshold"
            )
            error.evidence = evidence_obj  # type: ignore[attr-defined]
            raise error
        return evidence_obj.accepted_keys

    def _verify_legacy(self, keys: list[Key], threshold: int) -> dict[str, Key]:
        accepted_keys = {}
        pae = self.pae()

        # checks for threshold value.
        if threshold <= 0:
            raise ValueError("Threshold must be greater than 0")

        if len(keys) < threshold:
            raise ValueError("Number of keys can't be less than threshold")

        for signature in self.signatures.values():
            for key in keys:
                # If Signature keyid doesn't match with Key, skip.
                if not key.keyid == signature.keyid:
                    continue

                # If a key verifies the signature, we exit and use the result.
                try:
                    key.verify_signature(signature, pae)
                    accepted_keys[key.keyid] = key
                    break
                except exceptions.UnverifiedSignatureError:
                    continue

            # Break, if amount of accepted_keys are more than threshold.
            if len(accepted_keys) >= threshold:
                break

        if threshold > len(accepted_keys):
            raise exceptions.VerificationError(
                "Accepted signatures do not match threshold,"
                f" Found: {len(accepted_keys)}, Expected {threshold}"
            )

        return accepted_keys

    def verify_with_evidence(  # noqa: PLR0913
        self,
        keys: Any,
        threshold: int = 1,
        *,
        artifact: Any = None,
        artifact_name: str | None = None,
        certificates: Any = None,
        disabled_backends: Any = None,
        disabled_algorithms: Any = None,
        backend_status: Any = None,
        key_factories: Any = None,
    ) -> Evidence:
        """Verify once and return a sealed offline evidence document.

        Unlike :meth:`verify`, this method returns the evidence object even
        when the recorded conclusion is not ``verified``: the evidence states
        whether recomputation was possible and why it failed.
        """

        return seal_evidence(
            self,
            keys,
            threshold,
            artifact=artifact,
            artifact_name=artifact_name,
            certificates=certificates,
            disabled_backends=disabled_backends,
            disabled_algorithms=disabled_algorithms,
            backend_status=backend_status,
            key_factories=key_factories,
        )

    def seal_evidence(
        self,
        keys: Any,
        threshold: int = 1,
        **kwargs: Any,
    ) -> Evidence:
        """Alias for :meth:`verify_with_evidence`."""

        return self.verify_with_evidence(keys, threshold, **kwargs)

    def _emit_evidence(self, destination: Any, evidence: Evidence) -> None:
        if destination is None:
            return
        if destination is True:
            self.last_evidence = evidence
            return
        if callable(destination):
            destination(evidence)
            return
        if hasattr(destination, "write"):
            evidence.write(destination)
            return
        evidence.write(destination)


from securesystemslib.dsse_evidence import (  # noqa: E402
    EVIDENCE_KIND,
    EVIDENCE_VERSION,
    REPORT_KIND,
    REPORT_VERSION,
    Evidence,
    EvidenceBundle,
    EvidenceError,
    EvidenceFormatError,
    EvidenceReport,
    VerificationReport,
    create_evidence,
    load_evidence,
    seal_evidence,
    verify_evidence,
    verify_evidence_bundle,
)

__all__ = [
    "EVIDENCE_KIND",
    "EVIDENCE_VERSION",
    "REPORT_KIND",
    "REPORT_VERSION",
    "Envelope",
    "Evidence",
    "EvidenceBundle",
    "EvidenceError",
    "EvidenceFormatError",
    "EvidenceReport",
    "VerificationReport",
    "create_evidence",
    "load_evidence",
    "seal_evidence",
    "verify_evidence",
    "verify_evidence_bundle",
]
