"""
Staged intake of detached XML signatures whose references point to external attachments.

An archive may receive the signed envelope (the ``ds:Signature`` document) before the attachments it covers have
arrived. :class:`ExternalReferenceIntake` uses :meth:`signxml.XMLVerifier.verify` with a custom ``uri_resolver`` to
open each external reference only from a configured local directory. It records a receipt for every reference and
pauses, without approving anything, while inputs are still missing.

Only a fully verified signature is approved. Unverified references never appear in the public receipt (see
:meth:`IntakeReceipt.public_receipt`); operators can inspect every reference, including missing ones, through
:meth:`IntakeReceipt.audit`.
"""

from __future__ import annotations

import os
from base64 import b64decode
from collections.abc import Callable
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit

from lxml import etree

from .algorithms import CanonicalizationMethod, DigestAlgorithm
from .exceptions import InvalidInput, SignXMLException
from .verifier import SignatureConfiguration, VerifyResult, XMLVerifier


class ReferenceState(str, Enum):
    """
    State of a single reference declared by the signed envelope.
    """

    PENDING = "pending"
    "The referenced input has not been received yet."

    RECEIVED = "received"
    "The referenced input was read and its digest matches the digest declared by the (not yet fully verified) envelope."

    CONFIRMED = "confirmed"
    "The referenced input is covered by a signature that :class:`signxml.XMLVerifier` fully verified."

    REJECTED = "rejected"
    "The reference is unsafe, malformed, or its input does not match the signed digest."


class IntakeState(str, Enum):
    """
    State of an intake operation.
    """

    PAUSED = "paused"
    "At least one referenced input is still missing. No approval has been given."

    APPROVED = "approved"
    "Every reference was received and the complete signature verified successfully."

    REJECTED = "rejected"
    "A reference is unsafe, malformed, or does not match its signed digest, or signature verification failed."


@dataclass(frozen=True)
class ReferenceReceipt:
    """
    Auditable receipt for one reference declared in the signed envelope.
    """

    uri: str
    "The reference URI as declared in ``SignedInfo``."

    state: ReferenceState
    "The state of this reference."

    received: bool
    "Whether an input for this reference has been read from local evidence."

    confirmed: bool
    "Whether this reference was covered by a fully verified signature."

    digest_algorithm: str | None = None
    "The digest algorithm URI declared for this reference, if it could be parsed."

    digest_value: str | None = None
    "The base64-encoded digest declared for this reference, if it could be parsed."

    digest_matches: bool | None = None
    "Whether the received input matched the declared digest, or ``None`` if it was not checked."

    detail: str | None = None
    "Human-readable detail for pending and rejected references."


@dataclass(frozen=True)
class IntakeReceipt:
    """
    Immutable snapshot of a staged archive intake.

    The snapshot always contains an entry for every reference declared by the signed envelope. Use
    :meth:`audit` for operator-facing diagnostics and :meth:`public_receipt` for the externally publishable
    acknowledgement, which contains only confirmed references.
    """

    state: IntakeState
    "Overall intake state."

    references: tuple[ReferenceReceipt, ...]
    "Receipts for every reference declared by the signed envelope, including pending ones."

    approved: bool
    "Whether the complete signature was verified and final approval was given."

    detail: str
    "Human-readable summary of the current state."

    verification_result: VerifyResult | list[VerifyResult] | None = None
    "The result returned by :meth:`signxml.XMLVerifier.verify` after final approval, otherwise ``None``."

    def audit(self) -> dict[str, Any]:
        """
        Return a complete, serializable audit view of the intake.

        This view includes pending and rejected references so that operators can determine which local evidence is
        still needed. It never includes referenced data itself.
        """

        return {
            "state": self.state.value,
            "approved": self.approved,
            "detail": self.detail,
            "references": [
                {
                    "uri": reference.uri,
                    "state": reference.state.value,
                    "received": reference.received,
                    "confirmed": reference.confirmed,
                    "digest_algorithm": reference.digest_algorithm,
                    "digest_value": reference.digest_value,
                    "digest_matches": reference.digest_matches,
                    "detail": reference.detail,
                }
                for reference in self.references
            ],
        }

    def public_receipt(self) -> dict[str, Any]:
        """
        Return the externally publishable acknowledgement.

        Only references that were covered by a fully verified signature are listed. Pending, received-but-unconfirmed,
        and rejected references are absent, so unverified material cannot appear in the public receipt.
        """

        return {
            "state": self.state.value,
            "approved": self.approved,
            "references": [
                {
                    "uri": reference.uri,
                    "digest_algorithm": reference.digest_algorithm,
                    "digest_value": reference.digest_value,
                }
                for reference in self.references
                if reference.confirmed
            ],
        }


class _ReferenceUnavailable(Exception):
    """Internal signal that a reference could not be read from local evidence."""

    def __init__(self, uri: str):
        super().__init__(uri)
        self.uri = uri


class _UnsafeReference(Exception):
    """Internal signal that a reference URI would escape the configured attachment directory."""


class _LocalAttachmentResolver:
    """Resolve reference URIs to files inside a single local directory, and nothing else."""

    def __init__(self, root: str | os.PathLike):
        self.root = Path(root).expanduser().resolve()
        if not self.root.is_dir():
            raise InvalidInput(f"Attachment directory does not exist: {root}")

    def __call__(self, uri: str) -> bytes | None:
        path = self._path_for(uri)
        try:
            if not path.is_file():
                return None
            return path.read_bytes()
        except OSError:
            return None

    def _path_for(self, uri: str) -> Path:
        if not isinstance(uri, str) or not uri:
            raise _UnsafeReference("Reference URI is empty")
        parsed = urlsplit(uri)
        if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
            raise _UnsafeReference(f"Reference URI is not a plain local path: {uri}")
        raw_path = unquote(parsed.path)
        if raw_path.startswith(("/", "\\")) or "\\" in raw_path:
            raise _UnsafeReference(f"Reference URI is absolute: {uri}")
        parts = PurePosixPath(raw_path).parts
        if not parts or any(part in ("", ".", "..") for part in parts):
            raise _UnsafeReference(f"Reference URI is not a safe relative path: {uri}")
        candidate = (self.root / Path(*parts)).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise _UnsafeReference(f"Reference URI escapes the attachment directory: {uri}")
        return candidate


class ExternalReferenceIntake:
    """
    Stage receipt of a detached signature whose references point to local attachments.

    The signed envelope can arrive before its attachments. Call :meth:`receive` when the envelope arrives; the returned
    receipt pauses with :attr:`IntakeState.PAUSED` while inputs are missing. After the attachment directory is populated,
    call :meth:`resume` to re-read local evidence. Final approval is given only when every reference is present, every
    digest matches, and :meth:`signxml.XMLVerifier.verify` accepts the complete signature.

    Reference URIs are resolved only from **attachment_dir**. Absolute paths, URL schemes, query strings, fragments, and
    paths that escape the directory (including through symlinks) are rejected rather than opened. The resolver reads the
    directory afresh on every call, so files added or replaced between :meth:`receive` and :meth:`resume` are observed.

    :param attachment_dir:
        Directory containing the local attachments. May be omitted when a custom **uri_resolver** is supplied.
    :param verifier:
        :class:`signxml.XMLVerifier` instance to use. A new verifier is created if omitted.
    :param uri_resolver:
        Optional callable used instead of the built-in local-directory resolver. It receives the reference URI and must
        return bytes, an :class:`lxml.etree._Element`, or ``None`` if the input is not available. A resolver returning
        ``None`` leaves the reference pending.
    :param expect_config:
        :class:`signxml.SignatureConfiguration` describing the signature to accept. Defaults to a configuration with
        ``expect_references=True`` so that the number of references is taken from the envelope.
    :param expected_references:
        Number of references the signature must contain. Defaults to ``True``, which accepts the number declared by the
        envelope. Final approval fails if the count does not match.
    :param verify_kwargs:
        Additional keyword arguments passed to :meth:`signxml.XMLVerifier.verify` (for example ``x509_cert`` or
        ``hmac_key``). ``uri_resolver`` and ``expect_config`` are managed by this class and cannot be supplied here.
    """

    def __init__(
        self,
        attachment_dir: str | os.PathLike | None = None,
        *,
        verifier: XMLVerifier | None = None,
        uri_resolver: Callable[[str], bytes | etree._Element | None] | None = None,
        expect_config: SignatureConfiguration | None = None,
        expected_references: int | bool = True,
        **verify_kwargs: Any,
    ):
        if uri_resolver is not None and attachment_dir is not None:
            raise InvalidInput("Specify either attachment_dir or uri_resolver, not both")
        if uri_resolver is None and attachment_dir is None:
            raise InvalidInput("Either attachment_dir or uri_resolver is required")
        if any(key in verify_kwargs for key in ("uri_resolver", "expect_config", "expect_references")):
            raise InvalidInput("Pass uri_resolver, expect_config, and expect_references as explicit arguments")

        self._verifier = verifier if verifier is not None else XMLVerifier()
        self._expect_config = (
            expect_config if expect_config is not None else SignatureConfiguration(expect_references=True)
        )
        self._expected_references = expected_references
        self._verify_kwargs = dict(verify_kwargs)
        if "parser" in self._verify_kwargs:
            self._verifier._parser = self._verify_kwargs["parser"]
        if self._verify_kwargs.get("id_attribute") is not None:
            self._verifier.id_attributes = (self._verify_kwargs["id_attribute"],)
        self._external_resolver = uri_resolver
        self._local_resolver = _LocalAttachmentResolver(attachment_dir) if attachment_dir is not None else None
        self._envelope: bytes | None = None
        self._receipt: IntakeReceipt | None = None

    @property
    def receipt(self) -> IntakeReceipt | None:
        """The most recent intake snapshot, or ``None`` before :meth:`receive` is called."""

        return self._receipt

    def receive(self, envelope) -> IntakeReceipt:
        """
        Accept a signed envelope and evaluate the references it declares.

        Missing attachments do not raise an error. They are recorded as :attr:`ReferenceState.PENDING`, the intake pauses
        with :attr:`IntakeState.PAUSED`, and no approval is given.

        :param envelope: Detached signature XML, as a string, bytes, file-like object, or ElementTree element.
        :return: An immutable :class:`IntakeReceipt` snapshot.
        """

        root = self._verifier.get_root(envelope)
        self._envelope = self._verifier._tostring(root)
        self._receipt = self._evaluate()
        return self._receipt

    def resume(self) -> IntakeReceipt:
        """
        Re-read local evidence and give final approval if the complete signature now verifies.

        Every reference is resolved again from the attachment directory, so a file that was added or replaced since
        :meth:`receive` is re-read. The intake remains paused while any input is still pending, and becomes rejected if a
        received input no longer matches its signed digest.

        :return: An immutable :class:`IntakeReceipt` snapshot.
        """

        if self._envelope is None:
            raise InvalidInput("No signature envelope has been received")
        self._receipt = self._evaluate()
        return self._receipt

    def _resolve_uri(self, uri: str) -> bytes | etree._Element:
        if self._external_resolver is not None:
            try:
                result = self._external_resolver(uri)
            except OSError as exc:
                raise _ReferenceUnavailable(uri) from exc
        else:
            assert self._local_resolver is not None
            result = self._local_resolver(uri)
        if result is None:
            raise _ReferenceUnavailable(uri)
        return result

    def _evaluate(self) -> IntakeReceipt:
        assert self._envelope is not None
        verifier = self._verifier
        verifier.config = self._expect_config
        root = verifier.get_root(self._envelope)
        verifier._reject_manifests(root)
        signature = verifier._get_signature(root)
        signed_info = verifier._find(signature, "SignedInfo")
        c14n_method = verifier._find(signed_info, "CanonicalizationMethod")
        CanonicalizationMethod(c14n_method.get("Algorithm"))
        references = verifier._findall(signed_info, "Reference")

        receipts: list[ReferenceReceipt] = []
        for reference in references:
            receipts.append(self._evaluate_reference(reference, len(references), root))

        if any(receipt.state is ReferenceState.REJECTED for receipt in receipts):
            rejected = next(receipt for receipt in receipts if receipt.state is ReferenceState.REJECTED)
            return IntakeReceipt(
                state=IntakeState.REJECTED,
                references=tuple(receipts),
                approved=False,
                detail=f"Reference {rejected.uri!r} was rejected: {rejected.detail}",
            )

        pending = [receipt for receipt in receipts if receipt.state is ReferenceState.PENDING]
        if pending:
            return IntakeReceipt(
                state=IntakeState.PAUSED,
                references=tuple(receipts),
                approved=False,
                detail=f"Waiting for {len(pending)} referenced input(s): "
                + ", ".join(repr(receipt.uri) for receipt in pending),
            )

        try:
            verification_result = verifier.verify(
                self._envelope,
                uri_resolver=self._resolve_uri,
                expect_config=self._approval_config(),
                **self._verify_kwargs,
            )
        except _ReferenceUnavailable as exc:
            receipts = [
                ReferenceReceipt(
                    uri=receipt.uri,
                    state=ReferenceState.PENDING,
                    received=False,
                    confirmed=False,
                    digest_algorithm=receipt.digest_algorithm,
                    digest_value=receipt.digest_value,
                    digest_matches=None,
                    detail="Input disappeared before final verification",
                )
                if receipt.uri == exc.uri
                else receipt
                for receipt in receipts
            ]
            return IntakeReceipt(
                state=IntakeState.PAUSED,
                references=tuple(receipts),
                approved=False,
                detail=f"Reference {exc.uri!r} disappeared before final verification",
            )
        except (SignXMLException, etree.LxmlError, ValueError) as exc:
            return IntakeReceipt(
                state=IntakeState.REJECTED,
                references=tuple(receipts),
                approved=False,
                detail=f"Signature verification failed: {exc}",
            )

        confirmed = tuple(
            ReferenceReceipt(
                uri=receipt.uri,
                state=ReferenceState.CONFIRMED,
                received=True,
                confirmed=True,
                digest_algorithm=receipt.digest_algorithm,
                digest_value=receipt.digest_value,
                digest_matches=True,
                detail=None,
            )
            for receipt in receipts
        )
        return IntakeReceipt(
            state=IntakeState.APPROVED,
            references=confirmed,
            approved=True,
            detail="All referenced inputs were received and the complete signature verified",
            verification_result=verification_result,
        )

    def _evaluate_reference(
        self, reference: etree._Element, reference_count: int, root: etree._Element
    ) -> ReferenceReceipt:
        verifier = self._verifier
        uri = reference.get("URI")
        digest_method = verifier._find(reference, "DigestMethod", require=False)
        digest_algorithm = digest_method.get("Algorithm") if digest_method is not None else None
        digest_node = verifier._find(reference, "DigestValue", require=False)
        digest_value = digest_node.text if digest_node is not None else None

        def _rejected(detail: str, *, received: bool = False) -> ReferenceReceipt:
            return ReferenceReceipt(
                uri=uri or "",
                state=ReferenceState.REJECTED,
                received=received,
                confirmed=False,
                digest_algorithm=digest_algorithm,
                digest_value=digest_value,
                digest_matches=False if received else None,
                detail=detail,
            )

        if uri is None:
            return _rejected("Reference has no URI")
        if digest_algorithm is None or digest_value is None:
            return _rejected("Reference is missing DigestMethod or DigestValue")

        root_for_reference = verifier._fromstring(verifier._tostring(root)) if reference_count > 1 else root
        try:
            payload = verifier._resolve_reference(root_for_reference, reference, uri_resolver=self._resolve_uri)
        except _ReferenceUnavailable:
            return ReferenceReceipt(
                uri=uri,
                state=ReferenceState.PENDING,
                received=False,
                confirmed=False,
                digest_algorithm=digest_algorithm,
                digest_value=digest_value,
                digest_matches=None,
                detail="Input has not been received",
            )
        except _UnsafeReference as exc:
            return _rejected(str(exc))
        except InvalidInput as exc:
            return _rejected(str(exc))

        try:
            if isinstance(payload, etree._Element):
                verifier._reject_manifests(payload)
            if uri == "" or uri.startswith("#"):
                etree.strip_tags(payload, etree.Comment)
            transforms = verifier._find(reference, "Transforms", require=False)
            signature = verifier._get_signature(root_for_reference)
            payload_c14n = verifier._apply_transforms(payload, transforms_node=transforms, signature=signature)
            digest_alg = DigestAlgorithm(digest_algorithm)
            verifier.check_digest_alg_expected(digest_alg)
            received_digest = verifier._get_digest(payload_c14n, digest_alg)
            expected_digest = b64decode(digest_value)
        except (InvalidInput, ValueError, TypeError, etree.LxmlError) as exc:
            return _rejected(f"Unable to check reference: {exc}", received=True)

        if received_digest != expected_digest:
            return _rejected("Received input does not match the signed digest", received=True)

        return ReferenceReceipt(
            uri=uri,
            state=ReferenceState.RECEIVED,
            received=True,
            confirmed=False,
            digest_algorithm=digest_algorithm,
            digest_value=digest_value,
            digest_matches=True,
            detail="Input received; awaiting final signature approval",
        )

    def _approval_config(self) -> SignatureConfiguration:
        return replace(self._expect_config, expect_references=self._expected_references)
