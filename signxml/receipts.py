from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass
from enum import Enum

from lxml import etree

from .exceptions import InvalidInput
from .verifier import VerifyResult

LEGAL_DOCUMENT_NAMESPACE = "urn:signxml:legal-document-reconciliation:1"
DOCUMENT_KIND_ORIGINAL = "original"
DOCUMENT_KIND_REVISION = "revision"

class DocumentReconciliationStatus(Enum):
    ACCEPTED = "accepted"
    DUPLICATE_DOCUMENT_ID = "duplicate_document_id"
    MISSING_ORIGINAL = "missing_original"
    MULTIPLE_ORIGINALS = "multiple_originals"
    MISSING_PREDECESSOR = "missing_predecessor"
    OUT_OF_ORDER = "out_of_order"
    UNEXPECTED_PREDECESSOR = "unexpected_predecessor"
    MISSING_RECEIPT = "missing_receipt"


class ReceiptReconciliationStatus(Enum):
    ACCEPTED = "accepted"
    DUPLICATE_RECEIPT_ID = "duplicate_receipt_id"
    UNKNOWN_RECEIPT_TARGET = "unknown_receipt_target"
    OUT_OF_ORDER = "out_of_order"
    UNKNOWN_ROLE = "unknown_role"
    ROLE_SIGNATURE_MISMATCH = "role_signature_mismatch"
    ROLE_NOT_ALLOWED_FOR_DOCUMENT_KIND = "role_not_allowed_for_document_kind"
    ROLE_OUT_OF_SCOPE = "role_out_of_scope"
ERROR_MISSING_ORIGINAL = "missing_original"
ERROR_MULTIPLE_ORIGINALS = "multiple_originals"


def _legal_tag(name: str) -> str:
    return f"{{{LEGAL_DOCUMENT_NAMESPACE}}}{name}"


def _required_attribute(element: etree._Element, attribute: str) -> str:
    value = element.get(attribute)
    if value is None or not value.strip():
        raise InvalidInput(f"Signed {etree.QName(element).localname} is missing required attribute {attribute}")
    return value


def _required_sequence(element: etree._Element) -> int:
    raw_value = _required_attribute(element, "sequence")
    try:
        return int(raw_value)
    except ValueError as exception:
        raise InvalidInput(f"Signed document sequence must be an integer, got {raw_value!r}") from exception


def _as_tuple(values: Collection[str]) -> tuple[str, ...]:
    return tuple(values)


@dataclass(frozen=True)
class RoleCredential:
    """
    A role, the public key or HMAC secret allowed to sign receipts for it, and the document kinds and scopes in which
    that role is permitted to act. The wildcard scope ``"*"`` permits every scope.
    """

    public_key: bytes
    document_kinds: tuple[str, ...] = (DOCUMENT_KIND_ORIGINAL, DOCUMENT_KIND_REVISION)
    scopes: tuple[str, ...] = ("*",)


@dataclass(frozen=True)
class SignedDocumentCommitment:
    """A signed original or revision and the commitment object declared by its signed content."""

    document_id: str
    document_kind: str
    group_id: str
    sequence: int
    predecessor_id: str | None
    commitment: str
    signature_key: bytes


@dataclass(frozen=True)
class SignedReceipt:
    """A signed review receipt and the document, role, and scope it claims to apply to."""

    receipt_id: str
    group_id: str
    target_document_id: str
    role: str
    scope: str
    sequence: int
    signature_key: bytes


@dataclass(frozen=True)
class ReceiptReconciliationStatus:
    """The reconciliation result for one signed receipt."""

    receipt_id: str
    target_document_id: str
    role: str
    scope: str
    accepted: bool
    errors: tuple[str, ...]


@dataclass(frozen=True)
class DocumentReconciliationStatus:
    """The reconciliation result for one signed original or revision."""

    document_id: str
    document_kind: str
    sequence: int
    predecessor_id: str | None
    commitment: str
    accepted: bool
    errors: tuple[str, ...]
    valid_receipt_ids: tuple[str, ...]


@dataclass(frozen=True)
class ReconciliationReport:
    """The complete offline reconciliation report for one document group."""

    group_id: str
    accepted: bool
    documents: tuple[DocumentReconciliationStatus, ...]
    receipts: tuple[ReceiptReconciliationStatus, ...]
    errors: tuple[str, ...]


class OfflineReceiptReconciler:
    """
    Reconcile signed legal documents and review receipts without performing another cryptographic verification.

    Callers first verify every XML document with :class:`signxml.XMLVerifier` and pass the resulting
    :class:`signxml.VerifyResult` objects here. Only the verified ``signed_xml`` payload is examined, so unsigned
    envelope ordering and unsigned attachments cannot change which signed document a receipt applies to.
    """

    def __init__(self, role_credentials: Mapping[str, RoleCredential]):
        self.role_credentials = dict(role_credentials)

    def reconcile(self, verify_results: Collection[VerifyResult]) -> ReconciliationReport:
        """
        Reconcile verified originals, revisions, and receipts and return a report containing separate status codes for
        chain, ordering, receipt, role, and scope failures.
        """
        if not verify_results:
            raise InvalidInput("At least one VerifyResult is required for receipt reconciliation")

        documents: list[SignedDocumentCommitment] = []
        receipts: list[SignedReceipt] = []
        group_id: str | None = None

        for verify_result in verify_results:
            signed_xml = verify_result.signed_xml
            if signed_xml is None:
                raise InvalidInput("VerifyResult.signed_xml is required for receipt reconciliation")
            if group_id is None:
                group_id = signed_xml.get("groupId")
            elif signed_xml.get("groupId") != group_id:
                raise InvalidInput("VerifyResult objects belong to more than one document group")
            if not group_id:
                raise InvalidInput("Signed legal document is missing required attribute groupId")

            if signed_xml.tag == _legal_tag("LegalDocument"):
                documents.append(self._parse_document(signed_xml, verify_result.signature_key))
            elif signed_xml.tag == _legal_tag("ReviewReceipt"):
                receipts.append(self._parse_receipt(signed_xml, verify_result.signature_key))
            else:
                raise InvalidInput(f"Unsupported signed legal document tag {signed_xml.tag!r}")

        assert group_id is not None
        document_errors, group_errors = self._check_document_chains(documents)
        receipt_statuses = self._check_receipts(receipts, documents)
        valid_receipts_by_document = self._index_valid_receipts(receipt_statuses)
        document_statuses = tuple(
            self._build_document_status(document, document_errors.get(document.document_id, ()), valid_receipts_by_document)
            for document in sorted(documents, key=lambda item: (item.sequence, item.document_id))
        )
        receipt_result_statuses = tuple(
            sorted((status for status in receipt_statuses.values()), key=lambda item: item.receipt_id)
        )
        errors = tuple(
            sorted(
                {error for status in document_statuses + receipt_result_statuses for error in status.errors}
                | set(group_errors)
            )
        )
        return ReconciliationReport(
            group_id=group_id,
            accepted=not errors,
            documents=document_statuses,
            receipts=receipt_result_statuses,
            errors=errors,
        )

    def _parse_document(self, signed_xml: etree._Element, signature_key: bytes) -> SignedDocumentCommitment:
        document_kind = _required_attribute(signed_xml, "kind")
        if document_kind not in (DOCUMENT_KIND_ORIGINAL, DOCUMENT_KIND_REVISION):
            raise InvalidInput(f"Unsupported legal document kind {document_kind!r}")
        document_id = _required_attribute(signed_xml, "documentId")
        group_id = _required_attribute(signed_xml, "groupId")
        sequence = _required_sequence(signed_xml)
        predecessor_id = signed_xml.get("predecessorId")
        if document_kind == DOCUMENT_KIND_ORIGINAL and predecessor_id is not None:
            raise InvalidInput(f"Original document {document_id} must not declare a predecessorId")
        if document_kind == DOCUMENT_KIND_REVISION and not predecessor_id:
            raise InvalidInput(f"Revision document {document_id} must declare a predecessorId")
        commitment_element = signed_xml.find(_legal_tag("Commitment"))
        if commitment_element is None or commitment_element.text is None or not commitment_element.text.strip():
            raise InvalidInput(f"Document {document_id} must include signed Commitment text")
        return SignedDocumentCommitment(
            document_id=document_id,
            document_kind=document_kind,
            group_id=group_id,
            sequence=sequence,
            predecessor_id=predecessor_id,
            commitment=commitment_element.text.strip(),
            signature_key=signature_key,
        )

    def _parse_receipt(self, signed_xml: etree._Element, signature_key: bytes) -> SignedReceipt:
        return SignedReceipt(
            receipt_id=_required_attribute(signed_xml, "receiptId"),
            group_id=_required_attribute(signed_xml, "groupId"),
            target_document_id=_required_attribute(signed_xml, "targetDocumentId"),
            role=_required_attribute(signed_xml, "role"),
            scope=_required_attribute(signed_xml, "scope"),
            sequence=_required_sequence(signed_xml),
            signature_key=signature_key,
        )

    def _check_document_chains(
        self, documents: Collection[SignedDocumentCommitment]
    ) -> tuple[dict[str, tuple[str, ...]], tuple[str, ...]]:
        documents_by_id = {document.document_id: document for document in documents}
        errors: dict[str, list[str]] = {document.document_id: [] for document in documents}
        seen_document_ids: set[str] = set()
        group_errors: list[str] = []
        originals = [document for document in documents if document.document_kind == DOCUMENT_KIND_ORIGINAL]
        if not originals:
            group_errors.append(ERROR_MISSING_ORIGINAL)
        elif len(originals) > 1:
            group_errors.append(ERROR_MULTIPLE_ORIGINALS)
        for document in documents:
            if document.document_id in seen_document_ids:
                errors[document.document_id].append(ERROR_DUPLICATE_DOCUMENT_ID)
            seen_document_ids.add(document.document_id)

            if document.document_kind != DOCUMENT_KIND_REVISION:
                if document.predecessor_id is not None:
                    errors[document.document_id].append(ERROR_UNEXPECTED_PREDECESSOR)
                continue
            predecessor = documents_by_id.get(document.predecessor_id)
            if predecessor is None:
                errors[document.document_id].append(ERROR_MISSING_PREDECESSOR)
                continue
            if document.sequence <= predecessor.sequence:
                errors[document.document_id].append(ERROR_OUT_OF_ORDER)
        return (
            {document_id: tuple(document_errors) for document_id, document_errors in errors.items()},
            tuple(group_errors),
        )

    def _check_receipts(
        self,
        receipts: Collection[SignedReceipt],
        documents: Collection[SignedDocumentCommitment],
    ) -> dict[str, ReceiptReconciliationStatus]:
        documents_by_id = {document.document_id: document for document in documents}
        seen_receipt_ids: set[str] = set()
        statuses: dict[str, ReceiptReconciliationStatus] = {}
        for receipt in receipts:
            errors: list[str] = []
            if receipt.receipt_id in seen_receipt_ids:
                errors.append(ERROR_DUPLICATE_RECEIPT_ID)
            seen_receipt_ids.add(receipt.receipt_id)

            target = documents_by_id.get(receipt.target_document_id)
            if target is None:
                errors.append(ERROR_UNKNOWN_RECEIPT_TARGET)
            elif receipt.sequence != target.sequence:
                errors.append(ERROR_OUT_OF_ORDER)

            credential = self.role_credentials.get(receipt.role)
            if credential is None:
                errors.append(ERROR_UNKNOWN_ROLE)
            else:
                if credential.public_key != receipt.signature_key:
                    errors.append(ERROR_ROLE_SIGNATURE_MISMATCH)
                if target is not None and target.document_kind not in credential.document_kinds:
                    errors.append(ERROR_ROLE_NOT_ALLOWED_FOR_DOCUMENT_KIND)
                if "*" not in credential.scopes and receipt.scope not in credential.scopes:
                    errors.append(ERROR_ROLE_OUT_OF_SCOPE)

            statuses[receipt.receipt_id] = ReceiptReconciliationStatus(
                receipt_id=receipt.receipt_id,
                target_document_id=receipt.target_document_id,
                role=receipt.role,
                scope=receipt.scope,
                accepted=not errors,
                errors=tuple(errors),
            )
        return statuses

    def _index_valid_receipts(
        self, receipt_statuses: Mapping[str, ReceiptReconciliationStatus]
    ) -> dict[str, tuple[str, ...]]:
        valid_receipts: dict[str, list[str]] = {}
        for status in receipt_statuses.values():
            if status.accepted:
                valid_receipts.setdefault(status.target_document_id, []).append(status.receipt_id)
        return {document_id: tuple(sorted(receipt_ids)) for document_id, receipt_ids in valid_receipts.items()}

    def _build_document_status(
        self,
        document: SignedDocumentCommitment,
        chain_errors: tuple[str, ...],
        valid_receipts_by_document: Mapping[str, tuple[str, ...]],
    ) -> DocumentReconciliationStatus:
        errors = list(chain_errors)
        valid_receipt_ids = valid_receipts_by_document.get(document.document_id, ())
        if not valid_receipt_ids:
            errors.append(ERROR_MISSING_RECEIPT)
        return DocumentReconciliationStatus(
            document_id=document.document_id,
            document_kind=document.document_kind,
            sequence=document.sequence,
            predecessor_id=document.predecessor_id,
            commitment=document.commitment,
            accepted=not errors,
            errors=tuple(errors),
            valid_receipt_ids=valid_receipt_ids,
        )
