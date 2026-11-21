"""
Scoped disclosure and sign-off receipts on top of audit reports.

Several departments each receive a scoped slice of the central audit
report (see :mod:`detect_secrets.audit.report`). The central security
group needs to reconcile that every approved disposition was delivered
to -- and signed off by -- the owning department, without departments
being able to correlate findings across scopes through long-lived
stable markers.

To achieve this, findings are never identified to departments by their
baseline hash. Instead, each publication derives a per-scope,
per-epoch key from a master key held by the security group, and
findings are tagged with an HMAC marker under that key. Markers
therefore rotate every publication epoch and differ across scopes, so
a marker observed by one department cannot be matched against markers
seen by another department or in another period.

A receipt signed by a department is only verifiable within its
publication scope and its authorization window. The security group,
holding the master key, can re-derive any historical scope key and
re-verify old receipts internally.
"""
import hashlib
import hmac
import json
import time
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import NamedTuple
from typing import Optional
from typing import Tuple

from ..constants import VerifiedResult


APPROVED_CATEGORIES = (
    VerifiedResult.VERIFIED_TRUE.name,
    VerifiedResult.VERIFIED_FALSE.name,
)

_MARKER_LENGTH = 24


class ReceiptError(Exception):
    pass


class UnknownScopeError(ReceiptError):
    pass


class ReceiptWindowError(ReceiptError):
    pass


class ReceiptSignatureError(ReceiptError):
    pass


class ForeignMarkerError(ReceiptError):
    pass


class DisclosureScope(NamedTuple):
    """A publication scope: which files a department may see, and when."""
    scope_id: str
    filenames: Tuple[str, ...]
    epoch: str
    not_before: int
    not_after: int

    def covers(self, filename: str) -> bool:
        return filename in self.filenames

    def is_active(self, at_time: int) -> bool:
        return self.not_before <= at_time <= self.not_after


def derive_scope_key(master_key: bytes, scope_id: str, epoch: str) -> bytes:
    """Per-scope, per-epoch key. Only the master key holder can derive these."""
    return hmac.new(
        master_key,
        '{}/{}'.format(scope_id, epoch).encode('utf-8'),
        hashlib.sha256,
    ).digest()


def _fingerprint_finding(entry: Dict[str, Any]) -> str:
    """Stable internal identity of a report finding (never disclosed)."""
    canonical = json.dumps(
        {
            'filename': entry['filename'],
            # The report carries the plaintext under 'secrets'; we only
            # ever persist its hash.
            'secret': hashlib.sha256(
                str(entry.get('secrets', '')).encode('utf-8'),
            ).hexdigest(),
            'types': sorted(entry.get('types', [])),
        },
        sort_keys=True,
        separators=(',', ':'),
    )
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def compute_marker(scope_key: bytes, fingerprint: str) -> str:
    """Opaque, scope- and epoch-bound tag disclosed to the department."""
    return hmac.new(
        scope_key,
        fingerprint.encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()[:_MARKER_LENGTH]


def _canonical(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _sign(scope_key: bytes, payload: Dict[str, Any]) -> str:
    return hmac.new(scope_key, _canonical(payload), hashlib.sha256).hexdigest()


def publish_summary(
    report: Dict[str, Any],
    scope: DisclosureScope,
    scope_key: bytes,
) -> Dict[str, Any]:
    """
    Slice a central audit report down to one department's scope.

    The plaintext secret values are stripped; each finding is tagged
    with a rotating marker instead of any stable baseline identifier.
    """
    results = []
    for entry in report.get('results', []):
        if not scope.covers(entry['filename']):
            continue
        results.append({
            'marker': compute_marker(scope_key, _fingerprint_finding(entry)),
            'filename': entry['filename'],
            'lines': entry.get('lines', {}),
            'types': entry.get('types', []),
            'category': entry.get('category', VerifiedResult.UNVERIFIED.name),
        })
    return {
        'scope_id': scope.scope_id,
        'epoch': scope.epoch,
        'not_before': scope.not_before,
        'not_after': scope.not_after,
        'results': results,
    }


def create_receipt(
    scope: DisclosureScope,
    scope_key: bytes,
    dispositions: Iterable[Dict[str, str]],
    signed_at: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Sign off a (possibly partial) list of dispositions.

    Each disposition is ``{'marker': ..., 'disposition': ...}``; the
    receipt binds them to the scope and its authorization window.
    """
    if signed_at is None:
        signed_at = int(time.time())
    payload = {
        'scope_id': scope.scope_id,
        'epoch': scope.epoch,
        'not_before': scope.not_before,
        'not_after': scope.not_after,
        'signed_at': signed_at,
        'dispositions': sorted(
            (dict(item) for item in dispositions),
            key=lambda item: item['marker'],
        ),
    }
    receipt = dict(payload)
    receipt['signature'] = _sign(scope_key, payload)
    return receipt


def _verify_signature(receipt: Dict[str, Any], scope_key: bytes) -> None:
    payload = {key: receipt[key] for key in receipt if key != 'signature'}
    expected = _sign(scope_key, payload)
    if not hmac.compare_digest(expected, str(receipt.get('signature', ''))):
        raise ReceiptSignatureError('Receipt signature does not match.')


def verify_receipt(
    receipt: Dict[str, Any],
    scope: DisclosureScope,
    scope_key: bytes,
    at_time: Optional[int] = None,
) -> bool:
    """
    Department-facing verification: a partial receipt only holds within
    its own publication scope and authorization window.

    :raises: UnknownScopeError
    :raises: ReceiptWindowError
    :raises: ReceiptSignatureError
    """
    if at_time is None:
        at_time = int(time.time())
    if receipt.get('scope_id') != scope.scope_id or receipt.get('epoch') != scope.epoch:
        raise UnknownScopeError('Receipt does not belong to this scope.')
    if (
        receipt.get('not_before') != scope.not_before or
        receipt.get('not_after') != scope.not_after
    ):
        raise UnknownScopeError('Receipt window does not match the scope.')
    if not scope.is_active(receipt.get('signed_at', 0)):
        raise ReceiptWindowError('Receipt was signed outside its authorization window.')
    if not scope.is_active(at_time):
        raise ReceiptWindowError('Scope authorization window has expired.')
    _verify_signature(receipt, scope_key)
    return True


def verify_receipt_with_master_key(
    receipt: Dict[str, Any],
    master_key: bytes,
    scopes: Iterable[DisclosureScope],
) -> bool:
    """
    Security-group internal re-verification: re-derives the historical
    scope key and checks authenticity regardless of the current time,
    so old receipts remain auditable after their window closes.

    :raises: UnknownScopeError
    :raises: ReceiptSignatureError
    """
    for scope in scopes:
        if (
            receipt.get('scope_id') == scope.scope_id and
            receipt.get('epoch') == scope.epoch
        ):
            scope_key = derive_scope_key(master_key, scope.scope_id, scope.epoch)
            _verify_signature(receipt, scope_key)
            return True
    raise UnknownScopeError('No matching scope for this receipt.')


class ReconciliationResult(NamedTuple):
    covered: List[str]
    missing: List[str]
    foreign: List[str]

    @property
    def ok(self) -> bool:
        return not self.missing and not self.foreign


def reconcile(
    report: Dict[str, Any],
    scopes: Iterable[DisclosureScope],
    receipts: Iterable[Dict[str, Any]],
    master_key: bytes,
) -> ReconciliationResult:
    """
    Central check that every approved disposition in the report was
    delivered to and signed off by the department owning the file.

    Receipts are authenticated with the master key (expired windows are
    fine -- this is the security group's internal view). Markers that
    no active scope could have issued are reported as foreign.
    """
    scopes = list(scopes)
    expected: Dict[str, str] = {}   # marker -> owning scope_id
    for scope in scopes:
        scope_key = derive_scope_key(master_key, scope.scope_id, scope.epoch)
        for entry in report.get('results', []):
            if not scope.covers(entry['filename']):
                continue
            if entry.get('category') not in APPROVED_CATEGORIES:
                continue
            marker = compute_marker(scope_key, _fingerprint_finding(entry))
            expected[marker] = scope.scope_id

    delivered = set()
    foreign = set()
    for receipt in receipts:
        verify_receipt_with_master_key(receipt, master_key, scopes)
        scope_id = receipt['scope_id']
        for item in receipt.get('dispositions', []):
            marker = item['marker']
            if expected.get(marker) != scope_id:
                foreign.add(marker)
            else:
                delivered.add(marker)

    return ReconciliationResult(
        covered=sorted(delivered),
        missing=sorted(set(expected) - delivered),
        foreign=sorted(foreign),
    )


def transfer_filenames(
    old_scope: DisclosureScope,
    new_scope: DisclosureScope,
    filenames: Iterable[str],
    epoch: str,
    not_before: int,
    not_after: int,
) -> Tuple[DisclosureScope, DisclosureScope]:
    """
    Hand responsibility for files from one department to another.

    Both scopes are re-issued under a new epoch, so all previously
    published markers rotate and stale receipts can no longer be
    replayed against the new publication.
    """
    moved = set(filenames)
    updated_old = old_scope._replace(
        filenames=tuple(name for name in old_scope.filenames if name not in moved),
        epoch=epoch,
        not_before=not_before,
        not_after=not_after,
    )
    updated_new = new_scope._replace(
        filenames=tuple(
            list(new_scope.filenames) +
            [name for name in old_scope.filenames if name in moved]
        ),
        epoch=epoch,
        not_before=not_before,
        not_after=not_after,
    )
    return updated_old, updated_new
