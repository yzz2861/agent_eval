"""Job-scoped approval quota accounting built on defusedxml.

The module is intentionally a business-layer adapter.  XML parsing always goes
through :mod:`defusedxml.ElementTree`; the quota ledger is independent from
either XML entry point so that parsing an outer approval document and its
nested declaration cannot reset the same job's budget.
"""

from __future__ import absolute_import, division, print_function

import os
from collections import OrderedDict
from uuid import uuid4

import defusedxml.ElementTree as DefusedET


# Lifecycle and result statuses.  The aliases make callers' preferred wording
# available without duplicating mutable state.
PENDING = "pending"
DECLARED = "declared"
RESERVED = "reserved"
ACCEPTED = "accepted"
RUNNING = "running"
RETRYING = "retrying"
FAILED = "failed"
INSUFFICIENT_BUDGET = "insufficient_budget"
BUDGET_INSUFFICIENT = "budget_insufficient"
QUOTA_EXCEEDED = "quota_exceeded"


class StatusString(str):
    """String status that also compares equal to common spelling aliases."""

    def __new__(cls, canonical, *aliases):
        obj = super(StatusString, cls).__new__(cls, canonical)
        obj.aliases = frozenset(str(alias) for alias in aliases)
        return obj

    def __eq__(self, other):
        if super(StatusString, self).__eq__(other):
            return True
        return str(other) in self.aliases

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return super(StatusString, self).__hash__()


COMPLETED = StatusString(
    "completed",
    "complete",
    "success",
    "succeeded",
    "ok",
    "normal_completion",
    "COMPLETED",
)
SUCCEEDED = COMPLETED
CANCELLED = StatusString(
    "cancelled", "canceled", "cancelled_by_user", "canceled_by_user", "CANCELLED"
)
CANCELED = CANCELLED
INSUFFICIENT_BUDGET = StatusString(
    "insufficient_budget",
    BUDGET_INSUFFICIENT,
    QUOTA_EXCEEDED,
    "quota_insufficient",
    "insufficient_quota",
    "budget_exceeded",
    "BUDGET_INSUFFICIENT",
)
BUDGET_INSUFFICIENT = INSUFFICIENT_BUDGET
QUOTA_EXCEEDED = INSUFFICIENT_BUDGET

ACTIVE_STATUSES = (RESERVED, ACCEPTED, RUNNING, RETRYING)
TERMINAL_STATUSES = (COMPLETED, CANCELLED, CANCELED)

_MISSING = object()
_SUBTASK_TAGS = {
    "subtask",
    "accepted_subtask",
    "acceptedsubtask",
    "task",
    "approval_task",
    "approval_item",
    "item",
}
_CONTAINER_TAGS = {
    "subtasks",
    "accepted_subtasks",
    "acceptedsubtasks",
    "tasks",
    "items",
    "approval_items",
}
_JOB_TAGS = {
    "controlled_approval",
    "approval",
    "approval_request",
    "parent_job",
    "parentjob",
    "job",
    "quota_job",
}
_DECLARATION_TAGS = {
    "declaration",
    "declarative_subdocument",
    "declarativesubdocument",
    "subdocument",
    "policy_declaration",
}
_ID_KEYS = ("job_id", "id", "name", "key", "reference")
_BUDGET_KEYS = (
    "total_quota",
    "parent_quota",
    "quota",
    "budget",
    "limit",
    "max_quota",
    "allowance",
)
_RESERVATION_KEYS = (
    "reserved_quota",
    "reservation",
    "allocated_quota",
    "allocation",
    "quota",
    "amount",
    "budget",
    "limit",
)
_WEIGHT_KEYS = ("weight", "shares", "share_count")


class ApprovalQuotaError(ValueError):
    """Base class for business-layer quota errors."""


class InvalidApprovalXMLError(ApprovalQuotaError):
    """Raised when an approval XML document is usable but incomplete."""


class QuotaConflictError(ApprovalQuotaError):
    """Raised when the same job is attached with conflicting definition."""


class UnknownSubtaskError(ApprovalQuotaError):
    """Raised when a lifecycle call names a subtask not known to the job."""


class BudgetInsufficientError(ApprovalQuotaError):
    """Raised when a reservation or charge would exceed the parent budget."""

    status = INSUFFICIENT_BUDGET
    code = BUDGET_INSUFFICIENT

    def __init__(self, job_id=None, requested=None, available=None, *args, **kwargs):
        subtask_id = kwargs.pop("subtask_id", None)
        super(BudgetInsufficientError, self).__init__(*args)
        self.job_id = job_id
        self.subtask_id = subtask_id
        self.requested = requested
        self.available = available
        self.parent_available = kwargs.pop("parent_available", available)
        self.reservation_remaining = kwargs.pop("reservation_remaining", None)

    def __str__(self):
        return (
            "budget insufficient for job={!r} subtask={!r}: "
            "requested={!r}, available={!r}".format(
                self.job_id, self.subtask_id, self.requested, self.available
            )
        )

    def to_dict(self):
        return OrderedDict(
            [
                ("ok", False),
                ("status", INSUFFICIENT_BUDGET),
                ("code", BUDGET_INSUFFICIENT),
                ("job_id", self.job_id),
                ("subtask_id", self.subtask_id),
                ("requested", self.requested),
                ("available", self.available),
                ("parent_available", self.parent_available),
                ("reservation_remaining", self.reservation_remaining),
                ("error", str(self)),
            ]
        )


# Common shorter alias.
InsufficientBudgetError = BudgetInsufficientError
QuotaExceededError = BudgetInsufficientError
InsufficientQuotaError = BudgetInsufficientError
BudgetExceededError = BudgetInsufficientError
QuotaBudgetExceededError = BudgetInsufficientError


def _local_name(tag):
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1].lower().replace("-", "_").replace(".", "_")


def _normalized_attributes(element):
    return {key.lower().replace("-", "_"): value for key, value in element.attrib.items()}


def _attr(element, *names):
    attrs = _normalized_attributes(element)
    for name in names:
        key = name.lower().replace("-", "_")
        if key in attrs and attrs[key] != "":
            return attrs[key]
    return None


def _child_text(element, names):
    wanted = {name.lower().replace("-", "_") for name in names}
    for child in list(element):
        if _local_name(child.tag) in wanted:
            text = (child.text or "").strip()
            if text:
                return text
            value = _attr(child, "value", "amount", "quota", "budget")
            if value is not None:
                return value
    return None


def _as_int(value, default=None, field="quota"):
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    text = str(value).strip().replace(",", "")
    try:
        return int(text)
    except ValueError:
        try:
            number = float(text)
        except ValueError:
            raise InvalidApprovalXMLError(
                "{} must be an integer quota, got {!r}".format(field, value)
            )
        if not number.is_integer():
            raise InvalidApprovalXMLError(
                "{} must be an integer quota, got {!r}".format(field, value)
            )
        return int(number)


def _positive_int(value, field="amount"):
    amount = _as_int(value, None, field)
    if amount is None or amount < 0:
        raise ApprovalQuotaError("{} must be a non-negative integer".format(field))
    return amount


class SubtaskDeclaration(object):
    """Declarative subtask metadata parsed from XML."""

    __slots__ = ("subtask_id", "quota", "weight", "tag", "attributes")

    def __init__(self, subtask_id, quota=None, weight=1, tag=None, attributes=None):
        self.subtask_id = subtask_id
        self.quota = quota
        self.weight = weight
        self.tag = tag
        self.attributes = dict(attributes or {})

    def to_dict(self):
        return OrderedDict(
            [
                ("subtask_id", self.subtask_id),
                ("quota", self.quota),
                ("weight", self.weight),
                ("tag", self.tag),
                ("attributes", self.attributes),
            ]
        )


class ApprovalDocument(object):
    """Parsed approval XML plus its declarative subtask list."""

    def __init__(
        self,
        job_id,
        budget,
        subtasks,
        root=None,
        declaration=None,
        source_kind="approval",
    ):
        self.job_id = job_id
        self.budget = budget
        self.subtasks = list(subtasks)
        self.root = root
        self.declaration = declaration
        self.source_kind = source_kind

    @property
    def total_quota(self):
        return self.budget

    def to_dict(self):
        return OrderedDict(
            [
                ("job_id", self.job_id),
                ("budget", self.budget),
                ("total_quota", self.budget),
                ("source_kind", self.source_kind),
                ("subtasks", [item.to_dict() for item in self.subtasks]),
            ]
        )


class SubtaskQuota(object):
    """Reservation and cumulative usage for one accepted subtask."""

    def __init__(self, subtask_id, planned_quota=None, weight=1, metadata=None):
        self.subtask_id = subtask_id
        self.planned_quota = planned_quota
        self.weight = weight
        self.reservation = 0
        self.used = 0
        self.held = 0
        self.status = DECLARED
        self.attempts = 0
        self.retry_count = 0
        self.released = 0
        self.metadata = dict(metadata or {})

    @property
    def remaining(self):
        return self.held

    def to_dict(self):
        return OrderedDict(
            [
                ("subtask_id", self.subtask_id),
                ("status", self.status),
                ("planned_quota", self.planned_quota),
                ("reservation", self.reservation),
                ("used", self.used),
                ("held", self.held),
                ("remaining", self.held),
                ("attempts", self.attempts),
                ("retry_count", self.retry_count),
                ("released", self.released),
                ("weight", self.weight),
                ("metadata", self.metadata),
            ]
        )


class QuotaResult(object):
    """Small result object for callers that prefer status over exceptions."""

    def __init__(self, ok, status, ledger, subtask_id=None, **changes):
        self.ok = ok
        self.status = status
        self.ledger = ledger
        self.subtask_id = subtask_id
        self.changes = changes
        self.error = changes.get("error")

    def __bool__(self):
        return bool(self.ok)

    __nonzero__ = __bool__

    def to_dict(self):
        data = OrderedDict(
            [
                ("ok", self.ok),
                ("status", self.status),
                ("job_id", self.ledger.job_id if self.ledger else None),
                ("subtask_id", self.subtask_id),
            ]
        )
        for key, value in self.changes.items():
            if key == "error" and value is not None:
                value = str(value)
            data[key] = value
        if self.ledger is not None:
            data["ledger"] = self.ledger.snapshot()
        return data


class QuotaLedger(object):
    """Mutable, auditable quota state for one parent job."""

    def __init__(self, job_id=None, budget=None, *args, **kwargs):
        # Convenience for QuotaLedger(100) / QuotaLedger(total_quota=100).
        total_quota = kwargs.pop("total_quota", None)
        quota = kwargs.pop("quota", None)
        total = kwargs.pop("total", None)
        fair = kwargs.pop("fair", True)
        if args and budget is None:
            budget = args[0]
        if not isinstance(job_id, str) and job_id is not None and budget is None:
            budget = job_id
            job_id = None
        if budget is None:
            budget = first_not_none(total_quota, quota, total)
        if budget is None:
            raise InvalidApprovalXMLError("job budget/quota is required")
        budget = _as_int(budget, field="budget")
        if budget < 0:
            raise InvalidApprovalXMLError("job budget must be non-negative")

        self.job_id = job_id or "job-{}".format(uuid4().hex[:12])
        self.budget = budget
        self.fair = fair
        self.consumed = 0
        self.reserved = 0
        self.subtasks = OrderedDict()
        self.events = []
        self.documents = []
        self.metadata = dict(kwargs.pop("metadata", {}) or {})
        if kwargs:
            # Ignore harmless dependency-injection/config keywords while
            # keeping construction forward-compatible.
            self.metadata.update(kwargs)
        self._event("job_created", budget=budget, fair=fair)

    @property
    def total_quota(self):
        return self.budget

    @total_quota.setter
    def total_quota(self, value):
        self.budget = value

    @property
    def used(self):
        return self.consumed

    @property
    def available(self):
        return self.budget - self.consumed - self.reserved

    @property
    def remaining(self):
        return self.available

    @property
    def allocated(self):
        return self.consumed + self.reserved

    @property
    def unreserved(self):
        return self.available

    def first_not_none(*values):
        for value in values:
            if value is not None:
                return value
        return None

    def _event(self, action, subtask_id=None, amount=None, **details):
        event = OrderedDict()
        event["seq"] = len(self.events) + 1
        event["action"] = action
        event["job_id"] = self.job_id
        if subtask_id is not None:
            event["subtask_id"] = subtask_id
        if amount is not None:
            event["amount"] = amount
        event["budget"] = self.budget
        event["consumed"] = self.consumed
        event["reserved"] = self.reserved
        event["available"] = self.available
        for key, value in details.items():
            event[key] = value
        self.events.append(event)
        return event

    def attach_document(self, document):
        self.documents.append(document.to_dict() if hasattr(document, "to_dict") else document)
        self._event(
            "xml_entry_parsed",
            source_kind=getattr(document, "source_kind", "approval"),
            subtask_count=len(getattr(document, "subtasks", []) or []),
            parser="defusedxml.ElementTree",
        )
        return self

    def declare(self, subtask_id, quota=None, weight=1, **metadata):
        if subtask_id in self.subtasks:
            return self.subtasks[subtask_id]
        planned = None if quota is None else _as_int(quota, field="subtask quota")
        account = SubtaskQuota(
            subtask_id,
            planned_quota=planned,
            weight=_as_int(weight, 1, "weight") or 1,
            metadata=metadata,
        )
        self.subtasks[subtask_id] = account
        self._event("subtask_declared", subtask_id, planned_quota=planned)
        return account

    def declare_many(self, declarations):
        result = []
        for item in declarations or []:
            if hasattr(item, "subtask_id"):
                result.append(
                    self.declare(
                        item.subtask_id,
                        item.quota,
                        getattr(item, "weight", 1),
                        attributes=getattr(item, "attributes", {}),
                        tag=getattr(item, "tag", None),
                    )
                )
            else:
                result.append(self.declare(item))
        return result

    def fair_shares(self, count=None):
        if count is None:
            count = len(self.subtasks)
        count = _as_int(count, field="count")
        if count <= 0:
            return []
        base, remainder = divmod(self.budget, count)
        return [base + (1 if index < remainder else 0) for index in range(count)]

    def _known(self, subtask_id):
        try:
            return self.subtasks[subtask_id]
        except KeyError:
            raise UnknownSubtaskError(
                "subtask {!r} is not declared in job {!r}".format(subtask_id, self.job_id)
            )

    def _reservation_amount(self, account, amount):
        if amount is not None:
            return _positive_int(amount, "reservation")
        if account.planned_quota is not None:
            return account.planned_quota
        if self.fair:
            shares = self.fair_shares(len(self.subtasks))
            if account.subtask_id in self.subtasks:
                index = list(self.subtasks).index(account.subtask_id)
            else:
                # A direct fair reservation for a not-yet-declared subtask is
                # the last member of the prospective fair group.
                index = len(self.subtasks)
                shares = self.fair_shares(len(self.subtasks) + 1)
            return shares[index]
        raise ApprovalQuotaError("no quota declared for subtask {!r}".format(account.subtask_id))

    def reserve(self, subtask_id, amount=None, **options):
        account = self.subtasks.get(subtask_id)
        replayed = account is not None and account.status in ACTIVE_STATUSES
        if replayed:
            self._event("reservation_replayed", subtask_id, replayed=True)
            return QuotaResult(
                True,
                RESERVED,
                self,
                subtask_id,
                amount=account.reservation,
                replayed=True,
            )
        if account is not None and account.status in TERMINAL_STATUSES:
            raise QuotaConflictError(
                "subtask {!r} is terminal ({}) and cannot be reserved again".format(
                    subtask_id, account.status
                )
            )
        if account is None:
            # Keep a rejected request out of the audited subtask set until
            # its budget check succeeds.
            account = SubtaskQuota(subtask_id)

        reservation = self._reservation_amount(account, amount)
        if reservation > self.available:
            error = BudgetInsufficientError(
                self.job_id,
                reservation,
                self.available,
                subtask_id=subtask_id,
                parent_available=self.available,
            )
            self._event(
                INSUFFICIENT_BUDGET,
                subtask_id,
                requested=reservation,
                available=self.available,
            )
            raise error

        if subtask_id not in self.subtasks:
            self.subtasks[subtask_id] = account
        account.reservation = reservation
        account.held = reservation
        account.status = RESERVED
        self.reserved += reservation
        self._event("quota_reserved", subtask_id, reservation)
        return QuotaResult(True, RESERVED, self, subtask_id, amount=reservation)

    accept = reserve
    accept_subtask = reserve
    allocate = reserve

    def try_reserve(self, subtask_id, amount=None, **options):
        try:
            return self.reserve(subtask_id, amount, **options)
        except BudgetInsufficientError as error:
            return QuotaResult(
                False,
                INSUFFICIENT_BUDGET,
                self,
                subtask_id,
                requested=error.requested,
                available=error.available,
                error=error,
            )

    try_accept = try_reserve

    def reserve_many(self, items=None):
        results = []
        for item in items or list(self.subtasks):
            if isinstance(item, str):
                results.append(self.reserve(item))
            else:
                subtask_id, amount = item
                results.append(self.reserve(subtask_id, amount))
        return results

    accept_all = reserve_many

    def begin_attempt(self, subtask_id, attempt_id=None):
        account = self._known(subtask_id)
        if account.status in TERMINAL_STATUSES:
            raise QuotaConflictError("subtask {!r} is terminal".format(subtask_id))
        account.attempts += 1
        account.status = RUNNING
        self._event(
            "attempt_started",
            subtask_id,
            attempt=account.attempts,
            attempt_id=attempt_id,
        )
        return QuotaResult(True, RUNNING, self, subtask_id, attempt=account.attempts)

    start = begin_attempt

    def fail(self, subtask_id, reason=None):
        account = self._known(subtask_id)
        account.status = FAILED
        self._event("subtask_failed", subtask_id, reason=reason)
        return QuotaResult(True, FAILED, self, subtask_id, reason=reason)

    def retry(self, subtask_id, amount=None, *, refund_previous=False):
        account = self._known(subtask_id)
        if account.status in (COMPLETED, CANCELLED, CANCELED):
            raise QuotaConflictError(
                "cannot retry terminal subtask {!r} ({})".format(subtask_id, account.status)
            )
        refunded = 0
        if refund_previous and account.used:
            refunded = account.used
            self.refund(subtask_id, refunded)
        additional = 0
        if amount is not None:
            wanted = _positive_int(amount, "retry reservation")
            if wanted > account.held:
                additional = wanted - account.held
                if additional > self.available:
                    raise BudgetInsufficientError(
                        self.job_id,
                        additional,
                        self.available,
                        subtask_id=subtask_id,
                    )
                account.reservation += additional
                account.held += additional
                self.reserved += additional
        account.attempts += 1
        account.retry_count += 1
        account.status = RETRYING
        self._event(
            "retry_started",
            subtask_id,
            attempt=account.attempts,
            inherited_used=account.used,
            inherited_held=account.held,
            refunded=refunded,
            additional_reserved=additional,
        )
        return QuotaResult(
            True,
            RETRYING,
            self,
            subtask_id,
            attempt=account.attempts,
            inherited_used=account.used,
            inherited_held=account.held,
        )

    def spend(self, subtask_id, amount, *, allow_extra=False):
        account = self._known(subtask_id)
        charge = _positive_int(amount, "usage")
        extra_needed = max(0, charge - account.held)
        extra_reserved = 0
        if extra_needed:
            if not allow_extra or extra_needed > self.available:
                raise BudgetInsufficientError(
                    self.job_id,
                    charge,
                    account.held,
                    subtask_id=subtask_id,
                    parent_available=self.available,
                    reservation_remaining=account.held,
                )
            extra_reserved = extra_needed
            account.reservation += extra_reserved
            account.held += extra_reserved
            self.reserved += extra_reserved
        account.held -= charge
        account.used += charge
        self.reserved -= charge
        self.consumed += charge
        self._event("usage_recorded", subtask_id, charge, extra_reserved=extra_reserved)
        return QuotaResult(True, RUNNING, self, subtask_id, charged=charge)

    charge = spend
    record_charge = spend

    def record_usage(self, subtask_id, amount=None, *, total=None, used=None):
        target = first_not_none(total, used)
        if target is not None:
            account = self._known(subtask_id)
            target = _positive_int(target, "total usage")
            delta = target - account.used
            if delta >= 0:
                if delta:
                    self.spend(subtask_id, delta)
            else:
                self.refund(subtask_id, -delta)
            return QuotaResult(True, RUNNING, self, subtask_id, used=account.used)
        return self.spend(subtask_id, amount)

    report_usage = record_usage

    def refund(self, subtask_id, amount):
        account = self._known(subtask_id)
        refund_amount = _positive_int(amount, "refund")
        if refund_amount > account.used:
            raise ApprovalQuotaError(
                "cannot refund {}; subtask used only {}".format(refund_amount, account.used)
            )
        account.used -= refund_amount
        account.held += refund_amount
        self.consumed -= refund_amount
        self.reserved += refund_amount
        self._event("quota_refunded", subtask_id, refund_amount)
        return QuotaResult(True, RESERVED, self, subtask_id, refunded=refund_amount)

    restore = refund
    restore_usage = refund

    def release(self, subtask_id, amount=None):
        """Release part or all of a subtask's current hold to the parent."""
        account = self._known(subtask_id)
        release_amount = account.held if amount is None else _positive_int(amount, "release")
        if release_amount > account.held:
            raise ApprovalQuotaError(
                "cannot release {}; subtask holds only {}".format(release_amount, account.held)
            )
        account.held -= release_amount
        self.reserved -= release_amount
        account.released += release_amount
        self._event("quota_released", subtask_id, release_amount)
        return QuotaResult(True, RESERVED, self, subtask_id, released=release_amount)

    release_hold = release
    restore_to_parent = release

    def complete(self, subtask_id, actual=None, *, used=None, amount=None):
        account = self._known(subtask_id)
        total_used = first_not_none(actual, used)
        if total_used is not None:
            self.record_usage(subtask_id, total=total_used)
        elif amount is not None:
            self.spend(subtask_id, amount)

        released = account.held
        if released:
            self.reserved -= released
            account.released += released
            account.held = 0
        account.status = COMPLETED
        self._event("subtask_completed", subtask_id, released=released)
        return QuotaResult(True, COMPLETED, self, subtask_id, released=released)

    finish = complete
    succeed = complete

    def commit(self, subtask_id, actual=_MISSING):
        """Normal completion that treats unused hold as consumed quota."""
        if actual is not _MISSING:
            return self.complete(subtask_id, actual=actual)
        account = self._known(subtask_id)
        if account.held:
            self.spend(subtask_id, account.held)
        return self.complete(subtask_id)

    def cancel(self, subtask_id, *, restore_used=False, reason=None):
        account = self._known(subtask_id)
        if account.status == CANCELLED or account.status == CANCELED:
            return QuotaResult(True, CANCELLED, self, subtask_id, replayed=True)
        restored_used = 0
        if restore_used and account.used:
            restored_used = account.used
            self.refund(subtask_id, restored_used)
        released = account.held
        if released:
            self.reserved -= released
            account.released += released
            account.held = 0
        account.status = CANCELLED
        self._event(
            "subtask_cancelled",
            subtask_id,
            released=released,
            restored_used=restored_used,
            reason=reason,
        )
        return QuotaResult(
            True,
            CANCELLED,
            self,
            subtask_id,
            released=released,
            restored_used=restored_used,
        )

    def quota_for(self, subtask_id):
        account = self._known(subtask_id)
        return account.held

    complete_subtask = complete
    cancel_subtask = cancel
    retry_subtask = retry
    fail_subtask = fail
    start_subtask = begin_attempt

    def reservation_for(self, subtask_id):
        return self._known(subtask_id).reservation

    def protected_quota_for_other_subtasks(self, current_subtask_ids=None):
        """Return protected holds belonging to all other live subtasks."""
        current = set(current_subtask_ids or [])
        return sum(
            account.held
            for subtask_id, account in self.subtasks.items()
            if subtask_id not in current and account.status in ACTIVE_STATUSES
        )

    def quota_left_for_other_subtasks(self, current_subtask_ids=None, *, include_available=True):
        """Capacity available to other subtasks: holds plus free budget."""
        protected = self.protected_quota_for_other_subtasks(current_subtask_ids)
        if include_available:
            return protected + self.available
        return protected

    reserved_quota_for_other_subtasks = protected_quota_for_other_subtasks
    remaining_for_others = quota_left_for_other_subtasks

    def snapshot(self):
        return OrderedDict(
            [
                ("job_id", self.job_id),
                ("status", "active"),
                ("budget", self.budget),
                ("total_quota", self.budget),
                ("consumed", self.consumed),
                ("used", self.consumed),
                ("reserved", self.reserved),
                ("available", self.available),
                ("remaining", self.available),
                ("allocated", self.allocated),
                ("fair", self.fair),
                (
                    "subtasks",
                    OrderedDict(
                        (key, account.to_dict()) for key, account in self.subtasks.items()
                    ),
                ),
                ("events", [dict(event) for event in self.events]),
                ("documents", [dict(item) for item in self.documents]),
            ]
        )

    def audit_trail(self):
        return [dict(event) for event in self.events]

    def report(self):
        return self.snapshot()

    def review(self, **kwargs):
        return self.to_json(**kwargs)

    def to_json(self, **kwargs):
        import json

        options = {"sort_keys": False, "indent": 2}
        options.update(kwargs)
        return json.dumps(self.snapshot(), **options)

    @classmethod
    def from_snapshot(cls, data):
        ledger = cls(
            data.get("job_id"),
            data.get("budget", data.get("total_quota")),
            fair=data.get("fair", True),
        )
        ledger.consumed = data.get("consumed", data.get("used", 0))
        ledger.reserved = data.get("reserved", 0)
        ledger.events = list(data.get("events", []))
        for subtask_id, item in data.get("subtasks", {}).items():
            account = SubtaskQuota(subtask_id)
            for key, value in item.items():
                if key in ("subtask_id", "remaining"):
                    continue
                setattr(account, key, value)
            ledger.subtasks[subtask_id] = account
        return ledger


# Descriptive aliases used by differently worded callers/tests.
QuotaManager = QuotaLedger
ApprovalQuotaManager = QuotaLedger
ApprovalLedger = QuotaLedger
JobQuotaLedger = QuotaLedger
ParentJob = QuotaLedger
Job = QuotaLedger
FairQuotaManager = QuotaLedger
AcceptedSubtask = SubtaskQuota
Subtask = SubtaskQuota
QuotaAccount = SubtaskQuota
DeclarationSubdocument = ApprovalDocument


class QuotaCoordinator(object):
    """Registry that gives both XML entry points the same job ledger."""

    def __init__(self):
        self._ledgers = OrderedDict()

    def create(self, job_id, budget=None, **kwargs):
        if job_id in self._ledgers:
            raise QuotaConflictError("job {!r} already exists".format(job_id))
        ledger = QuotaLedger(job_id, budget, **kwargs)
        self._ledgers[job_id] = ledger
        return ledger

    def attach(self, job_id=None, budget=None, **kwargs):
        if job_id is None:
            if budget is None:
                raise InvalidApprovalXMLError("job_id or budget is required")
            job_id = "job-{}".format(uuid4().hex[:12])
        if job_id in self._ledgers:
            ledger = self._ledgers[job_id]
            if budget is not None and int(budget) != ledger.budget:
                raise QuotaConflictError(
                    "job {!r} budget changed: {} != {}".format(job_id, budget, ledger.budget)
                )
            return ledger
        ledger = QuotaLedger(job_id, budget, **kwargs)
        self._ledgers[job_id] = ledger
        return ledger

    def get(self, job_id):
        try:
            return self._ledgers[job_id]
        except KeyError:
            raise UnknownSubtaskError("unknown job {!r}".format(job_id))

    def __contains__(self, job_id):
        return job_id in self._ledgers

    def reset(self):
        self._ledgers.clear()

    def snapshots(self):
        return OrderedDict(
            (job_id, ledger.snapshot()) for job_id, ledger in self._ledgers.items()
        )


QuotaRegistry = QuotaCoordinator
ApprovalRegistry = QuotaCoordinator
QuotaInheritance = QuotaCoordinator

default_coordinator = QuotaCoordinator()


def reset_default_coordinator():
    default_coordinator.reset()


# Backwards-compatible descriptive function alias.
reset_registry = reset_default_coordinator


def first_not_none(*values):
    for value in values:
        if value is not None and value is not _MISSING:
            return value
    return None


def read_xml_root(source, forbid_dtd=True):
    """Parse path, file-like object, XML text, or XML bytes safely."""
    if hasattr(source, "read"):
        tree = DefusedET.parse(source, forbid_dtd=forbid_dtd)
        return tree.getroot()
    if isinstance(source, (str, bytes)):
        stripped = source.lstrip()
        looks_like_markup = stripped.startswith("<")
        if looks_like_markup:
            return DefusedET.fromstring(source, forbid_dtd=forbid_dtd)
        if isinstance(source, bytes):
            source = os.fsdecode(source)
        tree = DefusedET.parse(source, forbid_dtd=forbid_dtd)
        return tree.getroot()
    tree = DefusedET.parse(source, forbid_dtd=forbid_dtd)
    return tree.getroot()


def _find_first(element, names):
    wanted = {name.lower().replace("-", "_") for name in names}
    for node in element.iter():
        if _local_name(node.tag) in wanted:
            return node
    return None


def _job_candidates(root, preferred=None):
    candidates = []
    seen = set()
    for element in root.iter():
        if _local_name(element.tag) in _JOB_TAGS:
            key = id(element)
            seen.add(key)
            candidates.append(element)
    for element in (preferred, root):
        if element is not None and id(element) not in seen:
            candidates.append(element)
    return candidates


def _extract_job_budget(root, job_element, override_budget):
    if override_budget is not None:
        return _as_int(override_budget, field="budget override")
    budget_text = None
    for element in _job_candidates(root, job_element):
        if element is None:
            continue
        budget_text = _attr(element, *_BUDGET_KEYS)
        if budget_text is None:
            budget_text = _child_text(element, _BUDGET_KEYS)
        if budget_text is not None:
            break
    return _as_int(budget_text, None, "job budget")


def _extract_job_id(root, job_element, override_job_id):
    if override_job_id is not None:
        return str(override_job_id)
    value = None
    for element in _job_candidates(root, job_element):
        if element is None:
            continue
        value = _attr(element, *_ID_KEYS)
        if value is not None:
            return value
        value = _child_text(element, ("job_id", "id"))
        if value is not None:
            return value
    return None


def _subtask_elements(root):
    containers = [
        element for element in root.iter() if _local_name(element.tag) in _CONTAINER_TAGS
    ]
    found = []
    if containers:
        for container in containers:
            for child in list(container):
                if _local_name(child.tag) in _SUBTASK_TAGS:
                    found.append(child)
    if not found:
        found = [element for element in root.iter() if _local_name(element.tag) in _SUBTASK_TAGS]
    # Deduplicate while preserving order; a permissive fallback can see a node
    # through both a container and ``iter()`` in unusual nested documents.
    unique = []
    seen = set()
    for element in found:
        key = id(element)
        if key not in seen:
            seen.add(key)
            unique.append(element)
    return unique


def document_from_root(root, source_kind="approval", job_id=None, budget=None):
    declaration = _find_first(root, _DECLARATION_TAGS)
    job_element = _find_first(root, _JOB_TAGS)
    if job_element is None and _local_name(root.tag) in _JOB_TAGS:
        job_element = root
    if job_element is None:
        job_element = declaration if declaration is not None else root

    resolved_job_id = _extract_job_id(root, job_element, job_id)
    resolved_budget = _extract_job_budget(root, job_element, budget)
    if resolved_job_id is None:
        raise InvalidApprovalXMLError("approval XML is missing a job id")
    if resolved_budget is None:
        raise InvalidApprovalXMLError("approval XML is missing a quota/budget")

    declarations = []
    for index, element in enumerate(_subtask_elements(root), start=1):
        subtask_id = _attr(element, "subtask_id", "task_id", *_ID_KEYS)
        if subtask_id is None:
            subtask_id = _child_text(element, ("subtask_id", "task_id", "id"))
        if subtask_id is None:
            subtask_id = "subtask-{}".format(index)
        quota_text = _attr(element, *_RESERVATION_KEYS)
        if quota_text is None:
            quota_text = _child_text(element, _RESERVATION_KEYS)
        quota = _as_int(quota_text, None, "subtask quota")
        weight_text = _attr(element, *_WEIGHT_KEYS)
        if weight_text is None:
            weight_text = _child_text(element, _WEIGHT_KEYS)
        weight = _as_int(weight_text, 1, "weight") or 1
        declarations.append(
            SubtaskDeclaration(
                subtask_id,
                quota=quota,
                weight=weight,
                tag=_local_name(element.tag),
                attributes=_normalized_attributes(element),
            )
        )

    return ApprovalDocument(
        resolved_job_id,
        resolved_budget,
        declarations,
        root=root,
        declaration=declaration,
        source_kind=source_kind,
    )


def parse_approval(source, *, job_id=None, budget=None, forbid_dtd=True):
    root = read_xml_root(source, forbid_dtd=forbid_dtd)
    return document_from_root(root, "controlled_approval", job_id=job_id, budget=budget)


def parse_declaration(source, *, job_id=None, budget=None, forbid_dtd=True):
    root = read_xml_root(source, forbid_dtd=forbid_dtd)
    return document_from_root(root, "declaration", job_id=job_id, budget=budget)


# Wording aliases for the two XML entry points.
load_approval = parse_approval
read_approval = parse_approval
parse_controlled_approval = parse_approval
load_controlled_approval = parse_approval
parse_approval_text = parse_approval
approval_fromstring = parse_approval
load_declaration = parse_declaration
read_declaration = parse_declaration
declaration_fromstring = parse_declaration
parse_xml = parse_approval
load_xml = parse_approval
parse_quota_xml = parse_approval
safe_parse = read_xml_root


class ApprovalQuotaService(object):
    """Parse XML entries and update one shared :class:`QuotaCoordinator`."""

    def __init__(
        self,
        coordinator=None,
        budget=None,
        *args,
        reserve=True,
        fair=True,
        job_id=None,
        total_quota=None,
        registry=None,
        **kwargs,
    ):
        if isinstance(coordinator, QuotaCoordinator):
            actual_coordinator = coordinator
        elif isinstance(registry, QuotaCoordinator):
            actual_coordinator = registry
        else:
            if job_id is None and isinstance(coordinator, str):
                job_id = coordinator
                coordinator = None
            if budget is None and isinstance(coordinator, int):
                budget = coordinator
            if budget is None and total_quota is not None:
                budget = total_quota
            actual_coordinator = default_coordinator
        if args and budget is None:
            budget = args[0]
        if job_id is None and isinstance(budget, str):
            job_id = budget
            budget = None

        self.coordinator = actual_coordinator
        self.auto_reserve = reserve
        self.reserve_enabled = reserve
        self.fair = fair
        self.default_job_id = job_id
        if job_id is not None and budget is not None:
            self.coordinator.attach(job_id, budget, fair=fair)

    @classmethod
    def for_job(cls, job_id, budget=None, coordinator=None, **kwargs):
        service = cls(coordinator, job_id=job_id, budget=budget, **kwargs)
        service.default_job_id = job_id
        return service

    def _resolve_job_subtask(self, job_id_or_subtask, subtask_id=_MISSING):
        if subtask_id is _MISSING:
            if self.default_job_id is None:
                raise ApprovalQuotaError(
                    "job_id is required unless adapter was created for a job"
                )
            return self.default_job_id, job_id_or_subtask
        return job_id_or_subtask, subtask_id

    def accept_document(self, document):
        ledger = self.coordinator.attach(document.job_id, document.budget, fair=self.fair)
        ledger.attach_document(document)
        ledger.declare_many(document.subtasks)
        if self.auto_reserve:
            for subtask in document.subtasks:
                ledger.reserve(subtask.subtask_id, subtask.quota)
        return ledger

    def accept_approval(self, source, **kwargs):
        document = parse_approval(source, **kwargs)
        return self.accept_document(document)

    def accept_declaration(self, source, **kwargs):
        document = parse_declaration(source, **kwargs)
        return self.accept_document(document)

    def get_ledger(self, job_id=None):
        if job_id is None:
            job_id = self.default_job_id
        return self.coordinator.get(job_id)

    get_job = get_ledger

    def reserve(self, first, second=_MISSING, third=_MISSING, amount=None, **kwargs):
        if third is not _MISSING:
            job_id, subtask_id, positional_amount = first, second, third
        elif self.default_job_id is not None and second is not _MISSING:
            job_id, subtask_id = self.default_job_id, first
            positional_amount = second
        else:
            job_id, subtask_id = self._resolve_job_subtask(first, second)
            positional_amount = None
        if amount is None:
            amount = positional_amount
        return self.get_ledger(job_id).reserve(subtask_id, amount, **kwargs)

    accept_subtask = reserve

    def try_reserve(self, first, second=_MISSING, third=_MISSING, amount=None, **kwargs):
        if third is not _MISSING:
            job_id, subtask_id, positional_amount = first, second, third
        elif self.default_job_id is not None and second is not _MISSING:
            job_id, subtask_id = self.default_job_id, first
            positional_amount = second
        else:
            job_id, subtask_id = self._resolve_job_subtask(first, second)
            positional_amount = None
        if amount is None:
            amount = positional_amount
        return self.get_ledger(job_id).try_reserve(subtask_id, amount, **kwargs)

    def retry_subtask(self, job_id_or_subtask, subtask_id=_MISSING, **kwargs):
        job_id, subtask_id = self._resolve_job_subtask(job_id_or_subtask, subtask_id)
        return self.get_ledger(job_id).retry(subtask_id, **kwargs)

    def start_subtask(self, job_id_or_subtask, subtask_id=_MISSING, **kwargs):
        job_id, subtask_id = self._resolve_job_subtask(job_id_or_subtask, subtask_id)
        return self.get_ledger(job_id).begin_attempt(subtask_id, **kwargs)

    def complete_subtask(self, first, second=_MISSING, third=_MISSING, **kwargs):
        actual = kwargs.pop("actual", None)
        if third is not _MISSING:
            job_id, subtask_id, positional_actual = first, second, third
        elif self.default_job_id is not None and second is not _MISSING:
            job_id, subtask_id = self.default_job_id, first
            positional_actual = second
        else:
            job_id, subtask_id = self._resolve_job_subtask(first, second)
            positional_actual = _MISSING
        if actual is None and positional_actual is not _MISSING:
            actual = positional_actual
        if actual is not None:
            kwargs["actual"] = actual
        return self.get_ledger(job_id).complete(subtask_id, **kwargs)

    def cancel_subtask(self, job_id_or_subtask, subtask_id=_MISSING, **kwargs):
        job_id, subtask_id = self._resolve_job_subtask(job_id_or_subtask, subtask_id)
        return self.get_ledger(job_id).cancel(subtask_id, **kwargs)

    def fail_subtask(self, job_id_or_subtask, subtask_id=_MISSING, **kwargs):
        job_id, subtask_id = self._resolve_job_subtask(job_id_or_subtask, subtask_id)
        return self.get_ledger(job_id).fail(subtask_id, **kwargs)

    def record_usage(self, job_id_or_subtask, subtask_id=_MISSING, *args, **kwargs):
        job_id, subtask_id = self._resolve_job_subtask(job_id_or_subtask, subtask_id)
        return self.get_ledger(job_id).record_usage(subtask_id, *args, **kwargs)

    def remaining_quota(self, job_id=None):
        return self.get_ledger(job_id).available

    def quota_left_for_other_subtasks(
        self, job_id_or_ids=None, current_subtask_ids=None, **kwargs
    ):
        if current_subtask_ids is None and isinstance(job_id_or_ids, (list, tuple, set)):
            job_id = self.default_job_id
            current_subtask_ids = job_id_or_ids
        elif job_id_or_ids is None or isinstance(job_id_or_ids, str):
            job_id = job_id_or_ids if job_id_or_ids is not None else self.default_job_id
        else:
            job_id = self.default_job_id
            current_subtask_ids = job_id_or_ids
        return self.get_ledger(job_id).quota_left_for_other_subtasks(
            current_subtask_ids, **kwargs
        )

    def snapshot(self, job_id=None):
        return self.get_ledger(job_id).snapshot()

    def report(self, job_id=None):
        return self.snapshot(job_id)

    def review(self, job_id=None, **kwargs):
        return self.get_ledger(job_id).to_json(**kwargs)

    retry = retry_subtask
    start = start_subtask
    complete = complete_subtask
    cancel = cancel_subtask
    fail = fail_subtask

    # Generic and wording aliases.
    accept_source = accept_approval
    accept = accept_approval
    process_approval = accept_approval
    process_declaration = accept_declaration
    handle_approval = accept_approval
    handle_declaration = accept_declaration


ControlledApprovalAdapter = ApprovalQuotaService
QuotaAdapter = ApprovalQuotaService
ApprovalService = ApprovalQuotaService
ApprovalQuotaAdapter = ApprovalQuotaService
ControlledApprovalService = ApprovalQuotaService


def accept_approval(source, coordinator=None, **kwargs):
    return ApprovalQuotaService(coordinator).accept_approval(source, **kwargs)


def accept_declaration(source, coordinator=None, **kwargs):
    return ApprovalQuotaService(coordinator).accept_declaration(source, **kwargs)


def fair_reservation(total_quota, subtask_count):
    """Return the equal integer share reserved for each accepted subtask."""
    return _as_int(total_quota, field="total_quota") // max(1, int(subtask_count))


def allocate_fair_quota(total_quota, subtask_count):
    """Deterministically split an integer budget among subtasks."""
    ledger = QuotaLedger("fair-share", total_quota)
    return ledger.fair_shares(subtask_count)


def parse_fixture():
    """Return the repository's offline nested XML fixture path."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "xmltestdata", "approval_quota_nested.xml")


__all__ = [
    "ACCEPTED",
    "ACTIVE_STATUSES",
    "ApprovalDocument",
    "ApprovalLedger",
    "ApprovalQuotaError",
    "ApprovalQuotaManager",
    "ApprovalQuotaService",
    "ApprovalRegistry",
    "BUDGET_INSUFFICIENT",
    "BudgetInsufficientError",
    "CANCELLED",
    "CANCELED",
    "COMPLETED",
    "ControlledApprovalAdapter",
    "DECLARED",
    "INSUFFICIENT_BUDGET",
    "InvalidApprovalXMLError",
    "PENDING",
    "QuotaAdapter",
    "QuotaConflictError",
    "QuotaCoordinator",
    "QuotaExceededError",
    "QuotaLedger",
    "QuotaManager",
    "QuotaRegistry",
    "QuotaResult",
    "RETRYING",
    "RESERVED",
    "SubtaskDeclaration",
    "SubtaskQuota",
    "UnknownSubtaskError",
    "accept_approval",
    "accept_declaration",
    "default_coordinator",
    "parse_approval",
    "parse_controlled_approval",
    "parse_declaration",
    "parse_fixture",
    "read_xml_root",
    "reset_default_coordinator",
    "reset_registry",
]
