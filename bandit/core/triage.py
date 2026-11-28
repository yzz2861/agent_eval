# SPDX-License-Identifier: Apache-2.0
"""Responsibility-aware triage for Bandit results.

Bandit reports every finding a plugin can prove.  On a real on-call queue
that is often more than the responder can action in a shift.  This module
keeps the existing :class:`bandit.core.issue.Issue` objects unchanged and
adds an allocation layer on top of them:

* every issue is assigned to a caller supplied responsibility;
* duplicate alerts from the same responsibility only consume one slot;
* findings reported by several plugins at the same location are merged into
  one finding without losing the contributing rule identifiers;
* a responsibility can spend from a cumulative quota across several calls;
* a configurable severity level is never deferred, even when the quota is
  already exhausted;
* deferred findings carry the time at which the quota resets, so a caller
  knows when they become eligible again.

The module deliberately does not alter ``Issue`` or any existing formatter.
``TriageResult.as_dict()`` returns ordinary issue dictionaries (the same
keys used by the JSON formatter) and adds triage metadata alongside them.
"""

import datetime
import math
from collections import OrderedDict
from collections.abc import Mapping
from numbers import Real

from bandit.core import constants
from bandit.core import issue as issue_module

SEVERITY_ORDER = tuple(constants.RANKING)
DEFAULT_NON_DEFERRABLE = ("HIGH",)
DEFAULT_DEFERRAL_PERIOD = datetime.timedelta(days=1)
UNASSIGNED_RESPONSIBILITY = "unassigned"


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def _as_datetime(value):
    """Return *value* as a timezone-aware UTC datetime.

    ``None`` is preserved so a caller can explicitly say that no reset time
    is known.  Epoch numbers and ISO-8601 strings are accepted as a
    convenience for JSON round-trips.
    """

    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=datetime.timezone.utc)
        return value.astimezone(datetime.timezone.utc)
    if isinstance(value, Real) and not isinstance(value, bool):
        return datetime.datetime.fromtimestamp(
            float(value), tz=datetime.timezone.utc
        )
    if isinstance(value, str):
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return _as_datetime(parsed)
    raise TypeError(
        "expected a datetime, epoch number, ISO-8601 string or None"
    )


def _isoformat(value):
    value = _as_datetime(value)
    if value is None:
        return None
    return value.isoformat().replace("+00:00", "Z")


def severity_rank(severity):
    """Return the rank of a Bandit severity, or ``-1`` for unknown values."""

    try:
        return SEVERITY_ORDER.index(str(severity).upper())
    except ValueError:
        return -1


def _normalise_severity(severity):
    value = str(severity or "UNDEFINED").upper()
    return value if value in SEVERITY_ORDER else "UNDEFINED"


def _effective_severity(issue):
    """Return the strongest severity the issue can be shown to carry.

    A policy can downgrade the ``severity`` a plugin emitted.  Callers that
    retain the rule's original level in ``original_severity`` (or the common
    ``rule_severity`` / ``base_severity`` / ``raw_severity`` spellings) must
    not lose a HIGH finding just because the displayed level was lowered.
    """

    severity = _normalise_severity(getattr(issue, "severity", None))
    for attribute in (
        "original_severity",
        "rule_severity",
        "base_severity",
        "raw_severity",
    ):
        candidate = getattr(issue, attribute, None)
        if candidate and severity_rank(candidate) > severity_rank(severity):
            severity = _normalise_severity(candidate)
    return severity


def _normalise_levels(levels, name="non_deferrable"):
    if levels is None:
        return ()
    if isinstance(levels, str):
        levels = (levels,)
    try:
        result = tuple(str(level).upper() for level in levels)
    except TypeError:
        raise TypeError(f"{name} must be a severity or iterable of severities")
    invalid = [level for level in result if level not in SEVERITY_ORDER]
    if invalid:
        raise ValueError(
            "unknown severity level(s) in %s: %s"
            % (name, ", ".join(sorted(invalid)))
        )
    return result


def _normalise_quota(value):
    if value is None:
        return math.inf
    if isinstance(value, bool) or not isinstance(value, Real):
        raise TypeError("a quota must be a non-negative number or None")
    if value < 0:
        raise ValueError("a quota cannot be negative")
    return value


def _issue_test_id(issue):
    return issue.test_id or issue.test or ""


def _issue_identity(issue):
    """A stable identity for an alert emitted by the same plugin.

    Line and column are intentionally omitted: the location is already part
    of the group key, while a plugin can emit the same alert from slightly
    different offsets on rescan.  This mirrors ``Issue.__eq__`` and keeps a
    shifted duplicate from spending a second quota slot.
    """

    return (
        issue.fname,
        _issue_test_id(issue),
        _effective_severity(issue),
        _normalise_severity(issue.confidence),
        issue.cwe.id,
        issue.text,
    )


def _default_location_key(issue):
    # A line is the useful review unit for Bandit.  Different plugins often
    # attach their finding to slightly different columns on the same line.
    if issue.lineno is None:
        # Synthetic or partially populated Issue instances may not have a
        # location.  Do not collapse unrelated rules just because both lines
        # are missing.
        return (
            issue.fname,
            None,
            _issue_test_id(issue),
            issue.col_offset,
            issue.text,
        )
    return (issue.fname, issue.lineno)


def _flatten_issue(value, output, responsibility=None):
    if isinstance(value, issue_module.Issue):
        output.append((value, responsibility))
        return
    issues = getattr(value, "issues", None)
    if issues is not None:
        hint = getattr(value, "responsibility", responsibility)
        for item in issues:
            _flatten_issue(item, output, hint)
        return
    raise TypeError(
        "expected Bandit Issue (or Finding/DeferredFinding) instances"
    )


def _responsibility_from_issue(issue):
    for attribute in ("responsibility", "owner", "team"):
        value = getattr(issue, attribute, None)
        if value:
            return value
    return None


def _mapping_lookup(mapping, issue):
    keys = (
        issue,
        (issue.fname, issue.lineno),
        (issue.fname, issue.lineno, issue.col_offset),
        (issue.fname, _issue_test_id(issue)),
        _issue_test_id(issue),
        issue.test,
        issue.fname,
        "*",
        "default",
        None,
    )
    for key in keys:
        try:
            if key in mapping:
                return mapping[key]
        except TypeError:
            continue
    return None


def resolve_responsibility(issue, responsibilities, default):
    """Resolve the responsibility for a single issue.

    ``responsibilities`` may be a string (all issues), a callable, or a
    mapping.  A mapping is looked up by the issue itself, ``(filename,
    line)``, ``(filename, line, column)``, ``(filename, test_id)``,
    ``test_id``, plugin name, filename, and finally ``None``.  An attribute
    named ``responsibility``, ``owner`` or ``team`` on the issue is used when
    no mapping is supplied.
    """

    if responsibilities is None:
        value = _responsibility_from_issue(issue)
    elif isinstance(responsibilities, str):
        value = responsibilities
    elif callable(responsibilities):
        value = responsibilities(issue)
    elif isinstance(responsibilities, Mapping):
        value = _mapping_lookup(responsibilities, issue)
        if value is None:
            value = _responsibility_from_issue(issue)
    else:
        raise TypeError(
            "responsibilities must be a string, callable, mapping or None"
        )
    if value is None:
        value = default
    return value if value is not None else UNASSIGNED_RESPONSIBILITY


def _cost_for(issue, severity_costs):
    if severity_costs is None:
        return 1
    severity = _effective_severity(issue)
    if callable(severity_costs):
        cost = severity_costs(issue)
    elif isinstance(severity_costs, Mapping):
        cost = severity_costs.get(severity)
        if cost is None:
            cost = severity_costs.get(severity.lower())
        if cost is None:
            cost = severity_costs.get("DEFAULT", 1)
    else:
        raise TypeError("severity_costs must be a mapping, callable or None")
    if isinstance(cost, bool) or not isinstance(cost, Real) or cost < 0:
        raise ValueError("an issue cost must be a non-negative number")
    return cost


class Finding:
    """One reviewable location, possibly reported by several plugins."""

    def __init__(
        self,
        issues,
        responsibility,
        duplicate_count=0,
        quota_cost=1,
        over_quota=False,
        already_allocated=False,
    ):
        issues = tuple(issues)
        if not issues:
            raise ValueError("a finding needs at least one issue")
        self.issues = issues
        self.responsibility = responsibility
        self.duplicate_count = duplicate_count
        self.quota_cost = quota_cost
        self.over_quota = over_quota
        self.already_allocated = already_allocated
        self.issue = self._choose_representative(issues)

    @staticmethod
    def _choose_representative(issues):
        # Keep the most severe (and then most confident) alert.  This is
        # important when one plugin reports HIGH and another reports MEDIUM at
        # the same location: grouping must never downgrade the finding.
        return max(
            enumerate(issues),
            key=lambda item: (
                severity_rank(_effective_severity(item[1])),
                severity_rank(item[1].confidence),
                -item[0],
            ),
        )[1]

    @property
    def severity(self):
        return _effective_severity(self.issue)

    @property
    def confidence(self):
        return self.issue.confidence

    @property
    def fname(self):
        return self.issue.fname

    @property
    def lineno(self):
        return self.issue.lineno

    @property
    def test_id(self):
        return self.issue.test_id

    @property
    def test(self):
        return self.issue.test

    @property
    def text(self):
        return self.issue.text

    @property
    def location(self):
        return (self.issue.fname, self.issue.lineno)

    @property
    def test_ids(self):
        return tuple(
            dict.fromkeys(_issue_test_id(item) for item in self.issues)
        )

    @property
    def contributing_issues(self):
        return self.issues

    @property
    def rule_ids(self):
        return self.test_ids

    @property
    def test_names(self):
        return tuple(dict.fromkeys(item.test for item in self.issues))

    @property
    def alert_count(self):
        return len(self.issues) + self.duplicate_count

    @property
    def count(self):
        return self.alert_count

    @property
    def original_severities(self):
        return tuple(item.severity for item in self.issues)

    def __getattr__(self, name):
        # Make the wrapper behave like the representative Issue for callers
        # that are used to passing Issue objects around.  Guard against
        # recursion during construction.
        issue = object.__getattribute__(self, "issue")
        return getattr(issue, name)

    def as_dict(self, with_code=True, max_lines=3):
        data = self.issue.as_dict(with_code=with_code, max_lines=max_lines)
        reported_severity = _normalise_severity(self.issue.severity)
        data.update(
            {
                "issue_severity": self.severity,
                "reported_severity": reported_severity,
                "severity_downgraded": reported_severity != self.severity,
                "responsibility": self.responsibility,
                "test_ids": list(self.test_ids),
                "test_names": list(self.test_names),
                "duplicate_count": self.duplicate_count,
                "alert_count": self.alert_count,
                "quota_cost": self.quota_cost,
                "over_quota": self.over_quota,
                "already_allocated": self.already_allocated,
                "contributing_issues": [
                    item.as_dict(with_code=with_code, max_lines=max_lines)
                    for item in self.issues
                ],
            }
        )
        return data

    def __repr__(self):
        return "Finding(responsibility=%r, location=%r, test_ids=%r)" % (
            self.responsibility,
            self.location,
            self.test_ids,
        )


class DeferredFinding(Finding):
    """A finding that did not fit in the current responsibility quota."""

    def __init__(
        self,
        issues,
        responsibility,
        resume_at,
        reason="quota_exhausted",
        resume_reason="quota_reset",
        required_cost=1,
        remaining_quota=0,
        duplicate_count=0,
    ):
        super().__init__(
            issues,
            responsibility,
            duplicate_count=duplicate_count,
            quota_cost=required_cost,
        )
        self.resume_at = _as_datetime(resume_at)
        self.reason = reason
        self.resume_reason = resume_reason
        self.required_cost = required_cost
        self.remaining_quota = remaining_quota

    @property
    def available_at(self):
        return self.resume_at

    @property
    def recover_at(self):
        return self.resume_at

    @property
    def not_before(self):
        return self.resume_at

    @property
    def recoverable_at(self):
        return self.resume_at

    @property
    def quota_reset_at(self):
        return self.resume_at

    def is_resumable(self, now=None):
        if self.resume_at is None:
            return False
        now = _as_datetime(now) if now is not None else _utcnow()
        return now >= self.resume_at

    def as_dict(self, with_code=True, max_lines=3):
        data = super().as_dict(with_code=with_code, max_lines=max_lines)
        data.update(
            {
                "defer_reason": self.reason,
                "reason": self.reason,
                "resume_at": _isoformat(self.resume_at),
                "available_at": _isoformat(self.resume_at),
                "recoverable_at": _isoformat(self.resume_at),
                "quota_reset_at": _isoformat(self.resume_at),
                "resume_reason": self.resume_reason,
                "required_quota": self.required_cost,
                "remaining_quota_at_deferral": self.remaining_quota,
            }
        )
        return data

    def __repr__(self):
        return (
            "DeferredFinding(responsibility=%r, location=%r, "
            "resume_at=%r)"
            % (self.responsibility, self.location, self.resume_at)
        )


class DuplicateAlert:
    """An exact repeat of an alert already represented by a finding."""

    def __init__(
        self,
        issue,
        responsibility,
        kept_test_id,
        occurrences=1,
        reason="duplicate_alert",
    ):
        self.issue = issue
        self.responsibility = responsibility
        self.kept_test_id = kept_test_id
        self.occurrences = occurrences
        self.reason = reason

    @property
    def fname(self):
        return self.issue.fname

    @property
    def lineno(self):
        return self.issue.lineno

    @property
    def count(self):
        return self.occurrences

    def as_dict(self, with_code=False, max_lines=3):
        data = self.issue.as_dict(with_code=with_code, max_lines=max_lines)
        data.update(
            {
                "responsibility": self.responsibility,
                "reason": self.reason,
                "kept_test_id": self.kept_test_id,
                "occurrences": self.occurrences,
            }
        )
        return data


class DeferralQueue(list):
    """List-like queue whose entries all explain when they can resume."""

    def __init__(self, entries=()):
        super().__init__(entries)

    @property
    def entries(self):
        return list(self)

    def resumable(self, now=None):
        return DeferralQueue(
            entry for entry in self if entry.is_resumable(now=now)
        )

    def pending(self, now=None):
        return DeferralQueue(
            entry for entry in self if not entry.is_resumable(now=now)
        )

    def as_dict(self, with_code=False, max_lines=3):
        return [
            entry.as_dict(with_code=with_code, max_lines=max_lines)
            for entry in self
        ]


class TriageResult:
    """The actionable set and the deferral queue from one allocation."""

    def __init__(
        self,
        actionable=None,
        deferred=None,
        duplicates=None,
        usage=None,
        quotas=None,
        non_deferrable=(),
        next_reset_at=None,
        generated_at=None,
    ):
        self.actionable = list(actionable or [])
        self.deferred = DeferralQueue(deferred or [])
        self.duplicates = list(duplicates or [])
        self.usage = dict(usage or {})
        self.quotas = dict(quotas or {})
        self.non_deferrable = tuple(non_deferrable)
        self.next_reset_at = _as_datetime(next_reset_at)
        self.generated_at = _as_datetime(generated_at) or _utcnow()

    @property
    def queue(self):
        return self.deferred

    @property
    def deferral_queue(self):
        return self.deferred

    @property
    def escalated(self):
        return self.actionable

    @property
    def handled(self):
        return self.actionable

    @property
    def duplicate_count(self):
        return sum(item.occurrences for item in self.duplicates)

    @property
    def overflow(self):
        return [item for item in self.actionable if item.over_quota]

    @property
    def all_findings(self):
        return self.actionable + list(self.deferred)

    def by_responsibility(self):
        result = OrderedDict()
        for item in self.actionable:
            bucket = result.setdefault(
                item.responsibility,
                {"actionable": [], "deferred": [], "duplicates": []},
            )
            bucket["actionable"].append(item)
        for item in self.deferred:
            bucket = result.setdefault(
                item.responsibility,
                {"actionable": [], "deferred": [], "duplicates": []},
            )
            bucket["deferred"].append(item)
        for item in self.duplicates:
            bucket = result.setdefault(
                item.responsibility,
                {"actionable": [], "deferred": [], "duplicates": []},
            )
            bucket["duplicates"].append(item)
        return result

    def summary(self):
        result = OrderedDict()
        responsibilities = set(self.quotas) | set(self.usage)
        responsibilities.update(
            item.responsibility
            for item in self.actionable + list(self.deferred)
        )
        responsibilities.update(
            item.responsibility for item in self.duplicates
        )
        for responsibility in sorted(responsibilities, key=str):
            quota = self.quotas.get(responsibility)
            if quota is None:
                quota = math.inf
            used = self.usage.get(responsibility, 0)
            actionable = [
                item
                for item in self.actionable
                if item.responsibility == responsibility
            ]
            deferred = [
                item
                for item in self.deferred
                if item.responsibility == responsibility
            ]
            duplicates = [
                item
                for item in self.duplicates
                if item.responsibility == responsibility
            ]
            remaining = None if math.isinf(quota) else max(quota - used, 0)
            result[str(responsibility)] = {
                "quota": None if math.isinf(quota) else quota,
                "unlimited": math.isinf(quota),
                "used": used,
                "remaining": remaining,
                "actionable": len(actionable),
                "deferred": len(deferred),
                "overflow": len(
                    [item for item in actionable if item.over_quota]
                ),
                "duplicates": sum(item.occurrences for item in duplicates),
            }
        result["_totals"] = {
            "actionable": len(self.actionable),
            "deferred": len(self.deferred),
            "duplicates": self.duplicate_count,
            "overflow": len(self.overflow),
            "used": sum(self.usage.values()),
        }
        return result

    def as_dict(self, with_code=True, max_lines=3):
        actionable = [
            item.as_dict(with_code=with_code, max_lines=max_lines)
            for item in self.actionable
        ]
        deferred = self.deferred.as_dict(
            with_code=with_code, max_lines=max_lines
        )
        all_findings = actionable + deferred
        return {
            # ``results`` keeps the shape used by the existing JSON report and
            # contains every grouped finding, whether actionable or deferred.
            "results": all_findings,
            "all_findings": all_findings,
            "actionable": actionable,
            "deferred": deferred,
            "deferral_queue": deferred,
            "duplicates": [
                item.as_dict(with_code=with_code, max_lines=max_lines)
                for item in self.duplicates
            ],
            "summary": self.summary(),
            "non_deferrable": list(self.non_deferrable),
            "next_reset_at": _isoformat(self.next_reset_at),
            "generated_at": _isoformat(self.generated_at),
        }

    def __repr__(self):
        return "TriageResult(actionable=%d, deferred=%d, duplicates=%d)" % (
            len(self.actionable),
            len(self.deferred),
            self.duplicate_count,
        )


class TriageAllocator:
    """Allocate Bandit results against cumulative responsibility quotas.

    The allocator is stateful so repeated scans do not spend the same quota
    twice for an alert already escalated in the current quota period.  Call
    :meth:`reset_quota` when a new period starts (or let the configured
    ``reset_interval`` advance automatically when ``allocate`` is called with
    a later ``now``).
    """

    def __init__(
        self,
        quotas=None,
        *,
        quota=None,
        non_deferrable=DEFAULT_NON_DEFERRABLE,
        default_quota=0,
        severity_costs=None,
        responsibilities=None,
        default_responsibility=UNASSIGNED_RESPONSIBILITY,
        location_key=None,
        reset_interval=DEFAULT_DEFERRAL_PERIOD,
        next_reset_at=None,
        clock=None,
    ):
        if quota is not None:
            default_quota = quota
        if quotas is None:
            quotas = {}
        elif isinstance(quotas, Real) and not isinstance(quotas, bool):
            default_quota = quotas
            quotas = {}
        if not isinstance(quotas, Mapping):
            raise TypeError("quotas must be a mapping or a number")
        self.quotas = OrderedDict(
            (key, _normalise_quota(value)) for key, value in quotas.items()
        )
        self.default_quota = _normalise_quota(default_quota)
        self.non_deferrable = _normalise_levels(non_deferrable)
        self._non_deferrable_rank = (
            min(severity_rank(level) for level in self.non_deferrable)
            if self.non_deferrable
            else None
        )
        if (
            severity_costs is not None
            and not callable(severity_costs)
            and not isinstance(severity_costs, Mapping)
        ):
            raise TypeError(
                "severity_costs must be a mapping, callable or None"
            )
        self.severity_costs = severity_costs
        self.responsibilities = responsibilities
        self.default_responsibility = default_responsibility
        self.location_key = location_key or _default_location_key
        self.reset_interval = reset_interval
        if reset_interval is not None and not isinstance(
            reset_interval, datetime.timedelta
        ):
            raise TypeError("reset_interval must be a timedelta or None")
        if (
            reset_interval is not None
            and reset_interval <= datetime.timedelta(0)
        ):
            raise ValueError("reset_interval must be positive")
        self.clock = clock or _utcnow
        now = self._now()
        self._next_reset_at = _as_datetime(next_reset_at)
        if self._next_reset_at is None and reset_interval is not None:
            self._next_reset_at = now + reset_interval
        self._usage = {}
        self._charged = set()
        self._deferred = OrderedDict()

    def _now(self, now=None):
        if now is not None:
            return _as_datetime(now)
        return _as_datetime(self.clock())

    def _quota_for(self, responsibility):
        return self.quotas.get(responsibility, self.default_quota)

    def _remaining_for(self, responsibility):
        quota = self._quota_for(responsibility)
        if math.isinf(quota):
            return math.inf
        return max(quota - self._usage.get(responsibility, 0), 0)

    def _next_resume_at(self, now):
        if self._next_reset_at is not None and now < self._next_reset_at:
            return self._next_reset_at
        if self.reset_interval is not None:
            return now + self.reset_interval
        if self._next_reset_at is not None:
            return self._next_reset_at
        return now + DEFAULT_DEFERRAL_PERIOD

    def _roll_period_if_due(self, now):
        if self._next_reset_at is None or now < self._next_reset_at:
            return False
        self._usage.clear()
        self._charged.clear()
        if self.reset_interval is None:
            self._next_reset_at = None
        else:
            elapsed = now - self._next_reset_at
            periods = elapsed // self.reset_interval + 1
            self._next_reset_at += periods * self.reset_interval
        return True

    def _is_non_deferrable(self, finding):
        if self._non_deferrable_rank is None:
            return False
        return severity_rank(finding.severity) >= self._non_deferrable_rank

    def _group(self, issues, responsibilities):
        groups = OrderedDict()
        duplicates = []
        for order, (raw_issue, hint) in enumerate(issues):
            responsibility = resolve_responsibility(
                raw_issue, responsibilities, self.default_responsibility
            )
            if responsibilities is None and hint is not None:
                responsibility = hint
            key = (responsibility, self.location_key(raw_issue))
            group = groups.get(key)
            if group is None:
                group = {
                    "issues": [],
                    "identities": {},
                    "duplicates": [],
                    "order": order,
                    "responsibility": responsibility,
                }
                groups[key] = group
            identity = _issue_identity(raw_issue)
            if identity in group["identities"]:
                group["identities"][identity] += 1
                group["duplicates"].append((raw_issue, identity))
                continue
            group["identities"][identity] = 1
            group["issues"].append(raw_issue)
        result = []
        for key, group in groups.items():
            duplicate_count = sum(
                count - 1 for count in group["identities"].values()
            )
            for identity, count in group["identities"].items():
                if count <= 1:
                    continue
                duplicate = next(
                    item
                    for item, duplicate_identity in group["duplicates"]
                    if duplicate_identity == identity
                )
                kept = next(
                    item
                    for item in group["issues"]
                    if _issue_identity(item) == identity
                )
                duplicates.append(
                    DuplicateAlert(
                        duplicate,
                        group["responsibility"],
                        _issue_test_id(kept),
                        occurrences=count - 1,
                    )
                )
            issues_in_group = group["issues"]
            cost = max(
                _cost_for(item, self.severity_costs)
                for item in issues_in_group
            )
            result.append(
                (
                    key,
                    Finding(
                        issues_in_group,
                        group["responsibility"],
                        duplicate_count=duplicate_count,
                        quota_cost=cost,
                    ),
                    group["order"],
                )
            )
        return result, duplicates

    def allocate(
        self, issues, responsibilities=None, *, now=None, resume_at=None
    ):
        """Allocate a batch of Issues/Finding objects.

        ``issues`` may be a list of :class:`Issue`, :class:`Finding` or
        :class:`DeferredFinding` objects.  ``responsibilities`` overrides the
        allocator default for this call.  Deferred findings are returned in
        ``result.deferred`` with their ``resume_at`` timestamp.
        """

        if isinstance(issues, (issue_module.Issue, Finding, DeferredFinding)):
            issues = [issues]
        flattened = []
        for item in issues:
            _flatten_issue(item, flattened)
        now = self._now(now)
        self._roll_period_if_due(now)
        effective_responsibilities = (
            self.responsibilities
            if responsibilities is None
            else responsibilities
        )
        groups, duplicates = self._group(flattened, effective_responsibilities)
        groups.sort(
            key=lambda item: (
                -severity_rank(item[1].severity),
                -severity_rank(item[1].confidence),
                item[2],
            )
        )
        actionable = []
        deferred = []
        for key, group, _order in groups:
            responsibility = group.responsibility
            cost = group.quota_cost
            already_allocated = key in self._charged
            if already_allocated:
                group.already_allocated = True
                group.quota_cost = 0
                actionable.append(group)
                self._deferred.pop(key, None)
                continue
            remaining = self._remaining_for(responsibility)
            if cost <= remaining:
                self._usage[responsibility] = (
                    self._usage.get(responsibility, 0) + cost
                )
                self._charged.add(key)
                actionable.append(group)
                self._deferred.pop(key, None)
                continue
            if self._is_non_deferrable(group):
                # Mandatory findings stay visible even when the quota is
                # already spent.  The usage is allowed to exceed quota.
                group.over_quota = True
                self._usage[responsibility] = (
                    self._usage.get(responsibility, 0) + cost
                )
                self._charged.add(key)
                actionable.append(group)
                self._deferred.pop(key, None)
                continue
            resume_time = (
                _as_datetime(resume_at)
                if resume_at is not None
                else self._next_resume_at(now)
            )
            deferred_group = DeferredFinding(
                group.issues,
                responsibility,
                resume_at=resume_time,
                reason="quota_exhausted",
                resume_reason="quota_reset",
                required_cost=cost,
                remaining_quota=remaining,
                duplicate_count=group.duplicate_count,
            )
            deferred.append(deferred_group)
            self._deferred[key] = deferred_group
        # Keep the result queue consistent with the allocator state.  A
        # deferred entry for a group that was not part of this batch remains
        # pending, so callers can safely allocate small incremental batches.
        queue = DeferralQueue(self._deferred.values())
        for item in deferred:
            if item not in queue:
                queue.append(item)
        next_reset_at = self._next_reset_at
        if next_reset_at is None and queue:
            next_reset_at = min(item.resume_at for item in queue)
        return TriageResult(
            actionable=actionable,
            deferred=queue,
            duplicates=duplicates,
            usage=self._usage,
            quotas={
                responsibility: self._quota_for(responsibility)
                for responsibility in (
                    set(self.quotas)
                    | set(self._usage)
                    | set(self._deferred_responsibilities())
                )
            },
            non_deferrable=self.non_deferrable,
            next_reset_at=next_reset_at,
            generated_at=now,
        )

    plan = allocate
    allocate_results = allocate
    assign = allocate

    def reset_quota(self, responsibility=None, now=None):
        """Reset cumulative usage and return the released deferred entries.

        Passing ``responsibility=None`` resets every responsibility.  The
        returned entries become immediately resumable and are removed from
        the allocator's pending queue.
        """

        now = self._now(now)
        if responsibility is None:
            released = list(self._deferred.values())
            self._deferred.clear()
            self._usage.clear()
            self._charged.clear()
            if self.reset_interval is not None:
                self._next_reset_at = now + self.reset_interval
            else:
                self._next_reset_at = None
        else:
            released = [
                entry
                for entry in self._deferred.values()
                if entry.responsibility == responsibility
            ]
            for key in list(self._deferred):
                if key[0] == responsibility:
                    del self._deferred[key]
            self._usage.pop(responsibility, None)
            self._charged = {
                key for key in self._charged if key[0] != responsibility
            }
        for entry in released:
            entry.resume_at = now
            entry.resume_reason = "quota_reset"
        return released

    def recover(self, responsibility=None, now=None):
        """Reset quota and immediately re-allocate the released entries."""

        released = self.reset_quota(responsibility=responsibility, now=now)
        return self.allocate(released, now=now)

    reset = reset_quota
    reset_quotas = reset_quota

    @property
    def pending(self):
        return DeferralQueue(self._deferred.values())

    @property
    def deferral_queue(self):
        return self.pending

    @property
    def queue(self):
        return self.pending

    def _deferred_responsibilities(self):
        return {entry.responsibility for entry in self._deferred.values()}

    @property
    def next_reset_at(self):
        return self._next_reset_at

    @property
    def used(self):
        return dict(self._usage)

    @property
    def usage(self):
        return dict(self._usage)

    @property
    def remaining(self):
        result = {}
        responsibilities = set(self.quotas) | set(self._usage)
        for responsibility in responsibilities:
            result[responsibility] = self._remaining_for(responsibility)
        return result

    def remaining_for(self, responsibility):
        return self._remaining_for(responsibility)

    def used_for(self, responsibility):
        return self._usage.get(responsibility, 0)

    def quota_for(self, responsibility):
        return self._quota_for(responsibility)

    def set_quota(self, responsibility, quota):
        self.quotas[responsibility] = _normalise_quota(quota)

    def set_quotas(self, quotas):
        for responsibility, quota in quotas.items():
            self.set_quota(responsibility, quota)


# Common spellings used by integrations which wrap Bandit's result store.
ResponsibilityAllocator = TriageAllocator
QuotaAllocator = TriageAllocator
IssueAllocator = TriageAllocator
DeferredIssue = DeferredFinding
AllocationResult = TriageResult


def allocate(
    issues,
    responsibilities=None,
    quotas=None,
    *,
    responsibility=None,
    quota=None,
    non_deferrable=DEFAULT_NON_DEFERRABLE,
    default_quota=0,
    severity_costs=None,
    location_key=None,
    reset_interval=DEFAULT_DEFERRAL_PERIOD,
    next_reset_at=None,
    now=None,
    resume_at=None,
    clock=None,
    default_responsibility=UNASSIGNED_RESPONSIBILITY,
):
    """One-shot allocation helper.

    This is the stateless entry point for callers that already maintain their
    own cumulative usage.  Use :class:`TriageAllocator` when quota should
    persist across calls or when :meth:`TriageAllocator.reset_quota` is
    needed.
    """

    if responsibilities is None and responsibility is not None:
        responsibilities = responsibility
    allocator = TriageAllocator(
        quotas,
        quota=quota,
        non_deferrable=non_deferrable,
        default_quota=default_quota,
        severity_costs=severity_costs,
        responsibilities=responsibilities,
        default_responsibility=default_responsibility,
        location_key=location_key,
        reset_interval=reset_interval,
        next_reset_at=next_reset_at,
        clock=clock,
    )
    return allocator.allocate(issues, now=now, resume_at=resume_at)


allocate_issues = allocate
allocate_results = allocate
plan_triage = allocate
triage_issues = allocate
triage = allocate


def triage_manager(
    manager,
    responsibilities=None,
    quotas=None,
    *,
    sev_level=constants.LOW,
    conf_level=constants.LOW,
    **kwargs,
):
    """Allocate the current results of a :class:`BanditManager`.

    Existing formatters continue to use ``manager.get_issue_list()``; this
    helper is an additive path for callers that want the on-call view.
    """

    results = manager.get_issue_list(sev_level, conf_level)
    if not isinstance(results, list):
        # A baseline returns a dict of issue -> candidates.  Allocation is
        # still useful for the representative issues.
        results = list(results)
    return allocate(
        results, responsibilities=responsibilities, quotas=quotas, **kwargs
    )


def build_deferral_queue(issues, responsibilities=None, quotas=None, **kwargs):
    """Return only the deferral queue for a batch of issues."""

    return allocate(
        issues, responsibilities=responsibilities, quotas=quotas, **kwargs
    ).deferred


__all__ = [
    "DEFAULT_DEFERRAL_PERIOD",
    "DEFAULT_NON_DEFERRABLE",
    "AllocationResult",
    "DeferralQueue",
    "DeferredIssue",
    "DeferredFinding",
    "DuplicateAlert",
    "Finding",
    "IssueAllocator",
    "QuotaAllocator",
    "ResponsibilityAllocator",
    "TriageAllocator",
    "TriageResult",
    "allocate",
    "allocate_issues",
    "allocate_results",
    "build_deferral_queue",
    "plan_triage",
    "resolve_responsibility",
    "severity_rank",
    "triage",
    "triage_issues",
    "triage_manager",
]
