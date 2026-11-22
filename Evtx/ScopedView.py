#!/usr/bin/python
#    This file is part of python-evtx.
#
#   Copyright 2012, 2013 Willi Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
"""Scope-bound event browsing views.

The normal :mod:`Evtx.Evtx` API exposes every record in a log.  This module
adds a second layer that is useful when a log has to be split between people
with different responsibilities:

* :class:`RecordVisibility` decides which records exist for a view.
* :class:`FieldVisibility` decides which XML fields and attributes are visible.
* :class:`AggregateVisibility` decides which aggregate queries are permitted.

The policies are part of a :class:`Scope`.  A scope is signed by a
:class:`ScopedArchive`, and a view is bound to both the scope and a role.
Cursors are opaque, authenticated, and scope/role-bound.  A cursor issued for
one scope or role cannot be replayed against another scope or role, even when
the two ranges overlap.  That property is important because it prevents a
previous count or cursor from being used as an oracle for a hidden range.

Pages and snapshots carry signed receipts.  A receipt can be verified later,
after a scope has changed, without asking the new view about old/hidden
records.
"""

from __future__ import absolute_import

import os
import re
import hmac
import json
import base64
import hashlib
import secrets
import datetime
import xml.etree.ElementTree as ET
from collections import Counter

__all__ = [
    "AggregateNotVisible",
    "AggregatePolicy",
    "AggregateVisibilityPolicy",
    "AggregateVisibility",
    "AckScope",
    "BrowsePage",
    "Cursor",
    "CursorError",
    "CursorExpired",
    "CursorToken",
    "CursorScopeMismatch",
    "EventBrowser",
    "EventBrowseView",
    "EventField",
    "EventPage",
    "EventView",
    "FieldNotVisible",
    "FieldPolicy",
    "FieldVisibilityPolicy",
    "FieldVisibility",
    "InvalidCursor",
    "InvalidScope",
    "Page",
    "RecordNotVisible",
    "RecordPolicy",
    "AckRange",
    "RecordRange",
    "Receipt",
    "RecordVisibilityPolicy",
    "RecordView",
    "RecordVisibility",
    "ROLE_INVESTIGATOR",
    "ROLE_OPERATOR",
    "Reconciliation",
    "Scope",
    "ScopeError",
    "ScopePolicy",
    "ScopeMismatch",
    "ScopeReceipt",
    "SignedScope",
    "ScopedArchive",
    "ScopedEventBrowser",
    "ScopedEventView",
    "EventScope",
    "ScopedPage",
    "ScopedView",
    "ScopedViewError",
    "Snapshot",
    "ViewPolicy",
    "Visibility",
    "VisibilityPolicy",
    "browse",
    "browse_events",
    "create_view",
    "event_view",
    "normalize_role",
    "open_view",
    "open_scoped_view",
    "scoped_view",
]


DEFAULT_ROLE = "investigator"
ROLE_OPERATOR = "operator"
ROLE_INVESTIGATOR = "investigator"

_ROLE_ALIASES = {
    "duty": ROLE_OPERATOR,
    "duty_officer": ROLE_OPERATOR,
    "on_call": ROLE_OPERATOR,
    "oncall": ROLE_OPERATOR,
    "operator": ROLE_OPERATOR,
    "值班": ROLE_OPERATOR,
    "investigation_lead": ROLE_INVESTIGATOR,
    "investigator": ROLE_INVESTIGATOR,
    "lead": ROLE_INVESTIGATOR,
    "调查": ROLE_INVESTIGATOR,
    "调查负责人": ROLE_INVESTIGATOR,
}


def normalize_role(role):
    """Return the canonical role name for a role or role alias."""

    if role is None:
        return None
    key = str(role).strip().lower().replace("-", "_").replace(" ", "_")
    return _ROLE_ALIASES.get(key, key)


class ScopedViewError(Exception):
    """Base class for errors raised by scoped views."""


class ScopeError(ScopedViewError):
    """Base class for scope and cursor errors."""


class InvalidScope(ScopeError, ValueError):
    """Raised when a scope is malformed or was not issued by this archive."""


class ScopeMismatch(ScopeError, ValueError):
    """Raised when a scope and view role do not agree."""


class CursorError(ScopeError):
    """Base class for cursor errors."""


class InvalidCursor(CursorError, ValueError):
    """Raised when a cursor is malformed or is not an opaque cursor token."""


class CursorScopeMismatch(CursorError, ScopeMismatch):
    """Raised when a cursor belongs to another scope, role, or archive."""


class CursorExpired(CursorError, ValueError):
    """Raised when a valid cursor points beyond the current visible records."""


class RecordNotVisible(ScopeError, KeyError):
    """Raised when code asks for a record that the scope does not expose."""


class FieldNotVisible(ScopeError, KeyError):
    """Raised when code asks for a field that the scope does not expose."""


class AggregateNotVisible(FieldNotVisible):
    """Raised when an aggregate or grouping field is not visible."""


class _CallableInt(int):
    """An integer that can also be called.

    This keeps both ``view.count == n`` and ``view.count() == n`` working for
    callers that are used to either style.
    """

    def __call__(self):
        return int(self)


class _CallableDict(dict):
    def __call__(self):
        return self

    def to_dict(self):
        return dict(self)

    def to_json(self):
        return json.dumps(dict(self), ensure_ascii=False, sort_keys=True, default=str)


class _CallableDateTime(datetime.datetime):
    def __call__(self):
        return self


class Cursor(str):
    """An opaque, authenticated pagination token."""

    @property
    def token(self):
        return str(self)

    def __call__(self):
        return str(self)

    def __repr__(self):
        return "Cursor({!r})".format(str(self)[:12] + "...")


class XmlString(str):
    """A string that can also be called.

    ``record.xml`` and ``record.xml()`` therefore both return the redacted XML
    string, matching the style used by :class:`Evtx.Evtx.Record`.
    """

    def __call__(self):
        return str(self)


def _canonical(value):
    """Serialize a JSON-compatible value deterministically."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _json_default(value):
    if isinstance(value, datetime.datetime):
        return value.isoformat()
    raise TypeError("not JSON serializable: {!r}".format(value))


def _as_datetime(value):
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        ret = value
    elif isinstance(value, str):
        ret = datetime.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    else:
        raise TypeError("expected datetime or ISO-8601 string, got {!r}".format(value))
    if ret.tzinfo is None:
        ret = ret.replace(tzinfo=datetime.timezone.utc)
    return ret.astimezone(datetime.timezone.utc)


def _iso(value):
    if value is None:
        return None
    return _as_datetime(value).isoformat()


def _local_name(tag):
    if not isinstance(tag, str):
        return str(tag)
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    if ":" in tag:
        return tag.rsplit(":", 1)[1]
    return tag


def _norm_query(value):
    value = str(value).strip().replace("\\", "/")
    value = re.sub(
        r"\[\s*@Name\s*=\s*'([^']*)'\s*\]",
        lambda m: "[@Name={}]".format(json.dumps(m.group(1), ensure_ascii=False)),
        value,
    )
    value = re.sub(
        r"\[\s*@Name\s*=\s*\"([^\"]*)\"\s*\]",
        lambda m: "[@Name={}]".format(json.dumps(m.group(1), ensure_ascii=False)),
        value,
    )
    value = value.replace("/text()", "").replace("/#text", "")
    value = re.sub(r"\{[^}]*\}", "", value)
    while value.startswith("./") or value.startswith("/"):
        value = value[2:] if value.startswith("./") else value[1:]
    if value.startswith("Event/"):
        value = value[len("Event/") :]
    return value


def _glob_match(value, pattern):
    # fnmatch treats [] as a character class, but EVTX selector paths use
    # literal brackets, so translate globs with a tiny regex instead.
    regex = re.escape(pattern)
    regex = regex.replace(r"\*", ".*").replace(r"\?", ".")
    return re.fullmatch(regex, value, flags=re.IGNORECASE) is not None


def _path_candidates(path, name=None):
    path = _norm_query(path)
    yield path
    yield re.sub(r"\[\d+\]", "", path)
    yield re.sub(r'\[@Name="[^"]*"\]', "", path)
    yield re.sub(r"/@[^/]+$", "", path)
    for segment in path.split("/"):
        if not segment:
            continue
        yield segment
        base = re.sub(r"\[\d+\]", "", segment)
        base = re.sub(r'\[@Name="[^"]*"\]', "", base)
        if base:
            yield base
        for match in re.finditer(r'@Name="([^"]*)"', segment):
            yield match.group(1)
    if name:
        yield str(name)


def _path_variants(path):
    path = _norm_query(path)
    yield path
    yield re.sub(r"\[\d+\]", "", path)
    yield re.sub(r'\[@Name="[^"]*"\]', "", path)
    yield re.sub(r"/@[^/]+$", "", path)


def _ancestors(path):
    path = _norm_query(path)
    parts = path.split("/")
    for index in range(1, len(parts)):
        yield "/".join(parts[:index])


def _matches_pattern(pattern, path, name=None):
    pattern = _norm_query(pattern)
    if not pattern:
        return False
    for candidate in _path_candidates(path, name=name):
        if _glob_match(candidate, pattern):
            return True
    for variant in _path_variants(path):
        if _glob_match(variant, pattern):
            return True
        for ancestor in _ancestors(variant):
            if _glob_match(ancestor, pattern):
                return True
    return False


def _matches_any(patterns, path, name=None):
    if not patterns:
        return False
    return any(_matches_pattern(pattern, path, name=name) for pattern in patterns)


def _normalize_patterns(value):
    if value is None:
        return None
    if isinstance(value, str):
        value = (value,)
    ret = []
    for pattern in value:
        if pattern is None:
            continue
        normalized = _norm_query(pattern)
        if normalized:
            ret.append(normalized)
    return tuple(sorted(set(ret), key=lambda item: item.casefold()))


class RecordVisibility(object):
    """The records that a scope exposes.

    Record numbers are inclusive.  Time bounds are inclusive and evaluated
    against the record timestamp.  A custom predicate may be supplied for
    callers that need a different policy; it is represented by name in the
    signed scope metadata.
    """

    def __init__(self, start=None, end=None, start_time=None, end_time=None, predicate=None):
        if start is not None:
            start = int(start)
        if end is not None:
            end = int(end)
        if start is not None and end is not None and start > end:
            raise InvalidScope("record range start is after end")
        self._start = start
        self._end = end
        self._start_time = _as_datetime(start_time)
        self._end_time = _as_datetime(end_time)
        if self._start_time is not None and self._end_time is not None and self._start_time > self._end_time:
            raise InvalidScope("record time range start is after end")
        if predicate is not None and not callable(predicate):
            raise InvalidScope("predicate must be callable")
        self._predicate = predicate

    @property
    def start(self):
        return self._start

    @property
    def end(self):
        return self._end

    @property
    def start_time(self):
        return self._start_time

    @property
    def end_time(self):
        return self._end_time

    @property
    def predicate(self):
        return self._predicate

    @property
    def record_range(self):
        return (self._start, self._end)

    def contains(self, record_num, timestamp=None):
        if self._start is not None and record_num < self._start:
            return False
        if self._end is not None and record_num > self._end:
            return False
        if self._start_time is not None or self._end_time is not None:
            if timestamp is None:
                return False
            moment = _as_datetime(timestamp)
            if self._start_time is not None and moment < self._start_time:
                return False
            if self._end_time is not None and moment > self._end_time:
                return False
        if self._predicate is not None:
            try:
                return bool(self._predicate(record_num, timestamp))
            except TypeError:
                return bool(self._predicate(record_num))
        return True

    def to_dict(self):
        ret = {
            "start": self._start,
            "end": self._end,
            "start_time": _iso(self._start_time),
            "end_time": _iso(self._end_time),
        }
        if self._predicate is not None:
            ret["predicate"] = getattr(self._predicate, "__name__", repr(self._predicate))
        return ret

    @classmethod
    def from_dict(cls, value):
        if value is None:
            return cls()
        if isinstance(value, RecordVisibility):
            return value
        if isinstance(value, int):
            return cls(start=value)
        if isinstance(value, (tuple, list)) and len(value) == 2 and not isinstance(value[0], (str, dict)):
            return cls(start=value[0], end=value[1])
        value = dict(value)
        return cls(
            start=value.get("start", value.get("record_start")),
            end=value.get("end", value.get("record_end")),
            start_time=value.get("start_time", value.get("time_start")),
            end_time=value.get("end_time", value.get("time_end")),
        )

    def __repr__(self):
        return "RecordVisibility(start={!r}, end={!r}, start_time={!r}, end_time={!r})".format(
            self._start, self._end, self._start_time, self._end_time
        )


class FieldVisibility(object):
    """Visibility policy for XML elements and attributes.

    ``allow`` is an optional allow-list.  ``None`` means all fields are
    allowed.  ``deny`` always wins, and ``redact`` keeps the field but replaces
    its value with ``placeholder``.

    Patterns may be full paths (``System/EventID``), selector paths
    (``EventData/Data[@Name="SubjectUserName"]``), attribute paths
    (``System/Provider/@Name``), local names (``EventID``), or globs
    (``EventData/*``).
    """

    def __init__(self, allow=None, deny=None, redact=None, placeholder="[REDACTED]", **kwargs):
        if allow is None:
            allow = kwargs.pop("fields", None)
        if allow is None:
            allow = kwargs.pop("field_allow", None)
        if deny is None:
            deny = kwargs.pop("exclude_fields", None)
        if deny is None:
            deny = kwargs.pop("field_deny", None)
        if redact is None:
            redact = kwargs.pop("redact_fields", None)
        if kwargs:
            raise TypeError("unexpected FieldVisibility arguments: {}".format(", ".join(sorted(kwargs))))
        self._allow = _normalize_patterns(allow)
        self._deny = _normalize_patterns(deny) or ()
        self._redact = _normalize_patterns(redact) or ()
        self._placeholder = str(placeholder)

    @property
    def allow(self):
        return self._allow

    @property
    def deny(self):
        return self._deny

    @property
    def redact(self):
        return self._redact

    @property
    def placeholder(self):
        return self._placeholder

    @property
    def is_all_visible(self):
        return self._allow is None and not self._deny and not self._redact

    def action(self, path, name=None):
        """Return ``allow``, ``redact``, or ``deny`` for a field."""

        if _matches_any(self._deny, path, name=name):
            return "deny"
        if _matches_any(self._redact, path, name=name):
            return "redact"
        if self._allow is None:
            return "allow"
        if _matches_any(self._allow, path, name=name):
            return "allow"
        return "deny"

    def is_explicit_deny(self, path, name=None):
        return _matches_any(self._deny, path, name=name)

    def is_visible(self, path, name=None):
        return self.action(path, name=name) != "deny"

    visible = is_visible

    def to_dict(self):
        return {
            "allow": None if self._allow is None else list(self._allow),
            "deny": list(self._deny),
            "redact": list(self._redact),
            "placeholder": self._placeholder,
        }

    @classmethod
    def from_dict(cls, value):
        if value is None:
            return cls()
        if isinstance(value, FieldVisibility):
            return value
        if isinstance(value, (list, tuple, set)):
            return cls(allow=value)
        value = dict(value)
        return cls(
            allow=value.get("allow"),
            deny=value.get("deny"),
            redact=value.get("redact"),
            placeholder=value.get("placeholder", "[REDACTED]"),
        )

    def __repr__(self):
        return "FieldVisibility(allow={!r}, deny={!r}, redact={!r})".format(self._allow, self._deny, self._redact)


_AGGREGATE_ALIASES = {
    "by": "count_by",
    "countby": "count_by",
    "group": "count_by",
    "group_by": "count_by",
    "groupby": "count_by",
}


def _norm_aggregate(name):
    key = str(name).strip().lower().replace("-", "_").replace(" ", "_")
    return _AGGREGATE_ALIASES.get(key, key)


class AggregateVisibility(object):
    """Visibility policy for aggregate queries.

    ``min_group_size`` suppresses small groups in a ``count_by`` result.  This
    is useful when a group with one member would identify a specific record.
    """

    def __init__(self, allow=None, deny=None, min_group_size=1, max_groups=None, **kwargs):
        if allow is None:
            allow = kwargs.pop("aggregates", None)
        if allow is None:
            allow = kwargs.pop("aggregate_allow", None)
        if deny is None:
            deny = kwargs.pop("exclude_aggregates", None)
        if deny is None:
            deny = kwargs.pop("aggregate_deny", None)
        if kwargs:
            raise TypeError("unexpected AggregateVisibility arguments: {}".format(", ".join(sorted(kwargs))))

        def normalize(value):
            if value is None:
                return None
            if isinstance(value, str):
                value = (value,)
            return tuple(sorted({_norm_aggregate(item) for item in value}))

        self._allow = normalize(allow)
        self._deny = normalize(deny) or ()
        self._min_group_size = int(min_group_size)
        if self._min_group_size < 1:
            raise InvalidScope("min_group_size must be at least 1")
        self._max_groups = None if max_groups is None else int(max_groups)
        if self._max_groups is not None and self._max_groups < 1:
            raise InvalidScope("max_groups must be at least 1")

    @property
    def allow(self):
        return self._allow

    @property
    def deny(self):
        return self._deny

    @property
    def min_group_size(self):
        return self._min_group_size

    @property
    def max_groups(self):
        return self._max_groups

    def is_visible(self, name):
        name = _norm_aggregate(name)
        if "*" in self._deny or name in self._deny:
            return False
        if self._allow is None:
            return True
        return "*" in self._allow or name in self._allow

    def check(self, name):
        if not self.is_visible(name):
            raise AggregateNotVisible("aggregate is not visible: {}".format(name))

    allows = is_visible

    def to_dict(self):
        return {
            "allow": None if self._allow is None else list(self._allow),
            "deny": list(self._deny),
            "min_group_size": self._min_group_size,
            "max_groups": self._max_groups,
        }

    @classmethod
    def from_dict(cls, value):
        if value is None:
            return cls()
        if isinstance(value, AggregateVisibility):
            return value
        if isinstance(value, (list, tuple, set)):
            return cls(allow=value)
        value = dict(value)
        return cls(
            allow=value.get("allow"),
            deny=value.get("deny"),
            min_group_size=value.get("min_group_size", 1),
            max_groups=value.get("max_groups"),
        )

    def __repr__(self):
        return "AggregateVisibility(allow={!r}, deny={!r}, min_group_size={!r})".format(
            self._allow, self._deny, self._min_group_size
        )


class Visibility(object):
    """Container for the three independent visibility policies."""

    def __init__(self, records=None, fields=None, aggregates=None, **kwargs):
        if records is None:
            records = kwargs.pop("record", None)
        if fields is None:
            fields = kwargs.pop("field", None)
        if aggregates is None:
            aggregates = kwargs.pop("aggregate", None)
        if kwargs:
            raise TypeError("unexpected Visibility arguments: {}".format(", ".join(sorted(kwargs))))
        self.records = RecordVisibility.from_dict(records)
        self.fields = FieldVisibility.from_dict(fields)
        self.aggregates = AggregateVisibility.from_dict(aggregates)

    def to_dict(self):
        return {
            "records": self.records.to_dict(),
            "fields": self.fields.to_dict(),
            "aggregates": self.aggregates.to_dict(),
        }

    @classmethod
    def from_dict(cls, value):
        if value is None:
            return cls()
        if isinstance(value, Visibility):
            return value
        value = dict(value)
        return cls(
            records=value.get("records", value.get("record")),
            fields=value.get("fields", value.get("field")),
            aggregates=value.get("aggregates", value.get("aggregate")),
        )


class Scope(object):
    """An immutable description of what a view may expose."""

    def __init__(
        self,
        record_start=None,
        record_end=None,
        *,
        start=None,
        end=None,
        start_time=None,
        end_time=None,
        predicate=None,
        records=None,
        record_visibility=None,
        field_visibility=None,
        aggregate_visibility=None,
        visibility=None,
        fields=None,
        field_allow=None,
        exclude_fields=None,
        field_deny=None,
        redact_fields=None,
        placeholder="[REDACTED]",
        aggregates=None,
        aggregate_allow=None,
        exclude_aggregates=None,
        aggregate_deny=None,
        min_group_size=1,
        max_groups=None,
        role=None,
        label=None,
        source_digest=None,
        archive_id=None,
        signature=None,
        **kwargs,
    ):
        record_policy = kwargs.pop("record_policy", None)
        record_range = kwargs.pop("record_range", None)
        field_policy = kwargs.pop("field_policy", None)
        aggregate_policy = kwargs.pop("aggregate_policy", None)
        if kwargs:
            raise TypeError("unexpected Scope arguments: {}".format(", ".join(sorted(kwargs))))
        if record_visibility is None:
            if record_policy is not None:
                record_visibility = record_policy
            elif record_range is not None:
                record_visibility = RecordVisibility(start=record_range[0], end=record_range[1])
        if field_visibility is None and field_policy is not None:
            field_visibility = (
                field_policy if isinstance(field_policy, FieldVisibility) else FieldVisibility.from_dict(field_policy)
            )
        if aggregate_visibility is None and aggregate_policy is not None:
            aggregate_visibility = (
                aggregate_policy
                if isinstance(aggregate_policy, AggregateVisibility)
                else AggregateVisibility.from_dict(aggregate_policy)
            )
        if start is not None:
            if record_start is not None and record_start != start:
                raise InvalidScope("conflicting record start values")
            record_start = start
        if end is not None:
            if record_end is not None and record_end != end:
                raise InvalidScope("conflicting record end values")
            record_end = end

        if records is not None:
            if record_visibility is not None:
                raise InvalidScope("specify records or record_visibility, not both")
            record_visibility = records
        if isinstance(fields, FieldVisibility):
            if field_visibility is not None:
                raise InvalidScope("specify fields or field_visibility, not both")
            field_visibility = fields
            fields = None
        elif isinstance(fields, dict) and any(key in fields for key in ("allow", "deny", "redact", "placeholder")):
            field_visibility = FieldVisibility.from_dict(fields)
            fields = None
        if isinstance(aggregates, AggregateVisibility):
            if aggregate_visibility is not None:
                raise InvalidScope("specify aggregates or aggregate_visibility, not both")
            aggregate_visibility = aggregates
            aggregates = None
        elif isinstance(aggregates, dict) and any(
            key in aggregates for key in ("allow", "deny", "min_group_size", "max_groups")
        ):
            aggregate_visibility = AggregateVisibility.from_dict(aggregates)
            aggregates = None

        if visibility is not None:
            visibility = visibility if isinstance(visibility, Visibility) else Visibility.from_dict(visibility)
            if record_visibility is None:
                record_visibility = visibility.records
            if field_visibility is None and not any(
                value is not None for value in (fields, field_allow, exclude_fields, field_deny, redact_fields)
            ):
                field_visibility = visibility.fields
            if aggregate_visibility is None and not any(
                value is not None for value in (aggregates, aggregate_allow, exclude_aggregates, aggregate_deny)
            ):
                aggregate_visibility = visibility.aggregates

        if record_visibility is None:
            record_visibility = RecordVisibility(
                start=record_start,
                end=record_end,
                start_time=start_time,
                end_time=end_time,
                predicate=predicate,
            )
        else:
            record_visibility = RecordVisibility.from_dict(record_visibility)
            if any(value is not None for value in (record_start, record_end, start_time, end_time, predicate)):
                current = record_visibility.to_dict()
                record_visibility = RecordVisibility(
                    start=record_start if record_start is not None else current["start"],
                    end=record_end if record_end is not None else current["end"],
                    start_time=start_time if start_time is not None else current["start_time"],
                    end_time=end_time if end_time is not None else current["end_time"],
                    predicate=predicate if predicate is not None else record_visibility.predicate,
                )

        if field_visibility is None:
            field_visibility = FieldVisibility(
                allow=fields if fields is not None else field_allow,
                deny=exclude_fields if exclude_fields is not None else field_deny,
                redact=redact_fields,
                placeholder=placeholder,
            )
        else:
            field_visibility = FieldVisibility.from_dict(field_visibility)

        if aggregate_visibility is None:
            aggregate_visibility = AggregateVisibility(
                allow=aggregates if aggregates is not None else aggregate_allow,
                deny=exclude_aggregates if exclude_aggregates is not None else aggregate_deny,
                min_group_size=min_group_size,
                max_groups=max_groups,
            )
        else:
            aggregate_visibility = AggregateVisibility.from_dict(aggregate_visibility)

        self._record_visibility = record_visibility
        self._field_visibility = field_visibility
        self._aggregate_visibility = aggregate_visibility
        self._role = normalize_role(role)
        self._label = label
        self._source_digest = source_digest
        self._archive_id = archive_id
        self._signature = signature

    @property
    def record_visibility(self):
        return self._record_visibility

    records = record_visibility
    record_policy = record_visibility

    @property
    def field_visibility(self):
        return self._field_visibility

    field_policy = field_visibility

    @property
    def aggregate_visibility(self):
        return self._aggregate_visibility

    aggregate_policy = aggregate_visibility

    @property
    def visibility(self):
        return Visibility(
            records=self._record_visibility,
            fields=self._field_visibility,
            aggregates=self._aggregate_visibility,
        )

    @property
    def record_start(self):
        return self._record_visibility.start

    @property
    def record_end(self):
        return self._record_visibility.end

    @property
    def start(self):
        return self.record_start

    @property
    def end(self):
        return self.record_end

    @property
    def record_range(self):
        return self._record_visibility.record_range

    @property
    def ack_range(self):
        return self.record_range

    @property
    def acknowledged_range(self):
        return self.record_range

    @property
    def fields(self):
        return self._field_visibility.allow

    @property
    def field_allow(self):
        return self._field_visibility.allow

    @property
    def field_deny(self):
        return self._field_visibility.deny

    @property
    def exclude_fields(self):
        return self._field_visibility.deny

    @property
    def redact_fields(self):
        return self._field_visibility.redact

    @property
    def aggregates(self):
        return self._aggregate_visibility.allow

    @property
    def aggregate_allow(self):
        return self._aggregate_visibility.allow

    @property
    def aggregate_deny(self):
        return self._aggregate_visibility.deny

    @property
    def exclude_aggregates(self):
        return self._aggregate_visibility.deny

    @property
    def start_time(self):
        return self._record_visibility.start_time

    @property
    def end_time(self):
        return self._record_visibility.end_time

    @property
    def predicate(self):
        return self._record_visibility.predicate

    @property
    def min_group_size(self):
        return self._aggregate_visibility.min_group_size

    @property
    def max_groups(self):
        return self._aggregate_visibility.max_groups

    @property
    def placeholder(self):
        return self._field_visibility.placeholder

    @property
    def role(self):
        return self._role

    @property
    def label(self):
        return self._label

    @property
    def source_digest(self):
        return self._source_digest

    @property
    def archive_id(self):
        return self._archive_id

    @property
    def signature(self):
        return self._signature

    @property
    def is_signed(self):
        return bool(self._signature)

    @property
    def scope_id(self):
        return hashlib.sha256(_scope_payload(self)).hexdigest()

    @property
    def id(self):
        return self.scope_id

    def contains(self, record_num, timestamp=None):
        return self._record_visibility.contains(record_num, timestamp)

    allows = contains

    def _replace(self, **changes):
        return Scope(
            record_visibility=changes.pop("record_visibility", self._record_visibility),
            field_visibility=changes.pop("field_visibility", self._field_visibility),
            aggregate_visibility=changes.pop("aggregate_visibility", self._aggregate_visibility),
            role=changes.pop("role", self._role),
            label=changes.pop("label", self._label),
            source_digest=changes.pop("source_digest", self._source_digest),
            archive_id=changes.pop("archive_id", self._archive_id),
            signature=changes.pop("signature", self._signature),
        )

    def for_role(self, role):
        """Return an unsigned copy of this scope for the given role."""

        return self._replace(role=normalize_role(role), signature=None)

    def sign(self, secret):
        """Return a signed copy of this scope."""

        scope = self
        if hasattr(secret, "_signing_key"):
            scope = scope._replace(
                archive_id=secret.archive_id,
                source_digest=secret.source_digest,
                signature=None,
            )
            secret = secret._signing_key
        elif isinstance(secret, str):
            secret = secret.encode("utf-8")
        return _sign_scope(scope._replace(signature=None), secret)

    def verify(self, secret):
        """Verify this scope against a signing key or scoped archive."""

        if secret is None:
            return False
        if hasattr(secret, "_signing_key"):
            if self.archive_id != secret.archive_id:
                return False
            secret = secret._signing_key
        elif isinstance(secret, str):
            secret = secret.encode("utf-8")
        return _verify_scope(self, secret)

    def with_changes(self, **kwargs):
        """Return a new unsigned scope with selected policy changes."""

        visibility = kwargs.pop("visibility", None)
        if visibility is not None:
            visibility = visibility if isinstance(visibility, Visibility) else Visibility.from_dict(visibility)
            record_visibility = kwargs.pop("record_visibility", visibility.records)
            field_visibility = kwargs.pop("field_visibility", visibility.fields)
            aggregate_visibility = kwargs.pop("aggregate_visibility", visibility.aggregates)
        else:
            record_visibility = kwargs.pop("record_visibility", self._record_visibility)
            field_visibility = kwargs.pop("field_visibility", self._field_visibility)
            aggregate_visibility = kwargs.pop("aggregate_visibility", self._aggregate_visibility)

        record_keys = {"record_start", "record_end", "start", "end", "start_time", "end_time", "predicate"}
        if record_keys.intersection(kwargs):
            record_visibility = RecordVisibility(
                start=kwargs.pop("record_start", kwargs.pop("start", self.record_start)),
                end=kwargs.pop("record_end", kwargs.pop("end", self.record_end)),
                start_time=kwargs.pop("start_time", self._record_visibility.start_time),
                end_time=kwargs.pop("end_time", self._record_visibility.end_time),
                predicate=kwargs.pop("predicate", self._record_visibility.predicate),
            )

        field_keys = {
            "fields",
            "field_allow",
            "exclude_fields",
            "field_deny",
            "redact_fields",
            "placeholder",
        }
        if field_keys.intersection(kwargs):
            field_visibility = FieldVisibility(
                allow=kwargs.pop("fields", kwargs.pop("field_allow", self.fields)),
                deny=kwargs.pop("exclude_fields", kwargs.pop("field_deny", self._field_visibility.deny)),
                redact=kwargs.pop("redact_fields", self._field_visibility.redact),
                placeholder=kwargs.pop("placeholder", self._field_visibility.placeholder),
            )

        aggregate_keys = {
            "aggregates",
            "aggregate_allow",
            "exclude_aggregates",
            "aggregate_deny",
            "min_group_size",
            "max_groups",
        }
        if aggregate_keys.intersection(kwargs):
            aggregate_visibility = AggregateVisibility(
                allow=kwargs.pop("aggregates", kwargs.pop("aggregate_allow", self.aggregates)),
                deny=kwargs.pop("exclude_aggregates", kwargs.pop("aggregate_deny", self._aggregate_visibility.deny)),
                min_group_size=kwargs.pop("min_group_size", self._aggregate_visibility.min_group_size),
                max_groups=kwargs.pop("max_groups", self._aggregate_visibility.max_groups),
            )

        role = kwargs.pop("role", self.role)
        label = kwargs.pop("label", self.label)
        if kwargs:
            raise TypeError("unexpected Scope changes: {}".format(", ".join(sorted(kwargs))))
        return Scope(
            record_visibility=record_visibility,
            field_visibility=field_visibility,
            aggregate_visibility=aggregate_visibility,
            role=role,
            label=label,
        )

    def narrowed(self, start=None, end=None, role=None):
        new_start = self.record_start
        new_end = self.record_end
        if start is not None:
            new_start = start if new_start is None else max(int(start), new_start)
        if end is not None:
            new_end = end if new_end is None else min(int(end), new_end)
        return self.with_changes(
            start=new_start,
            end=new_end,
            role=self.role if role is None else role,
        )

    def to_dict(self):
        return {
            "scope_id": self.scope_id,
            "archive_id": self._archive_id,
            "source_digest": self._source_digest,
            "role": self._role,
            "label": self._label,
            "record_start": self.record_start,
            "record_end": self.record_end,
            "start_time": _iso(self.start_time),
            "end_time": _iso(self.end_time),
            "records": self._record_visibility.to_dict(),
            "field_allow": self._field_visibility.allow,
            "exclude_fields": self._field_visibility.deny,
            "redact_fields": self._field_visibility.redact,
            "fields": self._field_visibility.to_dict(),
            "aggregate_allow": self._aggregate_visibility.allow,
            "exclude_aggregates": self._aggregate_visibility.deny,
            "min_group_size": self._aggregate_visibility.min_group_size,
            "aggregates": self._aggregate_visibility.to_dict(),
            "signature": self._signature,
        }

    def to_json(self):
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, default=str)

    def public_dict(self):
        return {
            "scope_id": self.scope_id,
            "role": self._role,
            "label": self._label,
        }

    @property
    def receipt(self):
        return self.public_dict()

    @property
    def public(self):
        return self.public_dict()

    @classmethod
    def from_visibility(cls, visibility, **kwargs):
        visibility = visibility if isinstance(visibility, Visibility) else Visibility.from_dict(visibility)
        return cls(
            record_visibility=visibility.records,
            field_visibility=visibility.fields,
            aggregate_visibility=visibility.aggregates,
            **kwargs,
        )

    @classmethod
    def from_dict(cls, value):
        if value is None:
            return cls()
        if isinstance(value, Scope):
            return value
        if isinstance(value, (str, bytes, bytearray)):
            value = json.loads(value)
        if isinstance(value, int):
            return cls(start=value)
        if isinstance(value, (tuple, list)) and len(value) == 2:
            return cls(start=value[0], end=value[1])
        value = dict(value)
        records = value.get("records", value.get("record_visibility"))
        if records is None and any(
            key in value for key in ("record_start", "record_end", "start", "end", "start_time", "end_time")
        ):
            records = RecordVisibility(
                start=value.get("record_start", value.get("start")),
                end=value.get("record_end", value.get("end")),
                start_time=value.get("start_time"),
                end_time=value.get("end_time"),
            )
        fields = value.get("fields", value.get("field_visibility"))
        if fields is None and any(
            key in value for key in ("field_allow", "exclude_fields", "field_deny", "redact_fields")
        ):
            fields = FieldVisibility(
                allow=value.get("field_allow"),
                deny=value.get("exclude_fields", value.get("field_deny")),
                redact=value.get("redact_fields"),
                placeholder=value.get("placeholder", "[REDACTED]"),
            )
        aggregates = value.get("aggregates", value.get("aggregate_visibility"))
        if aggregates is None and any(
            key in value for key in ("aggregate_allow", "exclude_aggregates", "aggregate_deny", "min_group_size")
        ):
            aggregates = AggregateVisibility(
                allow=value.get("aggregate_allow"),
                deny=value.get("exclude_aggregates", value.get("aggregate_deny")),
                min_group_size=value.get("min_group_size", 1),
                max_groups=value.get("max_groups"),
            )
        return cls(
            record_visibility=RecordVisibility.from_dict(records),
            field_visibility=FieldVisibility.from_dict(fields),
            aggregate_visibility=AggregateVisibility.from_dict(aggregates),
            role=value.get("role"),
            label=value.get("label"),
            source_digest=value.get("source_digest"),
            archive_id=value.get("archive_id"),
            signature=value.get("signature"),
        )

    def __repr__(self):
        return "Scope(range={!r}, role={!r}, scope_id={!r})".format(self.record_range, self.role, self.scope_id[:12])

    def __eq__(self, other):
        return isinstance(other, Scope) and self.scope_id == other.scope_id

    def __hash__(self):
        return hash(self.scope_id)


def _scope_payload(scope):
    return _canonical(
        {
            "v": 1,
            "archive_id": scope.archive_id,
            "source_digest": scope.source_digest,
            "role": scope.role,
            "label": scope.label,
            "records": scope.record_visibility.to_dict(),
            "fields": scope.field_visibility.to_dict(),
            "aggregates": scope.aggregate_visibility.to_dict(),
        }
    )


def _sign_scope(scope, secret):
    if not scope.is_signed:
        signature = hmac.new(secret, b"scope.v1\0" + _scope_payload(scope), hashlib.sha256).hexdigest()
        scope = scope._replace(signature=signature)
    return scope


def _verify_scope(scope, secret):
    if not scope.is_signed:
        return False
    expected = hmac.new(secret, b"scope.v1\0" + _scope_payload(scope), hashlib.sha256).hexdigest()
    return hmac.compare_digest(scope.signature, expected)


def _child_segment(tag, name, index, duplicate):
    if name is not None:
        return "{}[@Name={}]".format(tag, json.dumps(name, ensure_ascii=False))
    if duplicate:
        return "{}[{}]".format(tag, index)
    return tag


def _join_path(parent, segment):
    if parent:
        return "{}/{}".format(parent, segment)
    return segment


class EventField(object):
    """One visible field extracted from a record's XML."""

    __slots__ = ("path", "name", "value", "kind", "attributes", "redacted", "parent_path")

    def __init__(self, path, name, value, kind="element", attributes=None, redacted=False, parent_path=None):
        self.path = path
        self.name = name
        self.value = value
        self.kind = kind
        self.attributes = tuple(attributes or ())
        self.redacted = bool(redacted)
        self.parent_path = parent_path if parent_path is not None else path.rsplit("/", 1)[0]

    @property
    def text(self):
        return self.value

    @property
    def key(self):
        return self.path

    @property
    def visible(self):
        return True

    def to_dict(self):
        return {
            "path": self.path,
            "name": self.name,
            "value": self.value,
            "kind": self.kind,
            "redacted": self.redacted,
        }

    def __getitem__(self, key):
        return self.to_dict()[key]

    def get(self, key, default=None):
        return self.to_dict().get(key, default)

    def __repr__(self):
        return "EventField(path={!r}, value={!r})".format(self.path, self.value)

    def __str__(self):
        return str(self.value)


def _extract_fields(root, field_visibility=None):
    fields = []

    def walk(parent, parent_path):
        children = list(parent)
        counts = Counter(_local_name(child.tag) for child in children)
        positions = Counter()
        for child in children:
            tag = _local_name(child.tag)
            positions[tag] += 1
            name = child.attrib.get("Name")
            if name is not None and field_visibility is not None:
                element_path = _join_path(parent_path, tag)
                attribute_path = element_path + "/@Name"
                selector_path = element_path + "[@Name={}]".format(json.dumps(name, ensure_ascii=False))
                selector_attribute_path = selector_path + "/@Name"
                if field_visibility.is_explicit_deny(attribute_path, name="Name") or field_visibility.is_explicit_deny(
                    selector_attribute_path, name="Name"
                ):
                    name = None
                else:
                    name_action = field_visibility.action(attribute_path, name="Name")
                    if name_action != "allow":
                        selector_action = field_visibility.action(selector_path, name=tag)
                        if selector_action == "allow":
                            name_action = "allow"
                        elif selector_action == "redact":
                            name_action = "redact"
                    if name_action == "deny":
                        name = None
                    elif name_action == "redact":
                        name = field_visibility.placeholder
            path = _join_path(
                parent_path,
                _child_segment(
                    tag,
                    name,
                    positions[tag],
                    counts[tag] > 1 and "Name" not in child.attrib,
                ),
            )
            attrs = tuple(child.attrib.items())
            for key, value in attrs:
                fields.append(
                    EventField(
                        path + "/@" + key,
                        key,
                        value,
                        kind="attribute",
                        attributes=attrs,
                        parent_path=path,
                    )
                )
            text = (child.text or "").strip()
            if text:
                fields.append(EventField(path, tag, text, kind="element", attributes=attrs, parent_path=path))
            walk(child, path)

    walk(root, "")
    return fields


def _field_matches_query(field, query):
    query = _norm_query(query)
    if not query:
        return False
    for candidate in _path_candidates(field.path, name=field.name):
        if _glob_match(candidate, query):
            return True
    return False


def _field_match_score(field, query):
    """Rank field matches so a local-name query prefers the element itself."""

    query = _norm_query(query)
    path = _norm_query(field.path)
    if field.kind == "attribute" and path == query:
        return 0
    if field.kind == "element" and path == query:
        return 0
    if field.name.casefold() == query.casefold():
        return 0 if field.kind == "element" else 1
    if field.kind == "element" and _norm_query(re.sub(r"\[@Name=\"[^\"]*\"\]", "", path)) == query:
        return 1
    if field.kind == "element":
        return 2
    return 4


def _redact_xml(root, field_visibility):
    """Return a serialized copy of ``root`` with hidden fields removed."""

    def prune(elem, path, is_root=False):
        tag = _local_name(elem.tag)
        if not is_root and field_visibility.is_explicit_deny(path, name=tag):
            return False

        original_had_content = bool(elem.attrib) or bool(list(elem)) or bool((elem.text or "").strip())

        for key in list(elem.attrib):
            action = field_visibility.action(path + "/@" + key, name=key)
            if action == "deny":
                del elem.attrib[key]
            elif action == "redact":
                elem.attrib[key] = field_visibility.placeholder

        if elem.text and elem.text.strip():
            action = field_visibility.action(path, name=tag)
            if action == "deny":
                elem.text = None
            elif action == "redact":
                elem.text = field_visibility.placeholder

        children = list(elem)
        counts = Counter(_local_name(child.tag) for child in children)
        positions = Counter()
        for child in children:
            child_tag = _local_name(child.tag)
            positions[child_tag] += 1
            child_segment = _child_segment(
                child_tag,
                child.attrib.get("Name"),
                positions[child_tag],
                counts[child_tag] > 1 and "Name" not in child.attrib,
            )
            if not prune(child, _join_path(path, child_segment)):
                elem.remove(child)

        if is_root:
            return True
        now_has_content = bool(elem.attrib) or bool(list(elem)) or bool((elem.text or "").strip())
        return not original_had_content or now_has_content

    try:
        ET.register_namespace("", "http://schemas.microsoft.com/win/2004/08/events/event")
    except ValueError:
        pass
    except AttributeError:
        pass
    prune(root, "", is_root=True)
    return ET.tostring(root, encoding="unicode", short_empty_elements=True)


class FieldValue(str):
    """A string value that also retains its field metadata."""

    def __new__(cls, field):
        obj = str.__new__(cls, field.value)
        obj.field = field
        return obj

    @property
    def value(self):
        return str(self)

    @property
    def path(self):
        return self.field.path

    @property
    def name(self):
        return self.field.name

    @property
    def redacted(self):
        return self.field.redacted

    def __call__(self):
        return str(self)


class FieldCollection(list):
    """A list of fields that also supports lookup by path or local name."""

    def _best(self, name):
        query = _norm_query(name)
        matches = []
        for order, field in enumerate(self):
            if _field_matches_query(field, name):
                matches.append((_field_match_score(field, query), order, field))
        if not matches:
            return None
        matches.sort(key=lambda item: (item[0], item[1]))
        return matches[0][2]

    def get(self, name, default=None):
        field = self._best(name)
        return default if field is None else FieldValue(field)

    def get_field(self, name, default=None):
        field = self._best(name)
        return default if field is None else field

    def __getitem__(self, key):
        if isinstance(key, str):
            value = self.get(key)
            if value is None:
                raise KeyError(key)
            return value
        return super(FieldCollection, self).__getitem__(key)

    def keys(self):
        return [field.path for field in self]

    def items(self):
        for field in self:
            yield field.path, field.value

    def values(self):
        return [FieldValue(field) for field in self]

    def to_dict(self):
        ret = {}
        for field in self:
            ret.setdefault(field.path, []).append(field.value)
        return {key: (items[0] if len(items) == 1 else items) for key, items in ret.items()}

    def __eq__(self, other):
        if isinstance(other, dict):
            return self.to_dict() == other
        return super(FieldCollection, self).__eq__(other)


class RecordView(object):
    """A record projected through a scope's field policy."""

    def __init__(self, view, record, ordinal):
        self._view = view
        self._record = record
        self.ordinal = ordinal
        self.record_num = _CallableInt(record.record_num())
        try:
            timestamp = record.timestamp()
            self.timestamp = (
                None
                if timestamp is None
                else _CallableDateTime(
                    timestamp.year,
                    timestamp.month,
                    timestamp.day,
                    timestamp.hour,
                    timestamp.minute,
                    timestamp.second,
                    timestamp.microsecond,
                    tzinfo=timestamp.tzinfo,
                    fold=getattr(timestamp, "fold", 0),
                )
            )
        except Exception:
            self.timestamp = None
        self._source_xml = None
        self._all_fields = None
        self._fields = None
        self._redacted_xml = None
        self._digest = None

    @property
    def role(self):
        return self._view.role

    @property
    def scope_id(self):
        return self._view.scope.scope_id

    @property
    def source_digest(self):
        return self._view.source_digest

    def _ensure_fields(self):
        if self._fields is not None:
            return
        field_visibility = self._view.scope.field_visibility
        try:
            self._source_xml = self._record.xml()
            root = ET.fromstring(self._source_xml)
        except Exception:
            if not field_visibility.is_all_visible:
                raise FieldNotVisible("unable to apply field visibility to record {}".format(self.record_num))
            self._all_fields = []
            self._fields = ()
            self._redacted_xml = self._source_xml or ""
            return

        all_fields = _extract_fields(root, field_visibility)
        visible = []
        for field in all_fields:
            action = field_visibility.action(field.path, name=field.name)
            if action == "deny":
                continue
            if action == "redact":
                field = EventField(
                    field.path,
                    field.name,
                    field_visibility.placeholder,
                    kind=field.kind,
                    attributes=field.attributes,
                    redacted=True,
                    parent_path=field.parent_path,
                )
            visible.append(field)
        self._all_fields = all_fields
        self._fields = tuple(visible)
        if field_visibility.is_all_visible:
            self._redacted_xml = self._source_xml
        else:
            self._redacted_xml = _redact_xml(root, field_visibility)

    @property
    def fields(self):
        self._ensure_fields()
        return FieldCollection(self._fields)

    @property
    def field_list(self):
        return self.fields

    @property
    def visible_fields(self):
        return self.fields

    @property
    def record_number(self):
        return self.record_num

    @property
    def data(self):
        return self.field_dict

    @property
    def metadata(self):
        return {
            "ordinal": self.ordinal,
            "record_num": self.record_num,
            "timestamp": _iso(self.timestamp),
        }

    @property
    def xml(self):
        self._ensure_fields()
        return XmlString(self._redacted_xml or "")

    @property
    def xml_text(self):
        return str(self.xml)

    @property
    def visible(self):
        return True

    def values(self, name):
        """Return the most specific visible values matching a name or path."""

        self._ensure_fields()
        matches = []
        query = _norm_query(name)
        for order, field in enumerate(self._fields):
            if not _field_matches_query(field, name):
                continue
            matches.append((_field_match_score(field, query), order, FieldValue(field)))
        if not matches:
            return []
        best = min(item[0] for item in matches)
        return [value for score, _order, value in matches if score == best]

    def get(self, name, default=None):
        values = self.values(name)
        return values[0] if values else default

    def field(self, name, default=None):
        return self.get(name, default=default)

    def __getitem__(self, name):
        value = self.get(name)
        if value is None:
            raise KeyError(name)
        return value

    @property
    def field_dict(self):
        ret = {}
        for field in self.fields:
            ret.setdefault(field.path, []).append(field.value)
        return {key: (values[0] if len(values) == 1 else values) for key, values in ret.items()}

    def to_dict(self):
        self._ensure_fields()
        return {
            "ordinal": self.ordinal,
            "record_num": self.record_num,
            "timestamp": _iso(self.timestamp),
            "fields": self.field_dict,
            "visible": True,
        }

    def to_json(self):
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)

    @property
    def digest(self):
        if self._digest is None:
            self._ensure_fields()
            payload = {
                "record_num": self.record_num,
                "timestamp": _iso(self.timestamp),
                "fields": [[field.path, field.value, field.kind, field.redacted] for field in self._fields],
            }
            self._digest = hashlib.sha256(_canonical(payload)).hexdigest()
        return self._digest

    @property
    def origin(self):
        """Original-file provenance, visible to investigators only."""

        if self._view.role != ROLE_INVESTIGATOR:
            return None
        try:
            chunk = self._record._chunk
            chunk_offset = chunk._offset
            chunk_first = chunk.file_first_record_number()
            chunk_last = chunk.file_last_record_number()
        except Exception:
            chunk_offset = None
            chunk_first = None
            chunk_last = None
        return {
            "record_num": self.record_num,
            "ordinal": self.ordinal,
            "absolute_offset": self._record._offset,
            "chunk_offset": chunk_offset,
            "record_offset": self._record._offset - chunk_offset if chunk_offset is not None else None,
            "chunk_file_first_record": chunk_first,
            "chunk_file_last_record": chunk_last,
            "source_digest": self._view.source_digest,
        }

    def __repr__(self):
        return "RecordView(ordinal={!r}, record_num={!r}, role={!r})".format(self.ordinal, self.record_num, self.role)


class Snapshot(object):
    """A signed receipt for a page or a full view."""

    def __call__(self):
        return self

    def __init__(self, payload, signature=None):
        self._payload = dict(payload)
        self._signature = signature

    @property
    def payload(self):
        return dict(self._payload)

    @property
    def signature(self):
        return self._signature

    @property
    def count(self):
        return _CallableInt(self._payload.get("count", 0))

    @property
    def total(self):
        return _CallableInt(self._payload.get("total", self._payload.get("count", 0)))

    @property
    def scope_id(self):
        return self._payload.get("scope_id")

    @property
    def archive_id(self):
        return self._payload.get("archive_id")

    @property
    def source_digest(self):
        return self._payload.get("source_digest")

    @property
    def record_start(self):
        return self._payload.get("record_start")

    @property
    def record_end(self):
        return self._payload.get("record_end")

    @property
    def record_range(self):
        return (self.record_start, self.record_end)

    @property
    def first_record_num(self):
        return self._payload.get("first_record_num")

    @property
    def last_record_num(self):
        return self._payload.get("last_record_num")

    @property
    def role(self):
        return self._payload.get("role")

    @property
    def kind(self):
        return self._payload.get("kind")

    @property
    def offset(self):
        return self._payload.get("offset", 0)

    @property
    def records(self):
        return list(self._payload.get("records", ()))

    def __len__(self):
        return len(self._payload.get("records", ()))

    entries = records
    record_count = count
    visible_count = total

    @property
    def content_root(self):
        return self._payload.get("content_root")

    def to_dict(self):
        ret = dict(self._payload)
        ret["signature"] = self._signature
        return ret

    def to_json(self):
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)

    def __getitem__(self, key):
        if key == "signature":
            return self._signature
        return self._payload[key]

    def get(self, key, default=None):
        if key == "signature":
            return self._signature
        return self._payload.get(key, default)

    def keys(self):
        return list(self._payload.keys()) + (["signature"] if self._signature else [])

    def items(self):
        return self.to_dict().items()

    def __contains__(self, key):
        return key in self._payload or (key == "signature" and self._signature is not None)

    @classmethod
    def from_dict(cls, value):
        if value is None:
            raise InvalidScope("snapshot is missing")
        if isinstance(value, Snapshot):
            return value
        if isinstance(value, (str, bytes, bytearray)):
            value = json.loads(value)
        value = dict(value)
        for key in ("receipt", "snapshot"):
            if key in value and isinstance(value[key], dict):
                value = dict(value[key])
                break
        signature = value.pop("signature", None)
        if "payload" in value and isinstance(value["payload"], dict):
            return cls(value["payload"], signature=signature)
        return cls(value, signature=signature)

    def verify(self, archive_or_secret):
        if not self._signature or archive_or_secret is None:
            return False
        if hasattr(archive_or_secret, "archive") and not hasattr(archive_or_secret, "_secret"):
            archive_or_secret = archive_or_secret.archive
        if hasattr(archive_or_secret, "_secret"):
            if self._payload.get("archive_id") != archive_or_secret.archive_id:
                return False
            secret = archive_or_secret._secret
        else:
            secret = archive_or_secret
            if isinstance(secret, str):
                secret = secret.encode("utf-8")
        expected = hmac.new(secret, b"snapshot.v1\0" + _canonical(self._payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(self._signature, expected):
            return False
        records = self._payload.get("records", [])
        content_root = hashlib.sha256(_canonical(records)).hexdigest()
        return hmac.compare_digest(str(self._payload.get("content_root", "")), content_root)

    def __repr__(self):
        return "Snapshot(kind={!r}, count={!r}, scope_id={!r})".format(
            self._payload.get("kind"), self.count, self.scope_id
        )


class Reconciliation(object):
    """Result of comparing an old signed output with a current view."""

    def __init__(
        self,
        valid,
        signature_valid,
        matched=0,
        changed=0,
        not_visible=0,
        old_count=0,
        old_total=0,
        current_count=0,
        old_scope_id=None,
        current_scope_id=None,
        reason=None,
    ):
        self.valid = bool(valid)
        self.signature_valid = bool(signature_valid)
        self.matched = int(matched)
        self.changed = int(changed)
        self.not_visible = int(not_visible)
        self.old_count = int(old_count)
        self.old_total = int(old_total)
        self.current_count = int(current_count)
        self.old_scope_id = old_scope_id
        self.current_scope_id = current_scope_id
        self.reason = reason

    def __bool__(self):
        return self.valid

    __nonzero__ = __bool__

    @property
    def verified(self):
        return self.valid

    def __getitem__(self, key):
        return self.to_dict()[key]

    def get(self, key, default=None):
        return self.to_dict().get(key, default)

    def to_dict(self):
        return {
            "valid": self.valid,
            "signature_valid": self.signature_valid,
            "matched": self.matched,
            "changed": self.changed,
            "not_visible": self.not_visible,
            "old_count": self.old_count,
            "old_total": self.old_total,
            "current_count": self.current_count,
            "old_scope_id": self.old_scope_id,
            "current_scope_id": self.current_scope_id,
            "reason": self.reason,
        }

    def to_json(self):
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)

    def __repr__(self):
        return "Reconciliation(valid={!r}, matched={!r}, changed={!r}, not_visible={!r})".format(
            self.valid, self.matched, self.changed, self.not_visible
        )


class Page(object):
    """One page of visible records plus its signed receipt."""

    def __init__(self, view, records, total, next_cursor=None, snapshot=None, offset=0, cursor=None):
        self._view = view
        self._records = list(records)
        self._total = int(total)
        self._next_cursor = next_cursor
        self._snapshot = snapshot
        self._offset = int(offset)
        self._cursor = cursor

    @property
    def records(self):
        return list(self._records)

    @property
    def count(self):
        return _CallableInt(len(self._records))

    @property
    def total(self):
        return _CallableInt(self._total)

    @property
    def visible_count(self):
        return self.total

    @property
    def offset(self):
        return self._offset

    @property
    def scope_id(self):
        return self._view.scope.scope_id

    @property
    def role(self):
        return self._view.role

    @property
    def record_start(self):
        return self._view.scope.record_start

    @property
    def record_end(self):
        return self._view.scope.record_end

    @property
    def ack_range(self):
        return self._view.scope.ack_range

    @property
    def visible_range(self):
        return self._view.visible_range

    @property
    def ordinal_range(self):
        return self._view.ordinal_range

    @property
    def cursor(self):
        return self._cursor

    @property
    def next_cursor(self):
        return self._next_cursor

    @property
    def has_more(self):
        return self._next_cursor is not None

    @property
    def snapshot(self):
        return self._snapshot

    @property
    def receipt(self):
        return self._snapshot

    def next(self, limit=None):
        if self._next_cursor is None:
            return None
        return self._view.records(cursor=self._next_cursor, limit=limit)

    def verify(self, archive_or_view=None):
        if self._snapshot is None:
            return False
        target = archive_or_view
        if target is None:
            target = self._view._archive
        if isinstance(target, ScopedView):
            target = target._archive
        return self._snapshot.verify(target)

    def to_json(self, include_records=True):
        return json.dumps(self.to_dict(include_records=include_records), ensure_ascii=False, sort_keys=True)

    def to_dict(self, include_records=True):
        ret = {
            "count": int(self.count),
            "total": int(self.total),
            "offset": self._offset,
            "next_cursor": self._next_cursor,
            "scope_id": self._view.scope.scope_id,
            "role": self._view.role,
        }
        if include_records:
            ret["records"] = [record.to_dict() for record in self._records]
        if self._snapshot is not None:
            ret["receipt"] = self._snapshot.to_dict()
        return ret

    def __iter__(self):
        return iter(self._records)

    def __len__(self):
        return len(self._records)

    def __getitem__(self, index):
        return self._records[index]

    def __eq__(self, other):
        if isinstance(other, Page):
            return self._records == other._records
        if isinstance(other, (list, tuple)):
            return self._records == list(other)
        return NotImplemented

    def __repr__(self):
        return "Page(count={!r}, total={!r}, has_more={!r})".format(len(self._records), self._total, self.has_more)


class ScopedArchive(object):
    """An EVTX archive that issues signed scopes and role-bound views."""

    def __init__(self, source, secret=None, open_now=False):
        from .Evtx import Evtx, FileHeader

        self._source = source
        self._Evtx = Evtx
        self._FileHeader = FileHeader
        self._evtx = None
        self._file_header = None
        self._buffer = None
        self._path = None
        self._owned = False
        self._closed = False
        if isinstance(source, (str, os.PathLike)):
            self._path = os.fspath(source)
        elif isinstance(source, (bytes, bytearray, memoryview)):
            head = bytes(source[:8])
            if head.startswith(b"ElfFile"):
                self._buffer = source
            else:
                self._path = os.fspath(source)
        elif hasattr(source, "records"):
            self._evtx = source
            if getattr(source, "_buf", None) is None:
                source.__enter__()
                self._owned = True
        elif hasattr(source, "chunks") and hasattr(source, "_buf"):
            self._file_header = source
        elif hasattr(source, "read"):
            data = source.read()
            if isinstance(data, str):
                data = data.encode("latin-1")
            self._buffer = data
        else:
            self._buffer = source
        self._source_digest_cache = None
        self._secret = None
        self._explicit_secret = secret
        self._archive_id_cache = None
        if open_now:
            self._ensure_open()

    def _ensure_open(self):
        if self._closed:
            raise ScopeError("archive is closed")
        if self._evtx is None:
            if self._path is not None:
                self._evtx = self._Evtx(self._path)
                self._evtx.__enter__()
                self._owned = True
            elif self._file_header is not None:
                self._evtx = self._file_header
            else:
                self._evtx = self._FileHeader(self._buffer, 0x0)
        elif getattr(self._evtx, "_buf", None) is None and hasattr(self._evtx, "__enter__"):
            self._evtx.__enter__()
            self._owned = True
        return self._evtx

    def records(self):
        """Yield records from a path, FileHeader, or mmap-style buffer."""

        evtx = self._ensure_open()
        if hasattr(evtx, "records"):
            for record in evtx.records():
                yield record
            return
        for chunk in evtx.chunks():
            for record in chunk.records():
                yield record

    @property
    def source(self):
        return self._source

    @property
    def closed(self):
        return self._closed

    @property
    def path(self):
        return self._path

    @property
    def source_digest(self):
        if self._source_digest_cache is None:
            digest = hashlib.sha256()
            if self._path is not None:
                with open(self._path, "rb") as handle:
                    while True:
                        block = handle.read(1024 * 1024)
                        if not block:
                            break
                        digest.update(block)
            elif self._buffer is not None:
                digest.update(bytes(self._buffer))
            else:
                evtx = self._ensure_open()
                buf = getattr(evtx, "_buf", None)
                if buf is not None:
                    digest.update(bytes(buf))
                else:
                    raise ScopeError("cannot fingerprint archive without a path or buffer")
            self._source_digest_cache = digest.hexdigest()
        return self._source_digest_cache

    @property
    def archive_id(self):
        if self._archive_id_cache is None:
            self._archive_id_cache = hashlib.sha256(
                b"python-evtx.archive.v1\0" + self.source_digest.encode("ascii")
            ).hexdigest()[:32]
        return self._archive_id_cache

    @property
    def _signing_key(self):
        # A deterministic default makes receipts and cursors portable across
        # ScopedArchive instances opened on the same file.  Production users
        # can supply their own secret to separate trust domains.
        if self._secret is None:
            if self._explicit_secret is not None:
                secret = self._explicit_secret
                if isinstance(secret, str):
                    secret = secret.encode("utf-8")
                self._secret = bytes(secret)
            else:
                self._secret = hashlib.sha256(
                    b"python-evtx.scoped-view.secret.v1\0" + self.source_digest.encode("ascii")
                ).digest()
        return self._secret

    def __enter__(self):
        self._ensure_open()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self._owned and self._evtx is not None:
            try:
                self._evtx.__exit__(None, None, None)
            except Exception:
                pass
        self._evtx = None

    def scope(self, *args, **kwargs):
        scope = kwargs.pop("scope", None)
        if scope is None:
            scope = Scope(*args, **kwargs)
        elif isinstance(scope, dict):
            scope = Scope.from_dict(scope)
        elif not isinstance(scope, Scope):
            raise TypeError("scope must be a Scope or dict")
        return self.bind_scope(scope)

    issue_scope = scope
    new_scope = scope

    def bind_scope(self, scope, role=None):
        if isinstance(scope, dict):
            scope = Scope.from_dict(scope)
        elif isinstance(scope, (tuple, list)):
            scope = Scope(*scope)
        elif isinstance(scope, int):
            scope = Scope(scope)
        if not isinstance(scope, Scope):
            raise TypeError("scope must be a Scope")

        target_role = normalize_role(role) if role is not None else scope.role
        if scope.role is not None and target_role is not None and scope.role != target_role:
            raise ScopeMismatch("scope is bound to role {!r}, not {!r}".format(scope.role, target_role))
        if target_role is None:
            target_role = DEFAULT_ROLE

        if scope.is_signed:
            if scope.archive_id is not None and scope.archive_id != self.archive_id:
                raise InvalidScope("scope was issued by a different archive")
            if not _verify_scope(scope, self._signing_key):
                raise InvalidScope("scope signature is invalid")

        bound = scope._replace(
            archive_id=self.archive_id,
            source_digest=self.source_digest,
            role=target_role,
            signature=None,
        )
        return _sign_scope(bound, self._signing_key)

    sign_scope = bind_scope
    seal_scope = bind_scope

    def browse(self, scope=None, record_end=None, *, role=None, **scope_kwargs):
        if record_end is not None:
            if isinstance(scope, int):
                scope = (scope, record_end)
            elif scope is None:
                scope = Scope(record_end=record_end, **scope_kwargs)
                scope_kwargs = {}
            else:
                raise TypeError("record_end is only valid when scope is a start number or omitted")
        if scope is None:
            scope = Scope(**scope_kwargs)
        elif isinstance(scope, dict):
            scope = Scope.from_dict(scope)
        elif isinstance(scope, (tuple, list)):
            scope = Scope(*scope, **scope_kwargs)
        elif isinstance(scope, int):
            scope = Scope(scope, **scope_kwargs)
        return ScopedView(self, scope, role=role)

    view = browse
    open_view = browse

    def verify_scope(self, scope):
        if isinstance(scope, dict):
            scope = Scope.from_dict(scope)
        return bool(
            isinstance(scope, Scope) and scope.archive_id == self.archive_id and _verify_scope(scope, self._signing_key)
        )

    def verify_snapshot(self, snapshot):
        try:
            if isinstance(snapshot, Page) or (hasattr(snapshot, "snapshot") and not isinstance(snapshot, Snapshot)):
                snapshot = snapshot.snapshot
            return Snapshot.from_dict(snapshot).verify(self)
        except Exception:
            return False

    verify_output = verify_snapshot
    verify = verify_snapshot

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self):
        return "ScopedArchive(path={!r}, archive_id={!r})".format(self._path, self.archive_id)


class _RecordsAccessor(object):
    """Callable/iterable facade so both ``view.records()`` and ``view.records`` work."""

    def __init__(self, view):
        self._view = view

    def __call__(self, cursor=None, limit=None, offset=None):
        return self._view._records(cursor=cursor, limit=limit, offset=offset)

    def __iter__(self):
        return self._view.iter_records()

    def __len__(self):
        return int(self._view.count)

    def __getitem__(self, index):
        return self._view[index]

    def __bool__(self):
        return int(self._view.count) > 0

    def __eq__(self, other):
        if isinstance(other, (list, tuple, Page, _RecordsAccessor)):
            return list(self) == list(other)
        return NotImplemented

    @property
    def count(self):
        return self._view.count

    @property
    def total(self):
        return self._view.count

    def __repr__(self):
        return repr(self._view)


class ScopedView(object):
    """An event browsing view bound to one signed scope and one role."""

    def __init__(self, source, scope=None, record_end=None, *, role=None, secret=None, **scope_kwargs):
        if isinstance(source, ScopedArchive):
            self._archive = source
            self._owns_archive = False
        else:
            self._archive = ScopedArchive(source, secret=secret)
            self._owns_archive = True

        if record_end is not None:
            if isinstance(scope, int):
                scope = (scope, record_end)
            elif scope is None:
                scope = Scope(record_end=record_end, **scope_kwargs)
            else:
                raise TypeError("record_end is only valid when scope is a start number or omitted")

        if scope is None:
            scope = Scope(**scope_kwargs)
        elif isinstance(scope, dict):
            scope = Scope.from_dict(scope)
        elif isinstance(scope, (tuple, list)):
            scope = Scope(*scope, **scope_kwargs)
        elif isinstance(scope, int):
            scope = Scope(scope, **scope_kwargs)

        self._scope = self._archive.bind_scope(scope, role=role)
        self._role = self._scope.role
        self._metadata_cache = None
        self._record_view_cache = {}
        self._record_index_cache = None
        self._closed = False

    @property
    def archive(self):
        return self._archive

    @property
    def closed(self):
        return self._closed

    @property
    def scope(self):
        return self._scope

    @property
    def public_scope(self):
        return self._scope.public_dict()

    @property
    def receipt(self):
        return self._scope.public_dict()

    @property
    def role(self):
        return self._role

    @property
    def source_digest(self):
        return self._archive.source_digest

    @property
    def is_investigator(self):
        return self._role == ROLE_INVESTIGATOR

    @property
    def is_operator(self):
        return self._role == ROLE_OPERATOR

    def _ensure_open(self):
        if self._closed:
            raise ScopeError("view is closed")
        return self._archive._ensure_open()

    def _metadata(self):
        if self._closed:
            raise ScopeError("view is closed")
        if self._metadata_cache is not None:
            return self._metadata_cache
        self._ensure_open()
        visibility = self._scope.record_visibility
        ret = []
        for record in self._archive.records():
            record_num = record.record_num()
            try:
                timestamp = record.timestamp()
            except Exception:
                timestamp = None
            if visibility.contains(record_num, timestamp):
                ret.append(
                    {
                        "record": record,
                        "record_num": record_num,
                        "timestamp": timestamp,
                        "ordinal": len(ret) + 1,
                    }
                )
        self._metadata_cache = ret
        self._record_index_cache = {item["record_num"]: item for item in ret}
        return ret

    def _record_view(self, item):
        ordinal = item["ordinal"]
        cached = self._record_view_cache.get(ordinal)
        if cached is None:
            cached = RecordView(self, item["record"], ordinal)
            self._record_view_cache[ordinal] = cached
        return cached

    @property
    def count(self):
        return _CallableInt(len(self._metadata()))

    @property
    def visible_count(self):
        return self.count

    @property
    def record_count(self):
        return self.count

    @property
    def scope_id(self):
        return self._scope.scope_id

    def __len__(self):
        return int(self.count)

    def __iter__(self):
        return self.iter_records()

    def __getitem__(self, index):
        if isinstance(index, slice):
            metadata = self._metadata()[index]
            return [self._record_view(item) for item in metadata]
        ordinal = int(index) + 1
        record = self.get_record_by_ordinal(ordinal)
        if record is None:
            raise IndexError(index)
        return record

    def iter_records(self):
        for item in self._metadata():
            yield self._record_view(item)

    @property
    def visible_records(self):
        return list(self.iter_records())

    @property
    def first(self):
        return self.get_record_by_ordinal(1)

    @property
    def last(self):
        return self.get_record_by_ordinal(int(self.count))

    @property
    def first_record_num(self):
        metadata = self._metadata()
        return metadata[0]["record_num"] if metadata else None

    @property
    def last_record_num(self):
        metadata = self._metadata()
        return metadata[-1]["record_num"] if metadata else None

    @property
    def visible_range(self):
        return (self.first_record_num, self.last_record_num)

    @property
    def ordinal_range(self):
        count = int(self.count)
        return (1, count) if count else (None, None)

    @property
    def ack_range(self):
        return self._scope.ack_range

    def _select(self, start, end):
        return [self._record_view(item) for item in self._metadata()[start:end]]

    def _cursor_key(self):
        material = _canonical(
            {
                "archive_id": self._archive.archive_id,
                "scope_id": self._scope.scope_id,
                "role": self._role,
            }
        )
        return hmac.new(self._archive._signing_key, b"cursor.key.v1\0" + material, hashlib.sha256).digest()

    @staticmethod
    def _keystream(key, nonce, length):
        output = bytearray()
        counter = 0
        while len(output) < length:
            output.extend(
                hmac.new(key, b"keystream.v1\0" + nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
            )
            counter += 1
        return bytes(output[:length])

    def encode_cursor(self, position):
        position = int(position)
        if position < 0:
            raise InvalidCursor("cursor position cannot be negative")
        payload = _canonical(
            {
                "v": 1,
                "archive_id": self._archive.archive_id,
                "scope_id": self._scope.scope_id,
                "role": self._role,
                "position": position,
            }
        )
        key = self._cursor_key()
        nonce = secrets.token_bytes(16)
        stream = self._keystream(key, nonce, len(payload))
        ciphertext = bytes(left ^ right for left, right in zip(payload, stream))
        tag = hmac.new(key, b"cursor.tag.v1\0" + nonce + ciphertext, hashlib.sha256).digest()[:16]
        return Cursor(base64.urlsafe_b64encode(nonce + ciphertext + tag).rstrip(b"=").decode("ascii"))

    @staticmethod
    def _b64decode(token):
        padding = "=" * (-len(token) % 4)
        return base64.urlsafe_b64decode(token + padding)

    def decode_cursor(self, token):
        if not isinstance(token, str):
            raise InvalidCursor("cursors must be opaque strings, not {!r}".format(type(token).__name__))
        try:
            raw = self._b64decode(token)
        except Exception:
            raise InvalidCursor("cursor is not valid base64")
        if len(raw) < 33:
            raise InvalidCursor("cursor is too short")
        nonce = raw[:16]
        tag = raw[-16:]
        ciphertext = raw[16:-16]
        key = self._cursor_key()
        expected = hmac.new(key, b"cursor.tag.v1\0" + nonce + ciphertext, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, expected):
            raise CursorScopeMismatch("cursor is not bound to this scope and role")
        stream = self._keystream(key, nonce, len(ciphertext))
        payload = bytes(left ^ right for left, right in zip(ciphertext, stream))
        try:
            value = json.loads(payload.decode("utf-8"))
        except Exception:
            raise InvalidCursor("cursor payload is invalid")
        if (
            value.get("v") != 1
            or value.get("archive_id") != self._archive.archive_id
            or value.get("scope_id") != self._scope.scope_id
            or value.get("role") != self._role
        ):
            raise CursorScopeMismatch("cursor is not bound to this scope and role")
        position = value.get("position")
        if not isinstance(position, int) or isinstance(position, bool) or position < 0:
            raise InvalidCursor("cursor position is invalid")
        return position

    def _records(self, cursor=None, limit=None, offset=None):
        if cursor is not None and offset is not None:
            raise InvalidCursor("use either a cursor or an offset, not both")
        if offset is not None:
            if not isinstance(offset, int) or isinstance(offset, bool):
                raise TypeError("offset must be an integer")
            if offset < 0:
                raise ValueError("offset cannot be negative")
            start = offset
        else:
            start = 0 if cursor is None else self.decode_cursor(cursor)
        total = int(self.count)
        if start > total:
            raise CursorExpired("offset or cursor points beyond the visible records")
        if limit is None:
            end = total
            page_limit = None
        else:
            if not isinstance(limit, int) or isinstance(limit, bool):
                raise TypeError("limit must be an integer or None")
            if limit < 0:
                raise ValueError("limit cannot be negative")
            end = min(total, start + limit)
            page_limit = limit

        records = self._select(start, end)
        next_cursor = None
        if page_limit is not None and page_limit > 0 and end < total:
            next_cursor = self.encode_cursor(end)
        snapshot = self._make_snapshot(records, total=total, offset=start, kind="page")
        return Page(
            self,
            records,
            total=total,
            next_cursor=next_cursor,
            snapshot=snapshot,
            offset=start,
            cursor=cursor,
        )

    @property
    def records(self):
        return _RecordsAccessor(self)

    def page(self, limit=None, cursor=None, offset=None):
        return self._records(cursor=cursor, limit=limit, offset=offset)

    def next_page(self, page, limit=None):
        if page is None or page.next_cursor is None:
            return None
        return self._records(cursor=page.next_cursor, limit=limit)

    def get_record(self, record_num):
        """Get a visible record by its original record number."""

        return self.get_by_record_number(record_num)

    def get_record_by_ordinal(self, ordinal):
        """Get a visible record by its 1-based position within the view."""

        try:
            ordinal = int(ordinal)
        except (TypeError, ValueError):
            return None
        if ordinal < 1:
            return None
        metadata = self._metadata()
        if ordinal > len(metadata):
            return None
        return self._record_view(metadata[ordinal - 1])

    get_by_ordinal = get_record_by_ordinal
    record = get_record_by_ordinal
    record_at = get_record_by_ordinal
    at = get_record_by_ordinal
    get = get_record_by_ordinal

    def get_by_record_number(self, record_num):
        try:
            record_num = int(record_num)
        except (TypeError, ValueError):
            return None
        self._metadata()
        item = self._record_index_cache.get(record_num)
        return None if item is None else self._record_view(item)

    def contains_record(self, record_num):
        return self.get_by_record_number(record_num) is not None

    def field_is_visible(self, name):
        field_visibility = self._scope.field_visibility
        query = _norm_query(name)
        query_name = query.rsplit("/", 1)[-1].lstrip("@")
        if "/" in query or "@" in query:
            return field_visibility.action(query, name=query_name) == "allow"
        if field_visibility.is_all_visible:
            return True
        metadata = self._metadata()
        if not metadata:
            return True
        for item in metadata:
            record = self._record_view(item)
            record._ensure_fields()
            for field in record._all_fields:
                if _field_matches_query(field, name):
                    if field_visibility.action(field.path, name=field.name) == "allow":
                        return True
        return False

    def count_by(self, field, min_group_size=None, max_groups=None):
        self._scope.aggregate_visibility.check("count_by")
        if not self.field_is_visible(field):
            raise AggregateNotVisible("grouping field is not visible: {}".format(field))
        threshold = self._scope.aggregate_visibility.min_group_size
        if min_group_size is not None:
            threshold = max(threshold, int(min_group_size))
        limit = self._scope.aggregate_visibility.max_groups if max_groups is None else int(max_groups)
        groups = {}
        for record in self.iter_records():
            values = {value for value in record.values(field) if value is not None and value != ""}
            for value in values:
                groups[value] = groups.get(value, 0) + 1
        groups = {key: value for key, value in groups.items() if value >= threshold}
        if limit is not None and len(groups) > limit:
            raise AggregateNotVisible("aggregate exceeds the visible group limit")
        return {key: groups[key] for key in sorted(groups, key=lambda item: str(item))}

    def timeline(self, min_group_size=None):
        self._scope.aggregate_visibility.check("timeline")
        threshold = self._scope.aggregate_visibility.min_group_size
        if min_group_size is not None:
            threshold = max(threshold, int(min_group_size))
        groups = {}
        for record in self.iter_records():
            if record.timestamp is None:
                continue
            key = _as_datetime(record.timestamp).date().isoformat()
            groups[key] = groups.get(key, 0) + 1
        groups = {key: value for key, value in groups.items() if value >= threshold}
        limit = self._scope.aggregate_visibility.max_groups
        if limit is not None and len(groups) > limit:
            raise AggregateNotVisible("aggregate exceeds the visible group limit")
        return {key: groups[key] for key in sorted(groups)}

    def _summary(self):
        self._scope.aggregate_visibility.check("summary")
        metadata = self._metadata()
        ret = {
            "count": len(metadata),
            "scope_id": self._scope.scope_id,
            "role": self._role,
        }
        if self._role == ROLE_INVESTIGATOR:
            ret["first_record_num"] = metadata[0]["record_num"] if metadata else None
            ret["last_record_num"] = metadata[-1]["record_num"] if metadata else None
        return _CallableDict(ret)

    summary = property(_summary)

    def aggregate(self, name=None, field=None, **kwargs):
        if name is None:
            name = "count_by" if field is not None else "count"
        name = _norm_aggregate(name)
        if name == "count":
            self._scope.aggregate_visibility.check("count")
            return int(self.count)
        if name == "count_by":
            if field is None:
                raise AggregateNotVisible("count_by requires a visible field")
            return self.count_by(field, **kwargs)
        if name == "timeline":
            return self.timeline(**kwargs)
        if name == "summary":
            return self.summary()
        raise AggregateNotVisible("unsupported aggregate: {}".format(name))

    def _make_snapshot(self, records, total, offset, kind):
        entries = []
        for record in records:
            entries.append(
                {
                    "ordinal": record.ordinal,
                    "record_num": record.record_num,
                    "timestamp": _iso(record.timestamp),
                    "digest": record.digest,
                }
            )
        payload = {
            "v": 1,
            "kind": kind,
            "archive_id": self._archive.archive_id,
            "source_digest": self._archive.source_digest,
            "scope_id": self._scope.scope_id,
            "role": self._role,
            "record_start": self._scope.record_start,
            "record_end": self._scope.record_end,
            "offset": int(offset),
            "count": len(entries),
            "total": int(total),
            "records": entries,
            "content_root": hashlib.sha256(_canonical(entries)).hexdigest(),
        }
        if entries:
            payload["first_record_num"] = entries[0]["record_num"]
            payload["last_record_num"] = entries[-1]["record_num"]
        signature = hmac.new(
            self._archive._signing_key, b"snapshot.v1\0" + _canonical(payload), hashlib.sha256
        ).hexdigest()
        return Snapshot(payload, signature=signature)

    @property
    def snapshot(self):
        metadata = self._metadata()
        records = [self._record_view(item) for item in metadata]
        return self._make_snapshot(records, total=len(metadata), offset=0, kind="full")

    def verify_output(self, output):
        if isinstance(output, (list, tuple)) and all(
            hasattr(item, "digest") and hasattr(item, "record_num") for item in output
        ):
            for item in output:
                current = self.get_by_record_number(item.record_num)
                if current is None or not hmac.compare_digest(str(current.digest), str(item.digest)):
                    return False
            return True
        if isinstance(output, Page):
            snapshot = output.snapshot
        elif hasattr(output, "snapshot") and not isinstance(output, Snapshot):
            snapshot = output.snapshot
        else:
            snapshot = output
        try:
            snapshot = Snapshot.from_dict(snapshot)
        except Exception:
            return False
        return snapshot.verify(self._archive)

    verify = verify_output
    verify_previous = verify_output
    verify_old = verify_output
    check_receipt = verify_output
    check_output = verify_output

    def reconcile(self, output):
        if isinstance(output, Page):
            candidate = output.snapshot
        elif hasattr(output, "snapshot") and not isinstance(output, Snapshot):
            candidate = output.snapshot
        else:
            candidate = output
        try:
            snapshot = Snapshot.from_dict(candidate)
        except Exception as error:
            return Reconciliation(
                valid=False,
                signature_valid=False,
                current_count=int(self.count),
                reason=str(error),
            )
        signature_valid = snapshot.verify(self._archive)
        old_entries = snapshot.records
        if not signature_valid:
            return Reconciliation(
                valid=False,
                signature_valid=False,
                old_count=len(old_entries),
                old_total=int(snapshot.total),
                current_count=int(self.count),
                old_scope_id=snapshot.scope_id,
                current_scope_id=self._scope.scope_id,
                reason="old output receipt did not verify",
            )

        matched = 0
        changed = 0
        not_visible = 0
        for entry in old_entries:
            record_num = entry.get("record_num")
            current = self.get_by_record_number(record_num)
            if current is None:
                not_visible += 1
            elif hmac.compare_digest(str(current.digest), str(entry.get("digest"))):
                matched += 1
            else:
                changed += 1
        return Reconciliation(
            valid=True,
            signature_valid=True,
            matched=matched,
            changed=changed,
            not_visible=not_visible,
            old_count=len(old_entries),
            old_total=int(snapshot.total),
            current_count=int(self.count),
            old_scope_id=snapshot.scope_id,
            current_scope_id=self._scope.scope_id,
        )

    reconcile_old = reconcile
    compare = reconcile

    def _provenance(self):
        metadata = self._metadata()
        first = metadata[0]["record_num"] if metadata else None
        last = metadata[-1]["record_num"] if metadata else None
        if self._role == ROLE_INVESTIGATOR:
            first_origin = self._record_view(metadata[0]).origin if metadata else None
            last_origin = self._record_view(metadata[-1]).origin if metadata else None
            return _CallableDict(
                {
                    "role": self._role,
                    "scope_id": self._scope.scope_id,
                    "source_digest": self._archive.source_digest,
                    "archive_id": self._archive.archive_id,
                    "record_start": self._scope.record_start,
                    "record_end": self._scope.record_end,
                    "source_range": self._scope.record_range,
                    "visible_record_range": (first, last),
                    "first_record_num": first,
                    "last_record_num": last,
                    "first_origin": first_origin,
                    "last_origin": last_origin,
                    "count": len(metadata),
                }
            )
        return _CallableDict(
            {
                "role": self._role,
                "scope_id": self._scope.scope_id,
                "count": len(metadata),
                "ordinal_start": 1 if metadata else None,
                "ordinal_end": len(metadata) if metadata else None,
                "visible_ordinal_range": ((1, len(metadata)) if metadata else (None, None)),
            }
        )

    provenance = property(_provenance)

    def to_dict(self, include_records=False):
        ret = {
            "scope_id": self._scope.scope_id,
            "role": self._role,
            "count": int(self.count),
            "provenance": self.provenance(),
        }
        if include_records:
            ret["records"] = [record.to_dict() for record in self.iter_records()]
        return ret

    def to_json(self, include_records=False):
        return json.dumps(self.to_dict(include_records=include_records), ensure_ascii=False, sort_keys=True)

    describe = to_dict

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self._owns_archive:
            self._archive.close()

    def __enter__(self):
        self._ensure_open()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self):
        return "ScopedView(scope_id={!r}, role={!r}, count={!r})".format(
            self._scope.scope_id[:12], self._role, int(self.count)
        )


# Familiar aliases.  They all refer to the same small, deliberately explicit
# API, which keeps call sites readable without duplicating policy logic.
ScopedEventView = ScopedView
ScopedEventBrowser = ScopedArchive
EventBrowser = ScopedArchive
EventBrowseView = ScopedView
EventView = ScopedView
RecordRange = RecordVisibility
RecordPolicy = RecordVisibility
RecordVisibilityPolicy = RecordVisibility
FieldPolicy = FieldVisibility
FieldVisibilityPolicy = FieldVisibility
AggregateVisibilityPolicy = AggregateVisibility
VisibilityPolicy = Visibility
ScopePolicy = Visibility
ReceiptScope = Scope
AckScope = Scope
AggregatePolicy = AggregateVisibility
BrowsePage = Page
EventPage = Page
ScopedPage = Page
CursorToken = Cursor
Receipt = Snapshot
SignedScope = Scope
ScopeReceipt = Scope
EventScope = Scope
AckRange = RecordVisibility
ViewPolicy = Visibility


def scoped_view(source, scope=None, record_end=None, **kwargs):
    """Open a :class:`ScopedView` over a path or open :class:`Evtx.Evtx`."""

    return ScopedView(source, scope=scope, record_end=record_end, **kwargs)


open_scoped_view = scoped_view
browse_events = scoped_view
create_view = scoped_view
event_view = scoped_view
open_view = scoped_view
browse = scoped_view
