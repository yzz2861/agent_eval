"""Offline, policy-aware index over EVTX records.

The index is built from the XML record view already used by the rest of
python-evtx (``Evtx.Views.evtx_record_xml_view``).  It is deliberately
offline: the generated JSON contains the evidence locations and the field
projection that a policy is allowed to see, so later queries do not need the
original log and cannot widen the projection.

Security model
--------------
``AccessPolicy`` is an explicit allow-list.  A build policy decides which
field values are stored in the index at all.  A viewer policy can be applied
when presenting or querying an index; it can only narrow what is visible.

A query is all-or-nothing.  If any condition is not available (not permitted
by either policy, not indexed, or uses an unsupported operator), the whole
conjunction is refused and no hit count is returned.  Conditions are never
silently dropped, because a count produced by a partially applied conjunction
would reveal information about the omitted field.
"""
from __future__ import absolute_import

import fnmatch
import hashlib
import json
import os
import re
import xml.etree.ElementTree as etree
from dataclasses import dataclass, field as dataclass_field
from typing import Any, Dict, List, Optional, Tuple

import Evtx.Evtx as evtx
from Evtx.Views import evtx_record_xml_view


INDEX_FORMAT = "python-evtx-offline-index"
INDEX_FORMAT_VERSION = 1

STATUS_AVAILABLE = "available"
STATUS_NOT_PERMITTED = "not_permitted"
STATUS_NOT_INDEXED = "not_indexed"
STATUS_UNSUPPORTED_OPERATOR = "unsupported_operator"

_OPERATORS = {
    "eq",
    "ne",
    "contains",
    "icontains",
    "startswith",
    "istartswith",
    "endswith",
    "iendswith",
    "exists",
    "gt",
    "gte",
    "lt",
    "lte",
}

_CONDITION_RE = re.compile(r"^\s*([A-Za-z0-9_.@#*?\-]+)\s*(!=|~=|\^=|\$=|>=|<=|=|>|<|\?)\s*(.*?)\s*$")

_FIELD_ALIASES = {
    "eventid": "System.EventID",
    "eventrecordid": "System.EventRecordID",
    "channel": "System.Channel",
    "computer": "System.Computer",
    "provider": "System.Provider.Name",
    "provider.name": "System.Provider.Name",
    "timecreated": "System.TimeCreated.SystemTime",
    "systemtime": "System.TimeCreated.SystemTime",
}


def _local_name(tag):
    if not isinstance(tag, str):
        return ""
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _child(element, name):
    for child in element:
        if _local_name(child.tag) == name:
            return child
    return None


def _add_value(fields, name, value):
    if value is None:
        return
    text = str(value).strip()
    if not text:
        return
    values = fields.setdefault(name, [])
    if text not in values:
        values.append(text)


def _flatten_element(element, prefix, fields):
    path = "%s.%s" % (prefix, _local_name(element.tag)) if prefix else _local_name(element.tag)
    for key, value in element.attrib.items():
        _add_value(fields, "%s.%s" % (path, key), value)
    if len(element) == 0:
        _add_value(fields, path, element.text)
        return
    for child in element:
        _flatten_element(child, path, fields)


def _extract_event_data(event_data, fields):
    for index, child in enumerate(event_data):
        local = _local_name(child.tag)
        name = child.get("Name")
        if name:
            path = "EventData.%s" % name
        elif local == "Data":
            path = "EventData._%d" % index
        else:
            path = "EventData.%s" % local

        for key, value in child.attrib.items():
            if key != "Name":
                _add_value(fields, "%s.%s" % (path, key), value)
        if len(child) == 0:
            _add_value(fields, path, child.text)
        else:
            for nested in child:
                _flatten_element(nested, path, fields)


def extract_record_fields(xml_or_element):
    """Extract canonical field values from one EVTX XML record view.

    Args:
      xml_or_element (str or xml.etree.ElementTree.Element): the record view.

    Returns:
      dict[str, list[str]]: field name to the distinct values in the record.
    """
    if isinstance(xml_or_element, str):
        root = etree.fromstring(xml_or_element)
    else:
        root = xml_or_element

    fields = {}
    system = _child(root, "System")
    if system is not None:
        for child in system:
            _flatten_element(child, "System", fields)

    event_data = _child(root, "EventData")
    if event_data is not None:
        _extract_event_data(event_data, fields)

    user_data = _child(root, "UserData")
    if user_data is not None:
        for child in user_data:
            _flatten_element(child, "UserData", fields)

    return fields


def normalize_field_name(name, known_fields=None):
    """Resolve a concise field name to a canonical index field name."""
    if name is None:
        raise ValueError("field name must not be empty")
    raw = str(name).strip()
    if not raw:
        raise ValueError("field name must not be empty")

    if known_fields:
        by_lower = {field.lower(): field for field in known_fields}
        canonical = by_lower.get(raw.lower())
        if canonical is not None:
            return canonical

    alias = _FIELD_ALIASES.get(raw.lower())
    if alias is not None:
        return alias
    if "." not in raw:
        return "EventData.%s" % raw
    return raw


def _normalize_policy_pattern(pattern):
    raw = str(pattern).strip()
    if not raw:
        raise ValueError("policy field pattern must not be empty")
    if any(character in raw for character in "*?["):
        return raw
    return normalize_field_name(raw)


@dataclass(frozen=True)
class AccessPolicy(object):
    """An explicit field allow-list used for building or viewing an index."""

    name: str
    allowed_fields: Tuple[str, ...]
    description: str = ""

    def __post_init__(self):
        fields = self.allowed_fields
        if isinstance(fields, str):
            fields = (fields,)
        normalized = tuple(_normalize_policy_pattern(field) for field in fields)
        object.__setattr__(self, "allowed_fields", normalized)

    def permits(self, field):
        candidates = {str(field).lower(), normalize_field_name(field).lower()}
        for pattern in self.allowed_fields:
            lowered = pattern.lower()
            for candidate in candidates:
                if fnmatch.fnmatchcase(candidate, lowered):
                    return True
        return False

    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "allowed_fields": list(self.allowed_fields),
        }

    @classmethod
    def event_type_only(cls, name="event-type", description=None):
        return cls(
            name,
            ("System.EventID",),
            description or "Only the event type (System.EventID) is visible.",
        )

    @classmethod
    def limited_fields(cls, fields=None, name="limited-fields", description=None):
        selected = tuple(DEFAULT_LIMITED_FIELDS if fields is None else fields)
        return cls(
            name,
            selected,
            description or "A fixed set of event fields is visible.",
        )

    @classmethod
    def all_fields(cls, name="all-fields", description=None):
        return cls(name, ("*",), description or "All indexed fields are visible.")


DEFAULT_LIMITED_FIELDS = (
    "System.EventID",
    "System.Channel",
    "System.Computer",
    "System.Provider.Name",
    "System.TimeCreated.SystemTime",
    "System.EventRecordID",
    "EventData.SubjectUserName",
    "EventData.TargetUserName",
    "EventData.SubjectDomainName",
    "EventData.TargetDomainName",
    "EventData.LogonType",
    "EventData.IpAddress",
    "EventData.WorkstationName",
    "EventData.LogonProcessName",
    "EventData.AuthenticationPackageName",
)

EVENT_TYPE_POLICY = AccessPolicy.event_type_only()
LIMITED_FIELD_POLICY = AccessPolicy.limited_fields()
FULL_POLICY = AccessPolicy.all_fields()


@dataclass(frozen=True)
class EvidenceLocation(object):
    """A composite location that remains usable when fields are redacted."""

    source: str
    chunk_index: int
    chunk_offset: int
    record_num: Optional[int]
    record_offset: int

    def to_dict(self):
        return {
            "source": self.source,
            "chunk_index": self.chunk_index,
            "chunk_offset": self.chunk_offset,
            "record_num": self.record_num,
            "record_offset": self.record_offset,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            source=data["source"],
            chunk_index=int(data["chunk_index"]),
            chunk_offset=int(data["chunk_offset"]),
            record_num=None if data.get("record_num") is None else int(data["record_num"]),
            record_offset=int(data["record_offset"]),
        )

    def sort_key(self):
        record_num = -1 if self.record_num is None else self.record_num
        return (self.source, self.chunk_index, record_num, self.record_offset)


@dataclass(frozen=True)
class RecordView(object):
    """One record XML view and the evidence location it came from."""

    xml: str
    location: EvidenceLocation


@dataclass
class Coverage(object):
    """What was verified while building an index."""

    file_verified: bool = True
    chunks_declared: int = 0
    chunks_seen: int = 0
    chunks_verified: int = 0
    chunks_failed: int = 0
    chunks_missing: int = 0
    records_seen: int = 0
    records_indexed: int = 0
    records_failed: int = 0
    failed_locations: List[Dict[str, Any]] = dataclass_field(default_factory=list)

    def add_failure(self, location, reason):
        item = location.to_dict()
        item["reason"] = reason
        self.failed_locations.append(item)

    def is_partial(self):
        return bool(
            not self.file_verified
            or self.chunks_failed
            or self.chunks_missing
            or self.records_failed
        )

    def to_dict(self):
        return {
            "partial": self.is_partial(),
            "file_verified": self.file_verified,
            "chunks_declared": self.chunks_declared,
            "chunks_seen": self.chunks_seen,
            "chunks_verified": self.chunks_verified,
            "chunks_failed": self.chunks_failed,
            "chunks_missing": self.chunks_missing,
            "records_seen": self.records_seen,
            "records_indexed": self.records_indexed,
            "records_failed": self.records_failed,
            "failed_locations": list(self.failed_locations),
        }

    @classmethod
    def from_dict(cls, data):
        coverage = cls()
        for key in (
            "file_verified",
            "chunks_declared",
            "chunks_seen",
            "chunks_verified",
            "chunks_failed",
            "chunks_missing",
            "records_seen",
            "records_indexed",
            "records_failed",
        ):
            if key in data:
                setattr(coverage, key, data[key])
        coverage.failed_locations = list(data.get("failed_locations", []))
        return coverage


@dataclass
class IndexedRecord(object):
    location: EvidenceLocation
    fields: Dict[str, List[str]]
    verified: bool = True
    chunk_verified: bool = True

    def projection(self, policy):
        return {
            field: list(values)
            for field, values in self.fields.items()
            if policy.permits(field)
        }

    def projection_sha256(self, policy):
        projection = self.projection(policy)
        payload = json.dumps(projection, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_dict(self, policy):
        return {
            "location": self.location.to_dict(),
            "verified": self.verified,
            "chunk_verified": self.chunk_verified,
            "projection_sha256": self.projection_sha256(policy),
            "fields": self.projection(policy),
        }


@dataclass(frozen=True)
class QueryCondition(object):
    field: str
    value: Optional[Any] = None
    op: str = "eq"

    def __post_init__(self):
        object.__setattr__(self, "op", str(self.op).lower())
        if self.value is not None and not isinstance(self.value, str):
            object.__setattr__(self, "value", str(self.value))

    def to_dict(self):
        return {"field": self.field, "op": self.op, "value": self.value}

    @classmethod
    def from_text(cls, text):
        match = _CONDITION_RE.match(text)
        if match is None:
            raise ValueError("invalid query condition: %r" % (text,))
        field_name, operator, value = match.groups()
        operators = {
            "=": "eq",
            "!=": "ne",
            "~=": "contains",
            "^=": "startswith",
            "$=": "endswith",
            ">": "gt",
            ">=": "gte",
            "<": "lt",
            "<=": "lte",
            "?": "exists",
        }
        query_op = operators[operator]
        return cls(field_name, None if query_op == "exists" else value, query_op)


@dataclass(frozen=True)
class ConditionAssessment(object):
    condition: QueryCondition
    field: str
    status: str
    reason: str = ""
    observed: Optional[bool] = True

    @property
    def available(self):
        return self.status == STATUS_AVAILABLE

    def to_dict(self):
        return {
            "condition": self.condition.to_dict(),
            "field": self.field,
            "status": self.status,
            "reason": self.reason,
            "observed": self.observed,
        }


@dataclass(frozen=True)
class Hit(object):
    location: EvidenceLocation
    projection_sha256: str
    verified: bool = True
    chunk_verified: bool = True
    matched_values: Dict[str, Tuple[str, ...]] = dataclass_field(default_factory=dict)

    def to_dict(self, include_values=False):
        data = {
            "location": self.location.to_dict(),
            "projection_sha256": self.projection_sha256,
            "verified": self.verified,
            "chunk_verified": self.chunk_verified,
        }
        if include_values:
            data["matched_values"] = {
                field: list(values) for field, values in sorted(self.matched_values.items())
            }
        return data


@dataclass
class QueryResult(object):
    available: bool
    assessments: List[ConditionAssessment]
    hits: List[Hit]
    hit_count: Optional[int]
    condition_counts: Optional[List[int]]
    reason: str = ""
    include_values: bool = False

    def to_dict(self):
        return {
            "available": self.available,
            "reason": self.reason,
            "conditions": [assessment.to_dict() for assessment in self.assessments],
            "hit_count": self.hit_count,
            "condition_counts": self.condition_counts,
            "hits": [hit.to_dict(self.include_values) for hit in self.hits],
        }


def _coerce_conditions(conditions):
    if isinstance(conditions, (str, QueryCondition, dict)):
        conditions = [conditions]
    coerced = []
    for condition in conditions:
        if isinstance(condition, QueryCondition):
            coerced.append(condition)
        elif isinstance(condition, str):
            coerced.append(QueryCondition.from_text(condition))
        elif isinstance(condition, dict):
            coerced.append(
                QueryCondition(
                    condition["field"],
                    condition.get("value"),
                    condition.get("op", condition.get("operator", "eq")),
                )
            )
        elif isinstance(condition, (tuple, list)):
            coerced.append(QueryCondition(*condition))
        else:
            raise TypeError("unsupported query condition: %r" % (condition,))
    if not coerced:
        raise ValueError("at least one query condition is required")
    return coerced


def _as_text(value):
    return "" if value is None else str(value)


def _matches(values, condition):
    op = condition.op
    if op not in _OPERATORS:
        return False
    if op == "exists":
        return bool(values)

    expected = _as_text(condition.value)
    if op == "ne":
        return bool(values) and all(_as_text(value) != expected for value in values)

    for value in values:
        actual = _as_text(value)
        if op == "eq" and actual == expected:
            return True
        if op == "contains" and expected in actual:
            return True
        if op == "icontains" and expected.lower() in actual.lower():
            return True
        if op == "startswith" and actual.startswith(expected):
            return True
        if op == "istartswith" and actual.lower().startswith(expected.lower()):
            return True
        if op == "endswith" and actual.endswith(expected):
            return True
        if op == "iendswith" and actual.lower().endswith(expected.lower()):
            return True
        if op in ("gt", "gte", "lt", "lte"):
            try:
                left, right = float(actual), float(expected)
            except ValueError:
                continue
            if op == "gt" and left > right:
                return True
            if op == "gte" and left >= right:
                return True
            if op == "lt" and left < right:
                return True
            if op == "lte" and left <= right:
                return True
    return False


class OfflineIndex(object):
    """A serializable field index whose projections are policy controlled."""

    def __init__(self, policy, records, coverage=None, sources=None):
        self.policy = policy
        self.records = sorted(records, key=lambda record: record.location.sort_key())
        self.coverage = coverage or Coverage()
        if sources is None:
            sources = sorted({record.location.source for record in self.records})
        self.sources = list(sources)
        self._known_fields = sorted({field for record in self.records for field in record.fields})

    def resolve_field(self, field):
        return normalize_field_name(field, self._known_fields)

    def assess(self, conditions, viewer_policy=None):
        """Explain whether each condition can be used against this index."""
        conditions = _coerce_conditions(conditions)
        assessments = []
        for condition in conditions:
            field_name = self.resolve_field(condition.field)
            observed = field_name in self._known_fields
            status = STATUS_AVAILABLE
            reason = ""

            if condition.op not in _OPERATORS:
                status = STATUS_UNSUPPORTED_OPERATOR
                reason = "operator %r is not supported" % condition.op
            elif not self.policy.permits(field_name):
                status = STATUS_NOT_INDEXED
                reason = "field is outside this index's build policy"
            elif viewer_policy is not None and not viewer_policy.permits(field_name):
                status = STATUS_NOT_PERMITTED
                reason = "field is not permitted by the viewer policy"
            elif not observed:
                reason = "field is permitted but no indexed record contains it"

            if status != STATUS_AVAILABLE:
                observed = None

            assessments.append(
                ConditionAssessment(
                    condition=condition,
                    field=field_name,
                    status=status,
                    reason=reason,
                    observed=observed,
                )
            )
        return assessments

    def explain(self, conditions, viewer_policy=None):
        """Alias for :meth:`assess`."""
        return self.assess(conditions, viewer_policy=viewer_policy)

    def query(self, conditions, viewer_policy=None, include_values=False, limit=None, verified_only=True):
        """Evaluate a conjunction, or refuse it if any condition is unavailable."""
        assessments = self.assess(conditions, viewer_policy=viewer_policy)
        unavailable = [assessment for assessment in assessments if not assessment.available]
        if unavailable:
            return QueryResult(
                available=False,
                assessments=assessments,
                hits=[],
                hit_count=None,
                condition_counts=None,
                reason="query refused because one or more conditions are unavailable; "
                "conditions are not partially applied",
                include_values=include_values,
            )

        candidate_records = [record for record in self.records if record.verified or not verified_only]
        matched = None
        condition_counts = []
        for assessment in assessments:
            this_condition = set()
            for index, record in enumerate(candidate_records):
                values = record.fields.get(assessment.field, [])
                if _matches(values, assessment.condition):
                    this_condition.add(index)
            condition_counts.append(len(this_condition))
            if matched is None:
                matched = this_condition
            else:
                matched &= this_condition

        matched = matched or set()
        ordered = sorted(matched)
        if limit is not None:
            ordered = ordered[: int(limit)]

        hits = []
        for index in ordered:
            record = candidate_records[index]
            matched_values = {}
            if include_values:
                for assessment in assessments:
                    matched_values[assessment.field] = tuple(record.fields.get(assessment.field, []))
            hits.append(
                Hit(
                    location=record.location,
                    projection_sha256=record.projection_sha256(viewer_policy or self.policy),
                    verified=record.verified,
                    chunk_verified=record.chunk_verified,
                    matched_values=matched_values,
                )
            )

        return QueryResult(
            available=True,
            assessments=assessments,
            hits=hits,
            hit_count=len(matched),
            condition_counts=condition_counts,
            reason="",
            include_values=include_values,
        )

    def _field_summaries(self, viewer_policy):
        records_per_field = {}
        values_per_field = {}
        for record in self.records:
            for field, values in record.fields.items():
                if not viewer_policy.permits(field):
                    continue
                records_per_field[field] = records_per_field.get(field, 0) + 1
                value_counts = values_per_field.setdefault(field, {})
                for value in values:
                    value_counts[value] = value_counts.get(value, 0) + 1

        summaries = []
        for field_name in sorted(records_per_field):
            value_counts = values_per_field[field_name]
            summaries.append(
                {
                    "field": field_name,
                    "record_count": records_per_field[field_name],
                    "values": [
                        {"value": value, "count": value_counts[value]}
                        for value in sorted(value_counts)
                    ],
                }
            )
        return summaries

    def to_dict(self, viewer_policy=None, include_records=True):
        explicit_viewer = viewer_policy is not None
        viewer_policy = viewer_policy or self.policy
        build_policy = self.policy.to_dict()
        if explicit_viewer:
            named_build_fields = [
                field
                for field in self.policy.allowed_fields
                if not any(character in field for character in "*?[")
            ]
            if not all(viewer_policy.permits(field) for field in named_build_fields):
                build_policy["allowed_fields"] = [
                    field
                    for field in named_build_fields
                    if viewer_policy.permits(field)
                ]
                if "*" in self.policy.allowed_fields:
                    build_policy["allowed_fields"].append("*")
                build_policy["redacted"] = True
        records = []
        if include_records:
            records = [record.to_dict(viewer_policy) for record in self.records]
        visible_fields = {
            field
            for record in self.records
            for field in record.fields
            if viewer_policy.permits(field)
        }
        return {
            "format": INDEX_FORMAT,
            "format_version": INDEX_FORMAT_VERSION,
            "build_policy": build_policy,
            "view_policy": viewer_policy.to_dict(),
            "sources": list(self.sources),
            "coverage": self.coverage.to_dict(),
            "fields": self._field_summaries(viewer_policy),
            "totals": {
                "records_indexed": self.coverage.records_indexed,
                "records_failed": self.coverage.records_failed,
                "fields_indexed": len(visible_fields),
            },
            "records": records,
        }

    def fingerprint(self, viewer_policy=None):
        payload = json.dumps(
            self.to_dict(viewer_policy=viewer_policy),
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def presentation(self, viewer_policy=None, include_records=True):
        """Render the policy-filtered index presentation."""
        return self.to_dict(viewer_policy=viewer_policy, include_records=include_records)

    def save(self, path):
        with open(path, "w", encoding="utf-8") as output:
            json.dump(self.to_dict(), output, indent=2, sort_keys=True, ensure_ascii=False)

    @classmethod
    def load(cls, path):
        with open(path, "r", encoding="utf-8") as source:
            data = json.load(source)
        if data.get("format") != INDEX_FORMAT:
            raise ValueError("not a python-evtx offline index")
        if int(data.get("format_version", 0)) != INDEX_FORMAT_VERSION:
            raise ValueError("unsupported index format version: %r" % (data.get("format_version"),))

        policy_data = data["build_policy"]
        policy = AccessPolicy(
            policy_data.get("name", "loaded"),
            tuple(policy_data["allowed_fields"]),
            policy_data.get("description", ""),
        )
        records = []
        for record_data in data.get("records", []):
            records.append(
                IndexedRecord(
                    location=EvidenceLocation.from_dict(record_data["location"]),
                    fields={field: list(values) for field, values in record_data.get("fields", {}).items()},
                    verified=bool(record_data.get("verified", True)),
                    chunk_verified=bool(record_data.get("chunk_verified", True)),
                )
            )
        return cls(
            policy=policy,
            records=records,
            coverage=Coverage.from_dict(data.get("coverage", {})),
            sources=data.get("sources"),
        )


def _filter_fields(fields, policy):
    return {
        field_name: list(values)
        for field_name, values in fields.items()
        if policy.permits(field_name)
    }


def build_index_from_views(views, policy=None, source="<views>", coverage=None):
    """Build an index from already rendered record views.

    This is useful for offline ingestion pipelines and for tests that need to
    exercise a verified fragment without a complete EVTX container.  Each item
    may be a ``RecordView``, a ``(xml, EvidenceLocation)`` tuple, or an XML
    string.
    """
    policy = policy or EVENT_TYPE_POLICY
    coverage = coverage or Coverage(chunks_declared=1, chunks_seen=1, chunks_verified=1)
    records = []

    for index, view in enumerate(views):
        if isinstance(view, RecordView):
            xml, location = view.xml, view.location
        elif isinstance(view, tuple) and len(view) == 2:
            xml, location = view
        elif isinstance(view, str):
            xml = view
            location = EvidenceLocation(source, 0, 0, index, 0)
        else:
            raise TypeError("unsupported record view: %r" % (view,))

        coverage.records_seen += 1
        try:
            fields = extract_record_fields(xml)
        except Exception:
            coverage.records_failed += 1
            coverage.add_failure(location, "record view could not be parsed")
            continue

        records.append(
            IndexedRecord(
                location=location,
                fields=_filter_fields(fields, policy),
                verified=True,
                chunk_verified=True,
            )
        )
        coverage.records_indexed += 1

    if coverage.records_failed:
        coverage.chunks_failed = max(coverage.chunks_failed, 1)
        coverage.chunks_verified = max(0, coverage.chunks_seen - coverage.chunks_failed)
    sources = sorted({record.location.source for record in records}) or [source]
    return OfflineIndex(policy=policy, records=records, coverage=coverage, sources=sources)


def build_evtx_index(path, policy=None, include_inactive=False, require_verified=True):
    """Build a policy-scoped offline index from an EVTX file.

    Corrupt or truncated regions do not abort the build.  Records that can be
    structurally verified and rendered are indexed, while the coverage block
    records what was skipped or missing.
    """
    policy = policy or EVENT_TYPE_POLICY
    coverage = Coverage()
    records = []
    source = os.fspath(path)

    with evtx.Evtx(path) as log:
        file_header = log.get_file_header()
        try:
            coverage.file_verified = bool(file_header.verify())
        except Exception:
            coverage.file_verified = False
        try:
            coverage.chunks_declared = int(file_header.chunk_count())
        except Exception:
            coverage.chunks_declared = 0

        for chunk_index, chunk in enumerate(file_header.chunks(include_inactive=include_inactive)):
            coverage.chunks_seen += 1
            try:
                chunk_verified = bool(chunk.verify())
            except Exception:
                chunk_verified = False
            if chunk_verified:
                coverage.chunks_verified += 1
            else:
                coverage.chunks_failed += 1

            chunk_records = chunk.records()
            while True:
                try:
                    record = next(chunk_records)
                except StopIteration:
                    break
                except Exception:
                    coverage.records_failed += 1
                    break

                coverage.records_seen += 1
                try:
                    record_num = record.record_num()
                except Exception:
                    record_num = None
                try:
                    chunk_offset = chunk.offset()
                    record_offset = record.offset()
                except Exception:
                    chunk_offset = 0
                    record_offset = 0
                location = EvidenceLocation(
                    source=source,
                    chunk_index=chunk_index,
                    chunk_offset=chunk_offset,
                    record_num=record_num,
                    record_offset=record_offset,
                )

                try:
                    record_verified = bool(record.verify())
                except Exception:
                    record_verified = False
                if require_verified and not record_verified:
                    coverage.records_failed += 1
                    coverage.add_failure(location, "record did not pass structural verification")
                    continue

                try:
                    xml = evtx_record_xml_view(record)
                    fields = extract_record_fields(xml)
                except Exception:
                    coverage.records_failed += 1
                    coverage.add_failure(location, "record view could not be parsed")
                    continue

                records.append(
                    IndexedRecord(
                        location=location,
                        fields=_filter_fields(fields, policy),
                        verified=record_verified,
                        chunk_verified=chunk_verified,
                    )
                )
                coverage.records_indexed += 1

        coverage.chunks_missing = max(0, coverage.chunks_declared - coverage.chunks_seen)

    return OfflineIndex(policy=policy, records=records, coverage=coverage, sources=[source])


Index = OfflineIndex
EvtxIndex = OfflineIndex
FieldPolicy = AccessPolicy
Policy = AccessPolicy
EVENT_TYPE_ONLY = EVENT_TYPE_POLICY
LIMITED_FIELDS_POLICY = LIMITED_FIELD_POLICY
build_index = build_evtx_index
generate_offline_index = build_evtx_index
load_index = OfflineIndex.load


def query_index(index, conditions, policy=None, **kwargs):
    """Query an index with an optional viewer policy."""
    return index.query(conditions, viewer_policy=policy, **kwargs)
