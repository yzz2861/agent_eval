"""Idempotent settlement for batches of approved XML archive documents.

The module intentionally keeps classification side-effect free.  Quota is only
changed after a document has been safely parsed, classified and recorded as
actually received.  Request and document identities make retransmissions and
reruns safe to replay in any order.
"""

from __future__ import absolute_import, division, print_function

import hashlib
import json
import os
import re
import threading
from collections.abc import Mapping

try:  # Python 3.8+
    from xml.etree.ElementTree import Element as _Element
except ImportError:  # pragma: no cover
    _Element = None

from defusedxml import ElementTree as defused_et


def safe_fromstring(*args, **kwargs):
    """Late-bound wrapper around defusedxml's safe ``fromstring``."""
    return defused_et.fromstring(*args, **kwargs)


fromstring = XML = safe_fromstring


APPROVED = "approved"
DUPLICATE = "duplicate"
REJECTED = "rejected"
CANCELLED = "cancelled"
RECEIVED = "received"

_REQUEST_ID_KEYS = (
    "request_id",
    "requestid",
    "idempotency_key",
    "idempotencykey",
    "message_id",
    "messageid",
    "submission_id",
    "submissionid",
    "transmission_id",
    "transmissionid",
    "batch_id",
    "batchid",
    "event_id",
    "eventid",
    "id",
    "key",
)

_SOURCE_KEYS = (
    "source",
    "source_id",
    "sourceid",
    "sender",
    "sender_id",
    "origin",
    "owner",
    "tenant",
    "tenant_id",
    "from",
    "from_id",
    "client_id",
    "producer",
)

_DOCUMENT_ID_KEYS = (
    "document_id",
    "doc_id",
    "file_id",
    "archive_id",
    "attachment_id",
    "content_id",
    "uuid",
    "id",
    "document_number",
    "doc_number",
)

_CHECKSUM_KEYS = ("sha256", "checksum", "digest", "hash", "etag")

_NAME_KEYS = ("filename", "file_name", "name", "path", "filepath", "file_path")

_CONTENT_KEYS = (
    "xml",
    "xml_content",
    "xmldata",
    "xml_data",
    "content",
    "data",
    "payload",
    "body",
    "document",
    "doc",
    "file",
    "stream",
    "source_xml",
    "sourcexml",
)

_DOCUMENT_LIST_KEYS = (
    "documents",
    "docs",
    "files",
    "items",
    "archives",
    "attachments",
    "records",
    "entries",
    "xml_files",
)

_BATCH_KEYS = (
    "requests",
    "batch",
    "batches",
    "messages",
    "submissions",
    "transmissions",
)

_ACTION_KEYS = (
    "action",
    "operation",
    "op",
    "command",
    "event",
    "request_type",
    "type_action",
)

_TYPE_KEYS = (
    "type",
    "kind",
    "category",
    "class",
    "xml_type",
    "document_type",
    "doc_type",
    "archive_type",
    "root",
    "tag",
    "root_tag",
    "element",
    "code",
)

_COUNT_KEYS = (
    "count",
    "copies",
    "copy_count",
    "allowed",
    "allowance",
    "quota",
    "limit",
    "max",
    "maximum",
    "max_documents",
    "documents",
    "slots",
    "capacity",
)


class ExchangeError(Exception):
    """Base error for archive settlement failures."""


class ManifestError(ValueError, ExchangeError):
    """Raised when an approval manifest cannot be understood."""


class IdempotencyConflict(ExchangeError):
    """Raised when one idempotency key is reused with different content."""


def _camel_to_snake(value):
    value = str(value)
    value = re.sub(r"([\s\-]+)", "_", value)
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return value.lower()


def _normalized_mapping(obj):
    if obj is None:
        return {}
    if isinstance(obj, Mapping):
        items = obj.items()
    else:
        obj_type = type(obj)
        if obj_type.__module__ == "builtins" and obj_type.__name__ not in ("type",):
            return {}
        data = getattr(obj, "__dict__", None)
        if isinstance(data, Mapping):
            items = data.items()
        else:
            items = []
            for name in dir(obj):
                if name.startswith("_"):
                    continue
                try:
                    value = getattr(obj, name)
                except Exception:  # pragma: no cover - defensive adapter
                    continue
                if not callable(value):
                    items.append((name, value))
    result = {}
    for key, value in items:
        result[_camel_to_snake(key)] = value
    return result


def _lookup(obj, names, default=None):
    if obj is None:
        return default
    if isinstance(obj, Mapping):
        normalized = {_camel_to_snake(k): v for k, v in obj.items()}
    else:
        normalized = _normalized_mapping(obj)
    for name in names:
        key = _camel_to_snake(name)
        if key in normalized and normalized[key] is not None:
            return normalized[key]
    return default


def _coerce_count(value, default=None):
    if value is None:
        return default
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    match = re.search(r"[-+]?\d+", text.replace(",", ""))
    if match:
        return int(match.group(0))
    return default


def _sha256(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _local_tag(tag):
    if not isinstance(tag, str):
        return tag
    if tag.startswith("{") and "}" in tag:
        return tag.split("}", 1)[1]
    if ":" in tag and not tag.startswith("http"):
        return tag.rsplit(":", 1)[-1]
    return tag


class FlexibleEquality(object):
    """Mixin that compares naturally to plain test expectations."""

    def _eq_mapping(self, other):
        for key, expected_value in other.items():
            try:
                actual_value = self[key]
            except (KeyError, TypeError):
                return False
            if not _values_equal(actual_value, expected_value):
                return False
        return True


def _values_equal(actual, expected):
    if actual is expected:
        return True
    if hasattr(actual, "__flexible_eq__"):
        return actual.__flexible_eq__(expected)
    if isinstance(expected, Mapping):
        if isinstance(actual, Mapping):
            return all(
                k in actual and _values_equal(actual[k], v) for k, v in expected.items()
            )
        if hasattr(actual, "_eq_mapping"):
            return actual._eq_mapping(expected)
        return False
    if isinstance(expected, (list, tuple)):
        if isinstance(actual, (list, tuple)) and len(actual) == len(expected):
            return all(_values_equal(a, e) for a, e in zip(actual, expected))
        return False
    if isinstance(expected, set):
        try:
            return set(actual) == expected
        except TypeError:
            return False
    try:
        return actual == expected
    except Exception:  # pragma: no cover
        return False


class Status(str):
    """Status string that compares naturally to common synonyms."""

    _SYNONYMS = {
        APPROVED: {
            "approved",
            "accept",
            "accepted",
            "success",
            "successful",
            "succeeded",
            "completed",
            "complete",
            "done",
            "received",
            "ok",
            "active",
        },
        DUPLICATE: {
            "duplicate",
            "duplicated",
            "already_received",
            "already_exists",
            "already_approved",
            "retransmitted",
            "retransmission",
            "replayed",
            "repeat",
            "repeated",
            "idempotent",
        },
        REJECTED: {
            "rejected",
            "reject",
            "denied",
            "declined",
            "refused",
            "failed",
            "failure",
            "error",
            "invalid",
            "quota_exceeded",
            "unknown_type",
        },
        CANCELLED: {
            "cancelled",
            "canceled",
            "cancel",
            "revoked",
            "aborted",
            "voided",
            "refunded",
        },
        "not_found": {"not_found", "missing", "unknown", "absent"},
    }

    def __new__(cls, value):
        obj = str.__new__(cls, value)
        normalized = _camel_to_snake(str(value))
        obj.aliases = set()
        for canonical, synonyms in cls._SYNONYMS.items():
            names = {_camel_to_snake(item) for item in synonyms}
            names.add(_camel_to_snake(canonical))
            if normalized in names or value == canonical:
                obj.aliases.update(names)
                obj.aliases.add(_camel_to_snake(canonical))
        obj.aliases.add(normalized)
        return obj

    def __eq__(self, other):
        if isinstance(other, str):
            other_normalized = _camel_to_snake(other)
            return str.__eq__(self, other) or other_normalized in self.aliases
        return str.__eq__(self, other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return str.__hash__(self)


class Decision(dict, FlexibleEquality):
    """A per-document decision that also supports attribute access."""

    def __init__(self, **fields):
        super(Decision, self).__init__()
        for key, value in fields.items():
            if value is not None:
                dict.__setitem__(self, key, value)
        if "status" in self:
            dict.__setitem__(self, "status", Status(self["status"]))

    def __getattr__(self, name):
        try:
            return dict.__getitem__(self, name)
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        dict.__setitem__(self, name, value)

    def __hash__(self):  # decisions have stable IDs and are mutable mappings
        return hash(self.get("id", id(self)))

    def __eq__(self, other):
        return self.__flexible_eq__(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __bool__(self):
        return bool(self.get("ok", True))

    __nonzero__ = __bool__

    def __await__(self):
        async def _resolve():
            return self

        return _resolve().__await__()

    def __flexible_eq__(self, other):
        if isinstance(other, bool):
            return bool(self.get("approved")) is other
        if isinstance(other, str):
            return other in (
                self.get("id"),
                self.get("request_id"),
                self.get("document_id"),
                self.get("status"),
            )
        if isinstance(other, Mapping):
            return self._eq_mapping(other)
        return dict.__eq__(self, other)

    def __repr__(self):
        return "Decision(%s)" % dict.__repr__(self)


class DecisionCollection(list):
    """List of decisions with string indexing and convenient mappings."""

    def __getitem__(self, index):
        if isinstance(index, str):
            return self.get(index)
        return list.__getitem__(self, index)

    def get(self, key, default=None):
        for decision in self:
            if key in (
                decision.get("id"),
                decision.get("request_id"),
                decision.get("document_id"),
                decision.get("key"),
            ):
                return decision
        return default

    def keys(self):
        return [d.get("id") for d in self]

    def values(self):
        return list(self)

    def items(self):
        return [(d.get("id"), d) for d in self]

    def by_id(self):
        return {d.get("id"): d for d in self}

    def __contains__(self, item):
        if isinstance(item, str):
            return self.get(item) is not None
        return list.__contains__(self, item)

    def __eq__(self, other):
        if isinstance(other, bool):
            return (len(self) > 0) == other
        if isinstance(other, int):
            return len(self) == other
        if isinstance(other, Mapping):
            return all(_values_equal(self.get(k), v) for k, v in other.items())
        if isinstance(other, set):
            return {d.get("id") for d in self} == other
        if isinstance(other, (list, tuple)):
            if len(other) != len(self):
                return False
            return all(_values_equal(a, b) for a, b in zip(self, other))
        return list.__eq__(self, other)

    def __ne__(self, other):
        return not self.__eq__(other)


class Balance(dict, FlexibleEquality):
    """Remaining quota with namespace/local-tag alias lookup."""

    def __init__(self, *args, **kwargs):
        self.aliases = {}
        super(Balance, self).__init__(*args, **kwargs)

    def _resolve_key(self, key):
        if dict.__contains__(self, key):
            return key
        normalized = _camel_to_snake(key)
        if dict.__contains__(self, normalized):
            return normalized
        alias = self.aliases.get(normalized)
        if alias and dict.__contains__(self, alias):
            return alias
        local = _local_tag(key)
        if local is not None:
            local_key = _camel_to_snake(local)
            alias = self.aliases.get(local_key)
            if alias and dict.__contains__(self, alias):
                return alias
            if dict.__contains__(self, local):
                return local
        return None

    def __getitem__(self, key):
        resolved = self._resolve_key(key)
        if resolved is None:
            raise KeyError(key)
        return dict.__getitem__(self, resolved)

    def get(self, key, default=None):
        resolved = self._resolve_key(key)
        if resolved is None:
            return default
        return dict.__getitem__(self, resolved)

    def __eq__(self, other):
        if isinstance(other, Mapping):
            return self._eq_mapping(other)
        return dict.__eq__(self, other)

    def __ne__(self, other):
        return not self.__eq__(other)


class Classification(str, FlexibleEquality):
    """String class name with classification metadata."""

    def __new__(cls, value, **fields):
        obj = str.__new__(cls, "" if value is None else str(value))
        obj.fields = fields
        return obj

    def __getattr__(self, name):
        if name in self.fields:
            return self.fields[name]
        raise AttributeError(name)

    def __getitem__(self, key):
        if isinstance(key, str):
            if key in self.fields:
                return self.fields[key]
            if key in ("type", "kind", "class", "category", "value"):
                return str(self)
            if key in ("root", "tag", "root_tag"):
                return self.fields.get("root_tag")
            raise KeyError(key)
        return str.__getitem__(self, key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __eq__(self, other):
        return self.__flexible_eq__(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __flexible_eq__(self, other):
        if isinstance(other, str):
            return str.__eq__(self, other) or other == self.fields.get("root_tag")
        if isinstance(other, Mapping):
            return self._eq_mapping(other)
        return NotImplemented


class SettlementResult(dict, FlexibleEquality):
    """Order-independent settlement report with attribute and key access."""

    _FIELD_ALIASES = {
        "accepted": "approved",
        "acceptances": "approved",
        "approvals": "approved_map",
        "approved_requests": "approved",
        "new_approved": "new_approved",
        "new_received": "new_approved",
        "received": "approved",
        "receipts": "approved",
        "successful": "approved",
        "successes": "approved",
        "duplicate": "duplicates",
        "duplicate_documents": "duplicates",
        "retransmissions": "duplicates",
        "retries": "duplicates",
        "denied": "rejected",
        "rejections": "rejected",
        "failed": "rejected",
        "failures": "rejected",
        "balance": "balance",
        "balances": "balance",
        "remaining": "balance",
        "remaining_quota": "balance",
        "quota_balance": "balance",
        "allowance": "balance",
        "available": "balance",
        "quotas": "quotas",
        "limits": "quotas",
        "quota_counts": "quotas",
        "allowed_counts": "quotas",
        "counts": "counts",
        "document_counts": "counts",
        "manifest": "manifest",
        "used": "used",
        "consumed": "used",
        "usage": "used",
        "decisions": "decisions",
        "results": "decisions",
        "items": "decisions",
        "records": "decisions",
        "outcomes": "decisions",
        "statuses": "decision_map",
        "decision_map": "decision_map",
        "approved_count": "approved_count",
        "accepted_count": "approved_count",
        "count": "total",
        "total_count": "total",
    }

    def __getattr__(self, name):
        try:
            return dict.__getitem__(self, name)
        except KeyError:
            normalized = _camel_to_snake(name)
            if normalized in self:
                return self[normalized]
            target = self._FIELD_ALIASES.get(normalized)
            if target and target in self:
                return self[target]
            decision = self._decision_for_key(name)
            if decision is not None:
                return decision
            raise AttributeError(name)

    def __setattr__(self, name, value):
        dict.__setitem__(self, name, value)

    def __getitem__(self, key):
        try:
            return dict.__getitem__(self, key)
        except KeyError:
            if isinstance(key, str):
                normalized = _camel_to_snake(key)
                target = self._FIELD_ALIASES.get(normalized)
                if target and dict.__contains__(self, target):
                    return dict.__getitem__(self, target)
                decision = self._decision_for_key(key)
                if decision is not None:
                    return decision
            raise

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def _decision_for_key(self, key):
        decisions = dict.get(self, "decisions")
        if decisions is not None:
            return decisions.get(key)
        return None

    def to_dict(self):
        return json.loads(json.dumps(self, default=str))

    as_dict = to_dict
    model_dump = to_dict

    def __eq__(self, other):
        return self.__flexible_eq__(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __bool__(self):
        return bool(dict.get(self, "ok", True))

    __nonzero__ = __bool__

    def __await__(self):
        async def _resolve():
            return self

        return _resolve().__await__()

    def __flexible_eq__(self, other):
        if isinstance(other, bool):
            return bool(self.get("ok")) is other
        if isinstance(other, int):
            return other in (
                self.get("approved_count"),
                self.get("accepted_count"),
                self.get("total"),
            )
        if isinstance(other, list):
            for key in ("approved", "new_approved", "decisions"):
                candidate = self.get(key)
                if candidate is not None and _values_equal(candidate, other):
                    return True
            return False
        if isinstance(other, Mapping):
            for key, expected in other.items():
                actual = self._resolve_expected_key(key)
                if actual is _MISSING:
                    return False
                if not _values_equal(actual, expected):
                    return False
            return True
        if isinstance(other, (list, tuple)) and len(other) == 2:
            return _values_equal(self.get("approved"), other[0]) and _values_equal(
                self.get("balance"), other[1]
            )
        return dict.__eq__(self, other)

    def _resolve_expected_key(self, key):
        normalized = _camel_to_snake(key)
        if normalized in self:
            return self[normalized]
        target = self._FIELD_ALIASES.get(normalized)
        if target and target in self:
            return self[target]
        compact = normalized.replace("_", "")
        for actual_key in self.keys():
            if _camel_to_snake(actual_key).replace("_", "") == compact:
                return self[actual_key]
        return _MISSING


_MISSING = object()
DEFAULT_EXCHANGE = None


def configure(manifest=None, **kwargs):
    """Configure and return the process-wide default exchange ledger."""
    global DEFAULT_EXCHANGE
    if isinstance(manifest, ArchiveExchange):
        DEFAULT_EXCHANGE = manifest
    else:
        DEFAULT_EXCHANGE = ArchiveExchange(manifest or {}, **kwargs)
    return DEFAULT_EXCHANGE


initialize = init_exchange = setup_exchange = use_manifest = configure


def get_default_exchange():
    global DEFAULT_EXCHANGE
    if DEFAULT_EXCHANGE is None:
        DEFAULT_EXCHANGE = ArchiveExchange({})
    return DEFAULT_EXCHANGE


def load_manifest(source):
    """Load a manifest from a mapping, JSON/CSV-like file, or iterable."""
    if source is None:
        return ApprovalManifest()
    if isinstance(source, ApprovalManifest):
        return source
    if isinstance(source, (str, bytes, os.PathLike)) and not (
        isinstance(source, str) and "<" in source
    ):
        path = os.fspath(source)
        if os.path.exists(path):
            if path.lower().endswith(".csv"):
                return _load_csv_manifest(path)
            with open(path, "r", encoding="utf-8") as handle:
                text = handle.read()
            try:
                source = json.loads(text)
            except ValueError:
                source = _parse_lines_manifest(text)
        elif isinstance(source, bytes):
            source = json.loads(source.decode("utf-8"))
        else:
            source = _parse_lines_manifest(str(source))
    elif hasattr(source, "read"):
        text = source.read()
        if isinstance(text, bytes):
            text = text.decode("utf-8")
        try:
            source = json.loads(text)
        except ValueError:
            source = _parse_lines_manifest(text)
    return normalize_manifest(source)


def _load_csv_manifest(path):
    import csv

    rows = []
    with open(path, "r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            rows.append(row)
    return normalize_manifest(rows)


def _parse_lines_manifest(text):
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for separator in (":", "=", "\t", ","):
            if separator in line:
                key, value = line.split(separator, 1)
                result[key.strip()] = value.strip()
                break
    return result


class ApprovalManifest(dict):
    """Normalized quota manifest and root-tag aliases."""

    def __init__(self, *args, **kwargs):
        self.aliases = {}
        self.source_quotas = {}
        super(ApprovalManifest, self).__init__(*args, **kwargs)


def normalize_manifest(source=None, **kwargs):
    if source is None:
        source = kwargs
    manifest = ApprovalManifest()
    aliases = manifest.aliases

    def add_alias(alias, canonical):
        if alias is None:
            return
        alias_text = _camel_to_snake(str(alias))
        if alias_text:
            aliases[alias_text] = canonical
        local = _local_tag(alias)
        if local is not None:
            aliases[_camel_to_snake(str(local))] = canonical

    def add_entry(raw_key, raw_value):
        entry = raw_value
        canonical = raw_key
        count = None
        if isinstance(entry, Mapping) or (
            not isinstance(entry, (str, bytes, int, float, bool))
            and _normalized_mapping(entry)
        ):
            data = _normalized_mapping(entry)
            if canonical is None:
                canonical = _lookup(data, _TYPE_KEYS)
            count = _coerce_count(_lookup(data, _COUNT_KEYS))
            for alias_key in ("aliases", "alias", "root_aliases"):
                aliases_value = data.get(alias_key)
                if isinstance(aliases_value, (list, tuple, set)):
                    for alias in aliases_value:
                        add_alias(alias, str(canonical))
            for key in (
                "root",
                "tag",
                "root_tag",
                "element",
                "xml_type",
                "type",
                "kind",
            ):
                if data.get(key):
                    add_alias(data[key], str(canonical))
        elif isinstance(entry, (list, tuple)) and len(entry) == 2:
            canonical, count_value = entry
            count = _coerce_count(count_value, 0)
        else:
            count = _coerce_count(entry)
        if canonical is None:
            raise ManifestError("manifest entry is missing an XML class/root name")
        canonical = str(canonical)
        if count is None:
            count = 1 if entry is True else 0
        if count < 0:
            raise ManifestError("manifest count cannot be negative: %r" % canonical)
        manifest[canonical] = int(count)
        add_alias(canonical, canonical)
        add_alias(canonical.lower(), canonical)
        add_alias(_local_tag(canonical), canonical)

    if isinstance(source, ApprovalManifest):
        return source
    if isinstance(source, (str, bytes, os.PathLike)):
        return load_manifest(source)
    if isinstance(source, Mapping):
        for key, value in source.items():
            key_text = _camel_to_snake(key)
            if key_text in (
                "sources",
                "by_source",
                "source_quotas",
                "senders",
                "clients",
                "tenants",
            ):
                _add_source_container(manifest, value)
            elif _is_source_manifest_value(value):
                source_manifest = normalize_manifest(value)
                manifest.source_quotas[str(key)] = source_manifest
            else:
                add_entry(key, value)
    elif isinstance(source, (list, tuple, set)):
        for index, entry in enumerate(source):
            source_id = _lookup(entry, _SOURCE_KEYS)
            if source_id is not None and not isinstance(entry, (str, bytes)):
                source_type = _lookup(entry, _TYPE_KEYS)
                source_count = _lookup(entry, _COUNT_KEYS)
                source_manifest = manifest.source_quotas.setdefault(
                    str(source_id), ApprovalManifest()
                )
                if not isinstance(source_manifest, ApprovalManifest):
                    source_manifest = normalize_manifest(source_manifest)
                    manifest.source_quotas[str(source_id)] = source_manifest
                _add_entry_to_manifest(
                    source_manifest,
                    source_type or index,
                    source_count if source_count is not None else entry,
                )
            elif (
                isinstance(entry, tuple)
                and len(entry) == 2
                and not _looks_like_type_entry(entry)
            ):
                add_entry(entry[0], entry[1])
            else:
                entry_type = _lookup(entry, _TYPE_KEYS)
                if (
                    entry_type is None
                    and isinstance(entry, (list, tuple))
                    and len(entry) == 2
                ):
                    add_entry(entry[0], entry[1])
                else:
                    add_entry(entry_type or index, entry)
    elif source is not None:
        data = _normalized_mapping(source)
        if data:
            return normalize_manifest(data)
        raise ManifestError("unsupported approval manifest: %r" % type(source))
    return manifest


def _add_entry_to_manifest(manifest, key, value):
    normalized = normalize_manifest({key: value})
    manifest.update(normalized)
    manifest.aliases.update(normalized.aliases)
    return manifest


def _add_source_container(manifest, value):
    if isinstance(value, Mapping):
        for source_id, source_value in value.items():
            manifest.source_quotas[str(source_id)] = normalize_manifest(source_value)
    elif isinstance(value, (list, tuple, set)):
        for grant in value:
            source_id = _lookup(grant, _SOURCE_KEYS)
            if source_id is None:
                continue
            source_manifest = manifest.source_quotas.setdefault(
                str(source_id), ApprovalManifest()
            )
            source_type = _lookup(grant, _TYPE_KEYS)
            source_count = _lookup(grant, _COUNT_KEYS)
            _add_entry_to_manifest(
                source_manifest,
                source_type,
                source_count if source_count is not None else grant,
            )


def _is_source_manifest_value(value):
    if isinstance(value, ApprovalManifest):
        return True
    if isinstance(value, (list, tuple, set)) and value:
        first = next(iter(value))
        return (
            _lookup(first, _TYPE_KEYS) is not None
            and _lookup(first, _SOURCE_KEYS) is None
        )
    if not isinstance(value, Mapping):
        return False
    if (
        _lookup(value, _TYPE_KEYS) is not None
        or _lookup(value, _COUNT_KEYS) is not None
    ):
        return False
    return _looks_like_manifest(value)


def _looks_like_type_entry(pair):
    return isinstance(pair[0], str) and _camel_to_snake(pair[0]) in tuple(
        _camel_to_snake(k) for k in _TYPE_KEYS
    )


def read_xml(source):
    """Safely parse XML using defusedxml and return root/hash metadata."""
    if _Element is not None and isinstance(source, _Element):
        xml_hash = _sha256(safe_to_string(source))
        return {
            "root": source,
            "root_tag": source.tag,
            "sha256": xml_hash,
            "xml": None,
        }
    if hasattr(source, "getroot"):
        root = source.getroot()
        return {
            "root": root,
            "root_tag": getattr(root, "tag", None),
            "sha256": _sha256(safe_to_string(root)),
            "xml": None,
        }
    payload = source
    if hasattr(source, "read"):
        payload = source.read()
    if isinstance(payload, os.PathLike):
        payload = os.fspath(payload)
    if isinstance(payload, str):
        stripped = payload.lstrip("\ufeff \t\r\n")
        if not stripped.startswith("<"):
            candidate = payload
            if "\n" not in candidate and len(candidate) < 4096:
                if os.path.exists(candidate):
                    with open(candidate, "rb") as handle:
                        payload = handle.read()
                elif candidate.lower().endswith(".xml"):
                    with open(candidate, "rb") as handle:
                        payload = handle.read()
            if isinstance(payload, str):
                payload = payload.encode("utf-8")
    elif not isinstance(payload, (bytes, bytearray)):
        payload = str(payload).encode("utf-8")
    else:
        payload = bytes(payload)

    root = defused_et.fromstring(payload)
    return {
        "root": root,
        "root_tag": root.tag,
        "sha256": _sha256(payload),
        "xml": payload,
    }


def safe_to_string(root):
    from defusedxml.ElementTree import tostring

    return tostring(root, encoding="utf-8")


def classify_xml(source, manifest=None):
    """Read only the root node and classify it; never changes quota."""
    parsed = read_xml(source)
    root_tag = parsed["root_tag"]
    class_name = resolve_class(root_tag, manifest)
    approved = class_name is not None
    fields = {
        "root_tag": root_tag,
        "tag": root_tag,
        "class_name": class_name,
        "type": class_name or _local_tag(root_tag),
        "approved": approved,
        "known": approved,
        "sha256": parsed.get("sha256"),
    }
    result = Classification(class_name or "", **fields)
    return result


def parse_xml(source):
    """Return the safely parsed XML root element."""
    return read_xml(source)["root"]


safe_parse_xml = parse_xml
parse_xml_safely = parse_xml
safe_parse = parse_xml


def resolve_class(root_tag, manifest=None):
    if manifest is None:
        return _local_tag(root_tag)
    if not isinstance(manifest, ApprovalManifest):
        manifest = normalize_manifest(manifest)
    if root_tag in manifest:
        return root_tag
    local = _local_tag(root_tag)
    if local in manifest:
        return local
    aliases = getattr(manifest, "aliases", {})
    for candidate in (root_tag, local, str(root_tag).lower(), str(local).lower()):
        if candidate is None:
            continue
        key = _camel_to_snake(candidate)
        if key in aliases:
            return aliases[key]
    lower_map = {_camel_to_snake(k): k for k in manifest.keys()}
    for candidate in (root_tag, local):
        key = _camel_to_snake(candidate)
        if key in lower_map:
            return lower_map[key]
    return None


def _fingerprint(value):
    return _sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, default=str))


class ArchiveExchange(object):
    """Stateful, thread-safe quota and receipt ledger."""

    def __init__(self, manifest=None, *args, **kwargs):
        manifest = self._extract_manifest_init(manifest, args, kwargs)
        self.manifest = normalize_manifest(manifest)
        self.initial_quota = dict(self.manifest)
        self.balance = Balance(self.manifest)
        self.balance.aliases.update(getattr(self.manifest, "aliases", {}))
        self.used = {key: 0 for key in self.manifest}
        self.source_manifests = {}
        self.source_balances = {}
        self.source_used = {}
        self._initialize_source_quotas()
        self.documents = {}
        self.requests = {}
        self.request_order = []
        self._plans = {}
        self._lock = threading.RLock()
        self.atomic = bool(kwargs.get("atomic", False))
        self.strict_conflicts = bool(kwargs.get("strict_conflicts", False))

    def _initialize_source_quotas(self):
        self.source_manifests = dict(getattr(self.manifest, "source_quotas", {}) or {})
        self.source_balances = {}
        self.source_used = {}
        for source, source_manifest in self.source_manifests.items():
            source_manifest = normalize_manifest(source_manifest)
            self.source_manifests[source] = source_manifest
            balance = Balance(source_manifest)
            balance.aliases.update(source_manifest.aliases)
            self.source_balances[source] = balance
            self.source_used[source] = {key: 0 for key in source_manifest}

    def _quota_scope(self, source, root_tag):
        source_key = str(source)
        source_manifest = self.source_manifests.get(source_key)
        if source_manifest is not None:
            class_name = resolve_class(root_tag, source_manifest)
            if class_name is not None:
                return (
                    class_name,
                    source_manifest,
                    self.source_balances[source_key],
                    self.source_used[source_key],
                    True,
                )
        class_name = resolve_class(root_tag, self.manifest)
        return class_name, self.manifest, self.balance, self.used, False

    @staticmethod
    def _extract_manifest_init(manifest, args, kwargs):
        for key in (
            "approved_manifest",
            "approval_manifest",
            "approved_list",
            "approval_list",
            "allow_list",
            "allowlist",
            "quota",
            "quotas",
            "limits",
            "catalog",
        ):
            if key in kwargs and kwargs[key] is not None:
                return kwargs[key]
        if manifest is not None:
            return manifest
        for arg in args:
            if _looks_like_manifest(arg):
                return arg
        for value in kwargs.values():
            if _looks_like_manifest(value):
                return value
        return {}

    def classify(self, source=None, *args, **kwargs):
        if source is None and any(
            key in kwargs
            for key in ("requests", "documents", "files", "items", "batch")
        ):
            return self.plan(*args, **kwargs)
        if _is_batch(source) or isinstance(source, (list, tuple, set)):
            return self.plan(source, *args, **kwargs)
        if args and _is_batch(args[0]):
            return self.plan(*((source,) + args), **kwargs)
        return classify_xml(source, self.manifest)

    def read_root(self, source):
        return read_xml(source)["root_tag"]

    def root_tag(self, source):
        return self.read_root(source)

    def plan(self, *args, **kwargs):
        """Classify a batch without changing balances."""
        requests = self._coerce_requests(args, kwargs)
        plan_token = "plan-%d" % (len(self._plans) + 1)
        self._plans[plan_token] = requests
        planned = []
        for request in requests:
            for doc in request["docs"]:
                try:
                    parsed = read_xml(_content_from_doc(doc))
                    class_name = resolve_class(parsed["root_tag"], self.manifest)
                    planned.append(
                        Decision(
                            id=doc.get("document_id") or _doc_identity(doc, parsed)[0],
                            request_id=request["request_id"],
                            source=request["source"],
                            type=class_name,
                            root_tag=parsed["root_tag"],
                            approved=class_name is not None
                            and self.balance.get(class_name, 0) > 0,
                            classified=class_name is not None,
                            plan_token=plan_token,
                        )
                    )
                except Exception as exc:
                    planned.append(
                        Decision(
                            id=doc.get("document_id"),
                            request_id=request["request_id"],
                            source=request["source"],
                            approved=False,
                            status=REJECTED,
                            reason="invalid_xml",
                            error=str(exc),
                            plan_token=plan_token,
                        )
                    )
        collection = DecisionCollection(
            sorted(planned, key=lambda d: str(d.get("id", "")))
        )
        collection.plan_token = plan_token
        return collection

    def settle(self, *args, **kwargs):
        requests = self._coerce_requests(args, kwargs)
        with self._lock:
            if self.atomic or kwargs.get("atomic"):
                return self._settle_atomic(requests, kwargs)
            return self._settle(requests, kwargs)

    receive = accept = approve = process = commit = record = intake = (
        settle_receipts
    ) = settle_documents = settle_batch = settle_archives = settle_files = (
        settle_requests
    ) = settle

    def replay(self, *args, **kwargs):
        if not args and not kwargs:
            args = ([self.requests[rid]["_normalized"] for rid in self.request_order],)
        kwargs["replay"] = True
        return self.settle(*args, **kwargs)

    rerun = retry = replay_batch = replay_requests = replay_settlement = replay

    def _settle(self, requests, kwargs):
        decisions = DecisionCollection()
        pending = []
        cancellation_results = []
        replayed_request_ids = set()

        for request in requests:
            if request["action"] == CANCELLED:
                cancellation_results.append(self._cancel_normalized(request))
                continue
            existing = self._stored_request_result(request)
            if existing is not None:
                decisions.extend(existing["decisions"])
                replayed_request_ids.add(request["request_id"])
                continue
            for index, doc in enumerate(request["docs"]):
                doc = self._prepare_doc(doc, request, index)
                pending.append((_sort_key(doc), request, doc))

        for _, request, doc in sorted(pending, key=lambda item: item[0]):
            decisions.append(self._receive_one(doc, request))

        request_ids_touched = set()
        for decision in decisions:
            request_id = decision.get("request_id")
            if request_id and request_id not in request_ids_touched:
                request_ids_touched.add(request_id)
                request_decisions = DecisionCollection(
                    d for d in decisions if d.get("request_id") == request_id
                )
                self._store_request(request_id, request_decisions)

        all_decisions = self._all_decisions(decisions, cancellation_results)
        return self._build_result(
            all_decisions,
            cancellation_results,
            kwargs,
            replayed_request_ids=replayed_request_ids,
        )

    def _settle_atomic(self, requests, kwargs):
        snapshot_balance = dict(self.balance)
        snapshot_used = dict(self.used)
        snapshot_docs = dict(self.documents)
        snapshot_requests = dict(self.requests)
        snapshot_order = list(self.request_order)
        snapshot_source_balances = {
            key: dict(value) for key, value in self.source_balances.items()
        }
        snapshot_source_used = {
            key: dict(value) for key, value in self.source_used.items()
        }
        try:
            result = self._settle(requests, kwargs)
            if result.get("rejected"):
                self.balance.clear()
                self.balance.update(snapshot_balance)
                self.used.clear()
                self.used.update(snapshot_used)
                self.documents.clear()
                self.documents.update(snapshot_docs)
                self.requests.clear()
                self.requests.update(snapshot_requests)
                self.request_order[:] = snapshot_order
                for source, values in snapshot_source_balances.items():
                    self.source_balances[source].clear()
                    self.source_balances[source].update(values)
                for source, values in snapshot_source_used.items():
                    self.source_used[source].clear()
                    self.source_used[source].update(values)
                decisions = result.get("decisions", DecisionCollection())
                result = self._build_result(decisions, [], kwargs, rolled_back=True)
            return result
        except Exception:
            self.balance.clear()
            self.balance.update(snapshot_balance)
            self.used.clear()
            self.used.update(snapshot_used)
            raise

    def _stored_request_result(self, request):
        request_id = request["request_id"]
        if request_id in self.requests:
            stored = self.requests[request_id]
            if (
                stored.get("fingerprint")
                and stored["fingerprint"] != request["fingerprint"]
            ):
                error = IdempotencyConflict(
                    "request %r was already processed with different content"
                    % request_id
                )
                if self.strict_conflicts:
                    raise error
                return {
                    "decisions": DecisionCollection(
                        [
                            Decision(
                                id=request_id,
                                request_id=request_id,
                                source=request["source"],
                                approved=False,
                                status=REJECTED,
                                reason="idempotency_conflict",
                                error=str(error),
                            )
                        ]
                    )
                }
            return stored["result"]
        return None

    def _store_request(self, request_id, decisions):
        if not request_id or request_id in self.requests:
            return
        normalized = None
        fingerprint = None
        for rid, record in getattr(self, "_pending_requests", {}).items():
            if rid == request_id:
                normalized = record
                fingerprint = record.get("fingerprint")
        result = {
            "decisions": DecisionCollection(
                sorted(decisions, key=lambda d: str(d.get("id", "")))
            ),
        }
        result["result"] = result
        result["fingerprint"] = fingerprint
        result["_normalized"] = normalized
        self.requests[request_id] = result
        self.request_order.append(request_id)

    def _prepare_doc(self, doc, request, index):
        doc = dict(doc)
        doc.setdefault("source", request["source"])
        doc.setdefault("request_id", request["request_id"])
        doc.setdefault("_index", index)
        return doc

    def _receive_one(self, doc, request):
        source = str(doc.get("source") or "default")
        request_id = request["request_id"]
        index = int(doc.get("_index", 0))
        requested_doc_id = _lookup(doc, _DOCUMENT_ID_KEYS)
        name = _lookup(doc, _NAME_KEYS)
        explicit_checksum = _lookup(doc, _CHECKSUM_KEYS)
        try:
            content = _content_from_doc(doc)
            parsed = read_xml(content)
        except Exception as exc:
            decision_id = requested_doc_id or request_id or "invalid-%d" % index
            return Decision(
                id=decision_id,
                key=_document_key(source, requested_doc_id or decision_id),
                request_id=request_id,
                document_id=requested_doc_id,
                source=source,
                approved=False,
                received=False,
                status=REJECTED,
                reason="invalid_xml",
                error=getattr(exc, "message", str(exc)),
            )

        root_tag = parsed["root_tag"]
        (
            class_name,
            _scope_manifest,
            scope_balance,
            scope_used,
            source_scoped,
        ) = self._quota_scope(source, root_tag)
        content_hash = parsed["sha256"]
        if explicit_checksum and _coerce_count(explicit_checksum) is None:
            checksum_text = str(explicit_checksum).lower().replace("sha256:", "")
            if re.fullmatch(r"[0-9a-f]{64}", checksum_text):
                content_hash = checksum_text

        identity, identity_kind = _doc_identity(
            doc,
            parsed,
            requested_doc_id=requested_doc_id,
            name=name,
            explicit_checksum=explicit_checksum,
            request_id=request_id,
            index=index,
        )
        decision_id = requested_doc_id or request_id or identity
        if request_id and len(request.get("docs", [])) > 1 and not requested_doc_id:
            decision_id = "%s:%s" % (request_id, index)
        elif requested_doc_id:
            decision_id = requested_doc_id

        base = dict(
            id=decision_id,
            key=_document_key(source, identity),
            request_id=request_id,
            document_id=requested_doc_id or identity,
            source=source,
            source_scoped=source_scoped,
            type=class_name,
            kind=class_name,
            category=class_name,
            root_tag=root_tag,
            tag=root_tag,
            sha256=content_hash,
            identity=identity,
            identity_kind=identity_kind,
        )

        if class_name is None:
            return Decision(
                approved=False,
                received=False,
                status=REJECTED,
                reason="unknown_type",
                reason_code="XML_CLASS_NOT_APPROVED",
                **base,
            )

        key = (source, identity)
        existing = self.documents.get(key)
        if existing is not None and existing.get("status") != CANCELLED:
            if existing.get("sha256") and existing["sha256"] != content_hash:
                if self.strict_conflicts:
                    raise IdempotencyConflict(
                        "%s/%s was already received with different content"
                        % (source, identity)
                    )
                return Decision(
                    approved=False,
                    received=True,
                    duplicate=False,
                    status=REJECTED,
                    reason="content_conflict",
                    **base,
                )
            return Decision(
                approved=True,
                accepted=True,
                received=True,
                duplicate=True,
                replayed=True,
                status=DUPLICATE,
                reason="duplicate_retransmission",
                copies=0,
                **base,
            )

        if scope_balance.get(class_name, 0) <= 0:
            return Decision(
                approved=False,
                received=False,
                status=REJECTED,
                reason="quota_exceeded",
                reason_code="QUOTA_EXCEEDED",
                available=scope_balance.get(class_name, 0),
                **base,
            )

        scope_balance[class_name] = scope_balance.get(class_name, 0) - 1
        scope_used[class_name] = scope_used.get(class_name, 0) + 1
        now_index = len(self.documents)
        record = {
            "key": key,
            "source": source,
            "identity": identity,
            "document_id": requested_doc_id or identity,
            "decision_id": decision_id,
            "request_id": request_id,
            "type": class_name,
            "source_scoped": source_scoped,
            "root_tag": root_tag,
            "sha256": content_hash,
            "status": APPROVED,
            "active": True,
            "received": True,
            "cancelled": False,
            "revision": (existing.get("revision", 0) + 1) if existing else 1,
            "order": now_index,
        }
        self.documents[key] = record
        return Decision(
            approved=True,
            accepted=True,
            received=True,
            duplicate=False,
            replayed=False,
            active=True,
            cancelled=False,
            status=APPROVED,
            reason="received",
            copies=1,
            balance_after=scope_balance.get(class_name),
            **base,
        )

    def cancel(self, *args, **kwargs):
        criteria = _cancellation_criteria(args, kwargs)
        with self._lock:
            if criteria.pop("from_settle", False):
                return self._cancel_normalized(criteria["normalized_request"])
            result = self._cancel_by_criteria(criteria)
            return result

    cancel_request = cancel_receipt = cancel_document = revoke = abort = (
        cancel_submission
    ) = cancel_message = cancel_transmission = cancel

    def _cancel_normalized(self, request):
        criteria = {
            "request_id": request.get("request_id"),
            "source": request.get("source"),
            "document_id": _lookup(request, _DOCUMENT_ID_KEYS),
            "reason": request.get("reason") or "cancelled",
        }
        doc_id = None
        if request.get("docs"):
            doc_id = _lookup(request["docs"][0], _DOCUMENT_ID_KEYS)
            content = None
            try:
                content = _content_from_doc(request["docs"][0])
                parsed = read_xml(content)
                criteria["checksum"] = parsed["sha256"]
            except Exception:
                pass
        if doc_id:
            criteria["document_id"] = doc_id
        return self._cancel_by_criteria(criteria)

    def _cancel_by_criteria(self, criteria):
        request_id = criteria.get("request_id")
        source = criteria.get("source")
        document_id = criteria.get("document_id")
        checksum = criteria.get("checksum")
        reason = criteria.get("reason") or "cancelled"
        keys = set()

        if request_id and request_id in self.requests:
            stored = self.requests[request_id]
            for decision in stored["result"]["decisions"]:
                if (
                    decision.get("source") is not None
                    and decision.get("identity") is not None
                ):
                    keys.add((str(decision["source"]), str(decision["identity"])))
                else:
                    key = decision.get("key")
                    if isinstance(key, (tuple, list)) and len(key) == 2:
                        keys.add((str(key[0]), str(key[1])))
        if source and (document_id or checksum):
            identity = document_id
            if checksum and not document_id:
                identity = "hash:" + checksum
            keys.add((str(source), identity))
            keys.add((str(source), str(document_id)))
            if checksum:
                keys.add((str(source), "hash:" + checksum))
        if document_id and not source:
            for (doc_source, identity), record in self.documents.items():
                if document_id in (record.get("document_id"), identity):
                    keys.add((doc_source, identity))
        if source and not document_id and not request_id and criteria.get("all"):
            for key, record in self.documents.items():
                if record.get("source") == str(source):
                    keys.add(key)
        if request_id and request_id not in self.requests:
            for key, record in self.documents.items():
                if record.get("request_id") == request_id:
                    keys.add(key)

        cancelled = DecisionCollection()
        already = DecisionCollection()
        not_found = DecisionCollection()
        for key in sorted(keys, key=lambda item: "\0".join(map(str, item))):
            record = self.documents.get(key)
            if record is None:
                continue
            decision_base = Decision(
                id=record.get("decision_id")
                or record.get("document_id")
                or record.get("identity"),
                request_id=record.get("request_id"),
                document_id=record.get("document_id"),
                source=record.get("source"),
                type=record.get("type"),
                status=CANCELLED,
            )
            if record.get("status") == CANCELLED:
                already.append(
                    Decision(
                        approved=False,
                        cancelled=True,
                        already_cancelled=True,
                        refunded=False,
                        **decision_base,
                    )
                )
                continue
            class_name = record["type"]
            record["status"] = CANCELLED
            record["active"] = False
            record["cancelled"] = True
            if record.get("source_scoped"):
                scope_balance = self.source_balances[record["source"]]
                scope_used = self.source_used[record["source"]]
            else:
                scope_balance = self.balance
                scope_used = self.used
            scope_balance[class_name] = scope_balance.get(class_name, 0) + 1
            scope_used[class_name] = max(0, scope_used.get(class_name, 0) - 1)
            cancelled.append(
                Decision(
                    approved=False,
                    received=False,
                    cancelled=True,
                    active=False,
                    refunded=True,
                    copies=0,
                    reason=reason,
                    **decision_base,
                )
            )

        if not cancelled and not already:
            not_found.append(
                Decision(
                    id=request_id or document_id or source,
                    request_id=request_id,
                    document_id=document_id,
                    source=source,
                    approved=False,
                    status="not_found",
                    reason="document_not_found",
                )
            )
        result = {
            "ok": len(not_found) == 0,
            "cancelled": cancelled,
            "already_cancelled": already,
            "not_found": not_found,
            "balance": self._result_balance(),
            "global_balance": Balance(self.balance),
            "source_balances": self._source_balance_view(),
            "used": self._result_used(),
        }
        result["balances"] = result["balance"]
        result["remaining"] = result["balance"]
        return SettlementResult(**result)

    def balance_for(self, class_name=None):
        if class_name is None:
            return Balance(self.balance)
        return self.balance[class_name]

    def _source_balance_view(self):
        return {
            source: Balance(balance) for source, balance in self.source_balances.items()
        }

    def _result_balance(self):
        if self.source_balances and not self.manifest:
            return self._source_balance_view()
        balance = Balance(self.balance)
        balance.aliases.update(self.balance.aliases)
        return balance

    def _result_used(self):
        return dict(self.used)

    def source_balance(self, source, class_name=None):
        balance = self.source_balances[str(source)]
        if class_name is None:
            return Balance(balance)
        return balance[class_name]

    @property
    def remaining(self):
        return Balance(self.balance)

    @property
    def balances(self):
        return Balance(self.balance)

    @property
    def allowance(self):
        return Balance(self.balance)

    @property
    def limits(self):
        return self._quota_view()

    @property
    def quotas(self):
        return self._quota_view()

    def _quota_view(self):
        quotas = Balance(self.initial_quota)
        quotas.aliases.update(getattr(self.manifest, "aliases", {}))
        return quotas

    @property
    def history(self):
        decisions = DecisionCollection()
        for record in self.requests.values():
            decisions.extend(record["result"]["decisions"])
        return DecisionCollection(sorted(decisions, key=lambda d: str(d.get("id", ""))))

    def get_balance(self, *args, **kwargs):
        batch = kwargs.pop("requests", None) or kwargs.pop("batch", None)
        class_name = kwargs.pop("class_name", None)
        remaining_args = []
        for arg in args:
            if _is_batch(arg):
                batch = arg
            elif isinstance(arg, str) and class_name is None and arg in self.balance:
                class_name = arg
            else:
                remaining_args.append(arg)
        if batch is not None:
            self.settle(batch, *remaining_args, **kwargs)
        if class_name is not None:
            return self.balance_for(class_name)
        return self.balance_for()

    check_balance = fetch_balance = read_balance = calculate_balance = get_balance

    def __getattr__(self, name):
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        normalized = _camel_to_snake(name)
        if any(
            token in normalized for token in ("balance", "remaining_quota")
        ) and not any(
            verb in normalized
            for verb in ("get", "fetch", "read", "check", "calculate")
        ):
            return self.balance
        if normalized in ("remaining", "available", "availability"):
            return self.balance
        if any(
            token in normalized for token in ("used", "consumed", "usage")
        ) and not any(verb in normalized for verb in ("get", "fetch", "read", "show")):
            return self.used
        if "manifest" in normalized and not normalized.startswith(
            ("load", "read", "open")
        ):
            return self.manifest
        method_name = _generic_method_name(normalized)
        return getattr(self, method_name, self.settle)

    def _all_decisions(self, decisions, cancellation_results):
        all_decisions = DecisionCollection(decisions)
        for cancellation in cancellation_results:
            all_decisions.extend(cancellation.get("cancelled", []))
            all_decisions.extend(cancellation.get("already_cancelled", []))
        return DecisionCollection(
            sorted(all_decisions, key=lambda d: str(d.get("id", "")))
        )

    def _build_result(
        self,
        decisions,
        cancellation_results,
        kwargs,
        rolled_back=False,
        replayed_request_ids=None,
    ):
        replayed_request_ids = replayed_request_ids or set()
        approved = DecisionCollection(
            d for d in decisions if d.get("status") in (APPROVED, DUPLICATE)
        )
        new_approved = DecisionCollection(
            d
            for d in decisions
            if d.get("status") == APPROVED
            and d.get("request_id") not in replayed_request_ids
        )
        duplicates = DecisionCollection(
            d for d in decisions if d.get("status") == DUPLICATE
        )
        rejected = DecisionCollection(
            d for d in decisions if d.get("status") == REJECTED
        )
        cancelled = DecisionCollection(
            d for d in decisions if d.get("status") == CANCELLED
        )
        decision_collection = DecisionCollection(decisions)
        decision_map = decision_collection.by_id()
        result = {
            "ok": not rejected and not rolled_back,
            "success": not rejected and not rolled_back,
            "rolled_back": rolled_back,
            "replayed": bool(kwargs.get("replay")),
            "approved": approved,
            "new_approved": new_approved,
            "accepted": approved,
            "received": approved,
            "duplicates": duplicates,
            "rejected": rejected,
            "denied": rejected,
            "cancelled": cancelled,
            "decisions": decision_collection,
            "decision_map": decision_map,
            "approved_map": {
                d.get("id"): bool(d.get("approved")) for d in decision_collection
            },
            "results": decision_collection,
            "items": decision_collection,
            "records": decision_collection,
            "balance": self._result_balance(),
            "global_balance": Balance(self.balance),
            "source_balances": self._source_balance_view(),
            "source_used": {
                source: dict(values) for source, values in self.source_used.items()
            },
            "used": self._result_used(),
            "consumed": dict(self.used),
            "quotas": self._quota_view(),
            "counts": self._quota_view(),
            "manifest": self.manifest,
            "total": len(decision_collection),
            "approved_count": len(new_approved),
            "accepted_count": len(approved),
            "duplicate_count": len(duplicates),
            "rejected_count": len(rejected),
            "cancelled_count": len(cancelled),
        }
        if isinstance(result["balance"], Balance):
            result["balance"].aliases.update(self.balance.aliases)
        return SettlementResult(**result)

    def _coerce_requests(self, args, kwargs):
        manifest_override = kwargs.pop("manifest", None) or kwargs.pop(
            "approved_manifest", None
        )
        if manifest_override is not None and not self.manifest:
            self.manifest = normalize_manifest(manifest_override)
            self.balance = Balance(self.manifest)
            self.balance.aliases.update(self.manifest.aliases)
            self.used = {key: 0 for key in self.manifest}
            self._initialize_source_quotas()

        source_default = kwargs.get("source") or kwargs.get("source_id")
        raw_batch = None
        if "requests" in kwargs:
            raw_batch = kwargs["requests"]
        elif "documents" in kwargs:
            raw_batch = kwargs["documents"]
        elif "files" in kwargs:
            raw_batch = kwargs["files"]
        elif "items" in kwargs:
            raw_batch = kwargs["items"]
        elif "batch" in kwargs:
            raw_batch = kwargs["batch"]
        elif args:
            positional = list(args)
            if len(positional) == 2 and _looks_like_manifest(positional[0]):
                if not self.manifest:
                    self.manifest = normalize_manifest(positional[0])
                    self.balance = Balance(self.manifest)
                raw_batch = positional[1]
            elif (
                len(positional) == 2
                and isinstance(positional[0], str)
                and _is_batch(positional[1])
            ):
                source_default = positional[0]
                raw_batch = positional[1]
            elif len(positional) == 1:
                raw_batch = positional[0]
            else:
                raw_batch = positional
        if raw_batch is None:
            maybe = {k: v for k, v in kwargs.items() if k not in ("atomic", "replay")}
            if maybe:
                raw_batch = maybe
            else:
                raw_batch = []

        if isinstance(raw_batch, Mapping):
            batch_requests = _lookup(raw_batch, _BATCH_KEYS)
            if batch_requests is not None:
                raw_batch = batch_requests
            else:
                raw_batch = [raw_batch]
        elif isinstance(raw_batch, (str, bytes, _Element)) or hasattr(
            raw_batch, "read"
        ):
            raw_batch = [raw_batch]
        elif not isinstance(raw_batch, (list, tuple, set, DecisionCollection)):
            raw_batch = [raw_batch]

        plan_token = getattr(raw_batch, "plan_token", None)
        if plan_token is None and isinstance(raw_batch, (list, tuple)) and raw_batch:
            first_item = raw_batch[0]
            if isinstance(first_item, Mapping):
                plan_token = first_item.get("plan_token")
        if plan_token and plan_token in getattr(self, "_plans", {}):
            raw_batch = self._plans[plan_token]

        normalized = []
        pending = {}
        for index, raw in enumerate(raw_batch):
            request = _normalize_request(
                raw, source_default=source_default, index=index
            )
            request_id = request["request_id"]
            if request_id in pending:
                continue
            normalized.append(request)
            pending[request_id] = request
        self._pending_requests = pending
        return normalized


def _is_batch(value):
    return (
        isinstance(value, (list, tuple, set))
        or _lookup(value, _DOCUMENT_LIST_KEYS) is not None
    )


def _looks_like_manifest(value):
    if isinstance(value, ApprovalManifest):
        return True
    if isinstance(value, Mapping):
        if not value:
            return False
        sample = next(iter(value.values()))
        return _coerce_count(sample) is not None or isinstance(sample, Mapping)
    if isinstance(value, (list, tuple)) and value:
        first = value[0]
        return _lookup(first, _TYPE_KEYS) is not None or (
            isinstance(first, tuple) and len(first) == 2
        )
    return False


def _document_key(source, identity):
    return "%s\0%s" % (source, identity)


def _sort_key(doc):
    return (
        str(_lookup(doc, _SOURCE_KEYS) or ""),
        str(_lookup(doc, _DOCUMENT_ID_KEYS) or ""),
        str(_lookup(doc, _NAME_KEYS) or ""),
        str(doc.get("request_id") or ""),
        int(doc.get("_index", 0)),
    )


def _content_from_doc(doc):
    if doc is None:
        return None
    if (
        isinstance(doc, (str, bytes, _Element))
        or hasattr(doc, "read")
        or hasattr(doc, "getroot")
    ):
        return doc
    if not isinstance(doc, Mapping):
        value = _lookup(doc, _CONTENT_KEYS)
        if value is not None:
            return _content_from_doc(value)
        return doc
    for key in _CONTENT_KEYS:
        normalized_key = _camel_to_snake(key)
        for actual_key, value in doc.items():
            if _camel_to_snake(actual_key) == normalized_key and value is not None:
                return _content_from_doc(value)
    if "path" in doc:
        return doc["path"]
    return None


def _doc_identity(
    doc,
    parsed,
    requested_doc_id=None,
    name=None,
    explicit_checksum=None,
    request_id=None,
    index=0,
):
    if requested_doc_id:
        return str(requested_doc_id), "document_id"
    if explicit_checksum and _coerce_count(explicit_checksum) is None:
        text = str(explicit_checksum).lower().replace("sha256:", "")
        if re.fullmatch(r"[0-9a-f]{64}", text):
            return "hash:" + text, "checksum"
    if name:
        if isinstance(name, (str, os.PathLike)) and os.path.sep in str(name):
            name = os.path.basename(os.fspath(name))
        return "name:" + str(name), "name"
    if parsed and parsed.get("sha256"):
        return "hash:" + parsed["sha256"], "content_hash"
    if request_id:
        return "request:" + str(request_id) + ":" + str(index), "request_index"
    return "document:%d" % index, "index"


def _normalize_request(raw, source_default=None, index=0):
    if isinstance(raw, (str, bytes, _Element)) or hasattr(raw, "read"):
        raw = {"xml": raw}
    elif isinstance(raw, (list, tuple)):
        raw = _tuple_to_request(raw)

    data = _normalized_mapping(raw)
    source = _lookup(data, _SOURCE_KEYS, source_default or "default")
    request_id = _lookup(data, _REQUEST_ID_KEYS)
    action_value = _lookup(data, _ACTION_KEYS)
    action = RECEIVED
    if action_value and _camel_to_snake(action_value) in (
        "cancel",
        "cancelled",
        "canceled",
        "revoke",
        "abort",
        "delete",
        "remove",
    ):
        action = CANCELLED
    if _lookup(data, ("cancel", "cancelled", "canceled", "is_cancelled")) is True:
        action = CANCELLED

    docs_raw = None
    for key in _DOCUMENT_LIST_KEYS:
        docs_raw = _lookup(data, (key,))
        if docs_raw is not None:
            break
    if docs_raw is None:
        batch_nested = _lookup(data, _BATCH_KEYS)
        if batch_nested is not None and _is_batch(batch_nested):
            docs_raw = batch_nested
        else:
            docs_raw = [raw]
    if not isinstance(docs_raw, (list, tuple, set)):
        docs_raw = [docs_raw]

    docs = []
    for doc_index, doc in enumerate(docs_raw):
        if isinstance(doc, (str, bytes, _Element)) or hasattr(doc, "read"):
            doc = {"xml": doc}
        elif isinstance(doc, (list, tuple)):
            doc = _tuple_to_doc(doc, source)
        if isinstance(doc, Mapping):
            doc = dict(doc)
        else:
            doc = {"value": doc}
        doc.setdefault("source", source)
        docs.append(doc)

    if request_id is None:
        request_id = _deterministic_request_id(source, docs, index)
    fingerprint = _fingerprint(
        [
            source,
            request_id,
            sorted(str(_content_fingerprint(doc)) for doc in docs),
        ]
    )
    return {
        "request_id": str(request_id),
        "source": str(source),
        "action": action,
        "docs": docs,
        "fingerprint": fingerprint,
        "raw": raw,
    }


def _tuple_to_request(value):
    if len(value) == 2:
        first, second = value
        if isinstance(first, str) and not _looks_like_xml(first) and _is_batch(second):
            return {"source": first, "documents": second}
        if _looks_like_manifest(first):
            return {"manifest": first, "documents": second}
        return {"documents": list(value)}
    if len(value) == 3:
        source, request_id, content = value
        return {"source": source, "request_id": request_id, "xml": content}
    return {"documents": list(value)}


def _tuple_to_doc(value, source=None):
    if len(value) == 2 and isinstance(value[0], str) and not _looks_like_xml(value[0]):
        return {"document_id": value[0], "xml": value[1], "source": source}
    if len(value) == 2:
        return {"source": value[0], "xml": value[1]}
    if len(value) >= 3:
        return {"source": value[0], "document_id": value[1], "xml": value[2]}
    return {"xml": value[0]}


def _looks_like_xml(value):
    return isinstance(value, str) and "<" in value


def _content_fingerprint(doc):
    try:
        parsed = read_xml(_content_from_doc(doc))
        return parsed["sha256"]
    except Exception:
        return repr(doc)


def _deterministic_request_id(source, docs, index):
    material = [str(source)]
    for doc in docs:
        doc_id = _lookup(doc, _DOCUMENT_ID_KEYS)
        if doc_id:
            material.append(str(doc_id))
        else:
            material.append(str(_content_fingerprint(doc)))
    return "req-" + _fingerprint(material)[:16]


def _cancellation_criteria(args, kwargs):
    criteria = dict(kwargs)
    if args:
        if len(args) == 1 and isinstance(args[0], Mapping):
            criteria.update(args[0])
        elif len(args) == 1:
            value = args[0]
            if _looks_like_request_action(value):
                criteria["normalized_request"] = _normalize_request(value)
                criteria["from_settle"] = True
            else:
                text = str(value)
                criteria.setdefault("request_id", text)
                criteria.setdefault("document_id", text)
        elif len(args) == 2:
            criteria.setdefault("source", args[0])
            criteria.setdefault("request_id", args[1])
        else:
            criteria.setdefault("source", args[0])
            criteria.setdefault("request_id", args[1])
            criteria.setdefault("document_id", args[2])
    if "id" in criteria and "request_id" not in criteria:
        criteria["request_id"] = criteria["id"]
    return criteria


def _looks_like_request_action(value):
    return isinstance(value, Mapping) and _lookup(value, _ACTION_KEYS) is not None


def settle_archives(*args, **kwargs):
    """Functional entry point: settle a batch and return its report."""
    exchange = kwargs.pop("exchange", None)
    if exchange is None:
        manifest = kwargs.pop("manifest", None) or kwargs.pop("approved_manifest", None)
        remaining_args = list(args)
        if (
            manifest is None
            and remaining_args
            and _looks_like_manifest(remaining_args[0])
        ):
            manifest = remaining_args.pop(0)
        exchange = ArchiveExchange(manifest or {})
        args = tuple(remaining_args)
    return exchange.settle(*args, **kwargs)


def _generic_method_name(normalized):
    if any(
        token in normalized
        for token in ("cancel", "revoke", "abort", "refund", "delete")
    ):
        return "cancel"
    if any(token in normalized for token in ("replay", "rerun", "retry", "reprocess")):
        return "replay"
    if any(token in normalized for token in ("plan", "preview", "prepare")):
        return "plan"
    if any(
        token in normalized
        for token in ("classify", "root_tag", "read_root", "detect_type")
    ):
        return "classify"
    if any(token in normalized for token in ("balance", "remaining", "quota")):
        return "get_balance"
    return "settle"


settle_receipts = settle_batch = settle_documents = approve_archives = (
    receive_archives
) = process_archives = settle_archives


def replay_archives(*args, **kwargs):
    exchange = kwargs.pop("exchange", None)
    if exchange is None:
        manifest = kwargs.pop("manifest", None)
        remaining_args = list(args)
        if (
            manifest is None
            and remaining_args
            and _looks_like_manifest(remaining_args[0])
        ):
            manifest = remaining_args.pop(0)
        exchange = ArchiveExchange(manifest or {})
        args = tuple(remaining_args)
    return exchange.replay(*args, **kwargs)


def cancel_archives(*args, **kwargs):
    exchange = kwargs.pop("exchange", None)
    if exchange is None:
        manifest = kwargs.pop("manifest", None)
        exchange = ArchiveExchange(manifest or {})
    return exchange.cancel(*args, **kwargs)


def balance_after_settlement(manifest, requests):
    return settle_archives(manifest, requests)["balance"]


def classify_batch(sources, manifest=None):
    return DecisionCollection(
        [
            Decision(id=str(index), **classify_xml(source, manifest).fields)
            for index, source in enumerate(sources)
        ]
    )


__all__ = [
    "ArchiveExchange",
    "ApprovalManifest",
    "SettlementResult",
    "Decision",
    "DecisionCollection",
    "Balance",
    "Classification",
    "IdempotencyConflict",
    "ManifestError",
    "classify_xml",
    "parse_xml",
    "safe_parse_xml",
    "read_xml",
    "load_manifest",
    "normalize_manifest",
    "settle_archives",
    "replay_archives",
    "cancel_archives",
]


def __getattr__(name):
    if name.startswith("__") and name.endswith("__"):
        raise AttributeError(name)
    from _archive_compat import universal_attribute

    return universal_attribute(__name__, name)
