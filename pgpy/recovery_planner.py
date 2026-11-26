"""Offline disaster-recovery key-loan planning for PGPy.

This module never decrypts messages and never unlocks or loads private key
material.  It reads only public PKESK recipient headers and caller-owned
manifest/registry data.
"""

import itertools
import os
import re
from datetime import date
from datetime import datetime
from datetime import timezone

from .packet.packets import PKESessionKey
from .pgp import PGPKey
from .pgp import PGPMessage


__all__ = [
    "HeaderReport",
    "RecoveryPlanner",
    "TimeWindow",
    "inspect_archive_header",
    "plan_recovery",
]


WILDCARD_KEY_ID = "0" * 16


class RecoveryPlanningError(ValueError):
    """Base error for invalid planner input."""


class PrivateKeyMaterialError(RecoveryPlanningError):
    """Raised when private key material is supplied to the offline planner."""


class Report(dict):
    """Dictionary report that also supports attribute access."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        self[name] = value


def _first(mapping, *names):
    for name in names:
        if name in mapping and mapping[name] is not None:
            return mapping[name]
    return None


def _field(obj, *names, default=None):
    if obj is None:
        return default

    if isinstance(names, str):
        names = (names,)

    if isinstance(obj, dict):
        normalized = {}
        for key, value in obj.items():
            normalized[str(key).lower().replace("-", "_").replace(" ", "_")] = value
        for name in names:
            lookup = name.lower().replace("-", "_").replace(" ", "_")
            if lookup in normalized and normalized[lookup] is not None:
                return normalized[lookup]
        return default

    for name in names:
        if hasattr(obj, name):
            value = getattr(obj, name)
            if value is not None:
                return value
    return default


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    return [value]


def _as_set(value):
    return {str(item) for item in _as_list(value) if item is not None}


def _utc_datetime(value):
    if value is None:
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)

    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc)

    text = str(value).strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"

    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _iso(value):
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def normalize_fingerprint(value):
    """Return an uppercase OpenPGP v4 fingerprint."""
    if hasattr(value, "fingerprint"):
        value = value.fingerprint

    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("latin-1")

    text = str(value).strip()
    text = text[4:] if text.lower().startswith("0x") else text
    text = re.sub(r"[\s:]+", "", text)
    text = text.upper()

    if not re.fullmatch(r"[0-9A-F]{40}", text):
        raise RecoveryPlanningError("expected a 40 hex-digit full fingerprint")
    return text


def normalize_key_identifier(value):
    """Normalize a fingerprint, long key ID, or short key ID."""
    if hasattr(value, "fingerprint"):
        value = value.fingerprint
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("latin-1")

    text = str(value).strip()
    text = text[4:] if text.lower().startswith("0x") else text
    text = re.sub(r"[\s:]+", "", text)
    return text.upper()


def _suffix_matches(identifier, fingerprint):
    identifier = normalize_key_identifier(identifier)
    if len(identifier) == 40:
        return identifier == fingerprint
    return fingerprint.endswith(identifier)


def _archive_identity(digest=None, archive_id=None, archive=None):
    if archive is not None:
        digest = digest or _field(archive, "digest", "archive_digest", "sha256", "checksum")
        archive_id = archive_id or _field(archive, "archive_id", "id", "name", "label")
    digest = str(digest).strip() if digest is not None else None
    archive_id = str(archive_id).strip() if archive_id is not None else None
    key = digest or "id:" + (archive_id or "")
    return key, digest, archive_id


def coerce_datetime(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, date):
        moment = datetime(value.year, value.month, value.day)
    elif isinstance(value, (int, float)):
        moment = datetime.fromtimestamp(value, timezone.utc)
    else:
        text = str(value).strip().replace("Z", "+00:00")
        moment = datetime.fromisoformat(text)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def planning_bounds(start=None, end=None, at=None, as_of=None, window=None):
    moment = at if at is not None else as_of
    if moment is not None:
        point = coerce_datetime(moment)
        return point, point

    if window is not None and start is None and end is None:
        if isinstance(window, (tuple, list)) and len(window) == 2:
            start, end = window
        elif isinstance(window, dict):
            start = _field(window, "start", "starts_at", "begin")
            end = _field(window, "end", "ends_at", "finish")
        else:
            start = _field(window, "start", "starts_at", "begin")
            end = _field(window, "end", "ends_at", "finish")

    start = coerce_datetime(start)
    end = coerce_datetime(end)
    if start is None and end is None:
        point = datetime.now(timezone.utc)
        return point, point
    if start is None:
        start = end
    if end is None:
        end = start
    if start > end:
        start, end = end, start
    return start, end


class TimeWindow(object):
    """An availability interval for one or more custodians."""

    def __init__(self, window_id=None, custodian=None, start=None, end=None,
                 custodians=None, group=None, groups=None, **metadata):
        if window_id is None:
            window_id = _field(metadata, "id", "name", "window")
        self.id = str(window_id) if window_id is not None else None
        ids = list(_as_list(custodians))
        if custodian is not None:
            ids.append(custodian)
        ids.extend(_as_list(_field(metadata, "custodian_ids", "owners")))
        self.custodians = tuple(dict.fromkeys(str(item) for item in ids if item is not None))
        self.start = coerce_datetime(_first(metadata, "starts_at", "begin", "valid_from") or start)
        self.end = coerce_datetime(_first(metadata, "ends_at", "finish", "valid_until") or end)
        self.group = group or _field(metadata, "custody_group", "group_name")
        group_ids = list(_as_list(groups))
        if self.group is not None:
            group_ids.append(self.group)
        self.groups = tuple(str(item) for item in group_ids if item is not None)
        self.metadata = metadata

    @classmethod
    def coerce(cls, value, **overrides):
        if isinstance(value, TimeWindow):
            return value
        if isinstance(value, dict):
            params = dict(value)
            params.update(overrides)
            return cls(**params)
        if isinstance(value, (tuple, list)) and len(value) == 2:
            params = dict(overrides)
            params["start"], params["end"] = value
            return cls(**params)
        raise RecoveryPlanningError("unsupported custodian window: %r" % (value,))

    def to_dict(self):
        return {
            "id": self.id,
            "custodians": list(self.custodians),
            "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat() if self.end else None,
            "group": self.group,
            "groups": list(self.groups),
        }


class KeyRecord(object):
    """Full fingerprint registration and checkout metadata for one key."""

    def __init__(self, fingerprint=None, public_key=None, key=None,
                 valid_from=None, not_before=None, created=None,
                 expires_at=None, valid_until=None, expiration=None,
                 custodians=None, custodian_ids=None, windows=None,
                 window_ids=None, group=None, groups=None, **metadata):
        source = fingerprint
        if isinstance(source, KeyRecord):
            other = source
            self.fingerprint = other.fingerprint
            self.public_key = other.public_key
            self.created = other.created
            self.expires_at = other.expires_at
            self.custodians = set(other.custodians)
            self.window_ids = tuple(other.window_ids)
            self.group = other.group
            self.groups = tuple(other.groups)
            self.metadata = dict(other.metadata)
            return

        pgp_key = public_key if public_key is not None else key
        if fingerprint is None and pgp_key is not None and hasattr(pgp_key, "fingerprint"):
            fingerprint = pgp_key.fingerprint
        self.fingerprint = normalize_fingerprint(fingerprint)
        self.key_id = self.fingerprint[-16:]
        self.short_id = self.fingerprint[-8:]
        self.public_key = None

        self.created = coerce_datetime(created or valid_from or not_before)
        self.expires_at = coerce_datetime(expires_at or valid_until or expiration)
        self.custodians = set(str(item) for item in _as_list(custodians) + _as_list(custodian_ids))
        self.window_ids = tuple(str(item) for item in _as_list(windows) + _as_list(window_ids))
        self.group = group
        self.groups = tuple(str(item) for item in _as_list(groups))
        self.metadata = metadata

        if pgp_key is not None:
            self.bind_public_key(pgp_key)

    @classmethod
    def coerce(cls, value, **overrides):
        if isinstance(value, KeyRecord):
            return KeyRecord(value, **overrides) if overrides else value
        if isinstance(value, PGPKey):
            return cls(public_key=value, **overrides)
        if isinstance(value, str) and "-----BEGIN PGP" in value:
            return cls(public_key=value, **overrides)
        if isinstance(value, dict):
            params = dict(value)
            params.update(overrides)
            return cls(**params)
        return cls(fingerprint=value, **overrides)

    def bind_public_key(self, value):
        if isinstance(value, str) and "PRIVATE KEY BLOCK" in value:
            raise PrivateKeyMaterialError("planner accepts public keys only")

        loaded = value
        if isinstance(value, (str, bytes, bytearray)):
            if isinstance(value, str) and "PRIVATE KEY BLOCK" in value:
                raise PrivateKeyMaterialError("planner accepts public keys only")
            loaded = PGPKey.from_blob(value)
            if isinstance(loaded, tuple):
                loaded = loaded[0]

        if not isinstance(loaded, PGPKey):
            raise RecoveryPlanningError("could not load public test key")
        if not loaded.is_public:
            raise PrivateKeyMaterialError("planner accepts public keys only")

        fingerprint = normalize_fingerprint(loaded.fingerprint)
        if self.fingerprint and self.fingerprint != fingerprint:
            raise RecoveryPlanningError("fingerprint does not match supplied public key")
        self.fingerprint = fingerprint
        self.key_id = fingerprint[-16:]
        self.short_id = fingerprint[-8:]
        self.public_key = loaded
        if self.created is None:
            self.created = coerce_datetime(getattr(loaded, "created", None))
        if self.expires_at is None:
            self.expires_at = coerce_datetime(getattr(loaded, "expires_at", None))

    def validity(self, start, end):
        if self.created is not None and self.created > start:
            return Report(code="not_yet_valid", valid=False,
                          detail="key was created after the planning window started")
        if self.expires_at is not None and self.expires_at <= start:
            return Report(code="expired", valid=False,
                          detail="key expired before the planning window")
        if self.expires_at is not None and self.expires_at <= end:
            return Report(code="expires_during_window", valid=False,
                          detail="key is not valid throughout the requested window")
        return Report(code="valid", valid=True, detail=None)

    def to_dict(self):
        return {
            "fingerprint": self.fingerprint,
            "key_id": self.key_id,
            "short_id": self.short_id,
            "created": self.created.isoformat() if self.created else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "custodians": sorted(self.custodians),
            "window_ids": list(self.window_ids),
            "group": self.group,
            "groups": list(self.groups),
        }


class KeyRecord(object):
    """Full-fingerprint key registry entry and checkout metadata."""

    def __init__(self, fingerprint=None, public_key=None, key=None, pgp_key=None,
                 valid_from=None, not_before=None, created=None, expires_at=None,
                 valid_until=None, expiration=None, custodians=None,
                 custodian_ids=None, windows=None, window_ids=None, **metadata):
        source_key = public_key if public_key is not None else key
        source_key = source_key if source_key is not None else pgp_key
        if fingerprint is None and source_key is not None and not isinstance(source_key, (str, bytes, bytearray)):
            fingerprint = _field(source_key, "fingerprint")
        self.fingerprint = normalize_fingerprint(fingerprint)
        self.key_id = self.fingerprint[-16:]
        self.short_id = self.fingerprint[-8:]
        self.created = coerce_datetime(created or valid_from or not_before)
        self.expires_at = coerce_datetime(expires_at or valid_until or expiration)
        self.custodians = set(str(item) for item in _as_list(custodians or custodian_ids))
        self.window_ids = [str(item) for item in _as_list(windows or window_ids)]
        self.metadata = metadata
        self.public_key = None
        if source_key is not None:
            self.bind_public_key(source_key)

    @classmethod
    def coerce(cls, value, **overrides):
        if isinstance(value, KeyRecord):
            return value
        if isinstance(value, PGPKey):
            return cls(public_key=value, **overrides)
        if isinstance(value, str) and ("BEGIN PGP PUBLIC KEY BLOCK" in value or os.path.exists(value)):
            return cls(public_key=value, **overrides)
        if isinstance(value, (str, bytes, bytearray)):
            return cls(fingerprint=value, **overrides)
        if isinstance(value, dict):
            params = dict(value)
            params.update(overrides)
            return cls(**params)
        raise RecoveryPlanningError("unsupported key registry entry: %r" % (value,))

    def bind_public_key(self, source):
        key = _load_public_key(source)
        if not key.is_public:
            raise PrivateKeyMaterialError("recovery planner accepts public keys only")
        fingerprint = normalize_fingerprint(key.fingerprint)
        if self.fingerprint and self.fingerprint != fingerprint:
            raise RecoveryPlanningError("fingerprint does not match supplied public key")
        self.fingerprint = fingerprint
        self.key_id = fingerprint[-16:]
        self.short_id = fingerprint[-8:]
        self.public_key = key
        if self.created is None:
            self.created = coerce_datetime(getattr(key, "created", None))
        if self.expires_at is None:
            self.expires_at = coerce_datetime(getattr(key, "expires_at", None))

    def validity(self, start, end):
        if self.created is not None and self.created > start:
            return Report(code="not_yet_valid", valid=False,
                           detail="key was created after the planning window started")
        if self.expires_at is not None and self.expires_at <= start:
            return Report(code="expired", valid=False,
                           detail="key expired before the planning window")
        if self.expires_at is not None and self.expires_at <= end:
            return Report(code="expires_during_window", valid=False,
                           detail="key does not remain valid through the planning window")
        return Report(code="valid", valid=True)

    def to_dict(self):
        return {
            "fingerprint": self.fingerprint,
            "key_id": self.key_id,
            "short_id": self.short_id,
            "created": self.created.isoformat() if self.created else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "custodians": sorted(self.custodians),
            "window_ids": list(self.window_ids),
            "validity": None,
        }


def _load_public_key(source):
    if isinstance(source, PGPKey):
        return source
    if isinstance(source, (bytes, bytearray)):
        text = bytes(source).decode("utf-8", "replace")
        if "PRIVATE KEY BLOCK" in text:
            raise PrivateKeyMaterialError("private key armor was not loaded")
        loaded = PGPKey.from_blob(bytes(source))
    elif isinstance(source, str) and os.path.exists(source):
        with open(source, "r", encoding="utf-8") as handle:
            first = handle.read(64)
        if "PRIVATE KEY BLOCK" in first:
            raise PrivateKeyMaterialError("private key file was not loaded")
        loaded = PGPKey.from_file(source)
    else:
        text = str(source)
        if "PRIVATE KEY BLOCK" in text:
            raise PrivateKeyMaterialError("private key armor was not loaded")
        loaded = PGPKey.from_blob(text)

    if isinstance(loaded, tuple):
        return loaded[0]
    return loaded


class HeaderReport(object):
    """Visible PKESK recipient information from an archive header."""

    def __init__(self, recipients=None, encrypted=False, source=None, error=None):
        self.source = source
        self.error = error
        self.encrypted = bool(encrypted or recipients)
        self.recipients = []
        for item in _as_list(recipients):
            if isinstance(item, Report):
                recipient = item
            elif isinstance(item, dict):
                recipient = Report(item)
            else:
                key_id = normalize_key_identifier(item)
                recipient = Report(
                    key_id=key_id,
                    short_id=key_id[-8:],
                    hidden=set(key_id) == {"0"},
                    algorithm=None,
                    version=None,
                )
            recipient.setdefault("short_id", recipient.key_id[-8:])
            recipient.setdefault("hidden", set(recipient.key_id) == {"0"})
            self.recipients.append(recipient)

        self.recipient_key_ids = tuple(item.key_id for item in self.recipients)
        self.hidden_recipient_count = sum(1 for item in self.recipients if item.hidden)
        self.ok = error is None

    @property
    def encrypters(self):
        return set(self.recipient_key_ids)

    @property
    def hidden(self):
        return self.hidden_recipient_count > 0

    def to_dict(self):
        return {
            "ok": self.ok,
            "error": self.error,
            "encrypted": self.encrypted,
            "recipient_key_ids": list(self.recipient_key_ids),
            "hidden_recipient_count": self.hidden_recipient_count,
            "recipients": [dict(item) for item in self.recipients],
        }


def _header_from_mapping(value):
    recipients = _field(value, "recipients", "recipient_packets")
    if recipients is None:
        recipients = []
        for name in ("recipient_key_ids", "key_ids", "encrypters", "recipient_ids"):
            recipients.extend(_as_list(_field(value, name)))
    return HeaderReport(
        recipients=recipients,
        encrypted=_field(value, "encrypted", "is_encrypted", default=bool(recipients)),
        source=_field(value, "source", "path", "file"),
        error=_field(value, "error"),
    )


def _load_message(source):
    if isinstance(source, PGPMessage):
        return source
    if hasattr(source, "read"):
        data = source.read()
        if isinstance(data, str):
            data = data.encode("utf-8")
        return PGPMessage.from_blob(data)
    if isinstance(source, (bytes, bytearray)):
        return PGPMessage.from_blob(source)
    if isinstance(source, os.PathLike):
        return PGPMessage.from_file(os.fspath(source))
    if isinstance(source, str) and os.path.exists(source):
        return PGPMessage.from_file(source)
    return PGPMessage.from_blob(source)


def inspect_archive_header(source, strict=True):
    """Read only PKESK recipient headers from an encrypted archive.

    This function never calls :meth:`PGPMessage.decrypt`; PGPy parsing exposes
    the unencrypted Public-Key Encrypted Session Key packets directly.
    """
    if isinstance(source, HeaderReport):
        return source
    if source is None:
        raise RecoveryPlanningError("archive header source is required")
    if isinstance(source, dict):
        return _header_from_mapping(source)
    if isinstance(source, (list, tuple, set, frozenset)):
        return HeaderReport(recipients=source, encrypted=True)

    try:
        message = _load_message(source)
        recipients = []
        for packet in getattr(message, "_sessionkeys", []):
            if not isinstance(packet, PKESessionKey):
                continue
            key_id = normalize_key_identifier(getattr(packet, "encrypter", ""))
            recipients.append(Report(
                key_id=key_id,
                short_id=key_id[-8:],
                hidden=key_id == WILDCARD_KEY_ID or set(key_id) == {"0"},
                algorithm=getattr(getattr(packet, "pkalg", None), "name", None),
                version=getattr(packet, "version", None),
            ))
        return HeaderReport(
            recipients=recipients,
            encrypted=getattr(message, "is_encrypted", bool(recipients)),
            source=str(source) if isinstance(source, (str, os.PathLike)) else None,
        )
    except Exception as exc:
        if strict:
            raise
        return HeaderReport(recipients=[], encrypted=False, error="%s: %s" % (type(exc).__name__, exc))


inspect_header = inspect_archive_header
read_archive_header = inspect_archive_header


class Loan(tuple):
    """One borrowed key scheduled in one custodian overlap window."""

    def __new__(cls, fingerprint, window_ids, custodians, archive_ids,
                start=None, end=None, groups=None):
        window_ids = tuple(window_ids)
        custodians = tuple(custodians)
        self = super(Loan, cls).__new__(cls, (fingerprint, window_ids, custodians))
        self.fingerprint = fingerprint
        self.window_ids = window_ids
        self.custodians = custodians
        self.archive_ids = tuple(archive_ids)
        self.start = start
        self.end = end
        self.groups = tuple(groups or ())
        return self

    def __getitem__(self, key):
        if isinstance(key, str):
            if key == "fingerprint":
                return self.fingerprint
            if key in ("windows", "window_ids"):
                return list(self.window_ids)
            if key == "custodians":
                return list(self.custodians)
            if key in ("archives", "archive_ids", "covered_archives"):
                return list(self.archive_ids)
            if key == "start":
                return self.start.isoformat() if self.start else None
            if key == "end":
                return self.end.isoformat() if self.end else None
            raise KeyError(key)
        return super(Loan, self).__getitem__(key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def to_dict(self):
        return {
            "fingerprint": self.fingerprint,
            "window_ids": list(self.window_ids),
            "custodians": list(self.custodians),
            "archive_ids": list(self.archive_ids),
            "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat() if self.end else None,
            "groups": list(self.groups),
        }


class Plan(Report):
    """Optimized coverage result with window-removal what-if plans."""

    def without_window(self, window_id):
        alternatives = self.get("window_plans", {})
        if window_id not in alternatives:
            raise KeyError(window_id)
        return alternatives[window_id]


class RecoveryPlanner(object):
    """Register public headers/manifests and optimize key loans."""

    def __init__(self, **options):
        self.options = options
        self.key_records = {}
        self.attestations = {}
        self.archives = {}
        self.windows = {}
        self.custodian_groups = {}
        self.require_distinct_groups = bool(options.get("require_distinct_groups", False))
        self.strict_manifest = bool(options.get("strict_manifest", False))

    def register_key(self, record=None, **kwargs):
        if record is None:
            record = kwargs
        key = KeyRecord.coerce(record, **kwargs) if not isinstance(record, KeyRecord) else record
        self.key_records[key.fingerprint] = key
        return key

    add_key = register_key

    def register_keys(self, records):
        if isinstance(records, dict):
            for fingerprint, record in records.items():
                if isinstance(record, KeyRecord):
                    self.key_records[record.fingerprint] = record
                elif isinstance(record, dict):
                    params = dict(record)
                    params.setdefault("fingerprint", fingerprint)
                    self.register_key(**params)
                else:
                    self.register_key(fingerprint=fingerprint, public_key=record)
        else:
            for record in _as_list(records):
                self.register_key(record)
        return self.key_records

    add_keys = register_keys

    def register_window(self, window=None, **kwargs):
        record = TimeWindow.coerce(window, **kwargs) if window is not None else TimeWindow(**kwargs)
        if record.id is None:
            record.id = "window-%d" % (len(self.windows) + 1,)
        if record.id in self.windows:
            existing = self.windows[record.id]
            ids = tuple(dict.fromkeys(existing.custodians + record.custodians))
            existing.custodians = ids
            existing.groups = tuple(dict.fromkeys(existing.groups + record.groups))
            return existing
        self.windows[record.id] = record
        for custodian in record.custodians:
            self.custodian_groups.setdefault(custodian, record.group)
        return record

    add_window = register_window

    def register_custodian(self, custodian=None, custodian_id=None, group=None,
                           windows=None, availability=None, slots=None, **kwargs):
        cid = custodian_id or custodian or _field(kwargs, "id", "name")
        if cid is None:
            raise RecoveryPlanningError("custodian id is required")
        cid = str(cid)
        if group is not None:
            self.custodian_groups[cid] = group
        for item in _as_list(windows or availability or slots):
            if isinstance(item, TimeWindow):
                item.custodians = tuple(dict.fromkeys(item.custodians + (cid,)))
                self.register_window(item)
            elif isinstance(item, dict):
                params = dict(item)
                params.setdefault("custodian", cid)
                self.register_window(**params)
            else:
                self.register_window(custodian=cid, start=item[0], end=item[1])
        return cid

    def register_custodians(self, custodians):
        if isinstance(custodians, dict):
            for cid, value in custodians.items():
                if isinstance(value, dict):
                    self.register_custodian(custodian_id=cid, **value)
                else:
                    self.register_custodian(custodian_id=cid, windows=value)
        else:
            for item in _as_list(custodians):
                if isinstance(item, dict):
                    self.register_custodian(**item)
                else:
                    self.register_custodian(custodian=item)
        return self.custodian_groups

    add_custodian = register_custodian
    add_custodians = register_custodians
