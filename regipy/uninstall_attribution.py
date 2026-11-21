"""Read-only attributed uninstall analysis across registry collection snapshots.

The analyzer joins evidence from a machine SOFTWARE hive and zero or more
per-user NTUSER.DAT hives. It deliberately works only on hive objects (or the
small in-memory fixtures used by tests); it never reads the live registry and
never checks the filesystem for an install location.

Identity is deliberately composite: ``(subject_kind, subject_id, product_id)``.
A product code seen in the machine uninstall view is therefore a different
attribution from the same product code in a user's hive.
"""

import binascii
import logging
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, Optional

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "1.0"

STATE_INSTALLED = "installed"
STATE_EXPLICIT_UNINSTALL = "explicit_uninstall"
STATE_MANUAL_RESIDUE = "manual_residue"
STATE_UNDETERMINED = "undetermined"

SUBJECT_MACHINE = "machine"
SUBJECT_USER = "user"

EVIDENCE_UNINSTALL_REGISTRATION = "uninstall_registration"
EVIDENCE_INSTALLER_PRODUCT = "installer_product"
EVIDENCE_INSTALLER_USER_DATA = "installer_user_data"

SOFTWARE_UNINSTALL_PATH = r"\Microsoft\Windows\CurrentVersion\Uninstall"
SOFTWARE_WOW64_UNINSTALL_PATH = r"\Wow6432Node" + SOFTWARE_UNINSTALL_PATH
NTUSER_UNINSTALL_PATH = r"\Software\Microsoft\Windows\CurrentVersion\Uninstall"

SOFTWARE_INSTALLER_PRODUCTS_PATH = r"\Classes\Installer\Products"
SOFTWARE_INSTALLER_USER_DATA_PATH = r"\Microsoft\Windows\CurrentVersion\Installer\UserData"
NTUSER_INSTALLER_PRODUCTS_PATH = r"\Software\Microsoft\Installer\Products"
PROFILE_LIST_PATH = r"\Microsoft\Windows NT\CurrentVersion\ProfileList"

_GUID_RE = re.compile(r"^\{?([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})\}?$")
_PACKED_GUID_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return binascii.b2a_hex(value).decode()
    if isinstance(value, Mapping):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(x) for x in value]
    isoformat = getattr(value, "isoformat", None)
    if callable(isoformat):
        return isoformat()
    return str(value)


def _compact_guid(value: str) -> Optional[str]:
    match = _GUID_RE.match(value.strip())
    if not match:
        return None
    return "".join(match.groups()).upper()


def normalize_product_code(value: Optional[str]) -> Optional[str]:
    """Return a canonical braced GUID, or ``None`` for a non-GUID identifier."""

    if not value:
        return None
    compact = _compact_guid(value)
    if compact is None:
        return None
    return (f"{{{compact[0:8]}-{compact[8:12]}-{compact[12:16]}-{compact[16:20]}-{compact[20:32]}}}").upper()


def pack_product_code(product_code: str) -> str:
    """Convert a Windows Installer ProductCode GUID to its packed key form.

    This is the representation used below ``Installer\\Products`` and
    ``Installer\\UserData\\<SID>\\Products``. If the input is not a GUID it is
    returned unchanged so callers can still use it as an opaque key.
    """

    compact = _compact_guid(product_code)
    if compact is None:
        return product_code
    return (
        compact[0:8][::-1]
        + compact[8:12][::-1]
        + compact[12:16][::-1]
        + compact[16:20][::-1]
        + "".join(compact[i : i + 2][::-1] for i in range(20, 32, 2))
    )


def unpack_product_code(packed_product_code: str) -> Optional[str]:
    """Inverse of :func:`pack_product_code` for a 32-hex-character key."""

    packed = packed_product_code.strip()
    if not _PACKED_GUID_RE.match(packed):
        return None
    compact = (
        packed[0:8][::-1]
        + packed[8:12][::-1]
        + packed[12:16][::-1]
        + packed[16:20][::-1]
        + "".join(packed[i : i + 2][::-1] for i in range(20, 32, 2))
    )
    return (f"{{{compact[0:8]}-{compact[8:12]}-{compact[12:16]}-{compact[16:20]}-{compact[20:32]}}}").upper()


@dataclass
class UserHive:
    """A user hive and the identity it should be attributed to."""

    subject_id: str
    hive: Any
    profile_path: Optional[str] = None
    display_name: Optional[str] = None

    def label(self) -> str:
        if self.display_name:
            return self.display_name
        if self.profile_path:
            normalized = self.profile_path.rstrip("\\/")
            leaf = re.split(r"[\\/]", normalized)[-1]
            if leaf:
                return leaf
        return self.subject_id


@dataclass
class CollectionSnapshot:
    """One read-only collection of machine and optional user hives."""

    collection_id: str
    software_hive: Optional[Any] = None
    user_hives: Any = field(default_factory=list)
    expected_user_ids: Any = field(default_factory=set)
    machine_id: str = SUBJECT_MACHINE
    captured_at: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized_users: list[UserHive] = []
        if isinstance(self.user_hives, Mapping):
            for subject_id, hive in self.user_hives.items():
                normalized_users.append(UserHive(subject_id=str(subject_id), hive=hive))
        else:
            for item in self.user_hives or []:
                if isinstance(item, UserHive):
                    normalized_users.append(item)
                elif isinstance(item, (tuple, list)) and len(item) == 2:
                    normalized_users.append(UserHive(subject_id=str(item[0]), hive=item[1]))
                else:
                    raise TypeError("user_hives must contain UserHive objects, pairs, or a mapping")
        self.user_hives = normalized_users
        if self.expected_user_ids is None:
            self.expected_user_ids = set()
        else:
            self.expected_user_ids = {str(x) for x in self.expected_user_ids}

    @property
    def machine_hive(self) -> Optional[Any]:
        return self.software_hive

    def with_user_hive(
        self,
        subject_id: str,
        hive: Any,
        profile_path: Optional[str] = None,
        display_name: Optional[str] = None,
    ) -> "CollectionSnapshot":
        users = [user for user in self.user_hives if user.subject_id.casefold() != subject_id.casefold()]
        users.append(
            UserHive(
                subject_id=subject_id,
                hive=hive,
                profile_path=profile_path,
                display_name=display_name,
            )
        )
        return CollectionSnapshot(
            collection_id=self.collection_id,
            software_hive=self.software_hive,
            user_hives=users,
            expected_user_ids=set(self.expected_user_ids),
            machine_id=self.machine_id,
            captured_at=self.captured_at,
            metadata=dict(self.metadata),
        )


@dataclass
class Evidence:
    evidence_id: str
    collection_id: str
    kind: str
    subject_kind: str
    subject_id: str
    product_id: str
    path: str
    timestamp: Optional[str] = None
    values: dict[str, Any] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "collection_id": self.collection_id,
            "kind": self.kind,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "product_id": self.product_id,
            "path": self.path,
            "timestamp": self.timestamp,
            "values": _json_safe(self.values),
            "details": _json_safe(self.details),
        }


@dataclass
class _SnapshotData:
    snapshot: CollectionSnapshot
    registrations: list[Evidence] = field(default_factory=list)
    contexts: list[Evidence] = field(default_factory=list)
    profiles: dict[str, str] = field(default_factory=dict)
    observed_subjects: set[tuple[str, str]] = field(default_factory=set)
    user_labels: dict[str, str] = field(default_factory=dict)


def _safe_get_key(hive: Any, path: str) -> Optional[Any]:
    if hive is None:
        return None
    try:
        return hive.get_key(path)
    except RegistryKeyNotFoundException:
        return None


def _iter_subkeys(key: Any) -> list[Any]:
    if key is None:
        return []
    try:
        subkeys = key.iter_subkeys()
    except RegistryKeyNotFoundException:
        return []
    if subkeys is None:
        return []
    return list(subkeys)


def _iter_values(key: Any) -> list[Any]:
    if key is None:
        return []
    try:
        values = key.iter_values(as_json=True)
    except RegistryKeyNotFoundException:
        return []
    if values is None:
        return []
    return list(values)


def _values_dict(key: Any) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for value in _iter_values(key):
        values[str(value.name)] = _json_safe(value.value)
    return values


def _key_timestamp(key: Any) -> Optional[str]:
    header = getattr(key, "header", None)
    raw = getattr(header, "last_modified", None)
    if raw is None:
        return None
    if isinstance(raw, str):
        return raw
    try:
        converted = convert_wintime(raw, as_json=True)
    except (TypeError, ValueError, OverflowError):
        return str(raw)
    return converted if isinstance(converted, str) else str(converted)


def _clean_product_id(key_name: str, values: Mapping[str, Any]) -> str:
    product_code = values.get("ProductCode")
    if isinstance(product_code, str):
        normalized = normalize_product_code(product_code)
        if normalized:
            return normalized

    normalized_key = normalize_product_code(key_name)
    if normalized_key:
        return normalized_key

    unpacked = unpack_product_code(key_name)
    if unpacked:
        return unpacked

    return key_name


def _product_match_key(product_id: str) -> str:
    normalized = normalize_product_code(product_id)
    if normalized:
        return normalized.lower()
    return product_id.casefold()


def _subject_match_key(subject_kind: str, subject_id: str) -> tuple[str, str]:
    return subject_kind, subject_id.casefold()


def _display_name(values: Mapping[str, Any], fallback: Optional[str] = None) -> Optional[str]:
    for name in ("DisplayName", "ProductName", "ParentDisplayName", "PackageName"):
        value = values.get(name)
        if isinstance(value, str) and value.strip():
            return value
    return fallback


def _evidence_id(
    collection_id: str,
    subject_kind: str,
    subject_id: str,
    kind: str,
    product_id: str,
    discriminator: Optional[str] = None,
) -> str:
    suffix = f"|{discriminator}" if discriminator else ""
    return f"{collection_id}|{subject_kind}:{subject_id}|{kind}|{_product_match_key(product_id)}{suffix}"


def _missing_evidence_id(collection_id: str, subject_kind: str, subject_id: str, kind: str) -> str:
    return f"{collection_id}|{subject_kind}:{subject_id}|missing|{kind}"


def _make_uninstall_evidence(
    key: Any,
    collection_id: str,
    subject_kind: str,
    subject_id: str,
    registry_path: str,
    architecture: str,
) -> Evidence:
    values = _values_dict(key)
    product_id = _clean_product_id(str(key.name), values)
    return Evidence(
        evidence_id=_evidence_id(
            collection_id,
            subject_kind,
            subject_id,
            EVIDENCE_UNINSTALL_REGISTRATION,
            product_id,
            architecture,
        ),
        collection_id=collection_id,
        kind=EVIDENCE_UNINSTALL_REGISTRATION,
        subject_kind=subject_kind,
        subject_id=subject_id,
        product_id=product_id,
        path=registry_path,
        timestamp=_key_timestamp(key),
        values=values,
        details={
            "architecture": architecture,
            "key_name": str(key.name),
            "product_name": _display_name(values),
        },
    )


def _make_context_evidence(
    key: Any,
    collection_id: str,
    subject_kind: str,
    subject_id: str,
    registry_path: str,
    kind: str,
    product_key_name: Optional[str] = None,
) -> Evidence:
    values = _values_dict(key)
    key_name = product_key_name or str(key.name)
    product_id = _clean_product_id(key_name, values)
    return Evidence(
        evidence_id=_evidence_id(
            collection_id,
            subject_kind,
            subject_id,
            kind,
            product_id,
            key_name.casefold(),
        ),
        collection_id=collection_id,
        kind=kind,
        subject_kind=subject_kind,
        subject_id=subject_id,
        product_id=product_id,
        path=registry_path,
        timestamp=_key_timestamp(key),
        values=values,
        details={
            "key_name": key_name,
            "product_name": _display_name(values),
        },
    )


def _read_profiles(software_hive: Any) -> dict[str, str]:
    profiles: dict[str, str] = {}
    key = _safe_get_key(software_hive, PROFILE_LIST_PATH)
    for profile_key in _iter_subkeys(key):
        profile_path = profile_key.get_value("ProfileImagePath") if hasattr(profile_key, "get_value") else None
        if isinstance(profile_path, str):
            profiles[str(profile_key.name)] = profile_path
    return profiles


def _collect_uninstall_entries(
    hive: Any,
    collection_id: str,
    subject_kind: str,
    subject_id: str,
    paths: Sequence[tuple[str, str]],
) -> list[Evidence]:
    evidence: list[Evidence] = []
    for path, architecture in paths:
        uninstall_key = _safe_get_key(hive, path)
        for product_key in _iter_subkeys(uninstall_key):
            evidence.append(
                _make_uninstall_evidence(
                    product_key,
                    collection_id=collection_id,
                    subject_kind=subject_kind,
                    subject_id=subject_id,
                    registry_path=path,
                    architecture=architecture,
                )
            )
    return evidence


def _collect_installer_products(
    hive: Any,
    collection_id: str,
    subject_kind: str,
    subject_id: str,
    base_path: str,
) -> list[Evidence]:
    evidence: list[Evidence] = []
    products_key = _safe_get_key(hive, base_path)
    for product_key in _iter_subkeys(products_key):
        evidence.append(
            _make_context_evidence(
                product_key,
                collection_id=collection_id,
                subject_kind=subject_kind,
                subject_id=subject_id,
                registry_path=base_path,
                kind=EVIDENCE_INSTALLER_PRODUCT,
            )
        )
    return evidence


def _collect_installer_user_data(
    software_hive: Any,
    collection_id: str,
    machine_id: str,
) -> list[Evidence]:
    evidence: list[Evidence] = []
    user_data_key = _safe_get_key(software_hive, SOFTWARE_INSTALLER_USER_DATA_PATH)
    for sid_key in _iter_subkeys(user_data_key):
        sid = str(sid_key.name)
        products_path = rf"{SOFTWARE_INSTALLER_USER_DATA_PATH}\{sid}\Products"
        products_key = _safe_get_key(software_hive, products_path)
        for product_key in _iter_subkeys(products_key):
            properties_path = rf"{products_path}\{product_key.name}\InstallProperties"
            properties_key = _safe_get_key(software_hive, properties_path) or product_key
            item = _make_context_evidence(
                properties_key,
                collection_id=collection_id,
                subject_kind=SUBJECT_USER,
                subject_id=sid,
                registry_path=properties_path if properties_key is not product_key else products_path,
                kind=EVIDENCE_INSTALLER_USER_DATA,
                product_key_name=str(product_key.name),
            )
            item.details["sid"] = sid
            item.details["machine_id"] = machine_id
            evidence.append(item)
    return evidence


def _collect_snapshot(snapshot: Optional[CollectionSnapshot]) -> Optional[_SnapshotData]:
    if snapshot is None:
        return None

    data = _SnapshotData(snapshot=snapshot)
    if snapshot.software_hive is not None:
        data.observed_subjects.add(_subject_match_key(SUBJECT_MACHINE, snapshot.machine_id))
        data.registrations.extend(
            _collect_uninstall_entries(
                snapshot.software_hive,
                snapshot.collection_id,
                SUBJECT_MACHINE,
                snapshot.machine_id,
                [
                    (SOFTWARE_UNINSTALL_PATH, "64-bit"),
                    (SOFTWARE_WOW64_UNINSTALL_PATH, "32-bit"),
                ],
            )
        )
        data.contexts.extend(
            _collect_installer_products(
                snapshot.software_hive,
                snapshot.collection_id,
                SUBJECT_MACHINE,
                snapshot.machine_id,
                SOFTWARE_INSTALLER_PRODUCTS_PATH,
            )
        )
        data.contexts.extend(
            _collect_installer_user_data(
                snapshot.software_hive,
                snapshot.collection_id,
                snapshot.machine_id,
            )
        )
        data.profiles = _read_profiles(snapshot.software_hive)

    for user_hive in snapshot.user_hives:
        label = user_hive.label()
        data.user_labels[user_hive.subject_id] = label
        data.observed_subjects.add(_subject_match_key(SUBJECT_USER, user_hive.subject_id))
        data.registrations.extend(
            _collect_uninstall_entries(
                user_hive.hive,
                snapshot.collection_id,
                SUBJECT_USER,
                user_hive.subject_id,
                [(NTUSER_UNINSTALL_PATH, "user")],
            )
        )
        data.contexts.extend(
            _collect_installer_products(
                user_hive.hive,
                snapshot.collection_id,
                SUBJECT_USER,
                user_hive.subject_id,
                NTUSER_INSTALLER_PRODUCTS_PATH,
            )
        )

    for sid, profile_path in data.profiles.items():
        if sid not in data.user_labels:
            normalized = profile_path.rstrip("\\/")
            leaf = re.split(r"[\\/]", normalized)[-1]
            data.user_labels[sid] = leaf or sid

    return data


def _subject_key(evidence: Evidence) -> tuple[str, str, str]:
    return (
        evidence.subject_kind,
        evidence.subject_id.casefold(),
        _product_match_key(evidence.product_id),
    )


def _subject_payload(subject_kind: str, subject_id: str, label: Optional[str]) -> dict[str, Any]:
    return {
        "kind": subject_kind,
        "id": subject_id,
        "label": label or subject_id,
    }


def _coverage_status(
    data: Optional[_SnapshotData],
    subject_kind: str,
    subject_id: str,
) -> str:
    if data is None:
        return "not_captured"
    if _subject_match_key(subject_kind, subject_id) in data.observed_subjects:
        return "observed"
    return "missing"


def _coverage_payload(
    data: Optional[_SnapshotData],
    expected_users: set[str],
    machine_id: str,
) -> dict[str, Any]:
    subjects: list[dict[str, Any]] = []
    machine_status = _coverage_status(data, SUBJECT_MACHINE, machine_id)
    subjects.append(
        {
            "kind": SUBJECT_MACHINE,
            "id": machine_id,
            "label": machine_id,
            "status": machine_status,
        }
    )

    user_ids = set(expected_users)
    if data is not None:
        user_ids.update(user.subject_id for user in data.snapshot.user_hives)
    for sid in sorted(user_ids, key=str.casefold):
        label = data.user_labels.get(sid) if data is not None else None
        status = _coverage_status(data, SUBJECT_USER, sid)
        subjects.append(
            {
                "kind": SUBJECT_USER,
                "id": sid,
                "label": label or sid,
                "status": status,
                **({"reason": "user_hive_not_supplied"} if status == "missing" else {}),
            }
        )

    missing = [item for item in subjects if item["status"] != "observed"]
    return {
        "complete": not missing,
        "subjects": subjects,
        "missing_subjects": missing,
    }


def _merge_registration_values(records: Sequence[Evidence]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for record in records:
        values.update(record.values)
    return values


def _installation_context(
    registrations: Sequence[Evidence],
    contexts: Sequence[Evidence],
) -> dict[str, Any]:
    values = _merge_registration_values(registrations)
    sources = sorted({record.kind for record in contexts})
    install_location = values.get("InstallLocation")
    install_source = values.get("InstallSource")
    uninstall_string = values.get("UninstallString")
    context = {
        "sources": sources,
        "evidence_ids": sorted(record.evidence_id for record in contexts),
        "install_location": install_location,
        "install_source": install_source,
        "uninstall_string": uninstall_string,
        "windows_installer": bool(values.get("WindowsInstaller")),
        "system_component": bool(values.get("SystemComponent")),
        "parent_key_name": values.get("ParentKeyName"),
        "parent_display_name": values.get("ParentDisplayName"),
        "release_type": values.get("ReleaseType"),
    }
    if isinstance(install_location, str) and re.search(r"(?i)(^|[\\/])users[\\/]", install_location):
        context["user_scoped_install_location"] = True
    return context


def _all_evidence_ids(attribution: Mapping[str, Any]) -> set[str]:
    trace = attribution.get("decision_trace", {})
    evidence_ids: set[str] = set()
    for key in ("supporting_evidence", "contrary_evidence", "missing_evidence"):
        evidence_ids.update(trace.get(key, []))
    return evidence_ids


def _empty_coverage_id(collection_id: str, subject_kind: str, subject_id: str) -> str:
    return _missing_evidence_id(collection_id, subject_kind, subject_id, "subject_hive")


def _build_attribution(
    key: tuple[str, str, str],
    subject_kind: str,
    subject_id: str,
    label: Optional[str],
    product_id: str,
    baseline: Optional[_SnapshotData],
    current: _SnapshotData,
    expected_users: set[str],
    machine_id: str,
) -> dict[str, Any]:
    baseline_registrations = [record for record in (baseline.registrations if baseline else []) if _subject_key(record) == key]
    current_registrations = [record for record in current.registrations if _subject_key(record) == key]
    baseline_contexts = [record for record in (baseline.contexts if baseline else []) if _subject_key(record) == key]
    current_contexts = [record for record in current.contexts if _subject_key(record) == key]

    baseline_coverage = _coverage_status(baseline, subject_kind, subject_id)
    current_coverage = _coverage_status(current, subject_kind, subject_id)

    baseline_has_registration = bool(baseline_registrations)
    current_has_registration = bool(current_registrations)
    baseline_has_context = bool(baseline_contexts)
    current_has_context = bool(current_contexts)
    baseline_observed = baseline_coverage == "observed"
    current_observed = current_coverage == "observed"

    supporting: list[str] = []
    contrary: list[str] = []
    missing: list[str] = []

    if current_observed and current_has_registration:
        state = STATE_INSTALLED
        reason = "uninstall_registration_observed"
        confidence = "high"
        supporting.extend(record.evidence_id for record in current_registrations)
        supporting.extend(record.evidence_id for record in current_contexts)
        supporting.extend(record.evidence_id for record in baseline_registrations)
        supporting.extend(record.evidence_id for record in baseline_contexts)
    elif not current_observed:
        state = STATE_UNDETERMINED
        reason = "missing_subject_hive"
        confidence = "low"
        supporting.extend(record.evidence_id for record in baseline_registrations)
        contrary.extend(record.evidence_id for record in baseline_registrations)
        missing.append(_empty_coverage_id(current.snapshot.collection_id, subject_kind, subject_id))
    elif baseline_has_registration and current_has_context:
        state = STATE_MANUAL_RESIDUE
        reason = "registration_removed_but_install_context_persists"
        confidence = "high"
        supporting.extend(record.evidence_id for record in baseline_registrations)
        supporting.extend(record.evidence_id for record in current_contexts)
        contrary.append(
            _missing_evidence_id(
                current.snapshot.collection_id,
                subject_kind,
                subject_id,
                EVIDENCE_UNINSTALL_REGISTRATION,
            )
        )
    elif baseline_has_registration:
        state = STATE_EXPLICIT_UNINSTALL
        reason = "registration_removed_between_complete_collections"
        confidence = "high" if current_observed and baseline_observed else "medium"
        supporting.extend(record.evidence_id for record in baseline_registrations)
        if baseline_has_context:
            supporting.extend(record.evidence_id for record in baseline_contexts)
    elif current_has_context and baseline is not None:
        state = STATE_MANUAL_RESIDUE
        reason = "install_context_without_registration"
        confidence = "medium" if current_observed else "low"
        supporting.extend(record.evidence_id for record in current_contexts)
        contrary.append(
            _missing_evidence_id(
                current.snapshot.collection_id,
                subject_kind,
                subject_id,
                EVIDENCE_UNINSTALL_REGISTRATION,
            )
        )
    elif current_has_context:
        state = STATE_UNDETERMINED
        reason = "install_context_without_baseline"
        confidence = "low"
        supporting.extend(record.evidence_id for record in current_contexts)
    else:
        state = STATE_UNDETERMINED
        reason = "insufficient_evidence"
        confidence = "low"
        if baseline:
            supporting.extend(record.evidence_id for record in baseline_contexts)

    if state in (STATE_INSTALLED, STATE_MANUAL_RESIDUE) and not current_observed:
        # Context-only rows from the SOFTWARE Installer\\UserData subtree can
        # name a user for whom no NTUSER hive was collected. Never turn that
        # into a residue/uninstall conclusion.
        state = STATE_UNDETERMINED
        reason = "missing_subject_hive"
        confidence = "low"
        missing.append(_empty_coverage_id(current.snapshot.collection_id, subject_kind, subject_id))

    supporting = sorted(set(supporting))
    contrary = sorted(set(contrary) - set(supporting))
    missing = sorted(set(missing))

    product_name = (
        _display_name(current_registrations[-1].values)
        if current_registrations
        else _display_name(baseline_registrations[-1].values)
        if baseline_registrations
        else _display_name(current_contexts[-1].values)
        if current_contexts
        else _display_name(baseline_contexts[-1].values)
        if baseline_contexts
        else None
    )

    all_contexts = baseline_contexts + current_contexts
    attribution_key = f"{subject_kind}:{subject_id}:{_product_match_key(product_id)}"
    return {
        "attribution_key": attribution_key,
        "subject": _subject_payload(subject_kind, subject_id, label),
        "subject_kind": subject_kind,
        "subject_id": subject_id,
        "product_id": product_id,
        "product_name": product_name,
        "state": state,
        "reason": reason,
        "confidence": confidence,
        "coverage": {
            "baseline": baseline_coverage,
            "current": current_coverage,
        },
        "installation_context": _installation_context(
            baseline_registrations + current_registrations,
            all_contexts,
        ),
        "baseline": {
            "observed": baseline_observed,
            "registration_evidence": sorted(record.evidence_id for record in baseline_registrations),
            "context_evidence": sorted(record.evidence_id for record in baseline_contexts),
        },
        "current": {
            "observed": current_observed,
            "registration_evidence": sorted(record.evidence_id for record in current_registrations),
            "context_evidence": sorted(record.evidence_id for record in current_contexts),
        },
        "decision_trace": {
            "rule": reason,
            "inputs": {
                "baseline_coverage": baseline_coverage,
                "current_coverage": current_coverage,
                "baseline_registration": baseline_has_registration,
                "current_registration": current_has_registration,
                "baseline_install_context": baseline_has_context,
                "current_install_context": current_has_context,
            },
            "supporting_evidence": supporting,
            "contrary_evidence": contrary,
            "missing_evidence": missing,
        },
    }


def _evidence_by_id(data: Optional[_SnapshotData]) -> dict[str, Evidence]:
    if data is None:
        return {}
    return {record.evidence_id: record for record in data.registrations + data.contexts}


def _value_changes(
    baseline_registrations: Sequence[Evidence],
    current_registrations: Sequence[Evidence],
) -> list[dict[str, Any]]:
    baseline_values = _merge_registration_values(baseline_registrations)
    current_values = _merge_registration_values(current_registrations)
    changed = []
    for name in sorted(set(baseline_values) | set(current_values), key=str.casefold):
        old = baseline_values.get(name)
        new = current_values.get(name)
        if old != new:
            changed.append({"name": name, "baseline": _json_safe(old), "current": _json_safe(new)})
    return changed


def _build_changes(
    baseline: Optional[_SnapshotData],
    current: _SnapshotData,
    all_keys: set[tuple[str, str, str]],
) -> list[dict[str, Any]]:
    if baseline is None:
        return []

    changes: list[dict[str, Any]] = []
    baseline_evidence = _evidence_by_id(baseline)
    current_evidence = _evidence_by_id(current)

    for key in sorted(all_keys):
        baseline_registrations = [
            record for record in (baseline.registrations if baseline else []) if _subject_key(record) == key
        ]
        current_registrations = [record for record in current.registrations if _subject_key(record) == key]
        baseline_contexts = [record for record in (baseline.contexts if baseline else []) if _subject_key(record) == key]
        current_contexts = [record for record in current.contexts if _subject_key(record) == key]

        baseline_ids = {record.evidence_id for record in baseline_registrations + baseline_contexts}
        current_ids = {record.evidence_id for record in current_registrations + current_contexts}
        value_changes = _value_changes(baseline_registrations, current_registrations)

        if (
            baseline is not None
            and bool(baseline_registrations) == bool(current_registrations)
            and bool(baseline_contexts) == bool(current_contexts)
            and not value_changes
            and baseline_ids == current_ids
        ):
            continue

        sample = (current_registrations + current_contexts + baseline_registrations + baseline_contexts)[0]
        subject_kind, _, _ = key
        changes.append(
            {
                "attribution_key": f"{subject_kind}:{sample.subject_id}:{_product_match_key(sample.product_id)}",
                "subject": _subject_payload(subject_kind, sample.subject_id, None),
                "product_id": sample.product_id,
                "product_name": _display_name(sample.values),
                "registration_change": _change_label(
                    baseline_registrations if baseline is not None else None,
                    current_registrations,
                ),
                "install_context_change": _change_label(
                    baseline_contexts if baseline is not None else None,
                    current_contexts,
                ),
                "value_changes": value_changes,
                "evidence_added": sorted(current_ids - baseline_ids),
                "evidence_removed": sorted(baseline_ids - current_ids),
                "sample_evidence_added": [
                    current_evidence[item].to_dict() for item in sorted(current_ids - baseline_ids) if item in current_evidence
                ],
                "sample_evidence_removed": [
                    baseline_evidence[item].to_dict()
                    for item in sorted(baseline_ids - current_ids)
                    if item in baseline_evidence
                ],
            }
        )
    return changes


def _change_label(baseline_records: Optional[Sequence[Evidence]], current_records: Sequence[Evidence]) -> str:
    if baseline_records is None:
        return "not_captured"
    had = bool(baseline_records)
    has = bool(current_records)
    if had and has:
        return "retained"
    if not had and has:
        return "added"
    if had and not has:
        return "removed"
    return "absent"


class UninstallAttributionAnalyzer:
    """Join machine/user uninstall views without mutating or reading live state."""

    def __init__(
        self,
        current: CollectionSnapshot,
        baseline: Optional[CollectionSnapshot] = None,
        machine_id: Optional[str] = None,
    ) -> None:
        self.current = current
        self.baseline = baseline
        self.machine_id = machine_id or current.machine_id or SUBJECT_MACHINE
        if self.current.machine_id != self.machine_id:
            self.current = replace(self.current, machine_id=self.machine_id)
        if self.baseline is not None and self.baseline.machine_id != self.machine_id:
            self.baseline = replace(self.baseline, machine_id=self.machine_id)

    def analyze(self) -> dict[str, Any]:
        baseline_data = _collect_snapshot(self.baseline)
        current_data = _collect_snapshot(self.current)
        assert current_data is not None

        expected_users: set[str] = set()
        if self.baseline is not None:
            expected_users.update(self.baseline.expected_user_ids)
            expected_users.update(user.subject_id for user in self.baseline.user_hives)
        expected_users.update(self.current.expected_user_ids)
        expected_users.update(user.subject_id for user in self.current.user_hives)

        records_by_key: dict[tuple[str, str, str], list[Evidence]] = defaultdict(list)
        for record in baseline_data.registrations + baseline_data.contexts if baseline_data else []:
            records_by_key[_subject_key(record)].append(record)
        for record in current_data.registrations + current_data.contexts:
            records_by_key[_subject_key(record)].append(record)

        attributions: list[dict[str, Any]] = []
        for key in sorted(records_by_key):
            sample = records_by_key[key][0]
            label = None
            if sample.subject_kind == SUBJECT_USER:
                label = (
                    (current_data.user_labels.get(sample.subject_id))
                    or (baseline_data.user_labels.get(sample.subject_id) if baseline_data else None)
                    or current_data.profiles.get(sample.subject_id)
                )
            else:
                label = self.machine_id
            attributions.append(
                _build_attribution(
                    key,
                    sample.subject_kind,
                    sample.subject_id,
                    label,
                    sample.product_id,
                    baseline_data,
                    current_data,
                    expected_users,
                    self.machine_id,
                )
            )

        changes = _build_changes(baseline_data, current_data, set(records_by_key))
        evidence_index: dict[str, Any] = {}
        for data in (baseline_data, current_data):
            for evidence_id, record in _evidence_by_id(data).items():
                evidence_index[evidence_id] = record.to_dict()

        state_counts: dict[str, int] = {}
        for attribution in attributions:
            state = attribution["state"]
            state_counts[state] = state_counts.get(state, 0) + 1

        current_coverage = _coverage_payload(current_data, expected_users, self.machine_id)
        baseline_coverage = _coverage_payload(baseline_data, expected_users, self.machine_id)
        return {
            "schema_version": SCHEMA_VERSION,
            "analysis": "uninstall_attribution",
            "read_only": True,
            "baseline_collection": _collection_payload(self.baseline),
            "current_collection": _collection_payload(self.current),
            "coverage": {
                "complete": current_coverage["complete"],
                "baseline": baseline_coverage,
                "current": current_coverage,
            },
            "summary": {
                "attribution_count": len(attributions),
                "state_counts": dict(sorted(state_counts.items())),
                "change_count": len(changes),
            },
            "attributions": attributions,
            "changes": changes,
            "evidence_index": dict(sorted(evidence_index.items())),
        }


def _collection_payload(snapshot: Optional[CollectionSnapshot]) -> Optional[dict[str, Any]]:
    if snapshot is None:
        return None
    return {
        "collection_id": snapshot.collection_id,
        "captured_at": snapshot.captured_at,
        "machine_id": snapshot.machine_id,
        "software_hive_present": snapshot.software_hive is not None,
        "user_subjects": sorted(user.subject_id for user in snapshot.user_hives),
        "expected_user_subjects": sorted(snapshot.expected_user_ids),
        "metadata": _json_safe(snapshot.metadata),
    }


def analyze_uninstall_attribution(
    current: CollectionSnapshot,
    baseline: Optional[CollectionSnapshot] = None,
    machine_id: Optional[str] = None,
) -> dict[str, Any]:
    """Convenience wrapper around :class:`UninstallAttributionAnalyzer`."""

    return UninstallAttributionAnalyzer(current=current, baseline=baseline, machine_id=machine_id).analyze()


def compare_attribution_reports(previous: Mapping[str, Any], current: Mapping[str, Any]) -> dict[str, Any]:
    """Explain conclusion changes between two attribution reports.

    This is the trace used by the missing-hive demo: the previous report may say
    ``undetermined`` because a subject hive was absent; after the hive is added
    the new report can say ``installed`` and this function identifies the
    evidence IDs that were not present in the earlier decision.
    """

    previous_attributions = {item["attribution_key"]: item for item in previous.get("attributions", [])}
    current_attributions = {item["attribution_key"]: item for item in current.get("attributions", [])}
    previous_evidence = previous.get("evidence_index", {})
    current_evidence = current.get("evidence_index", {})

    conclusion_changes: list[dict[str, Any]] = []
    for key in sorted(set(previous_attributions) | set(current_attributions)):
        before = previous_attributions.get(key, {})
        after = current_attributions.get(key, {})
        if before.get("state") == after.get("state") and before.get("reason") == after.get("reason"):
            continue

        before_ids = _all_evidence_ids(before)
        after_ids = _all_evidence_ids(after)
        changed_by = sorted(after_ids - before_ids)
        no_longer_present = sorted(before_ids - after_ids)
        changed_by_evidence = [
            current_evidence.get(evidence_id, previous_evidence.get(evidence_id, {"evidence_id": evidence_id}))
            for evidence_id in changed_by
        ]
        no_longer_present_evidence = [
            previous_evidence.get(evidence_id, {"evidence_id": evidence_id}) for evidence_id in no_longer_present
        ]

        conclusion_changes.append(
            {
                "attribution_key": key,
                "subject": after.get("subject") or before.get("subject"),
                "product_id": after.get("product_id") or before.get("product_id"),
                "previous": {
                    "state": before.get("state"),
                    "reason": before.get("reason"),
                    "confidence": before.get("confidence"),
                },
                "current": {
                    "state": after.get("state"),
                    "reason": after.get("reason"),
                    "confidence": after.get("confidence"),
                },
                "changed_by": changed_by,
                "changed_by_evidence": changed_by_evidence,
                "no_longer_present": no_longer_present,
                "no_longer_present_evidence": no_longer_present_evidence,
                "explanation": _change_explanation(before, after, changed_by_evidence),
            }
        )

    previous_coverage = previous.get("coverage", {}).get("current", {})
    current_coverage = current.get("coverage", {}).get("current", {})
    previous_status = {f"{item['kind']}:{item['id']}": item["status"] for item in previous_coverage.get("subjects", [])}
    current_status = {f"{item['kind']}:{item['id']}": item["status"] for item in current_coverage.get("subjects", [])}
    coverage_changes = [
        {
            "subject": key,
            "previous": previous_status.get(key, "not_captured"),
            "current": current_status.get(key, "not_captured"),
        }
        for key in sorted(set(previous_status) | set(current_status))
        if previous_status.get(key) != current_status.get(key)
    ]

    return {
        "schema_version": SCHEMA_VERSION,
        "read_only": True,
        "conclusion_changes": conclusion_changes,
        "coverage_changes": coverage_changes,
    }


def _change_explanation(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    changed_by_evidence: Sequence[Mapping[str, Any]],
) -> str:
    kinds = sorted({item.get("kind") for item in changed_by_evidence if item.get("kind")})
    if before.get("state") == STATE_UNDETERMINED and after.get("state") == STATE_INSTALLED:
        if EVIDENCE_UNINSTALL_REGISTRATION in kinds:
            return "A newly supplied hive contains the uninstall registration that closed the coverage gap."
        if EVIDENCE_INSTALLER_USER_DATA in kinds or EVIDENCE_INSTALLER_PRODUCT in kinds:
            return "A newly supplied hive contains installation context that was missing from the earlier report."
    if after.get("state") == STATE_MANUAL_RESIDUE:
        return "The new evidence shows installation context without a current uninstall registration."
    if after.get("state") == STATE_EXPLICIT_UNINSTALL:
        return "Complete current coverage shows neither the uninstall registration nor its install context."
    if kinds:
        return f"The decision changed after new evidence became available: {', '.join(kinds)}."
    return "The decision changed because the available evidence set changed."
