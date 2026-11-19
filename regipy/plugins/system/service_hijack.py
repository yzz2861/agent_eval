"""
Offline service-hijack analysis for SYSTEM hives.

The generic ``services`` plugin dumps every service from every ControlSet into
one bucket, which makes it impossible to tell whether a suspicious ImagePath was
actually in force when the machine booted. This plugin keeps the ControlSets
apart and classifies each one using two independent sources:

1. the hive-local ``Select`` key (Current / Default / Failed / LastKnownGood),
2. an explicit boot context supplied by the analyst (the ControlSet that was
   active at the time of interest).

For every service it correlates service type, start mode, ImagePath,
Parameters/ServiceDll and the DependOnService chain, then flags only in-scope
path substitutions and internal configuration contradictions. It never
concludes execution from a suspicious-looking string alone: when the SOFTWARE
hive or the environment information needed to expand / verify a path is
missing, the observation is marked unverifiable and the limitation is
recorded. Everything is computed offline; no Windows host, event log or service
manager is contacted.
"""

import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from regipy.exceptions import RegistryKeyNotFoundException, RegistryParsingException
from regipy.hive_types import SOFTWARE_HIVE_TYPE, SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.registry import RegistryHive
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

SELECT_PATH = r"\Select"
SERVICES_PATH = r"Services"
PARAMETERS_PATH = r"Parameters"

ROLE_CURRENT = "current"
ROLE_CANDIDATE = "candidate"
ROLE_UNKNOWN = "unknown"

# Base Win32/driver type bits; the high nibble carries modifier flags
# (0x40 = user service, 0x100 = interactive) that we keep in the raw value but
# mask off for the label.
SERVICE_TYPE_BASE_MASK = 0x3F
SERVICE_TYPE_BASE_LABELS = {
    0x1: "kernel_driver",
    0x2: "file_system_driver",
    0x4: "adapter_driver",
    0x8: "recognizer_driver",
    0x10: "win32_own_process",
    0x20: "win32_share_process",
}


def _service_type_label(service_type: Optional[int]) -> Optional[str]:
    if service_type is None:
        return None
    base = service_type & SERVICE_TYPE_BASE_MASK
    label = SERVICE_TYPE_BASE_LABELS.get(base)
    if label is None:
        return f"unknown_type_0x{service_type:x}"
    if service_type & 0x100:
        label = "interactive_" + label
    if service_type & 0x40:
        label = "user_" + label
    return label


START_LABELS = {0: "boot", 1: "system", 2: "automatic", 3: "manual", 4: "disabled"}

ENV_VAR_PATTERN = re.compile(r"%([^%]+)%")


@dataclass
class RawValue:
    """A registry value exactly as stored, before any interpretation."""

    name: str
    value: Any
    value_type: str
    is_corrupted: bool


@dataclass
class DependencyNode:
    """One hop in a DependOnService dependency chain."""

    name: str
    present: bool
    control_set: str
    start: Optional[int]
    start_label: Optional[str]
    circular: bool


@dataclass
class ServiceFinding:
    """The full correlated record for one service in one ControlSet."""

    service_name: str
    control_set: str
    control_set_role: str
    role_reason: str
    service_key_path: str
    last_modified: Any
    service_type: Optional[int]
    service_type_label: Optional[str]
    start: Optional[int]
    start_label: Optional[str]
    object_name: Optional[str]
    image_path: Optional[str]
    image_path_expanded: Optional[str]
    service_dll: Optional[str]
    service_dll_expanded: Optional[str]
    dependencies: list = field(default_factory=list)
    dependency_chain: list = field(default_factory=list)
    missing_dependencies: list = field(default_factory=list)
    circular_dependencies: list = field(default_factory=list)
    raw_values: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    analysis_limits: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class ServiceHijackPlugin(Plugin):
    NAME = "service_hijack"
    DESCRIPTION = (
        "Offline analysis of service ImagePath / ServiceDll hijacking across ControlSets, with"
        " Select-based and explicit boot-context classification, dependency chains and context limits"
    )
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def __init__(
        self,
        registry_hive: RegistryHive,
        as_json: bool = False,
        trim_values: bool = False,
        active_control_set: Optional[int] = None,
        software_hive: Optional[RegistryHive] = None,
        environment: Optional[dict] = None,
    ) -> None:
        super().__init__(registry_hive, as_json=as_json, trim_values=trim_values)
        # Explicit analyst-provided boot context. When given it overrides the
        # hive-local Select value, because Select reflects the last boot while
        # the investigation may target a different point in time.
        self.active_control_set = active_control_set
        self.software_hive = software_hive
        self.environment = dict(environment) if environment else {}
        self._context_limits: list = []
        self._service_index: dict = {}
        self._control_set_names: list = []

    def run(self) -> None:
        logger.debug("Started Service Hijack analysis plugin...")
        self.entries = []
        select_values = self._read_select()
        self._control_set_names = self._discover_control_sets()
        roles = self._classify_control_sets(select_values)
        self._service_index = self._index_services()
        for control_set in self._control_set_names:
            role, reason = roles[control_set]
            for service_name in sorted(self._service_index.get(control_set, {})):
                self.entries.append(
                    self._analyze_service(control_set, role, reason, service_name).to_dict()
                )

    def _read_select(self) -> dict:
        """Return the raw Select values; missing Select is itself a limit."""
        try:
            select_key = self.registry_hive.get_key(SELECT_PATH)
        except RegistryKeyNotFoundException:
            self._context_limits.append("Select key not found; ControlSet roles cannot be derived from the hive")
            return {}
        values = {}
        for value in select_key.iter_values(as_json=False):
            values[value.name] = value.value
        return values

    def _discover_control_sets(self) -> list:
        """Enumerate ControlSetNNN root keys directly (not the hardcoded 001/002)."""
        names = []
        for subkey in self.registry_hive.root.iter_subkeys():
            if isinstance(subkey.name, str) and re.fullmatch(r"ControlSet\d{3,}", subkey.name):
                names.append(subkey.name)
        if not names:
            self._context_limits.append("No ControlSetNNN keys found at the hive root")
        return sorted(names)

    @staticmethod
    def _control_set_number(name: str) -> Optional[int]:
        match = re.fullmatch(r"ControlSet(\d{3,})", name)
        return int(match.group(1)) if match else None

    def _classify_control_sets(self, select_values: dict) -> dict:
        """Map each ControlSet to current/candidate/unknown with an explanation."""
        referenced = {}
        for select_name in ("Current", "Default", "Failed", "LastKnownGood"):
            number = select_values.get(select_name)
            if isinstance(number, int):
                referenced.setdefault(number, []).append(select_name)

        explicit = self.active_control_set
        result = {}
        for name in self._control_set_names:
            number = self._control_set_number(name)
            select_refs = referenced.get(number, []) if number is not None else []
            if explicit is not None and number == explicit:
                result[name] = (ROLE_CURRENT, f"Explicit boot context selects {name}")
            elif explicit is not None:
                result[name] = (
                    ROLE_CANDIDATE,
                    f"Explicit boot context points to ControlSet{explicit:03d}; {name} is a non-active alternative",
                )
            elif select_refs:
                if "Current" in select_refs:
                    reason = "Select\\Current points to this ControlSet"
                    if len(select_refs) > 1:
                        reason += " (also referenced as " + ", ".join(r for r in select_refs if r != "Current") + ")"
                    result[name] = (ROLE_CURRENT, reason)
                else:
                    result[name] = (
                        ROLE_CANDIDATE,
                        "Referenced by Select as " + ", ".join(select_refs) + " but not Current",
                    )
            else:
                result[name] = (ROLE_UNKNOWN, "Not referenced by any Select value and no explicit boot context given")
        return result

    def _index_services(self) -> dict:
        """Build {control_set: {service_name: NKRecord}} for dependency lookups."""
        index = {}
        for control_set in self._control_set_names:
            services_path = rf"\{control_set}\{SERVICES_PATH}"
            try:
                services_key = self.registry_hive.get_key(services_path)
            except RegistryKeyNotFoundException:
                self._context_limits.append(f"Services key missing for {control_set}")
                continue
            index[control_set] = {}
            for service in services_key.iter_subkeys():
                index[control_set][service.name] = service
        return index

    def _get_raw_values(self, service_key) -> list:
        raw = []
        if service_key.values_count == 0:
            return raw
        try:
            for value in service_key.iter_values(as_json=self.as_json):
                # iter_values always yields Value objects; normalize to plain dicts.
                if hasattr(value, "name"):
                    raw.append({
                        "name": value.name,
                        "value": value.value,
                        "value_type": value.value_type,
                        "is_corrupted": value.is_corrupted,
                    })
                else:
                    raw.append(dict(value))
        except RegistryParsingException as ex:
            logger.error(f"Failed reading values for {service_key.name}: {ex}")
        return raw

    @staticmethod
    def _raw_value(raw_values: list, name: str) -> Optional[dict]:
        for value in raw_values:
            if value["name"] == name:
                return value
        return None

    def _read_service_dll(self, control_set: str, service_name: str) -> tuple:
        path = rf"\{control_set}\{SERVICES_PATH}\{service_name}\{PARAMETERS_PATH}"
        try:
            parameters_key = self.registry_hive.get_key(path)
        except RegistryKeyNotFoundException:
            return None, []
        raw = self._get_raw_values(parameters_key)
        service_dll_value = self._raw_value(raw, "ServiceDll")
        if service_dll_value is None:
            return None, raw
        return service_dll_value["value"], raw

    def _expand_environment(self, raw_path: Optional[str]) -> tuple:
        """Expand %VAR% references using explicit environment only."""
        if not raw_path:
            return None, []
        limits = []
        unresolved = set(ENV_VAR_PATTERN.findall(raw_path))
        expanded = raw_path
        for var in sorted(unresolved):
            if var in self.environment:
                expanded = expanded.replace(f"%{var}%", self.environment[var])
            else:
                limits.append(
                    f"Environment variable %{var}% has no supplied value; path expansion is incomplete"
                )
        return expanded, limits

    def _software_anchor(self, value_name: str) -> Optional[str]:
        """Read a trusted path anchor (e.g. SystemRoot) from the SOFTWARE hive."""
        if self.software_hive is None or self.software_hive.hive_type != SOFTWARE_HIVE_TYPE:
            return None
        try:
            key = self.software_hive.get_key(r"\Microsoft\Windows NT\CurrentVersion")
            value = key.get_value(value_name=value_name, raise_on_missing=False)
        except RegistryKeyNotFoundException:
            return None
        return value if isinstance(value, str) else None

    def _analyze_service(self, control_set: str, role: str, reason: str, service_name: str) -> ServiceFinding:
        service_key = self._service_index[control_set][service_name]
        service_path = rf"\{control_set}\{SERVICES_PATH}\{service_name}"
        raw_values = self._get_raw_values(service_key)
        limits = list(self._context_limits)

        type_value = self._raw_value(raw_values, "Type")
        start_value = self._raw_value(raw_values, "Start")
        image_value = self._raw_value(raw_values, "ImagePath")
        object_value = self._raw_value(raw_values, "ObjectName")
        depend_value = self._raw_value(raw_values, "DependOnService")

        service_type = type_value["value"] if type_value and isinstance(type_value["value"], int) else None
        start = start_value["value"] if start_value and isinstance(start_value["value"], int) else None
        image_path = image_value["value"] if image_value else None
        object_name = object_value["value"] if object_value else None
        dependencies = list(depend_value["value"]) if depend_value and isinstance(depend_value["value"], list) else []

        service_dll, parameters_raw = self._read_service_dll(control_set, service_name)
        if parameters_raw:
            raw_values.extend(parameters_raw)

        image_expanded, image_limits = self._expand_environment(image_path)
        dll_expanded, dll_limits = self._expand_environment(service_dll)
        limits.extend(image_limits)
        limits.extend(dll_limits)

        timestamp = convert_wintime(service_key.header.last_modified, as_json=self.as_json)
        finding = ServiceFinding(
            service_name=service_name,
            control_set=control_set,
            control_set_role=role,
            role_reason=reason,
            service_key_path=service_path,
            last_modified=timestamp,
            service_type=service_type,
            service_type_label=_service_type_label(service_type),
            start=start,
            start_label=START_LABELS.get(start) if start is not None else None,
            object_name=object_name,
            image_path=image_path,
            image_path_expanded=image_expanded,
            service_dll=service_dll,
            service_dll_expanded=dll_expanded,
            dependencies=dependencies,
            raw_values=raw_values,
        )

        self._resolve_dependencies(control_set, service_name, dependencies, finding)
        self._detect_contradictions(finding, service_type, start, image_path, service_dll)
        self._detect_path_substitution(finding, image_expanded, dll_expanded, limits)
        self._apply_role_scope(finding)
        finding.analysis_limits = sorted(set(limits))
        return finding

    @staticmethod
    def _apply_role_scope(finding: ServiceFinding) -> None:
        # A substitution only represents an in-force hijack on the current
        # ControlSet; elsewhere the bytes were not necessarily booted.
        if finding.control_set_role == ROLE_CURRENT:
            return
        for item in finding.findings:
            if item.get("rule") == "path_substitution":
                item["severity"] = "unverified"
                item["detail"] = (
                    "Substitution exists in a non-current ControlSet ("
                    + finding.control_set_role
                    + "); it was not necessarily in force at boot"
                )

    def _service_dependencies(self, control_set: str, service_name: str) -> list:
        depend_value = None
        service = self._service_index.get(control_set, {}).get(service_name)
        if service is None or service.values_count == 0:
            return []
        for value in service.iter_values(as_json=False):
            if value.name == "DependOnService":
                depend_value = value.value
                break
        return list(depend_value) if isinstance(depend_value, list) else []

    def _resolve_dependencies(
        self, control_set: str, root_service: str, direct_dependencies: list, finding: ServiceFinding
    ) -> None:
        """Walk the dependency graph with an explicit visited set so cycles terminate."""
        chain = []
        missing = []
        circular = []
        visited = {root_service}
        stack = list(direct_dependencies)
        while stack:
            dependency = stack.pop(0)
            if dependency in visited:
                # Reaching an already-expanded service through the graph means a cycle.
                circular.append(dependency)
                chain.append(DependencyNode(
                    name=dependency, present=True, control_set=control_set, start=None,
                    start_label=None, circular=True,
                ).__dict__)
                continue
            visited.add(dependency)
            dep_service = self._service_index.get(control_set, {}).get(dependency)
            if dep_service is None:
                missing.append(dependency)
                chain.append(DependencyNode(
                    name=dependency, present=False, control_set=control_set, start=None,
                    start_label=None, circular=False,
                ).__dict__)
                continue
            dep_start = None
            if dep_service.values_count:
                for value in dep_service.iter_values(as_json=False):
                    if value.name == "Start" and isinstance(value.value, int):
                        dep_start = value.value
                        break
            chain.append(DependencyNode(
                name=dependency, present=True, control_set=control_set, start=dep_start,
                start_label=START_LABELS.get(dep_start), circular=False,
            ).__dict__)
            # Keep back-edges in the stack so the visited check at the top of
            # the loop records the cycle; only de-duplicate genuine repeats.
            for nested in reversed(self._service_dependencies(control_set, dependency)):
                if nested not in stack:
                    stack.insert(0, nested)
        finding.dependency_chain = chain
        finding.missing_dependencies = sorted(set(missing))
        finding.circular_dependencies = sorted(set(circular))

    def _detect_contradictions(
        self,
        finding: ServiceFinding,
        service_type: Optional[int],
        start: Optional[int],
        image_path: Optional[str],
        service_dll: Optional[str],
    ) -> None:
        # svchost-hosted (share-process) services normally point ImagePath at the
        # host executable and keep their payload in a per-service Parameters (or
        # other) subkey; the absence of Parameters/ServiceDll alone is therefore
        # not a contradiction. Both own- and share-process user services may
        # legally load a ServiceDll.
        if start == 4 and (image_path or service_dll):
            finding.findings.append({
                "rule": "disabled_service_with_payload",
                "severity": "configuration_contradiction",
                "detail": "Service is disabled (Start=4) but still carries an executable payload",
            })
        if service_type is None or start is None:
            finding.findings.append({
                "rule": "incomplete_service_definition",
                "severity": "configuration_contradiction",
                "detail": "Service is missing Type and/or Start, so launch behavior cannot be established",
            })
        if finding.missing_dependencies:
            finding.findings.append({
                "rule": "missing_dependency",
                "severity": "configuration_contradiction",
                "detail": "DependOnService references services absent from this ControlSet: "
                + ", ".join(finding.missing_dependencies),
            })
        if finding.circular_dependencies:
            finding.findings.append({
                "rule": "circular_dependency",
                "severity": "configuration_contradiction",
                "detail": "Dependency chain contains a cycle: " + ", ".join(finding.circular_dependencies),
            })

    def _detect_path_substitution(
        self,
        finding: ServiceFinding,
        image_expanded: Optional[str],
        dll_expanded: Optional[str],
        limits: list,
    ) -> None:
        # Only flag path substitutions we can actually verify. A path we cannot
        # expand (missing environment) or cannot compare against a trusted
        # anchor (missing SOFTWARE) is reported as an observation, never as a
        # confirmed hijack, and never as evidence of execution.
        self._evaluate_payload_path(finding, "ImagePath", image_expanded, limits)
        if dll_expanded is not None:
            self._evaluate_payload_path(finding, "ServiceDll", dll_expanded, limits)

    def _evaluate_payload_path(self, finding: ServiceFinding, field_name: str, path: Optional[str], limits: list) -> None:
        if not path:
            return
        normalized = path.replace("/", "\\")
        lower = normalized.lower()
        # Unresolved %VAR% means we cannot judge the target location at all.
        if "%" in normalized:
            limits.append(f"{field_name} still contains unresolved environment references: {path}")
            finding.findings.append({
                "rule": "unverified_path",
                "severity": "unverified",
                "field": field_name,
                "detail": "Path cannot be fully expanded with the supplied environment; no location verdict made",
                "path": path,
            })
            return

        system_root = self._software_anchor("SystemRoot") or self.environment.get("SystemRoot")
        if system_root is None:
            limits.append(
                "No SOFTWARE hive or SystemRoot environment supplied; trusted system path anchors are unavailable"
            )
            finding.findings.append({
                "rule": "unverified_path",
                "severity": "unverified",
                "field": field_name,
                "detail": "Path location cannot be compared to a trusted anchor without SystemRoot context",
                "path": path,
            })
            return

        system_root_norm = system_root.replace("/", "\\").rstrip("\\").lower()
        trusted_prefixes = (
            system_root_norm + r"\system32",
            system_root_norm + r"\syswow64",
            system_root_norm + r"\winsxs",
        )
        in_trusted_location = lower.startswith(trusted_prefixes)
        # A user-writable or non-system location is the in-scope substitution signal.
        user_writable_markers = ("\\users\\public\\", "\\programdata\\", "\\windows\\temp\\", "\\temp\\", "\\appdata\\")
        outside_system = not in_trusted_location and not lower.startswith(system_root_norm)
        looks_writable = any(marker in lower for marker in user_writable_markers)
        if outside_system or looks_writable:
            finding.findings.append({
                "rule": "path_substitution",
                "severity": "suspicious",
                "field": field_name,
                "detail": "Payload path resolves outside the trusted system directories",
                "path": path,
                "trusted_anchor": system_root,
            })
        elif not in_trusted_location:
            finding.findings.append({
                "rule": "non_standard_system_path",
                "severity": "unverified",
                "field": field_name,
                "detail": "Path sits under the Windows directory but outside System32/SysWOW64/WinSxS",
                "path": path,
            })
