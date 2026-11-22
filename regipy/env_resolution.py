"""
Offline interpretation of environment-variable placeholders found in registry data.

Service ImagePath values, shell commands and similar registry strings often contain
placeholders such as ``%SystemRoot%``. This module expands them against a caller
supplied :class:`EnvironmentSnapshot` (which may itself be built from registry
evidence via :func:`snapshot_from_hive`) and records, for every segment of the
result, exactly which snapshot, scope and variable definition justified it.

The layer is strictly offline: it never executes the strings it processes, never
resolves them against the live machine and never touches the filesystem paths it
produces. Parts of a string that cannot be proven from the supplied evidence are
kept verbatim as candidates instead of being guessed.
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import NTUSER_HIVE_TYPE, SOFTWARE_HIVE_TYPE, SYSTEM_HIVE_TYPE

logger = logging.getLogger(__name__)

# Well known registry evidence locations used by snapshot_from_hive
SESSION_MANAGER_ENVIRONMENT_PATH = r"Control\Session Manager\Environment"
NT_CURRENT_VERSION_PATH = r"Microsoft\Windows NT\CurrentVersion"
CURRENT_VERSION_PATH = r"Microsoft\Windows\CurrentVersion"
USER_ENVIRONMENT_PATH = "Environment"

# Maximum nesting depth when a variable definition itself contains placeholders
DEFAULT_MAX_DEPTH = 8

# A placeholder is a %...% run without an inner percent or whitespace. A lone
# percent sign (as in "100% of ...") is not a placeholder and is preserved as
# literal text.
PLACEHOLDER_PATTERN = re.compile(r"%([^\s%]+)%")

# SOFTWARE\Microsoft\Windows\CurrentVersion value names mapped to the variable
# names investigators expect to see in placeholders
WELL_KNOWN_CURRENT_VERSION_VALUES = {
    "ProgramFilesDir": "ProgramFiles",
    "ProgramFilesDir (x86)": "ProgramFiles(x86)",
    "ProgramW6432Dir": "ProgramW6432",
    "CommonFilesDir": "CommonProgramFiles",
    "CommonFilesDir (x86)": "CommonProgramFiles(x86)",
    "CommonW6432Dir": "CommonProgramW6432",
}


class VariableStatus(Enum):
    """The outcome of resolving a single placeholder against a snapshot"""

    RESOLVED = "resolved"
    PARTIAL_DEFINITION = "partial_definition"
    EMPTY_DEFINITION = "empty_definition"
    UNDEFINED = "undefined"
    SCOPE_MISSING = "scope_missing"
    CYCLE = "cycle"
    DEPTH_EXCEEDED = "depth_exceeded"


class ExpansionStatus(Enum):
    """The overall outcome of expanding one registry string"""

    RESOLVED = "resolved"
    PARTIAL = "partial"
    UNRESOLVED = "unresolved"
    LITERAL = "literal"


@dataclass
class VariableResolution:
    """
    Provenance record for one placeholder occurrence.

    ``definition`` is the raw definition taken from the snapshot, ``expansion``
    is that definition after nested placeholders were expanded. Both are ``None``
    when the variable could not be resolved, in which case the original
    placeholder is kept as a candidate value.
    """

    name: str
    status: VariableStatus
    snapshot_id: Optional[str] = None
    scope: Optional[str] = None
    definition: Optional[str] = None
    expansion: Optional[str] = None
    chain: list[str] = field(default_factory=list)
    depth: int = 0

    @property
    def is_proven(self) -> bool:
        return self.status in (VariableStatus.RESOLVED, VariableStatus.EMPTY_DEFINITION)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status.value,
            "snapshot_id": self.snapshot_id,
            "scope": self.scope,
            "definition": self.definition,
            "expansion": self.expansion,
            "chain": list(self.chain),
            "depth": self.depth,
        }


@dataclass
class Segment:
    """
    One ordered piece of the original string: either literal text or a
    placeholder occurrence together with its resolution provenance.
    """

    text: str
    kind: str
    variable: Optional[VariableResolution] = None

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "kind": self.kind,
            "variable": self.variable.to_dict() if self.variable else None,
        }


@dataclass
class ExpansionResult:
    """The result of expanding one registry string against one snapshot"""

    original: str
    expanded: str
    status: ExpansionStatus
    snapshot_id: Optional[str]
    scopes: list[str]
    segments: list[Segment]
    variables: list[VariableResolution]

    @property
    def unresolved_variables(self) -> list[VariableResolution]:
        return [variable for variable in self.variables if not variable.is_proven]

    def to_dict(self) -> dict:
        return {
            "original": self.original,
            "expanded": self.expanded,
            "status": self.status.value,
            "snapshot_id": self.snapshot_id,
            "scopes": list(self.scopes),
            "segments": [segment.to_dict() for segment in self.segments],
            "variables": [variable.to_dict() for variable in self.variables],
        }


@dataclass
class SnapshotComparison:
    """
    The same original string expanded against several snapshots.

    ``outcome_by_snapshot`` lets a reviewer see exactly which snapshot each
    distinct conclusion depends on.
    """

    original: str
    results: list[ExpansionResult]

    @property
    def outcome_by_snapshot(self) -> dict[str, list[str]]:
        outcomes: dict[str, list[str]] = {}
        for result in self.results:
            outcomes.setdefault(result.expanded, []).append(result.snapshot_id or "")
        return outcomes

    @property
    def depends_on_snapshot(self) -> bool:
        """True when different snapshots lead to different conclusions"""
        return len(self.outcome_by_snapshot) > 1

    def to_dict(self) -> dict:
        return {
            "original": self.original,
            "depends_on_snapshot": self.depends_on_snapshot,
            "outcome_by_snapshot": dict(self.outcome_by_snapshot.items()),
            "results": [result.to_dict() for result in self.results],
        }


class EnvironmentSnapshot:
    """
    A caller supplied snapshot of environment definitions, organized in scopes
    (for example ``system`` or ``user:S-1-5-18``). Variable names are matched
    case-insensitively, mirroring Windows semantics; scope names are matched
    case-insensitively as well. Original casing is preserved for provenance.
    """

    def __init__(self, snapshot_id: str, scopes: Optional[dict[str, dict[str, str]]] = None):
        self.snapshot_id = snapshot_id
        self.scopes: dict[str, dict[str, str]] = dict(scopes or {})
        self._scope_index: dict[str, str] = {scope.lower(): scope for scope in self.scopes}
        self._variable_indexes: dict[str, dict[str, str]] = {
            scope.lower(): {name.upper(): name for name in variables} for scope, variables in self.scopes.items()
        }

    def __repr__(self) -> str:
        variable_count = sum(len(variables) for variables in self.scopes.values())
        return f"EnvironmentSnapshot(snapshot_id={self.snapshot_id!r}, scopes={len(self.scopes)}, variables={variable_count})"

    def has_scope(self, scope: str) -> bool:
        return scope.lower() in self._scope_index

    def lookup(self, name: str, scopes: list[str]) -> Optional[tuple[str, str, str]]:
        """
        Look up a variable in the given scopes, in order.
        :return: (scope, original variable name, definition) or None
        """
        for scope in scopes:
            scope_key = self._scope_index.get(scope.lower())
            if scope_key is None:
                continue
            original_name = self._variable_indexes[scope.lower()].get(name.upper())
            if original_name is not None:
                return scope_key, original_name, self.scopes[scope_key][original_name]
        return None


def _resolve_variable(
    name: str,
    snapshot: Optional[EnvironmentSnapshot],
    scopes: list[str],
    depth: int,
    max_depth: int,
    seen: tuple[str, ...],
    variables: list[VariableResolution],
) -> VariableResolution:
    """
    Resolve one placeholder against the snapshot, recursing into nested
    definitions. Appends every resolution (including nested ones) to ``variables``.
    """
    if depth > max_depth:
        resolution = VariableResolution(name=name, status=VariableStatus.DEPTH_EXCEEDED, depth=depth)
        variables.append(resolution)
        return resolution

    if name.upper() in seen:
        resolution = VariableResolution(
            name=name,
            status=VariableStatus.CYCLE,
            snapshot_id=snapshot.snapshot_id if snapshot else None,
            chain=list(seen),
            depth=depth,
        )
        variables.append(resolution)
        return resolution

    if snapshot is None or not any(snapshot.has_scope(scope) for scope in scopes):
        resolution = VariableResolution(
            name=name,
            status=VariableStatus.SCOPE_MISSING,
            snapshot_id=snapshot.snapshot_id if snapshot else None,
            depth=depth,
        )
        variables.append(resolution)
        return resolution

    found = snapshot.lookup(name, scopes)
    if found is None:
        resolution = VariableResolution(
            name=name,
            status=VariableStatus.UNDEFINED,
            snapshot_id=snapshot.snapshot_id,
            depth=depth,
        )
        variables.append(resolution)
        return resolution

    scope, original_name, definition = found
    resolution = VariableResolution(
        name=name,
        status=VariableStatus.RESOLVED,
        snapshot_id=snapshot.snapshot_id,
        scope=scope,
        definition=definition,
        depth=depth,
    )
    variables.append(resolution)

    if definition == "":
        resolution.status = VariableStatus.EMPTY_DEFINITION
        resolution.expansion = ""
        return resolution

    # Expand nested placeholders inside the definition itself
    nested_seen = seen + (name.upper(),)
    nested_count = len(variables)
    expanded_parts = []
    position = 0
    for match in PLACEHOLDER_PATTERN.finditer(definition):
        expanded_parts.append(definition[position : match.start()])
        nested = _resolve_variable(match.group(1), snapshot, scopes, depth + 1, max_depth, nested_seen, variables)
        resolution.chain.append(nested.name)
        expanded_parts.append(nested.expansion if nested.is_proven else match.group(0))
        position = match.end()
    expanded_parts.append(definition[position:])
    resolution.expansion = "".join(expanded_parts)
    if any(not variable.is_proven for variable in variables[nested_count:]):
        # The definition itself contains placeholders that could not be proven,
        # so the expansion is a candidate rather than a proven value
        resolution.status = VariableStatus.PARTIAL_DEFINITION
    return resolution


def expand_placeholders(
    value: str,
    snapshot: Optional[EnvironmentSnapshot] = None,
    scopes: Optional[list[str]] = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> ExpansionResult:
    """
    Expand every placeholder in ``value`` against ``snapshot``.

    Proven parts are substituted; unproven placeholders are kept verbatim as
    candidate values. The original string and the provenance of every segment
    are preserved in the result. Nothing is executed and no path is accessed.
    """
    requested_scopes = list(scopes) if scopes else ["system"]
    segments: list[Segment] = []
    variables: list[VariableResolution] = []
    expanded_parts: list[str] = []

    position = 0
    for match in PLACEHOLDER_PATTERN.finditer(value):
        if match.start() > position:
            segments.append(Segment(text=value[position : match.start()], kind="literal"))
            expanded_parts.append(value[position : match.start()])

        top_level_count = len(variables)
        resolution = _resolve_variable(match.group(1), snapshot, requested_scopes, 0, max_depth, (), variables)
        top_level_resolution = variables[top_level_count]
        if resolution.is_proven:
            replacement = resolution.expansion or ""
        else:
            replacement = match.group(0)
        expanded_parts.append(replacement)
        segments.append(Segment(text=replacement, kind="variable", variable=top_level_resolution))
        position = match.end()

    if position < len(value):
        segments.append(Segment(text=value[position:], kind="literal"))
        expanded_parts.append(value[position:])

    if not variables:
        status = ExpansionStatus.LITERAL
    elif all(variable.is_proven for variable in variables):
        status = ExpansionStatus.RESOLVED
    elif any(variable.is_proven for variable in variables):
        status = ExpansionStatus.PARTIAL
    else:
        status = ExpansionStatus.UNRESOLVED

    return ExpansionResult(
        original=value,
        expanded="".join(expanded_parts),
        status=status,
        snapshot_id=snapshot.snapshot_id if snapshot else None,
        scopes=requested_scopes,
        segments=segments,
        variables=variables,
    )


def compare_snapshots(
    value: str,
    snapshots: list[EnvironmentSnapshot],
    scopes: Optional[list[str]] = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> SnapshotComparison:
    """
    Expand the same original string against several snapshots, so a reviewer
    can see which snapshot each distinct conclusion depends on.
    """
    results = [expand_placeholders(value, snapshot=snapshot, scopes=scopes, max_depth=max_depth) for snapshot in snapshots]
    return SnapshotComparison(original=value, results=results)


def scope_from_key(registry_hive, key_path: str) -> dict[str, str]:
    """
    Read every value of a registry key into a ``{name: definition}`` mapping.
    Non-string values are stringified; the key itself is registry evidence and
    is only parsed, never executed.
    """
    key = registry_hive.get_key(key_path)
    return {value.name: str(value.value) for value in key.get_values()}


def snapshot_from_hive(
    registry_hive,
    snapshot_id: Optional[str] = None,
    user_scope: str = "user",
) -> EnvironmentSnapshot:
    """
    Build an :class:`EnvironmentSnapshot` from well known registry evidence:

    - SYSTEM hives: ``Control\\Session Manager\\Environment`` of every control
      set (first control set wins on conflicts) becomes the ``system`` scope.
    - SOFTWARE hives: ``SystemRoot`` and the well known ``CurrentVersion``
      directories are mapped to their usual variable names in the ``system`` scope.
    - NTUSER hives: the user's ``Environment`` key becomes the ``user`` scope
      (renameable via ``user_scope``).

    Missing keys are skipped; whatever evidence exists is used as-is.
    """
    scopes: dict[str, dict[str, str]] = {}
    hive_type = (registry_hive.hive_type or "").lower()

    if hive_type in (SYSTEM_HIVE_TYPE, ""):
        system_variables: dict[str, str] = {}
        for control_set_path in registry_hive.get_control_sets(SESSION_MANAGER_ENVIRONMENT_PATH):
            try:
                for name, definition in scope_from_key(registry_hive, control_set_path).items():
                    system_variables.setdefault(name, definition)
            except RegistryKeyNotFoundException:
                continue
        if system_variables:
            scopes["system"] = system_variables

    if hive_type in (SOFTWARE_HIVE_TYPE, ""):
        software_variables: dict[str, str] = {}
        try:
            system_root = scope_from_key(registry_hive, NT_CURRENT_VERSION_PATH).get("SystemRoot")
            if system_root:
                software_variables["SystemRoot"] = system_root
        except RegistryKeyNotFoundException:
            pass
        try:
            current_version_values = scope_from_key(registry_hive, CURRENT_VERSION_PATH)
            for value_name, variable_name in WELL_KNOWN_CURRENT_VERSION_VALUES.items():
                if current_version_values.get(value_name):
                    software_variables[variable_name] = current_version_values[value_name]
        except RegistryKeyNotFoundException:
            pass
        if software_variables:
            existing = scopes.setdefault("system", {})
            for name, definition in software_variables.items():
                existing.setdefault(name, definition)

    if hive_type in (NTUSER_HIVE_TYPE, ""):
        try:
            user_variables = scope_from_key(registry_hive, USER_ENVIRONMENT_PATH)
            if user_variables:
                scopes[user_scope] = user_variables
        except RegistryKeyNotFoundException:
            pass

    resolved_snapshot_id = snapshot_id or getattr(registry_hive, "name", None) or "registry-evidence"
    snapshot = EnvironmentSnapshot(snapshot_id=resolved_snapshot_id, scopes=scopes)
    logger.debug(f"Built environment snapshot {resolved_snapshot_id} from hive evidence: {snapshot!r}")
    return snapshot
