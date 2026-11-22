"""Unit tests for regipy.env_resolution - offline placeholder interpretation"""

import json
from unittest.mock import MagicMock

from regipy.env_resolution import (
    EnvironmentSnapshot,
    ExpansionStatus,
    VariableStatus,
    compare_snapshots,
    expand_placeholders,
    scope_from_key,
    snapshot_from_hive,
)
from regipy.exceptions import RegistryKeyNotFoundException


def _snapshot(snapshot_id="snapshot-a", scopes=None):
    return EnvironmentSnapshot(
        snapshot_id=snapshot_id,
        scopes=scopes or {"system": {"SystemRoot": r"C:\Windows", "ProgramFiles": r"C:\Program Files"}},
    )


class TestExpandPlaceholders:
    def test_basic_expansion_with_provenance(self):
        result = expand_placeholders(r"%SystemRoot%\System32\svchost.exe -k netsvcs", snapshot=_snapshot())

        assert result.status == ExpansionStatus.RESOLVED
        assert result.expanded == r"C:\Windows\System32\svchost.exe -k netsvcs"
        assert result.original == r"%SystemRoot%\System32\svchost.exe -k netsvcs"
        assert result.snapshot_id == "snapshot-a"

        variable_segment = result.segments[0]
        assert variable_segment.kind == "variable"
        assert variable_segment.text == r"C:\Windows"
        assert variable_segment.variable.scope == "system"
        assert variable_segment.variable.definition == r"C:\Windows"
        assert variable_segment.variable.snapshot_id == "snapshot-a"
        assert result.segments[1].kind == "literal"
        assert result.segments[1].text == r"\System32\svchost.exe -k netsvcs"

    def test_variable_names_are_case_insensitive(self):
        result = expand_placeholders(r"%systemroot%\explorer.exe", snapshot=_snapshot())
        assert result.expanded == r"C:\Windows\explorer.exe"
        assert result.variables[0].status == VariableStatus.RESOLVED

    def test_nested_substitution_records_chain(self):
        snapshot = _snapshot(scopes={"system": {"SystemRoot": r"C:\Windows", "BinDir": r"%SystemRoot%\System32"}})
        result = expand_placeholders(r"%BinDir%\svc.exe", snapshot=snapshot)

        assert result.status == ExpansionStatus.RESOLVED
        assert result.expanded == r"C:\Windows\System32\svc.exe"

        top_level = result.variables[0]
        assert top_level.name == "BinDir"
        assert top_level.definition == r"%SystemRoot%\System32"
        assert top_level.expansion == r"C:\Windows\System32"
        assert top_level.chain == ["SystemRoot"]

        nested = result.variables[1]
        assert nested.name == "SystemRoot"
        assert nested.depth == 1

    def test_empty_definition_is_proven_empty(self):
        snapshot = _snapshot(scopes={"system": {"EmptyVar": ""}})
        result = expand_placeholders(r"%EmptyVar%\svc.exe", snapshot=snapshot)

        assert result.status == ExpansionStatus.RESOLVED
        assert result.expanded == r"\svc.exe"
        assert result.variables[0].status == VariableStatus.EMPTY_DEFINITION
        assert result.variables[0].is_proven

    def test_missing_scope_keeps_candidate(self):
        result = expand_placeholders(r"%AppData%\tool.exe", snapshot=_snapshot(), scopes=["user:S-1-5-18"])

        assert result.status == ExpansionStatus.UNRESOLVED
        assert result.expanded == r"%AppData%\tool.exe"
        assert result.variables[0].status == VariableStatus.SCOPE_MISSING
        assert not result.variables[0].is_proven

    def test_no_snapshot_keeps_candidate(self):
        result = expand_placeholders(r"%SystemRoot%\svc.exe", snapshot=None)

        assert result.status == ExpansionStatus.UNRESOLVED
        assert result.expanded == r"%SystemRoot%\svc.exe"
        assert result.snapshot_id is None
        assert result.variables[0].status == VariableStatus.SCOPE_MISSING

    def test_undefined_variable_keeps_candidate(self):
        result = expand_placeholders(r"%SystemRoot%\%Unknown%\svc.exe", snapshot=_snapshot())

        assert result.status == ExpansionStatus.PARTIAL
        assert result.expanded == r"C:\Windows\%Unknown%\svc.exe"
        assert [variable.name for variable in result.unresolved_variables] == ["Unknown"]
        assert result.variables[1].status == VariableStatus.UNDEFINED

    def test_user_scope_fallback_order(self):
        snapshot = _snapshot(
            scopes={
                "system": {"Target": r"C:\system"},
                "user:S-1-5-18": {"Target": r"C:\user"},
            }
        )
        result = expand_placeholders(r"%Target%\x", snapshot=snapshot, scopes=["user:S-1-5-18", "system"])
        assert result.expanded == r"C:\user\x"
        assert result.variables[0].scope == "user:S-1-5-18"

    def test_cycle_is_reported_not_recursed(self):
        snapshot = _snapshot(scopes={"system": {"A": "%B%", "B": "%A%"}})
        result = expand_placeholders("%A%", snapshot=snapshot)

        assert result.status == ExpansionStatus.UNRESOLVED
        assert result.expanded == "%A%"
        assert result.variables[-1].status == VariableStatus.CYCLE

    def test_depth_exceeded_is_reported(self):
        variables = {f"Var{i}": f"%Var{i + 1}%" for i in range(10)}
        variables["Var10"] = "end"
        snapshot = _snapshot(scopes={"system": variables})
        result = expand_placeholders("%Var0%", snapshot=snapshot, max_depth=3)

        assert result.status == ExpansionStatus.UNRESOLVED
        assert result.variables[-1].status == VariableStatus.DEPTH_EXCEEDED

    def test_literal_string_has_no_variables(self):
        result = expand_placeholders(r"C:\Windows\System32\svc.exe", snapshot=_snapshot())

        assert result.status == ExpansionStatus.LITERAL
        assert result.expanded == r"C:\Windows\System32\svc.exe"
        assert result.variables == []
        assert all(segment.kind == "literal" for segment in result.segments)

    def test_lone_percent_is_literal(self):
        result = expand_placeholders(r"100% of %SystemRoot%", snapshot=_snapshot())

        assert result.expanded == r"100% of C:\Windows"
        assert len(result.variables) == 1

    def test_result_is_json_serializable(self):
        result = expand_placeholders(r"%SystemRoot%\%Unknown%\svc.exe", snapshot=_snapshot())
        serialized = json.dumps(result.to_dict())
        assert "snapshot-a" in serialized


class TestCompareSnapshots:
    def test_different_snapshots_identify_dependency(self):
        snapshot_a = _snapshot(snapshot_id="host-a", scopes={"system": {"SystemRoot": r"C:\Windows"}})
        snapshot_b = _snapshot(snapshot_id="host-b", scopes={"system": {"SystemRoot": r"D:\WinNT"}})

        comparison = compare_snapshots(r"%SystemRoot%\System32\svc.exe", [snapshot_a, snapshot_b])

        assert comparison.depends_on_snapshot
        assert comparison.outcome_by_snapshot == {
            r"C:\Windows\System32\svc.exe": ["host-a"],
            r"D:\WinNT\System32\svc.exe": ["host-b"],
        }
        assert json.dumps(comparison.to_dict())

    def test_identical_outcome_is_snapshot_independent(self):
        snapshot_a = _snapshot(snapshot_id="host-a")
        snapshot_b = _snapshot(snapshot_id="host-b")

        comparison = compare_snapshots(r"%SystemRoot%\System32\svc.exe", [snapshot_a, snapshot_b])

        assert not comparison.depends_on_snapshot
        assert comparison.outcome_by_snapshot == {r"C:\Windows\System32\svc.exe": ["host-a", "host-b"]}


def _mock_hive(hive_type, key_values):
    """Build a mock RegistryHive: {key_path: {value_name: value}}"""
    hive = MagicMock()
    hive.hive_type = hive_type
    hive.name = "EVIDENCE_HIVE"

    def get_key(key_path):
        normalized = key_path.lstrip("\\")
        if normalized not in key_values:
            raise RegistryKeyNotFoundException(f"Did not find subkey at {key_path}")
        key = MagicMock()
        values = []
        for name, value in key_values[normalized].items():
            mock_value = MagicMock()
            mock_value.name = name
            mock_value.value = value
            values.append(mock_value)
        key.get_values.return_value = values
        return key

    def get_control_sets(path):
        candidate = rf"ControlSet001\{path}"
        return [rf"\{candidate}"] if candidate in key_values else []

    hive.get_key.side_effect = get_key
    hive.get_control_sets.side_effect = get_control_sets
    return hive


class TestSnapshotFromHive:
    def test_system_hive_environment(self):
        hive = _mock_hive(
            "system",
            {
                r"ControlSet001\Control\Session Manager\Environment": {
                    "SystemRoot": r"E:\Windows",
                    "Path": r"E:\Windows\System32",
                }
            },
        )
        snapshot = snapshot_from_hive(hive, snapshot_id="evidence-system")

        assert snapshot.snapshot_id == "evidence-system"
        assert snapshot.lookup("SystemRoot", ["system"]) == ("system", "SystemRoot", r"E:\Windows")

        result = expand_placeholders(r"%SystemRoot%\System32\svc.exe", snapshot=snapshot)
        assert result.expanded == r"E:\Windows\System32\svc.exe"
        assert result.variables[0].snapshot_id == "evidence-system"

    def test_software_hive_well_known_variables(self):
        hive = _mock_hive(
            "software",
            {
                r"Microsoft\Windows NT\CurrentVersion": {"SystemRoot": r"C:\Windows"},
                r"Microsoft\Windows\CurrentVersion": {
                    "ProgramFilesDir": r"C:\Program Files",
                    "ProgramFilesDir (x86)": r"C:\Program Files (x86)",
                },
            },
        )
        snapshot = snapshot_from_hive(hive)

        assert snapshot.lookup("ProgramFiles", ["system"])[2] == r"C:\Program Files"
        assert snapshot.lookup("ProgramFiles(x86)", ["system"])[2] == r"C:\Program Files (x86)"
        assert snapshot.lookup("SystemRoot", ["system"])[2] == r"C:\Windows"

    def test_ntuser_hive_user_scope(self):
        hive = _mock_hive("ntuser", {"Environment": {"TEMP": r"C:\Users\user\AppData\Local\Temp"}})
        snapshot = snapshot_from_hive(hive, user_scope="user:S-1-5-18")

        assert snapshot.lookup("TEMP", ["user:S-1-5-18"])[2] == r"C:\Users\user\AppData\Local\Temp"
        assert not snapshot.has_scope("system")

    def test_missing_keys_are_skipped(self):
        hive = _mock_hive("software", {})
        snapshot = snapshot_from_hive(hive)
        assert snapshot.scopes == {}

    def test_scope_from_key_stringifies_values(self):
        hive = _mock_hive("ntuser", {"Environment": {"Count": 3}})
        assert scope_from_key(hive, "Environment") == {"Count": "3"}
