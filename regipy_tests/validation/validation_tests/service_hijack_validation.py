from regipy.plugins.system.service_hijack import ROLE_CANDIDATE, ROLE_CURRENT, ServiceHijackPlugin
from regipy_tests.validation.validation import ValidationCase


class ServiceHijackPluginValidationCase(ValidationCase):
    plugin = ServiceHijackPlugin
    # Deterministic multi-control-set material synthesized offline and stored
    # alongside the captured hives; see regipy_tests/synthetic/hive_builder.py.
    test_hive_file_name = "synthetic_service_hijack_system.xz"
    expected_entries_count = 2

    def custom_test(self, c: "ValidationCase") -> None:
        plugin = ServiceHijackPlugin(
            c.input_hive,
            as_json=True,
            environment={"SystemRoot": r"C:\Windows", "windir": r"C:\Windows"},
        )
        plugin.run()
        entries = {(e["control_set"], e["service_name"]): e for e in plugin.entries}

        current = entries[("ControlSet001", "SuspiciousShared")]
        candidate = entries[("ControlSet002", "SuspiciousShared")]
        assert current["control_set_role"] == ROLE_CURRENT
        assert candidate["control_set_role"] == ROLE_CANDIDATE

        rules = {f["rule"]: f for f in current["findings"]}
        assert "path_substitution" in rules
        assert rules["path_substitution"]["field"] == "ServiceDll"
        assert rules["path_substitution"]["severity"] == "suspicious"
        assert "missing_dependency" in rules
        assert current["missing_dependencies"] == ["MissingDep"]
        assert current["service_type_label"] == "win32_share_process"

        # The candidate set holds a trusted DLL and no confirmed substitution.
        assert all(f["rule"] != "path_substitution" for f in candidate["findings"])
