"""
Tests for the offline service-hijack plugin.

All hives are synthesized in-process by regipy_tests.synthetic.hive_builder, so the
suite needs no Windows host and no captured binary hives. The scenarios cover:

* ControlSet selection changes (Select vs explicit boot context vs unknown),
* a ServiceDll shared by several services,
* missing and circular dependencies (the latter must terminate),
* context limits when SOFTWARE / environment information is absent.
"""

import os
import shutil
import tempfile

import pytest

from regipy.plugins.system.service_hijack import (
    ROLE_CANDIDATE,
    ROLE_CURRENT,
    ROLE_UNKNOWN,
    ServiceHijackPlugin,
)
from regipy.registry import RegistryHive
from regipy_tests.synthetic.hive_builder import (
    SyntheticKey,
    add_service,
    build_synthetic_hive,
    make_system_root,
)


SYSTEM_ROOT = r"C:\Windows"
BASE_ENV = {"SystemRoot": SYSTEM_ROOT, "windir": SYSTEM_ROOT}


@pytest.fixture()
def system_hive_path():
    tmp_dir = tempfile.mkdtemp(dir=".")

    def _build(root: SyntheticKey) -> str:
        path = os.path.join(tmp_dir, "SYSTEM")
        build_synthetic_hive(root, path)
        return path

    yield _build
    shutil.rmtree(tmp_dir, ignore_errors=True)



def _run(hive_path, **kwargs):
    hive = RegistryHive(hive_path, hive_type="system")
    plugin = ServiceHijackPlugin(hive, as_json=True, **kwargs)
    plugin.run()
    return plugin.entries


def _by_name(entries, control_set, service_name):
    for entry in entries:
        if entry["control_set"] == control_set and entry["service_name"] == service_name:
            return entry
    raise AssertionError(f"{service_name} not found in {control_set}")


def _rules(entry):
    return {finding["rule"] for finding in entry["findings"]}


def _multi_control_set_root():
    root = make_system_root()
    root.set_dword(r"Select", "Current", 1)
    root.set_dword(r"Select", "Default", 1)
    root.set_dword(r"Select", "LastKnownGood", 2)
    root.set_dword(r"Select", "Failed", 0)
    # ControlSet001: the active set, hosts a hijacked shared-process service.
    add_service(
        root, r"ControlSet001", "SharedSvc", service_type=0x20, start=2,
        image_path=r"%SystemRoot%\System32\svchost.exe",
        service_dll=r"C:\Users\Public\shared_evil.dll",
    )
    # ControlSet002: the last-known-good candidate with the legitimate DLL.
    add_service(
        root, r"ControlSet002", "SharedSvc", service_type=0x20, start=2,
        image_path=r"%SystemRoot%\System32\svchost.exe",
        service_dll=r"%SystemRoot%\System32\shared_good.dll",
    )
    # ControlSet003: present but never referenced by Select.
    add_service(
        root, r"ControlSet003", "SharedSvc", service_type=0x20, start=2,
        image_path=r"%SystemRoot%\System32\svchost.exe",
        service_dll=r"D:\staging\shared_unknown.dll",
    )
    return root


def test_select_drives_current_candidate_and_unknown_roles(system_hive_path):
    path = system_hive_path(_multi_control_set_root())
    entries = _run(path, environment=dict(BASE_ENV))

    current = _by_name(entries, "ControlSet001", "SharedSvc")
    candidate = _by_name(entries, "ControlSet002", "SharedSvc")
    unknown = _by_name(entries, "ControlSet003", "SharedSvc")

    assert current["control_set_role"] == ROLE_CURRENT
    assert "Select" in current["role_reason"]
    assert candidate["control_set_role"] == ROLE_CANDIDATE
    assert unknown["control_set_role"] == ROLE_UNKNOWN
    # Only the current set carries the confirmed substitution.
    assert "path_substitution" in _rules(current)
    # The candidate points at a trusted System32 DLL, so it carries no substitution.
    assert "path_substitution" not in _rules(candidate)
    # The unknown set has a substitution but it cannot be asserted as in-force.
    unknown_sub = next(f for f in unknown["findings"] if f["rule"] == "path_substitution")
    assert unknown_sub["severity"] == "unverified"


def test_explicit_boot_context_overrides_select(system_hive_path):
    path = system_hive_path(_multi_control_set_root())
    entries = _run(path, active_control_set=2, environment=dict(BASE_ENV))

    forced_current = _by_name(entries, "ControlSet002", "SharedSvc")
    demoted = _by_name(entries, "ControlSet001", "SharedSvc")
    assert forced_current["control_set_role"] == ROLE_CURRENT
    assert "Explicit boot context" in forced_current["role_reason"]
    assert demoted["control_set_role"] == ROLE_CANDIDATE
    # The formerly-current set is now a candidate and its verdict is downgraded.
    demoted_sub = next(f for f in demoted["findings"] if f["rule"] == "path_substitution")
    assert demoted_sub["severity"] == "unverified"
    # The newly current set is clean, while the demoted set is downgraded.
    assert "path_substitution" not in _rules(forced_current)


def test_shared_service_dll_is_correlated_per_service(system_hive_path):
    root = make_system_root()
    root.set_dword(r"Select", "Current", 1)
    shared_dll = r"C:\ProgramData\vendor\shared.dll"
    for name in ("SvcOne", "SvcTwo", "SvcThree"):
        add_service(
            root, r"ControlSet001", name, service_type=0x20, start=2,
            image_path=r"%SystemRoot%\System32\svchost.exe -k netsvcs",
            service_dll=shared_dll,
        )
    path = system_hive_path(root)
    entries = _run(path, environment=dict(BASE_ENV))

    flagged = [e for e in entries if "path_substitution" in _rules(e)]
    assert {e["service_name"] for e in flagged} == {"SvcOne", "SvcTwo", "SvcThree"}
    for entry in flagged:
        dll_finding = next(f for f in entry["findings"] if f["rule"] == "path_substitution")
        assert dll_finding["field"] == "ServiceDll"
        assert entry["service_dll"] == shared_dll
        assert entry["service_type_label"] == "win32_share_process"


def test_missing_dependency_is_reported_not_assumed_executed(system_hive_path):
    root = make_system_root()
    root.set_dword(r"Select", "Current", 1)
    add_service(
        root, r"ControlSet001", "Needy", service_type=0x10, start=2,
        image_path=r"%SystemRoot%\System32\needy.exe",
        dependencies=["AbsentDep", "AlsoAbsent"],
    )
    path = system_hive_path(root)
    entries = _run(path, environment=dict(BASE_ENV))
    entry = _by_name(entries, "ControlSet001", "Needy")
    assert set(entry["missing_dependencies"]) == {"AbsentDep", "AlsoAbsent"}
    assert "missing_dependency" in _rules(entry)
    chain_names = {node["name"] for node in entry["dependency_chain"]}
    assert {"AbsentDep", "AlsoAbsent"}.issubset(chain_names)
    assert all(not node["present"] for node in entry["dependency_chain"])


def test_circular_dependency_terminates_and_is_flagged(system_hive_path):
    root = make_system_root()
    root.set_dword(r"Select", "Current", 1)
    add_service(root, r"ControlSet001", "RingA", service_type=0x10, start=2,
                 image_path=r"%SystemRoot%\System32\a.exe", dependencies=["RingB"])
    add_service(root, r"ControlSet001", "RingB", service_type=0x10, start=3,
                 image_path=r"%SystemRoot%\System32\b.exe", dependencies=["RingC"])
    add_service(root, r"ControlSet001", "RingC", service_type=0x10, start=3,
                 image_path=r"%SystemRoot%\System32\c.exe", dependencies=["RingA"])
    path = system_hive_path(root)
    # Must return instead of looping forever.
    entries = _run(path, environment=dict(BASE_ENV))
    for name in ("RingA", "RingB", "RingC"):
        entry = _by_name(entries, "ControlSet001", name)
        assert entry["circular_dependencies"], f"{name} should report a cycle"
        assert "circular_dependency" in _rules(entry)
        assert any(node["circular"] for node in entry["dependency_chain"])


def test_missing_environment_downgrades_to_unverified(system_hive_path):
    root = make_system_root()
    root.set_dword(r"Select", "Current", 1)
    add_service(
        root, r"ControlSet001", "EnvSvc", service_type=0x10, start=2,
        image_path=r"%CompanyRoot%\bin\envsvc.exe",
    )
    path = system_hive_path(root)
    # No environment and no SOFTWARE hive: the path cannot be judged.
    entries = _run(path)
    entry = _by_name(entries, "ControlSet001", "EnvSvc")
    assert "unverified_path" in _rules(entry)
    assert "path_substitution" not in _rules(entry)
    assert any("CompanyRoot" in limit for limit in entry["analysis_limits"])


def test_missing_software_context_prevents_confirmed_verdict(system_hive_path):
    root = make_system_root()
    root.set_dword(r"Select", "Current", 1)
    add_service(
        root, r"ControlSet001", "NoAnchor", service_type=0x10, start=2,
        image_path=r"C:\Users\Public\noanchor.exe",
    )
    path = system_hive_path(root)
    # Environment without SystemRoot and no SOFTWARE hive means no trusted anchor.
    entries = _run(path, environment={"UnrelatedVar": "x"})
    entry = _by_name(entries, "ControlSet001", "NoAnchor")
    assert "unverified_path" in _rules(entry)
    assert "path_substitution" not in _rules(entry)
    assert any("SystemRoot" in limit for limit in entry["analysis_limits"])


def test_raw_values_and_correlation_chain_are_preserved(system_hive_path):
    root = make_system_root()
    root.set_dword(r"Select", "Current", 1)
    add_service(
        root, r"ControlSet001", "Documented", service_type=0x10, start=2,
        image_path=r"%SystemRoot%\System32\doc.exe",
        object_name="LocalSystem",
        dependencies=["Helper"],
    )
    add_service(root, r"ControlSet001", "Helper", service_type=0x20, start=3,
                 image_path=r"%SystemRoot%\System32\svchost.exe",
                 service_dll=r"%SystemRoot%\System32\helper.dll")
    path = system_hive_path(root)
    entries = _run(path, environment=dict(BASE_ENV))
    entry = _by_name(entries, "ControlSet001", "Documented")

    raw_names = {value["name"] for value in entry["raw_values"]}
    assert {"Type", "Start", "ImagePath", "ObjectName", "DependOnService"}.issubset(raw_names)
    assert all("value_type" in value and "is_corrupted" in value for value in entry["raw_values"])
    helper = next(node for node in entry["dependency_chain"] if node["name"] == "Helper")
    assert helper["present"] is True
    assert helper["start_label"] == "manual"
    assert entry["image_path_expanded"] == r"C:\Windows\System32\doc.exe"


def test_unknown_control_set_when_select_absent(system_hive_path):
    root = make_system_root()
    add_service(root, r"ControlSet001", "Lone", service_type=0x10, start=2,
                 image_path=r"%SystemRoot%\System32\lone.exe")
    path = system_hive_path(root)
    entries = _run(path, environment=dict(BASE_ENV))
    entry = _by_name(entries, "ControlSet001", "Lone")
    assert entry["control_set_role"] == ROLE_UNKNOWN
    assert any("Select key not found" in limit for limit in entry["analysis_limits"])


def test_software_hive_anchor_confirms_substitution(system_hive_path):
    from regipy_tests.synthetic.hive_builder import build_synthetic_hive as _build
    root = make_system_root()
    root.set_dword(r"Select", "Current", 1)
    add_service(
        root, r"ControlSet001", "AnchorSvc", service_type=0x10, start=2,
        image_path=r"C:\Users\Public\anchor.exe",
    )
    sys_path = system_hive_path(root)

    software_root = SyntheticKey(name="CMI-CreateHive")
    software_root.set_sz(r"Microsoft\Windows NT\CurrentVersion", "SystemRoot", SYSTEM_ROOT)
    import os as _os
    sw_path = _os.path.join(_os.path.dirname(sys_path), "SOFTWARE")
    _build(software_root, sw_path, file_name=r"\SystemRoot\System32\Config\SOFTWARE")

    system_hive = RegistryHive(sys_path, hive_type="system")
    software_hive = RegistryHive(sw_path, hive_type="software")
    plugin = ServiceHijackPlugin(system_hive, as_json=True, software_hive=software_hive)
    plugin.run()
    entry = plugin.entries[0]
    substitution = next(f for f in entry["findings"] if f["rule"] == "path_substitution")
    assert substitution["severity"] == "suspicious"
    assert substitution["trusted_anchor"] == SYSTEM_ROOT
    assert not any("SystemRoot" in limit for limit in entry["analysis_limits"])
