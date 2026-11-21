from regipy.hive_types import NTUSER_HIVE_TYPE, SOFTWARE_HIVE_TYPE
from regipy.plugins.software.uninstall_attribution import UninstallAttributionPlugin
from regipy.registry import RegistryHive
from regipy.uninstall_attribution import (
    EVIDENCE_UNINSTALL_REGISTRATION,
    STATE_EXPLICIT_UNINSTALL,
    STATE_INSTALLED,
    STATE_MANUAL_RESIDUE,
    STATE_UNDETERMINED,
    CollectionSnapshot,
    analyze_uninstall_attribution,
    compare_attribution_reports,
    pack_product_code,
    unpack_product_code,
)
from regipy_tests.synthetic_hive import build_hive

MACHINE_UNINSTALL = r"\Microsoft\Windows\CurrentVersion\Uninstall"
USER_UNINSTALL = r"\Software\Microsoft\Windows\CurrentVersion\Uninstall"
MACHINE_PRODUCTS = r"\Classes\Installer\Products"
USER_PRODUCTS = r"\Software\Microsoft\Installer\Products"
PROFILE_LIST = r"\Microsoft\Windows NT\CurrentVersion\ProfileList"

PRODUCT = "{11111111-1111-1111-1111-111111111111}"
PRODUCT_REMOVED = "{22222222-2222-2222-2222-222222222222}"
PRODUCT_RESIDUE = "{33333333-3333-3333-3333-333333333333}"
SID_ALICE = "S-1-5-21-100-200-300-1001"
ALICE_PROFILE = r"C:\Users\alice"


def _machine_software(*products, contexts=()):
    entries = {}
    for product in products:
        entries[rf"{MACHINE_UNINSTALL}\{product}"] = {
            "DisplayName": f"Product {product}",
            "UninstallString": f"msiexec /x {product}",
            "InstallLocation": r"C:\Program Files\Contoso",
        }
    for product in contexts:
        entries[rf"{MACHINE_PRODUCTS}\{pack_product_code(product)}"] = {
            "ProductName": f"Product {product}",
        }
    entries[rf"{PROFILE_LIST}\{SID_ALICE}"] = {"ProfileImagePath": ALICE_PROFILE}
    return build_hive(SOFTWARE_HIVE_TYPE, entries)


def _user_hive(products):
    entries = {}
    for product in products:
        entries[rf"{USER_UNINSTALL}\{product}"] = {
            "DisplayName": f"Product {product} (alice)",
            "UninstallString": f"msiexec /x {product}",
            "InstallLocation": rf"{ALICE_PROFILE}\AppData\Local\Contoso",
        }
        entries[rf"{USER_PRODUCTS}\{pack_product_code(product)}"] = {
            "ProductName": f"Product {product} (alice)",
        }
    return build_hive(NTUSER_HIVE_TYPE, entries)


def test_packed_product_code_round_trip():
    product = "{90140000-00A1-0409-0000-0000000FF1CE}"
    packed = pack_product_code(product)
    assert packed == "000041091A0090400000000000F01FEC"
    assert unpack_product_code(packed) == product


def test_same_product_is_attributed_to_machine_and_user_subjects():
    baseline_software = _machine_software(PRODUCT, contexts=[PRODUCT])
    baseline_user = _user_hive([PRODUCT])
    current_software = _machine_software(PRODUCT, contexts=[PRODUCT])
    current_user = _user_hive([PRODUCT])
    baseline = CollectionSnapshot(
        "baseline",
        baseline_software,
        {SID_ALICE: baseline_user},
        expected_user_ids={SID_ALICE},
    )
    partial_current = CollectionSnapshot("current", current_software)

    partial = analyze_uninstall_attribution(current=partial_current, baseline=baseline)
    user_rows = [row for row in partial["attributions"] if row["subject_kind"] == "user" and row["product_id"] == PRODUCT]
    machine_rows = [row for row in partial["attributions"] if row["subject_kind"] == "machine" and row["product_id"] == PRODUCT]
    assert len(user_rows) == 1
    assert len(machine_rows) == 1
    assert machine_rows[0]["state"] == STATE_INSTALLED
    assert user_rows[0]["state"] == STATE_UNDETERMINED
    assert user_rows[0]["reason"] == "missing_subject_hive"
    assert partial["coverage"]["complete"] is False

    completed_current = partial_current.with_user_hive(
        SID_ALICE,
        current_user,
        profile_path=ALICE_PROFILE,
    )
    completed = analyze_uninstall_attribution(current=completed_current, baseline=baseline)
    completed_user = next(
        row for row in completed["attributions"] if row["subject_kind"] == "user" and row["product_id"] == PRODUCT
    )
    assert completed_user["state"] == STATE_INSTALLED
    assert completed["coverage"]["complete"] is True

    report_diff = compare_attribution_reports(partial, completed)
    change = next(
        item
        for item in report_diff["conclusion_changes"]
        if item["subject"]["kind"] == "user" and item["product_id"] == PRODUCT
    )
    assert change["previous"]["state"] == STATE_UNDETERMINED
    assert change["current"]["state"] == STATE_INSTALLED
    assert any(
        evidence["kind"] == EVIDENCE_UNINSTALL_REGISTRATION and evidence["collection_id"] == "current"
        for evidence in change["changed_by_evidence"]
    )
    assert report_diff["coverage_changes"]


def test_explicit_uninstall_is_distinct_from_manual_residue():
    baseline_software = _machine_software(
        PRODUCT_REMOVED,
        PRODUCT_RESIDUE,
        contexts=[PRODUCT_REMOVED, PRODUCT_RESIDUE],
    )
    current_software = build_hive(
        SOFTWARE_HIVE_TYPE,
        {
            rf"{MACHINE_PRODUCTS}\{pack_product_code(PRODUCT_RESIDUE)}": {
                "ProductName": f"Product {PRODUCT_RESIDUE}",
            },
            rf"{PROFILE_LIST}\{SID_ALICE}": {"ProfileImagePath": ALICE_PROFILE},
        },
    )
    baseline = CollectionSnapshot("baseline", baseline_software)
    current = CollectionSnapshot("current", current_software)
    report = analyze_uninstall_attribution(current=current, baseline=baseline)
    by_product = {row["product_id"]: row for row in report["attributions"]}

    removed = by_product[PRODUCT_REMOVED]
    residue = by_product[PRODUCT_RESIDUE]
    assert removed["state"] == STATE_EXPLICIT_UNINSTALL
    assert removed["reason"] == "registration_removed_between_complete_collections"
    assert removed["decision_trace"]["inputs"]["current_install_context"] is False
    assert residue["state"] == STATE_MANUAL_RESIDUE
    assert residue["reason"] == "registration_removed_but_install_context_persists"
    assert residue["decision_trace"]["inputs"]["current_install_context"] is True
    assert residue["decision_trace"]["contrary_evidence"]

    changes = {change["product_id"]: change for change in report["changes"]}
    assert changes[PRODUCT_REMOVED]["registration_change"] == "removed"
    assert changes[PRODUCT_RESIDUE]["install_context_change"] == "retained"


def test_real_hive_plugin_reports_read_only_attributions(software_hive):
    plugin = UninstallAttributionPlugin(RegistryHive(software_hive), as_json=True)
    plugin.run()
    assert plugin.report is not None
    assert plugin.report["read_only"] is True
    assert plugin.report["coverage"]["complete"] is True
    assert len(plugin.report["attributions"]) >= 67
    assert any(
        row["product_id"] == "{00FC3F65-86EB-475E-881F-A5B1CF731320}" and row["state"] == STATE_INSTALLED
        for row in plugin.report["attributions"]
    )


def test_real_user_hive_is_joined_to_machine_snapshot(software_hive, ntuser_hive_2):
    current = CollectionSnapshot(
        "current",
        RegistryHive(software_hive),
        {SID_ALICE: RegistryHive(ntuser_hive_2)},
    )
    report = analyze_uninstall_attribution(current=current)
    zoom = next(row for row in report["attributions"] if row["subject_kind"] == "user" and row["product_id"] == "ZoomUMX")
    assert zoom["state"] == STATE_INSTALLED
    assert report["coverage"]["complete"] is True
