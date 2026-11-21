"""Offline demo for the uninstall attribution plugin.

Run from the repository root:

    PYTHONPATH=. python docs/uninstall_attribution_demo.py

No live registry and no filesystem probing are used. The hives are tiny
in-memory trees.
"""

import json

from regipy.hive_types import NTUSER_HIVE_TYPE, SOFTWARE_HIVE_TYPE
from regipy.uninstall_attribution import (
    CollectionSnapshot,
    analyze_uninstall_attribution,
    compare_attribution_reports,
    pack_product_code,
)
from regipy_tests.synthetic_hive import build_hive

PRODUCT = "{11111111-1111-1111-1111-111111111111}"
SID_ALICE = "S-1-5-21-100-200-300-1001"
PROFILE = r"C:\Users\alice"
MACHINE_UNINSTALL = r"\Microsoft\Windows\CurrentVersion\Uninstall"
USER_UNINSTALL = r"\Software\Microsoft\Windows\CurrentVersion\Uninstall"
MACHINE_PRODUCTS = r"\Classes\Installer\Products"
PROFILE_LIST = r"\Microsoft\Windows NT\CurrentVersion\ProfileList"


def software_hive():
    return build_hive(
        SOFTWARE_HIVE_TYPE,
        {
            rf"{MACHINE_UNINSTALL}\{PRODUCT}": {
                "DisplayName": "Contoso Agent",
                "InstallLocation": r"C:\Program Files\Contoso",
                "UninstallString": f"msiexec /x {PRODUCT}",
            },
            rf"{MACHINE_PRODUCTS}\{pack_product_code(PRODUCT)}": {"ProductName": "Contoso Agent"},
            rf"{PROFILE_LIST}\{SID_ALICE}": {"ProfileImagePath": PROFILE},
        },
    )


def user_hive():
    return build_hive(
        NTUSER_HIVE_TYPE,
        {
            rf"{USER_UNINSTALL}\{PRODUCT}": {
                "DisplayName": "Contoso Agent (Alice)",
                "InstallLocation": rf"{PROFILE}\AppData\Local\Contoso",
                "UninstallString": f"msiexec /x {PRODUCT}",
            },
        },
    )


def main():
    baseline = CollectionSnapshot(
        "baseline",
        software_hive(),
        {SID_ALICE: user_hive()},
        expected_user_ids={SID_ALICE},
    )
    partial_current = CollectionSnapshot("current", software_hive())
    partial = analyze_uninstall_attribution(current=partial_current, baseline=baseline)

    completed_current = partial_current.with_user_hive(SID_ALICE, user_hive(), profile_path=PROFILE)
    completed = analyze_uninstall_attribution(current=completed_current, baseline=baseline)
    diff = compare_attribution_reports(partial, completed)

    print("partial coverage:", partial["coverage"]["complete"])
    print(
        "partial user conclusion:",
        [(row["state"], row["reason"]) for row in partial["attributions"] if row["subject_kind"] == "user"],
    )
    print("completed coverage:", completed["coverage"]["complete"])
    print(
        "completed user conclusion:",
        [(row["state"], row["reason"]) for row in completed["attributions"] if row["subject_kind"] == "user"],
    )
    print("conclusion changes:")
    print(json.dumps(diff["conclusion_changes"], indent=2))
    print("coverage changes:")
    print(json.dumps(diff["coverage_changes"], indent=2))


if __name__ == "__main__":
    main()
