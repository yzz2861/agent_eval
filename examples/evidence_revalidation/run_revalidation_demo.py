"""Two-step supplemental-evidence ("buchuan") demo.

Scenario
--------

The baseline NTUSER hive holds one Run value (``Sidebar``) and has no WinSCP
``Sessions`` key. The initial evidence report therefore contains:

* a persistence finding backed by the ``Run\\Sidebar`` value reference;
* a no-stored-session finding backed by a *missing key* reference.

Two supplemental actions then arrive independently:

1. An existing value is changed (``Run\\Sidebar`` points at a new binary).
   Only the persistence finding carries evidence on that value, so only
   ``demo_persistence_evidence`` is revalidated; the missing-key conclusion
   stays untouched and keeps its original entry id.
2. The previously missing WinSCP ``Sessions`` key is supplied. Only the
   stored-credential plugin ever declared that missing-key evidence, so only
   ``demo_stored_credential_evidence`` is revalidated; the persistence finding
   remains valid without any re-run.

Every revalidation archives the previous report and records the exact
revocation scope. Run with::

    python examples/evidence_revalidation/run_revalidation_demo.py
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from demo_plugins import (
    DEMO_PLUGINS,
    RUN_KEY_PATH,
    WINSCP_SESSIONS_PATH,
    build_demo_hive,
)

from regipy.evidence import (
    DictHive,
    build_evidence_report,
    load_report,
    revalidate_report,
    save_report,
)

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
REPORT_PATH = os.path.join(OUTPUT_DIR, "evidence_report.json")


def _summarize(report: dict) -> dict:
    return {name: [entry.get("_entry_id") for entry in section["entries"]] for name, section in report["plugins"].items()}


def main() -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    baseline_hive = DictHive(build_demo_hive(), hive_type="ntuser")
    report = build_evidence_report(baseline_hive, DEMO_PLUGINS, source_path="baseline-ntuser (in-memory)")
    save_report(report, REPORT_PATH)
    print("== Baseline report written ==")
    print(json.dumps(_summarize(report), indent=2))

    # Step 1: supplement a changed *existing* value.
    value_edited_hive = baseline_hive.apply_changes(
        value_changes={
            (RUN_KEY_PATH, "Sidebar"): r"C:\Users\public\sidebar-patched.exe /autoRun",
        }
    )
    step_one = revalidate_report(
        load_report(REPORT_PATH),
        value_edited_hive,
        DEMO_PLUGINS,
        source_path="ntuser + value edit (in-memory)",
        report_path=REPORT_PATH,
    )
    print("\n== Step 1: existing Run\\Sidebar value changed ==")
    print(json.dumps(step_one.to_dict(), indent=2, default=str))

    # Step 2: supplement the previously missing key.
    key_added_hive = value_edited_hive.apply_changes(
        added_keys={
            WINSCP_SESSIONS_PATH: {
                "timestamp": "2024-02-02T00:00:00+00:00",
                "subkeys": ["admin@example.com"],
                "values": {},
            },
            rf"{WINSCP_SESSIONS_PATH}\admin@example.com": {
                "timestamp": "2024-02-02T00:00:00+00:00",
                "subkeys": [],
                "values": {
                    "HostName": {"value": "example.com", "value_type": "REG_SZ"},
                },
            },
        }
    )
    step_two = revalidate_report(
        load_report(REPORT_PATH),
        key_added_hive,
        DEMO_PLUGINS,
        source_path="ntuser + value edit + recovered key (in-memory)",
        report_path=REPORT_PATH,
    )
    print("\n== Step 2: previously missing WinSCP Sessions key supplied ==")
    print(json.dumps(step_two.to_dict(), indent=2, default=str))

    print("\n== Archived report versions ==")
    archive_dir = os.path.join(OUTPUT_DIR, "archive")
    for name in sorted(os.listdir(archive_dir)):
        print(f" - {name}")


if __name__ == "__main__":
    main()
