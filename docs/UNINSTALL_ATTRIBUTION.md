# Uninstall Attribution

`uninstall_attribution` is a read-only forensic helper for questions such as
“was this program removed, or did the collection miss a user hive?” It joins
the machine-wide uninstall view in `SOFTWARE` with one or more per-user
`NTUSER.DAT` views, Windows Installer context, and a baseline/current pair of
collection snapshots. It does not read the running registry, call `winreg`, or
probe an install path on disk.

## Identity

An attribution key is composite:

```text
(subject_kind, subject_id, product_id)
```

`subject_kind` is `machine` or `user`; `subject_id` is the machine identifier
or user SID. Consequently the same ProductCode in `SOFTWARE` and in Alice’s
`NTUSER.DAT` produces two independent attributions and is never merged.

Windows Installer `ProductCode` values are normalized to braced GUIDs. The
packed keys below `Classes\Installer\Products` and
`Installer\UserData\<SID>\Products` are unpacked with
`unpack_product_code()` so they can be joined to uninstall registrations
without relying on display names.

## Evidence Sources

- Machine registrations: `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
  and the `Wow6432Node` view.
- User registrations: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Uninstall`.
- MSI product context: `SOFTWARE\Classes\Installer\Products`, per-user
  `Installer\UserData\<SID>\Products\<packed-code>\InstallProperties`, and
  `NTUSER.DAT\Software\Microsoft\Installer\Products`.
- Profile mapping: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`.

Every record receives a deterministic evidence ID containing the collection,
subject, source kind, and product key. The report exposes an `evidence_index`
and each attribution carries `supporting_evidence`, `contrary_evidence`, and
`missing_evidence` arrays.

## States

| State | Rule |
| --- | --- |
| `installed` | A current uninstall registration is observed for the subject. |
| `explicit_uninstall` | A baseline registration exists, current coverage is observed, and the current collection has neither the registration nor install context. |
| `manual_residue` | Install context remains without a current registration, either after a baseline registration disappeared or as context-only evidence when a baseline is available. |
| `undetermined` | The current subject hive is missing, or there is not enough baseline/context evidence to choose another state. |

The missing-hive rule is intentional: absence of a user registration in a
collection that did not include that user’s hive is never converted into
`explicit_uninstall`.

## Python API

```python
from regipy.uninstall_attribution import (
    CollectionSnapshot, analyze_uninstall_attribution, compare_attribution_reports,
)

baseline = CollectionSnapshot(
    "baseline",
    software_hive=baseline_software,
    user_hives={"S-1-5-21-...-1001": baseline_alice_ntuser},
    expected_user_ids={"S-1-5-21-...-1001"},
)
current = CollectionSnapshot(
    "current",
    software_hive=current_software,
    user_hives={"S-1-5-21-...-1001": current_alice_ntuser},
)

report = analyze_uninstall_attribution(current=current, baseline=baseline)
print(report["coverage"]["complete"])
print(report["attributions"])
print(report["changes"])
```

After adding a previously missing hive, compare the two reports:

```python
diff = compare_attribution_reports(partial_report, completed_report)
print(diff["coverage_changes"])
print(diff["conclusion_changes"])  # changed_by lists the evidence IDs that changed the decision
```

## CLI

```bash
regipy-uninstall-attribution \
  --software /evidence/current/SOFTWARE \
  --baseline-software /evidence/baseline/SOFTWARE \
  --user-hive S-1-5-21-...-1001=/evidence/current/NTUSER.DAT \
  --baseline-user-hive S-1-5-21-...-1001=/evidence/baseline/NTUSER.DAT \
  --expected-user S-1-5-21-...-1001 \
  -o attribution.json
```

All hive paths are explicit inputs. The command never enumerates a live
profile or registry location.

## Offline Demo

```bash
PYTHONPATH=. python docs/uninstall_attribution_demo.py
```

The demo uses synthetic in-memory hives. With the user hive omitted, the same
ProductCode that is `installed` for the machine subject is `undetermined` for
Alice. After `with_user_hive()` adds Alice’s hive, the conclusion becomes
`installed`; `compare_attribution_reports()` identifies the new current user
`uninstall_registration` evidence as `changed_by` and reports the coverage
transition from `missing` to `observed`.
