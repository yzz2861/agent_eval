# Evidence Dependencies and On-Demand Re-verification

Forensic plugins draw each conclusion from specific registry evidence: a key
they read, a value they read, or — just as importantly — the *absence* of an
expected key or value. When a supplemental registry extract arrives that
changes only a handful of cells, re-running every plugin to decide whether an
old report still holds is wasteful and obscures what actually changed.

regipy lets plugins **declare their evidence dependencies**. A re-verification
manager then compares the incoming patch against the recorded evidence and
reruns only the plugins whose conclusions the patch can invalidate, while
preserving the previous report and recording the exact invalidation scope.

## Declaring evidence in a plugin

Every `Plugin` instance owns an `EvidenceTracker` (`self.evidence`) and exposes
four declarative helpers:

| Helper | Meaning |
| --- | --- |
| `self.evidence_key_read(path)` | The key at `path` was read and participated in the conclusion. |
| `self.evidence_value_read(path, name)` | Value `name` under `path` was read. |
| `self.evidence_key_missing(path)` | A lookup of `path` failed and that absence participated in the conclusion. |
| `self.evidence_value_missing(path, name)` | Value `name` was looked up, not found, and that absence participated. |

Bind each emitted entry to the evidence that produced it with
`self.bind_evidence(index, evidence_indices)`. The `evidence_scope()` context
manager collects the evidence consulted for one entry:

```python
def run(self):
    try:
        key = self.registry_hive.get_key(KEY_PATH)
    except RegistryKeyNotFoundException:
        # The "no artifact" conclusion rests on the key's absence.
        self.evidence_key_missing(KEY_PATH)
        self.entries.append({"artifact_present": False})
        self.bind_evidence(len(self.entries) - 1)
        return

    with self.evidence_scope() as scope:
        self.evidence_key_read(KEY_PATH)
        value = key.get_value("Indicator")
        self.evidence_value_read(KEY_PATH, "Indicator")
    self.entries.append({"indicator": value})
    self.bind_evidence(len(self.entries) - 1, scope)
```

Entries emitted without an explicit binding conservatively depend on all
evidence collected by the plugin, so such a plugin is re-verified wholesale.

Registry paths and value names are normalized case-insensitively (the Windows
registry is case-insensitive), so declarations match regardless of casing.

## Modelling a supplemental extract

Patches live in `regipy.patching` and are applied through an in-memory
read-only overlay (`PatchedRegistryHive`); the original hive file is never
rewritten.

```python
from regipy.patching import AddedKeyPatch, ValueChangePatch

# An existing value is corrected.
value_patch = ValueChangePatch(
    r"\Software\Microsoft\Windows\CurrentVersion\Run",
    "Sidebar",
    r"C:\Supplemental\Sidebar.exe /autoRun",
    value_type="REG_EXPAND_SZ",
)

# A previously missing key (with values) is supplied.
key_patch = AddedKeyPatch(
    r"\Software\MyVendor\MissingArtifact",
    values={"Indicator": "supplemental-artifact"},
)
```

## Selective re-verification

```python
from regipy.reverification import ReverificationManager

manager = ReverificationManager(hive, as_json=True)
manager.register_run([plugin_a, plugin_b])  # plugins that already ran

# Inspect the invalidation scope without rerunning anything.
scopes = manager.plan_invalidation([value_patch])

# Rerun only the affected plugins on the patched overlay.
result = manager.reverify([value_patch], previous_report)
result.affected_plugins      # plugins whose evidence intersects the patch
result.unaffected_plugins    # plugins whose old conclusions still hold
result.previous_report       # the report as it was before this round
result.new_report            # previous report with affected entries refreshed
result.invalidation_scopes   # evidence ids, entry indices and human reasons
result.save_report_bundle("review/round1.json")
```

A `ValueChangePatch` invalidates key-read evidence on its key and value-read /
value-missing evidence for the named value only; an `AddedKeyPatch`
invalidates key-missing (and value-missing) evidence at the added key path and
its subpaths. Each round therefore pulls in only the conclusions that actually
depended on the changed cells — a value correction never invalidates a
conclusion resting on an unrelated missing key, and vice versa.

## Reference plugins

The interface is demonstrated by three shipped plugins:

* `regipy/plugins/ntuser/typed_urls.py` — value-read evidence plus a
  key-missing declaration when the TypedURLs key does not exist.
* `regipy/plugins/ntuser/network_drives.py` — per-drive entries bound to the
  `RemotePath` value evidence, and a key-missing declaration for `\Network`.
* `regipy/plugins/system/computer_name.py` — each emitted entry scoped to the
  `ComputerName` value it reads.

The end-to-end two-round scenario (correct a value, then supply a missing
key, each round invalidating only its own dependencies) is covered in
`regipy_tests/test_evidence_reverification.py`.
