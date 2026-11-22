# Evidence dependency & targeted revalidation demo

This example shows the evidence-dependency interface added under
`regipy/evidence/`. It answers a concrete forensic workflow problem: after
supplemental registry material ("buchuan") arrives, only the conclusions whose
evidence actually changed should be revalidated — the rest of the old report
stays citable.

## What is demonstrated

`demo_plugins.py` defines two evidence-aware plugins with disjoint evidence:

- `demo_persistence_evidence` emits one entry per `...\CurrentVersion\Run`
  value. Each entry declares a value-level dependency on that exact value
  (plus the parent key).
- `demo_stored_credential_evidence` emits a `no_stored_sessions` entry when the
  WinSCP `Sessions` key is absent. The conclusion explicitly declares the
  **missing key** as evidence, so it can be revoked later if the key is
  recovered.

`run_revalidation_demo.py` then performs two independent supplemental actions:

1. **Edit an existing value** (`Run\Sidebar` changes command). Only the
   persistence plugin has evidence on that value, so only
   `demo_persistence_evidence` is revalidated. The stored-credential entry is
   retained untouched (same entry id, no re-run).
2. **Supply the previously missing key** (the WinSCP `Sessions` key is added).
   Only `demo_stored_credential_evidence` declared that missing-key evidence,
   so only it is revalidated: the old `no_stored_sessions` conclusion is
   revoked with the exact reason and a new `stored_session` entry appears. The
   persistence finding remains valid without any re-run.

Each revalidation:

- writes the new report to `output/evidence_report.json`;
- moves the previous report into `output/archive/` (the old report is never
  overwritten);
- records the per-entry **revocation scope** (entry id, stale evidence refs,
  human-readable reasons) inside `revalidation_history`.

## Run it

```bash
python examples/evidence_revalidation/run_revalidation_demo.py
```

## The interface in one minute

```python
from regipy.evidence import EvidenceAwarePlugin

class MyPlugin(EvidenceAwarePlugin):
    def run(self):
        # automatic tracking: every lookup through self.tracked becomes evidence
        key = self.tracked.get_key(r"\Some\Key")
        # explicit negative evidence: a missing item participates in the conclusion
        if not self.evidence.key_exists(r"\Some\Other\Key"):
            self.declare_key_absent(r"\Some\Other\Key", note="absence is part of the finding")
        # bind evidence to an individual output entry
        with self.entry_scope(entry_id):
            self.tracked.get_value(r"\Some\Key", "ValueName")
        self.add_evidenced_entry({...}, entry_id=entry_id)
```

Reports are produced with `build_evidence_report()` / `save_report()` and
revalidated with `revalidate_report()`, which diffs the new source against the
baseline snapshot embedded in the report and re-runs only affected plugins.
