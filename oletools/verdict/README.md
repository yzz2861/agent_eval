# Composite verdict API (`oletools.verdict`)

Gateway-embeddable, order-independent decision layer. It takes a **container
tree** (the parsed document and every embedded sub-object) and the **results
of individual detectors** and returns one verdict plus the smallest evidence
set needed to justify it. There is no CLI and no UI here - this is a Python
API only.

## Why

Treating "no macro found" as "the file is safe" is wrong when encrypted
parts, unrecognised embedded formats or corrupt sub-documents were never
scanned. The engine keeps those cases distinct.

## The four node states

| State | Meaning |
| --- | --- |
| `RISK` | At least one detector confirmed a finding. |
| `CLEAN` | Every required capability applicable to the node ran clean. |
| `UNCOVERED` | The node was parsed but a required capability was not run (encryption, unknown format, skipped branch, ...). |
| `UNPARSEABLE` | The node or a required sub-document could not be parsed (corruption, cycle, unreadable stream). |

Document verdicts: `ALLOW`, `BLOCK_RISK`, `BLOCK_UNCOVERED`,
`BLOCK_UNPARSEABLE`.

## Propagation and counting rules

1. A confirmed finding always blocks. Removing a capability from the
   required set only relaxes *coverage*; it can never erase a finding that
   was already reported.
2. Encryption, unknown embedded formats, corruption and reference cycles are
   structural failures, never "clean". They force `UNCOVERED` /
   `UNPARSEABLE` regardless of policy.
3. Child states propagate to parents: a parent is never safer than its worst
   reachable child. An unexamined or unknown-format edge carries the worst
   state of its target, so no unchecked branch can disappear.
4. A sub-object referenced by several paths is modelled as one node with
   several incoming edges. It is counted once and evidence is deduplicated,
   while every root-to-node path is still reported.
5. Re-submitting a result for the same `(node, capability, detector,
   signature)` replaces only that record and increments its attempt count.
   Retries therefore touch one piece of evidence, never the whole set.
6. All aggregation sorts by stable keys, so the verdict and canonical JSON
   do not depend on traversal or submission order.

## Minimal blocking evidence

`VerdictReport.blocking_evidence` contains only the records that actually
justify the verdict (deduplicated). For `BLOCK_RISK` it holds just the
findings; for coverage/parse blocks it holds the structural and gap evidence.
Clean and informational records never appear there. `report.evidence` keeps
every retained record for auditing.

## Example

```python
from oletools.verdict import (
    Capability, ContainerNode, ContainerEdge, DetectorResult,
    NodeKind, Outcome, Policy, Severity, VerdictEngine,
)

root = ContainerNode("doc", kind=NodeKind.OOXML)
embedded = ContainerNode("emb1", kind=NodeKind.OLE, encrypted=True)
edges = [ContainerEdge("doc", "emb1", label="embeddings/1.bin")]

# Business decides which capabilities are mandatory.
policy = Policy(required_capabilities=[
    Capability.MACRO, Capability.DDE, Capability.ENCRYPTION,
    Capability.UNKNOWN_EMBED, Capability.PARSER,
])

engine = VerdictEngine([root], edges=edges, nodes=[embedded], policy=policy)
engine.submit_result(DetectorResult(
    "doc", Capability.MACRO, Outcome.CLEAN, "olevba"))
report = engine.evaluate()
report.verdict            # Verdict.BLOCK_UNCOVERED (encrypted part)
report.node_states        # node_id -> NodeStatus
report.blocking_evidence  # minimal, deduplicated justification
report.to_json()          # canonical, order-independent JSON

# Retry a failed detector: same detector + signature replaces one record.
engine.submit_result(DetectorResult(
    "doc", Capability.MACRO, Outcome.CLEAN, "olevba", signature="macro"))
```

### Adapting real oletools detectors

`oletools.verdict.adapters` converts `oleid` indicators without importing
the detector at module load time:

```python
from oletools.verdict.adapters import run_oleid, node_from_oleid
from oletools.verdict import VerdictEngine, Policy, Capability

results = run_oleid("doc", data=file_bytes)
oid = OleID(data=file_bytes); oid.check()
node = node_from_oleid("doc", oid)
engine = VerdictEngine([node], policy=Policy.strict_default())
engine.submit_results(results)
report = engine.evaluate()
```

## Offline tests

No network or Office files are required for the core suite. The fixtures in
`oletools/verdict/fixtures.py` build a nested, partially encrypted tree in
memory with a shared sub-object and a corrupt stream, plus a simulated
scanner that can inject transient failures to exercise retry replacement.

```
python -m pytest tests/verdict -q
```
