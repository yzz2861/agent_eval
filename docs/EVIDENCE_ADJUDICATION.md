# Execution Evidence Adjudication

The `regipy.evidence` subpackage turns existing plugin output into conservative
**facts** and combines them under explicit rules. It is opt-in and never
changes plugin output: every plugin keeps emitting its original entries.

## Why adjudication is needed

A single artifact rarely answers "did this user run this program?":

* **AmCache** proves a file was *present* on the volume. It does not prove the
  file was executed.
* **UserAssist** records Explorer run counts. A positive `run_counter` is
  execution evidence; a zero counter only shows the program was enumerated.
* **BAM** records per-SID background activity and attributes execution to a
  specific user.
* **ShimCache** is populated for compatibility reasons; it only supports a weak
  "execution possible" reading, even when its flag is set.

Absence is never treated as negation. If UserAssist has no entry for a program,
the API reports insufficient evidence, not "not executed". A hive that was not
collected is recorded as a **coverage gap**.

## Verdicts

| Verdict | Chinese label | Meaning |
| --- | --- | --- |
| `insufficient_evidence` | 证据不足 | No aligned facts for the queried subject, or its facts could not be aligned. |
| `present` | 存在 | Only file-presence facts (e.g. AmCache on its own). |
| `possibly_executed` | 可能执行 | Weak execution-related facts, no strong execution fact. |
| `execution_evidenced` | 已获执行证据 | At least one strong `execution_occurred` fact. |

## Alignment rules

Facts from different hives are only spliced into one conclusion when all of the
following align:

1. **User identity** - SIDs must match, or both facts must come from the same
   user-scoped hive. Machine-wide artifacts (AmCache, ShimCache) describe the
   host and may support any user cluster. An attributable fact is never spliced
   into an anonymous one.
2. **Path equivalence** - environment placeholders (`%SYSTEM32%`), NT device
   paths (`\Device\HarddiskVolumeN\...`), `\??\` prefixes and case differences
   are normalized. Without a registered volume-to-drive mapping, device paths
   stay distinct instead of collapsing onto drive letters. Per-user
   placeholders such as `%APPDATA%` cannot be expanded and never match.
3. **Acquisition window** - windows must be identical (and fully known) or
   provably overlapping. Disjoint windows produce `window_disjoint`
   counter-evidence; partially recorded windows produce `window_unknown`.
   Neither case is spliced.

Unalignable facts are retained as explicit **counter-evidence** with the failing
reason. Contradictory facts (for example a zero UserAssist run counter next to a
strong BAM execution record) are both retained in `conflicts`; they are never
merged by timestamp.

## Usage

```python
import datetime as dt
from regipy.evidence import (
    CollectionWindow,
    EvidenceAdjudicator,
    UserIdentity,
)

UTC = dt.timezone.utc
adjudicator = EvidenceAdjudicator(
    volume_mappings={r"\Device\HarddiskVolume2": "C:"},
)

# Machine-wide AmCache: file presence only.
adjudicator.add_plugin_output(
    "amcache",
    amcache_plugin.entries,
    window=CollectionWindow(
        dt.datetime(2020, 1, 1, tzinfo=UTC),
        dt.datetime(2020, 2, 15, tzinfo=UTC),
        source_name="amcache",
    ),
)

# User-scoped UserAssist from alice's NTUSER.DAT.
adjudicator.add_plugin_output(
    "user_assist",
    user_assist_plugin.entries,
    window=CollectionWindow(
        dt.datetime(2020, 1, 1, tzinfo=UTC),
        dt.datetime(2020, 2, 1, tzinfo=UTC),
        source_name="ntuser-alice",
    ),
    identity=UserIdentity(sid="S-1-5-21-1-1001", username="alice"),
)

for conclusion in adjudicator.adjudicate_all():
    print(conclusion.to_dict())
    # conclusion.verdict, conclusion.minimal_support,
    # conclusion.supporting_fact_ids, conclusion.counter_evidence,
    # conclusion.coverage_gaps, conclusion.conflicts

# Or query one program/user directly.
result = adjudicator.adjudicate_path(
    r"C:\Windows\System32\cmd.exe",
    UserIdentity(sid="S-1-5-21-1-1001"),
)
```

The one-shot helper accepts raw plugin outputs plus optional windows and
identities:

```python
from regipy.evidence import adjudicate

conclusions = adjudicate(
    plugin_outputs={
        "amcache": amcache_entries,
        "user_assist": user_assist_entries,
    },
    windows={"amcache": amcache_window, "user_assist": ntuser_window},
    identities={"user_assist": alice},
    volume_mappings={r"\Device\HarddiskVolume2": "C:"},
)
```

Every conclusion is JSON-serializable via `to_dict()`. `minimal_support` holds
the smallest fact-id set that justifies the verdict; `supporting_fact_ids`
lists every fact considered; `counter_evidence` explains why each excluded fact
could not be spliced in.

## Supported sources

| Source key (plugin `NAME`) | Proposition emitted |
| --- | --- |
| `amcache` | weak `file_present`, machine-wide |
| `user_assist` | strong `execution_occurred` when `run_counter > 0`, otherwise weak `execution_possible` |
| `background_activity_moderator` (BAM) | strong per-SID `execution_occurred` |
| `shimcache` | weak machine-wide `execution_possible` |

Unknown source names raise `ValueError` so evidence cannot be silently dropped.
