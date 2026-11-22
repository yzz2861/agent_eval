# audit_completeness

Query-completeness checks for audit JSON dumps that are too large to load
wholesale. The checker streams ijson public events and answers a question the
investigators care about: when a risk field is absent, is the field genuinely
*missing* from a record that was fully collected, or was the tail of the
transfer simply *not collected*?

## Public event entry points

Only public ijson API is used:

- `ijson.parse(fileobj)` for the synchronous short-read driver;
- `ijson.parse_coro(sink)` for the push/coroutine driver.

Both emit identical `(prefix, event, value)` tuples. A truncated stream makes
both raise `ijson.IncompleteJSONError`, which the drivers convert into a
truncation result instead of letting it abort the audit.

## Caller rules are type-tagged paths

Each rule is an ijson dotted prefix plus the JSON type that must be present:

```python
rules = [
    ("batches.item.records.item.risk_level", "string"),
    ("batches.item.records.item.amount", "number"),
    ("batches.item.records.item.flags", "array"),
    ("batches.item.records.item.flags.item", "string"),
]
```

Accepted type tags: `null`, `boolean`, `number`, `string`, `map`, `array`
(with aliases such as `str`, `int`, `bool`, `object`, `list`). Mapping and
sequence rule shapes are both accepted (see `audit_completeness.rules`).

## The two negative conclusions are kept separate

- `missing` / `type_mismatched` are emitted only after the owning container
  closes (`end_map` / `end_array`). They are definitive, negative conclusions
  about data that was actually transferred.
- `truncated` is emitted when `IncompleteJSONError` fires first. Each still-open
  container becomes one truncation record listing the rules whose presence
  cannot be decided; these never become `missing` findings.
- `completed_fields()` returns the findings that are already safe to re-check
  even though the stream was cut.


## Drivers produce identical observations

```python
import io
from audit_completeness import audit_stream, audit_bytes

result_sync = audit_stream(io.BytesIO(payload), rules, buf_size=4096)
result_push = audit_bytes(payload, rules, chunk_size=512)
```

`audit_chunks(iterable_of_bytes, rules)` is the lower-level push entry for
callers that already receive network chunks. On identical bytes the sync and
push results agree on every finding list and on the truncation flag.

## Bundled short streams

`audit_completeness.fixtures` builds:

- `build_full_stream()`: a small, well-formed stream of normal records;
- `build_truncated_stream()`: the same content cut while the final batch"s
  last record is still open, so earlier completed fields stay reviewable and
  the open tail is reported as uncollected rather than missing.

Run the walkthrough:

```
python -m audit_completeness.demo
```

Run the assertions (standard pytest where parent directories are readable):

```
pytest tests/test_audit_completeness.py
```
