# Grant-scoped XML reading

`defusedxml.scoped` (also re-exported as `defusedxml.managed`) is a managed
read entry for import services that fan one XML document out to several
business processors.  Each processor declares the tree segments it may read.
The resulting view contains materialized copies of those segments only; it has
no reference to the complete tree, the SAX handler, the parser, or the source
bytes.

## Quick start

```python
from defusedxml import ManagedReader, ReadGrant

reader = ManagedReader([
    ReadGrant(
        "orders",
        allowed=["import/orders/order", "import/returns"],
        required=["import/orders/order", "import/returns"],
    ),
    ReadGrant(
        "billing",
        allowed=["import/billing/invoice", "import/credit-notes"],
    ),
])

with reader.open("import.xml") as opened:
    document = opened.parse()

orders = document.views["orders"]
billing = document.views["billing"]
```

`open_scoped(source, grants)` is the short form when only the opened source is
needed.  `read_scoped(source, grants)` opens and parses in one call.

## Authorization flow

1. `ManagedReader.open()` reads the source, hashes it, and attaches a
   `GrantView` snapshot to the `AuthorizedSource`.
2. `AuthorizedSource.parse()` feeds that same snapshot to the SAX handler.  The
   handler records start/end event indexes, lines, and columns while it copies
   only authorized elements.
3. `ScopedDocument` exposes one `ProcessorView` per grant.  Every view carries
   the same `grant_id` and source digest as the opened source.

A processor can verify continuity with:

```python
assert opened.grants["orders"].grant_id == orders.authorization.grant_id
assert opened.source.sha256 == orders.source.sha256
```

## Grant semantics

- Paths are absolute element paths relative to the document root, using the
  literal SAX qnames.  `import/orders/order` and
  `(import, orders, order)` are equivalent.
- Each occurrence of an allowed path becomes one `ScopedSegment`.
- Every authorized descendant is also indexed, so nested `required` paths get their own boundaries.
- All descendants of an allowed segment are included unless they match a
  `denied` prefix.
- Allowed paths in one grant must not overlap.
- `required` defaults to `allowed`.  A required path that is absent produces a
  missing `ScopedSegment` instead of an exception.

## Boundaries and missing hints

Every segment has a `SegmentBoundary` with:

- `path`, `present`, `reason`, and `depth`
- `start_event` / `end_event` (SAX start/end element event indexes)
- `start_line`, `start_column`, `end_line`, `end_column`

A missing segment has `present=False`, `reason="not_found"`, and `root=None`.
`view.missing_paths` and `view.requirements` summarize these hints.

## Non-leak guarantees

- Unauthorized lookups raise `AccessDenied`.  Its `args` are empty and its
  message is the constant `requested tree segment is not available`.  It does
  not inherit from `KeyError` or `LookupError`.
- The exception and the per-view audit entry contain only a truncated digest of
  the requested path, never the path text or an XML value.
- A view holds only copied authorized elements.  `repr()`, `vars()`, traceback
  formatting, and debugger-visible object references cannot reach unauthorized
  branches.
- Parser failures are converted to `ScopedReadError` with stable codes such as
  `dtd_forbidden`, `entities_forbidden`, and `malformed_xml`.  Underlying
  exception text, DTD names, entity names, and entity values are not copied
  into the error or its evidence.
- DTDs, entity declarations, and external references are rejected by the
  defused SAX parser by default.

## Evidence

`ManagedReader.audit` keeps sanitized open/parse events.  `ProcessorView.evidence`
keeps sanitized denied-lookup events for that processor.  Entries contain event
kinds, outcomes, grant ids, source digests, path digests, and event counts.

## Runnable fixture

The fixture `xmltestdata/scoped-import.xml` contains only placeholder values.
Run:

```bash
python demo_scoped_import.py
python test_scoped.py
```

The demo prints the values seen by the two stand-in processors, the segment
boundaries, the missing-item hints, the denied-lookup evidence, and the evidence
from a rejected DTD.  It asserts that neither processor saw the other branch or
the audit branch.
