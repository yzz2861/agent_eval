# Optional Content and Layers

pypdf can inspect optional content groups (OCGs), alternate configurations, and
``/OC`` marked-content sequences without flattening the document. This is useful
for forensic review: hidden evidence must remain discoverable even when it is
absent from the default visible list.

## Inventory and configurations

:attr:`PdfReader.optional_content_groups<pypdf.PdfReader.optional_content_groups>`
returns every OCG, including groups that are hidden by default. Each
:class:`OptionalContentGroup<pypdf.OptionalContentGroup>` keeps the original
dictionary and indirect reference:

```python
from pypdf import PdfReader

reader = PdfReader("handover.pdf")
for group in reader.optional_content_groups:
    print(group.name, group.reference)
```

`reader.optional_content_configurations` returns the default configuration
(`/D`) followed by each entry in `/Configs`.

## Conditional visibility

A target may be an OCG name, an OCG object or reference, or a marked-content
property name. Results contain one entry per configuration:

```python
report = reader.get_optional_content_visibility("Review Stamp")
for result in report:
    print(result.configuration.name, result.state)

report = reader.get_optional_content_visibility("/Stamp", page=0)
```

Visibility is three-state: `visible`, `hidden`, or `unknown`. Unresolved
groups, unsupported view expressions (`/VE`), unknown visibility policies, and
malformed configuration entries are reported as `unknown`; they are never
coerced to visible or hidden.

The `evidence` entries on each result retain the original OCG, `/Properties`
entry, resource dictionary, and content stream references. Nested Form XObjects
are scanned with their own `/Resources` when present, otherwise with the
resource scope of their caller. This prevents same-named properties in a page
and a form from being confused.

`reader.get_optional_content_state(...)` returns a single state, and
`reader.is_optional_content_visible(...)` returns `True`, `False`, or `None`.
