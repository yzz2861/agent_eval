# Matcher impact assessment example

All commands run from the repository root and use the same offline prefixes in
`samples.json`: a JPEG fixture, a PNG fixture, and a custom `FOO` prefix.

## Shadowing registry (new matcher registered first)

```console
python -m filetype.impact \
  --samples examples/impact/samples.json \
  --before-routes examples/impact/before_routes.json \
  --after-matchers examples/impact/after_shadow.json \
  --after-routes examples/impact/after_routes.json \
  --format text
```

Expected findings:

- `new.foo` is a `new_format` routed to `new-medium` with capability 6.
- `sample.jpg` is a `downgrade`: `image-strong` capability 10 becomes
  `legacy-weak` capability 2.

## Appended registry (one registration order changed)

Replace `after_shadow.json` with `after_append.json`. The new format is still
recognised, but the legacy JPEG stays on `image-strong`. The downgrade
disappears from changed isolation decisions.

## Faulty third-party matcher

Use `after_broken.json`. The report keeps the same two routing configs,
lists every affected sample under `errors.affected_samples`, and points to the
matcher name, registry side, and rank that raised.

```console
python -m filetype.impact \
  --samples examples/impact/samples.json \
  --before-routes examples/impact/before_routes.json \
  --after-matchers examples/impact/after_broken.json \
  --after-routes examples/impact/after_routes.json \
  --format markdown
```

Generated reports are checked in as `report_shadow.md`, `report_append.md`, and
`report_broken.md`.
