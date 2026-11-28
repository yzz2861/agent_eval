# Generated-source provenance

Generated files often contain the same placeholder value many times.  Reporting
every physical occurrence makes review noisy, but suppressing by secret hash is
unsafe: a hand-written file may contain the same value.  The provenance layer
therefore groups only hits whose generated file has a verifiable source, and
leaves everything else alone.

## Declaration

The caller supplies a generation source declaration and the configuration
version used by the scan:

```json
{
  "config_version": "generator-config-2026-11-28",
  "edges": [
    {
      "generated": "generated/api_client.py",
      "source": "templates/api_client.j2",
      "rule": "api-client"
    }
  ]
}
```

The following equivalent edge/record forms are accepted:

```json
{"generated/api_client.py": ["templates/api_client.j2"]}
```

```json
{"edge": {"from": "generated/api_client.py", "to": "templates/api_client.j2"}}
```

``source``/``sources`` may contain multiple values.  A generated file with more
than one distinct source is ambiguous and produces a rescan request rather than
an arbitrary attribution.

## Feedback

`build_feedback(hits, generation_sources, config_version=...)` returns:

- `upstream_remediation`: one entry per verified upstream source.  Each entry
  contains every original `locations` entry (`filename`, `line_number`,
  `secret_hash`) and the same complete hit list.
- `pending_verification`: generated hits which cannot be attributed, including
  one-to-many sources, removed generation rules, configuration mismatches, and
  insufficient evidence.  `newly_pending` is the subset that was not pending in
  the previous feedback.
- `rescan`: the generated file, reason, candidate sources, and affected
  locations that must be rescanned.
- `manual`: hits from files without a generation declaration.  These are never
  absorbed into a generated group, even when their hash matches one there.

The scanner and pre-commit hook continue to see all hits; this layer only
changes reviewer feedback.

## CLI

```console
detect-secrets feedback .secrets.baseline \
  --generation-sources generation-sources.json \
  --config-version generator-config-2026-11-28 \
  --previous-feedback previous-feedback.json
```

The same options are available on `scan` (with `--feedback`) and `audit`.
