# in-toto-contract-check

```{eval-rst}
.. argparse::
  :ref: in_toto.in_toto_contract_check.create_parser
  :prog: in-toto-contract-check
  :noepilog: true
```

## Offline path contract checks

`in-toto-contract-check` evaluates a JSON contract without reading build
artifacts or walking the filesystem. It simulates the path mapping exported by
each platform profile and runs the resulting material or product names through
in-toto's real artifact rule verifier.

The report answers four acceptance questions:

- Did each platform reach the same pass/fail decision and consume the same
  canonical artifacts?
- Were rules evaluated against the original recorded path or an explicitly
  normalized path?
- Which candidates exist when a mapping is ambiguous?
- Which rule's applicable set expanded between the `before` and `after`
  policies?

The example in `examples/contract-check/windows-linux-contract.json` covers
case-only differences, NFC/NFD-equivalent filenames, working-directory versus
absolute path roots, and a case-fold mapping collision.

## Contract shape

- `platforms[]` describes each exporter: `name`, `path_style` (`posix` or
  `windows`), `export` (`relative`, `rooted`, or `dot-relative`), `root`,
  optional `case_sensitive`, optional `unicode_normalization`, and a `mapping`
  of canonical artifact names to one or more exported path spellings.
- `cases[]` describes each set of ordinary filenames: `steps` (each with
  `materials` and `products`), the `target` step/type whose rules are checked,
  and `policies`.
- Each policy has `rules`, `match_names` (`original` or `normalized`), and a
  `normalization` object with `unicode`, `case`, `separator`, and
  `strip_prefixes`. Normalization applies to both recorded names and rule
  patterns.
- Artifact entries accept `sha256`, a `hashes` object, or `content` (hashed for
  convenience) and default to a deterministic hash of the artifact name.

Rules use the usual in-toto formats, for example `ALLOW src/*.py`,
`MATCH *.py IN lib WITH PRODUCTS IN lib FROM build`, or `DISALLOW *`.

```console
in-toto-contract-check examples/contract-check/windows-linux-contract.json \
    --report-only \
    -o acceptance-report.md
```

The command exits `1` if the selected policy is `DIVERGENT` or `AMBIGUOUS`.
Use `--report-only` when generating an acceptance artifact that should not fail
the surrounding job.
