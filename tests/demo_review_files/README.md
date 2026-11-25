# Artifact usage review sample

`reviewed/base.toml` is the reviewed configuration. The build copies it to
`dist/release/base.toml` and `dist/test/base.toml`. Those two downstream files
have identical content, but only the release path is connected to the reviewed
origin by a MATCH rule.

The review therefore follows the recorded material/product path instead of
just comparing hashes:

- `dist/release/base.toml` is in scope and its `release` use is approved.
- `dist/test/base.toml` shares the same content, but its `test` use is kept as
  out-of-scope evidence because approval did not travel through that path.
- If the link for a downstream step is missing, the conclusion for its use is
  unknown rather than out of scope.

`usage.json` is an example purposes/uses declaration. The sample can be
reviewed directly:

```shell
in-toto-review --layout root.layout --link-dir . \
    --usage-declarations usage.json --json
```

It exits `1` and reports the identical `dist/test/base.toml` copy as
out-of-scope evidence.
