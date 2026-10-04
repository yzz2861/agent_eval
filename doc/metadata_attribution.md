---
title: Metadata Attribution
---

The `metadata_attribution` plugin records where the values of `filename`,
`size` and `mime_type` came from. For every field it keeps three pieces of
information:

* the value **declared** by the client (upload form, `Content-Type` header,
  metadata passed to the attacher),
* the value **measured** by the server (from the IO object or file content),
* the value that was actually **adopted** as the metadata value.

```rb
Shrine.plugin :metadata_attribution

uploaded_file = uploader.upload(file)
uploaded_file.metadata_source("size")       #=> :measured
uploaded_file.measured_metadata("size")     #=> 345993
uploaded_file.declared_metadata("size")     #=> nil
uploaded_file.metadata_attribution("size")
#=> {
#     "declared" => nil,
#     "measured" => 345993,
#     "adopted" => 345993,
#     "source"   => "measured",
#     "observations" => [{ "source" => "measured", "value" => 345993 }],
#   }
```

## Sources

| Source     | Meaning                                                        |
| :--------- | :------                                                        |
| `:measured` | extracted by the server from the IO object or file content    |
| `:declared` | provided by the client (filename, Content-Type, cached data)  |

`size` is always measured. `filename` is declared when it comes from
`#original_filename` and measured when derived from a server-side path.
`mime_type` is declared by default; load the [`determine_mime_type`][determine_mime_type]
plugin to record a content-derived, measured MIME type (the built-in
`:content_type` analyzer remains declared because it reads the client header).

When both values exist the measured value wins and is adopted; the declared
value is preserved in the evidence and never overwrites it.

## Trusted sources

Configure which sources may be used during validation:

```rb
Shrine::Attacher.metadata_trusted_sources :measured

Shrine::Attacher.validate do
  validate_metadata_source(:size, :mime_type)
end
```

Per-field policies are supported:

```rb
Shrine::Attacher.metadata_trusted_sources :declared, size: :measured
```

If a field has no measured value, a declared value is **not** silently used in
its place: the adopted source stays `:declared` and the validation fails.

## Cached data

Attachment data submitted from a cache is client controlled. Any
`"measured"` evidence inside cached data is therefore downgraded to
`"declared"` when it enters the attacher, so an attacker cannot forge
measured metadata:

```rb
attacher.attach_cached(forged_cached_data)
attacher.file.metadata_source("size")   #=> :declared
attacher.file.measured_metadata("size") #=> nil
```

Combine this with the [`restore_cached_data`][restore_cached_data] plugin to
re-measure the file from storage; the fresh server-side observation is trusted
and adopted.

## Refreshing metadata

The [`refresh_metadata`][refresh_metadata] plugin keeps prior observations and
appends new ones. The adopted value is updated, while the full history remains
available for inspection.

## Serialization

Evidence is stored inside the attachment metadata under
`"metadata_evidence"` and carries a `"version"` number. Attachments saved
before this plugin was loaded contain no evidence and are still readable;
their metadata sources simply return `nil`.

[determine_mime_type]: /doc/plugins/determine_mime_type.md
[restore_cached_data]: /doc/plugins/restore_cached_data.md
[refresh_metadata]: /doc/plugins/refresh_metadata.md
