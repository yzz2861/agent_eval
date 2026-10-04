---
title: Metadata Evidence
---

The [`metadata_evidence`][metadata_evidence] plugin records where each piece
of file metadata came from. For every tracked field (`filename`, `size`
and `mime_type` by default) it keeps three values:

* **declared** – the value claimed by the client (original filename,
  `Content-Type` header, or metadata submitted as cached attachment data)
* **probed** – the value the server measured from the actual IO content
  (file size, MIME type analyzed by [determine_mime_type])
* **adopted** – the value that was written into the metadata hash

```rb
plugin :metadata_evidence
```

```rb
file = uploader.upload(io)

file.evidence
# {
#   "version"   => 1,
#   "filename"  => { "declared" => "nature.jpg", "probed" => nil,          "adopted" => "nature.jpg" },
#   "size"      => { "declared" => nil,          "probed" => 1024,         "adopted" => 1024 },
#   "mime_type" => { "declared" => "image/png",  "probed" => "image/jpeg", "adopted" => "image/jpeg" },
# }

file.metadata_source("size")      #=> :probed
file.metadata_source("mime_type") #=> :probed
file.metadata_source("filename")  #=> :declared
```

The evidence hash is stored inside the `evidence` metadata key, so it's
retained when file data is serialized (e.g. in the attachment attribute or
cached attachment data). The format is versioned; attachments stored before
this plugin was loaded (or with an unsupported evidence version) simply
return `nil` from `#evidence`.

A value is only recorded as probed when the server actually measured it:
the size requires a measurable IO (an uploaded file counts only once it's
opened), and the MIME type requires the [determine_mime_type] plugin with a
content analyzer (any analyzer other than `:content_type`). The filename
can never be probed, since the server cannot verify a name.

## Validation

The `validate_metadata_source` helper requires that adopted values come
from trusted sources only. It fails closed: when no probed value was
recorded, the declared value is not accepted as a substitute, and
attachments without evidence are rejected as well.

```rb
Attacher.validate do
  validate_metadata_source :size, :mime_type, sources: [:probed]
end
```

## Refreshing metadata

Refreshing metadata (via the [refresh_metadata] plugin, which is loaded
automatically) preserves the previously recorded evidence and updates the
adopted values. Declared values are carried over when the refreshed file
doesn't carry new claims, while probed values are always re-measured —
they're never inherited from file data, which may have been submitted by
the client.

This makes tampering visible when restoring cached data with the
[restore_cached_data] plugin:

```rb
# client submits cached data with forged metadata: { "size" => 5, ... }
attacher.assign(params[:file])

attacher.file.metadata["size"]         #=> 1024 (re-measured)
attacher.file.evidence["size"]
# { "declared" => 5, "probed" => 1024, "adopted" => 1024 }
```

Note that evidence recorded during a cache upload is only as trustworthy as
the cached attachment data itself. Use [restore_cached_data] (or the
[signature] plugin) so that evidence is re-established server-side when
cached data is assigned.

## Options

The tracked fields can be configured:

```rb
plugin :metadata_evidence, fields: %i[size mime_type]
```

[metadata_evidence]: https://github.com/shrinerb/shrine/blob/master/lib/shrine/plugins/metadata_evidence.rb
[determine_mime_type]: https://shrinerb.com/docs/plugins/determine_mime_type
[refresh_metadata]: https://shrinerb.com/docs/plugins/refresh_metadata
[restore_cached_data]: https://shrinerb.com/docs/plugins/restore_cached_data
[signature]: https://shrinerb.com/docs/plugins/signature
