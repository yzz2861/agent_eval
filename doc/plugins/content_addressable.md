---
title: Content Addressable
---

The [`content_addressable`][content_addressable] plugin generates locations
from the hash of the file content, so that files with identical content are
stored under the same location:

```rb
plugin :content_addressable
```

```rb
"ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73.jpg"
# :digest.:extension
```

The hash is calculated on the server from the actual file content, so it
cannot be spoofed by the client. The hashing algorithm defaults to SHA256,
but can be changed via the `:digest` option, and a `:prefix` can be added:

```rb
plugin :content_addressable, digest: :sha512, prefix: "blobs"
```

Since identical files receive the same location, attachments with the same
content can share a single stored file, while still keeping their own
metadata (filename, MIME type, etc) on the record. To actually deduplicate
the stored files, use the `Shrine::Storage::ContentAddressable` storage
wrapper, which uploads the file only when the first attachment references
it, and deletes it only when the last referencing attachment is deleted:

```rb
require "shrine/storage/content_addressable"
require "shrine/storage/file_system"

refs = Shrine::Storage::ContentAddressable::MemoryRefs.new

Shrine.storages[:store] = Shrine::Storage::ContentAddressable.new(
  Shrine::Storage::FileSystem.new("public", prefix: "uploads"),
  refs: refs,
)
```

The reference counting is coordinated through a reference store object
(`MemoryRefs` above is an in-memory implementation suitable for a single
process), which atomically tracks how many attachments reference each file,
ensuring concurrent uploads and deletions of the same content don't
interfere with each other. See the [storage
documentation][storage-content-addressable] for more details.

[content_addressable]: https://github.com/shrinerb/shrine/blob/master/lib/shrine/plugins/content_addressable.rb
[storage-content-addressable]: https://github.com/shrinerb/shrine/blob/master/lib/shrine/storage/content_addressable.rb
