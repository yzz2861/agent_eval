---
title: Content Addressable
---

The [`content_addressable`][content_addressable] plugin adds an optional
content-addressable storage (CAS) layer: attachments whose bytes are identical
share a single blob, while each attachment keeps its own independent name and
metadata.

The blob key is a digest (SHA-256 by default) calculated **on the server side**
from the actual uploaded content, so it cannot be spoofed by the client. Each
attachment still stores its own `filename`, `mime_type`, `size` and custom
metadata; only the underlying bytes are shared.

## Setup

The plugin needs a *reference store*, an object that implements the minimal
atomic reference protocol (`#acquire` and `#release`). Shrine ships with a
local, on-disk implementation that coordinates reference counts with
per-key file locks (safe across threads and processes):

```rb
require "shrine/storage/file_system"
require "shrine/storage/file_system_ref_store"

Shrine.storages = {
  cache: Shrine::Storage::FileSystem.new("storage/cache"),
  store: Shrine::Storage::FileSystem.new("storage/blobs"),
}

Shrine.plugin :content_addressable,
  ref_store: Shrine::Storage::FileSystemRefStore.new("storage/refs")
```

When content-addressable storage is enabled for more than one physical storage
(typically `:cache` and `:store`), configure a separate RefStore instance per
storage so reference counts are never shared across distinct blob locations:

```rb
Shrine.plugin :content_addressable, ref_store: {
  cache: Shrine::Storage::FileSystemRefStore.new("storage/cache_refs"),
  store: Shrine::Storage::FileSystemRefStore.new("storage/store_refs"),
}
```

To restrict the plugin to specific storages, pass `:storages`:

```rb
Shrine.plugin :content_addressable,
  storages: [:store],
  ref_store: Shrine::Storage::FileSystemRefStore.new("storage/refs")
```

The digest algorithm can be changed with `:algorithm`, and a fixed key prefix
(useful for sharding or namespacing) with `:prefix`:

```rb
Shrine.plugin :content_addressable,
  algorithm: :sha512,
  prefix:    "sha512/",
  ref_store: ref_store
```

## Usage

Uploading identical content produces two attachments that point at the same
blob but retain separate metadata:

```rb
first  = Shrine.upload(file_a, :store, metadata: { "filename" => "a.jpg" })
second = Shrine.upload(file_b, :store, metadata: { "filename" => "b.jpg" })

first.id == second.id   #=> true (same content digest)
first.original_filename #=> "a.jpg"
second.original_filename#=> "b.jpg"
```

The blob is deleted only once the last referencing attachment is deleted:

```rb
first.delete             # reference count 2 -> 1, blob kept
second.exists?           #=> true
second.delete            # reference count 1 -> 0, blob deleted
```

Uploading to an explicit `:location` bypasses content addressing and performs
a regular upload, which keeps features such as `UploadedFile#replace` working.

## The Reference Store Protocol

A RefStore only coordinates reference counts; the blob bytes themselves live
in an ordinary Shrine storage. Two atomic operations are required:

```rb
created, result = ref_store.acquire(key) do |create|
  blob_storage.upload(io, key) if create
end

ref_store.release(key) do |last|
  blob_storage.delete(key) if last
end
```

* `#acquire(key)` serializes concurrent calls for the same key. Exactly one
  caller creating the first reference receives `create == true`; every other
  caller blocks until that call finishes and then receives `create == false`.
  If the block raises, the first reference is rolled back, so a failed upload
  never leaves a dangling reference and a later caller becomes the creator.
* `#release(key)` yields `last == true` only when this was the final
  reference. The block runs while the release is still serialized against
  concurrent acquisitions, so deleting the last reference and a new reference
  joining cannot interleave badly: the blob is never removed while an
  attachment still references it.

Because deletion is driven solely by the reference count, a failed upload or
a failed association can only roll back the reference it created; it can never
delete a blob that other attachments depend on.

See `Shrine::Storage::RefStore` for the full interface contract and
`Shrine::Storage::FileSystemRefStore` for the bundled implementation.

[content_addressable]: https://github.com/shrinerb/shrine/blob/master/lib/shrine/plugins/content_addressable.rb
