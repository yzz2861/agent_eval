---
title: Upload Session
---

The [`upload_session`][upload_session] plugin adds support for resumable,
chunked uploads to local storage. Clients can upload chunks out of order,
retry interrupted requests, and finalize the upload once every byte has been
confirmed.

```rb
require "shrine/storage/file_system"

Shrine.storages[:cache] = Shrine::Storage::FileSystem.new("uploads/cache")
Shrine.plugin :upload_session
```

## Protocol

The plugin adds a Rack application returned by `Shrine.upload_session_endpoint`:

```rb
# config/routes.rb (Rails)
Rails.application.routes.draw do
  mount ImageUploader.upload_session_endpoint(:cache) => "/uploads/session"
end
```

### Creating a session

`POST /` starts a new session. The client declares the total file size, and
may declare the checksum algorithm (`md5`, `sha1`, `sha256`, `sha384`, or
`sha512`) that will be verified on finalization:

```rb
# POST /uploads/session
{ "size": 11, "filename": "hello.txt", "checksum_algorithm": "sha256" }
```

```json
{
  "id": "us-045e8e2f...",
  "total_size": 11,
  "ranges": [],
  "received": 0,
  "finalized": false,
  "expires_at": "2026-10-05T20:55:49+08:00"
}
```

### Uploading chunks

`PUT /:session_id` uploads a raw chunk at the byte offset given in the
`Upload-Offset` header (a `Content-Range: bytes START-END/TOTAL` header is also
accepted). Chunks may be sent out of order and in arbitrary sizes. The
response always contains the currently confirmed ranges.

Re-submitting the same range with the same content is a safe idempotent retry
(`200`). Different content for a confirmed range, or a range that partially
overlaps confirmed ranges, is rejected with `409 Conflict`; the client should
abort the session and start over in that case. A chunk extending past the
declared size is rejected with `416`.

### Status and abort

`GET /:session_id` returns the session status shown above. `DELETE
/:session_id` aborts the session and removes its staged chunks (`204`).

### Finalizing

`POST /:session_id/finalize` verifies that the complete declared length was
received and, when a checksum was declared, verifies the complete content
digest. On success it publishes the file to its final storage location and
returns the standard uploaded file JSON:

```json
{
  "id": "43kewit94.txt",
  "storage": "cache",
  "metadata": { "size": 11, "filename": "hello.txt" }
}
```

Finalizing twice returns the same result; only the first call publishes a
file. Finalizing an incomplete session or with a mismatched checksum returns
`409 Conflict` and leaves the session open for more chunks.

Only finalized sessions can be used as `Shrine::UploadedFile` objects.

## Ruby API

Sessions can also be driven directly from Ruby:

```rb
uploader = Shrine.new(:cache)

session = uploader.create_upload_session(total_size: 11)
uploader.put_upload_chunk(session.id, StringIO.new("world"), offset: 6)
uploader.put_upload_chunk(session.id, StringIO.new("hello "), offset: 0)

uploaded_file = uploader.finalize_upload_session(session.id)
uploaded_file.read #=> "hello world"
```

The storage exposes the same methods (`#create_upload_session`,
`#put_upload_chunk`, `#get_upload_session`, `#finalize_upload_session`,
`#abort_upload_session`, `#prune_upload_sessions!`) for non-Rack use.

## State storage

Session state is isolated behind the small `Shrine::UploadSessions::Store`
interface (`#create`, `#fetch`, `#read`, `#delete`, `#prune_expired!`), so it
can be backed by Redis, a database, or any other key-value store. The default
`Shrine::UploadSessions::Memory` keeps state in process memory and is suitable
for local testing and single-process setups.

```rb
Shrine::Storage::FileSystem.new(
  "uploads/cache",
  upload_session_store: MyRedisSessionStore.new,
  upload_session_ttl:   24 * 60 * 60,
)
```

Unfinished sessions and their staged chunks are cleaned up once they expire via
`#prune_upload_sessions!`. Already published files are never touched by
cleanup.

[upload_session]: https://github.com/shrinerb/shrine/blob/master/lib/shrine/plugins/upload_session.rb
[Uppy]: https://uppy.io
