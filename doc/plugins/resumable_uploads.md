---
title: Resumable Uploads
---

The [`resumable_uploads`][resumable_uploads] plugin adds support for
resumable, chunked uploads to local storage. Clients can create an upload
session, send chunks in any order, retry failed ranges, and finalize the
upload once every byte has been received. Session state is isolated behind a
small store interface, with an in-memory implementation suitable for tests
and a filesystem implementation for single-machine setups.

```rb
plugin :resumable_uploads
```

## Service

`Shrine.resumable_upload` returns a service object bound to one of the
registered storages:

```rb
service = Shrine.resumable_upload(:cache)

session = service.create_session(total_size: 1024, filename: "video.mp4")
session.id #=> "9f86d081884c7d65..."
```

Chunks are submitted as binary strings with an absolute start offset. They
can be sent out of order:

```rb
service.put_chunk(session.id, "...", start_offset: 512)
service.put_chunk(session.id, "...", start_offset: 0)

service.get_session(session.id).merged_ranges #=> [[0, 1024]]
```

Once all bytes are present, the session can be finalized. Finalization
verifies the declared length and content checksum, then publishes the
assembled bytes to the Shrine storage and returns an `UploadedFile`:

```rb
uploaded_file = service.finalize(session.id)
uploaded_file         #=> #<Shrine::UploadedFile ...>
uploaded_file.read    #=> full file content
```

## Idempotent ranges and conflicts

Submitting the same byte range with the same content is a no-op and always
succeeds, so clients can freely retry requests. Two situations are rejected
with `Shrine::ResumableUpload::Conflict`:

* a range that was already confirmed is submitted again with different
  content, and
* a range partially overlaps a confirmed range (mixes received and new
  bytes).

Ranges outside the declared length raise
`Shrine::ResumableUpload::RangeInvalid` (HTTP `416`).

## Checksums

An expected digest can be declared at session creation using the
`"algorithm=hex-digest"` format (`sha1`, `sha256`, `sha384`, `sha512` and
`md5` are supported):

```rb
session = service.create_session(
  total_size: content.bytesize,
  checksum:   "sha256=#{Digest::SHA256.hexdigest(content)}",
)
```

The checksum is checked at finalization time, before anything is published.
A mismatch raises `Shrine::ResumableUpload::ChecksumMismatch` (HTTP `460`).

## Finalization semantics

`#finalize` can only succeed once. Calling it again for the same session
returns the same `UploadedFile` without publishing a second object, so two
concurrent finalize requests cannot create duplicates. Unfinished sessions
cannot be used as uploaded files: finalizing a session with missing bytes
raises `Shrine::ResumableUpload::Incomplete` (HTTP `409`).

An unfinished session can be aborted, discarding its partial content:

```rb
service.abort(session.id)
```

## Expiry and cleanup

Sessions carry an `expires_at` timestamp (24 hours by default). Expired
sessions can be removed with `#cleanup`; only session metadata and partial
assemblies are deleted. Files already published to the Shrine storage are
never affected.

The lifetime can be configured globally or per session:

```rb
plugin :resumable_uploads, expires_in: 60 * 60 # one hour

service.create_session(total_size: 1024, expires_in: 300) # five minutes
```

## Session stores

State persistence is defined by `Shrine::ResumableUpload::SessionStore`.
Implementations need to provide `#create`, `#find`, `#update`,
`#write_chunk`, `#read_chunk`, `#open`, `#delete`, `#delete_content` and
`#each_session`. This makes it straightforward to back sessions with Redis,
SQL or any other store.

The default store is an in-memory store, which keeps all state in the
process and is best suited for tests. For single-machine setups a
filesystem store persists session metadata as JSON and partial bytes in
`*.part` files (with file locking for concurrent and cross-process
requests):

```rb
store = Shrine::ResumableUpload::FileSystemSessionStore.new("tmp/uploads/sessions")
Shrine.resumable_upload(:cache, session_store: store)
```

## Customizing publication

The location, metadata and upload steps can be overridden:

```rb
plugin :resumable_uploads,
  location: -> (session) { "resumable/#{session.id}" },
  metadata: -> (session) { { "filename" => session.filename } }
```

## Rack endpoint

`Shrine.resumable_upload_endpoint` exposes the same flow over HTTP. The
protocol is JSON based and also accepts tus-style headers:

| Request                  | Action                                           |
| :----------------------- | :----------------------------------------------- |
| `POST /`                 | create a session (`total_size`, optional checksum) |
| `PATCH /:id`             | append a chunk (`Content-Range: bytes a-b/total` or `Upload-Offset`) |
| `GET /:id` / `HEAD /:id` | read confirmed ranges (`Upload-Received-Ranges`) |
| `POST /:id/finalize`     | verify length/checksum and publish the file      |
| `DELETE /:id`            | abort an unfinished session                       |

```rb
# config/routes.rb (Rails)
Rails.application.routes.draw do
  mount ImageUploader.resumable_upload_endpoint(:cache) => "/images/resumable"
end
```

The finalize response is the JSON representation of the uploaded file, so
it can be passed directly to `Shrine.uploaded_file`.

[resumable_uploads]: https://github.com/shrinerb/shrine/blob/master/lib/shrine/plugins/resumable_uploads.rb
