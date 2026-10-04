---
title: Quarantine
---

The [`quarantine`][quarantine] plugin makes every new upload land in a
dedicated **quarantine** storage. The file is held there, without any public
download URL, until an external scanner confirms it is clean. Only then is it
promoted into permanent storage and published.

The scanner is integrated through an ordinary callable, so no scanning
software needs to be installed in your application or test environment.

## Setup

Register a quarantine storage and load the plugin:

```rb
Shrine.storages = {
  cache:       Shrine::Storage::FileSystem.new("storage/cache"),
  quarantine:  Shrine::Storage::FileSystem.new("storage/quarantine"), # not publicly served
  store:       Shrine::Storage::FileSystem.new("storage/store"),
}

Shrine.plugin :quarantine, storage: :quarantine
```

## Scanner

Register a scanner callable. It receives the quarantined
`Shrine::UploadedFile` and the attacher context, and returns a verdict:

* `:clean` / `"clean"` – safe to publish
* `:infected` / `"infected"` – rejected
* `:failed` / `"failed"` – the scan could not be completed
* `:pending` – the scan was enqueued and a callback will arrive later

Any exception raised by the callable is recorded as a `failed` scan.

### Synchronous scanning

```rb
Shrine::Attacher.scanner do |file, context|
  MyScanner.clean?(file.download) ? :clean : :infected
end
```

When a cached attachment is finalized, the scanner runs immediately. A clean
file is promoted to permanent storage and its quarantined copy is removed; an
infected or failed file stays in quarantine.

### Asynchronous scanning

Enqueue the scan and return `:pending`. The serialized scan payload is
available in `context[:scan_data]`; pass it back unchanged when the external
scanner reports its verdict:

```rb
Shrine::Attacher.scanner do |file, context|
  ScannerJob.perform_async(context[:scan_data])
  :pending
end
```

```rb
class ScannerJob
  include Sidekiq::Worker

  def perform(scan_data)
    record   = User.find(scan_data.dig("metadata", "record_id"))
    attacher = Shrine::Attacher.find_scan(model: record, name: :file, file: scan_data)
    verdict  = ExternalScanner.result_for(scan_data["id"]) # :clean | :infected | :failed
    attacher.resolve_scan(verdict, scan_data)
  rescue Shrine::AttachmentChanged
    # The attachment was replaced; this callback is stale.
  end
end
```

`Attacher.find_scan` retrieves the current attacher and raises
`Shrine::AttachmentChanged` when the referenced file is no longer the
attached one, so an outdated callback can never mutate the current attachment.

You can also drive the outcomes directly:

```rb
attacher.scan_pass(scan_data)   # => :clean - promote and delete the quarantine copy
attacher.scan_reject(scan_data) # => :infected
attacher.scan_fail(scan_data)   # => :failed
```

## States

The state is stored in the file metadata (`scan_status`) together with a
unique `scan_id` and an attachment `scan_generation`:

* `pending` – waiting in quarantine (no public URL)
* `clean` – promoted to permanent storage
* `infected` – rejected, remains in quarantine (no public URL)
* `failed` – scan errored, remains in quarantine and can be retried

```rb
attacher.scan_status    #=> "pending" | "clean" | "infected" | "failed"
attacher.scan_pending?
attacher.scan_clean?
attacher.scan_infected?
attacher.scan_failed?
attacher.scan_id         # unique scan identity
attacher.scan_generation # incremented on every replacement

attacher.retry_scan if attacher.scan_failed?
```

A quarantined file never returns a public URL:

```rb
attacher.url           #=> nil while pending/infected/failed
attacher.file.url      # raises Shrine::FileInQuarantine
```

Trying to promote a file that has not been confirmed clean raises
`Shrine::FileInQuarantine`.

## Idempotency and stale callbacks

Scan callbacks are idempotent. Delivering the same verdict twice never changes
state twice and never double-promotes or double-deletes.

When the user replaces the attachment before an old scan completes, the old
callback is detected as stale (`scan_generation`/`scan_id` no longer match
the current file) and returns `:stale` without touching the current
attachment.

`Attacher#clean_scan(scan_data)` deletes only the quarantined object owned by
that particular scan. It refuses to delete the currently attached file and
anything in permanent storage.

## Persistence

When a persistence plugin such as `:activerecord` is loaded, scan state
changes are persisted automatically. For custom persistence, register a block:

```rb
Shrine::Attacher.scan_persist_block do |attacher|
  attacher.record.save!(validate: false)
end
```

[quarantine]: https://github.com/shrinerb/shrine/blob/master/lib/shrine/plugins/quarantine.rb

