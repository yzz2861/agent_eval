---
title: Virus Scanning
---

The [`virus_scanning`][virus_scanning] plugin sends every newly assigned file
to a quarantine storage and keeps it there until an external scanner confirms
the file is safe. While a file is in quarantine:

* it has scan status `pending`, `rejected` or `failed`,
* no public download URL is generated for it,
* it is not promoted to permanent storage on record save.

Only files with a `passed` scan result are published.

## Quick start

The scanner is integrated through an ordinary Ruby callable that receives the
`Shrine::UploadedFile` and returns the scan result. No scanner software needs
to be installed to use or test the plugin.

```rb
# Gemfile
gem "shrine"
```

```rb
require "shrine"

class ImageUploader < Shrine
  plugin :virus_scanning,
    scanner: -> (file) { MyAntivirus.scan(file.download).clean? }
end
```

The scanner result is interpreted as follows:

| Return value             | Meaning                              |
| ------------------------ | ------------------------------------ |
| `true` or `:clean`       | the file passed the scan             |
| `false` or `:infected`   | the file was rejected                |
| raised exception         | the scan failed (can be retried)     |

Any object responding to `#call` works, so a scanner client class can be
passed directly:

```rb
class MyScanner
  def call(uploaded_file)
    # returns true/false or raises
  end
end

Shrine.plugin :virus_scanning, scanner: MyScanner.new
```

## Scan statuses

The status is stored in the file metadata and is available on the attacher:

```rb
attacher = Shrine::Attacher.new
attacher.attach_cached(file)

attacher.scan_pending?   #=> true
attacher.scan_status     #=> :pending
attacher.url             #=> nil (no public URL while quarantined)

attacher.scan_passed?    #=> false
attacher.scan_rejected?  #=> false
attacher.scan_failed?    #=> false
attacher.quarantined?    #=> true
```

| Status     | Behavior                                                            |
| ---------- | ------------------------------------------------------------------ |
| `pending`  | waiting for the scanner; file stays in quarantine, no URL           |
| `passed`   | promoted to permanent storage, URL available                        |
| `rejected` | quarantine object deleted, rejected status retained, no URL         |
| `failed`   | quarantine object kept so the scan can be retried, no URL           |

## Asynchronous scanning

For asynchronous scanning register a `scan_block`, which is responsible for
enqueuing the scan (typically via a backgrounding library). While the block
is registered it is used instead of calling the scanner directly, and the
file stays in a `pending` state until the job reports the result.

```rb
class DocumentUploader < Shrine
  plugin :virus_scanning

  Attacher.scan_block do |attacher|
    VirusScanJob.perform_async(
      attacher.record.class.name,
      attacher.record.id,
      attacher.name,
      attacher.scan_generation, # attachment generation the task belongs to
    )
  end
end
```

The background job opens the current attacher, runs the external scanner and
reports the result using `#accept_scan!`, `#reject_scan!` or `#fail_scan!`,
always passing the generation captured when the task was created:

```rb
class VirusScanJob
  include Sidekiq::Worker

  def perform(record_class, record_id, name, generation)
    record   = record_class.constantize.find(record_id)
    attacher = record.public_send(:"#{name}_attacher")

    begin
      if MyAntivirus.clean?(attacher.file.download)
        attacher.accept_scan!(generation)
      else
        attacher.reject_scan!(generation)
      end
    rescue => error
      attacher.fail_scan!(generation, error.message)
    end

    record.save
  end
end
```

`#rescan!` retries a failed scan (using the same generation) when a scanner
and/or scan block is configured on the attacher:

```rb
attacher.rescan! if attacher.scan_failed?
```

## Attachment generation and stale callbacks

Every scan task is bound to both the file's identity (`id` and storage) and
an attachment generation stored in the file metadata:

```rb
attacher.attach_cached(first_file)
attacher.scan_generation #=> 1

attacher.attach_cached(second_file)
attacher.scan_generation #=> 2

# old job reports late; it cannot modify the current attachment
attacher.accept_scan!(1)   # no-op
attacher.scan_status      #=> :pending

# only the callback for the current generation is applied
attacher.accept_scan!(2)
```

This guarantees that when a user has already replaced an attachment, an old
scanner callback cannot promote, reject or otherwise modify the current file.

Repeated callbacks for the same generation are idempotent: once a task has a
terminal result (`passed`, `rejected` or `failed`), further callbacks are
ignored, and a late conflicting result cannot overwrite it.

## Cleanup ownership

Promotion on acceptance and deletion on rejection only remove the object
owned by the current scan task (the object in quarantine storage carrying the
current attachment generation). Objects belonging to other tasks, such as a
previously replaced file whose scan callback is still in flight, are left
untouched.

## Configuration

| Name          | Description                                                       | Default   |
| ------------- | ----------------------------------------------------------------- | --------- |
| `:scanner`    | Callable receiving the `UploadedFile`, returning the scan result. | `nil`     |
| `:scan_block` | Callable invoked when a file enters quarantine (enqueue a job).   | `nil`     |
| `:quarantine` | Storage key used as quarantine.                                   | `:cache`  |

The scanner and scan block can be configured globally via the plugin options
or `Attacher.scan_block`, or per attacher via `#virus_scanner` and
`#scan_block`.

[virus_scanning]: https://github.com/shrinerb/shrine/blob/master/lib/shrine/plugins/virus_scanning.rb
