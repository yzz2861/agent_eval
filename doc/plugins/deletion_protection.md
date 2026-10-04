---
title: Deletion Protection
---

The [`deletion_protection`][deletion_protection] plugin separates two facts
that otherwise happen together:

* the application no longer references an uploaded file,
* the file is allowed to be physically deleted from storage.

When an attachment is destroyed or replaced, the old file is marked as
*pending deletion* instead of being removed immediately. Physical deletion is
allowed only once **all three** conditions hold:

1. the file is marked as pending deletion,
2. every explicit hold on it has been released (or has expired),
3. its retention period has expired.

Releasing a hold never bypasses the remaining retention period. The same rules
apply when an attachment is replaced and its old file is cleaned up. No
background service is required: pending files are deleted on demand by calling
`cleanup_pending_deletions`, e.g. from a scheduled rake task or an admin
action.

## Setup

```rb
plugin :deletion_protection
```

## Retention period

A global retention period can be configured as a number of seconds. When an
attachment is destroyed or replaced, the old file is kept until the period
elapses.

```rb
plugin :deletion_protection, retention: 7 * 24 * 60 * 60 # 7 days
```

The retention can also be a callable, which receives the uploaded file and
the attacher context:

```rb
plugin :deletion_protection, retention: ->(file, context) {
  file.mime_type.start_with?("image/") ? 30 * 24 * 60 * 60 : 7 * 24 * 60 * 60
}
```

## Explicit holds

Administrators or compliance flows can freeze deletion independently of the
retention period. Holds are referenced by name, so multiple holds can coexist:

```rb
Shrine::Attacher.hold_deletion(file, :legal_hold)
Shrine::Attacher.hold_deletion(file, :audit)

Shrine::Attacher.deletion_blockers(file) #=> [:hold]

Shrine::Attacher.release_deletion_hold(file, :legal_hold)
# the audit hold (and any retention) still protects the file
```

A hold can be given an automatic expiry time:

```rb
Shrine::Attacher.hold_deletion(file, :freeze, until: 1.week.from_now)
```

## Undoing pending deletion

If a file was marked pending by mistake, the pending state can be reverted
(for instance from an admin "restore" action). Existing holds are preserved:

```rb
Shrine::Attacher.undo_pending_deletion(file)
Shrine::Attacher.pending_deletion?(file) #=> false
```

## Inspecting why deletion is blocked

`deletion_blockers` returns the reasons a file cannot currently be deleted:

* `:not_pending` – the application has not released the file yet,
* `:hold` – at least one explicit hold is active,
* `:retention` – the retention period has not expired yet.

```rb
attacher.destroy
Shrine::Attacher.deletion_blockers(file) #=> [:retention]
Shrine::Attacher.deletable?(file)       #=> false
```

## Sweeping pending files

Physical deletion happens through an explicit sweep, so no resident
background process is needed:

```rb
# e.g. a daily cron job or rake task
Shrine::Attacher.cleanup_pending_deletions #=> [#<Shrine::UploadedFile ...>]
```

Only pending files without active holds and past their retention deadline are
deleted; their protection records are removed afterwards.

## Controlling time

A clock can be injected, which makes boundary conditions deterministic in
tests:

```rb
time = Time.now
Shrine.plugin :deletion_protection,
  retention: 60,
  clock: -> { time }

attacher.attach(io)
attacher.destroy

Shrine::Attacher.deletion_blockers(attacher.file) #=> [:retention]
time += 60
Shrine::Attacher.deletion_blockers(attacher.file) #=> []
```

## Persistence

Protection state is stored per `[storage, id]` pair in a thread-safe
in-memory store by default. In multi-process deployments, supply a custom
store object responding to `fetch(key)`, `update(key)`, `delete(key)` and
`each_pending`:

```rb
Shrine.plugin :deletion_protection, store: MyProtectionStore.new
```

[deletion_protection]: https://github.com/shrinerb/shrine/blob/master/lib/shrine/plugins/deletion_protection.rb
