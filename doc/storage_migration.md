---
id: storage-migration
title: Migrating Attachments Between Storages
---

The storage migration helper moves a batch of Shrine attachments in safe,
restartable steps:

1. Copy source objects to fixed target locations.
2. Verify target metadata and SHA256 content checksum.
3. Switch the attachment reference only when the current source reference is
   unchanged.
4. Leave source deletion for a separate, explicit cleanup stage.

The migration plan is immutable. A separate result journal records the result
of every item after each step, so an interrupted run can resume without
re-uploading objects that have already been copied and verified.

## Plan

Build a plan from attachers. Each item records the source identity, target
location, SHA256 checksum, and metadata that must match after the copy.

```rb
require "shrine/storage_migration"

plan = Shrine::StorageMigration::Plan.build(
  Photo.find_each.map do |photo|
    attacher = photo.image_attacher
    next unless attacher.stored?

    {
      id:             photo.id,
      attacher:       attacher,
      target_storage: :new_store,
      target_id:      attacher.file.id,
    }
  end.compact
)

plan.save("storage-migration/plan.json")
```

The target id defaults to the source id, but can be set explicitly when the
target storage uses a different key.

## Execute

The executor needs a way to fetch the current attacher and a conditional
persistence strategy. With Active Record or Sequel, the persistence plugin
provides `#atomic_persist`, so the built-in strategy can be used.

```rb
Shrine.plugin :activerecord # or :sequel

plan = Shrine::StorageMigration::Plan.load("storage-migration/plan.json")
log  = Shrine::StorageMigration::ResultLog.load("storage-migration/results.json")

migrator = Shrine::StorageMigration.new(
  find_attacher: ->(item) do
    photo = Photo.find(item.id)
    photo.image_attacher
  end
)

results = migrator.run(plan, log)
```

For persistence layers that do not provide `#atomic_persist`, provide `reload`
and `persist` callbacks. The executor re-reads the attachment inside the
reload callback, compares it with the source identity saved in the plan, and
only then calls the persist callback.

```rb
Shrine::StorageMigration.new(
  find_attacher: ->(item) { find_record(item).image_attacher },
  reload: ->(attacher, item) do
    reloaded_record = reload_record(item)
    yield reloaded_record.image_attacher
  end,
  persist: ->(attacher, item) do
    save_attachment_data(item, attacher.record.image_data)
  end,
)
```

A custom `switch` callback is also supported for applications that want to use
an optimistic database update directly. It receives the source and target
`Shrine::UploadedFile` objects and must raise
`Shrine::AttachmentChanged` when the current reference no longer matches the
source.

## Results

The result journal is written atomically after each item reaches a durable
state. Result hashes include the item status, current stage, source and target
identity, checksum, metadata, target file data, and error details for failed
attempts.

- `copied`: target was copied and verified, but the reference was not switched.
- `switched`: target was copied, verified, and the reference was switched.
- `attachment_changed`: a user or another process changed the source reference.
- `copy_failed`, `verify_failed`, or `switch_failed`: the item can be retried.
- `source_missing`, `source_failed`, or `source_changed`: the source must be
  investigated before continuing.
- `metadata_mismatch`: the current metadata no longer matches the immutable plan.

Re-running the executor skips completed items. If switching was interrupted,
the already verified target is re-read and checksummed, but it is not
re-uploaded. If a copy failed, the source is read again and the target is
replaced.

## Cleanup

Do not delete source objects during migration. After all references have been
switched, applications have been verified, and a backup or rollback window has
passed, run a separate cleanup job that deletes only the source identities
saved in the plan.
