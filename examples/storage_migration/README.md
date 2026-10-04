# Storage migration plan & executor

Tooling for moving a batch of Shrine attachments from one storage to
another (e.g. `store` -> `archive`), with verification before any record
is touched and a manifest that makes interrupted runs resumable.

## Pieces

* `StorageMigration::Plan` - immutable migration plan. It pins the source
  storage identity (only objects in this storage are migrated), the target
  storage and object location (`target_location`: a prefix string or a
  `->(source_id) { ... }` proc), the metadata fields to verify
  (`verify_metadata`, default `size`, `mime_type`, `filename`), and the
  manifest path.
* `StorageMigration::Executor` - executes a plan against a list of
  records in three explicit phases.
* `StorageMigration::Manifest` - append-only JSONL log; the executor
  records every step here and consults it before touching a record.

## Phases

    plan = StorageMigration::Plan.new(
      source_storage:  :store,
      target_storage:  :archive,
      target_location: "migrated",          # object ids become "migrated/<source id>"
      verify_metadata: %w[size mime_type filename],
      manifest_path:   "tmp/migration-manifest.jsonl",
    )

    executor = StorageMigration::Executor.new(plan, uploader: MyUploader, name: :image)

    executor.run(records)           # copy + verify, then conditional switch
    executor.cleanup_phase(records) # explicit follow-up: delete source objects

1. **copy_phase** - streams each source object to the target storage,
   then verifies it: SHA-256 of the content plus every
   `verify_metadata` field must match the source. Only verified copies
   are recorded as `copied`. Failures are recorded as `failed` (with the
   error) and the record is left untouched.
2. **switch_phase** - re-reads the record and only rewrites the
   attachment column if the original reference (id + storage) is
   unchanged. If the user replaced the attachment in the meantime, the
   record is marked `skipped` (`reason: "attachment_changed"`) and left
   alone; the next run migrates the replacement.
3. **cleanup_phase** - a separate, explicit phase: deletes the source
   object only while the record still points at the migrated copy.

## Resuming

The manifest is the single source of truth. On a rerun (even in a new
process), a record whose manifest entry is `copied`/`switched`/`cleaned`
for the *same* source object (matching id and SHA-256) is not uploaded
again; the executor just continues with the remaining phases. Replaced
attachments are detected via the checksum and migrated as new objects.

Manifest statuses per record key: `copied` -> `switched` -> `cleaned`,
plus `failed` (copy/verify error) and `skipped` (attachment changed).

## Production notes

* The check-then-write in `switch_phase` should be an atomic conditional
  update against the real database (e.g.
  `UPDATE ... WHERE image_data = '<snapshot>'`), so a concurrent
  replacement cannot slip in between the read and the write.
* Run `cleanup_phase` only after the switched records have been verified
  in production; until then both copies exist and a rollback is just a
  column update away.

## Demo & tests

Both use two temporary directories to simulate the source and target
storages:

    bundle exec ruby examples/storage_migration/example.rb
    bundle exec ruby examples/storage_migration/test_storage_migration.rb

The tests cover copy failures (recorded, then resumed), attachments
replaced by the user between copy and switch, and repeated execution
(no re-upload of verified objects, idempotent cleanup).

