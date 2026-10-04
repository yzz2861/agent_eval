title: Attachment Group Commit
---

The [`attachment_group_commit`][attachment_group_commit] plugin provides a
helper for replacing multiple attachments of a record as a group. For example,
an application might have a body, a cover, and an attachment list that should
be swapped together, so that readers never see a mix of old and new files.

```rb
plugin :attachment_group_commit
```

## Problem Statement

File storage is not transactional, so replacing several attachments "all at
once" cannot be modeled as a single atomic operation. This helper makes the
three phases explicit instead of pretending otherwise:

1. **prepare** – assigns the new files to each attacher, validates them, and
   uploads them to permanent storage. The record is not modified.
2. **commit** – publishes the whole group of new file references through a
   single persistence callback provided by you (e.g. one database update).
3. **cleanup** – deletes the old files.

If the persistence callback fails, the old references are kept and the files
uploaded in this round are reclaimed. If deleting old files fails after a
successful commit, the error is retryable and the completed commit is never
rolled back.

## Usage

The record is expected to use the `entity` or `model` plugin, so that
`#<name>_attacher` methods are defined:

```rb
group = Shrine::AttachmentGroupCommit.new(application,
  body:        body_io,
  cover:       cover_io,
  attachments: attachments_io,
)

group.prepare

group.commit do |columns|
  # called exactly once with the whole group of new references, e.g.
  # { body_data: "...", cover_data: "...", attachments_data: "..." }
  application.update!(columns)
end

group.cleanup
```

All three phases can also be run in one go:

```rb
Shrine::AttachmentGroupCommit.commit(application,
  body:        body_io,
  cover:       cover_io,
  attachments: attachments_io,
) do |columns|
  application.update!(columns)
end
```

Assigning `nil` removes the corresponding attachment. When the `validation`
plugin is loaded, attachments are validated during prepare, and any errors
raise `Shrine::AttachmentGroupCommit::ValidationError` (which carries the
`#errors` hash keyed by attachment name).

## Failure Handling

* **prepare fails** (validation or upload error) – files uploaded during this
  round are reclaimed, old references are kept, and the error is re-raised.
* **commit callback fails** – files uploaded during this round are reclaimed,
  old references are kept, and the original error is re-raised.
* **cleanup fails** – `Shrine::AttachmentGroupCommit::CleanupError` is raised
  (carrying the `#remaining` files), and calling `group.cleanup` again
  retries deleting them. The completed commit is not affected.

[attachment_group_commit]: https://github.com/shrinerb/shrine/blob/master/lib/shrine/plugins/attachment_group_commit.rb
