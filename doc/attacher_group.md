---
title: Attacher Group
---

An application can have multiple attachment columns that must be replaced as
one group, such as an application body, cover page, and attachment list. File
storage does not provide database transactions, so `Shrine::AttacherGroup`
uses explicit prepare, commit, and cleanup phases.

```rb
group = Shrine::AttacherGroup.new(
  body: body_attacher,
  cover: cover_attacher,
  attachments: attachments_attacher,
)

group.prepare # upload and validate every new object

group.commit do |references|
  ApplicationRecord.where(id: application.id).update_all(references)
end

group.cleanup # delete old objects only after the business commit succeeds
```

Each attacher may already have a cached file assigned. `#prepare` promotes all
changed attachments and validates them before invoking the callback. If
preparation or the persistence callback fails, all attachers are restored to
their old references and objects uploaded during the failed attempt are
deleted.

The persistence callback is the only operation allowed to publish new
references. If it raises or returns `false`, the business state is treated as
unchanged. Old objects are deleted only in `#cleanup`. If cleanup fails,
calling it again retries deletion; it never rolls back the successful commit.
