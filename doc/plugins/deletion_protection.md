---
title: Deletion Protection
---

The [`deletion_protection`][deletion_protection] plugin separates two pieces
of information that are normally conflated:

* the application no longer references an uploaded file (pending deletion),
* the file is actually allowed to be physically deleted.

A file that was replaced or whose record was destroyed is first **marked
pending**. Its physical deletion is then independently gated by explicit
administrative **holds** and a **retention deadline**. Releasing a hold never
shortens the remaining retention period. Ordinary attachment replacement goes
through the exact same rules as record destruction, so old files cannot bypass
the protection by accident.

Cleanup is performed synchronously on demand &mdash; there is no background
service that has to be running. A configurable clock makes retention behavior
fully deterministic and testable.

## Setup

```rb
plugin :deletion_protection
```

## Retention period

A default retention period can be configured globally. It is measured from
the moment a file first becomes pending:

```rb
plugin :deletion_protection, retention_period: 30 * 24 * 60 * 60 # 30 days
```

Deadlines can also be recorded per file, as an absolute time or a duration
relative to the configured clock:

```rb
attacher.retain_until!(30.days.from_now)
attacher.retain_for!(30 * 24 * 60 * 60)
```

An earlier deadline never shortens a deadline that was already recorded.

## Administrative holds

A hold prevents physical deletion for as long as it is active, independently
of the retention period. This is useful for legal freezes, admin review, or
any other temporary protection:

```rb
attacher.hold                       # indefinite hold named :admin
attacher.hold(name: :legal)         # named hold
attacher.hold(until_time: deadline) # automatically expiring hold

attacher.release_hold(name: :legal)
```

Releasing a hold leaves the pending flag and the retention deadline intact,
so a file stays protected until its retention period has fully elapsed.

## Requesting and cancelling deletion

When an attachment is replaced or its record is destroyed, the old file is
marked pending automatically. Deletion can also be requested explicitly:

```rb
attacher.request_destroy #=> true if deleted now, false if deferred
```

A pending deletion can be revoked. Holds and retention remain recorded:

```rb
attacher.cancel_destroy
attacher.pending_deletion? #=> false
```

## Inspecting block reasons

`#deletion_block_reasons` reports exactly what is currently preventing
physical deletion, which is handy for admin UIs and logging:

```rb
attacher.deletion_block_reasons
#=> [:retain_until, :hold_admin]
```

Possible reasons are `:retain_until`, and `:hold_<name>` for every active
hold. An empty array means nothing blocks deletion (the file additionally
has to be pending before cleanup will remove it).

## Cleaning up

Physical deletion is performed synchronously. Call this from a rake task, a
cron job, or an admin action:

```rb
Attacher.cleanup_deletions         # one storage
Attacher.cleanup_all_deletions     # every registered storage
```

Only pending files without active holds and whose retention deadline has
passed are deleted. If a physical deletion raises, the recorded state is
kept so the next cleanup run retries it.

## Configurable clock

By default `Time.now` is used. A different clock can be injected, which makes
boundary verification deterministic:

```rb
clock = -> { Time.now }
plugin :deletion_protection, retention_period: 60, clock: clock
```

## Custom registry

Deletion state is stored in a thread-safe in-memory registry keyed by
storage and file id, and is independent from application records. For
multi-process or persistent setups, configure an object that implements the
same public interface (for example backed by Redis or a database table):

```rb
plugin :deletion_protection, registry: MyDeletionRegistry.new
```

[deletion_protection]: https://github.com/shrinerb/shrine/blob/master/lib/shrine/plugins/deletion_protection.rb

## Background jobs

Cleanup itself never requires a running worker; `#cleanup_deletions` is a plain
synchronous call. If the [`backgrounding`][backgrounding] plugin is loaded with
a registered `destroy_block`, destruction requests are enqueued as before and
bypass the synchronous hold/retention check. Do not register a destroy block
when deletions should always go through the cleanup sweep.

[backgrounding]: /docs/plugins/backgrounding
