# Offline firmware remediation example

This example shows how to derive an offline remediation plan from:

* TUF verified target descriptions loaded from local, hash-pinned metadata
  views (`archive` and `current`), and
* a caller supplied compatibility table describing the target, installed
  version and use combinations allowed for each device group.

Both example devices have firmware `1.0.0` installed. The release team has
withdrawn that target, but the two groups still have different controlled
routes:

* `monitoring/mon-01` installs `firmware/monitor-1.1.0.bin` from the current
  snapshot.
* `spare/spare-01` takes the archived, pending-review rollback to
  `firmware/spare-0.9.0.bin`. The action is marked `controlled` and
  `requires-approval`.

Run it from the repository root:

```console
python examples/firmware_remediation/plan
python examples/firmware_remediation/plan --json
```

The table printed by the default run is:

```text
Withdrawn targets (rollback-only): firmware/common-1.0.0.bin

group/device       installed  action    target                      version  view       flags
monitoring/mon-01  1.0.0      INSTALL   firmware/monitor-1.1.0.bin  1.1.0    current@9  -
spare/spare-01     1.0.0      ROLLBACK  firmware/spare-0.9.0.bin    0.9.0    archive@4  archived, stale, controlled, pending-review, requires-approval
```

The notes also call out that both devices have the withdrawn `1.0.0` target
installed, so a reinstall of that target is not offered.

The archive and current views are separate trust scopes. Each view is verified
against its own trusted root, timestamp and snapshot. Snapshot metadata pins
the hashes of all targets roles, so an old snapshot cannot be paired with a
newly signed delegated role (or the reverse).
