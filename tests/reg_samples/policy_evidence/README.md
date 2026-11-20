Policy evidence fixture
=======================

Three 8 KiB snapshots of the same four security-policy values:

- baseline.hive: AuditLevel is RegDWord; IncompletePolicy declares two
  bytes although four inline bytes are still readable.
- representation_change.hive: AuditLevel keeps the bytes
  01 00 00 00 but changes its type marker to RegBigEndian.
- value_change.hive: LmCompatibilityLevel changes from 3 to 4.

Run the external comparator from the repository root:

    python samples/compare_policy_evidence.py <before.hive> <after.hive>

Use --json for machine-readable output.
