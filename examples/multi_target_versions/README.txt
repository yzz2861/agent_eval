Multi-target syntax examples
============================

legacy_syntax.py
  Parses under both an older target and the host target.  The same B404 and
  B602 hits therefore appear with both versions in python_versions.  The
  blanket "# nosec" is recorded as a suppression, not as a deletion.

host_only_syntax.py
  Uses structural pattern matching, which the 3.8 grammar rejects.  A 3.8
  target is therefore REJECTED for the whole file and contributes no rule
  results.  On a host that understands the grammar the target is CHECKED and
  real rules such as B404/B602 appear only for that version.  A target newer
  than the host is UNCOVERED: it was not scanned, so an empty finding list is
  not evidence of safety.

Try this:

  bandit -r examples/multi_target_versions \
      --target-versions 3.8,3.12,3.14 -f json
