struct_leak_audit
==================

Static, pycparser-based check for the diagnostic reporting pattern in which a
*public* structure is built and passed to a host-provided reporting function.
The outer type name is never trusted as proof that no sensitive field can leak;
every field and every whole-object write is traced to its real source.

The analyzer works on the pycparser AST only. No compilation or preprocessing
is needed, so the C snippets under audit may use forward-declared types and
need not include any standard headers.

Tracked construction styles
---------------------------

* Field-by-field initialization / assignment. Each field is traced separately,
  so a field rewritten with a safe constant (even when it shares its name with
  an internal field) is reported SAFE, while a field read from an internal
  object is reported for REVIEW.
* Whole-structure copies (pub = *internal and memcpy / memmove). These are
  UNSAFE and the finding records the rendered right-hand source so the
  reviewer can see where the data really came from.
* Known projection functions named in the configuration are trusted as
  sanitizers and reported SAFE.

Indirect calls whose callee cannot be bound to a declared function (function
pointer calls, unknown callees) are kept as REVIEW findings rather than guessed
at.

Usage
-----

Command line:

    python -m struct_leak_audit.cli tests/struct_leak_cases/unsafe_report.c --struct diag_public --exit host_report

Add trusted projections with repeatable --projection flags and use --json for
machine-readable output. The process exits non-zero when an UNSAFE finding is
present.

Library:

    from struct_leak_audit import AuditConfig, audit_file, to_text

    config = AuditConfig(
        public_struct="diag_public",
        report_functions=("host_report",),
        projection_functions=("project_public",),
    )
    print(to_text(audit_file("report.c", config)))
