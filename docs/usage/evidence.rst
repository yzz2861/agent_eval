Call evidence for approved host functions
==========================================

Some applications allow several teams to submit short restricted rules which
may call host functions approved by the application.  A normal application log
which only records the host function name cannot tell two scripts apart when
both use the same name.

The RestrictedPython.evidence module adds an optional evidence outlet next to
restricted compilation and execution.  It binds every call to:

* the identity of the script (script_id),
* the restricted source statement and call expression,
* the adapter which the caller registered for the source-level name,
* a receipt id, a parent receipt id, and a per-call-site attempt number.

Receipts contain metadata only.  Arguments, return values, exception messages
and other values which originate in restricted code are never stored in a
receipt or report.

Registering adapters
--------------------

An EvidenceSession owns the adapter registrations of one script::

    from RestrictedPython import EvidenceSession

    session = EvidenceSession("team-a/rule-17")

    def lookup(value):
        return approved_catalog[value]

    session.register_adapter(
        "lookup", lookup, adapter_id="team-a.catalog.lookup")

The source-level name is what the restricted rule writes.  adapter_id is the
stable identity of the caller-registered adapter.  When two scripts use the
same source-level name, their sessions and adapter ids keep the receipts
separate.

Running a rule
--------------

EvidenceSession.run compiles and executes the rule.  It behaves like normal
restricted execution and also records the approved calls::

    result = session.run("""
    def rule(value):
        return lookup(value)
    result = rule("A-1")
    """)

    for receipt in session.report().receipts:
        print(
            receipt.script_id,
            receipt.statement,
            receipt.function_name,
            receipt.adapter_id,
        )

The module level helpers run_restricted_evidence and
compile_restricted_evidence accept either a session or a script_id plus an
adapters mapping::

    from RestrictedPython import run_restricted_evidence

    result = run_restricted_evidence(
        "result = lookup(1)",
        script_id="team-b/rule-9",
        adapters={"lookup": lookup},
    )

When compiling without running, call install_globals(namespace) on the
returned compile result (or on the session) before exec so the generated
hidden helper and adapter names are present.

Nested calls, retries, and partial records
------------------------------------------

A host adapter may call a restricted callback.  Calls made by that callback
receive the adapter receipt id as parent_call_id and a larger depth.
EvidenceReport.trace returns the root-to-leaf chain.

Repeated calls to the same source location get an increasing attempt and the
previous receipt id in previous_call_id.  A failed call has status equal to
error and only the exception type name in error_type.

Every receipt receives a monotonically increasing sequence.  Reports built
from partial receipts show gaps in missing_sequences; a trace whose parent
record is absent lists the absent id in missing_call_ids instead of silently
presenting an incomplete chain as complete.

Optional sinks
--------------

A session or recorder may receive a callable sink or an object with a write
method accepting one receipt.  Delivery failures are retried
max_delivery_attempts times.  The receipt stays in the recorder even when
delivery fails, with delivery_status equal to failed.  Call
EvidenceRecorder.flush later to retry.

as_dict() on a receipt or report returns JSON-friendly metadata for shipping
to a background record.  It never includes restricted values.
