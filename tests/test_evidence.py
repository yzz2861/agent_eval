import json

import pytest

from RestrictedPython.evidence import EvidenceHub
from RestrictedPython.evidence import EvidenceLedger
from RestrictedPython.evidence import RetryingFunctionAdapter
from RestrictedPython.evidence import audit_records


def test_same_named_functions_trace_to_separate_scripts():
    hub = EvidenceHub()

    def ping_a(value):
        return f"A:{value}"

    def ping_b(value):
        return f"B:{value}"

    hub.register_function(
        "ping", ping_a, caller="team-a", adapter_id="adapter-a"
    )
    hub.register_function(
        "ping", ping_b, caller="team-b", adapter_id="adapter-b"
    )

    run_a = hub.run_script(
        'answer = ping("one")\n',
        script_id="script-a",
        caller="team-a",
    )
    run_b = hub.run_script(
        'answer = ping("two")\n',
        script_id="script-b",
        caller="team-b",
    )

    assert run_a.namespace["answer"] == "A:one"
    assert run_b.namespace["answer"] == "B:two"

    receipt_a = run_a.receipts[0]
    receipt_b = run_b.receipts[0]

    assert receipt_a.script_id == "script-a"
    assert receipt_b.script_id == "script-b"
    assert receipt_a.function_name == "ping"
    assert receipt_b.function_name == "ping"
    assert receipt_a.adapter_id == "adapter-a"
    assert receipt_b.adapter_id == "adapter-b"
    assert receipt_a.source_statement == 'answer = ping("one")'
    assert receipt_b.source_statement == 'answer = ping("two")'
    assert receipt_a.line_number == 1
    assert receipt_b.line_number == 1
    assert receipt_a.receipt_id != receipt_b.receipt_id

    report = json.loads(hub.report().to_json())
    assert report["ok"] is True
    assert len(report["receipts"]) == 2


def test_nested_callback_has_parent_chain_and_source():
    hub = EvidenceHub()

    def outer(callback):
        return callback(41)

    def late(value):
        return value + 1

    hub.register_function("outer", outer, adapter_id="outer-adapter")
    hub.register_function("late", late, adapter_id="late-adapter")

    run = hub.run_script(
        """
def calculate(value):
    return late(value)

outer(calculate)
""",
        script_id="nested",
    )

    by_name = {item.function_name: item for item in run.receipts}
    outer_receipt = by_name["outer"]
    late_receipt = by_name["late"]

    assert late_receipt.parent_call_id == outer_receipt.call_id
    assert late_receipt.root_call_id == outer_receipt.call_id
    assert outer_receipt.parent_call_id is None
    assert outer_receipt.source_statement == "outer(calculate)"
    assert late_receipt.source_statement == "return late(value)"
    assert run.report.ok


class SecretValue:
    def __repr__(self):
        return "SECRET_REPR_7781"


def test_retry_attempts_are_recorded_without_restricted_values():
    hub = EvidenceHub()
    state = {"attempts": 0}

    def flaky(*args):
        state["attempts"] += 1
        if state["attempts"] == 1:
            raise RuntimeError("SECRET_ERROR_9913")
        return "recovered"

    adapter = RetryingFunctionAdapter(flaky, max_attempts=2)
    hub.register_function("sync", adapter, caller="ops")
    secret = SecretValue()

    run = hub.run_script(
        "sync(secret)",
        script_id="retry-script",
        caller="ops",
        namespace={"secret": secret},
    )

    receipt = run.receipts[0]
    assert receipt.status == "succeeded"
    assert receipt.attempt_count == 2
    kinds = [record.kind for record in run.report.records]
    assert "attempt_started" in kinds
    assert "attempt_failed" in kinds
    assert "retry_scheduled" in kinds
    assert "call_succeeded" in kinds

    payload = run.report.to_json()
    assert "SECRET_ERROR_9913" not in payload
    assert "SECRET_REPR_7781" not in payload
    assert "RuntimeError" in payload


def test_partial_records_can_be_audited():
    hub = EvidenceHub()

    def flaky():
        if not getattr(flaky, "failed", False):
            flaky.failed = True
            raise RuntimeError("temporary")
        return "ok"

    hub.register_function(
        "job",
        RetryingFunctionAdapter(flaky, max_attempts=2),
    )
    hub.run_script("job()", script_id="partial")
    records = hub.ledger.records

    missing_start = [
        record for record in records if record.kind != "call_started"
    ]
    report = EvidenceLedger(records=missing_start).report()
    assert not report.ok
    assert report.receipts[0].missing_start is True
    assert any(issue.code == "missing_call_start" for issue in report.issues)

    missing_middle = [
        record for index, record in enumerate(records) if index != 1
    ]
    audit = audit_records(missing_middle)
    assert not audit.ok
    assert audit.missing_sequences


def test_sink_is_optional_and_receives_safe_records():
    sink = []
    hub = EvidenceHub(sink=sink.append)
    hub.register_function("ping", lambda value: value)

    hub.run_script("ping(1)", script_id="sink-script")

    assert sink
    assert all(record.call_id for record in sink)
    assert hub.report().ok


def test_compile_errors_are_reported():
    hub = EvidenceHub()
    with pytest.raises(Exception) as exc_info:
        hub.run_script("eval('1')", script_id="bad")
    assert "Eval calls are not allowed" in str(exc_info.value)


def test_backend_name_only_records_can_be_reconciled():
    hub = EvidenceHub()
    hub.register_function("ping", lambda *args: None, caller="team-a")
    hub.register_function("ping", lambda *args: None, caller="team-b")

    hub.run_script(
        'ping("one")', script_id="reconcile-a", caller="team-a"
    )
    hub.run_script(
        'ping("two")', script_id="reconcile-b", caller="team-b"
    )

    matched = hub.reconcile(["ping", "ping"])
    assert matched.ok
    assert [item.script_id for item in matched.matches] == [
        "reconcile-a",
        "reconcile-b",
    ]
    assert [item.source_statement for item in matched.matches] == [
        'ping("one")',
        'ping("two")',
    ]

    partial = hub.reconcile(["ping"])
    assert not partial.ok
    assert len(partial.missing_backend_call_ids) == 1
