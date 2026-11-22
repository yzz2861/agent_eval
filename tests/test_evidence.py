import ast
import json

import pytest

from RestrictedPython import CallReceipt
from RestrictedPython import EvidenceRecorder
from RestrictedPython import EvidenceReport
from RestrictedPython import EvidenceSession
from RestrictedPython import FunctionAdapter
from RestrictedPython import compile_restricted_evidence
from RestrictedPython import run_restricted_evidence
from RestrictedPython import safe_builtins


def test_same_function_name_is_bound_to_script_and_statement():
    script_a = """
def rule(value):
    return lookup(value)
result = rule(1)
"""
    script_b = """
def rule(value):
    return lookup(value) + 100
result = rule(2)
"""
    session_a = EvidenceSession('team-a/rule')
    session_b = EvidenceSession('team-b/rule')
    session_a.register_adapter(
        'lookup',
        lambda value: f'a:{value}',
        adapter_id='team-a.lookup')
    session_b.register_adapter(
        'lookup',
        lambda value: value * 100,
        adapter_id='team-b.lookup')

    result_a = session_a.run(script_a)
    result_b = session_b.run(script_b)

    assert result_a.locals['result'] == 'a:1'
    assert result_b.locals['result'] == 300

    receipt_a, = session_a.report().receipts
    receipt_b, = session_b.report().receipts
    assert receipt_a.function_name == receipt_b.function_name == 'lookup'
    assert receipt_a.script_id == 'team-a/rule'
    assert receipt_b.script_id == 'team-b/rule'
    assert receipt_a.adapter_id == 'team-a.lookup'
    assert receipt_b.adapter_id == 'team-b.lookup'
    assert receipt_a.statement == 'return lookup(value)'
    assert receipt_b.statement == 'return lookup(value) + 100'
    assert receipt_a.expression == 'lookup(value)'
    assert receipt_b.expression == 'lookup(value)'
    assert session_a.report().trace(receipt_a.call_id).receipts == (
        receipt_a,)
    assert session_b.report().trace(receipt_b.call_id).receipts == (
        receipt_b,)


def test_nested_callback_is_linked_to_its_parent_call():
    session = EvidenceSession('callback-rule')

    def call_back(callback):
        return callback()

    session.register_adapter(
        'call_back', call_back, adapter_id='host.call_back')
    session.register_adapter(
        'lookup', lambda value: value * 10, adapter_id='host.lookup')

    result = session.run("""
def rule(value):
    return call_back(lambda: lookup(value))
result = rule(4)
""")

    assert result.locals['result'] == 40
    parent, child = session.report().receipts
    assert parent.function_name == 'call_back'
    assert parent.depth == 0
    assert parent.parent_call_id is None
    assert child.function_name == 'lookup'
    assert child.depth == 1
    assert child.parent_call_id == parent.call_id
    assert session.report().children(parent.call_id) == (child,)
    assert session.report().roots() == (parent,)
    trace = session.report().trace(child.call_id)
    assert trace.receipts == (parent, child)
    assert trace.missing_call_ids == ()


def test_failed_retry_is_linked_and_only_metadata_is_reported():
    secret = 'SENSITIVE-RETURN-VALUE'
    calls = []

    def leaky(value):
        calls.append(value)
        if len(calls) == 1:
            raise ValueError(secret)
        return secret

    session = EvidenceSession('retry-rule')
    session.register_adapter('leaky', leaky, adapter_id='host.leaky')

    session.run(
        """
def attempt(value):
    try:
        leaky(value)
    except ValueError:
        pass
attempt(1)
attempt(2)
""",
        globals={'__builtins__': safe_builtins.copy()})

    first, second = session.report().receipts
    assert first.status == 'error'
    assert first.error_type == 'ValueError'
    assert second.status == 'ok'
    assert first.attempt == 1
    assert second.attempt == 2
    assert second.previous_call_id == first.call_id
    assert first.statement == 'leaky(value)'
    serialized = json.dumps(session.report().as_dict())
    assert secret not in serialized
    assert 'arguments' not in first.as_dict()
    assert 'return_value' not in first.as_dict()


def test_partial_records_and_missing_parent_are_traceable():
    session = EvidenceSession('partial-rule')
    session.register_adapter(
        'outer', lambda callback: callback(), adapter_id='host.outer')
    session.register_adapter(
        'inner', lambda: 1, adapter_id='host.inner')
    session.run("""
def rule():
    return outer(lambda: inner())
result = rule()
""")
    outer, inner = session.report().receipts

    partial = EvidenceReport.from_receipts(
        [inner], expected_sequences=range(inner.sequence + 1))

    assert partial.receipts == (inner,)
    assert partial.missing_sequences == (outer.sequence,)
    trace = partial.trace(inner.call_id)
    assert trace.receipts == (inner,)
    assert trace.missing_call_ids == (outer.call_id,)


class FlakySink:
    def __init__(self, failures):
        self.failures = failures
        self.receipts = []

    def write(self, receipt):
        if self.failures:
            self.failures -= 1
            raise OSError('sink unavailable')
        self.receipts.append(receipt)


def test_sink_failure_is_retried_and_can_be_flushed_later():
    sink = FlakySink(failures=2)
    session = EvidenceSession(
        'sink-rule', sink=sink, max_delivery_attempts=2)
    session.register_adapter('value', lambda: 1, adapter_id='host.value')

    session.run('value()')

    receipt, = session.report().receipts
    assert receipt.delivery_status == 'failed'
    assert receipt.delivery_attempts == 2
    assert receipt.delivery_error_type == 'OSError'
    assert sink.receipts == []

    assert session.recorder.flush() == 1
    receipt, = session.report().receipts
    assert receipt.delivery_status == 'delivered'
    assert sink.receipts == [receipt]


def test_eval_mode_and_module_level_helpers():
    def double(value):
        return value * 2

    result = run_restricted_evidence(
        'double(3)',
        script_id='eval-rule',
        adapters={'double': double},
        mode='eval')

    assert result.value == 6
    receipt, = result.receipts
    assert receipt.statement == 'double(3)'
    assert receipt.adapter_id == 'eval-rule:double'


def test_compile_only_flow_installs_hidden_adapter_names():
    session = EvidenceSession('compiled-rule')
    session.register_adapter('double', lambda value: value * 2)
    compiled = compile_restricted_evidence(
        'result = double(4)', session=session)

    namespace = {}
    session.install_globals(namespace)
    exec(compiled.code, namespace)

    assert namespace['result'] == 8
    receipt, = session.report().receipts
    assert receipt.expression == 'double(4)'
    assert receipt.status == 'ok'


def test_ast_source_uses_unparsed_statements():
    session = EvidenceSession('ast-rule')
    session.register_adapter('lookup', lambda value: value)
    tree = ast.parse('result = lookup(7)')

    session.run(tree)

    receipt, = session.report().receipts
    assert receipt.statement == 'result = lookup(7)'
    assert receipt.expression == 'lookup(7)'


def test_bytes_source_keeps_source_statements():
    session = EvidenceSession('bytes-rule')
    session.register_adapter('lookup', lambda value: value)

    session.run(b'result = lookup(9)\n')

    receipt, = session.report().receipts
    assert receipt.statement == 'result = lookup(9)'


def test_function_adapter_can_be_registered_directly():
    adapter = FunctionAdapter(
        name='lookup', adapter_id='shared.lookup', function=lambda: 'ok')
    session = EvidenceSession('adapter-rule')
    session.register_adapter('lookup', adapter)

    result = session.run('result = lookup()')

    assert result.locals['result'] == 'ok'
    receipt, = session.report().receipts
    assert receipt.adapter_id == 'shared.lookup'
    assert 'adapter_id=' in repr(adapter)


@pytest.mark.parametrize('name', ['', 'not valid', '_private', 'class'])
def test_invalid_adapter_names_are_rejected(name):
    session = EvidenceSession('invalid-rule')
    with pytest.raises(ValueError):
        session.register_adapter(name, lambda: None)


def test_adapter_registration_conflicts_are_rejected():
    session = EvidenceSession('conflict-rule')
    session.register_adapter('lookup', lambda: 1, adapter_id='one')

    with pytest.raises(ValueError):
        session.register_adapter('lookup', lambda: 2, adapter_id='two')
    with pytest.raises(ValueError):
        session.register_adapter('other', lambda: 2, adapter_id='one')
    with pytest.raises(ValueError):
        session.register_adapter(
            'other',
            FunctionAdapter('different', 'three', lambda: 3))
    with pytest.raises(ValueError):
        session.register_adapter(
            'lookup',
            FunctionAdapter('lookup', 'four', lambda: 4),
            adapter_id='five')

    replaced = session.register_adapter(
        'lookup', lambda: 5, adapter_id='five', replace=True)
    assert session.adapters['lookup'] is replaced


def test_session_and_recorder_validation():
    with pytest.raises(ValueError):
        EvidenceSession('')
    with pytest.raises(ValueError):
        EvidenceSession('rule', recorder=EvidenceRecorder(), sink=lambda x: x)
    with pytest.raises(ValueError):
        EvidenceRecorder(max_delivery_attempts=0)
    with pytest.raises(TypeError):
        run_restricted_evidence('1', script_id=None)
    with pytest.raises(TypeError):
        run_restricted_evidence(
            '1', EvidenceSession('rule'), script_id='other')
    with pytest.raises(TypeError):
        run_restricted_evidence(
            '1', EvidenceSession('rule'), recorder=EvidenceRecorder())


def test_receipt_report_lookup_helpers_and_no_sink_flush():
    recorder = EvidenceRecorder()
    session = EvidenceSession('helpers-rule', recorder=recorder)
    session.register_adapter('one', lambda: 1, adapter_id='host.one')
    session.register_adapter('two', lambda: 2, adapter_id='host.two')
    session.run('one()\ntwo()')

    report = session.report()
    first, second = report.receipts
    assert report.get(first.call_id) == first
    assert report.get('missing') is None
    assert report.for_script('helpers-rule') == report
    assert report.for_script('other').receipts == ()
    assert report.for_adapter('host.one') == (first,)
    assert report.for_function('two') == (second,)
    assert report.for_call_site(first.call_site_id) == (first,)
    assert tuple(report) == report.receipts
    assert report.as_dict()['script_id'] == 'helpers-rule'
    assert recorder.flush() == 0


def test_sink_accepts_a_callable_and_records_pending_start():
    delivered = []
    session = EvidenceSession('callable-sink', sink=delivered.append)
    session.register_adapter('value', lambda: 1)

    session.run('value()')

    receipt, = delivered
    assert isinstance(receipt, CallReceipt)
    assert receipt.delivery_status == 'delivered'
    assert receipt.complete


def test_receipt_aliases_and_report_aliases():
    session = EvidenceSession(
        "alias-rule",
        adapters={"lookup": lambda value: value})
    session.run("result = lookup(3)", adapters={})

    receipt = session.receipts[0]
    assert receipt.source == receipt.statement
    assert receipt.function == receipt.function_name
    assert receipt.adapter == receipt.adapter_id
    assert receipt.parent_id == receipt.parent_call_id
    assert receipt.retry is False

    report = session.recorder.report("alias-rule")
    assert report.records == report.receipts
    assert report.missing == report.missing_sequences
    assert session.records == session.receipts
    assert session.recorder.records == session.recorder.receipts
    assert session.recorder.get(receipt.call_id) == receipt
    assert report.trace("unknown").missing_call_ids == ("unknown",)


def test_custom_policy_and_undecodable_source():
    from RestrictedPython import RestrictingNodeTransformer

    class CustomPolicy(RestrictingNodeTransformer):
        pass

    session = EvidenceSession("policy-rule")
    session.register_adapter("lookup", lambda value: value)
    session.run("result = lookup(1)", policy=CustomPolicy)
    assert session.receipts[0].statement == "result = lookup(1)"

    broken = EvidenceSession("broken-rule").compile(b"\xff")
    assert broken.code is None
    assert broken.errors


def test_module_level_compile_with_script_id():
    from RestrictedPython import compile_restricted_with_evidence

    compiled = compile_restricted_with_evidence(
        "lookup(5)",
        script_id="module-rule",
        adapters={"lookup": lambda value: value},
        mode="eval")
    assert compiled.code is not None


def test_local_function_shadowing_the_adapter_is_not_rewritten():
    session = EvidenceSession("shadow-rule")
    session.register_adapter("lookup", lambda value: value + 100)

    result = session.run("""
def lookup(value):
    return value + 1
result = lookup(1)
""")

    assert result.locals["result"] == 2
    assert session.receipts == ()


def test_global_adapter_call_after_nested_function_is_recorded():
    session = EvidenceSession("global-rule")
    session.register_adapter("lookup", lambda value: value + 1)

    result = session.run("""
def helper(value):
    local = value
    return local
result = lookup(helper(4))
""")

    assert result.locals["result"] == 5
    receipt, = session.receipts
    assert receipt.statement == "result = lookup(helper(4))"


def test_compiled_result_can_install_its_session_globals():
    compiled = compile_restricted_evidence(
        "result = lookup(6)",
        script_id="attached-rule",
        adapters={"lookup": lambda value: value + 1})

    namespace = {}
    compiled.install_globals(namespace)
    exec(compiled.code, namespace)

    assert namespace["result"] == 7
    assert compiled.session is not None
    receipt, = compiled.session.receipts
    assert receipt.script_id == "attached-rule"
