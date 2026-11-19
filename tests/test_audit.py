"""Tests for the independent guard instrumentation audit."""

from __future__ import annotations

import ast

import pytest

from RestrictedPython import audit
from RestrictedPython import compile_restricted_exec
from RestrictedPython.audit import audit_compiled_code
from RestrictedPython.audit import audit_restricted
from RestrictedPython.audit import GuardAuditError
from RestrictedPython.audit import InconclusiveAuditError
from RestrictedPython.transformer import RestrictingNodeTransformer


class MissingAttributeGuardTransformer(RestrictingNodeTransformer):
    """Defective policy: leaves attribute access completely unguarded."""

    def visit_Attribute(self, node: ast.Attribute):
        if node.attr.startswith("_") and node.attr != "_":
            self.error(node, "invalid attribute name")
        if node.attr.endswith("__roles__"):
            self.error(node, "invalid attribute name")
        return self.node_contents_visit(node)


class MissingIterationGuardTransformer(RestrictingNodeTransformer):
    """Defective policy: never wraps iterables in _getiter_."""

    def guard_iter(self, node):
        return self.node_contents_visit(node)


COVERED_SOURCE = """
value = obj.attribute
obj.attribute = new_value
del obj.attribute
item = container[key]
container[key] = item
del container[key]
for element in sequence:
    pass
squares = [number for number in numbers]
spread = function(*positional, **keywords)
(first, second) = pair
with manager() as (left, right):
    pass
def nested():
    inner = deeply.hidden[0]
    return [entry for entry in inner]
"""


def test_audit_clean_source_passes():
    result = audit_restricted(COVERED_SOURCE)
    assert result.ok
    assert not result.inconclusive
    assert result.missing == []
    assert result.duplicate == []
    assert result.unprovable == []
    result.assert_guarded()
    expected_kinds = {site.kind for site in result.expected}
    assert expected_kinds == {
        "attribute_load", "attribute_store",
        "subscript_load", "subscript_store",
        "for_iteration", "comprehension_iteration",
        "call_spread", "assign_unpack", "with_unpack",
    }


def test_audit_covers_every_access_category():
    result = audit_restricted(COVERED_SOURCE)
    by_guard = {}
    for site in result.expected:
        by_guard.setdefault(site.guard, []).append(site.kind)
    assert "_getattr_" in by_guard
    assert "_getitem_" in by_guard
    assert "_write_" in by_guard
    assert "_getiter_" in by_guard
    assert "_apply_" in by_guard
    assert "_unpack_sequence_" in by_guard


def test_audit_detects_missing_attribute_guard():
    result = audit_restricted(
        COVERED_SOURCE, policy=MissingAttributeGuardTransformer)
    assert not result.ok
    assert not result.inconclusive
    missing_kinds = {site.kind for site in result.missing}
    assert missing_kinds == {"attribute_load", "attribute_store"}
    lines = {site.span[0] for site in result.missing}
    assert lines == {2, 3, 4, 16}
    assert result.unprovable == []
    with pytest.raises(GuardAuditError):
        result.assert_guarded()


def test_audit_detects_missing_iteration_guard():
    result = audit_restricted(
        COVERED_SOURCE, policy=MissingIterationGuardTransformer)
    assert not result.ok
    assert not result.inconclusive
    missing_kinds = {site.kind for site in result.missing}
    assert missing_kinds == {
        "for_iteration", "comprehension_iteration"}
    for site in result.missing:
        assert site.guard == "_getiter_"
    locations = {(site.kind, site.span[0]) for site in result.missing}
    assert locations == {
        ("for_iteration", 8), ("comprehension_iteration", 10),
        ("comprehension_iteration", 17),
    }
    assert result.unprovable == []
    with pytest.raises(GuardAuditError):
        result.assert_guarded()


def test_audit_does_not_execute_the_source():
    marker = []
    source = ("sentinel = object()\n"
              "marker.append(sentinel)\n"
              "value = sentinel.attr\n"
              "for item in sentinel.items:\n"
              "    pass\n")
    result = audit_restricted(source)
    assert result.ok
    assert marker == []
    # Positive control: the marker mechanism itself works when executed.
    namespace = {"marker": marker}
    exec("marker.append(1)", namespace)
    assert marker == [1]


def test_audit_compiled_code_entry_point():
    source = "result = data[0].attr"
    compiled = compile_restricted_exec(source)
    assert compiled.errors == ()
    transformed = ast.parse(source)
    policy = RestrictingNodeTransformer([], [], {})
    policy.visit(transformed)
    result = audit_compiled_code(source, compiled.code, transformed)
    assert result.ok
    assert result.bytecode_counts.get("_getattr_") == 1
    assert result.bytecode_counts.get("_getitem_") == 1


def test_audit_refuses_conclusion_on_unknown_bytecode_version(
        monkeypatch):
    from RestrictedPython import _bytecode
    monkeypatch.setattr(
        _bytecode, "SUPPORTED_BYTECODE_VERSIONS", frozenset())
    result = audit_restricted("value = obj.attr")
    assert result.inconclusive
    assert not result.ok
    with pytest.raises(InconclusiveAuditError):
        result.assert_guarded()


def test_audit_flags_duplicate_guards():
    class DuplicatingTransformer(RestrictingNodeTransformer):
        def visit_Attribute(self, node):
            replaced = super().visit_Attribute(node)
            if (isinstance(node.ctx, ast.Load)
                    and isinstance(replaced, ast.Call)):
                wrapped = ast.Tuple([replaced, replaced], ast.Load())
                ast.fix_missing_locations(wrapped)
                return wrapped
            return replaced

    result = audit_restricted("value = obj.attr",
                              policy=DuplicatingTransformer)
    assert not result.ok
    assert result.duplicate
    guard, span, count = result.duplicate[0]
    assert guard == "_getattr_"
    assert count == 2


def test_audit_flags_unexplainable_guard_calls():
    class ExtraGuardTransformer(RestrictingNodeTransformer):
        def visit_Module(self, node):
            node = self.node_contents_visit(node)
            extra = ast.Expr(ast.Call(
                func=ast.Name("_getattr_", ast.Load()),
                args=[ast.Name("value", ast.Load()),
                      ast.Constant("other")],
                keywords=[]))
            ast.fix_missing_locations(extra)
            node.body.insert(0, extra)
            return node

    result = audit_restricted("value = obj.attr",
                              policy=ExtraGuardTransformer)
    assert not result.ok
    assert len(result.unprovable) == 1
    assert result.unprovable[0].guard == "_getattr_"


def test_audit_nested_code_objects_are_counted():
    source = ("def outer():\n"
              "    def inner():\n"
              "        return deep.attr[0]\n"
              "    return [item for item in inner()]\n")
    result = audit_restricted(source)
    assert result.ok
    assert result.bytecode_counts["_getattr_"] >= 1
    assert result.bytecode_counts["_getitem_"] >= 1
    assert result.bytecode_counts["_getiter_"] >= 1


def test_audit_eval_mode():
    result = audit_restricted("obj.attr + data[0]", mode="eval")
    assert result.ok
    kinds = {site.kind for site in result.expected}
    assert kinds == {"attribute_load", "subscript_load"}


def test_audit_rejects_non_policy():
    with pytest.raises(TypeError):
        audit_restricted("value = obj.attr", policy=object)


def test_audit_marks_transformation_errors_inconclusive():
    result = audit_restricted("value = obj._private")
    assert result.inconclusive
    assert result.errors
    with pytest.raises(InconclusiveAuditError):
        result.assert_guarded()


def test_audit_recognises_infrastructure_guards():
    result = audit_restricted("counter += 1\n")
    assert result.ok
    assert result.unprovable == []
    assert [observation.guard for observation in result.infrastructure] == [
        "_inplacevar_",
    ]
