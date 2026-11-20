"""Classification of right-hand expressions into provenance categories."""
from __future__ import annotations

from pycparser import c_ast

from .analyzer import root_identifier, render
from .model import FIELD_INIT, INTERNAL, UNKNOWN, WHOLE_COPY


def is_constant(node: c_ast.Node) -> bool:
    """Literals, string literals and signed literals count as safe."""
    if isinstance(node, c_ast.Constant):
        return True
    if isinstance(node, c_ast.UnaryOp) and node.op in ("-", "+"):
        return is_constant(node.expr)
    return False


def classify_rhs(node, parameters, variables, config):
    """Return (category, rendered source) for an initializer/RHS node.

    Categories are the model-level provenance codes consumed by the engine:
    FIELD_INIT (safe constant), INTERNAL (a field read off an internal
    object), WHOLE_COPY (a whole internal object), and UNKNOWN for anything
    that cannot be bound and therefore needs human review.
    """
    if is_constant(node):
        return FIELD_INIT, render(node)

    if isinstance(node, c_ast.FuncCall):
        return _classify_call(node, config)

    base = root_identifier(node)
    if base is None:
        return UNKNOWN, render(node)
    info = variables.get(base.name)

    if isinstance(node, c_ast.StructRef):
        if info is None:
            return UNKNOWN, render(node)
        if info.is_target:
            return UNKNOWN, render(node)
        return INTERNAL, render(node)

    if info is None:
        return UNKNOWN, render(node)

    if info.is_target:
        return UNKNOWN, render(node)

    return WHOLE_COPY, render(node)


def _classify_call(node, config):
    callee = node.name
    if isinstance(callee, c_ast.ID) and callee.name in config.projection_functions:
        return FIELD_INIT, render(node)
    return UNKNOWN, render(node)

