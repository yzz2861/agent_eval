"""Static analyzer that flags internal-structure leakage at reporting exits.

The check is built purely on pycparser's AST: no compilation or preprocessing
is required, so the snippets under audit may rely on types that are only
forward-declared inside the translation unit.

Three construction styles are distinguished, matching the review brief:

* field-by-field initialization / assignment -- traced per field so that a
  field rewritten with a safe constant is not confused with one copied from
  the internal structure;
* whole-structure copies (``pub = *internal``, ``memcpy`` ...) -- reported as
  unsafe, with the real right-hand source rendered into the finding;
* known projection functions -- trusted by name from the configuration and
  treated as safe sanitizers.

Indirect calls whose callee cannot be bound to a declared function are kept
as REVIEW findings instead of being guessed at.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from pycparser import c_ast
from pycparser.c_generator import CGenerator


_generator = CGenerator()

def render(node: c_ast.Node | None) -> str:
    """Render an AST expression back to compact C source."""
    if node is None:
        return "<none>"
    return _generator.visit(node).strip()


def root_identifier(node: c_ast.Node) -> c_ast.ID | None:
    """Return the innermost base identifier of an lvalue expression."""
    if isinstance(node, c_ast.ID):
        return node
    if isinstance(node, c_ast.StructRef):
        return root_identifier(node.name)
    if isinstance(node, c_ast.UnaryOp):
        return root_identifier(node.expr)
    if isinstance(node, c_ast.ArrayRef):
        return root_identifier(node.name)
    if isinstance(node, c_ast.Cast):
        return root_identifier(node.expr)
    return None


def struct_name_of(decl_type: c_ast.Node) -> str | None:
    """Extract a struct tag from a declarator chain, if any."""
    node = decl_type
    while isinstance(node, (c_ast.PtrDecl, c_ast.ArrayDecl)):
        node = node.type
    if isinstance(node, c_ast.TypeDecl) and isinstance(node.type, c_ast.Struct):
        return node.type.name
    return None



@dataclass
class AuditConfig:
    """Knobs that pin the audit to a concrete structure and reporting exit."""

    public_struct: str
    report_functions: tuple[str, ...]
    projection_functions: tuple[str, ...] = ()
    copy_functions: tuple[str, ...] = ("memcpy", "memmove")


@dataclass
class _VarInfo:
    """What we know about one local variable of the audited function."""

    name: str
    struct_name: str | None            # resolved struct tag, or None
    is_pointer: bool
    is_target: bool                    # an instance/pointer of the public struct
    param: bool = False
    # Per-field provenance: field name -> category + rendered source.
    fields: dict[str, tuple[str, str]] = field(default_factory=dict)
    # Whole-object provenance once a whole-struct write happened.
    whole: tuple[str, str] | None = None

