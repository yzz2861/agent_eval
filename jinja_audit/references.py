"""AST extraction and finite evaluation of template-name expressions.

Jinja's own :func:`jinja2.meta.find_referenced_templates` flattens every
expression to either a literal name or ``None``.  That loses the distinction
between a literal candidate list and a genuinely unbounded dynamic name, so
the auditor walks the AST itself and keeps the original node around.

Only three shapes are considered knowable without rendering:

* a string constant (``"x.html"``);
* a literal list/tuple of string constants (Jinja's built-in multi-template
  include form, ``include ["a.html", "b.html"]``);
* a bare variable whose domain the host has explicitly declared
  (``candidates={template_name: {var: ["a.html", "b.html"]}}``).

Everything else -- concatenation, filters, function calls, attribute access,
conditional expressions -- is reported as ``unknown`` and turns into a hold.
"""

from __future__ import annotations

from collections.abc import Mapping

from jinja2 import Environment, nodes
from jinja2.exceptions import TemplateSyntaxError

from .models import (
    Reference,
    ReferenceKind,
    Resolution,
    ResolutionResult,
    TemplateRepository,
)

# Per-template declarations of the finite domains of template-name variables.
# Keyed by the template the reference lives in, then by variable name.
CandidateMap = Mapping[str, Mapping[str, tuple[str, ...] | list[str]]]

_REFERENCE_NODES = (nodes.Extends, nodes.Include, nodes.Import, nodes.FromImport)


def extract_references(
    template_name: str,
    source: str,
    candidates: CandidateMap | None = None,
    environment: Environment | None = None,
) -> list[Reference]:
    """Parse ``source`` without rendering and return every template edge."""
    env = environment or Environment()
    try:
        ast = env.parse(source)
    except TemplateSyntaxError as exc:
        raise TemplateParseError(template_name, exc.lineno, exc.message) from exc

    domains = (candidates or {}).get(template_name, {})
    references: list[Reference] = []
    for node in ast.find_all(_REFERENCE_NODES):
        result = resolve_expression(node.template, domains)
        references.append(
            Reference(
                source=template_name,
                kind=_kind_of(node),
                lineno=node.lineno,
                expression=render_expression(node.template),
                resolution=result.resolution,
                targets=tuple(result.values),
                ignore_missing=bool(getattr(node, "ignore_missing", False)),
                unknown_reason=result.unknown_reason,
            )
        )
    return references


class TemplateParseError(Exception):
    """Raised when a template cannot be parsed; an unparseable template cannot
    be reviewed offline and must block publication."""

    def __init__(self, template: str, lineno: int | None, message: str) -> None:
        self.template = template
        self.lineno = lineno
        super().__init__(f"{template}:{lineno or '?'}: {message}")


def _kind_of(node: nodes.Node) -> ReferenceKind:
    if isinstance(node, nodes.Extends):
        return ReferenceKind.EXTENDS
    if isinstance(node, nodes.Include):
        return ReferenceKind.INCLUDE
    if isinstance(node, nodes.FromImport):
        return ReferenceKind.FROM_IMPORT
    return ReferenceKind.IMPORT


def resolve_expression(
    node: nodes.Node,
    domains: Mapping[str, tuple[str, ...] | list[str]] | None = None,
) -> ResolutionResult:
    """Evaluate one template-name expression against declared variable domains."""
    domains = domains or {}

    if isinstance(node, nodes.Const) and isinstance(node.value, str):
        return ResolutionResult(Resolution.STATIC, (node.value,))

    if isinstance(node, (nodes.List, nodes.Tuple)):
        values: list[str] = []
        for item in node.items:
            if not isinstance(item, nodes.Const) or not isinstance(item.value, str):
                return _unknown(
                    "candidate list contains a non-constant entry; "
                    "host must bound it explicitly"
                )
            values.append(item.value)
        if not values:
            return _unknown("empty candidate list cannot name a template")
        return ResolutionResult(Resolution.CANDIDATES, tuple(values))

    if isinstance(node, nodes.Name):
        if node.name in domains:
            values = tuple(domains[node.name])
            if not values:
                return _unknown(f"declared domain for '{node.name}' is empty")
            return ResolutionResult(Resolution.CANDIDATES, values)
        return _unknown(
            f"variable '{node.name}' has no declared domain; "
            "host must suspend or declare its possible values"
        )

    return _unknown(
        f"expression of type {type(node).__name__} cannot be evaluated offline"
    )


def _unknown(reason: str) -> ResolutionResult:
    return ResolutionResult(Resolution.UNKNOWN, (), reason)


def render_expression(node: nodes.Node) -> str:
    """Best-effort, Jinja-flavoured textual form for audit output."""
    if isinstance(node, nodes.Const):
        return repr(node.value)
    if isinstance(node, nodes.Name):
        return node.name
    if isinstance(node, (nodes.List, nodes.Tuple)):
        return "[" + ", ".join(render_expression(item) for item in node.items) + "]"
    if isinstance(node, nodes.Concat):
        return " ~ ".join(render_expression(part) for part in node.nodes)
    if isinstance(node, nodes.Filter):
        args = ", ".join(render_expression(arg) for arg in node.args)
        base = render_expression(node.node)
        return f"{base}|{node.name}({args})" if args else f"{base}|{node.name}"
    if isinstance(node, nodes.Getattr):
        return f"{render_expression(node.node)}.{node.attr}"
    if isinstance(node, nodes.Getitem):
        return f"{render_expression(node.node)}[{render_expression(node.arg)}]"
    if isinstance(node, nodes.Call):
        return f"{render_expression(node.node)}(...)"
    if isinstance(node, nodes.CondExpr):
        return (
            f"{render_expression(node.expr1)} if <test> "
            f"else {render_expression(node.expr2)}"
        )
    return type(node).__name__


def closure_first_pass(
    repository: TemplateRepository,
    entry: str,
    candidates: CandidateMap | None = None,
    environment: Environment | None = None,
) -> tuple[list[Reference], list[str]]:
    """Parse the reachable graph once, returning edges and parse problems.

    Traversal is breadth-first and cycle-safe.  Templates only reachable
    through an ``unknown`` edge cannot be visited by construction; that is
    exactly the gap the host has to resolve.
    """
    seen: set[str] = set()
    pending = [entry]
    references: list[Reference] = []
    parse_errors: list[str] = []
    while pending:
        current = pending.pop(0)
        if current in seen or not repository.exists(current):
            continue
        seen.add(current)
        try:
            current_refs = extract_references(
                current, repository.get(current), candidates, environment
            )
        except TemplateParseError as exc:
            parse_errors.append(str(exc))
            continue
        references.extend(current_refs)
        for ref in current_refs:
            for target in ref.targets:
                if target not in seen:
                    pending.append(target)
    return references, parse_errors
