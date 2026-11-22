"""Renderers turning a program IR into Python source.

Two styles are provided:

* ``render_canonical`` -- stable, minimal formatting.
* ``render_rewrite`` -- an equivalent rewrite: consistent variable
  renames, reordered independent statements, alternate import style,
  alternate subprocess entry points, flipped quotes and extra blank
  lines.  None of these change the contract state, so the expected
  conclusions are identical; only source locations move.

Both renderers return the source plus a map from contract id to the
1-based line where that statement landed, so expectations and findings
can be attributed back to contracts.
"""

import random
from dataclasses import dataclass

from tests.functional.gencontracts import model

_SINK_FUNCS = ("Popen", "run", "call")


@dataclass(frozen=True)
class Rendered:
    source: str
    stmt_lines: dict  # contract id -> 1-based line number


class _Style:
    def __init__(
        self,
        quote="'",
        from_imports=False,
        renames=None,
        sink_funcs=None,
        reorder=False,
        blank_lines=False,
        rng=None,
    ):
        self.quote = quote
        self.from_imports = from_imports
        self.renames = renames or {}
        self.sink_funcs = sink_funcs or {}
        self.reorder = reorder
        self.blank_lines = blank_lines
        self.rng = rng


def _render_expr(expr, style):
    if isinstance(expr, model.Lit):
        return style.quote + expr.text + style.quote
    if isinstance(expr, model.Var):
        return style.renames.get(expr.name, expr.name)
    if isinstance(expr, model.Move):
        inner = _render_expr(expr.arg, style)
        if expr.op == model.MOVE_STR:
            return "str(%s)" % inner
        if expr.op == model.MOVE_COPY:
            if style.from_imports:
                return "copy(%s)" % inner
            return "copy.copy(%s)" % inner
        if expr.op == model.MOVE_DICT_GET:
            key = style.quote + "k" + style.quote
            return "{%s: %s}.get(%s)" % (key, inner, key)
        if expr.op == model.MOVE_TUPLE:
            return "(%s,)[0]" % inner
    raise ValueError("unknown expression: %r" % (expr,))


def _render_stmt(stmt, style):
    if isinstance(stmt, model.Bind):
        name = style.renames.get(stmt.name, stmt.name)
        return "%s = %s" % (name, _render_expr(stmt.expr, style))
    if isinstance(stmt, model.ShellSink):
        func = style.sink_funcs.get(stmt.cid, "subprocess.Popen")
        shell = "True" if stmt.shell else "False"
        return "%s(%s, shell=%s)" % (
            func,
            _render_expr(stmt.cmd, style),
            shell,
        )
    if isinstance(stmt, model.ConnectSink):
        return "client.connect(%s=%s)" % (
            stmt.keyword,
            _render_expr(stmt.value, style),
        )
    raise ValueError("unknown statement: %r" % (stmt,))


def _ordered(body, style):
    if not style.reorder:
        return list(body)
    rng = style.rng
    remaining = list(body)
    placed_defs = set()
    order = []
    while remaining:
        ready = [
            stmt
            for stmt in remaining
            if model.stmt_uses(stmt) <= placed_defs
        ]
        chosen = rng.choice(ready)
        remaining.remove(chosen)
        placed_defs |= model.stmt_defs(chosen)
        order.append(chosen)
    return order


def _render(program, style):
    lines = []
    stmt_lines = {}
    if style.from_imports:
        lines.append("from subprocess import Popen, call, run")
        lines.append("from copy import copy")
    else:
        lines.append("import subprocess")
        lines.append("import copy")
    for scope in program.scopes:
        lines.append("")
        if scope.name:
            lines.append("def %s():" % scope.name)
            indent = "    "
            if not scope.body:
                lines.append(indent + "pass")
        else:
            indent = ""
        for stmt in _ordered(scope.body, style):
            stmt_lines[stmt.cid] = len(lines) + 1
            lines.append(indent + _render_stmt(stmt, style))
            if (
                style.blank_lines
                and style.rng is not None
                and style.rng.random() < 0.3
            ):
                lines.append("")
    return Rendered("\n".join(lines) + "\n", stmt_lines)


def render_canonical(program):
    return _render(program, _Style())


def render_rewrite(program, seed):
    """Render an equivalent rewrite; ``seed`` makes it deterministic."""
    rng = random.Random(seed)
    renames = {}
    for _, stmt in model.iter_statements(program):
        if isinstance(stmt, model.Bind):
            renames[stmt.name] = "data_%d" % len(renames)
    from_imports = rng.random() < 0.5
    sink_funcs = {}
    for _, stmt in model.iter_statements(program):
        if isinstance(stmt, model.ShellSink):
            func = rng.choice(_SINK_FUNCS)
            if not from_imports:
                func = "subprocess." + func
            sink_funcs[stmt.cid] = func
    style = _Style(
        quote='"',
        from_imports=from_imports,
        renames=renames,
        sink_funcs=sink_funcs,
        reorder=True,
        blank_lines=True,
        rng=rng,
    )
    return _render(program, style)
