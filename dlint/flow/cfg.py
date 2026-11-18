#!/usr/bin/env python

"""A small, dependency-free intra-procedural control flow graph.

The graph is intentionally statement oriented: each :class:`BasicBlock` holds
a sequence of AST statements that execute unconditionally one after another,
and :class:`Edge` objects describe the control transfers between blocks.

Four edge kinds are distinguished so downstream path analysis can reason about
*why* control moved:

- ``fall``    : normal sequencing / fall-through
- ``branch``  : an ``if`` test selected this successor
- ``except``  : an exception raised inside a ``try`` was caught by a handler
- ``finally`` : control entered a ``finally`` block after an abrupt exit

``return``, ``raise``, ``break`` and ``continue`` become terminal blocks whose
outcomes are resolved when the enclosing construct finishes, which keeps loop
``else`` clauses and ``finally`` semantics explicit.
"""

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast


FALL = 'fall'
BRANCH = 'branch'
EXCEPTION = 'except'
FINALLY = 'finally'

TERMINAL_RETURN = 'return'
TERMINAL_RAISE = 'raise'
TERMINAL_BREAK = 'break'
TERMINAL_CONTINUE = 'continue'


class BasicBlock(object):
    """A basic block: ordered statements with a stable identity."""

    def __init__(self, block_id):
        self.id = block_id
        self.statements = []
        self.successors = []
        self.predecessors = []
        self.terminal = None
        # True when some statement in this block can raise, e.g. it contains
        # a function call. Used to add conservative exception edges.
        self.raises = False

    def append(self, statement):
        self.statements.append(statement)

    @property
    def lineno(self):
        if self.statements:
            return self.statements[0].lineno
        return None

    def __repr__(self):
        return 'BasicBlock({})'.format(self.id)


class Edge(object):
    """A directed control transfer between two blocks."""

    def __init__(self, source, target, kind=FALL, label=None, lineno=None):
        self.source = source
        self.target = target
        self.kind = kind
        # branch edges: True / False. except edges: handler index.
        self.label = label
        self.lineno = lineno

    def __repr__(self):
        return 'Edge({} -> {}, {})'.format(
            self.source.id, self.target.id, self.kind
        )


class ControlFlowGraph(object):
    """A completed control flow graph for a single scope."""

    def __init__(self, entry, blocks, edges):
        self.entry = entry
        self.blocks = blocks
        self.edges = edges

    def successors(self, block):
        return [(edge.target, edge) for edge in block.successors]


def _statement_can_raise(statement):
    """Conservative check: any embedded call may raise. A bare ``raise`` is
    represented by its terminal block rather than this flag."""
    for node in ast.walk(statement):
        if isinstance(node, ast.Call):
            return True
    return False


class _CFGBuilder(object):
    def __init__(self):
        self._next_id = 0
        self.blocks = []
        self.edges = []

    def new_block(self):
        block = BasicBlock(self._next_id)
        self._next_id += 1
        self.blocks.append(block)
        return block

    def link(self, source, target, kind=FALL, label=None, lineno=None):
        edge = Edge(source, target, kind=kind, label=label, lineno=lineno)
        source.successors.append(edge)
        target.predecessors.append(edge)
        self.edges.append(edge)

    def build(self, body):
        entry = self.new_block()
        self._statements(body, entry)
        return ControlFlowGraph(entry, self.blocks, self.edges)

    def _statements(self, statements, entry):
        # Build a statement list, returning the reachable frontier blocks.
        # A block with terminal set never falls through to later statements.
        # Each statement boundary is joined through a fresh merge block so
        # nested branches converge instead of duplicating the remaining
        # program on every path (which would otherwise be exponential).
        frontier = [entry]
        for statement in statements:
            reachable = [b for b in frontier if b.terminal is None]
            if not reachable:
                break

            produced = []
            for block in reachable:
                produced.extend(self._statement(statement, block))

            live = [b for b in produced if b.terminal is None]
            next_frontier = []
            if len(self._dedupe(live)) > 1:
                merge = self.new_block()
                for block in self._dedupe(live):
                    self.link(block, merge, FALL)
                next_frontier.append(merge)
            else:
                next_frontier.extend(self._dedupe(live))
            next_frontier.extend(
                b for b in self._dedupe(produced) if b.terminal is not None
            )
            frontier = self._dedupe(next_frontier)
        return self._dedupe(frontier)

    @staticmethod
    def _dedupe(blocks):
        seen = set()
        unique = []
        for block in blocks:
            if block.id not in seen:
                seen.add(block.id)
                unique.append(block)
        return unique

    def _statement(self, statement, entry):
        builder = getattr(
            self, 'build_' + type(statement).__name__, self._simple
        )
        return builder(statement, entry)

    def _simple(self, statement, entry):
        entry.append(statement)
        entry.raises = entry.raises or _statement_can_raise(statement)
        return [entry]

    def build_If(self, statement, entry):
        entry.append(statement)
        entry.raises = entry.raises or _statement_can_raise(statement.test)

        true_entry = self.new_block()
        false_entry = self.new_block()
        self.link(entry, true_entry, BRANCH, label=True,
                  lineno=statement.lineno)
        self.link(entry, false_entry, BRANCH, label=False,
                  lineno=statement.lineno)

        true_exits = self._statements(statement.body, true_entry)
        if statement.orelse:
            false_exits = self._statements(statement.orelse, false_entry)
        else:
            false_exits = [false_entry]
        return true_exits + false_exits

    def build_While(self, statement, entry):
        return self._loop(statement, entry)

    def build_For(self, statement, entry):
        return self._loop(statement, entry)

    def _loop(self, statement, entry):
        entry.append(statement)

        body_entry = self.new_block()
        else_entry = self.new_block()
        after_loop = self.new_block()

        # Condition/iteration selects the body, or leaves the loop.
        self.link(entry, body_entry, BRANCH, label=True,
                  lineno=statement.lineno)
        self.link(entry, else_entry, BRANCH, label=False,
                  lineno=statement.lineno)

        body_exits = self._statements(statement.body, body_entry)

        # Terminals may be nested behind merge blocks, so resolve them by
        # scanning every block reachable from the loop body.
        body_blocks = self._reachable(body_entry)
        normal_exits = []
        for block in body_exits:
            if block.terminal is None:
                normal_exits.append(block)

        for block in body_blocks:
            if block.terminal == TERMINAL_CONTINUE:
                block.terminal = None
                self.link(block, entry, FALL)
            elif block.terminal == TERMINAL_BREAK:
                block.terminal = None
                self.link(block, after_loop, FALL)

        # Normal end of body / implicit continue re-run the header.
        for block in self._dedupe(normal_exits):
            self.link(block, entry, FALL)

        if statement.orelse:
            else_exits = self._statements(statement.orelse, else_entry)
        else:
            # Empty else block falls straight through.
            else_exits = [else_entry]

        for block in else_exits:
            if block.terminal is None:
                self.link(block, after_loop, FALL)

        return [after_loop]

    def build_Break(self, statement, entry):
        entry.append(statement)
        entry.terminal = TERMINAL_BREAK
        return [entry]

    def build_Continue(self, statement, entry):
        entry.append(statement)
        entry.terminal = TERMINAL_CONTINUE
        return [entry]

    def build_Return(self, statement, entry):
        entry.append(statement)
        entry.terminal = TERMINAL_RETURN
        return [entry]

    def build_Raise(self, statement, entry):
        entry.append(statement)
        entry.terminal = TERMINAL_RAISE
        return [entry]

    def build_Try(self, statement, entry):
        entry.append(statement)

        try_entry = self.new_block()
        self.link(entry, try_entry, FALL)
        try_exits = self._statements(statement.body, try_entry)

        handler_entries = []
        handler_exits = []
        for handler in statement.handlers:
            handler_block = self.new_block()
            handler_entries.append(handler_block)
            handler_exits.extend(
                self._statements(handler.body, handler_block)
            )

        # Conservative exception edges: every raising try block can transfer
        # to any handler. Only raising blocks get edges, so a try with no
        # calls introduces no spurious bypass.
        raising_blocks = [
            block for block in self._reachable(try_entry) if block.raises
        ]
        for block in raising_blocks:
            for index, handler_block in enumerate(handler_entries):
                self.link(block, handler_block, EXCEPTION,
                          label=index, lineno=block.lineno)

        if statement.orelse:
            else_entry = self.new_block()
            for block in try_exits:
                self.link(block, else_entry, FALL)
            normal_exits = self._statements(statement.orelse, else_entry)
        else:
            normal_exits = list(try_exits)

        normal_exits = self._dedupe(normal_exits + handler_exits)

        if not statement.finalbody:
            return normal_exits

        # Every exit - normal completion, caught exceptions and abrupt
        # terminals (return/raise/break/continue) - runs the finally body.
        finally_entry = self.new_block()
        abrupt_exits = []
        for block in normal_exits:
            if block.terminal is None:
                self.link(block, finally_entry, FINALLY,
                          lineno=statement.lineno)
            else:
                abrupt_exits.append(block)
        # An uncaught raise inside the try also passes through finally.
        if not statement.handlers:
            for block in raising_blocks:
                if block.terminal == TERMINAL_RAISE:
                    abrupt_exits.append(block)
        abrupt_exits = self._dedupe(abrupt_exits)
        for block in abrupt_exits:
            self.link(block, finally_entry, FINALLY,
                      lineno=statement.lineno)

        finally_exits = self._statements(
            statement.finalbody, finally_entry
        )

        # If finally does not terminate itself, pending abrupt actions resume.
        results = [block for block in finally_exits if block.terminal is None]
        for block in abrupt_exits:
            pending = self.new_block()
            pending.terminal = block.terminal
            pending.statements = list(block.statements[-1:])
            for block in finally_exits:
                if block.terminal is None:
                    self.link(block, pending, FINALLY,
                              lineno=statement.lineno)
            results.append(pending)
        return self._dedupe(results)

    def build_With(self, statement, entry):
        entry.append(statement)
        entry.raises = True
        body_entry = self.new_block()
        self.link(entry, body_entry, FALL)
        return self._statements(statement.body, body_entry)

    def build_FunctionDef(self, statement, entry):
        # Nested scopes are analyzed independently and are opaque here.
        return self._simple(statement, entry)

    build_AsyncFunctionDef = build_FunctionDef
    build_ClassDef = build_FunctionDef

    def _reachable(self, entry):
        seen = set()
        queue = [entry]
        while queue:
            block = queue.pop()
            if block.id in seen:
                continue
            seen.add(block.id)
            for edge in block.successors:
                queue.append(edge.target)
        return [block for block in self.blocks if block.id in seen]


def build_cfg(statements):
    """Build a :class:`ControlFlowGraph` from a list of AST statements.

    Pass ``function_node.body`` or ``module_node.body``.
    """
    builder = _CFGBuilder()
    return builder.build(statements)


# marker
