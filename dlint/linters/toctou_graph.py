#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast
import sys


EDGE_BRANCH = "branch"
EDGE_EXCEPTION = "exception"
EDGE_LOOP = "loop-back-edge"
EDGE_SEQUENTIAL = "sequential"


class FlowGraph(object):
    """Statement-level intra-procedural control-flow graph.

    Nodes are AST statement nodes. Edges are tuples of
    ``(source, target, tag)`` where ``tag`` is one of the ``EDGE_*``
    constants. Nested function and class definitions are kept opaque because
    their bodies are independent scopes analyzed separately by the linter.
    """

    def __init__(self):
        self.entry = None
        self.successors = {}
        self.edges = []

    def add_edge(self, source, target, tag=EDGE_SEQUENTIAL):
        if target is None:
            return
        if source is None:
            self.entry = target
            return
        targets = self.successors.setdefault(id(source), [])
        if (id(target), tag) not in [(id(t), tg) for t, tg in targets]:
            targets.append((target, tag))
            self.edges.append((source, target, tag))

    def outgoing(self, node):
        return self.successors.get(id(node), [])


def _is_scope_node(node):
    scopes = (ast.ClassDef, ast.FunctionDef)
    if sys.version_info >= (3, 5):
        scopes += (ast.AsyncFunctionDef,)
    return isinstance(node, scopes)


def build_flow_graph(body):
    """Build a FlowGraph for a statement list such as a function body.

    Returns ``(graph, exit_nodes)`` where ``exit_nodes`` are statements that
    can fall through the end of the body.
    """
    graph = FlowGraph()
    exit_nodes = _build_sequence(graph, None, body)
    if graph.entry is None and body:
        graph.entry = body[0]
    return graph, exit_nodes


def _connect_all(graph, exits, target, tag):
    for exit_node in exits:
        graph.add_edge(exit_node, target, tag)


def _build_sequence(graph, predecessor, statements, add_entry_edge=True):
    current = predecessor
    exits = [predecessor] if predecessor is not None else []
    for statement in statements:
        exits = _build_statement(
            graph, current, statement, add_entry_edge=add_entry_edge
        )
        current = exits[0] if exits else None
        add_entry_edge = True
    if not statements:
        return [predecessor] if predecessor is not None else []
    return exits


def _build_statement(graph, predecessor, node, add_entry_edge=True):
    if add_entry_edge and predecessor is not None:
        graph.add_edge(predecessor, node)

    if _is_scope_node(node):
        return [node]

    if isinstance(node, ast.If):
        return _build_if(graph, node)
    if isinstance(node, (ast.While, ast.For)):
        return _build_loop(graph, node)
    if isinstance(node, ast.Try):
        return _build_try(graph, node)
    if isinstance(node, ast.With):
        return _build_with(graph, node)
    if isinstance(node, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
        return []

    return [node]


def _build_if(graph, node):
    exits = []
    if node.body:
        exits.extend(
            _build_sequence(graph, node, node.body, add_entry_edge=False)
        )
    else:
        exits.append(node)
    if node.orelse:
        exits.extend(
            _build_sequence(graph, node, node.orelse, add_entry_edge=False)
        )
    else:
        exits.append(node)
    for target in [s for s in node.body[:1]] + [s for s in node.orelse[:1]]:
        graph.add_edge(node, target, EDGE_BRANCH)
    return exits


def _build_loop(graph, node):
    body_first = node.body[0] if node.body else None
    graph.add_edge(node, body_first, EDGE_BRANCH)

    body_exits = _build_sequence(
        graph, node, node.body, add_entry_edge=False
    )
    _connect_all(graph, body_exits, body_first, EDGE_LOOP)

    if node.orelse:
        return _build_sequence(graph, node, node.orelse, add_entry_edge=False)
    return [node]


def _build_try(graph, node):
    body_first = node.body[0] if node.body else None
    graph.add_edge(node, body_first, EDGE_SEQUENTIAL)
    body_exits = _build_sequence(
        graph, node, node.body, add_entry_edge=False
    )

    exits = list(body_exits)
    for handler in node.handlers:
        handler_first = handler.body[0] if handler.body else None
        graph.add_edge(node, handler_first, EDGE_EXCEPTION)
        exits.extend(_build_sequence(
            graph, node, handler.body, add_entry_edge=False
        ))

    if node.orelse:
        exits.extend(_build_sequence(
            graph, body_first or node, node.orelse, add_entry_edge=False
        ))
    if node.finalbody:
        final_first = node.finalbody[0]
        for exit_node in list(exits) or [node]:
            graph.add_edge(exit_node, final_first, EDGE_EXCEPTION)
        exits = _build_sequence(
            graph, final_first, node.finalbody[1:], add_entry_edge=False
        )
    return exits


def _build_with(graph, node):
    if not node.body:
        return [node]
    return _build_sequence(graph, node, node.body, add_entry_edge=False)
