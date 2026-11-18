#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast
import textwrap

import dlint
from dlint.flow import cfg


def _graph(source):
    function = ast.parse(textwrap.dedent(source)).body[0]
    return cfg.build_cfg(function.body)


def _edge_kinds(graph):
    return sorted(edge.kind for edge in graph.edges)


class TestCFG(dlint.test.base.BaseTest):

    def test_linear_sequence_fall_through(self):
        graph = _graph(
            """
            def f():
                a = 1
                b = 2
            """
        )
        self.assertEqual(1, len(graph.blocks))
        self.assertEqual([], _edge_kinds(graph))

    def test_if_has_two_branches(self):
        graph = _graph(
            """
            def f(p):
                if p:
                    a = 1
                else:
                    a = 2
            """
        )
        branch_edges = [e for e in graph.edges if e.kind == cfg.BRANCH]
        self.assertEqual(2, len(branch_edges))
        self.assertEqual(
            {True, False}, {edge.label for edge in branch_edges}
        )

    def test_break_and_continue_resolve_to_loop(self):
        graph = _graph(
            """
            def f(items):
                for item in items:
                    if item:
                        continue
                    if not item:
                        break
            """
        )
        terminals = [b for b in graph.blocks if b.terminal is not None]
        self.assertEqual([], terminals)

    def test_loop_else_is_distinct(self):
        graph = _graph(
            """
            def f(items):
                for item in items:
                    pass
                else:
                    pass
            """
        )
        self.assertTrue(any(b.statements == [] for b in graph.blocks))

    def test_try_adds_exception_edges_only_for_raising_blocks(self):
        graph = _graph(
            """
            def f():
                try:
                    risky()
                except ValueError:
                    pass
            """
        )
        except_edges = [e for e in graph.edges if e.kind == cfg.EXCEPTION]
        self.assertTrue(except_edges)
        self.assertTrue(all(e.lineno is not None for e in except_edges))

    def test_pure_assignment_has_no_exception_edge(self):
        graph = _graph(
            """
            def f():
                try:
                    a = 1
                except ValueError:
                    pass
            """
        )
        self.assertEqual(
            [], [e for e in graph.edges if e.kind == cfg.EXCEPTION]
        )

    def test_finally_runs_for_return(self):
        graph = _graph(
            """
            def f():
                try:
                    return 1
                finally:
                    cleanup()
            """
        )
        finally_edges = [e for e in graph.edges if e.kind == cfg.FINALLY]
        self.assertTrue(finally_edges)
        returns = [
            block for block in graph.blocks
            if block.terminal == cfg.TERMINAL_RETURN
        ]
        self.assertTrue(returns)

    def test_every_block_is_reachable_from_entry(self):
        graph = _graph(
            """
            def f(p):
                if p:
                    for item in p:
                        try:
                            risky(item)
                        except ValueError:
                            continue
                        finally:
                            cleanup()
                else:
                    return
            """
        )
        seen = set()
        queue = [graph.entry]
        while queue:
            block = queue.pop()
            if block.id in seen:
                continue
            seen.add(block.id)
            queue.extend(edge.target for edge in block.successors)
        self.assertEqual(seen, {block.id for block in graph.blocks})


if __name__ == "__main__":
    import unittest
    unittest.main()
