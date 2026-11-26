"""Tests for the local security budget adaptation layer."""
from __future__ import print_function

import io
import unittest

from defusedxml import ElementTree
from defusedxml.budget import (
    BudgetExceeded,
    BudgetState,
    BudgetStateError,
    SecurityBudget,
)


NORMAL_XML = b"<root><a>one</a><b>two</b></root>"
FIRST_ELEMENT = b"<root><a>one</a>"
TAIL_ELEMENTS = b"<b>two</b></root>"


class SecurityBudgetTest(unittest.TestCase):
    def test_validation(self):
        with self.assertRaises(ValueError):
            SecurityBudget(-1)
        with self.assertRaises(TypeError):
            SecurityBudget(1.5)
        with self.assertRaises(TypeError):
            SecurityBudget(True)

    def test_terminal_ledger_cannot_be_reused(self):
        budget = SecurityBudget(len(NORMAL_XML))
        ElementTree.fromstring_budget(NORMAL_XML, budget)
        self.assertTrue(budget.is_complete)
        with self.assertRaises(BudgetStateError):
            budget.charge(1)


class BudgetedElementTreeTest(unittest.TestCase):
    def test_cutoff_lands_exactly_on_element_boundary(self):
        # The approved quota is exhausted precisely after the first complete
        # element. Its end event must still be observable and the ledger stays
        # active until the next chunk crosses the limit.
        budget = SecurityBudget(len(FIRST_ELEMENT))
        parser = ElementTree.BudgetedPullParser(budget, events=("start", "end"))
        parser.feed(FIRST_ELEMENT)

        events = parser.drain_events()
        tags = [elem.tag for event, elem in events if event == "end"]
        self.assertEqual(tags, ["a"])
        self.assertEqual(budget.consumed, len(FIRST_ELEMENT))
        self.assertEqual(budget.remaining, 0)
        self.assertTrue(budget.is_active)

        with self.assertRaises(BudgetExceeded):
            parser.feed(TAIL_ELEMENTS)
        self.assertTrue(budget.is_exceeded)
        # The boundary element remains available even after the budget trips.
        self.assertEqual(tags, ["a"])

    def test_full_tree_cutoff_on_element_boundary(self):
        # The full-tree adapter shares the exact same quota semantics.
        budget = SecurityBudget(len(FIRST_ELEMENT))
        parser = ElementTree.BudgetedXMLParser(budget)
        parser.feed(FIRST_ELEMENT)
        self.assertEqual(budget.consumed, len(FIRST_ELEMENT))
        self.assertTrue(budget.is_active)

        with self.assertRaises(BudgetExceeded):
            parser.feed(TAIL_ELEMENTS)
        self.assertTrue(budget.is_exceeded)

    def test_caller_closes_before_end_of_stream(self):
        budget = SecurityBudget(4096)
        parser = ElementTree.BudgetedPullParser(budget, events=("end",))
        parser.feed(FIRST_ELEMENT)
        parser.drain_events()

        parser.cancel()
        self.assertTrue(budget.is_cancelled)
        self.assertFalse(budget.accepted)
        self.assertEqual(budget.state, BudgetState.CANCELLED)

        # Cancellation is idempotent and the partial consumption is retained.
        parser.cancel()
        self.assertEqual(budget.consumed, len(FIRST_ELEMENT))

    def test_context_manager_records_cancellation_on_error(self):
        budget = SecurityBudget(4096)
        with self.assertRaises(ElementTree.ParseError):
            with ElementTree.BudgetedXMLParser(budget) as parser:
                parser.feed(b"<root>")
                parser.feed(b"<broken>")
                parser.close()
        self.assertTrue(budget.is_cancelled)

    def test_successful_parse_completes_budget(self):
        budget = SecurityBudget(4096)
        root = ElementTree.fromstring_budget(NORMAL_XML, budget)

        self.assertEqual(root.tag, "root")
        self.assertEqual([child.tag for child in root], ["a", "b"])
        self.assertEqual(budget.consumed, len(NORMAL_XML))
        self.assertEqual(budget.remaining, 4096 - len(NORMAL_XML))
        self.assertTrue(budget.is_complete)
        self.assertTrue(budget.accepted)
        self.assertEqual(budget.state, BudgetState.COMPLETED)

    def test_incremental_successful_parse(self):
        budget = SecurityBudget(4096)
        with ElementTree.BudgetedPullParser(budget, events=("end",)) as parser:
            parser.feed(b"<root>")
            parser.feed(b"<a>one</a>")
            parser.feed(b"<b>two</b></root>")
            events = parser.drain_events()
        self.assertEqual([elem.tag for _, elem in events], ["a", "b", "root"])
        self.assertTrue(budget.is_complete)

    def test_iterparse_cancel_and_complete_share_ledger(self):
        document = io.BytesIO(NORMAL_XML)
        budget = SecurityBudget(4096)
        iterator = ElementTree.budgeted_iterparse(
            document, budget, events=("end",), chunk_size=len(FIRST_ELEMENT)
        )
        first_event = next(iterator)
        self.assertEqual(first_event[1].tag, "a")

        # Abandoning the iterator after consuming only half the document is a
        # cancellation, never a pass.
        iterator.close()
        self.assertTrue(budget.is_cancelled)
        self.assertEqual(budget.consumed, len(FIRST_ELEMENT))

        # A fresh ledger with the same approved quota lets the document finish.
        document = io.BytesIO(NORMAL_XML)
        budget = SecurityBudget(4096)
        events = list(
            ElementTree.budgeted_iterparse(
                document, budget, events=("end",), chunk_size=len(FIRST_ELEMENT)
            )
        )
        self.assertEqual([elem.tag for _, elem in events], ["a", "b", "root"])
        self.assertTrue(budget.is_complete)
        self.assertEqual(budget.consumed, len(NORMAL_XML))

    def test_both_interfaces_honor_same_approved_limit(self):
        small_limit = len(FIRST_ELEMENT)

        streaming = SecurityBudget(small_limit)
        stream_parser = ElementTree.BudgetedPullParser(streaming)
        stream_parser.feed(FIRST_ELEMENT)

        tree_parser = ElementTree.BudgetedXMLParser(SecurityBudget(small_limit))
        tree_parser.feed(FIRST_ELEMENT)

        self.assertEqual(streaming.limit, tree_parser.budget.limit)
        self.assertEqual(streaming.consumed, tree_parser.budget.consumed)
        self.assertTrue(streaming.is_active)
        self.assertTrue(tree_parser.budget.is_active)

        with self.assertRaises(BudgetExceeded):
            stream_parser.feed(TAIL_ELEMENTS)
        with self.assertRaises(BudgetExceeded):
            tree_parser.feed(TAIL_ELEMENTS)

    def test_legacy_entry_points_keep_exception_semantics(self):
        # Existing online entry points remain usable without a budget and keep
        # raising the standard ParseError for malformed documents.
        root = ElementTree.fromstring(NORMAL_XML)
        self.assertEqual(root.tag, "root")
        with self.assertRaises(ElementTree.ParseError):
            ElementTree.fromstring("not xml")
        with self.assertRaises(ElementTree.ParseError):
            list(ElementTree.iterparse(io.BytesIO(b"not xml")))


if __name__ == "__main__":
    unittest.main()
