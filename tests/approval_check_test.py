"""Tests for the approval check built on pefile's static import data."""

import unittest

import pefile

import approval_check as ac
from demo_approval import (
    AGENT_PE,
    FAKE_SYMBOL_DIRECTORY,
    PURPOSE_A,
    PURPOSE_B,
    VIEWER_PE,
)


def evaluate(data, policy):
    pe = pefile.PE(data=data)
    try:
        return ac.evaluate(pe, policy, symbol_directory=FAKE_SYMBOL_DIRECTORY)
    finally:
        pe.close()


def by_dll(findings):
    return {f.dependency.dll: f for f in findings}


class ApprovalCheckTest(unittest.TestCase):
    def test_viewer_fully_approved_under_purpose_a(self):
        findings, review_view = evaluate(VIEWER_PE, PURPOSE_A)
        classified = by_dll(findings)
        self.assertEqual(classified["core.dll"].classification, ac.REQUIRED)
        self.assertEqual(classified["legacy.dll"].classification, ac.REQUIRED)
        self.assertEqual(
            classified["plugin.dll"].classification, ac.RUNTIME_OPTIONAL
        )
        self.assertEqual(review_view, [])

    def test_same_dependencies_rejected_under_purpose_b(self):
        findings, review_view = evaluate(VIEWER_PE, PURPOSE_B)
        classified = by_dll(findings)
        self.assertEqual(classified["core.dll"].classification, ac.REQUIRED)
        self.assertEqual(classified["legacy.dll"].classification, ac.UNEXPLAINED)
        self.assertEqual(classified["plugin.dll"].classification, ac.UNEXPLAINED)
        self.assertEqual(
            {f.dependency.dll for f in review_view}, {"legacy.dll", "plugin.dll"}
        )

    def test_ordinal_identity_resolved_by_symbol_directory(self):
        findings, _ = evaluate(VIEWER_PE, PURPOSE_A)
        legacy = by_dll(findings)["legacy.dll"].dependency
        self.assertEqual(legacy.symbols[0].name, "LegacyInit")
        self.assertEqual(legacy.symbols[0].resolved_by, "symbol-directory")

    def test_unknown_ordinal_floats_to_review_view(self):
        for policy in (PURPOSE_A, PURPOSE_B):
            findings, review_view = evaluate(AGENT_PE, policy)
            legacy = by_dll(findings)["legacy.dll"]
            self.assertEqual(legacy.classification, ac.IDENTITY_INCOMPLETE)
            self.assertIn(legacy, review_view)


if __name__ == "__main__":
    unittest.main()
