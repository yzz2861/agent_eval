#
# Copyright 2016 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
import ast

import testtools

from bandit.core import blacklisting
from bandit.core import context as b_context


def _call_context(source):
    node = ast.parse(source).body[0].value
    return b_context.Context(
        {
            "node": node,
            "call": node,
            "name": "eval",
            "qualname": "eval",
        }
    )


class BlacklistingTests(testtools.TestCase):
    def test_report_issue(self):
        data = {"level": "HIGH", "message": "test {name}", "id": "B000"}

        issue = blacklisting.report_issue(data, "name")
        issue_dict = issue.as_dict(with_code=False)
        self.assertIsInstance(issue_dict, dict)
        self.assertEqual("B000", issue_dict["test_id"])
        self.assertEqual("HIGH", issue_dict["issue_severity"])
        self.assertEqual({}, issue_dict["issue_cwe"])
        self.assertEqual("HIGH", issue_dict["issue_confidence"])
        self.assertEqual("test name", issue_dict["issue_text"])

    def test_report_issue_defaults(self):
        data = {"message": "test {name}"}

        issue = blacklisting.report_issue(data, "name")
        issue_dict = issue.as_dict(with_code=False)
        self.assertIsInstance(issue_dict, dict)
        self.assertEqual("LEGACY", issue_dict["test_id"])
        self.assertEqual("MEDIUM", issue_dict["issue_severity"])
        self.assertEqual({}, issue_dict["issue_cwe"])
        self.assertEqual("HIGH", issue_dict["issue_confidence"])
        self.assertEqual("test name", issue_dict["issue_text"])

    def test_exact_qualname_beats_wildcard_regardless_of_order(self):
        wildcard = {
            "id": "B900",
            "name": "wild",
            "qualnames": ["e*"],
            "message": "wild {name}",
            "level": "HIGH",
        }
        exact = {
            "id": "B307",
            "name": "eval",
            "qualnames": ["eval"],
            "message": "exact {name}",
            "level": "MEDIUM",
        }
        context = _call_context('eval("x")')

        for checks in ((wildcard, exact), (exact, wildcard)):
            found = blacklisting.blacklist(context, {"Call": list(checks)})
            self.assertEqual("B307", found.test_id)
            self.assertEqual("MEDIUM", found.severity)

    def test_wildcard_qualname_matches_call(self):
        check = {
            "id": "B901",
            "name": "wild",
            "qualnames": ["eval.*"],
            "message": "wild {name}",
            "level": "HIGH",
        }
        node = ast.parse('eval.danger("x")').body[0].value
        context = b_context.Context(
            {
                "node": node,
                "call": node,
                "name": "danger",
                "qualname": "eval.danger",
            }
        )
        found = blacklisting.blacklist(context, {"Call": [check]})
        self.assertEqual("B901", found.test_id)
