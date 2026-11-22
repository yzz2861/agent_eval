import unittest

from dlint import scope


class TestScopeAudit(unittest.TestCase):
    def test_version_normalization(self):
        self.assertEqual(scope.normalize_version("py38"), (3, 8))
        self.assertEqual(scope.normalize_version(38), (3, 8))
        self.assertEqual(scope.normalize_version("python 3.8"), (3, 8))
        self.assertEqual(scope.normalize_version((2, 7)), (2, 7))

    def test_modern_syntax_gates(self):
        fstring = "x = f" + chr(34) + "{1}" + chr(34) + "\n"
        walrus = "if (x := 1):\n    pass\n"
        async_source = "async def f():\n    await g()\n"
        self.assertFalse(scope.syntax_supported(fstring, "2.7"))
        self.assertFalse(scope.syntax_supported(fstring, "3.5"))
        self.assertTrue(scope.syntax_supported(fstring, "3.6"))
        self.assertFalse(scope.syntax_supported(walrus, "3.7"))
        self.assertTrue(scope.syntax_supported(walrus, "3.8"))
        self.assertFalse(scope.syntax_supported(async_source, "3.4"))
        self.assertTrue(scope.syntax_supported(async_source, "3.5"))

    def test_python2_only_syntax(self):
        self.assertTrue(scope.syntax_supported("print 1\n", "2.7"))
        self.assertFalse(scope.syntax_supported("print 1\n", "3.8"))
        self.assertTrue(scope.syntax_supported("exec \"x\"\n", "2.7"))
        self.assertFalse(scope.syntax_supported("exec \"x\"\n", "3.8"))

    def test_audit_separates_statuses(self):
        source = "value = input(\"x\")\n"
        report = [{
            "filename": "app.py",
            "lineno": 1,
            "code": "DUO108",
            "message": "DUO108 use of input is insecure",
        }]
        result = scope.audit_scope(
            {"app.py": source},
            report,
            versions=["2.7", "3.8"],
            rules=["DUO108", "DUO101"],
        )
        old = result["2.7"]
        new = result["3.8"]
        self.assertEqual([e.status for e in old.eligible], ["eligible"])
        self.assertEqual(old.eligible[0].code, "DUO108")
        self.assertEqual(new.no_findings, [])
        self.assertEqual(
            [e.code for e in new.rule_not_applicable],
            ["DUO108", "DUO101"],
        )
        self.assertEqual(new.eligible, [])
        self.assertEqual(len(new.skipped), 2)

    def test_syntax_error_is_not_no_findings(self):
        source = "x = f" + chr(34) + "{1}" + chr(34) + "\n"
        report = [{
            "filename": "app.py",
            "lineno": 1,
            "code": "DUO105",
            "message": "DUO105 finding",
        }]
        result = scope.audit_scope(
            {"app.py": source}, report, versions=["3.5"], rules=["DUO105"]
        )
        self.assertEqual(result["3.5"].syntax_unsupported[0].status, "syntax_unsupported")
        self.assertEqual(result["3.5"].no_findings, [])

    def test_rule_not_enabled(self):
        report = [{
            "filename": "app.py",
            "lineno": 1,
            "code": "DUO105",
            "message": "DUO105 finding",
        }]
        result = scope.audit_scope(
            {"app.py": "exec(\"x\")\n"}, report,
            versions=["3.8"], rules=["DUO102"]
        )
        self.assertEqual(result["3.8"].rule_not_enabled[0].code, "DUO105")
        self.assertEqual(result["3.8"].eligible, [])

    def test_report_string_and_dict_payload(self):
        report = "app.py:1:1: DUO105 use of exec is insecure"
        result = scope.audit_scope(
            {"app.py": "exec(\"x\")\n"}, report,
            versions=["3.8"], rules=["DUO105"]
        )
        self.assertTrue(result["3.8"].is_eligible("DUO105"))
        payload = {
            "sources": {"app.py": "exec(\"x\")\n"},
            "results": [{
                "filename": "app.py",
                "lineno": 1,
                "code": "DUO105",
                "message": "DUO105 use of exec is insecure",
            }],
            "rules": ["DUO105"],
        }
        payload_result = scope.audit_scope(payload, versions=["3.8"])
        self.assertTrue(payload_result["3.8"].is_eligible("DUO105"))

    def test_versions_are_independent(self):
        report = [{
            "filename": "app.py",
            "lineno": 1,
            "code": "DUO105",
            "message": "DUO105 finding",
        }]
        result = scope.audit_scope(
            {"app.py": "exec(\"x\")\n"}, report,
            versions=["2.7", "3.8"], rules=["DUO105"]
        )
        self.assertTrue(result["2.7"].is_eligible("DUO105"))
        self.assertTrue(result["3.8"].is_eligible("DUO105"))
        self.assertEqual(result.common_eligible()[0].code, "DUO105")

    def test_multiple_sources_use_their_own_syntax(self):
        sources = {
            "py2.py": "print 1\n",
            "py3.py": "x = f\"{1}\"\n",
        }
        report = [
            {
                "filename": "py2.py",
                "lineno": 1,
                "code": "DUO105",
                "message": "DUO105 py2 item",
            },
            {
                "filename": "py3.py",
                "lineno": 1,
                "code": "DUO105",
                "message": "DUO105 py3 item",
            },
        ]
        result = scope.audit_scope(
            sources, report, versions=["2.7", "3.8"], rules=["DUO105"]
        )
        self.assertEqual(
            [entry.scope for entry in result["2.7"].eligible],
            ["py2.py"],
        )
        self.assertEqual(
            [entry.scope for entry in result["3.8"].eligible],
            ["py3.py"],
        )
        self.assertEqual(
            [entry.scope for entry in result["2.7"].syntax_unsupported],
            ["py3.py"],
        )
        self.assertEqual(
            [entry.scope for entry in result["3.8"].syntax_unsupported],
            ["py2.py"],
        )



if __name__ == "__main__":
    unittest.main()
