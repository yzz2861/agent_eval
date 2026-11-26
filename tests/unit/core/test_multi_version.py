# SPDX-License-Identifier: Apache-2.0
import ast
import json
import sys
import tempfile
import unittest

from bandit.core import multi_version


class MultiVersionScanTests(unittest.TestCase):
    def test_scan_reports_file_status_findings_and_suppression(self):
        host_version = sys.version_info[:2]
        old_target = (3, 7)
        unsupported_target = (3, 1)

        with tempfile.TemporaryDirectory() as temp_dir:
            old_file = f"{temp_dir}/old_syntax.py"
            modern_file = f"{temp_dir}/modern_syntax.py"
            suppressed_file = f"{temp_dir}/suppressed.py"

            with open(old_file, "w") as source:
                source.write(
                    "async = subprocess.Popen(\"echo old\", shell=True)\n"
                )
            with open(modern_file, "w") as source:
                source.write(
                    "import subprocess\n"
                    "def command(value):\n"
                    "    match value:\n"
                    "        case 'x':\n"
                    "            return subprocess.Popen(\n"
                    "                'echo x', shell=True\n"
                    "            )\n"
                )
            with open(suppressed_file, "w") as source:
                source.write(
                    "import subprocess\n"
                    "subprocess.Popen(\"echo suppressed\", shell=True) "
                    "# nosec: B602\n"
                )

            report = multi_version.scan(
                [old_file, modern_file, suppressed_file],
                [old_target, host_version, unsupported_target],
            )

        self.assertEqual(
            report["targets"],
            [
                {
                    "python_version": "3.7",
                    "status": "supported",
                    "reason": "ast.parse supports this target grammar.",
                },
                {
                    "python_version": f"{host_version[0]}.{host_version[1]}",
                    "status": "supported",
                    "reason": "ast.parse supports this target grammar.",
                },
                {
                    "python_version": "3.1",
                    "status": "uncovered",
                    "reason": "The host interpreter cannot parse this "
                    "grammar target.",
                },
            ],
        )
        self.assertEqual(
            report["target_stats"],
            {
                "3.7": {
                    "checked": 2,
                    "rejected": 1,
                    "inconclusive": 0,
                    "uncovered": 1,
                },
                f"{host_version[0]}.{host_version[1]}": {
                    "checked": 3,
                    "rejected": 0,
                    "inconclusive": 0,
                    "uncovered": 1,
                },
                "3.1": {
                    "checked": 0,
                    "rejected": 0,
                    "inconclusive": 0,
                    "uncovered": 3,
                },
            },
        )

        files = {item["filename"]: item for item in report["files"]}
        self.assertEqual(
            files[old_file]["targets"]["3.7"]["status"], "checked"
        )
        self.assertEqual(
            files[old_file]["targets"]["3.1"]["status"], "uncovered"
        )
        old_host_status = files[old_file]["targets"][
            f"{host_version[0]}.{host_version[1]}"
        ]
        self.assertEqual(old_host_status["status"], "rejected")
        self.assertIn("SyntaxError", old_host_status["reason"])

        self.assertEqual(
            files[modern_file]["targets"]["3.7"]["status"], "rejected"
        )
        modern_host_status = files[modern_file]["targets"][
            f"{host_version[0]}.{host_version[1]}"
        ]
        self.assertEqual(modern_host_status["status"], "checked")

        suppressed = files[suppressed_file]["targets"]["3.7"]
        self.assertEqual(suppressed["status"], "checked")
        self.assertEqual(suppressed["issue_count"], 0)

        finding_indexes = {}
        for index, finding in enumerate(report["findings"]):
            finding_indexes[finding["filename"]] = index

        old_finding = report["findings"][finding_indexes[old_file]]
        self.assertEqual(old_finding["test_ids"], ["B602"])
        self.assertEqual(old_finding["applicable_targets"], ["3.7"])
        self.assertEqual(old_finding["suppressed_targets"], [])
        self.assertEqual(
            old_finding["target_results"]["3.7"]["suppressed"], False
        )

        modern_finding = report["findings"][finding_indexes[modern_file]]
        self.assertEqual(modern_finding["test_ids"], ["B602"])
        self.assertEqual(
            modern_finding["applicable_targets"],
            [f"{host_version[0]}.{host_version[1]}"],
        )
        self.assertEqual(modern_finding["suppressed_targets"], [])

        suppressed_finding = report["findings"][
            finding_indexes[suppressed_file]
        ]
        self.assertEqual(suppressed_finding["test_ids"], ["B602"])
        self.assertEqual(
            suppressed_finding["applicable_targets"],
            ["3.7", f"{host_version[0]}.{host_version[1]}"],
        )
        self.assertEqual(
            suppressed_finding["suppressed_targets"],
            ["3.7", f"{host_version[0]}.{host_version[1]}"],
        )
        self.assertEqual(
            suppressed_finding["target_results"]["3.7"]["suppressed"], True
        )
        self.assertEqual(
            suppressed_finding["target_results"]["3.7"]["suppressed_by"],
            ["B602"],
        )

        serialized = json.loads(json.dumps(report))
        self.assertEqual(
            serialized["host"]["python_version"], list(host_version)
        )

    def test_target_grammar_uses_ast_feature_version(self):
        target = (3, 7)
        self.assertEqual(
            multi_version.target_grammar_status(target),
            {
                "python_version": "3.7",
                "status": "supported",
                "reason": "ast.parse supports this target grammar.",
            },
        )
        ast.parse(
            "async = 1\n", feature_version=target
        )


if __name__ == "__main__":
    unittest.main()
